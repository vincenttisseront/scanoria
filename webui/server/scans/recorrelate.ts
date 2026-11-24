// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// F3, contrat 16 : re-corrélation sans réanalyse. Quand le helper publie une
// base plus récente (osv-db, trivy-db, grype-db, epss, kev), chaque projet qui
// a un SBOM reçoit une analyse « recorrelate » :
// - au plus une mise en file par base et par jour ; la première fois qu'une base
//   est vue, sa date est seulement retenue (aucune vague d'analyses à la mise à jour) ;
// - priorité basse (G17), rien n'est cloné : la source est la liste des purl du
//   SBOM de l'analyse d'origine (sbom_source), d'où le runner écrit lui-même un
//   CycloneDX minimal ; seuls les modules SCA qui lisent l'entrée « sbom » tournent ;
// - référence « sbom:<ref> » : la série des re-corrélations reste à part des
//   analyses du dépôt (« nouveau » et « corrigé » ne se mélangent pas) ; une
//   re-corrélation ne déclare d'ailleurs jamais un résultat corrigé ;
// - son verdict n'est pas un verdict de release ; un résultat vraiment nouveau
//   pour le projet (critique, élevé, KEV ou malveillant MAL-, H4) est signalé :
//   événement d'audit « recorrelation.exposure », repris en bandeau du tableau de bord.

import type pg from 'pg'
import type { Queryable } from '../utils/db'
import { writeAudit } from '../utils/audit'
import { readModulesState, type InstalledModule } from '../utils/catalog'
import { resolveProfile, type PlanCatalogEntry, type PlannedModule, type CoverageGap, readPlanCatalog } from './plan'
import { SBOM_PURL_RE, type ScanJob } from './contract'

export const RECORRELATE_TRIGGER = 'recorrelate'
/** G17 : sous les analyses planifiées (10). */
export const RECORRELATE_PRIORITY = 5
export const RECORRELATE_FEEDS = ['osv-db', 'trivy-db', 'grype-db', 'epss', 'kev'] as const
const SETTING_KEY = 'scan.recorrelation'
const DAY_MS = 86_400_000
/** La tâche du runner est bornée à 256 Kio : la liste des purl doit y tenir. */
export const MAX_SOURCE_BYTES = 220 * 1024
export const REF_PREFIX = 'sbom:'

export async function isRecorrelation(db: Queryable, scanId: string): Promise<boolean> {
  const r = await db.query<{ trigger: string }>('SELECT trigger FROM scans WHERE id = $1', [scanId])
  return r.rows[0]?.trigger === RECORRELATE_TRIGGER
}

/** Modules d'une re-corrélation : scanners SCA installés, sains, actifs, qui lisent un SBOM. */
export function recorrelationPlan(input: { installed: InstalledModule[], catalog: Map<string, PlanCatalogEntry> }): { modules: PlannedModule[], gaps: CoverageGap[] } {
  return resolveProfile({
    profile: { id: RECORRELATE_TRIGGER, slug: RECORRELATE_TRIGGER, categories: ['sca'], include_modules: [], exclude_modules: [] },
    sourceKind: 'sbom',
    projectLicense: null,
    installed: input.installed,
    catalog: input.catalog,
  })
}

/** Source de la tâche du runner : purl du SBOM d'origine (sans doublon), ou null s'il manque ou ne tient pas. */
export async function recorrelationSource(db: Queryable, scanId: string): Promise<Extract<ScanJob['source'], { kind: 'sbom' }> | null> {
  const s = await db.query<{ sbom_source: string | null }>('SELECT sbom_source::text FROM scans WHERE id = $1', [scanId])
  const source = s.rows[0]?.sbom_source
  if (!source) return null
  const r = await db.query<{ purl: string }>('SELECT purl FROM sbom_components WHERE scan_id = $1 ORDER BY purl LIMIT 50000', [source])
  const purls = [...new Set(r.rows.map(x => x.purl).filter(p => SBOM_PURL_RE.test(p)))]
  if (!purls.length) return null
  const bytes = purls.reduce((n, p) => n + Buffer.byteLength(p, 'utf8') + 3, 0)
  if (bytes > MAX_SOURCE_BYTES) return null
  return { kind: 'sbom', scan_id: source, components: purls }
}

interface FeedMark { updated_at: string, enqueued_at: string | null }
type Marks = Record<string, FeedMark>

async function readMarks(db: Queryable): Promise<Marks> {
  const r = await db.query<{ value: unknown }>('SELECT value FROM appliance_settings WHERE key = $1', [SETTING_KEY])
  const v = r.rows[0]?.value
  return v && typeof v === 'object' && !Array.isArray(v) ? v as Marks : {}
}

async function writeMarks(db: Queryable, marks: Marks): Promise<void> {
  await db.query(
    `INSERT INTO appliance_settings (key, value, updated_at) VALUES ($1, $2, now())
     ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()`, [SETTING_KEY, JSON.stringify(marks)])
}

/**
 * Bases mises à jour depuis la dernière re-corrélation, au plus une fois par
 * jour et par base. Met à jour les marques ; renvoie les bases qui déclenchent.
 */
export function feedsToRecorrelate(feeds: { id: string, updated_at?: string | null, status: string }[], marks: Marks, now: Date): { due: string[], marks: Marks } {
  const next: Marks = { ...marks }
  const due: string[] = []
  for (const f of feeds) {
    if (!(RECORRELATE_FEEDS as readonly string[]).includes(f.id) || !f.updated_at || f.status === 'missing') continue
    const updated = Date.parse(f.updated_at)
    if (!Number.isFinite(updated)) continue
    const mark = marks[f.id]
    if (!mark) {
      next[f.id] = { updated_at: f.updated_at, enqueued_at: null }
      continue
    }
    if (updated <= Date.parse(mark.updated_at)) continue
    if (mark.enqueued_at && now.getTime() - Date.parse(mark.enqueued_at) < DAY_MS) continue
    next[f.id] = { updated_at: f.updated_at, enqueued_at: now.toISOString() }
    due.push(f.id)
  }
  return { due, marks: next }
}

/** Dernière analyse terminée qui a un SBOM, par projet actif. */
async function latestSbomScans(db: Queryable): Promise<{ project_id: string, scan_id: string, ref: string, commit_sha: string | null }[]> {
  const r = await db.query<{ project_id: string, scan_id: string, ref: string, commit_sha: string | null }>(
    `SELECT DISTINCT ON (s.project_id) s.project_id::text, s.id::text AS scan_id, s.ref, s.commit_sha
       FROM scans s JOIN projects p ON p.id = s.project_id
      WHERE s.status = 'done' AND p.archived_at IS NULL AND s.trigger <> 'recorrelate'
        AND EXISTS (SELECT 1 FROM sbom_components c WHERE c.scan_id = s.id)
      ORDER BY s.project_id, s.finished_at DESC NULLS LAST, s.queued_at DESC`)
  return r.rows
}

/** Met en file la re-corrélation d'un projet ; null si une est déjà en file. */
export async function enqueueRecorrelation(db: Pick<pg.Pool, 'connect'>, input: { projectId: string, sourceScanId: string, feeds?: string[] }): Promise<string | null> {
  const client = await db.connect()
  try {
    await client.query('BEGIN')
    const p = await client.query<{ profile_id: string, gate_id: string }>(
      'SELECT profile_id, gate_id FROM projects WHERE id = $1 AND archived_at IS NULL FOR UPDATE', [input.projectId])
    const project = p.rows[0]
    const src = await client.query<{ ref: string, commit_sha: string | null }>(
      'SELECT ref, commit_sha FROM scans WHERE id = $1 AND project_id = $2', [input.sourceScanId, input.projectId])
    const dup = await client.query(
      `SELECT 1 FROM scans WHERE project_id = $1 AND trigger = 'recorrelate' AND status IN ('queued', 'dispatched', 'running', 'ingesting') LIMIT 1`, [input.projectId])
    if (!project || !src.rows[0] || dup.rowCount) {
      await client.query('COMMIT')
      return null
    }
    const ref = (REF_PREFIX + src.rows[0].ref).slice(0, 255)
    const ins = await client.query<{ id: string }>(
      `INSERT INTO scans (project_id, number, trigger, priority, ref, commit_sha, profile_id, gate_id, sbom_source)
       VALUES ($1, (SELECT COALESCE(max(number), 0) + 1 FROM scans WHERE project_id = $1), 'recorrelate', $2, $3, $4, $5, $6, $7)
       RETURNING id::text`,
      [input.projectId, RECORRELATE_PRIORITY, ref, src.rows[0].commit_sha, project.profile_id, project.gate_id, input.sourceScanId])
    await client.query('COMMIT')
    return ins.rows[0]!.id
  }
  catch (err) {
    await client.query('ROLLBACK').catch(() => {})
    throw err
  }
  finally {
    client.release()
  }
}

/** Au moins un module installé et actif sait re-corréler un SBOM. */
function canRecorrelate(installed: InstalledModule[], catalog: Map<string, PlanCatalogEntry>): boolean {
  return recorrelationPlan({ installed, catalog }).modules.length > 0
}

/**
 * Une passe (scanoria-worker) : bases plus récentes → re-corrélations en file.
 * Renvoie le nombre d'analyses mises en file.
 */
export async function runRecorrelation(pool: pg.Pool, paths: { modulesStateFile: string, catalogIndexFile: string }, now = new Date(), log: (m: string) => void = console.log): Promise<number> {
  const state = await readModulesState(paths.modulesStateFile)
  if (!state.available) return 0
  const marks = await readMarks(pool)
  const { due, marks: next } = feedsToRecorrelate(state.feeds, marks, now)
  if (due.length && !canRecorrelate(state.modules, await readPlanCatalog(paths.catalogIndexFile))) {
    // La mise à jour n'est pas consommée : elle déclenchera dès qu'un module saura re-corréler.
    const kept = Object.fromEntries(Object.entries(next).filter(([f]) => !due.includes(f) || marks[f]).map(([f, m]) => [f, due.includes(f) ? marks[f]! : m]))
    if (JSON.stringify(kept) !== JSON.stringify(marks)) await writeMarks(pool, kept)
    log(`recorrelation skipped (${due.join(', ')}): no installed module reads an SBOM`)
    return 0
  }
  if (JSON.stringify(next) !== JSON.stringify(marks)) await writeMarks(pool, next)
  if (!due.length) return 0
  let n = 0
  for (const s of await latestSbomScans(pool)) {
    if (await enqueueRecorrelation(pool, { projectId: s.project_id, sourceScanId: s.scan_id, feeds: due })) n++
  }
  log(`recorrelation: ${n} scan(s) queued after update of ${due.join(', ')}`)
  return n
}

/**
 * Fin d'une re-corrélation : résultats vraiment nouveaux pour le projet (créés
 * par cette analyse, sans résultat existant sur le même avis et la même
 * version), critiques, élevés, KEV ou malveillants → événement d'audit.
 */
export async function reportRecorrelation(db: Queryable, scanId: string): Promise<number> {
  const s = await db.query<{ project_id: string, trigger: string }>('SELECT project_id::text, trigger FROM scans WHERE id = $1', [scanId])
  const scan = s.rows[0]
  if (!scan || scan.trigger !== RECORRELATE_TRIGGER) return 0
  const r = await db.query<{ id: string, severity: string, malicious: boolean, kev: boolean }>(
    `SELECT f.id::text, f.severity,
            (f.malicious OR EXISTS (SELECT 1 FROM unnest(f.vuln_ids) v WHERE upper(v) LIKE 'MAL-%')) AS malicious,
            EXISTS (SELECT 1 FROM vuln_intel i WHERE i.kev AND (i.vuln_id = ANY (f.vuln_ids) OR i.aliases && f.vuln_ids)) AS kev
       FROM scan_findings sf JOIN findings f ON f.id = sf.finding_id
      WHERE sf.scan_id = $1 AND f.first_scan_id = $1
        AND NOT EXISTS (SELECT 1 FROM findings o
                         WHERE o.project_id = f.project_id AND o.id <> f.id AND o.vuln_ids && f.vuln_ids
                           AND o.package ->> 'name' IS NOT DISTINCT FROM f.package ->> 'name'
                           AND o.package ->> 'version' IS NOT DISTINCT FROM f.package ->> 'version')`, [scanId])
  const hits = r.rows.filter(f => f.malicious || f.kev || f.severity === 'critical' || f.severity === 'high')
  if (!hits.length) return 0
  await writeAudit(db, {
    actor: { type: 'system' },
    action: 'recorrelation.exposure',
    outcome: 'success',
    targetType: 'project',
    targetId: scan.project_id,
    details: {
      scan_id: scanId,
      count: hits.length,
      malicious: hits.filter(f => f.malicious).length,
      kev: hits.filter(f => f.kev).length,
      critical: hits.filter(f => f.severity === 'critical').length,
      high: hits.filter(f => f.severity === 'high').length,
      finding_ids: hits.slice(0, 20).map(f => f.id),
    },
  })
  return hits.length
}
