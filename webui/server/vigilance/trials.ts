// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// F13, mise à jour d'outil à l'essai (contrat 25 de la 0.6).
// 1. « Essayer la version N+1 » : ligne module_trials (un seul essai en cours
//    par module), puis demande start-trial : le helper récupère l'image
//    candidate de l'index signé et la retient.
// 2. Une fois l'image retenue, les sample_size dernières analyses terminées
//    qui ont utilisé le module sont rejouées avec la candidate : déclencheur
//    « trial », priorité 5, référence « trial:<ref> », replay_of = l'analyse
//    d'origine. Aucun effet de bord : aucune ingestion dans findings, aucun
//    verdict, aucune tâche IA, ni cache V4, ni sbom_components, ni statut de
//    commit, et rien dans les tableaux de bord ni les recherches.
// 3. L'écart (nouveaux résultats, disparus, inchangés, par empreinte G19, et
//    durées) est rangé dans module_trials.summary.
// 4. Adopter = update-module normal (sauvegarde comprise) ; abandonner =
//    l'image candidate est retirée. Les deux sont confirmés dans la console.

import type pg from 'pg'
import type { Queryable } from '../utils/db'
import { writeAudit, type AuditActor } from '../utils/audit'
import { compareVersions, type CatalogIndex, type InstalledModule } from '../utils/catalog'
import { submitRequest, type Requester } from '../utils/requests'
import { readOutput } from '../findings/ingest'
import { readModuleHints } from '../findings/manifest'
import { parseCycloneDx, parseSarif } from '../findings/parse'
import { CATEGORIES } from '#shared/analysis'
import { parsePlan, planTimeout, type ScanPlan } from '../scans/plan'
import type { RetainedImage } from './pins'

export const TRIAL_TRIGGER = 'trial'
/** G17 : sous les analyses planifiées (10), comme les re-corrélations. */
export const TRIAL_PRIORITY = 5
export const TRIAL_REF_PREFIX = 'trial:'
export const DEFAULT_SAMPLE = 3
/** Exemples de résultats nouveaux ou disparus gardés par analyse. */
const MAX_EXAMPLES = 10

export type TrialStatus = 'running' | 'done' | 'adopted' | 'abandoned' | 'error'

export interface TrialPerScan {
  scan_id: string
  trial_scan_id: string
  new: number
  gone: number
  unchanged: number
  new_examples: { rule: string, path: string | null }[]
  gone_examples: { rule: string, path: string | null }[]
}

export interface TrialSummary {
  new: number
  gone: number
  unchanged: number
  scans: number
  failed: number
  duration_old_ms: number | null
  duration_new_ms: number | null
  per_scan: TrialPerScan[]
  error?: string | null
  note?: 'no-sample' | null
}

export class TrialError extends Error {
  constructor(readonly code: 'E_TRIAL_MODULE' | 'E_TRIAL_VERSION' | 'E_TRIAL_RUNNING' | 'E_TRIAL_NOT_FOUND' | 'E_TRIAL_STATE') {
    super(code)
  }
}

export async function isTrialScan(db: Queryable, scanId: string): Promise<boolean> {
  const r = await db.query<{ trigger: string }>('SELECT trigger FROM scans WHERE id = $1', [scanId])
  return r.rows[0]?.trigger === TRIAL_TRIGGER
}

/** Démarre l'essai : la candidate vient de l'index vérifié, plus récente que la version installée. */
export interface StartTrialInput {
  moduleId: string
  version?: string | null
  sampleSize?: number
  actor: AuditActor
  requester: Requester
  requestsDir: string
  installed: InstalledModule[]
  index: CatalogIndex | null
}

export async function startTrial(db: Queryable, input: StartTrialInput): Promise<{ trialId: string, requestId: string, version: string }> {
  const cur = input.installed.find(m => m.id === input.moduleId)
  if (!cur || cur.type !== 'scanner' || cur.status !== 'healthy' || !cur.enabled) throw new TrialError('E_TRIAL_MODULE')
  const candidates = (input.index?.modules ?? [])
    .filter(m => m.id === cur.id && compareVersions(m.version, cur.version) > 0)
    .sort((a, b) => compareVersions(b.version, a.version))
  const target = input.version ? candidates.find(m => m.version === input.version) : candidates[0]
  const digest = target?.image?.split('@')[1]
  if (!target || !digest || !/^sha256:[0-9a-f]{64}$/.test(digest)) throw new TrialError('E_TRIAL_VERSION')
  const sample = Math.max(1, Math.min(50, input.sampleSize ?? DEFAULT_SAMPLE))
  let trialId: string
  try {
    const r = await db.query<{ id: string }>(
      `INSERT INTO module_trials (module_id, from_version, to_version, to_digest, sample_size, started_by)
       VALUES ($1, $2, $3, $4, $5, $6) RETURNING id::text`,
      [cur.id, cur.version, target.version, digest, sample, input.actor.userId ?? null])
    trialId = r.rows[0]!.id
  }
  catch (e) {
    if ((e as { code?: string }).code === '23505') throw new TrialError('E_TRIAL_RUNNING')
    throw e
  }
  let requestId: string
  try {
    const req = await submitRequest(db, input.requestsDir, 'start-trial',
      { module: cur.id, version: target.version, trial_id: trialId, action: 'start' }, input.requester)
    requestId = req.id
  }
  catch (e) {
    await db.query(`UPDATE module_trials SET status = 'error', finished_at = now(), summary = $2 WHERE id = $1`,
      [trialId, JSON.stringify({ error: 'E_INTERNAL' })])
    throw e
  }
  await writeAudit(db, {
    actor: input.actor, action: 'module.trial-start', outcome: 'success', targetType: 'module', targetId: cur.id,
    requestId, details: { trial_id: trialId, from_version: cur.version, to_version: target.version, to_digest: digest, sample_size: sample },
  })
  return { trialId, requestId, version: target.version }
}

/** Plan d'essai : celui de l'analyse d'origine, réduit au module, avec la candidate. */
export function trialPlan(orig: ScanPlan, moduleId: string, toVersion: string, toDigest: string): ScanPlan | null {
  const m = orig.modules.find(x => x.id === moduleId)
  if (!m) return null
  const repo = m.image?.split('@')[0] ?? null
  const mod = { ...m, version: toVersion, image_digest: toDigest, image: repo ? `${repo}@${toDigest}` : null, alternate: 'trial' as const }
  return { ...orig, created_at: new Date().toISOString(), modules: [mod], gaps: [], timeout_s: planTimeout([mod]) }
}

interface TrialRow {
  id: string
  module_id: string
  from_version: string
  to_version: string
  to_digest: string
  sample_size: number
  started_at: Date
}

/** Analyses d'origine : dernières analyses terminées où le module a réussi (hors essais et re-corrélations). */
async function sampleScans(db: Queryable, moduleId: string, limit: number) {
  const r = await db.query<{ id: string, project_id: string, ref: string, commit_sha: string | null, upload_id: string | null, profile_id: string, gate_id: string, plan: unknown }>(
    `SELECT s.id::text, s.project_id::text, s.ref, s.commit_sha, s.upload_id::text, s.profile_id::text, s.gate_id::text, s.plan
       FROM scans s JOIN projects p ON p.id = s.project_id
       JOIN scan_modules sm ON sm.scan_id = s.id AND sm.module_id = $1 AND sm.status = 'ok'
      WHERE s.status = 'done' AND s.trigger NOT IN ('trial', 'recorrelate') AND s.plan IS NOT NULL
        AND p.archived_at IS NULL
      ORDER BY s.finished_at DESC NULLS LAST LIMIT $2`, [moduleId, limit])
  return r.rows
}

async function enqueueTrialScans(pool: pg.Pool, t: TrialRow): Promise<number> {
  const sample = await sampleScans(pool, t.module_id, t.sample_size)
  let n = 0
  for (const s of sample) {
    const orig = parsePlan(s.plan)
    const plan = orig && trialPlan(orig, t.module_id, t.to_version, t.to_digest)
    if (!plan) continue
    await pool.query(
      `INSERT INTO scans (project_id, number, trigger, priority, ref, commit_sha, upload_id, profile_id, gate_id, plan, replay_of, trial_id)
       VALUES ($1, (SELECT COALESCE(max(number), 0) + 1 FROM scans WHERE project_id = $1), 'trial', $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
      [s.project_id, TRIAL_PRIORITY, (TRIAL_REF_PREFIX + s.ref).slice(0, 255), s.commit_sha ?? plan.source.commit,
        s.upload_id, s.profile_id, s.gate_id, JSON.stringify(plan), s.id, t.id])
    n++
  }
  return n
}

/**
 * Une passe (console) : essais dont l'image est retenue → analyses d'essai en
 * file ; demande refusée → essai en erreur ; analyses d'essai toutes finies →
 * résumé. Sans état de vigilance lisible, rien n'est mis en file.
 */
export async function trialTick(pool: pg.Pool, retained: RetainedImage[] | null): Promise<void> {
  const r = await pool.query<TrialRow & { scans: number, open: number }>(
    `SELECT t.id::text, t.module_id, t.from_version, t.to_version, t.to_digest, t.sample_size, t.started_at,
            (SELECT count(*)::int FROM scans s WHERE s.trial_id = t.id) AS scans,
            (SELECT count(*)::int FROM scans s WHERE s.trial_id = t.id AND s.status IN ('queued', 'dispatched', 'running', 'ingesting')) AS open
       FROM module_trials t WHERE t.status = 'running'`)
  for (const t of r.rows) {
    if (t.scans > 0) {
      if (t.open === 0) await finishTrial(pool, t.id)
      continue
    }
    const req = await pool.query<{ status: string, code: string | null }>(
      `SELECT status, code FROM helper_requests WHERE type = 'start-trial' AND params ->> 'trial_id' = $1
        ORDER BY created_at DESC LIMIT 1`, [t.id])
    const st = req.rows[0]
    if (st && ['error', 'rejected', 'lost'].includes(st.status)) {
      await pool.query(`UPDATE module_trials SET status = 'error', finished_at = now(), summary = $2 WHERE id = $1 AND status = 'running'`,
        [t.id, JSON.stringify({ error: st.code ?? 'E_INTERNAL' })])
      continue
    }
    if (st?.status !== 'ok' || !retained?.some(x => x.module === t.module_id && x.version === t.to_version && x.image_digest === t.to_digest)) continue
    const n = await enqueueTrialScans(pool, t)
    if (n === 0) {
      await pool.query(`UPDATE module_trials SET status = 'done', finished_at = now(), summary = $2 WHERE id = $1 AND status = 'running'`,
        [t.id, JSON.stringify(emptySummary('no-sample'))])
    }
  }
}

function emptySummary(note: TrialSummary['note'] = null): TrialSummary {
  return { new: 0, gone: 0, unchanged: 0, scans: 0, failed: 0, duration_old_ms: null, duration_new_ms: null, per_scan: [], note }
}

/** Compare, par empreinte G19, les sorties de la candidate aux résultats de l'analyse d'origine. Renvoie le nombre de résultats. */
export async function recordTrialModule(db: Queryable, input: { scanId: string, moduleId: string, resultDir: string, outputs: Record<string, string> }): Promise<number> {
  const s = await db.query<{ trial_id: string, replay_of: string | null, module_version: string | null }>(
    `SELECT s.trial_id::text, s.replay_of::text, sm.module_version FROM scans s
       LEFT JOIN scan_modules sm ON sm.scan_id = s.id AND sm.module_id = $2 WHERE s.id = $1 AND s.trigger = 'trial'`,
    [input.scanId, input.moduleId])
  const scan = s.rows[0]
  if (!scan) throw new Error('not a trial scan')
  const hints = await readModuleHints(input.moduleId, scan.module_version)
  const ctx = { moduleId: input.moduleId, moduleCategories: hints.categories.filter(c => (CATEGORIES as readonly string[]).includes(c)) }
  const found = new Map<string, { rule: string, path: string | null }>()
  for (const kind of ['sarif', 'cyclonedx'] as const) {
    const rel = input.outputs[kind]
    if (!rel) continue
    const { doc, error } = await readOutput(input.resultDir, rel)
    if (error) throw new Error(`output ${kind}: ${error.code}`)
    const out = kind === 'sarif' ? parseSarif(doc, ctx) : parseCycloneDx(doc, ctx)
    if (out.issues.some(i => i.code === 'invalid-document')) throw new Error(`output ${kind}: invalid`)
    for (const f of out.findings) found.set(f.fingerprint, { rule: f.ruleId, path: f.path })
  }
  const before = new Map<string, { rule: string, path: string | null }>()
  if (scan.replay_of) {
    const o = await db.query<{ fingerprint: string, rule_id: string, path: string | null }>(
      `SELECT f.fingerprint, f.rule_id, f.path FROM scan_findings sf JOIN findings f ON f.id = sf.finding_id
        WHERE sf.scan_id = $1 AND f.tool = $2`, [scan.replay_of, input.moduleId])
    for (const f of o.rows) before.set(f.fingerprint, { rule: f.rule_id, path: f.path })
  }
  const added = [...found].filter(([fp]) => !before.has(fp))
  const gone = [...before].filter(([fp]) => !found.has(fp))
  const entry: TrialPerScan = {
    scan_id: scan.replay_of ?? input.scanId,
    trial_scan_id: input.scanId,
    new: added.length,
    gone: gone.length,
    unchanged: found.size - added.length,
    new_examples: added.slice(0, MAX_EXAMPLES).map(([, v]) => v),
    gone_examples: gone.slice(0, MAX_EXAMPLES).map(([, v]) => v),
  }
  await db.query(
    `UPDATE module_trials
        SET summary = jsonb_set(COALESCE(summary, '{}'::jsonb), '{per_scan}',
                                COALESCE(summary -> 'per_scan', '[]'::jsonb) || jsonb_build_array($2::jsonb))
      WHERE id = $1 AND status = 'running'`, [scan.trial_id, JSON.stringify(entry)])
  return found.size
}

/** Fin d'une analyse d'essai : statut seul, jamais de verdict. */
export async function concludeTrial(db: Queryable, scanId: string, outcome: { status: 'done' | 'error', error: unknown }): Promise<void> {
  const r = await db.query<{ trial_id: string }>(
    `UPDATE scans SET status = $2, verdict = NULL, verdict_details = NULL, error = $3, finished_at = now()
      WHERE id = $1 AND status = 'ingesting' RETURNING trial_id::text`,
    [scanId, outcome.status, outcome.error ? JSON.stringify(outcome.error) : null])
  const trialId = r.rows[0]?.trial_id
  if (!trialId) return
  const open = await db.query(`SELECT 1 FROM scans WHERE trial_id = $1 AND status IN ('queued', 'dispatched', 'running', 'ingesting') LIMIT 1`, [trialId])
  if (!open.rowCount) await finishTrial(db, trialId)
}

/** Résumé de l'essai : totaux, analyses en échec, durées moyennes (ancienne et candidate). */
export async function finishTrial(db: Queryable, trialId: string): Promise<void> {
  const t = await db.query<{ module_id: string, summary: Partial<TrialSummary> | null }>(
    `SELECT module_id, summary FROM module_trials WHERE id = $1 AND status = 'running'`, [trialId])
  const trial = t.rows[0]
  if (!trial) return
  const perScan = Array.isArray(trial.summary?.per_scan) ? trial.summary.per_scan : []
  const d = await db.query<{ failed: number, total: number, new_ms: number | null, old_ms: number | null }>(
    `SELECT count(*) FILTER (WHERE s.status <> 'done' OR sm.status IS DISTINCT FROM 'ok')::int AS failed,
            count(*)::int AS total,
            avg(sm.duration_ms) FILTER (WHERE sm.status = 'ok')::int AS new_ms,
            avg(om.duration_ms) FILTER (WHERE om.status = 'ok' AND sm.status = 'ok')::int AS old_ms
       FROM scans s
       LEFT JOIN scan_modules sm ON sm.scan_id = s.id AND sm.module_id = $2
       LEFT JOIN scan_modules om ON om.scan_id = s.replay_of AND om.module_id = $2
      WHERE s.trial_id = $1`, [trialId, trial.module_id])
  const row = d.rows[0]!
  const summary: TrialSummary = {
    new: perScan.reduce((n, p) => n + p.new, 0),
    gone: perScan.reduce((n, p) => n + p.gone, 0),
    unchanged: perScan.reduce((n, p) => n + p.unchanged, 0),
    scans: row.total,
    failed: row.failed,
    duration_old_ms: row.old_ms,
    duration_new_ms: row.new_ms,
    per_scan: perScan,
  }
  await db.query(`UPDATE module_trials SET status = 'done', summary = $2, finished_at = now() WHERE id = $1 AND status = 'running'`,
    [trialId, JSON.stringify(summary)])
}

export interface TrialView {
  id: string
  module_id: string
  from_version: string
  to_version: string
  to_digest: string
  status: TrialStatus
  sample_size: number
  summary: TrialSummary | null
  started_at: string
  finished_at: string | null
  progress: { total: number, finished: number }
}

export async function listTrials(db: Queryable, moduleId: string, limit = 10): Promise<TrialView[]> {
  const r = await db.query<Omit<TrialView, 'started_at' | 'finished_at' | 'progress'> & { started_at: Date, finished_at: Date | null, total: number, finished: number }>(
    `SELECT t.id::text, t.module_id, t.from_version, t.to_version, t.to_digest, t.status, t.sample_size, t.summary,
            t.started_at, t.finished_at,
            (SELECT count(*)::int FROM scans s WHERE s.trial_id = t.id) AS total,
            (SELECT count(*)::int FROM scans s WHERE s.trial_id = t.id AND s.status IN ('done', 'error', 'cancelled')) AS finished
       FROM module_trials t WHERE t.module_id = $1 ORDER BY t.started_at DESC LIMIT $2`, [moduleId, limit])
  return r.rows.map(({ total, finished, started_at, finished_at, ...t }) => ({
    ...t, started_at: started_at.toISOString(), finished_at: finished_at?.toISOString() ?? null, progress: { total, finished },
  }))
}

export async function getTrial(db: Queryable, moduleId: string, trialId: string): Promise<TrialView | null> {
  return (await listTrials(db, moduleId, 50)).find(t => t.id === trialId) ?? null
}

/** Abandon : analyses d'essai encore en file annulées, image candidate retirée par le helper. */
/**
 * Un essai « adopté » dont la mise à jour n'a pas abouti (version installée
 * différente de la candidate) reste abandonnable : sa candidate est alors libérée.
 */
export function abandonableStatuses(trial: Pick<TrialView, 'to_version'>, installedVersion: string | null): TrialView['status'][] {
  return installedVersion !== null && installedVersion !== trial.to_version
    ? ['running', 'done', 'error', 'adopted']
    : ['running', 'done', 'error']
}

export async function abandonTrial(db: Queryable, input: { trial: TrialView, installedVersion: string | null, actor: AuditActor, requester: Requester, requestsDir: string }): Promise<string> {
  const allowed = abandonableStatuses(input.trial, input.installedVersion)
  if (!allowed.includes(input.trial.status)) throw new TrialError('E_TRIAL_STATE')
  const r = await db.query(`UPDATE module_trials SET status = 'abandoned', finished_at = COALESCE(finished_at, now())
                             WHERE id = $1 AND status = ANY($2::text[])`, [input.trial.id, allowed])
  if (!r.rowCount) throw new TrialError('E_TRIAL_STATE')
  await db.query(`UPDATE scans SET status = 'cancelled', finished_at = now() WHERE trial_id = $1 AND status = 'queued'`, [input.trial.id])
  const req = await submitRequest(db, input.requestsDir, 'start-trial',
    { module: input.trial.module_id, version: input.trial.to_version, trial_id: input.trial.id, action: 'abandon' }, input.requester)
  await writeAudit(db, {
    actor: input.actor, action: 'module.trial-abandon', outcome: 'success', targetType: 'module', targetId: input.trial.module_id,
    requestId: req.id, details: { trial_id: input.trial.id, to_version: input.trial.to_version },
  })
  return req.id
}

/** Adoption : l'essai est marqué adopté ; la mise à jour elle-même est un update-module normal. */
export async function markAdopted(db: Queryable, trialId: string): Promise<boolean> {
  const r = await db.query(`UPDATE module_trials SET status = 'adopted', finished_at = COALESCE(finished_at, now())
                             WHERE id = $1 AND status = 'done'`, [trialId])
  return !!r.rowCount
}
