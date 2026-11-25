// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Publication d'une analyse dans sa forge (contrat 30) :
// - statut de commit scanoria/<profil> pour toute analyse d'un commit d'un
//   projet relié à une forge (en attente, échec anticipé V8, verdict) ;
// - pour une PR : un seul commentaire de synthèse, mis à jour en place
//   (forge_publications.external_id), et les annotations J7 une seule fois.
// Republication par onVerdictChanged (contrat 27) après une exception
// approuvée : le statut et le commentaire suivent le nouveau verdict.
// Une publication ne lève jamais : l'erreur est rangée dans forge_publications.

import { VerdictDetails } from '#shared/analysis'
import type { Queryable } from '../utils/db'
import { decideComponent, loadPolicy } from '../licenses/policy'
import { ForgeError } from './http'
import { MAX_ANNOTATIONS, type PullRequestRef } from './pr-types'
import { projectForge, type ProjectForge } from './context'
import { buildAnnotations, buildSummary, statusFor, type DependencyChange, type ForgeLocale, type Phase, type SummaryFinding } from './summary'

export const MAX_SUMMARY_FINDINGS = 20
const SLUG_RE = /^[a-z0-9][a-z0-9-]{0,62}$/

export function forgeLocale(): ForgeLocale {
  return process.env.NUXT_FORGE_LOCALE === 'en' ? 'en' : 'fr'
}

interface ScanRow {
  id: string
  project_id: string
  number: number
  ref: string
  commit_sha: string | null
  pull_request: (Partial<PullRequestRef> & { number: number, base_sha: string, changed_files?: string[] }) | null
  verdict: VerdictDetails['verdict'] | null
  verdict_details: unknown
  early_failure: { reasons?: unknown } | null
  status: string
  trigger: string
  profile_slug: string | null
  quarantine_days: number | null
}

async function loadScan(db: Queryable, scanId: string): Promise<ScanRow | null> {
  const r = await db.query<ScanRow>(
    `SELECT s.id, s.project_id, s.number, s.ref, s.commit_sha, s.pull_request, s.verdict, s.verdict_details, s.early_failure,
            s.status, s.trigger, COALESCE(s.plan -> 'profile' ->> 'slug', p.slug) AS profile_slug,
            (COALESCE(s.plan -> 'gate' -> 'rules', g.rules) ->> 'quarantine_days')::int AS quarantine_days
       FROM scans s JOIN profiles p ON p.id = s.profile_id JOIN gates g ON g.id = s.gate_id
      WHERE s.id = $1`, [scanId])
  return r.rows[0] ?? null
}

async function setPublication(db: Queryable, scanId: string, kind: string, state: 'pending' | 'published' | 'error', fields: { external_id?: string | null, annotations?: number, error?: string | null } = {}): Promise<void> {
  await db.query(
    `INSERT INTO forge_publications (scan_id, kind, external_id, annotations, state, error, updated_at)
     VALUES ($1, $2, $3, COALESCE($4, 0), $5, $6, now())
     ON CONFLICT (scan_id, kind) DO UPDATE SET
       external_id = COALESCE(EXCLUDED.external_id, forge_publications.external_id),
       annotations = COALESCE($4, forge_publications.annotations),
       state = EXCLUDED.state, error = EXCLUDED.error, updated_at = now()`,
    [scanId, kind, fields.external_id ?? null, fields.annotations ?? null, state, fields.error ? fields.error.slice(0, 1000) : null])
}

async function publication(db: Queryable, scanId: string, kind: string): Promise<{ external_id: string | null, state: string } | null> {
  const r = await db.query<{ external_id: string | null, state: string }>(
    'SELECT external_id, state FROM forge_publications WHERE scan_id = $1 AND kind = $2', [scanId, kind])
  return r.rows[0] ?? null
}

/** Commentaire de synthèse déjà publié pour cette PR (analyse précédente) : réutilisé en place. */
async function previousComment(db: Queryable, scan: ScanRow): Promise<string | null> {
  if (!scan.pull_request) return null
  const r = await db.query<{ external_id: string }>(
    `SELECT fp.external_id FROM forge_publications fp JOIN scans s ON s.id = fp.scan_id
      WHERE s.project_id = $1 AND fp.kind = 'pr-comment' AND fp.external_id IS NOT NULL
        AND (s.pull_request ->> 'number')::bigint = $2
      ORDER BY fp.updated_at DESC LIMIT 1`, [scan.project_id, scan.pull_request.number])
  return r.rows[0]?.external_id ?? null
}

function errorText(err: unknown): string {
  return err instanceof ForgeError ? err.message : 'E_FORGE_PUBLISH'
}

/** Nouveaux résultats de l'analyse, les plus graves d'abord, avec l'explication I2 existante. */
export async function newFindings(db: Queryable, scanId: string, locale: ForgeLocale, limit: number): Promise<{ items: SummaryFinding[], total: number }> {
  const total = await db.query<{ n: number }>(
    `SELECT count(*)::int AS n FROM scan_findings sf JOIN findings f ON f.id = sf.finding_id
      WHERE sf.scan_id = $1 AND sf.is_new AND f.status IN ('new', 'confirmed')`, [scanId])
  const r = await db.query<SummaryFinding>(
    `SELECT f.id, f.tool, f.rule_id, f.title, f.severity, f.path, f.start_line, f.category, f.malicious, f.secret_type, f.origin,
            ai.summary AS ai_summary, ai.model AS ai_model
       FROM scan_findings sf JOIN findings f ON f.id = sf.finding_id
       LEFT JOIN LATERAL (
         SELECT t.output ->> 'summary' AS summary, t.model FROM ai_tasks t
          WHERE t.kind = 'explain-finding' AND t.subject_type = 'finding' AND t.subject_id = f.id::text
            AND t.status = 'done' AND t.locale = $3 AND t.output ? 'summary'
          ORDER BY t.finished_at DESC NULLS LAST LIMIT 1) ai ON true
      WHERE sf.scan_id = $1 AND sf.is_new AND f.status IN ('new', 'confirmed')
      ORDER BY array_position(ARRAY['critical', 'high', 'medium', 'low', 'info'], f.severity), f.malicious DESC, f.path NULLS LAST, f.start_line NULLS LAST
      LIMIT $2`, [scanId, limit, locale])
  return { items: r.rows, total: total.rows[0]?.n ?? 0 }
}

/** I9 : explication de l'IA déjà rédigée pour cette analyse, sinon null. */
async function aiVerdict(db: Queryable, scanId: string, locale: ForgeLocale): Promise<{ text: string, model: string | null } | null> {
  const r = await db.query<{ text: string | null, model: string | null }>(
    `SELECT output ->> 'summary' AS text, model FROM ai_tasks
      WHERE kind = 'explain-verdict' AND subject_type = 'scan' AND subject_id = $1 AND status = 'done' AND locale = $2
      ORDER BY finished_at DESC NULLS LAST LIMIT 1`, [scanId, locale])
  return r.rows[0]?.text ? { text: r.rows[0].text, model: r.rows[0].model } : null
}

/**
 * H6 : dépendances ajoutées entre la base de la PR et la PR (SBOM des deux
 * analyses), avec leur licence (F8), leur âge (H5) et, pour npm, un script
 * d'installation déclaré dans package-lock.json.
 */
export async function dependencyDiff(db: Queryable, scan: ScanRow, ctx: ProjectForge | null, baseScanId: string | null) {
  const head = await db.query<{ purl: string, name: string, version: string | null, licenses: string[], published_at: Date | null, ecosystem: string }>(
    'SELECT purl, name, version, licenses, published_at, ecosystem FROM sbom_components WHERE scan_id = $1', [scan.id])
  if (!head.rows.length) return null
  const base = baseScanId
    ? new Set((await db.query<{ purl: string }>('SELECT purl FROM sbom_components WHERE scan_id = $1', [baseScanId])).rows.map(r => r.purl))
    : null
  const headSet = new Set(head.rows.map(r => r.purl))
  const added = base ? head.rows.filter(r => !base.has(r.purl)) : head.rows
  const removed = base ? [...base].filter(p => !headSet.has(p)).length : 0
  const policy = await loadPolicy(db, scan.project_id)
  const scripts = await npmInstallScripts(ctx, scan, added.some(a => a.ecosystem === 'npm'))
  const now = Date.now()
  const changes: DependencyChange[] = added.slice(0, 200).map(c => ({
    purl: c.purl,
    name: c.name,
    version: c.version,
    licenses: c.licenses,
    decision: decideComponent(policy, c.licenses).decision,
    age_days: c.published_at ? Math.max(0, Math.floor((now - new Date(c.published_at).getTime()) / 86_400_000)) : null,
    install_script: c.ecosystem === 'npm' && scripts.has(`${c.name}@${c.version ?? ''}`),
  }))
  // Les plus risquées d'abord : licence interdite, script d'installation, version récente.
  changes.sort((a, b) => Number(b.decision === 'denied') - Number(a.decision === 'denied')
    || Number(b.install_script) - Number(a.install_script)
    || (a.age_days ?? 1e9) - (b.age_days ?? 1e9) || a.name.localeCompare(b.name))
  return { added: changes, removed, baseKnown: base !== null }
}

/** Paquets npm (nom@version) qui déclarent un script d'installation dans le package-lock.json de la PR. */
async function npmInstallScripts(ctx: ProjectForge | null, scan: ScanRow, wanted: boolean): Promise<Set<string>> {
  const out = new Set<string>()
  const sha = scan.pull_request?.head_sha ?? scan.commit_sha
  if (!wanted || !ctx || !sha) return out
  const raw = await ctx.client.readFile(ctx.repo, sha, 'package-lock.json', { maxBytes: 16 * 1024 * 1024 }).catch(() => null)
  if (!raw) return out
  try {
    const lock = JSON.parse(raw) as { packages?: Record<string, { version?: unknown, hasInstallScript?: unknown, name?: unknown }> }
    for (const [path, p] of Object.entries(lock.packages ?? {})) {
      if (p?.hasInstallScript !== true || typeof p.version !== 'string') continue
      const name = typeof p.name === 'string' ? p.name : path.replace(/^.*node_modules\//, '')
      if (name) out.add(`${name}@${p.version}`)
    }
  }
  catch {
    // package-lock.json illisible : aucun script signalé (la couverture le dit déjà).
  }
  return out
}

export interface PublishOptions {
  phase: Phase
  /** Raisons d'un échec anticipé (V8, contrat 35). */
  earlyReasons?: string[]
}

/**
 * Publie l'analyse dans sa forge. Sans contexte (projet sans forge ni jeton,
 * commit inconnu), rien ; une erreur de la forge est rangée, jamais levée.
 */
export async function publishScan(db: Queryable, scanId: string, opts: PublishOptions): Promise<'published' | 'skipped' | 'error'> {
  let scan: ScanRow | null
  let ctx: ProjectForge | null
  try {
    scan = await loadScan(db, scanId)
    if (!scan || ['trial', 'external', 'recorrelate', 'replay'].includes(scan.trigger)) return 'skipped'
    const sha = scan.pull_request?.head_sha ?? scan.commit_sha
    if (!sha) return 'skipped'
    ctx = await projectForge(db, scan.project_id)
    if (!ctx) return 'skipped'
  }
  catch {
    return 'skipped'
  }
  const locale = forgeLocale()
  const details = VerdictDetails.safeParse(scan.verdict_details)
  const earlyReasons = opts.earlyReasons ?? (Array.isArray(scan.early_failure?.reasons) ? (scan.early_failure!.reasons as unknown[]).filter((x): x is string => typeof x === 'string') : [])
  const phase: Phase = opts.phase === 'final' && !scan.verdict ? 'pending' : opts.phase
  const scanUrl = ctx.consoleUrl ? `${ctx.consoleUrl}/scans/${scan.id}` : null
  const profile = scan.profile_slug && SLUG_RE.test(scan.profile_slug) ? scan.profile_slug : 'scan'
  let failed = false

  // 1. Statut de commit (toute analyse d'un commit).
  try {
    const st = statusFor(phase, scan.verdict, details.success ? details.data : null, earlyReasons, locale)
    await ctx.publisher.setCommitStatus(ctx.repo, {
      sha: scan.pull_request?.head_sha ?? scan.commit_sha!, context: `scanoria/${profile}`, state: st.state, description: st.description, target_url: scanUrl,
    })
    await setPublication(db, scan.id, 'commit-status', 'published')
  }
  catch (err) {
    failed = true
    await setPublication(db, scan.id, 'commit-status', 'error', { error: errorText(err) }).catch(() => {})
  }

  // 2. PR : commentaire de synthèse (un seul par PR) puis annotations (une fois, au verdict).
  const pr = scan.pull_request
  if (pr && typeof pr.number === 'number' && phase !== 'pending') {
    try {
      const { pullRequestBaseScan } = await import('../gates/pr-baseline')
      const base = await pullRequestBaseScan(db, scan.id)
      const found = await newFindings(db, scan.id, locale, MAX_SUMMARY_FINDINGS)
      const body = buildSummary({
        locale, phase, scanUrl,
        exceptionUrl: id => (ctx!.consoleUrl ? `${ctx!.consoleUrl}/projects/${scan!.project_id}/exceptions/new?finding=${id}&scan=${scan!.id}` : null),
        scanNumber: scan.number, profile, verdict: scan.verdict,
        details: details.success ? details.data : null,
        earlyReasons,
        newFindings: found.items,
        totalNew: found.total,
        dependencies: phase === 'final' ? await dependencyDiff(db, scan, ctx, base?.baseScanId ?? null) : null,
        quarantineDays: scan.quarantine_days ?? 7,
        aiVerdict: phase === 'final' ? await aiVerdict(db, scan.id, locale) : null,
      })
      const existing = (await publication(db, scan.id, 'pr-comment'))?.external_id ?? await previousComment(db, scan)
      const id = await ctx.publisher.upsertComment(ctx.repo, pr.number, body, existing)
      await setPublication(db, scan.id, 'pr-comment', 'published', { external_id: id })

      const kind = ctx.forge.kind === 'github' ? 'check-run' : 'pr-review'
      if (phase === 'final' && (await publication(db, scan.id, kind))?.state !== 'published' && pr.head_sha && pr.head_ref && pr.base_ref) {
        const all = await newFindings(db, scan.id, locale, 200)
        const changed = Array.isArray(pr.changed_files) ? new Set(pr.changed_files) : null
        const annotations = buildAnnotations(all.items, changed, locale, MAX_ANNOTATIONS)
        const st = statusFor(phase, scan.verdict, details.success ? details.data : null, earlyReasons, locale)
        if (annotations.length || kind === 'check-run') {
          const res = await ctx.publisher.publishAnnotations(ctx.repo, pr as PullRequestRef, annotations, body, st.state)
          await setPublication(db, scan.id, res.kind, 'published', { external_id: res.id, annotations: res.count })
        }
      }
    }
    catch (err) {
      failed = true
      await setPublication(db, scan.id, 'pr-comment', 'error', { error: errorText(err) }).catch(() => {})
    }
  }
  return failed ? 'error' : 'published'
}
