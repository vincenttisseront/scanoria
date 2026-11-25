// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// § 7.2 : statut de commit « scanoria/release-gate » sur le commit du tag,
// par le client de forge (contrat 30) : en attente pendant l'analyse, puis
// succès, échec ou non concluant (toujours bloquant, G13), avec un lien vers
// la page Release et l'explication courte du verdict (I9). Un verdict
// favorable sans rapport signé reste bloquant : la preuve fait partie du gate.
// § 7.3 : fichiers joints à la release de la forge (rapport signé, SARIF
// fusionné, SBOM), quand la forge le permet ; le droit manquant est signalé.
// Rien ne lève : chaque issue est tracée dans l'audit.

import { VerdictDetails } from '#shared/analysis'
import type { Queryable } from '../utils/db'
import { writeAudit } from '../utils/audit'
import { forgeAccess } from '../forges/index'
import { ForgeError } from '../forges/http'
import { projectForge } from '../forges/context'
import { forgeLocale } from '../forges/publish'
import { statusFor } from '../forges/summary'
import { missingAssetPermission, releaseForge, type AssetOutcome } from '../forges/release'
import { readArtifact } from './artifacts'
import { signedEnvelope } from './sign'

export const GATE_CONTEXT = 'scanoria/release-gate'

interface GateRow {
  scan_id: string
  project_id: string
  tag: string
  commit_sha: string
  verdict: string | null
  verdict_details: unknown
  scan_status: string
  report_status: string | null
}

async function gateRow(db: Queryable, scanId: string): Promise<GateRow | null> {
  const r = await db.query<GateRow>(
    `SELECT s.id::text AS scan_id, s.project_id::text, rc.tag, COALESCE(s.commit_sha, rc.commit_sha) AS commit_sha,
            s.verdict, s.verdict_details, s.status AS scan_status, rr.status AS report_status
       FROM scans s JOIN release_candidates rc ON rc.scan_id = s.id
       LEFT JOIN release_reports rr ON rr.scan_id = s.id
      WHERE s.id = $1 LIMIT 1`, [scanId])
  return r.rows[0] ?? null
}

const T = {
  fr: { pending: 'analyse de release en cours', unsigned: 'rapport non signé : bloquant', signing: 'signature du rapport en cours' },
  en: { pending: 'release scan in progress', unsigned: 'report not signed: blocking', signing: 'signing the report' },
}

/** État et texte du statut, d'après l'analyse et son rapport. */
export function gateState(row: Pick<GateRow, 'tag' | 'verdict' | 'verdict_details' | 'scan_status' | 'report_status'>, locale: 'fr' | 'en') {
  const t = T[locale]
  if (!row.verdict || ['queued', 'dispatched', 'running', 'ingesting'].includes(row.scan_status)) {
    return { state: 'pending' as const, description: `${row.tag} : ${t.pending}` }
  }
  const details = VerdictDetails.safeParse(row.verdict_details)
  const st = statusFor('final', row.verdict as 'passed' | 'failed' | 'inconclusive', details.success ? details.data : null, [], locale)
  if (row.verdict === 'passed' && row.report_status !== 'signed') {
    return row.report_status === 'error'
      ? { state: 'failure' as const, description: `${row.tag} : ${t.unsigned}` }
      : { state: 'pending' as const, description: `${row.tag} : ${t.signing}` }
  }
  return { state: st.state, description: `${row.tag} : ${st.description}` }
}

/** Publie le statut scanoria/release-gate d'une analyse de release ; ne lève jamais. */
export async function publishReleaseGate(db: Queryable, scanId: string): Promise<'published' | 'skipped' | 'error'> {
  let row: GateRow | null
  try {
    row = await gateRow(db, scanId)
  }
  catch {
    return 'skipped'
  }
  if (!row) return 'skipped'
  const ctx = await projectForge(db, row.project_id).catch(() => null)
  if (!ctx) return 'skipped'
  const st = gateState(row, forgeLocale())
  try {
    await ctx.publisher.setCommitStatus(ctx.repo, {
      sha: row.commit_sha,
      context: GATE_CONTEXT,
      state: st.state,
      description: st.description,
      target_url: ctx.consoleUrl ? `${ctx.consoleUrl}/releases/${row.scan_id}` : null,
    })
    await writeAudit(db, { actor: { type: 'system' }, action: 'release.gate.published', outcome: 'success', targetType: 'scan', targetId: row.scan_id, details: { tag: row.tag, state: st.state } })
    return 'published'
  }
  catch (err) {
    const code = err instanceof ForgeError ? err.code : 'E_FORGE_PUBLISH'
    await writeAudit(db, { actor: { type: 'system' }, action: 'release.gate.published', outcome: 'failure', targetType: 'scan', targetId: row.scan_id, details: { tag: row.tag, state: st.state, code } }).catch(() => {})
    return 'error'
  }
}

export const ASSET_FILES = [
  { name: 'scanoria-release-report.json', source: 'report.json', type: 'application/json' },
  { name: 'scanoria-results.sarif', source: 'results.sarif', type: 'application/sarif+json' },
  { name: 'scanoria-sbom.cdx.json', source: 'sbom.cdx.json', type: 'application/vnd.cyclonedx+json' },
] as const

export interface AssetsResult {
  outcome: 'uploaded' | 'skipped' | 'missing-permission' | 'no-release' | 'error'
  missing_permission?: string
  files?: Record<string, AssetOutcome | 'absent'>
  code?: string
}

/**
 * Joint le rapport signé, le SARIF et le SBOM à la release du tag dans la
 * forge (activé par défaut). Aucun fichier si la release n'existe pas, si
 * la forge n'y donne pas droit (droit manquant rendu) ou sans rapport signé.
 */
export async function uploadReleaseAssets(db: Queryable, scanId: string): Promise<AssetsResult> {
  const r = await db.query<{ project_id: string, tag: string, report: unknown, report_sha256: string, signature: string | null, key_fingerprint: string | null, signed_at: Date | null, status: string }>(
    `SELECT project_id::text, tag, report, report_sha256, signature, key_fingerprint, signed_at, status FROM release_reports WHERE scan_id = $1`, [scanId])
  const rep = r.rows[0]
  if (!rep || rep.status !== 'signed') return { outcome: 'skipped' }
  const ctx = await projectForge(db, rep.project_id).catch(() => null)
  if (!ctx) return { outcome: 'skipped' }
  const missing = missingAssetPermission(ctx.forge.kind, ctx.app?.kind === 'github-app' ? (ctx.app.permissions as Record<string, unknown> | null) : null)
  let result: AssetsResult
  if (missing) result = { outcome: 'missing-permission', missing_permission: missing }
  else {
    try {
      const rf = releaseForge(await forgeAccess(db, ctx.forge))
      const files: Record<string, AssetOutcome | 'absent'> = {}
      let outcome: AssetsResult['outcome'] = 'uploaded'
      for (const f of ASSET_FILES) {
        const data = f.source === 'report.json'
          ? signedEnvelope({ ...rep, signature: rep.signature!, key_fingerprint: rep.key_fingerprint!, signed_at: rep.signed_at! })
          : await readArtifact(scanId, f.source)
        if (!data) {
          files[f.name] = 'absent'
          continue
        }
        const o = await rf.uploadAsset(ctx.repo, rep.tag, f.name, data, f.type)
        files[f.name] = o
        if (o === 'no-release') {
          outcome = 'no-release'
          break
        }
      }
      result = { outcome, files }
    }
    catch (err) {
      const code = err instanceof ForgeError ? err.code : 'E_FORGE_PUBLISH'
      result = code === 'E_FORGE_AUTH' ? { outcome: 'missing-permission', missing_permission: 'release-assets', code } : { outcome: 'error', code }
    }
  }
  await writeAudit(db, {
    actor: { type: 'system' }, action: 'release.assets', outcome: result.outcome === 'uploaded' || result.outcome === 'no-release' ? 'success' : 'failure',
    targetType: 'scan', targetId: scanId, details: { tag: rep.tag, ...result },
  }).catch(() => {})
  return result
}
