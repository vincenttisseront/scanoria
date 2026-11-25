// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Boucle de la gate de release dans la console (seule à déposer des demandes
// au helper), appelée par la boucle d'ingestion (utils/runtime.ts) :
// 1. signatures revenues du helper : revérifiées puis recopiées (sign.ts) ;
// 2. analyses de release terminées sans rapport : rapport canonique construit,
//    fichiers rangés (SARIF, SBOM), rapport « pending », demande de signature ;
// 3. rapports signés pas encore traités : statut scanoria/release-gate,
//    fichiers joints à la release de la forge, notes I6 demandées, puis
//    onReleaseVerdict (contrat 40), une seule fois (marque d'audit) ;
//    un rapport en erreur publie un statut bloquant ;
// 4. analyses de branche configurée (deploy_targets.on_trigger = 'branch') :
//    onReleaseVerdict sans rapport, une seule fois.
// Ne lève jamais.

import type { Queryable } from '../utils/db'
import { writeAudit } from '../utils/audit'
import { enqueueAiTask } from '../ai/enqueue'
import { forgeAccess } from '../forges/index'
import { projectForge } from '../forges/context'
import { releaseForge } from '../forges/release'
import { writeReleaseArtifacts } from './artifacts'
import { buildReleaseReport, REPORT_SCHEMA, ReleaseReportError } from './report'
import { applianceKey, applySignatureResults, requestReportSignature } from './sign'
import { canonicalBytes, sha256Hex } from './canonical'
import { emitReleaseVerdict } from './events'
import { publishReleaseGate, uploadReleaseAssets } from './gate'
import { notesMarkdown } from './notes'

const PREPARE_PER_TICK = 3
const FINALIZE_PER_TICK = 5
const EMITTED = 'release.verdict.emitted'
const NOTES_ATTEMPTS = 3

/** Analyses de release terminées, avec un tag, sans rapport. */
async function scansToPrepare(db: Queryable): Promise<string[]> {
  const r = await db.query<{ id: string }>(
    `SELECT s.id::text FROM scans s JOIN release_candidates rc ON rc.scan_id = s.id
      WHERE s.trigger = 'release' AND s.verdict IS NOT NULL AND s.status IN ('done', 'error')
        AND s.finished_at > now() - interval '7 days'
        AND NOT EXISTS (SELECT 1 FROM release_reports rr WHERE rr.scan_id = s.id)
      ORDER BY s.finished_at LIMIT ${PREPARE_PER_TICK}`)
  return r.rows.map(x => x.id)
}

/** Construit, range et fait signer le rapport d'une analyse de release. */
export async function prepareReport(db: Queryable, scanId: string, requestsDir?: string): Promise<'requested' | 'error'> {
  const meta = (await db.query<{ project_id: string, project_name: string, finished_at: string | null, tag: string, commit_sha: string }>(
    `SELECT s.project_id::text, p.name AS project_name, to_char(s.finished_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS finished_at,
            rc.tag, COALESCE(s.commit_sha, rc.commit_sha) AS commit_sha
       FROM scans s JOIN projects p ON p.id = s.project_id JOIN release_candidates rc ON rc.scan_id = s.id WHERE s.id = $1 LIMIT 1`, [scanId])).rows[0]
  if (!meta) return 'error'
  try {
    const artifacts = await writeReleaseArtifacts(db, { id: scanId, project_name: meta.project_name, finished_at: meta.finished_at })
    const built = await buildReleaseReport(db, scanId, { artifacts })
    const ins = await db.query(
      `INSERT INTO release_reports (scan_id, project_id, tag, commit_sha, previous_scan_id, report, report_sha256, status)
       VALUES ($1, $2, $3, $4, $5, $6, $7, 'pending') ON CONFLICT (scan_id) DO NOTHING`,
      [scanId, meta.project_id, built.tag, built.commitSha, built.previousScanId, JSON.stringify(built.report), built.sha256])
    if (!ins.rowCount) return 'requested'
    // La forme rangée en base (jsonb) doit redonner exactement les mêmes octets.
    const stored = (await db.query<{ report: unknown }>('SELECT report FROM release_reports WHERE scan_id = $1', [scanId])).rows[0]
    if (!stored || sha256Hex(canonicalBytes(stored.report)) !== built.sha256) throw new ReleaseReportError('E_RELEASE_TOO_LARGE')
    await requestReportSignature(db, scanId, built.bytes, built.sha256, 1, requestsDir)
    return 'requested'
  }
  catch (err) {
    const code = err instanceof ReleaseReportError ? err.code : 'E_RELEASE_BUILD'
    console.error(`[release] report of scan ${scanId}: ${code} ${(err as Error)?.message ?? ''}`)
    // Le rapport reste en erreur (statut bloquant) : jamais de favorable sans preuve.
    const stub = { schema: REPORT_SCHEMA, scan_id: scanId, error: code }
    await db.query(
      `INSERT INTO release_reports (scan_id, project_id, tag, commit_sha, report, report_sha256, status, error)
       VALUES ($1, $2, $3, $4, $5, $6, 'error', $7)
       ON CONFLICT (scan_id) DO UPDATE SET status = 'error', error = EXCLUDED.error WHERE release_reports.status = 'pending'`,
      [scanId, meta.project_id, meta.tag, meta.commit_sha, JSON.stringify(stub), sha256Hex(canonicalBytes(stub)), code]).catch(() => {})
    return 'error'
  }
}

/** Rapports signés ou en erreur dont l'issue n'a pas encore été publiée. */
async function reportsToFinalize(db: Queryable): Promise<{ scan_id: string, project_id: string, status: string, report_sha256: string, verdict: string }[]> {
  const r = await db.query<{ scan_id: string, project_id: string, status: string, report_sha256: string, verdict: string }>(
    `SELECT rr.scan_id::text, rr.project_id::text, rr.status, rr.report_sha256, s.verdict FROM release_reports rr JOIN scans s ON s.id = rr.scan_id
      WHERE rr.status IN ('signed', 'error') AND rr.created_at > now() - interval '7 days'
        AND NOT EXISTS (SELECT 1 FROM audit_log a WHERE a.action = '${EMITTED}' AND a.target_type = 'scan' AND a.target_id = rr.scan_id::text)
      ORDER BY rr.created_at LIMIT ${FINALIZE_PER_TICK}`)
  return r.rows
}

/** Publication d'un rapport signé (ou en erreur), puis contrat 40, une seule fois. */
export async function finalizeRelease(db: Queryable, row: { scan_id: string, project_id: string, status: string, report_sha256: string, verdict: string }): Promise<void> {
  // La marque d'abord : un redémarrage au milieu ne rejoue jamais un déploiement.
  await writeAudit(db, { actor: { type: 'system' }, action: EMITTED, outcome: 'success', targetType: 'scan', targetId: row.scan_id, details: { verdict: row.verdict, report: row.status, sha256: row.status === 'signed' ? row.report_sha256 : null } })
  await publishReleaseGate(db, row.scan_id)
  if (row.status !== 'signed') return
  await uploadReleaseAssets(db, row.scan_id).catch(() => {})
  await enqueueAiTask(db, { kind: 'release-notes', subjectType: 'release', subjectId: row.scan_id, projectId: row.project_id, priority: 10 }).catch(() => null)
  await emitReleaseVerdict(db, { scanId: row.scan_id, projectId: row.project_id, verdict: row.verdict as 'passed', reportSha256: row.report_sha256 })
}

/** Contrat 40 pour les branches configurées : analyses de la branche principale d'un projet qui a une cible « branch ». */
async function emitBranchVerdicts(db: Queryable): Promise<number> {
  const r = await db.query<{ id: string, project_id: string, verdict: string }>(
    `SELECT s.id::text, s.project_id::text, s.verdict FROM scans s JOIN projects p ON p.id = s.project_id
      WHERE s.verdict IS NOT NULL AND s.status IN ('done', 'error') AND s.pull_request IS NULL AND s.ref = p.default_branch
        AND s.trigger IN ('manual', 'schedule', 'commit', 'webhook', 'api') AND s.finished_at > now() - interval '2 days'
        AND EXISTS (SELECT 1 FROM deploy_targets t WHERE t.project_id = s.project_id AND t.on_trigger = 'branch' AND t.enabled)
        AND NOT EXISTS (SELECT 1 FROM audit_log a WHERE a.action = '${EMITTED}' AND a.target_type = 'scan' AND a.target_id = s.id::text)
      ORDER BY s.finished_at LIMIT ${FINALIZE_PER_TICK}`)
  for (const s of r.rows) {
    await writeAudit(db, { actor: { type: 'system' }, action: EMITTED, outcome: 'success', targetType: 'scan', targetId: s.id, details: { verdict: s.verdict, report: null, branch: true } })
    await emitReleaseVerdict(db, { scanId: s.id, projectId: s.project_id, verdict: s.verdict as 'passed', reportSha256: null })
  }
  return r.rows.length
}

/** I6 : notes terminées jointes à la release de la forge (annexe non signée), une fois ; NOTES_ATTEMPTS essais au plus. */
async function uploadNotes(db: Queryable): Promise<void> {
  const r = await db.query<{ scan_id: string, project_id: string, tag: string }>(
    `SELECT rr.scan_id::text, rr.project_id::text, rr.tag FROM release_reports rr
      WHERE rr.status = 'signed' AND rr.created_at > now() - interval '7 days'
        AND EXISTS (SELECT 1 FROM ai_tasks t WHERE t.kind = 'release-notes' AND t.subject_type = 'release' AND t.subject_id = rr.scan_id::text AND t.status = 'done')
        AND NOT EXISTS (SELECT 1 FROM audit_log a WHERE a.action = 'release.notes.uploaded' AND a.target_type = 'scan' AND a.target_id = rr.scan_id::text AND a.outcome = 'success')
        AND (SELECT count(*) FROM audit_log a WHERE a.action = 'release.notes.uploaded' AND a.target_type = 'scan' AND a.target_id = rr.scan_id::text) < ${NOTES_ATTEMPTS}
      LIMIT 3`)
  for (const x of r.rows) {
    const md = await notesMarkdown(db, x.scan_id)
    let outcome = 'skipped'
    if (md) {
      const ctx = await projectForge(db, x.project_id).catch(() => null)
      if (ctx) {
        outcome = await releaseForge(await forgeAccess(db, ctx.forge)).uploadAsset(ctx.repo, x.tag, 'scanoria-security-notes.md', Buffer.from(md, 'utf8'), 'text/markdown')
          .catch(() => 'error')
      }
    }
    await writeAudit(db, { actor: { type: 'system' }, action: 'release.notes.uploaded', outcome: outcome === 'error' ? 'failure' : 'success', targetType: 'scan', targetId: x.scan_id, details: { outcome } })
  }
}

let running = false

/** Une passe ; ne lève jamais. */
export async function releaseTick(db: Queryable, requestsDir: string, log: (m: string) => void = console.warn): Promise<void> {
  if (running) return
  running = true
  try {
    await applySignatureResults(db, await applianceKey(), requestsDir)
    for (const id of await scansToPrepare(db)) await prepareReport(db, id, requestsDir)
    for (const row of await reportsToFinalize(db)) await finalizeRelease(db, row)
    await emitBranchVerdicts(db)
    await uploadNotes(db)
  }
  catch (err) {
    log(`[release] ${(err as Error).message}`)
  }
  finally {
    running = false
  }
}
