// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Lectures de la page Release et des routes /api/releases/** : rapport et son
// état de signature, comparaison F2 détaillée (titres lus en base, liens vers
// les résultats), publications dans la forge (audit), fichiers disponibles.
// Erreurs à code stable E_RELEASE_* (traduites sous releases.errors.*).

import { createError } from 'h3'
import type { Queryable } from '../utils/db'
import { forgeAccess } from '../forges/index'
import { projectForge } from '../forges/context'
import { isSafeTag, releaseForge } from '../forges/release'
import { compareScans } from './compare'
import { readArtifact } from './artifacts'
import { GATE_CONTEXT, gateState } from './gate'
import { forgeLocale } from '../forges/publish'

export type ReleaseErrorCode = 'E_RELEASE_NOT_FOUND' | 'E_RELEASE_NOT_SIGNED' | 'E_RELEASE_MODE' | 'E_RELEASE_TAG'
  | 'E_RELEASE_TAG_MOVED' | 'E_RELEASE_COMMIT' | 'E_RELEASE_PROJECT'

export function releaseError(statusCode: number, code: ReleaseErrorCode, extra: Record<string, unknown> = {}) {
  return createError({ statusCode, statusMessage: code, data: { code, ...extra } })
}

export interface ReleaseRow {
  scan_id: string
  project_id: string
  project_slug: string
  project_name: string
  tag: string
  commit_sha: string
  previous_scan_id: string | null
  report: Record<string, unknown>
  report_sha256: string
  status: 'pending' | 'signed' | 'error'
  signature: string | null
  key_fingerprint: string | null
  error: string | null
  created_at: string
  signed_at: Date | null
  scan_number: number
  scan_status: string
  verdict: string | null
  verdict_details: unknown
  source: string | null
}

export async function getRelease(db: Queryable, scanId: string): Promise<ReleaseRow | null> {
  const r = await db.query<ReleaseRow>(
    `SELECT rr.scan_id::text, rr.project_id::text, p.slug AS project_slug, p.name AS project_name, rr.tag, rr.commit_sha,
            rr.previous_scan_id::text, rr.report, rr.report_sha256, rr.status, rr.signature, rr.key_fingerprint, rr.error,
            to_char(rr.created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS created_at, rr.signed_at,
            s.number AS scan_number, s.status AS scan_status, s.verdict, s.verdict_details, rc.source
       FROM release_reports rr JOIN scans s ON s.id = rr.scan_id JOIN projects p ON p.id = rr.project_id
       LEFT JOIN release_candidates rc ON rc.scan_id = rr.scan_id
      WHERE rr.scan_id = $1 LIMIT 1`, [scanId])
  return r.rows[0] ?? null
}

/** Analyse de release encore sans rapport (en file, en cours, ou rapport en préparation). */
async function candidate(db: Queryable, scanId: string) {
  const r = await db.query<{ project_id: string, tag: string, commit_sha: string, source: string, scan_status: string, verdict: string | null, scan_number: number }>(
    `SELECT rc.project_id::text, rc.tag, rc.commit_sha, rc.source, s.status AS scan_status, s.verdict, s.number AS scan_number
       FROM release_candidates rc JOIN scans s ON s.id = rc.scan_id WHERE rc.scan_id = $1 LIMIT 1`, [scanId])
  return r.rows[0] ?? null
}

async function publications(db: Queryable, scanId: string) {
  const r = await db.query<{ action: string, outcome: string, details: Record<string, unknown>, at: string }>(
    `SELECT DISTINCT ON (action) action, outcome, details, to_char(occurred_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS at
       FROM audit_log WHERE target_type = 'scan' AND target_id = $1
        AND action IN ('release.gate.published', 'release.assets', 'release.notes.uploaded', 'release.verdict.emitted')
      ORDER BY action, occurred_at DESC`, [scanId])
  return Object.fromEntries(r.rows.map(x => [x.action.replace(/^release\./, ''), { outcome: x.outcome, details: x.details, at: x.at }]))
}

/** Vue de la page Release d'une analyse ; null si l'analyse n'est pas une release. */
export async function releaseView(db: Queryable, scanId: string) {
  const rel = await getRelease(db, scanId)
  if (!rel) {
    const c = await candidate(db, scanId)
    if (!c) return null
    return {
      scan_id: scanId, project_id: c.project_id, tag: c.tag, commit_sha: c.commit_sha, source: c.source, scan_number: c.scan_number,
      scan_status: c.scan_status, verdict: c.verdict, report: null, report_status: null, gate_context: GATE_CONTEXT,
      gate: gateState({ tag: c.tag, verdict: c.verdict, verdict_details: null, scan_status: c.scan_status, report_status: null }, forgeLocale()),
      publications: await publications(db, scanId), files: {}, comparison: null,
    }
  }
  const files = Object.fromEntries(await Promise.all((['results.sarif', 'sbom.cdx.json'] as const).map(async n => [n, !!(await readArtifact(scanId, n))])))
  const comparison = rel.previous_scan_id ? await compareScans(db, rel.previous_scan_id, scanId) : null
  const signedVerdict = (rel.report.verdict as { value?: string } | undefined)?.value ?? null
  return {
    scan_id: scanId,
    project_id: rel.project_id,
    project_slug: rel.project_slug,
    project_name: rel.project_name,
    tag: rel.tag,
    commit_sha: rel.commit_sha,
    source: rel.source,
    scan_number: rel.scan_number,
    scan_status: rel.scan_status,
    verdict: rel.verdict,
    /** Verdict inscrit dans le rapport signé ; différent si une exception l'a changé depuis. */
    signed_verdict: signedVerdict,
    report: rel.report,
    report_status: rel.status,
    report_sha256: rel.report_sha256,
    key_fingerprint: rel.key_fingerprint,
    signed_at: rel.signed_at ? new Date(rel.signed_at).toISOString() : null,
    error: rel.error,
    previous_scan_id: rel.previous_scan_id,
    comparison,
    gate_context: GATE_CONTEXT,
    gate: gateState({ tag: rel.tag, verdict: rel.verdict, verdict_details: rel.verdict_details, scan_status: rel.scan_status, report_status: rel.status }, forgeLocale()),
    publications: await publications(db, scanId),
    files: { 'report.json': rel.status === 'signed', ...files },
  }
}

/** Releases d'un projet (les plus récentes d'abord), pour choisir la comparaison. */
export async function listReleases(db: Queryable, projectId: string, limit = 50) {
  const r = await db.query(
    `SELECT rc.scan_id::text, rc.tag, rc.commit_sha, rc.source, s.number AS scan_number, s.status AS scan_status, s.verdict,
            rr.status AS report_status, to_char(rc.seen_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS seen_at
       FROM release_candidates rc LEFT JOIN scans s ON s.id = rc.scan_id LEFT JOIN release_reports rr ON rr.scan_id = rc.scan_id
      WHERE rc.project_id = $1 ORDER BY rc.seen_at DESC LIMIT $2`, [projectId, limit])
  return r.rows
}

/** Commit d'un tag lu dans la forge du projet (mode poussé), ou null sans accès à la forge. */
export async function tagCommit(db: Queryable, projectId: string, tag: string): Promise<string | null | 'absent'> {
  if (!isSafeTag(tag)) return 'absent'
  const ctx = await projectForge(db, projectId)
  if (!ctx) return null
  const tags = await releaseForge(await forgeAccess(db, ctx.forge)).tags(ctx.repo)
  return tags.find(t => t.name === tag)?.commit_sha ?? 'absent'
}
