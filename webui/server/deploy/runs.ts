// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Contrat 40 → J11–J13 (0.8, chantier D) : une exécution (`deployments`) par
// cible et par analyse, créée une seule fois. Rien ne part si le verdict n'est
// pas « passed » : le refus est enregistré avec sa raison. Une cible
// désactivée ou un projet suspendu (ou archivé) refuse de même.

import type { Queryable } from '../utils/db'
import { parseConfig, type DeployKind } from './config'

export type RefusedReason = 'verdict-not-passed' | 'target-disabled' | 'project-suspended'
export type DeploymentStatus = 'pending' | 'running' | 'succeeded' | 'failed' | 'refused'

export interface VerdictEvent {
  scanId: string
  projectId: string
  verdict: string | null
  reportSha256: string | null
}

export interface DeploymentRow {
  id: string
  target_id: string
  scan_id: string
  kind: DeployKind
  environment: string
  status: DeploymentStatus
  refused_reason: RefusedReason | null
  external_id: string | null
  external_url: string | null
  error: string | null
  created_at: string
  finished_at: string | null
}

export const DEPLOYMENT_COLUMNS = `d.id::text, d.target_id::text, d.scan_id::text, t.kind, t.environment, d.status, d.refused_reason,
  d.external_id, d.external_url, d.error,
  to_char(d.created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS created_at,
  to_char(d.finished_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS finished_at`

/** Analyses qu'une cible prend en compte : release (contrat 40) ou branche configurée. */
const SCAN_MATCH = `s.project_id = t.project_id AND s.queued_at >= t.created_at AND s.pull_request IS NULL
  AND s.status = 'done' AND s.verdict IS NOT NULL
  AND ((t.on_trigger = 'release' AND (s.trigger = 'release' OR EXISTS (SELECT 1 FROM release_candidates rc WHERE rc.scan_id = s.id)))
    OR (t.on_trigger = 'branch' AND s.trigger IN ('manual', 'schedule', 'commit', 'webhook', 'api')
        AND t.config ->> 'branch' IS NOT NULL AND s.ref IN (t.config ->> 'branch', 'refs/heads/' || (t.config ->> 'branch'))))`

interface CandidateRow {
  target_id: string
  scan_id: string
  kind: DeployKind
  config: unknown
  enabled: boolean
  suspended: boolean
  verdict: string | null
  on_trigger: string
  report_status: string | null
  report_age_s: number | null
}

/** Raison d'un refus, ou null si l'exécution peut partir. */
export function refusalOf(input: { verdict: string | null, enabled: boolean, suspended: boolean }): RefusedReason | null {
  if (!input.enabled) return 'target-disabled'
  if (input.suspended) return 'project-suspended'
  if (input.verdict !== 'passed') return 'verdict-not-passed'
  return null
}

/**
 * Crée les exécutions d'une analyse (ou de toutes les analyses récentes sans
 * exécution si scanId est omis). Une release attend la signature de son
 * rapport (contrat 40) ; un rapport en erreur fait échouer l'exécution.
 * Rend les exécutions créées.
 */
export async function createDeployments(db: Queryable, scanId?: string): Promise<{ id: string, status: DeploymentStatus }[]> {
  const r = await db.query<CandidateRow>(
    `SELECT t.id::text AS target_id, s.id::text AS scan_id, t.kind, t.config, t.enabled,
            (p.suspended_at IS NOT NULL OR p.archived_at IS NOT NULL) AS suspended, s.verdict, t.on_trigger,
            rr.status AS report_status, extract(epoch FROM now() - s.finished_at)::int AS report_age_s
       FROM deploy_targets t
       JOIN projects p ON p.id = t.project_id
       JOIN scans s ON ${SCAN_MATCH}
       LEFT JOIN release_reports rr ON rr.scan_id = s.id
      WHERE ($1::uuid IS NULL OR s.id = $1::uuid)
        AND s.finished_at > now() - interval '7 days'
        AND NOT EXISTS (SELECT 1 FROM deployments d WHERE d.target_id = t.id AND d.scan_id = s.id)
      ORDER BY s.finished_at
      LIMIT 200`, [scanId ?? null])
  const created: { id: string, status: DeploymentStatus }[] = []
  for (const x of r.rows) {
    const refused = refusalOf({ verdict: x.verdict, enabled: x.enabled, suspended: x.suspended })
    let status: DeploymentStatus = refused ? 'refused' : 'pending'
    let error: string | null = null
    if (!refused && x.on_trigger === 'release' && x.report_status !== 'signed') {
      // Rapport pas encore signé : on attend (1 h au plus), sans rien créer.
      if (x.report_status !== 'error' && (x.report_age_s ?? 0) < 3600) continue
      status = 'failed'
      error = 'E_DEPLOY_REPORT'
    }
    if (!refused && !parseConfig(x.kind, x.config)) {
      status = 'failed'
      error = 'E_DEPLOY_CONFIG'
    }
    const ins = await db.query<{ id: string }>(
      `INSERT INTO deployments (target_id, scan_id, status, refused_reason, error, finished_at)
       VALUES ($1, $2, $3, $4, $5, CASE WHEN $3 IN ('refused', 'failed') THEN now() END)
       ON CONFLICT (target_id, scan_id) DO NOTHING RETURNING id::text`,
      [x.target_id, x.scan_id, status, refused, error])
    if (ins.rows[0]) created.push({ id: ins.rows[0].id, status })
  }
  return created
}

export async function listDeployments(db: Queryable, filter: { scanId?: string, projectId?: string, limit?: number }): Promise<DeploymentRow[]> {
  const r = await db.query<DeploymentRow>(
    `SELECT ${DEPLOYMENT_COLUMNS} FROM deployments d JOIN deploy_targets t ON t.id = d.target_id
      WHERE ($1::uuid IS NULL OR d.scan_id = $1::uuid) AND ($2::uuid IS NULL OR t.project_id = $2::uuid)
      ORDER BY d.created_at DESC, t.kind LIMIT $3`,
    [filter.scanId ?? null, filter.projectId ?? null, Math.min(filter.limit ?? 100, 500)])
  return r.rows
}

/** Passe une exécution à l'état final (une seule fois). */
export async function finishDeployment(db: Queryable, id: string, status: 'succeeded' | 'failed', fields: { error?: string | null, externalId?: string | null, externalUrl?: string | null } = {}): Promise<void> {
  await db.query(
    `UPDATE deployments SET status = $2, error = $3, external_id = COALESCE($4, external_id),
            external_url = COALESCE($5, external_url), finished_at = now()
      WHERE id = $1 AND status IN ('pending', 'running')`,
    [id, status, fields.error?.slice(0, 1000) ?? null, fields.externalId ?? null, safeUrl(fields.externalUrl)])
}

/** Réserve une exécution (pending → running) ; faux si une autre passe l'a déjà prise. */
export async function claimDeployment(db: Queryable, id: string, externalId: string | null = null): Promise<boolean> {
  const r = await db.query(`UPDATE deployments SET status = 'running', external_id = COALESCE($2, external_id) WHERE id = $1 AND status = 'pending'`, [id, externalId])
  return (r.rowCount ?? 0) > 0
}

export async function setExternal(db: Queryable, id: string, externalId: string | null, externalUrl: string | null): Promise<void> {
  await db.query(`UPDATE deployments SET external_id = COALESCE($2, external_id), external_url = COALESCE($3, external_url) WHERE id = $1`,
    [id, externalId, safeUrl(externalUrl)])
}

export function safeUrl(u: string | null | undefined): string | null {
  return u && /^https:\/\/[^\s]{1,490}$/.test(u) ? u : null
}
