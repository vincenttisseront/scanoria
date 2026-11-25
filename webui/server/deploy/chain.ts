// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// J16 (0.8, chantier D) : vue de la chaîne d'un projet, en lecture seule.
// PR analysées (verdict, fusion automatique de la forge activée ou non),
// releases analysées (verdict, rapport signé), puis attestations et
// déploiements de chaque analyse. Chaque étape porte son état ; la première
// étape défavorable arrête la chaîne et sa raison est affichée (I9, J15).

import type { Queryable } from '../utils/db'
import { listAttestations, type AttestationRow } from '../attest'
import { AUTOMERGE_ACTION } from './autonomous'
import { listDeployments, type DeploymentRow } from './runs'

export interface ChainPr {
  scan_id: string
  number: number | null
  verdict: string | null
  status: string
  finished_at: string | null
  auto_merge: string | null
}

export interface ChainRelease {
  scan_id: string
  tag: string | null
  commit_sha: string | null
  verdict: string | null
  status: string
  report_status: string | null
  finished_at: string | null
  /** Raisons du verdict (I9), quand il n'est pas favorable. */
  reasons: unknown[]
  attestations: Omit<AttestationRow, 'envelope'>[]
  deployments: DeploymentRow[]
}

export interface Chain {
  autonomous: boolean
  pull_requests: ChainPr[]
  releases: ChainRelease[]
}

const TS = (c: string) => `to_char(${c} AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"')`

export async function projectChain(db: Queryable, projectId: string, limit = 10): Promise<Chain> {
  const p = await db.query<{ autonomous_chain: boolean }>('SELECT autonomous_chain FROM projects WHERE id = $1', [projectId])
  const prs = await db.query<ChainPr>(
    `SELECT s.id::text AS scan_id, (s.pull_request ->> 'number')::int AS number, s.verdict, s.status, ${TS('s.finished_at')} AS finished_at,
            (SELECT a.details ->> 'result' FROM audit_log a WHERE a.action = $3 AND a.target_type = 'scan' AND a.target_id = s.id::text
              ORDER BY a.id DESC LIMIT 1) AS auto_merge
       FROM scans s WHERE s.project_id = $1 AND s.pull_request IS NOT NULL AND (s.pull_request ->> 'number') ~ '^[0-9]{1,9}$'
      ORDER BY s.created_at DESC LIMIT $2`, [projectId, limit, AUTOMERGE_ACTION])
  const rel = await db.query<Omit<ChainRelease, 'attestations' | 'deployments'>>(
    `SELECT s.id::text AS scan_id, COALESCE(rr.tag, rc.tag) AS tag, s.commit_sha, s.verdict, s.status, rr.status AS report_status,
            ${TS('s.finished_at')} AS finished_at,
            CASE WHEN s.verdict IS DISTINCT FROM 'passed' THEN COALESCE(s.verdict_details -> 'reasons', '[]'::jsonb) ELSE '[]'::jsonb END AS reasons
       FROM scans s
       LEFT JOIN release_reports rr ON rr.scan_id = s.id
       LEFT JOIN release_candidates rc ON rc.scan_id = s.id
      WHERE s.project_id = $1 AND s.pull_request IS NULL
        AND (s.trigger = 'release' OR rc.scan_id IS NOT NULL OR EXISTS (SELECT 1 FROM deployments d WHERE d.scan_id = s.id))
      ORDER BY s.created_at DESC LIMIT $2`, [projectId, limit])
  const releases: ChainRelease[] = []
  for (const r of rel.rows) {
    const atts = (await listAttestations(db, r.scan_id)).map(({ envelope: _e, ...a }) => a)
    releases.push({ ...r, reasons: Array.isArray(r.reasons) ? r.reasons.slice(0, 20) : [], attestations: atts, deployments: await listDeployments(db, { scanId: r.scan_id }) })
  }
  return { autonomous: p.rows[0]?.autonomous_chain === true, pull_requests: prs.rows, releases }
}
