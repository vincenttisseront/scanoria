// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// 0.7, chantier D (contrat 33, G18) : le quality gate d'une analyse de PR
// compare à la base de la PR (« nouveau code ») et non à l'analyse précédente
// de la même ref. Base : la dernière analyse réussie du commit de base, à
// défaut la dernière analyse réussie de la branche cible antérieure à la PR.
// Sans base analysée, tout est nouveau (prudence : un résultat n'est jamais
// déclaré ancien sans preuve). Un résultat de la PR est ancien s'il figure
// dans l'analyse de base.

import type { Queryable } from '../utils/db'

export interface PullRequestInfo {
  number: number
  base_sha: string
  base_ref?: string
  head_sha?: string
  head_ref?: string
  author?: string | null
}

/** Analyse de base d'une analyse de PR ; null si l'analyse n'est pas une PR ou si aucune base n'est analysée. */
export async function pullRequestBaseScan(db: Queryable, scanId: string): Promise<{ pr: PullRequestInfo, baseScanId: string | null } | null> {
  const r = await db.query<{ project_id: string, pull_request: PullRequestInfo | null, queued_at: Date }>(
    'SELECT project_id, pull_request, queued_at FROM scans WHERE id = $1', [scanId])
  const scan = r.rows[0]
  const pr = scan?.pull_request
  if (!scan || !pr || typeof pr.base_sha !== 'string') return null
  const base = await db.query<{ id: string }>(
    `SELECT id FROM scans
      WHERE project_id = $1 AND id <> $2 AND status = 'done' AND pull_request IS NULL
        AND trigger NOT IN ('trial', 'external', 'recorrelate')
        AND (commit_sha = $3 OR (commit_sha IS DISTINCT FROM $3 AND ref = $4 AND queued_at <= $5))
      ORDER BY (commit_sha = $3) DESC NULLS LAST, finished_at DESC NULLS LAST LIMIT 1`,
    [scan.project_id, scanId, pr.base_sha, typeof pr.base_ref === 'string' ? pr.base_ref : '', scan.queued_at])
  return { pr, baseScanId: base.rows[0]?.id ?? null }
}

/**
 * Fonction séparée d'evaluate.ts (contrat 33) : identifiants des résultats de
 * l'analyse déjà présents dans la base de la PR, ou null pour une analyse qui
 * n'est pas une PR (le calcul habituel de is_new s'applique alors).
 */
export async function pullRequestBaseline(db: Queryable, scanId: string): Promise<Set<string> | null> {
  const info = await pullRequestBaseScan(db, scanId)
  if (!info) return null
  if (!info.baseScanId) return new Set()
  const r = await db.query<{ finding_id: string }>(
    `SELECT sf.finding_id FROM scan_findings sf
      WHERE sf.scan_id = $1 AND EXISTS (SELECT 1 FROM scan_findings b WHERE b.scan_id = $2 AND b.finding_id = sf.finding_id)`,
    [scanId, info.baseScanId])
  return new Set(r.rows.map(x => x.finding_id))
}

/**
 * Enregistre la comparaison à la base dans scan_findings.is_new (affichage
 * « nouveau » de la console et du commentaire de PR) ; sans effet hors PR.
 */
export async function applyPullRequestBaseline(db: Queryable, scanId: string): Promise<boolean> {
  const old = await pullRequestBaseline(db, scanId)
  if (!old) return false
  await db.query(
    `UPDATE scan_findings SET is_new = NOT (finding_id = ANY($2::uuid[])) WHERE scan_id = $1`,
    [scanId, [...old]])
  return true
}
