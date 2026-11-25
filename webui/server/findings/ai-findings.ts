// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Résultats des modules d'analyse par IA (0.7, contrat 32 ; CLAUDE.md § 3.5,
// K1–K10). Un module relié au relais IA (scan.network: ai-relay) produit des
// résultats origin = 'ai' : badge « IA », niveau informatif (gravité `info`,
// la gravité native gardée et rendue à la confirmation), avec le modèle et
// son empreinte, et **hors verdict** tant qu'une personne ne les a pas
// confirmés. Confirmer est réservé à une personne humaine (users.kind =
// 'human') de rôle operator ou plus ; c'est tracé dans l'audit, et le résultat
// devient alors un résultat normal. L'IA, un jeton d'API, un jeton de CI ou un
// compte « agent » ou « bot » ne confirment jamais.
//
// Retours I24 : le tri d'une personne sur un résultat IA (confirmé, ou faux
// positif) est la mesure de l'accord IA/humain, par module et par modèle.

import type { Queryable } from '../utils/db'
import { parseModelLabel } from '../ai/models'
import { readModuleHints } from './manifest'
import { resolveSeverities } from './severity'

/** Ce que le gate lit d'un résultat pour décider s'il compte (contrat 32). */
export interface AiOriginFields {
  origin?: string | null
  ai_confirmed_at?: string | Date | null
}

/** Résultat d'un module d'IA pas encore confirmé par une personne : hors verdict. */
export function isUnconfirmedAi(f: AiOriginFields): boolean {
  return f.origin === 'ai' && !f.ai_confirmed_at
}

/**
 * Résultats retenus pour le verdict : les résultats IA non confirmés sont
 * écartés avant tout le reste (même un avis MAL- qu'un modèle aurait cité
 * n'entre pas dans H4 sans confirmation humaine).
 */
export function excludeUnconfirmedAi<F extends AiOriginFields>(findings: F[]): { kept: F[], excluded: number } {
  const kept: F[] = []
  let excluded = 0
  for (const f of findings) {
    if (isUnconfirmedAi(f)) excluded++
    else kept.push(f)
  }
  return { kept, excluded }
}

export class AiFindingError extends Error {
  constructor(public readonly code: 'E_NOT_FOUND' | 'E_NOT_AI' | 'E_NOT_HUMAN' | 'E_ALREADY_CONFIRMED') {
    super(code)
  }
}

export interface AiFindingInfo {
  id: string
  project_id: string
  origin: string
  tool: string
  confirmed: boolean
  confirmed_at: string | null
  confirmed_by: string | null
  /** Modèle et début de son empreinte, relevés dans le journal du relais de la dernière analyse. */
  model: string | null
  digest: string | null
}

/** Modèle(s) qui ont servi au module dans l'analyse qui a vu le résultat en dernier. */
async function modelOf(db: Queryable, findingId: string): Promise<{ model: string, digest: string | null } | null> {
  const { rows } = await db.query<{ model: string | null }>(
    `SELECT c.model
       FROM findings f
       JOIN scans s ON s.id = f.last_scan_id
       JOIN ai_calls c ON c.via = 'relay' AND c.module_id = f.tool AND c.project_id = f.project_id
                      AND c.outcome = 'ok' AND c.model IS NOT NULL
                      AND c.at >= COALESCE(s.started_at, s.queued_at) - interval '1 minute'
                      AND c.at <= COALESCE(s.finished_at, now()) + interval '1 minute'
      WHERE f.id = $1
      ORDER BY c.at DESC LIMIT 1`,
    [findingId],
  )
  return parseModelLabel(rows[0]?.model)
}

export async function getAiFinding(db: Queryable, id: string): Promise<AiFindingInfo> {
  const { rows } = await db.query<{ id: string, project_id: string, origin: string, tool: string, ai_confirmed_at: Date | null, confirmed_by: string | null }>(
    `SELECT f.id, f.project_id, f.origin, f.tool, f.ai_confirmed_at, u.username AS confirmed_by
       FROM findings f LEFT JOIN users u ON u.id = f.ai_confirmed_by
      WHERE f.id = $1`,
    [id],
  )
  const row = rows[0]
  if (!row) throw new AiFindingError('E_NOT_FOUND')
  const model = row.origin === 'ai' ? await modelOf(db, id) : null
  return {
    id: row.id,
    project_id: row.project_id,
    origin: row.origin,
    tool: row.tool,
    confirmed: row.ai_confirmed_at !== null,
    confirmed_at: row.ai_confirmed_at?.toISOString() ?? null,
    confirmed_by: row.confirmed_by,
    model: model?.model ?? null,
    digest: model?.digest ?? null,
  }
}

/**
 * Confirmation d'un résultat IA par une personne (contrat 32). Le rôle
 * (operator ou plus) est vérifié par la route ; ici : compte humain, résultat
 * IA, pas déjà confirmé. Renvoie l'état d'avant pour l'audit.
 */
export async function confirmAiFinding(db: Queryable, id: string, userId: number): Promise<{ project_id: string, tool: string }> {
  const user = await db.query<{ kind: string }>('SELECT kind FROM users WHERE id = $1', [userId])
  if (user.rows[0]?.kind !== 'human') throw new AiFindingError('E_NOT_HUMAN')
  const cur = await db.query<{ project_id: string, tool: string, origin: string, ai_confirmed_at: Date | null, native_severity: string | null }>(
    'SELECT project_id, tool, origin, ai_confirmed_at, native_severity FROM findings WHERE id = $1 FOR UPDATE',
    [id],
  )
  const row = cur.rows[0]
  if (!row) throw new AiFindingError('E_NOT_FOUND')
  if (row.origin !== 'ai') throw new AiFindingError('E_NOT_AI')
  if (row.ai_confirmed_at) throw new AiFindingError('E_ALREADY_CONFIRMED')
  // Informatif jusqu'ici (`info`) : il retrouve la gravité normalisée de sa gravité native.
  let severity: string | null = null
  if (row.native_severity) {
    const hints = await readModuleHints(row.tool)
    severity = (await resolveSeverities(db, row.tool, [row.native_severity], hints.severityMap)).get(row.native_severity) ?? null
  }
  await db.query(
    `UPDATE findings SET ai_confirmed_by = $2, ai_confirmed_at = now(), updated_at = now(),
            severity = COALESCE($3, severity),
            status = CASE WHEN status = 'new' THEN 'confirmed' ELSE status END,
            status_by = CASE WHEN status = 'new' THEN $2 ELSE status_by END,
            status_at = CASE WHEN status = 'new' THEN now() ELSE status_at END
      WHERE id = $1`,
    [id, userId, severity],
  )
  return { project_id: row.project_id, tool: row.tool }
}

export interface AiModuleAgreement {
  module: string
  /** Résultats IA vus pendant la période. */
  total: number
  confirmed: number
  rejected: number
  pending: number
  /** Part confirmée parmi les résultats tranchés par une personne (0–1), null sans tri. */
  rate: number | null
}

/** I24 : accord IA/humain par module d'analyse par IA, sur une période (90 jours par défaut). */
export async function aiModuleAgreement(db: Queryable, days = 90): Promise<AiModuleAgreement[]> {
  const { rows } = await db.query<{ module: string, total: number, confirmed: number, rejected: number }>(
    `SELECT tool AS module, count(*)::int AS total,
            count(*) FILTER (WHERE ai_confirmed_at IS NOT NULL)::int AS confirmed,
            count(*) FILTER (WHERE ai_confirmed_at IS NULL AND status = 'false-positive' AND status_by IS NOT NULL)::int AS rejected
       FROM findings
      WHERE origin = 'ai' AND updated_at > now() - make_interval(days => $1)
      GROUP BY tool ORDER BY tool`,
    [days],
  )
  return rows.map((r) => {
    const decided = r.confirmed + r.rejected
    return { ...r, pending: r.total - decided, rate: decided ? Math.round((r.confirmed / decided) * 1000) / 1000 : null }
  })
}
