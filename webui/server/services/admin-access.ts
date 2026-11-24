// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Accès administrateur d'un module « service » mis en service par l'appliance
// (SonarQube, chantier B de la 0.4). Le mot de passe admin n'est jamais en
// base : la demande reset-service-admin le dépose une seule fois en mémoire
// vive (/run/scanoria/oneshot/<id de demande>.json, root:scanoria 0640) ; la
// console le lit une seule fois, pour l'administrateur qui a fait la demande,
// puis marque la demande « révélée » (helper_requests.output.revealed).

import { readFile } from 'node:fs/promises'
import { join } from 'node:path'
import type { Queryable } from '../utils/db'

/** Modules dont l'appliance gère le compte administrateur (provision.py). */
export const MANAGED_ADMIN_MODULES = ['sonarqube'] as const

export const ONESHOT_DIR = process.env.NUXT_ONESHOT_DIR || '/run/scanoria/oneshot'
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/
const PASSWORD_RE = /^[A-Za-z0-9#%+=_.-]{20,128}$/

export function managesAdmin(id: string): boolean {
  return (MANAGED_ADMIN_MODULES as readonly string[]).includes(id)
}

export type RevealOutcome
  = | { ok: true, login: string, password: string }
    | { ok: false, code: 'E_NOT_FOUND' | 'E_FORBIDDEN' | 'E_PRECONDITION' | 'E_GONE' }

/**
 * Révèle une seule fois le mot de passe déposé par la demande requestId.
 * La marque « révélée » est posée avant la lecture : une seconde lecture
 * échoue même si la première a été interrompue.
 */
export async function revealAdminPassword(db: Queryable, opts: { requestId: string, moduleId: string, userId: string, dir?: string }): Promise<RevealOutcome> {
  if (!UUID_RE.test(opts.requestId)) return { ok: false, code: 'E_NOT_FOUND' }
  const { rows } = await db.query<{ status: string, requested_by: string | null, module: string | null, revealed: boolean }>(
    `SELECT status, requested_by::text, params->>'id' AS module, COALESCE((output->>'revealed')::boolean, false) AS revealed
       FROM helper_requests WHERE id = $1 AND type = 'reset-service-admin'`, [opts.requestId])
  const row = rows[0]
  if (!row || row.module !== opts.moduleId) return { ok: false, code: 'E_NOT_FOUND' }
  if (row.requested_by !== opts.userId) return { ok: false, code: 'E_FORBIDDEN' }
  if (row.status !== 'ok') return { ok: false, code: 'E_PRECONDITION' }
  if (row.revealed) return { ok: false, code: 'E_GONE' }
  const marked = await db.query(
    `UPDATE helper_requests SET output = COALESCE(output, '{}'::jsonb) || '{"revealed": true}'::jsonb
      WHERE id = $1 AND COALESCE((output->>'revealed')::boolean, false) = false RETURNING id`, [opts.requestId])
  if (!marked.rowCount) return { ok: false, code: 'E_GONE' }
  let parsed: unknown
  try {
    const buf = await readFile(join(opts.dir ?? ONESHOT_DIR, `${opts.requestId}.json`))
    if (buf.length > 4096) return { ok: false, code: 'E_GONE' }
    parsed = JSON.parse(buf.toString('utf8'))
  }
  catch {
    // Fichier déjà purgé par le helper (10 minutes) ou machine redémarrée.
    return { ok: false, code: 'E_GONE' }
  }
  const password = (parsed as { password?: unknown } | null)?.password
  if (typeof password !== 'string' || !PASSWORD_RE.test(password)) return { ok: false, code: 'E_GONE' }
  return { ok: true, login: 'admin', password }
}
