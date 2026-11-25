// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Quality gates en base (table gates) : liste, détail, création par copie,
// édition des règles, suppression d'un gate inutilisé, affectation à un projet.

import { z } from 'zod'
import type { Queryable } from '../utils/db'
import { GateRules, SLUG_RE } from '#shared/analysis'

/** Caractère de contrôle (U+0000–U+001F, U+007F). */
function hasControl(v: string): boolean {
  for (const ch of v) {
    const c = ch.codePointAt(0)!
    if (c < 0x20 || c === 0x7f) return true
  }
  return false
}

/** Référence Git admissible (git check-ref-format, plus un SHA) : jamais d'option ni d'espace. */
export function validRef(r: string): boolean {
  return !hasControl(r) && !/[\s~^:?*[\\]/.test(r) && !r.includes('..') && !r.includes('@{')
    && !r.startsWith('-') && !r.startsWith('/') && !r.endsWith('/') && !r.endsWith('.lock') && !r.endsWith('.')
}

export const gateCreateSchema = z.strictObject({
  slug: z.string().regex(SLUG_RE),
  copy_from: z.string().uuid().optional(),
})
export const gateUpdateSchema = z.strictObject({
  rules: GateRules,
  /** I19 (0.8) : proposition de l'IA d'où viennent les règles ; gardée dans l'audit (« proposé par IA »). */
  ai_task_id: z.string().uuid().optional(),
})
export const gateAssignSchema = z.strictObject({ project_id: z.string().uuid() })
export const tokenCreateSchema = z.strictObject({
  name: z.string().trim().min(1).max(100).refine(v => !hasControl(v), { message: 'control characters' }),
  expires_in_days: z.number().int().min(1).max(3650).nullable().optional(),
})
export const scanCreateSchema = z.strictObject({
  ref: z.string().min(1).max(255).refine(validRef, { message: 'invalid ref' }),
  profile: z.string().regex(SLUG_RE).optional(),
})
export const badgeUpdateSchema = z.strictObject({ enabled: z.boolean() })

export interface GateRow {
  id: string
  slug: string
  builtin: boolean
  rules: GateRules
  created_at: string
  updated_at: string
  updated_by_username: string | null
  projects: number
}

const COLUMNS = `g.id, g.slug, g.builtin, g.rules,
  to_char(g.created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS created_at,
  to_char(g.updated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS updated_at,
  u.username AS updated_by_username,
  (SELECT count(*)::int FROM projects p WHERE p.gate_id = g.id AND p.archived_at IS NULL) AS projects`

export async function listGates(db: Queryable): Promise<GateRow[]> {
  const res = await db.query<GateRow>(
    `SELECT ${COLUMNS} FROM gates g LEFT JOIN users u ON u.id = g.updated_by ORDER BY g.builtin DESC, g.slug`,
  )
  return res.rows
}

export async function getGate(db: Queryable, id: string): Promise<GateRow | null> {
  const res = await db.query<GateRow>(`SELECT ${COLUMNS} FROM gates g LEFT JOIN users u ON u.id = g.updated_by WHERE g.id = $1`, [id])
  return res.rows[0] ?? null
}

export async function gateProjects(db: Queryable, id: string): Promise<{ id: string, slug: string, name: string }[]> {
  const res = await db.query<{ id: string, slug: string, name: string }>(
    'SELECT id, slug, name FROM projects WHERE gate_id = $1 AND archived_at IS NULL ORDER BY name LIMIT 500',
    [id],
  )
  return res.rows
}

export class SlugTakenError extends Error {}

/** Crée un gate en copiant les règles d'un autre (par défaut « defaut »). */
export async function createGate(db: Queryable, p: { slug: string, copyFrom?: string, userId: number }): Promise<GateRow | null> {
  try {
    const res = await db.query<{ id: string }>(
      `INSERT INTO gates (slug, builtin, rules, updated_by)
       SELECT $1, false, src.rules, $3 FROM gates src
        WHERE ($2::uuid IS NULL AND src.slug = 'defaut') OR src.id = $2::uuid
        LIMIT 1
       RETURNING id`,
      [p.slug, p.copyFrom ?? null, p.userId],
    )
    if (!res.rows[0]) return null
    return getGate(db, res.rows[0].id)
  }
  catch (err) {
    if ((err as { code?: string }).code === '23505') throw new SlugTakenError()
    throw err
  }
}

export async function updateGateRules(db: Queryable, id: string, rules: GateRules, userId: number): Promise<GateRow | null> {
  const res = await db.query('UPDATE gates SET rules = $2, updated_at = now(), updated_by = $3 WHERE id = $1', [id, JSON.stringify(rules), userId])
  if (!res.rowCount) return null
  return getGate(db, id)
}

/** Suppression : jamais un gate intégré, jamais un gate référencé (projets ou analyses). */
export async function deleteGate(db: Queryable, id: string): Promise<'deleted' | 'not-found' | 'builtin' | 'in-use'> {
  const g = await db.query<{ builtin: boolean, used: boolean }>(
    `SELECT builtin, EXISTS (SELECT 1 FROM projects WHERE gate_id = $1) OR EXISTS (SELECT 1 FROM scans WHERE gate_id = $1) AS used
       FROM gates WHERE id = $1`,
    [id],
  )
  const row = g.rows[0]
  if (!row) return 'not-found'
  if (row.builtin) return 'builtin'
  if (row.used) return 'in-use'
  await db.query('DELETE FROM gates WHERE id = $1', [id])
  return 'deleted'
}

export interface ProjectRef {
  id: string
  slug: string
  name: string
  gate_id: string
  archived: boolean
  badge_enabled: boolean
  default_branch: string | null
}

export async function getProjectRef(db: Queryable, id: string): Promise<ProjectRef | null> {
  const res = await db.query<ProjectRef>(
    `SELECT id, slug, name, gate_id, archived_at IS NOT NULL AS archived, badge_enabled, default_branch
       FROM projects WHERE id = $1`,
    [id],
  )
  return res.rows[0] ?? null
}

export async function assignGate(db: Queryable, gateId: string, projectId: string): Promise<{ from: string } | null> {
  const res = await db.query<{ from: string }>(
    `UPDATE projects p SET gate_id = $1 FROM (SELECT id, gate_id FROM projects WHERE id = $2 FOR UPDATE) old
      WHERE p.id = old.id RETURNING old.gate_id AS from`,
    [gateId, projectId],
  )
  return res.rows[0] ?? null
}
