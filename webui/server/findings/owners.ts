// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// F6 : responsables des résultats.
// - À l'ingestion, findings.owners reçoit les responsables lus dans le
//   CODEOWNERS de l'analyse (results/<tâche>/codeowners.txt, copié par le
//   runner sans rien exécuter) ; sans fichier, la liste est vidée.
// - owner_mappings relie un responsable (« @equipe », « @login », adresse) à
//   un compte de la console, pour tous les projets ou un seul ; éditable par
//   un administrateur, audité.
// - « Mes résultats » : résultats dont un responsable est relié au compte,
//   ou est son identifiant (« @identifiant ») ou son adresse.

import { lstat, open, realpath } from 'node:fs/promises'
import { join, sep } from 'node:path'
import { z } from 'zod'
import type { Queryable } from '../utils/db'
import { MAX_CODEOWNERS_BYTES, ownersFor, parseCodeowners, type ParsedCodeowners } from './codeowners'

export const CODEOWNERS_FILE = 'codeowners.txt'

/** Lit codeowners.txt d'un dossier de résultats : fichier ordinaire, sans lien, borné. null = absent ou refusé. */
export async function readCodeowners(resultDir: string): Promise<ParsedCodeowners | null> {
  let root: string
  try {
    root = await realpath(resultDir)
  }
  catch {
    return null
  }
  const full = join(root, CODEOWNERS_FILE)
  try {
    const st = await lstat(full)
    if (!st.isFile() || st.isSymbolicLink() || st.nlink > 1 || st.size > MAX_CODEOWNERS_BYTES) return null
    const real = await realpath(full)
    if (!real.startsWith(root + sep)) return null
    const fh = await open(real, 'r')
    try {
      if ((await fh.stat()).size > MAX_CODEOWNERS_BYTES) return null
      return parseCodeowners(await fh.readFile('utf8'))
    }
    finally {
      await fh.close()
    }
  }
  catch {
    return null
  }
}

/** Remplit findings.owners des résultats donnés (ingestion d'un module). */
export async function assignOwners(db: Queryable, projectId: string, findingIds: string[], parsed: ParsedCodeowners | null): Promise<number> {
  if (!findingIds.length) return 0
  const { rows } = await db.query<{ id: string, path: string | null }>(
    'SELECT id, path FROM findings WHERE project_id = $1 AND id = ANY($2::uuid[])', [projectId, findingIds])
  const updates = rows.map(r => ({ id: r.id, owners: parsed ? ownersFor(parsed, r.path) : [] }))
  if (!updates.length) return 0
  const res = await db.query(
    `UPDATE findings f SET owners = x.owners
       FROM jsonb_to_recordset($1::jsonb) AS x(id uuid, owners text[])
      WHERE f.id = x.id AND f.owners IS DISTINCT FROM x.owners`,
    [JSON.stringify(updates)],
  )
  return res.rowCount ?? 0
}

// ---------------------------------------------------------------- correspondances

export const ownerMappingSchema = z.strictObject({
  project_id: z.string().uuid().nullable(),
  owner: z.string().trim().min(1).max(255).regex(/^[^\s\0]+$/),
  user_id: z.number().int().positive(),
})
export type OwnerMappingInput = z.infer<typeof ownerMappingSchema>

export interface OwnerMappingRow {
  project_id: string | null
  project_slug: string | null
  owner: string
  user_id: number
  username: string
  created_at: string
}

export async function listOwnerMappings(db: Queryable, projectId?: string): Promise<OwnerMappingRow[]> {
  const r = await db.query<OwnerMappingRow>(
    `SELECT m.project_id, p.slug AS project_slug, m.owner, m.user_id::int AS user_id, u.username,
            to_char(m.created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS created_at
       FROM owner_mappings m JOIN users u ON u.id = m.user_id LEFT JOIN projects p ON p.id = m.project_id
      WHERE ($1::uuid IS NULL OR m.project_id = $1 OR m.project_id IS NULL)
      ORDER BY m.owner, u.username LIMIT 1000`,
    [projectId ?? null],
  )
  return r.rows
}

/** Ajoute une correspondance ; false si elle existait déjà. */
export async function addOwnerMapping(db: Queryable, input: OwnerMappingInput): Promise<boolean> {
  const r = await db.query(
    `INSERT INTO owner_mappings (project_id, owner, user_id) VALUES ($1, $2, $3)
     ON CONFLICT (project_id, owner, user_id) DO NOTHING`,
    [input.project_id, input.owner, input.user_id],
  )
  return (r.rowCount ?? 0) > 0
}

export async function removeOwnerMapping(db: Queryable, input: OwnerMappingInput): Promise<boolean> {
  const r = await db.query(
    'DELETE FROM owner_mappings WHERE project_id IS NOT DISTINCT FROM $1 AND owner = $2 AND user_id = $3',
    [input.project_id, input.owner, input.user_id],
  )
  return (r.rowCount ?? 0) > 0
}

/** Formes sous lesquelles un compte peut apparaître dans CODEOWNERS sans correspondance (minuscules). */
export async function ownerAliases(db: Queryable, userId: number): Promise<string[]> {
  const r = await db.query<{ username: string, email: string | null }>('SELECT username, email FROM users WHERE id = $1', [userId])
  const u = r.rows[0]
  if (!u) return []
  return [`@${u.username}`.toLowerCase(), ...(u.email ? [u.email.toLowerCase()] : [])]
}

/**
 * Clause SQL « résultat de cette personne » (alias f = findings) : $user est le
 * compte, $aliases ses formes directes (ownerAliases).
 */
export function mineClause(userParam: string, aliasesParam: string): string {
  return `EXISTS (SELECT 1 FROM unnest(f.owners) o
     WHERE lower(o) = ANY(${aliasesParam}::text[])
        OR EXISTS (SELECT 1 FROM owner_mappings m
                    WHERE m.user_id = ${userParam} AND lower(m.owner) = lower(o)
                      AND (m.project_id IS NULL OR m.project_id = f.project_id)))`
}
