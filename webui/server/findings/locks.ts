// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Verrous G8 vus par le circuit des exceptions (contrat 27) et le tri en
// masse (F4) : exigences verrouillées (contrat 28) de tous les profils d'un
// projet (profil par défaut et profils par déclencheur G9), en remontant la
// hiérarchie entreprise → équipe → projet. Les exigences s'ajoutent : un
// verrou posé à n'importe quel niveau s'applique.
//
// La résolution complète du profil effectif (fusion, planchers) est celle du
// chantier C (resolveProfile, contrat 29). Ici, seule la question « cette
// exception assouplirait-elle un verrou ? » est posée, de façon stricte :
// - module requis (required_modules), ou module dont une catégorie est requise
//   (required_categories) : aucune exception « module » ne le dispense ;
// - plancher de gate sur les secrets (gate_floor.max_secrets) : aucune
//   exception ni règle de tri « accepté » ne couvre un secret.

import { ProfileLocks } from '#shared/analysis'
import type { Queryable } from '../utils/db'
import { readModuleHints } from './manifest'

export interface ProjectLocks {
  modules: Set<string>
  categories: Set<string>
  /** Clés de gate_floor posées par au moins un niveau. */
  floorKeys: Set<string>
}

/** Au plus 16 niveaux remontés : la hiérarchie en a trois, une boucle est coupée. */
const MAX_DEPTH = 16

export async function projectLocks(db: Queryable, projectId: string): Promise<ProjectLocks> {
  const { rows } = await db.query<{ locks: unknown }>(
    `WITH RECURSIVE chain(id, depth) AS (
       SELECT unnest(ARRAY[p.profile_id, p.profile_pr_id, p.profile_nightly_id, p.profile_release_id]), 0
         FROM projects p WHERE p.id = $1
       UNION
       SELECT pr.parent_id, c.depth + 1 FROM chain c JOIN profiles pr ON pr.id = c.id
        WHERE pr.parent_id IS NOT NULL AND c.depth < ${MAX_DEPTH}
     )
     SELECT DISTINCT pr.id, pr.locks FROM chain c JOIN profiles pr ON pr.id = c.id`,
    [projectId],
  )
  const out: ProjectLocks = { modules: new Set(), categories: new Set(), floorKeys: new Set() }
  for (const r of rows) {
    const parsed = ProfileLocks.safeParse(r.locks ?? {})
    // Un verrou illisible ne s'applique pas ici ; le chantier C le refuse à l'enregistrement.
    if (!parsed.success) continue
    for (const m of parsed.data.required_modules) out.modules.add(m)
    for (const c of parsed.data.required_categories) out.categories.add(c)
    for (const k of Object.keys(parsed.data.gate_floor)) out.floorKeys.add(k)
  }
  return out
}

/** Un module exigé par un verrou (directement ou par une de ses catégories). */
export async function moduleLocked(locks: ProjectLocks, moduleId: string): Promise<boolean> {
  if (locks.modules.has(moduleId)) return true
  if (!locks.categories.size) return false
  const hints = await readModuleHints(moduleId)
  return hints.categories.some(c => locks.categories.has(c))
}

/** Les secrets sont verrouillés quand un niveau impose un plancher sur max_secrets. */
export function secretsLocked(locks: ProjectLocks): boolean {
  return locks.floorKeys.has('max_secrets')
}
