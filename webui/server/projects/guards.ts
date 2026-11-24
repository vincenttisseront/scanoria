// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Lecture d'une forge ou d'un projet par l'identifiant d'une route : 404 si
// l'identifiant n'est pas un UUID ou n'existe pas.

import type { Queryable } from '../utils/db'
import { apiError } from '../utils/http'
import { getForge, type ForgeRow } from '../forges'
import { getProject, type ProjectRow } from './service'

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/

export async function requireForge(db: Queryable, id: string | undefined): Promise<ForgeRow> {
  const forge = id && UUID_RE.test(id) ? await getForge(db, id) : null
  if (!forge) throw apiError(404, 'E_NOT_FOUND')
  return forge
}

export async function requireProject(db: Queryable, id: string | undefined): Promise<ProjectRow> {
  const project = id && UUID_RE.test(id) ? await getProject(db, id) : null
  if (!project) throw apiError(404, 'E_NOT_FOUND')
  return project
}
