// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Reprise de l'existant (J5) : accès au dépôt d'un projet et erreurs à code stable.

import { createError } from 'h3'
import type { Queryable } from '../utils/db'
import { ForgeError } from '../forges'
import { projectClient, type ProjectRow } from '../projects/service'
import { ImportRunError, type RepoAccess } from './service'

export async function repoAccess(db: Queryable, project: ProjectRow, ref?: string): Promise<RepoAccess> {
  const access = await projectClient(db, project)
  if (!access) throw new ImportRunError('E_IMPORT_NO_SOURCE')
  return { ...access, ref: ref ?? project.default_branch ?? 'HEAD' }
}

export function importHttpError(err: unknown): never {
  if (err instanceof ImportRunError) {
    throw createError({ statusCode: err.code === 'E_IMPORT_TOKEN' ? 409 : 400, statusMessage: err.code, data: { code: err.code } })
  }
  if (err instanceof ForgeError) {
    throw createError({ statusCode: 502, statusMessage: err.code, data: { code: err.code, status: err.status ?? null } })
  }
  throw err
}
