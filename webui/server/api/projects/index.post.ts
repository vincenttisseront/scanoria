// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// POST /api/projects (operator) : ajoute un projet (dépôt d'une forge, URL Git
// libre ou archive téléversée). Détection F1, profil, gate et planification
// sont choisis automatiquement ; rien n'est installé.

import { defineEventHandler, setResponseStatus } from 'h3'
import { getPool } from '../../utils/db'
import { clientAddress, readValidated, requireRole } from '../../utils/http'
import { createFromBody } from '../../projects/create'
import { publicProject } from '../../projects/service'
import { projectCreateSchema } from '../../projects/schemas'

export default defineEventHandler(async (event) => {
  const auth = requireRole(event, 'operator')
  const body = await readValidated(event, projectCreateSchema)
  const actor = { type: 'user' as const, userId: auth.user.id, username: auth.user.username, ip: clientAddress(event) }
  const project = await createFromBody(getPool(), body, actor)
  setResponseStatus(event, 201)
  return { project: publicProject(project) }
})
