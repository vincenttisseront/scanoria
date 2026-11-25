// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// POST /api/projects/:id/exception-requests (jeton d'API du projet, portée
// scan:create, ou session operator) : demande d'exception depuis la CI (J15).
// Un jeton est une identité NON humaine : il demande, il ne décide jamais.
// Corps : celui de POST /api/exceptions sans project_id, plus commit_authors
// facultatif (auteurs du commit analysé, exclus de l'approbation).
// → 201 avec la demande (status « requested »).

import { defineEventHandler, getRouterParam, setResponseStatus } from 'h3'
import { getPool, withTransaction } from '../../../utils/db'
import { readValidated } from '../../../utils/http'
import { ciCaller, uuidParam } from '../../../gates/http'
import { requestException } from '../../../findings/exceptions'
import { exceptionHttpError, exceptionRequestSchema } from '../../../findings/exceptions-http'

export default defineEventHandler(async (event) => {
  const caller = ciCaller(event, 'scan:create', 'operator')
  const projectId = uuidParam(getRouterParam(event, 'id'))
  const body = await readValidated(event, exceptionRequestSchema)
  try {
    const row = await withTransaction(getPool(), db => requestException(db, {
      project_id: projectId,
      kind: body.kind,
      target: body.target,
      reason: body.reason,
      expires_on: body.expires_on,
      scan_id: body.scan_id,
      commit_authors: body.commit_authors ?? [],
      requested_via: caller.kind === 'token' ? 'api' : 'console',
      requester_label: caller.kind === 'token' ? `api-token:${caller.token.prefix}` : caller.auth.user.username,
      requester_is_human: caller.kind !== 'token',
      requester_user_id: caller.kind === 'token' ? null : caller.auth.user.id,
    }))
    setResponseStatus(event, 201)
    return row
  }
  catch (err) {
    throw exceptionHttpError(err)
  }
})
