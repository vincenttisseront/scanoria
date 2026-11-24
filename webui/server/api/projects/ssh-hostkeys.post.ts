// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// POST /api/projects/ssh-hostkeys (operator) : relève les clés d'hôte SSH d'un
// dépôt (ssh-keyscan) pour que l'opérateur compare les empreintes avant de
// les accepter.

import { defineEventHandler } from 'h3'
import { readValidated, requireRole } from '../../utils/http'
import { mapProjectError, projectError } from '../../projects/errors'
import { parseGitUrl } from '../../projects/git-url'
import { hostPattern, scanHostKeys } from '../../projects/ssh'
import { hostKeysSchema } from '../../projects/schemas'

export default defineEventHandler(async (event) => {
  requireRole(event, 'operator')
  const body = await readValidated(event, hostKeysSchema)
  let url
  try {
    url = parseGitUrl(body.url)
  }
  catch (err) {
    mapProjectError(err)
  }
  if (url.kind !== 'ssh') throw projectError(400, 'E_GIT_URL')
  const keys = await scanHostKeys(url.host, url.port)
  if (!keys) throw projectError(502, 'E_SSH_KEYSCAN')
  return { host: hostPattern(url.host, url.port), keys, known_hosts: keys.map(k => k.line).join('\n') }
})
