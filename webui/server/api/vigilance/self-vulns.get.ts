// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// GET /api/vigilance/self-vulns?subject=console|module:<id> (lecteur) :
// vulnérabilités ouvertes d'un sujet de l'appliance (F19).

import { defineEventHandler } from 'h3'
import { z } from 'zod'
import { queryValidated, requireAuth } from '../../utils/http'
import { getPool } from '../../utils/db'
import { listSelfVulns } from '../../vigilance/selfvulns'

const query = z.strictObject({ subject: z.string().regex(/^(console|module:[a-z0-9][a-z0-9-]{1,40})$/) })

export default defineEventHandler(async (event) => {
  requireAuth(event)
  const { subject } = queryValidated(event, query)
  return { subject, vulns: await listSelfVulns(getPool(), subject) }
})
