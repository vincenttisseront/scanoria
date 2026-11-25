// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// POST /api/config/import/preview (admin) {yaml} : aperçu des écarts entre une
// configuration exportée et l'appliance (J8). Rien n'est écrit ; l'empreinte
// rendue est exigée par l'application.

import { createError, defineEventHandler } from 'h3'
import { z } from 'zod'
import { getPool } from '../../../utils/db'
import { readValidated, requireRole } from '../../../utils/http'
import { APPLIANCE_CONFIG_MAX_BYTES, parseApplianceConfig, planImport } from '../../../config/appliance'

const body = z.strictObject({ yaml: z.string().min(1).max(APPLIANCE_CONFIG_MAX_BYTES) })

export default defineEventHandler(async (event) => {
  requireRole(event, 'admin')
  const { yaml } = await readValidated(event, body)
  const parsed = parseApplianceConfig(yaml)
  if (!parsed.ok) throw createError({ statusCode: 422, statusMessage: 'E_CONFIG_INVALID', data: { code: 'E_CONFIG_INVALID', issues: parsed.issues } })
  return planImport(getPool(), parsed.config, yaml)
})
