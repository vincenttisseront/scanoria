// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// GET /api/config/schema (viewer) : schéma JSON de .scanoria.yml (J8), le même
// que docs/scanoria-config.schema.json.

import { defineEventHandler } from 'h3'
import { requireRole } from '../../utils/http'
import { repoConfigJsonSchema } from '../../config/repo-config'

export default defineEventHandler((event) => {
  requireRole(event, 'viewer')
  return repoConfigJsonSchema()
})
