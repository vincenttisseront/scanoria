// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// GET /api/users (admin) : liste des comptes, sans empreinte de mot de passe.

import { defineEventHandler } from 'h3'
import { getPool } from '../../utils/db'
import { requireRole } from '../../utils/http'
import { listUsers } from '../../utils/users'

export default defineEventHandler(async (event) => {
  requireRole(event, 'admin')
  return { items: await listUsers(getPool()) }
})
