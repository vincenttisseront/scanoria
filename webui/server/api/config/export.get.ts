// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// GET /api/config/export (admin) : toute la configuration de l'appliance en
// YAML versionné (J8), sans aucun secret. Audit config.export.

import { defineEventHandler } from 'h3'
import { getPool } from '../../utils/db'
import { clientAddress, requireRole } from '../../utils/http'
import { writeAudit } from '../../utils/audit'
import { getRunningVersion } from '../../utils/appliance'
import { getConfig } from '../../utils/config'
import { exportConfig } from '../../config/appliance'

export default defineEventHandler(async (event) => {
  const auth = requireRole(event, 'admin')
  const pool = getPool()
  const now = new Date()
  const { yaml, config } = await exportConfig(pool, { applianceVersion: await getRunningVersion(getConfig().versionFile).catch(() => undefined), now })
  await writeAudit(pool, {
    actor: { type: 'user', userId: auth.user.id, username: auth.user.username, ip: clientAddress(event) },
    action: 'config.export', outcome: 'success', targetType: 'config',
    details: { profiles: config.profiles.length, gates: config.gates.length, projects: config.projects.length, rulesets: config.rulesets.length },
  })
  return { yaml, filename: `scanoria-config-${now.toISOString().slice(0, 10)}.yml` }
})
