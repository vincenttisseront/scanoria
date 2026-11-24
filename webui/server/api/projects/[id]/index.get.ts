// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// GET /api/projects/:id (viewer) : projet, détection F1 et choix possibles
// (profils, quality gates) pour le formulaire de modification.

import { defineEventHandler, getRouterParam } from 'h3'
import { getPool } from '../../../utils/db'
import { requireRole } from '../../../utils/http'
import { requireProject } from '../../../projects/guards'
import { publicProject } from '../../../projects/service'
import { currentDailySlot, dailySlotMinute } from '../../../projects/schedule'

export default defineEventHandler(async (event) => {
  requireRole(event, 'viewer')
  const pool = getPool()
  const project = await requireProject(pool, getRouterParam(event, 'id'))
  const [profiles, gates] = await Promise.all([
    pool.query<{ id: string, slug: string, builtin: boolean }>('SELECT id::text, slug, builtin FROM profiles ORDER BY builtin DESC, slug'),
    pool.query<{ id: string, slug: string, builtin: boolean }>('SELECT id::text, slug, builtin FROM gates ORDER BY builtin DESC, slug'),
  ])
  const minute = dailySlotMinute(project.id)
  return {
    project: publicProject(project),
    choices: { profiles: profiles.rows, gates: gates.rows },
    schedule: {
      daily_time_utc: `${String(Math.floor(minute / 60)).padStart(2, '0')}:${String(minute % 60).padStart(2, '0')}`,
      last_daily_slot: currentDailySlot(project.id, new Date()).toISOString().replace(/\.\d{3}Z$/, 'Z'),
      poll_interval_s: 300,
    },
  }
})
