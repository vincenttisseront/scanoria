// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// GET /api/state (tout utilisateur connecté) : état publié par le service root
// (/run/scanoria/state.json), marqué indisponible au-delà de 3 minutes.

import { defineEventHandler } from 'h3'
import { getConfig } from '../utils/config'
import { requireAuth } from '../utils/http'
import { getRunningVersion, readPublishedState } from '../utils/appliance'

export default defineEventHandler(async (event) => {
  requireAuth(event)
  const cfg = getConfig()
  const published = await readPublishedState(cfg.stateFile)
  return { ...published, console_version: await getRunningVersion(cfg.versionFile) }
})
