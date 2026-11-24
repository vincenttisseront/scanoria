// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// GET /api/catalog/modules/:id/vigilance (lecteur) : canaris (G14), essais
// (F13), projets qui figent une version (G6) et vulnérabilités (F19) du module.

import { defineEventHandler, getRouterParam } from 'h3'
import { apiError, requireAuth } from '../../../../utils/http'
import { getPool } from '../../../../utils/db'
import { loadCatalogContext } from '../../../../utils/catalog-view'
import { compareVersions } from '../../../../utils/catalog'
import { canaryHistory } from '../../../../vigilance/canaries'
import { listTrials } from '../../../../vigilance/trials'
import { listSelfVulns } from '../../../../vigilance/selfvulns'
import { MODULE_ID_RE } from '#shared/schemas'

export default defineEventHandler(async (event) => {
  requireAuth(event)
  const id = getRouterParam(event, 'id') ?? ''
  if (!MODULE_ID_RE.test(id)) throw apiError(404, 'E_NOT_FOUND')
  const pool = getPool()
  const ctx = await loadCatalogContext()
  const installed = ctx.installed.find(m => m.id === id)
  const pins = await pool.query<{ project_id: string, slug: string, name: string, version: string, reason: string }>(
    `SELECT p.id::text AS project_id, p.slug, p.name, x.version, x.reason
       FROM project_module_pins x JOIN projects p ON p.id = x.project_id WHERE x.module_id = $1 ORDER BY p.slug LIMIT 200`, [id])
  return {
    canaries: await canaryHistory(pool, id),
    trials: await listTrials(pool, id),
    // F13 : versions plus récentes de l'index vérifié, candidates à l'essai.
    trial_candidates: installed?.type === 'scanner'
      ? (ctx.index?.modules ?? []).filter(m => m.id === id && compareVersions(m.version, installed.version) > 0).map(m => m.version)
      : [],
    pins: pins.rows,
    vulns: installed ? await listSelfVulns(pool, `module:${id}`, 50) : [],
  }
})
