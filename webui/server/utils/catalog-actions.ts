// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Aides des actions du catalogue : module installé désigné par l'URL, et
// traduction d'un corps « modules ou pack » en demandes de plan.

import { getRouterParam, type H3Event } from 'h3'
import { apiError, requireRole } from './http'
import { loadCatalogContext, type CatalogContext } from './catalog-view'
import { dependentsOf, type PlanRequest } from './module-plan'
import { MODULE_ID_RE } from '#shared/schemas'

export function planRequests(
  body: { modules?: PlanRequest[], pack?: string },
  ctx: Pick<CatalogContext, 'index' | 'installed'>,
): PlanRequest[] {
  if (body.modules) return body.modules
  const pack = ctx.index?.packs.find(p => p.id === body.pack)
  if (!pack) throw apiError(404, 'E_NOT_FOUND')
  const installed = new Set(ctx.installed.map(m => m.id))
  const pending = pack.modules.filter(id => !installed.has(id))
  if (!pending.length) throw apiError(409, 'E_PLAN', { blockers: [{ code: 'W_PACK_INSTALLED', other: pack.id }] })
  return pending.map(id => ({ id }))
}

/** Module installé désigné par :id (admin) ; 404 E_NOT_INSTALLED sinon. */
export async function installedModuleParam(event: H3Event) {
  requireRole(event, 'admin')
  const id = getRouterParam(event, 'id') ?? ''
  if (!MODULE_ID_RE.test(id)) throw apiError(404, 'E_NOT_FOUND')
  const context = await loadCatalogContext()
  const installed = context.installed.find(m => m.id === id)
  if (!installed) throw apiError(404, 'E_NOT_INSTALLED')
  return { id, installed, ctx: { ...context, dependents: dependentsOf(id, context) } }
}
