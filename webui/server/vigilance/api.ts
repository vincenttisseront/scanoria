// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Vues de vigilance servies par l'API (0.6, chantier B) : bandeaux du tableau
// de bord et de Mises à jour, fiche d'un module, versions figées d'un projet.

import { z } from 'zod'
import type { H3Event } from 'h3'
import type { Queryable } from '../utils/db'
import { getConfig } from '../utils/config'
import { clientAddress, type AuthContext } from '../utils/http'
import type { AuditActor } from '../utils/audit'
import type { Requester } from '../utils/requests'
import type { CatalogContext } from '../utils/catalog-view'
import { readVigilanceState, type VigilanceState } from './state'
import { isDetectionFailure, latestCanaries } from './canaries'
import { selfVulnSummary } from './selfvulns'
import { consoleUpdate } from './tick'
import { loadPins, pinWarnings } from './pins'

export const pinBodySchema = z.strictObject({ reason: z.string().trim().min(3).max(2000) })
export const trialBodySchema = z.strictObject({
  version: z.string().regex(/^[0-9A-Za-z][0-9A-Za-z.+_-]{0,63}$/).optional(),
  sample_size: z.number().int().min(1).max(50).optional(),
})
export const canariesBodySchema = z.strictObject({
  ids: z.array(z.string().regex(/^[a-z0-9][a-z0-9-]{1,40}$/)).min(1).max(64).optional(),
})

export function actorOf(event: H3Event, auth: AuthContext): { actor: AuditActor, requester: Requester } {
  const ip = clientAddress(event)
  return {
    actor: { type: 'user', userId: auth.user.id, username: auth.user.username, ip },
    requester: { userId: auth.user.id, username: auth.user.username, ...(ip ? { address: ip } : {}) },
  }
}

/** Modules dont l'image installée a une vulnérabilité ouverte (F19). */
export async function vulnerableModules(db: Queryable): Promise<Set<string>> {
  const r = await db.query<{ subject: string }>(`SELECT DISTINCT subject FROM self_vulns WHERE resolved_at IS NULL AND subject LIKE 'module:%'`)
  return new Set(r.rows.map(x => x.subject.slice('module:'.length)))
}

export async function vigilanceSummary(db: Queryable, ctx: CatalogContext, vig?: VigilanceState) {
  const cfg = getConfig()
  const state = vig ?? await readVigilanceState(cfg.vigilanceStateFile)
  const upd = await consoleUpdate(cfg.stateFile)
  const vulns = await selfVulnSummary(db, { installed: ctx.installed, index: ctx.index, consoleUpdate: upd })
  const canaries = await latestCanaries(db)
  const installedIds = new Set(ctx.installed.map(m => m.id))
  const trials = await db.query<{ id: string, module_id: string, to_version: string, status: string }>(
    `SELECT id::text, module_id, to_version, status FROM module_trials WHERE status IN ('running', 'done') ORDER BY started_at DESC LIMIT 20`)
  const failing = canaries.filter(c => isDetectionFailure(c) && installedIds.has(c.module_id))
  return {
    available: state.available,
    self_sbom: state.self_sbom
      ? { at: state.self_sbom.at, gaps: state.self_sbom.gaps,
          subjects: state.self_sbom.subjects.map(s => ({ subject: s.subject, version: s.version ?? null, components: s.components,
            error: s.error?.code ?? null, tools: s.tools.map(t => ({ id: t.id, version: t.version, ok: t.ok })) })) }
      : null,
    vulns,
    // Alerte F19 : « module X vulnérable, mise à jour disponible ».
    alerts: vulns.filter(v => v.update_available && (v.critical + v.high + v.medium + v.low + v.info) > 0)
      .map(v => ({ subject: v.subject, update_available: v.update_available, critical: v.critical, high: v.high,
        total: v.critical + v.high + v.medium + v.low + v.info })),
    canaries: { latest: canaries.filter(c => installedIds.has(c.module_id)), failing: failing.map(c => c.module_id) },
    retained: state.retained,
    trials: trials.rows,
  }
}

/** Versions figées d'un projet, avec leurs avertissements, et modules qu'on peut figer. */
export async function projectPinsView(db: Queryable, projectId: string, ctx: CatalogContext) {
  const state = await readVigilanceState(getConfig().vigilanceStateFile)
  const vulnerable = await vulnerableModules(db)
  const pins = [...(await loadPins(db, projectId)).values()]
  return {
    pins: pins.map((p) => {
      const cur = ctx.installed.find(m => m.id === p.module_id)
      return {
        ...p,
        installed_version: cur?.version ?? null,
        warnings: pinWarnings(p, {
          index: ctx.index, installed: ctx.installed, retained: state.available ? state.retained : null,
          // F19 : seule l'image installée est analysée ; elle est celle de la version figée si les versions concordent.
          vulnerable: cur?.version === p.version ? vulnerable : new Set(),
        }),
      }
    }),
    pinnable: ctx.installed.filter(m => m.type === 'scanner' && !pins.some(p => p.module_id === m.id))
      .map(m => ({ id: m.id, version: m.version })),
  }
}
