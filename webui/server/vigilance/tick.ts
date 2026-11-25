// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Passe de vigilance de la console (0.6, chantier B), environ chaque minute
// dans la boucle d'ingestion : versions figées publiées pour le helper (G6),
// essais F13 (mise en file, résumé), canaris G14 et vulnérabilités de
// l'appliance F19 rangés en base.

import type pg from 'pg'
import type { ConsoleConfig } from '../utils/config'
import { readCatalogIndex, readModulesState } from '../utils/catalog'
import { readPublishedState, stateSection } from '../utils/appliance'
import { publishPinsFile } from './pins'
import { readVigilanceState } from './state'
import { trialTick } from './trials'
import { applyCanaryResults } from './canaries'
import { ingestSelfStatus } from './selfvulns'

let lastPins: string | undefined

/** Mise à jour de la console disponible (état publié par le helper), ou null. */
export async function consoleUpdate(stateFile: string): Promise<string | null> {
  const st = await readPublishedState(stateFile)
  const u = stateSection<{ available?: boolean, latest_version?: string | null }>(st.state, 'update')
  return u?.available && typeof u.latest_version === 'string' ? u.latest_version : null
}

export async function vigilanceTick(pool: pg.Pool, cfg: ConsoleConfig, log: (m: string) => void = console.error): Promise<void> {
  const step = async (name: string, fn: () => Promise<unknown>) => {
    try {
      await fn()
    }
    catch (e) {
      log(`[vigilance] ${name}: ${(e as Error).message}`)
    }
  }
  await step('pins', async () => {
    lastPins = await publishPinsFile(pool, cfg.pinsFile, lastPins)
  })
  const vig = await readVigilanceState(cfg.vigilanceStateFile)
  await step('trials', () => trialTick(pool, vig.available ? vig.retained : null))
  await step('canaries', () => applyCanaryResults(pool))
  await step('self-vulns', async () => {
    if (!vig.self_sbom) return
    const [mods, index, upd] = await Promise.all([readModulesState(cfg.modulesStateFile), readCatalogIndex(cfg.catalogIndexFile), consoleUpdate(cfg.stateFile)])
    const r = await ingestSelfStatus(pool, vig.self_sbom, { selfDir: cfg.vigilanceSelfDir, installed: mods.modules, index, consoleUpdate: upd })
    if (r) console.log(`[vigilance] appliance SBOM: ${r.subjects} subject(s), ${r.new} new, ${r.resolved} resolved`)
  })
}
