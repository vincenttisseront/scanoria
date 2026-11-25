// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Socle de la 0.6 : règle G16 (contrat 20), rejeu des plans antérieurs (G11)
// et alignement de la migration 012 avec les contrats partagés.
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'
import { GateRules } from '#shared/analysis'
import { rulesFromPlan } from '../../server/gates/evaluate'

const root = (rel: string) => fileURLToPath(new URL(`../../../${rel}`, import.meta.url))
const SQL_012 = readFileSync(root('webui/server/db/migrations/012_offline.sql'), 'utf8').replace(/\s+/g, ' ')

describe('socle 0.6', () => {
  it('G16 : défaut 7 jours, null accepté, bornes refusées', () => {
    expect(GateRules.parse({}).feed_max_age_days).toBe(7)
    expect(GateRules.parse({ feed_max_age_days: null }).feed_max_age_days).toBeNull()
    expect(GateRules.safeParse({ feed_max_age_days: 0 }).success).toBe(false)
    expect(GateRules.safeParse({ feed_max_age_days: 366 }).success).toBe(false)
    expect(GateRules.safeParse({ feed_max_age_days: 1.5 }).success).toBe(false)
  })

  it('G11 : un plan sans la règle G16 la rejoue désactivée', () => {
    expect(rulesFromPlan({ gate: { rules: { vuln_block_from: 'high', kev_blocks: true } } })?.feed_max_age_days).toBeNull()
    expect(rulesFromPlan({ gate: { rules: { vuln_block_from: 'high' } } })).toMatchObject({ feed_max_age_days: null, kev_blocks: false })
  })

  it('G11 : un plan 0.6 garde sa règle, y compris null', () => {
    expect(rulesFromPlan({ gate: { rules: { feed_max_age_days: 3 } } })?.feed_max_age_days).toBe(3)
    expect(rulesFromPlan({ gate: { rules: { feed_max_age_days: null, kev_blocks: true } } })?.feed_max_age_days).toBeNull()
  })

  it('plan invalide : aucune règle', () => {
    expect(rulesFromPlan({ gate: { rules: [] } })).toBeNull()
    expect(rulesFromPlan({ gate: { rules: 'x' } })).toBeNull()
    expect(rulesFromPlan({ gate: { rules: { feed_max_age_days: 0 } } })).toBeNull()
    expect(rulesFromPlan({})).toBeNull()
  })

  it('migration 012 : défaut G16 posé sur les gates existants', () => {
    const seeded = JSON.parse(/'(\{[^']*"feed_max_age_days"[^']*\})'::jsonb/.exec(SQL_012)![1]!)
    expect(seeded).toEqual({ feed_max_age_days: GateRules.parse({}).feed_max_age_days })
  })
})
