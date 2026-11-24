// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Gate 0.5 (B) : raisons F8 (licences) et H5 (quarantaine) tirées des
// composants du SBOM ; rejeu inchangé d'un plan antérieur à la 0.5.

import { randomUUID } from 'node:crypto'
import { describe, expect, it } from 'vitest'
import { computeVerdict, rulesFromPlan, type GateComponent, type GateInput } from '../../server/gates/evaluate'
import { GateRules, VerdictDetails } from '#shared/analysis'

const NOW = '2026-11-24T10:00:00Z'
const comp = (p: Partial<GateComponent> = {}): GateComponent => ({ purl: `pkg:npm/x${randomUUID().slice(0, 8)}@1.0.0`, decision: 'allowed', published_at: '2025-01-01T00:00:00Z', ...p })

function run(p: Partial<GateInput> = {}, rules: Partial<GateRules> = {}) {
  const out = computeVerdict({
    gateId: randomUUID(), rules: GateRules.parse(rules), modules: [{ module_id: 'trivy', status: 'ok' }], findings: [], exceptions: [],
    coverage: null, today: '2026-11-24', evaluatedAt: NOW, ...p,
  })
  expect(VerdictDetails.safeParse(out).success).toBe(true)
  return out
}

describe('gate : licences (F8)', () => {
  it('licence interdite bloquante par défaut, action « corriger »', () => {
    const v = run({ components: [comp({ decision: 'denied' }), comp({ decision: 'denied' }), comp()] })
    expect(v.verdict).toBe('failed')
    expect(v.reasons).toContainEqual(expect.objectContaining({ code: 'license-denied', blocking: true, count: 2, actions: ['fix'] }))
  })

  it('license_denied_blocks = false : signalée sans bloquer', () => {
    const v = run({ components: [comp({ decision: 'denied' })] }, { license_denied_blocks: false })
    expect(v.verdict).toBe('passed')
    expect(v.reasons).toContainEqual(expect.objectContaining({ code: 'license-denied', blocking: false, count: 1 }))
  })

  it('licence à revoir : toujours informative', () => {
    const v = run({ components: [comp({ decision: 'review' }), comp({ decision: 'review' })] })
    expect(v.verdict).toBe('passed')
    expect(v.reasons).toEqual([expect.objectContaining({ code: 'license-review', blocking: false, count: 2 })])
  })

  it('aucun composant : aucune raison', () => {
    expect(run({ components: [] }).reasons).toEqual([])
    expect(run().reasons).toEqual([])
  })
})

describe('gate : quarantaine (H5)', () => {
  const recent = () => comp({ published_at: '2026-11-22T00:00:00Z' })

  it('bloquante pour une release, action « attendre »', () => {
    const v = run({ trigger: 'release', components: [recent(), comp()] })
    expect(v.verdict).toBe('failed')
    expect(v.reasons).toContainEqual(expect.objectContaining({ code: 'quarantine', blocking: true, count: 1, actions: ['wait'] }))
  })

  it.each(['pr', 'manual', 'schedule', 'webhook', undefined])('informative pour le déclencheur %s', (trigger) => {
    const v = run({ trigger, components: [recent()] })
    expect(v.verdict).toBe('passed')
    expect(v.reasons).toContainEqual(expect.objectContaining({ code: 'quarantine', blocking: false }))
  })

  it('levée à l’échéance, date inconnue ignorée, quarantine_days = 0 la désactive', () => {
    expect(run({ trigger: 'release', components: [comp({ published_at: '2026-11-16T09:00:00Z' })] }).verdict).toBe('passed')
    expect(run({ trigger: 'release', components: [comp({ published_at: null }), comp({ published_at: 'pas une date' })] }).reasons).toEqual([])
    expect(run({ trigger: 'release', components: [recent()] }, { quarantine_days: 0 }).reasons).toEqual([])
    expect(run({ trigger: 'release', components: [comp({ published_at: '2026-11-10T00:00:00Z' })] }, { quarantine_days: 30 }).verdict).toBe('failed')
  })
})

describe('rejeu d’un plan antérieur à la 0.5 (G11)', () => {
  it('règles F8/H3/H5 désactivées : le verdict de l’époque est conservé', () => {
    const old = rulesFromPlan({ gate: { rules: { new_code_only: true, vuln_block_from: 'high', max_secrets: 0 } } })
    expect(old).not.toBeNull()
    expect(old).toMatchObject({ license_denied_blocks: false, kev_blocks: false, epss_block_from: null, quarantine_days: 0 })
    const v = run({ trigger: 'release', rules: old!, components: [comp({ decision: 'denied', published_at: '2026-11-23T00:00:00Z' })] })
    expect(v.verdict).toBe('passed')
    expect(v.reasons.filter(r => r.blocking)).toEqual([])
  })

  it('plan 0.5 : règles explicites reprises telles quelles', () => {
    const r = rulesFromPlan({ gate: { rules: { quarantine_days: 3, license_denied_blocks: true } } })
    expect(r).toMatchObject({ quarantine_days: 3, license_denied_blocks: true })
  })
})
