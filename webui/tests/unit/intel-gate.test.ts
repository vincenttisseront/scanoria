// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// H3 (0.5, chantier C) : quality gate KEV et EPSS (contrat 15). KEV bloquant
// quelle que soit la gravité, EPSS au-dessus du seuil même sous
// vuln_block_from, exceptions datées comme pour « vuln », H4 hors exception,
// règles désactivables, rejeu d'un plan d'avant la 0.5 inchangé (G11).

import { randomUUID } from 'node:crypto'
import { describe, expect, it } from 'vitest'
import { computeVerdict, intelReasons, rulesFromPlan, type GateException, type GateFinding, type GateInput } from '../../server/gates/evaluate'
import { GateRules, VerdictDetails } from '#shared/analysis'

const TODAY = '2026-11-24'
function gf(p: Partial<GateFinding> = {}): GateFinding {
  return {
    id: randomUUID(), tool: 'osv-scanner', rule_id: 'CVE-2026-1000', category: 'sca', severity: 'low', path: 'package-lock.json',
    vuln_ids: ['CVE-2026-1000'], package_name: 'lodash', malicious: false, secret_type: null, status: 'new', status_until: null, is_new: true,
    ...p,
  }
}
function run(p: Partial<GateInput> = {}, rules: Record<string, unknown> = {}) {
  const v = computeVerdict({
    gateId: randomUUID(), rules: GateRules.parse(rules), modules: [{ module_id: 'osv-scanner', status: 'ok' }],
    findings: [], exceptions: [], coverage: null, today: TODAY, evaluatedAt: '2026-11-24T10:00:00Z', ...p,
  })
  expect(VerdictDetails.safeParse(v).success).toBe(true)
  return v
}
const exc = (kind: string, target: unknown, p: Partial<GateException> = {}): GateException =>
  ({ id: randomUUID(), kind, target, reason: `motif ${kind}`, expires_on: '2026-12-31', ...p })

describe('H3 : KEV', () => {
  it('bloquant sous le seuil de gravité (low, vuln_block_from = high)', () => {
    const f = gf({ kev: true, severity: 'low' })
    const v = run({ findings: [f] })
    expect(v.verdict).toBe('failed')
    expect(v.reasons[0]).toMatchObject({ code: 'kev', blocking: true, count: 1, severity: 'low', finding_ids: [f.id], actions: ['fix', 'request-exception'] })
    // Compté une seule fois : il ne figure plus dans la raison « vuln » non bloquante.
    expect(v.reasons.filter(r => r.code === 'vuln')).toEqual([])
    expect(v.counts.low).toBe(1)
  })

  it('kev_blocks = false : la CVE suit le seuil de gravité habituel', () => {
    const v = run({ findings: [gf({ kev: true, severity: 'low' })] }, { kev_blocks: false, epss_block_from: null })
    expect(v.verdict).toBe('passed')
    expect(v.reasons).toEqual([expect.objectContaining({ code: 'vuln', blocking: false, severity: 'low' })])
  })

  it('exception datée de type vuln : appliquée comme pour « vuln » ; expirée : bloquant', () => {
    const f = gf({ kev: true })
    const ok = run({ findings: [f], exceptions: [exc('vuln', { vuln_id: 'CVE-2026-1000' })] })
    expect(ok.verdict).toBe('passed')
    expect(ok.exceptions_applied).toHaveLength(1)
    const expired = run({ findings: [f], exceptions: [exc('vuln', { vuln_id: 'CVE-2026-1000' }, { expires_on: '2026-11-01' })] })
    expect(expired.verdict).toBe('failed')
  })

  it('tri humain et ancien code : non retenus', () => {
    expect(run({ findings: [gf({ kev: true, status: 'false-positive' })] }).verdict).toBe('passed')
    expect(run({ findings: [gf({ kev: true, is_new: false })] }).verdict).toBe('passed')
    expect(run({ findings: [gf({ kev: true, is_new: false })] }, { new_code_only: false }).verdict).toBe('failed')
  })

  it('H4 reste prioritaire et sans exception, même KEV', () => {
    const mal = gf({ malicious: true, vuln_ids: ['MAL-2026-1'], kev: true })
    const v = run({ findings: [mal], exceptions: [exc('vuln', { vuln_id: 'MAL-2026-1' })] })
    expect(v.reasons[0]).toMatchObject({ code: 'malicious-package', blocking: true })
    expect(v.reasons.some(r => r.code === 'kev')).toBe(false)
  })

  it('seules les vulnérabilités comptent : un SAST marqué KEV ne bloque pas par KEV', () => {
    const v = run({ findings: [gf({ category: 'sast', kev: true, severity: 'low' })] })
    expect(v.reasons.some(r => r.code === 'kev')).toBe(false)
  })
})

describe('H3 : EPSS', () => {
  it('EPSS ≥ seuil (0.1 par défaut) bloquant même sous vuln_block_from', () => {
    const hi = gf({ epss: 0.1, severity: 'medium' })
    const lo = gf({ epss: 0.09, severity: 'medium', vuln_ids: ['CVE-2026-2000'] })
    const v = run({ findings: [hi, lo] })
    expect(v.verdict).toBe('failed')
    expect(v.reasons[0]).toMatchObject({ code: 'epss', blocking: true, count: 1, finding_ids: [hi.id] })
    expect(v.reasons[1]).toMatchObject({ code: 'vuln', blocking: false, count: 1, finding_ids: [lo.id] })
  })

  it('seuil nul : EPSS ignoré ; seuil abaissé : appliqué', () => {
    expect(run({ findings: [gf({ epss: 0.9 })] }, { epss_block_from: null }).verdict).toBe('passed')
    expect(run({ findings: [gf({ epss: 0.02 })] }, { epss_block_from: 0.01 }).verdict).toBe('failed')
    expect(run({ findings: [gf({ epss: null })] }, { epss_block_from: 0 }).verdict).toBe('passed')
  })

  it('KEV avant EPSS ; une CVE KEV n’est pas comptée deux fois', () => {
    const k = gf({ kev: true, epss: 0.5 })
    const e = gf({ epss: 0.3, vuln_ids: ['CVE-2026-3000'] })
    const v = run({ findings: [e, k] })
    expect(v.reasons.map(r => [r.code, r.count])).toEqual([['kev', 1], ['epss', 1]])
  })

  it('sous le seuil de gravité habituel aussi bloquant par sa gravité : une seule raison', () => {
    const f = gf({ severity: 'critical', epss: 0.5 })
    const v = run({ findings: [f] })
    expect(v.reasons.map(r => r.code)).toEqual(['epss'])
  })

  it('intelReasons : ordre par gravité puis EPSS', () => {
    const a = gf({ severity: 'low', epss: 0.9 })
    const b = gf({ severity: 'high', epss: 0.2 })
    const c = gf({ severity: 'high', epss: 0.6 })
    const r = intelReasons([a, b, c], GateRules.parse({}))
    expect(r.reasons[0]!.finding_ids).toEqual([c.id, b.id, a.id])
    expect(r.consumed.size).toBe(3)
  })
})

describe('G11 : plan d’avant la 0.5', () => {
  it('règles KEV et EPSS désactivées au rejeu : verdict de l’époque', () => {
    const rules = rulesFromPlan({ gate: { rules: { vuln_block_from: 'high', new_code_only: true } } })!
    expect(rules).toMatchObject({ kev_blocks: false, epss_block_from: null })
    const v = run({ findings: [gf({ kev: true, epss: 0.9 })], rules, correlate: false })
    expect(v.verdict).toBe('passed')
  })

  it('plan de la 0.5 : règles reprises telles quelles', () => {
    expect(rulesFromPlan({ gate: { rules: { kev_blocks: true, epss_block_from: 0.2 } } })).toMatchObject({ kev_blocks: true, epss_block_from: 0.2 })
  })
})
