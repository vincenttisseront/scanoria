// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// G16 (0.6, chantier A, contrat 20) : fraîcheur obligatoire des bases. Une base
// plus vieille que feed_max_age_days au début de l'analyse rend le verdict non
// concluant (bloquant), sauf exception datée « module » ; null = seulement
// signalé au-delà de 7 jours ; instant de référence figé dans le plan (G11) ;
// bloc additif : sans instant de référence ni bases, rien ne change.

import { randomUUID } from 'node:crypto'
import { describe, expect, it } from 'vitest'
import {
  computeVerdict, freshnessReasons, planFreshnessAt, rulesFromPlan,
  type GateException, type GateFinding, type GateInput, type GateModule,
} from '../../server/gates/evaluate'
import { FEED_ALERT_DAYS, GateRules, VerdictDetails, feedAgeDays } from '#shared/analysis'

const TODAY = '2026-11-24'
const AT = '2026-11-24T10:00:00Z'
const daysBefore = (n: number, at = AT) => new Date(Date.parse(at) - n * 86_400_000).toISOString().replace(/\.\d{3}Z$/, 'Z')

function mod(id: string, feeds: { id: string, updated_at: unknown }[], status = 'ok'): GateModule {
  return { module_id: id, status, feeds: feeds.map(f => ({ version: '1', ...f })) }
}
function run(p: Partial<GateInput> = {}, rules: Record<string, unknown> = {}) {
  const v = computeVerdict({
    gateId: randomUUID(), rules: GateRules.parse(rules), modules: [mod('osv-scanner', [{ id: 'osv-db', updated_at: daysBefore(1) }])],
    findings: [], exceptions: [], coverage: null, today: TODAY, evaluatedAt: AT, freshnessAt: AT, ...p,
  })
  expect(VerdictDetails.safeParse(v).success).toBe(true)
  return v
}
const exc = (target: unknown, p: Partial<GateException> = {}): GateException =>
  ({ id: randomUUID(), kind: 'module', target, reason: 'base importée avec retard', expires_on: '2026-12-31', ...p })
const gf = (p: Partial<GateFinding> = {}): GateFinding => ({
  id: randomUUID(), tool: 'osv-scanner', rule_id: 'CVE-2026-1000', category: 'sca', severity: 'critical', path: 'package-lock.json',
  vuln_ids: ['CVE-2026-1000'], package_name: 'lodash', malicious: false, secret_type: null, status: 'new', status_until: null, is_new: true, ...p,
})

describe('G16 : seuil feed_max_age_days', () => {
  it('base récente : verdict inchangé, aucune raison', () => {
    const v = run()
    expect(v.verdict).toBe('passed')
    expect(v.reasons).toEqual([])
  })

  it('base au-delà du seuil (défaut 7 jours) : non concluant, raison feed-stale bloquante', () => {
    const v = run({ modules: [mod('osv-scanner', [{ id: 'osv-db', updated_at: daysBefore(10) }])] })
    expect(v.verdict).toBe('inconclusive')
    expect(v.reasons).toEqual([{
      code: 'feed-stale', blocking: true, count: 10, severity: null, module: 'osv-scanner', finding_ids: [],
      actions: ['refresh-feed', 'request-exception'],
    }])
  })

  it('exactement au seuil : encore permis ; juste au-delà : bloquant', () => {
    expect(run({ modules: [mod('osv-scanner', [{ id: 'osv-db', updated_at: daysBefore(7) }])] }).verdict).toBe('passed')
    const just = new Date(Date.parse(daysBefore(7)) - 60_000).toISOString()
    expect(run({ modules: [mod('osv-scanner', [{ id: 'osv-db', updated_at: just }])] }).verdict).toBe('inconclusive')
  })

  it('seuil propre au gate (30 jours)', () => {
    const modules = [mod('osv-scanner', [{ id: 'osv-db', updated_at: daysBefore(20) }])]
    expect(run({ modules }, { feed_max_age_days: 30 }).verdict).toBe('passed')
    expect(run({ modules }, { feed_max_age_days: 14 }).verdict).toBe('inconclusive')
  })

  it('une raison par module, âge de sa base la plus ancienne ; ordre stable', () => {
    const v = run({
      modules: [
        mod('trivy', [{ id: 'trivy-db', updated_at: daysBefore(9) }]),
        mod('grype', [{ id: 'grype-db', updated_at: daysBefore(12) }, { id: 'epss', updated_at: daysBefore(30) }]),
        mod('gitleaks', []),
      ],
    })
    expect(v.reasons.map(r => [r.module, r.count])).toEqual([['grype', 30], ['trivy', 9]])
  })

  it('date de base illisible ou absente : comptée trop ancienne (échec par défaut, G13)', () => {
    for (const updated_at of ['pas une date', null, undefined, 42]) {
      const v = run({ modules: [mod('osv-scanner', [{ id: 'osv-db', updated_at }])] })
      expect(v.verdict).toBe('inconclusive')
      expect(v.reasons[0]).toMatchObject({ code: 'feed-stale', count: 0 })
    }
  })

  it('entrées hostiles ignorées sans planter (feeds non tableau, id absent)', () => {
    const v = run({ modules: [{ module_id: 'osv-scanner', status: 'ok', feeds: 'x' }, { module_id: 'trivy', status: 'ok', feeds: [null, { updated_at: daysBefore(99) }] }] })
    expect(v.verdict).toBe('passed')
  })

  it('un résultat bloquant donne « failed », la base trop ancienne reste listée', () => {
    const v = run({ findings: [gf()], modules: [mod('osv-scanner', [{ id: 'osv-db', updated_at: daysBefore(10) }])] })
    expect(v.verdict).toBe('failed')
    expect(v.reasons.map(r => r.code)).toEqual(['vuln', 'feed-stale'])
  })
})

describe('G16 : null = seulement signaler', () => {
  it('au-delà de 7 jours : raison informative, verdict réussi', () => {
    const v = run({ modules: [mod('osv-scanner', [{ id: 'osv-db', updated_at: daysBefore(FEED_ALERT_DAYS + 3) }])] }, { feed_max_age_days: null })
    expect(v.verdict).toBe('passed')
    expect(v.reasons).toEqual([expect.objectContaining({ code: 'feed-stale', blocking: false, count: 10, actions: ['refresh-feed'] })])
  })

  it('sous 7 jours : rien', () => {
    expect(run({ modules: [mod('osv-scanner', [{ id: 'osv-db', updated_at: daysBefore(3) }])] }, { feed_max_age_days: null }).reasons).toEqual([])
  })

  it('aucune exception consommée quand rien ne bloque', () => {
    const v = run({
      modules: [mod('osv-scanner', [{ id: 'osv-db', updated_at: daysBefore(20) }])],
      exceptions: [exc({ module_id: 'osv-scanner' })],
    }, { feed_max_age_days: null })
    expect(v.exceptions_applied).toEqual([])
  })
})

describe('G16 : exceptions datées « module »', () => {
  const stale = [mod('osv-scanner', [{ id: 'osv-db', updated_at: daysBefore(10) }])]

  it('exception valide du module : levée, tracée, verdict réussi', () => {
    const e = exc({ module_id: 'osv-scanner' })
    const v = run({ modules: stale, exceptions: [e] })
    expect(v.verdict).toBe('passed')
    expect(v.reasons).toEqual([expect.objectContaining({ code: 'feed-stale', blocking: false, actions: [] })])
    expect(v.exceptions_applied).toEqual([{ id: e.id, reason: e.reason, expires_on: e.expires_on }])
  })

  it('exception expirée ou d’un autre module : reste bloquant', () => {
    expect(run({ modules: stale, exceptions: [exc({ module_id: 'osv-scanner' }, { expires_on: '2026-11-01' })] }).verdict).toBe('inconclusive')
    expect(run({ modules: stale, exceptions: [exc({ module_id: 'trivy' })] }).verdict).toBe('inconclusive')
  })

  it('le module en échec et sa base trop ancienne : une seule exception lève les deux', () => {
    const e = exc({ module_id: 'osv-scanner' })
    const v = run({ modules: [mod('osv-scanner', [{ id: 'osv-db', updated_at: daysBefore(10) }], 'error')], exceptions: [e] })
    expect(v.verdict).toBe('passed')
    expect(v.exceptions_applied).toHaveLength(1)
  })
})

describe('G16 : rejeu et instant de référence (G11)', () => {
  const modules = [mod('osv-scanner', [{ id: 'osv-db', updated_at: '2026-11-20T00:00:00Z' }])]

  it('l’instant du plan fait foi : rejouée plus tard, l’analyse garde son verdict', () => {
    const atStart = run({ modules, freshnessAt: '2026-11-22T00:00:00Z', evaluatedAt: '2026-12-24T00:00:00Z' })
    expect(atStart.verdict).toBe('passed')
    const late = run({ modules, freshnessAt: '2026-12-24T00:00:00Z' })
    expect(late.verdict).toBe('inconclusive')
  })

  it('planFreshnessAt : created_at du plan, sinon null', () => {
    expect(planFreshnessAt({ created_at: '2026-11-22T00:00:00Z' })).toBe('2026-11-22T00:00:00Z')
    for (const p of [null, {}, { created_at: 'hier' }, { created_at: 3 }, 'x']) expect(planFreshnessAt(p)).toBeNull()
  })

  it('plan d’avant la 0.6 : règle absente rejouée à null, donc seulement signalée', () => {
    const rules = rulesFromPlan({ gate: { rules: { vuln_block_from: 'high', kev_blocks: true } } })!
    expect(rules.feed_max_age_days).toBeNull()
    const v = computeVerdict({
      gateId: randomUUID(), rules, modules: [mod('osv-scanner', [{ id: 'osv-db', updated_at: daysBefore(40) }])],
      findings: [], exceptions: [], coverage: null, today: TODAY, evaluatedAt: AT, freshnessAt: AT,
    })
    expect(v.verdict).toBe('passed')
  })

  it('bloc additif : sans instant de référence, aucun contrôle', () => {
    const v = run({ modules: [mod('osv-scanner', [{ id: 'osv-db', updated_at: daysBefore(90) }])], freshnessAt: undefined })
    expect(v.reasons).toEqual([])
    expect(freshnessReasons({ ...{ gateId: 'g', modules: [], findings: [], exceptions: [], today: TODAY, evaluatedAt: AT }, rules: GateRules.parse({}) }, GateRules.parse({}))).toEqual({ blocking: [], info: [], applied: [] })
  })
})

describe('feedAgeDays (§ 9, console)', () => {
  it('âge en jours entiers, jamais négatif ; null si date illisible', () => {
    const now = Date.parse(AT)
    expect(feedAgeDays(daysBefore(8), now)).toBe(8)
    expect(feedAgeDays('2027-01-01T00:00:00Z', now)).toBe(0)
    expect(feedAgeDays(null, now)).toBeNull()
    expect(feedAgeDays('n/a', now)).toBeNull()
  })
})
