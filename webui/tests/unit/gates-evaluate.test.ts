// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Quality gate (chantier E) : computeVerdict règle par règle, H4 non
// contournable, G13, exceptions (actives, expirées, par type), nouveau code,
// ordre des raisons ; aides (glob, familles, références Git, jetons, badge).

import { randomUUID } from 'node:crypto'
import { describe, expect, it } from 'vitest'
import { computeVerdict, familyOf, globToRegExp, rulesFromPlan, type GateException, type GateFinding, type GateInput, type GateModule } from '../../server/gates/evaluate'
import { validRef, gateCreateSchema, scanCreateSchema, tokenCreateSchema } from '../../server/gates/gates'
import { generateToken, hashToken, tokenPrefix } from '../../server/gates/tokens'
import { badgeSvg } from '../../server/gates/badge'
import { API_TOKEN_RE, GateRules, VerdictDetails } from '#shared/analysis'

const TODAY = '2026-11-24'
const GATE = randomUUID()

function finding(p: Partial<GateFinding> = {}): GateFinding {
  return {
    id: randomUUID(), tool: 'trivy', rule_id: 'R1', category: 'sca', severity: 'high', path: 'src/app.js',
    vuln_ids: [], package_name: null, malicious: false, secret_type: null, status: 'new', status_until: null, is_new: true,
    ...p,
  }
}
const ok = (id: string): GateModule => ({ module_id: id, status: 'ok' })

function exc(kind: string, target: unknown, p: Partial<GateException> = {}): GateException {
  return { id: randomUUID(), kind, target, reason: `motif ${kind}`, expires_on: '2026-12-31', ...p }
}

function run(p: Partial<GateInput> = {}) {
  const out = computeVerdict({
    gateId: GATE, rules: GateRules.parse({}), modules: [ok('trivy'), ok('gitleaks')], findings: [], exceptions: [],
    coverage: null, today: TODAY, evaluatedAt: '2026-11-24T10:00:00Z', ...p,
  })
  expect(VerdictDetails.safeParse(out).success).toBe(true)
  return out
}

describe('computeVerdict', () => {
  it('aucun résultat, modules sains → passed', () => {
    const v = run()
    expect(v.verdict).toBe('passed')
    expect(v.reasons).toEqual([])
    expect(v.counts).toEqual({ critical: 0, high: 0, medium: 0, low: 0, info: 0 })
    expect(v.gate_id).toBe(GATE)
    expect(v.new_code_only).toBe(true)
  })

  it('H4 : un paquet malveillant bloque toujours, même ancien, trié ou visé par une exception', () => {
    const f = finding({ malicious: true, vuln_ids: ['MAL-2026-1'], is_new: false, status: 'false-positive', severity: 'low' })
    const v = run({
      findings: [f],
      exceptions: [exc('finding', { finding_id: f.id }), exc('vuln', { vuln_id: 'MAL-2026-1' }), exc('path', { glob: '**' })],
    })
    expect(v.verdict).toBe('failed')
    expect(v.reasons[0]).toMatchObject({ code: 'malicious-package', blocking: true, count: 1, actions: ['fix'] })
    expect(v.reasons[0]!.actions).not.toContain('request-exception')
    expect(v.exceptions_applied).toEqual([])
  })

  it('H4 : prime sur un verdict non concluant', () => {
    const v = run({ findings: [finding({ malicious: true })], modules: [{ module_id: 'trivy', status: 'error' }] })
    expect(v.verdict).toBe('failed')
  })

  it('familles : catégories, secrets et malveillants', () => {
    expect(familyOf({ category: 'sca', malicious: true, secret_type: null })).toBe('malicious')
    expect(familyOf({ category: 'sast', malicious: false, secret_type: 'aws' })).toBe('secret')
    expect(familyOf({ category: 'secrets', malicious: false, secret_type: null })).toBe('secret')
    for (const c of ['sca', 'container', 'sbom', 'dast']) expect(familyOf({ category: c, malicious: false, secret_type: null })).toBe('vuln')
    for (const c of ['sast', 'ci']) expect(familyOf({ category: c, malicious: false, secret_type: null })).toBe('sast')
    expect(familyOf({ category: 'iac', malicious: false, secret_type: null })).toBe('iac')
    for (const c of ['quality', 'lint', 'licenses', 'inconnu']) expect(familyOf({ category: c, malicious: false, secret_type: null })).toBe('other')
  })

  it('secrets : bloquants au-delà de max_secrets', () => {
    const secrets = [finding({ category: 'secrets', secret_type: 'generic' }), finding({ category: 'secrets', secret_type: 'aws', severity: 'critical' })]
    let v = run({ findings: secrets })
    expect(v.verdict).toBe('failed')
    expect(v.reasons[0]).toMatchObject({ code: 'secret', blocking: true, count: 2, severity: 'critical', actions: ['fix', 'request-exception'] })
    v = run({ findings: secrets, rules: GateRules.parse({ max_secrets: 2 }) })
    expect(v.verdict).toBe('passed')
    expect(v.reasons[0]).toMatchObject({ code: 'secret', blocking: false, count: 2, actions: [] })
  })

  it.each([
    ['vuln', 'sca', 'vuln_block_from'],
    ['sast', 'sast', 'sast_block_from'],
    ['iac', 'iac', 'iac_block_from'],
  ] as const)('%s : seuil %s', (code, category, rule) => {
    const high = finding({ category, severity: 'high' })
    const medium = finding({ category, severity: 'medium' })
    let v = run({ findings: [medium, high] })
    expect(v.verdict).toBe('failed')
    expect(v.reasons.map(r => [r.code, r.severity, r.blocking])).toEqual([[code, 'high', true], [code, 'medium', false]])
    expect(v.reasons[0]!.finding_ids).toEqual([high.id])
    v = run({ findings: [medium, high], rules: GateRules.parse({ [rule]: 'critical' }) })
    expect(v.verdict).toBe('passed')
    v = run({ findings: [medium, high], rules: GateRules.parse({ [rule]: null }) })
    expect(v.verdict).toBe('passed')
    v = run({ findings: [medium], rules: GateRules.parse({ [rule]: 'medium' }) })
    expect(v.verdict).toBe('failed')
  })

  it('autres résultats (qualité, lint) : jamais bloquants', () => {
    const v = run({ findings: [finding({ category: 'quality', severity: 'critical' }), finding({ category: 'lint', severity: 'low' })] })
    expect(v.verdict).toBe('passed')
    expect(v.reasons.map(r => [r.code, r.severity, r.blocking])).toEqual([['other', 'critical', false], ['other', 'low', false]])
    expect(v.counts).toMatchObject({ critical: 1, low: 1 })
  })

  it('nouveau code seulement : les anciens résultats ne comptent pas, sauf si la règle est désactivée', () => {
    const old = finding({ is_new: false, severity: 'critical' })
    expect(run({ findings: [old] }).verdict).toBe('passed')
    const v = run({ findings: [old], rules: GateRules.parse({ new_code_only: false }) })
    expect(v.verdict).toBe('failed')
    expect(v.new_code_only).toBe(false)
  })

  it('tri humain : faux positif et accepté en cours écartés, accepté échu compté', () => {
    expect(run({ findings: [finding({ status: 'false-positive' })] }).verdict).toBe('passed')
    expect(run({ findings: [finding({ status: 'fixed' })] }).verdict).toBe('passed')
    expect(run({ findings: [finding({ status: 'accepted', status_until: TODAY })] }).verdict).toBe('passed')
    expect(run({ findings: [finding({ status: 'accepted', status_until: '2026-11-23' })] }).verdict).toBe('failed')
    expect(run({ findings: [finding({ status: 'confirmed' })] }).verdict).toBe('failed')
  })

  describe('exceptions', () => {
    it('path : glob, outil facultatif', () => {
      const f = finding({ path: 'tests/fixtures/a.js' })
      let v = run({ findings: [f], exceptions: [exc('path', { glob: 'tests/**' })] })
      expect(v.verdict).toBe('passed')
      expect(v.exceptions_applied).toHaveLength(1)
      expect(v.exceptions_applied[0]).toMatchObject({ reason: 'motif path', expires_on: '2026-12-31' })
      v = run({ findings: [f], exceptions: [exc('path', { glob: 'tests/**', tool: 'gitleaks' })] })
      expect(v.verdict).toBe('failed')
      expect(v.exceptions_applied).toEqual([])
      v = run({ findings: [finding({ path: null })], exceptions: [exc('path', { glob: '**' })] })
      expect(v.verdict).toBe('failed')
    })

    it('rule, vuln (avec paquet facultatif) et finding', () => {
      const f = finding({ rule_id: 'CVE-2026-0001', vuln_ids: ['CVE-2026-0001', 'GHSA-aaaa-bbbb-cccc'], package_name: 'lodash' })
      expect(run({ findings: [f], exceptions: [exc('rule', { rule_id: 'CVE-2026-0001' })] }).verdict).toBe('passed')
      expect(run({ findings: [f], exceptions: [exc('rule', { rule_id: 'CVE-2026-0001', tool: 'grype' })] }).verdict).toBe('failed')
      expect(run({ findings: [f], exceptions: [exc('vuln', { vuln_id: 'ghsa-aaaa-bbbb-cccc' })] }).verdict).toBe('passed')
      expect(run({ findings: [f], exceptions: [exc('vuln', { vuln_id: 'CVE-2026-0001', package: 'lodash' })] }).verdict).toBe('passed')
      expect(run({ findings: [f], exceptions: [exc('vuln', { vuln_id: 'CVE-2026-0001', package: 'autre' })] }).verdict).toBe('failed')
      expect(run({ findings: [f], exceptions: [exc('finding', { finding_id: f.id })] }).verdict).toBe('passed')
      expect(run({ findings: [f], exceptions: [exc('finding', { finding_id: randomUUID() })] }).verdict).toBe('failed')
    })

    it('expirée, cible invalide ou type inconnu : ignorée', () => {
      const f = finding()
      expect(run({ findings: [f], exceptions: [exc('finding', { finding_id: f.id }, { expires_on: '2026-11-23' })] }).verdict).toBe('failed')
      expect(run({ findings: [f], exceptions: [exc('finding', { finding_id: f.id, extra: 1 })] }).verdict).toBe('failed')
      expect(run({ findings: [f], exceptions: [exc('rule', 'R1')] }).verdict).toBe('failed')
      expect(run({ findings: [f], exceptions: [exc('wildcard', { finding_id: f.id })] }).verdict).toBe('failed')
      expect(run({ findings: [f], exceptions: [exc('finding', { finding_id: f.id }, { expires_on: TODAY })] }).verdict).toBe('passed')
    })

    it('exceptions appliquées listées une fois, triées par échéance', () => {
      const a = finding({ path: 'tests/a.js' })
      const b = finding({ path: 'tests/b.js' })
      const late = exc('path', { glob: 'tests/**' }, { expires_on: '2027-06-30' })
      const soon = exc('module', { module_id: 'trivy' }, { expires_on: '2026-12-01' })
      const v = run({ findings: [a, b], exceptions: [late, soon], modules: [{ module_id: 'trivy', status: 'timeout' }] })
      expect(v.exceptions_applied.map(e => e.id)).toEqual([soon.id, late.id])
    })
  })

  describe('G13 : modules du plan', () => {
    it.each([
      ['missing', 'module-missing', ['install-module', 'request-exception']],
      ['invalid-output', 'output-invalid', ['rerun', 'request-exception']],
      ['error', 'module-error', ['rerun', 'request-exception']],
      ['timeout', 'module-error', ['rerun', 'request-exception']],
      ['oom', 'module-error', ['rerun', 'request-exception']],
      ['pending', 'module-error', ['rerun', 'request-exception']],
      ['running', 'module-error', ['rerun', 'request-exception']],
    ])('%s → non concluant (%s)', (status, code, actions) => {
      const v = run({ modules: [ok('gitleaks'), { module_id: 'trivy', status }] })
      expect(v.verdict).toBe('inconclusive')
      expect(v.reasons).toEqual([{ code, blocking: true, count: 1, severity: null, module: 'trivy', finding_ids: [], actions }])
    })

    it('skipped est neutre', () => {
      expect(run({ modules: [ok('gitleaks'), { module_id: 'trivy', status: 'skipped' }] }).verdict).toBe('passed')
    })

    it('plan vide → non concluant', () => {
      const v = run({ modules: [] })
      expect(v.verdict).toBe('inconclusive')
      expect(v.reasons[0]).toMatchObject({ code: 'module-missing', module: null, actions: ['install-module'] })
    })

    it('exception datée de type module : informative, verdict levé', () => {
      const e = exc('module', { module_id: 'trivy' })
      const v = run({ modules: [{ module_id: 'trivy', status: 'error' }], exceptions: [e] })
      expect(v.verdict).toBe('passed')
      expect(v.reasons[0]).toMatchObject({ code: 'module-error', blocking: false, actions: [] })
      expect(v.exceptions_applied.map(x => x.id)).toEqual([e.id])
      expect(run({ modules: [{ module_id: 'trivy', status: 'error' }], exceptions: [exc('module', { module_id: 'trivy' }, { expires_on: '2026-01-01' })] }).verdict).toBe('inconclusive')
    })

    it('un résultat bloquant rend « failed » même si un module échoue', () => {
      const v = run({ findings: [finding({ severity: 'critical' })], modules: [{ module_id: 'trivy', status: 'oom' }] })
      expect(v.verdict).toBe('failed')
      expect(v.reasons.map(r => r.code)).toEqual(['vuln', 'module-error'])
    })
  })

  it('couverture : trous signalés sans bloquer', () => {
    const v = run({ coverage: { gaps: [{ kind: 'lockfile-missing', manager: 'npm' }, { kind: 'language-without-module', language: 'go' }] } })
    expect(v.verdict).toBe('passed')
    expect(v.reasons).toEqual([{ code: 'coverage-gap', blocking: false, count: 2, severity: null, module: null, finding_ids: [], actions: ['install-module'] }])
    expect(run({ coverage: { gaps: 'x' } }).reasons).toEqual([])
    expect(run({ coverage: 'x' }).reasons).toEqual([])
  })

  it('ordre des raisons : malveillant, secrets, bloquants par gravité, modules, informations', () => {
    const v = run({
      findings: [
        finding({ category: 'iac', severity: 'high' }),
        finding({ category: 'sast', severity: 'critical' }),
        finding({ category: 'sca', severity: 'low' }),
        finding({ category: 'secrets', secret_type: 'generic' }),
        finding({ malicious: true }),
      ],
      modules: [ok('gitleaks'), { module_id: 'trivy', status: 'missing' }],
      coverage: { gaps: [{ kind: 'skipped-files' }] },
    })
    expect(v.reasons.map(r => `${r.code}:${r.severity ?? r.module ?? ''}:${r.blocking}`)).toEqual([
      'malicious-package:high:true', 'secret:high:true', 'sast:critical:true', 'iac:high:true',
      'module-missing:trivy:true', 'vuln:low:false', 'coverage-gap::false',
    ])
  })

  it('au plus 50 identifiants par raison, les plus graves d’abord', () => {
    const many = Array.from({ length: 70 }, () => finding({ category: 'secrets', secret_type: 'generic', severity: 'medium' }))
    const crit = finding({ category: 'secrets', secret_type: 'generic', severity: 'critical' })
    const v = run({ findings: [...many, crit] })
    expect(v.reasons[0]!.count).toBe(71)
    expect(v.reasons[0]!.finding_ids).toHaveLength(50)
    expect(v.reasons[0]!.finding_ids[0]).toBe(crit.id)
  })

  it('règles invalides refusées (H4 et G13 non désactivables)', () => {
    expect(() => run({ rules: { ...GateRules.parse({}), block_malicious: false } as unknown as GateRules })).toThrow()
  })
})

describe('aides', () => {
  it('globToRegExp', () => {
    const m = (g: string, p: string) => globToRegExp(g).test(p)
    expect(m('tests/**', 'tests/a/b.js')).toBe(true)
    expect(m('tests/**', 'src/tests/a.js')).toBe(false)
    expect(m('**/test_*.py', 'test_a.py')).toBe(true)
    expect(m('**/test_*.py', 'a/b/test_a.py')).toBe(true)
    expect(m('*.md', 'docs/a.md')).toBe(false)
    expect(m('docs/?.md', 'docs/a.md')).toBe(true)
    expect(m('a.b(c)+', 'a.b(c)+')).toBe(true)
    expect(m('a.b', 'axb')).toBe(false)
  })

  it('rulesFromPlan : règles figées valides, sinon null', () => {
    expect(rulesFromPlan(null)).toBeNull()
    expect(rulesFromPlan({ modules: [] })).toBeNull()
    expect(rulesFromPlan({ gate: { rules: { max_secrets: 3 } } })).toMatchObject({ max_secrets: 3, new_code_only: true })
    expect(rulesFromPlan({ gate: { rules: { block_malicious: false } } })).toBeNull()
  })

  it('références Git et corps des requêtes', () => {
    for (const r of ['main', 'v1.2.3', 'feat/x', 'refs/tags/v1', 'a'.repeat(40)]) expect(validRef(r), r).toBe(true)
    for (const r of ['-x', '--upload-pack=x', 'a..b', 'a b', 'a~1', 'a^', 'a:b', 'x.lock', '/a', 'a/', 'a@{1}', 'a\u0001', 'a\\b', 'a*']) expect(validRef(r), r).toBe(false)
    expect(scanCreateSchema.safeParse({ ref: 'main', profile: 'rapide' }).success).toBe(true)
    expect(scanCreateSchema.safeParse({ ref: 'main', profile: 'Rapide!' }).success).toBe(false)
    expect(scanCreateSchema.safeParse({ ref: 'main', extra: 1 }).success).toBe(false)
    expect(tokenCreateSchema.safeParse({ name: 'ci' }).success).toBe(true)
    expect(tokenCreateSchema.safeParse({ name: 'c\ni' }).success).toBe(false)
    expect(tokenCreateSchema.safeParse({ name: 'ci', expires_in_days: 0 }).success).toBe(false)
    expect(gateCreateSchema.safeParse({ slug: 'strict' }).success).toBe(true)
    expect(gateCreateSchema.safeParse({ slug: 'Strict' }).success).toBe(false)
  })

  it('jetons : format, empreinte, préfixe', () => {
    const seen = new Set<string>()
    for (let i = 0; i < 50; i++) {
      const tok = generateToken()
      expect(tok).toMatch(API_TOKEN_RE)
      seen.add(tok)
    }
    expect(seen.size).toBe(50)
    const tok = generateToken()
    expect(hashToken(tok)).toMatch(/^[0-9a-f]{64}$/)
    expect(tokenPrefix(tok)).toMatch(/^scn_[A-Za-z0-9]{4}$/)
  })

  it('badge SVG : texte fixe par verdict', () => {
    expect(badgeSvg('passed')).toContain('>passed<')
    expect(badgeSvg('failed')).toContain('#c62828')
    expect(badgeSvg('inconclusive')).toContain('>inconclusive<')
    expect(badgeSvg(null)).toContain('>unknown<')
    expect(badgeSvg('passed').startsWith('<svg xmlns="http://www.w3.org/2000/svg"')).toBe(true)
  })
})
