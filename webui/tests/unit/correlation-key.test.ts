// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// F16 (0.5, chantier C) : clé de recoupement (contrat 18) pour chaque famille,
// alias ramenés au CVE, purl sans version, regroupement dans le quality gate
// (un groupe compte une seule fois, à la gravité la plus haute), résultat seul
// inchangé, rejeu d'un plan d'avant la 0.5 inchangé (G11).

import { createHash, randomUUID } from 'node:crypto'
import { describe, expect, it } from 'vitest'
import { canonicalVulnId, collapseCorrelated, correlationKey, purlWithoutVersion, type CorrelationInput } from '../../server/findings/correlation'
import { computeVerdict, planIsPre05, type GateFinding, type GateInput } from '../../server/gates/evaluate'
import { fingerprintOf } from '../../server/findings/normalize'
import { GateRules } from '#shared/analysis'

const sha = (s: string) => createHash('sha256').update(s, 'utf8').digest('hex')

function input(p: Partial<CorrelationInput> = {}): CorrelationInput {
  return { category: 'sca', cwe: [], vuln_ids: [], package: null, path: null, snippet: null, start_line: null, secret_type: null, ...p }
}

describe('correlationKey', () => {
  it('vulnérabilité de dépendance : vuln:<CVE>|<purl sans version>', () => {
    const k = correlationKey(input({ vuln_ids: ['GHSA-xvch-5gv4-984h', 'CVE-2021-44906'], package: { ecosystem: 'npm', name: 'Minimist' } }))
    expect(k).toBe(sha('vuln:CVE-2021-44906|pkg:npm/minimist'))
    expect(k).toMatch(/^[0-9a-f]{64}$/)
  })

  it('alias GHSA et OSV ramenés au CVE : deux outils, une seule clé', () => {
    const osv = correlationKey(input({ vuln_ids: ['GHSA-xvch-5gv4-984h', 'CVE-2021-44906'], package: { ecosystem: 'npm', name: 'minimist' } }))
    const trivy = correlationKey(input({ vuln_ids: ['CVE-2021-44906'], package: { ecosystem: 'npm', name: 'minimist' } }))
    expect(osv).toBe(trivy)
    expect(canonicalVulnId(['osv-2026-1', 'GHSA-aaaa-bbbb-cccc'])).toBe('GHSA-AAAA-BBBB-CCCC')
    expect(canonicalVulnId(['PYSEC-2026-2', 'OSV-2026-1'])).toBe('OSV-2026-1')
    expect(canonicalVulnId(['CVE-2026-0002', 'CVE-2026-0001'])).toBe('CVE-2026-0001')
    expect(canonicalVulnId([])).toBeNull()
    expect(canonicalVulnId(null)).toBeNull()
  })

  it('purl sans version, nom normalisé (PyPI : PEP 503)', () => {
    expect(purlWithoutVersion({ ecosystem: 'PyPI', name: 'Django_Rest.Framework' })).toBe('pkg:pypi/django-rest-framework')
    expect(purlWithoutVersion({ ecosystem: 'Go', name: 'golang.org/x/net' })).toBe('pkg:golang/golang.org/x/net')
    expect(purlWithoutVersion({ ecosystem: 'Maven', name: 'org.example:lib' })).toBe('pkg:maven/org.example:lib')
    expect(purlWithoutVersion({ ecosystem: null, name: 'x' })).toBe('pkg:generic/x')
    expect(purlWithoutVersion({ ecosystem: 'Exotic Eco', name: 'x' })).toBe('pkg:exoticeco/x')
    expect(purlWithoutVersion({ ecosystem: 'npm', name: '  ' })).toBeNull()
    expect(purlWithoutVersion(null)).toBeNull()
  })

  it('même paquet, versions différentes : même clé ; autre paquet : autre clé', () => {
    const a = correlationKey(input({ vuln_ids: ['CVE-2026-1000'], package: { ecosystem: 'npm', name: 'lodash' } }))
    const b = correlationKey(input({ vuln_ids: ['CVE-2026-1000'], package: { ecosystem: 'npm', name: 'lodash' }, path: 'other/package-lock.json' }))
    const c = correlationKey(input({ vuln_ids: ['CVE-2026-1000'], package: { ecosystem: 'npm', name: 'underscore' } }))
    expect(a).toBe(b)
    expect(c).not.toBe(a)
  })

  it('SAST et IaC : cwe:<n>|<chemin>|<empreinte de contexte>, indépendante de l’outil et de l’indentation', () => {
    const semgrep = correlationKey(input({ category: 'sast', cwe: ['CWE-89', 'CWE-943'], path: 'src/db.py', snippet: 'cur.execute("SELECT " + q)' }))
    const bandit = correlationKey(input({ category: 'sast', cwe: ['CWE-89'], path: 'src/db.py', snippet: '   cur.execute("SELECT "   + q)\n' }))
    expect(semgrep).toBe(bandit)
    expect(semgrep).toBe(sha(`cwe:89|src/db.py|${sha('ctx\u001fcur.execute("SELECT " + q)')}`))
    const iac = correlationKey(input({ category: 'iac', cwe: ['CWE-732'], path: 'main.tf', snippet: 'acl = "public-read"' }))
    expect(iac).toMatch(/^[0-9a-f]{64}$/)
    expect(correlationKey(input({ category: 'sast', cwe: ['CWE-89'], path: 'src/other.py', snippet: 'cur.execute("SELECT " + q)' }))).not.toBe(semgrep)
  })

  it('sans extrait : la ligne sert de contexte ; extrait masqué ignoré', () => {
    const a = correlationKey(input({ category: 'sast', cwe: ['CWE-79'], path: 'a.js', start_line: 12 }))
    expect(a).toBe(sha('cwe:79|a.js|L12'))
    expect(correlationKey(input({ category: 'sast', cwe: ['CWE-79'], path: 'a.js', snippet: '[secret masqué : snippet, longueur 40]', start_line: 3 }))).toBe(sha('cwe:79|a.js|L3'))
    expect(correlationKey(input({ category: 'sast', cwe: ['CWE-79'], path: 'a.js' }))).toBeNull()
  })

  it('null : secrets, qualité, SAST sans CWE ni chemin, vulnérabilité sans paquet', () => {
    expect(correlationKey(input({ category: 'secrets', vuln_ids: ['CVE-2026-1'], package: { ecosystem: 'npm', name: 'x' } }))).toBeNull()
    expect(correlationKey(input({ secret_type: 'aws', category: 'sca', vuln_ids: ['CVE-2026-1'], package: { ecosystem: 'npm', name: 'x' } }))).toBeNull()
    expect(correlationKey(input({ category: 'quality', cwe: ['CWE-1'], path: 'a', snippet: 'x' }))).toBeNull()
    expect(correlationKey(input({ category: 'sast', cwe: [], path: 'a', snippet: 'x' }))).toBeNull()
    expect(correlationKey(input({ category: 'sast', cwe: ['CWE-1'], path: null, snippet: 'x' }))).toBeNull()
    expect(correlationKey(input({ category: 'sca', vuln_ids: ['CVE-2026-1'] }))).toBeNull()
    expect(correlationKey(input({ category: 'sast', cwe: ['pas un cwe'], path: 'a', snippet: 'x' }))).toBeNull()
  })

  it('empreinte G19 inchangée : la clé n’entre pas dans fingerprintOf', () => {
    const base = { tool: 'trivy', ruleId: 'CVE-2021-44906', path: 'package-lock.json', context: '', pkg: { ecosystem: 'npm', name: 'minimist', version: '1.2.5', fixed: [] }, vulnId: 'CVE-2021-44906', partial: null }
    expect(fingerprintOf(base)).toBe(sha(['dep', 'trivy', 'npm', 'minimist', '1.2.5', 'CVE-2021-44906'].join('\u001f')))
  })
})

const TODAY = '2026-11-24'
function gf(p: Partial<GateFinding> = {}): GateFinding {
  return {
    id: randomUUID(), tool: 'trivy', rule_id: 'R1', category: 'sca', severity: 'high', path: 'package-lock.json',
    vuln_ids: ['CVE-2026-1000'], package_name: 'lodash', malicious: false, secret_type: null, status: 'new', status_until: null, is_new: true,
    ...p,
  }
}
function run(p: Partial<GateInput> = {}) {
  return computeVerdict({
    gateId: randomUUID(), rules: GateRules.parse({ epss_block_from: null, kev_blocks: false }), modules: [{ module_id: 'trivy', status: 'ok' }, { module_id: 'osv-scanner', status: 'ok' }],
    findings: [], exceptions: [], coverage: null, today: TODAY, evaluatedAt: '2026-11-24T10:00:00Z', ...p,
  })
}

describe('F16 dans le quality gate', () => {
  it('un groupe compte une seule fois, à la gravité la plus haute du groupe', () => {
    const key = 'a'.repeat(64)
    const a = gf({ tool: 'trivy', severity: 'medium', correlation_key: key })
    const b = gf({ tool: 'osv-scanner', severity: 'critical', correlation_key: key })
    const v = run({ findings: [a, b] })
    expect(v.counts).toMatchObject({ critical: 1, medium: 0 })
    expect(v.reasons).toHaveLength(1)
    expect(v.reasons[0]).toMatchObject({ code: 'vuln', severity: 'critical', count: 1, finding_ids: [b.id] })
  })

  it('résultat seul ou sans clé : verdict et raisons identiques', () => {
    const a = gf({ severity: 'high' })
    const b = gf({ severity: 'high', vuln_ids: ['CVE-2026-2000'] })
    const without = run({ findings: [a, b] })
    const withKeys = run({ findings: [{ ...a, correlation_key: 'b'.repeat(64) }, { ...b, correlation_key: 'c'.repeat(64) }] })
    expect(withKeys.verdict).toBe(without.verdict)
    expect(withKeys.reasons).toEqual(without.reasons)
    expect(withKeys.counts).toEqual(without.counts)
  })

  it('un membre exclu (exception, tri) laisse l’autre compter', () => {
    const key = 'd'.repeat(64)
    const a = gf({ tool: 'trivy', severity: 'critical', correlation_key: key, status: 'false-positive' })
    const b = gf({ tool: 'osv-scanner', severity: 'high', correlation_key: key })
    const v = run({ findings: [a, b] })
    expect(v.reasons[0]).toMatchObject({ code: 'vuln', severity: 'high', count: 1, finding_ids: [b.id] })
  })

  it('G11 : rejeu d’un plan d’avant la 0.5 sans regroupement', () => {
    const key = 'e'.repeat(64)
    const v = run({ findings: [gf({ correlation_key: key }), gf({ correlation_key: key, tool: 'osv-scanner' })], correlate: false })
    expect(v.counts.high).toBe(2)
    expect(planIsPre05({ gate: { rules: { vuln_block_from: 'high' } } })).toBe(true)
    expect(planIsPre05({ gate: { rules: { vuln_block_from: 'high', kev_blocks: true } } })).toBe(false)
    expect(planIsPre05({})).toBe(false)
    expect(planIsPre05(null)).toBe(false)
  })

  it('collapseCorrelated : malveillant en tête, KEV et EPSS les plus hauts repris', () => {
    const key = 'f'.repeat(64)
    const list = collapseCorrelated([
      { id: '1', severity: 'critical' as const, malicious: false, correlation_key: key, kev: false, epss: 0.2 },
      { id: '2', severity: 'low' as const, malicious: true, correlation_key: key, kev: true, epss: null },
      { id: '3', severity: 'high' as const, malicious: false, correlation_key: null },
    ])
    expect(list).toEqual([
      { id: '2', severity: 'low', malicious: true, correlation_key: key, kev: true, epss: 0.2 },
      { id: '3', severity: 'high', malicious: false, correlation_key: null },
    ])
    const tie = collapseCorrelated([
      { id: 'b', severity: 'high' as const, malicious: false, correlation_key: key },
      { id: 'a', severity: 'high' as const, malicious: false, correlation_key: key },
    ])
    expect(tie).toEqual([{ id: 'a', severity: 'high', malicious: false, correlation_key: key, kev: false, epss: null }])
  })
})
