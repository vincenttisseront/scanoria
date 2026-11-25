// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// 0.7 chantier A : modules SAST, IaC et CI. Manifestes (licence, réseau,
// applicabilité, jeux de règles G4), SARIF produit par les convertisseurs de
// sast_run.py (modules/<id>/tests/converted.sarif, vérifié par b31-sast.sh)
// lu par la console : gravités, catégories, secrets jamais recopiés, verdict.

import { randomUUID } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'
import { parse as parseYaml } from 'yaml'
import { parseSarif } from '../../server/findings/parse'
import { originSeverity } from '../../server/findings/severity'
import { computeVerdict, type GateFinding } from '../../server/gates/evaluate'
import { GateRules } from '#shared/analysis'

const MODULES = fileURLToPath(new URL('../../../modules/', import.meta.url))
interface Manifest {
  id: string
  type: string
  categories: string[]
  license: { spdx: string, restrictions: string }
  image?: string
  image_pending?: boolean
  severity_map?: Record<string, string>
  scan: { network: string, command: string[], rulesets?: { engine: string, mount: string, required?: boolean, env?: string }, applies_to?: unknown }
}
const manifest = (id: string) => parseYaml(readFileSync(`${MODULES}${id}/module.yaml`, 'utf8')) as Manifest
const converted = (id: string) => JSON.parse(readFileSync(`${MODULES}${id}/tests/converted.sarif`, 'utf8')) as unknown

const NEW = ['opengrep', 'semgrep', 'checkov', 'kics', 'bandit', 'zizmor', 'scorecard']

function verdictOf(id: string) {
  const m = manifest(id)
  const out = parseSarif(converted(id), { moduleId: id, moduleCategories: m.categories })
  const findings: GateFinding[] = out.findings.map(f => ({
    id: randomUUID(), tool: id, rule_id: f.ruleId, category: f.category, severity: originSeverity(f.nativeSeverity, m.severity_map),
    path: f.path, vuln_ids: [], package_name: null, malicious: false, secret_type: null, status: 'new', status_until: null, is_new: true,
  }))
  return { out, findings, v: computeVerdict({
    gateId: randomUUID(), rules: GateRules.parse({}), modules: [{ module_id: id, status: 'ok' }], findings, exceptions: [],
    coverage: null, today: '2026-11-25', evaluatedAt: '2026-11-25T10:00:00Z',
  }) }
}

describe('sast : manifestes', () => {
  it.each(NEW)('%s : scanner sans réseau, image épinglée ou construite, licence libre', (id) => {
    const m = manifest(id)
    expect(m.type).toBe('scanner')
    expect(m.scan.network).toBe('none')
    if (m.image_pending) expect(m.image).toBeUndefined()
    else expect(m.image).toMatch(/@sha256:[0-9a-f]{64}$/)
    expect(m.license.spdx).toMatch(/^(Apache-2\.0|MIT|LGPL-2\.1-only)$/)
  })

  it('jeux de règles : moteurs et montage /rules ; Semgrep exige un jeu (règles officielles jamais livrées)', () => {
    expect(manifest('opengrep').scan.rulesets).toEqual({ engine: 'opengrep', mount: '/rules' })
    expect(manifest('semgrep').scan.rulesets).toEqual({ engine: 'semgrep', mount: '/rules', required: true })
    expect(manifest('semgrep').license.restrictions).toBe('other')
    expect(manifest('checkov').scan.rulesets?.engine).toBe('checkov')
    expect(manifest('kics').scan.rulesets?.engine).toBe('kics')
    expect(manifest('gitleaks').scan.rulesets).toEqual({ engine: 'gitleaks', mount: '/rules', env: 'GITLEAKS_CONFIG' })
  })

  it('zizmor (H1) ne tourne que sur des workflows ; Scorecard (H2) en catégorie ci', () => {
    expect(JSON.stringify(manifest('zizmor').scan.applies_to)).toContain('ci')
    expect(manifest('zizmor').categories).toContain('ci')
    expect(manifest('scorecard').categories).toContain('ci')
    expect(manifest('scorecard').scan.command).toContain('--min-score={opt.min_score}')
  })
})

describe('sast : Bandit converti', () => {
  it('gravités : confiance faible abaissée d’un cran, CWE en étiquette ; secrets jamais recopiés', () => {
    const { out } = verdictOf('bandit')
    const by = Object.fromEntries(out.findings.map(f => [f.ruleId, f]))
    expect(Object.keys(by).sort()).toEqual(['bandit/B105', 'bandit/B301', 'bandit/B506', 'bandit/B602'])
    expect(originSeverity(by['bandit/B602']!.nativeSeverity, null)).toBe('high')
    expect(originSeverity(by['bandit/B506']!.nativeSeverity, null)).toBe('low')
    expect(by['bandit/B602']!.cwe).toEqual(['CWE-78'])
    expect(JSON.stringify(converted('bandit'))).not.toContain('valeur-de-test')
  })

  it('verdict par défaut : bloquant (mot de passe en dur compté comme secret, SAST high)', () => {
    const { v } = verdictOf('bandit')
    expect(v.verdict).toBe('failed')
    expect(v.reasons.filter(r => r.blocking).map(r => [r.code, r.severity])).toEqual([['secret', 'low'], ['sast', 'high']])
  })
})

describe('sast : Scorecard converti', () => {
  it('score global sous le seuil : résultat high en catégorie ci, bloquant ; contrôles faibles informatifs', () => {
    const { out, v } = verdictOf('scorecard')
    const by = Object.fromEntries(out.findings.map(f => [f.ruleId, f]))
    expect(originSeverity(by['scorecard/score-below-threshold']!.nativeSeverity, null)).toBe('high')
    expect(by['scorecard/score-below-threshold']!.category).toBe('ci')
    expect(originSeverity(by['scorecard/Token-Permissions']!.nativeSeverity, null)).toBe('low')
    expect(by['scorecard/Token-Permissions']!.path).toBe('.github/workflows/triage.yml')
    // -1 (non concluant en local) et 10 : aucun résultat.
    expect(by['scorecard/Pinned-Dependencies']).toBeUndefined()
    expect(by['scorecard/License']).toBeUndefined()
    expect(v.verdict).toBe('failed')
    expect(v.reasons.filter(r => r.blocking).map(r => r.code)).toEqual(['sast'])
  })
})
