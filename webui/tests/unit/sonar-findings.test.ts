// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Chantier B de la 0.4 : résultats SonarQube dans les résultats unifiés.
// Catégorie explicite (« scanoria-category: ») retenue seulement si le module
// la déclare, jamais au-dessus des secrets ; catégories des modules existants
// inchangées ; gravités natives et table du manifeste sonar-scanner ; tâche du
// runner avec project_id et default_branch facultatifs (contrat 8 étendu).

import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'
import { parse as parseYaml } from 'yaml'
import { parseSarif } from '../../server/findings/parse'
import { EXPLICIT_CATEGORY_TAG, inferCategory } from '../../server/findings/normalize'
import { originSeverity } from '../../server/findings/severity'
import { scanJobSchema } from '../../server/scans/contract'

const MODULES = fileURLToPath(new URL('../../../modules/', import.meta.url))
const recorded = (id: string) => JSON.parse(readFileSync(`${MODULES}${id}/tests/recorded.sarif`, 'utf8')) as unknown
const manifest = (id: string) => parseYaml(readFileSync(`${MODULES}${id}/module.yaml`, 'utf8')) as {
  categories: string[]
  scan: { severity_map: Record<string, string> }
}

describe('catégorie explicite', () => {
  const base = { hasVuln: false, hasPackage: false }
  it('retenue si le module déclare la catégorie', () => {
    expect(inferCategory({ ...base, moduleCategories: ['quality', 'sast'], tags: [`${EXPLICIT_CATEGORY_TAG}quality`] })).toBe('quality')
    expect(inferCategory({ ...base, moduleCategories: ['quality', 'sast'], tags: [`${EXPLICIT_CATEGORY_TAG}sast`] })).toBe('sast')
  })
  it('ignorée si le module ne la déclare pas', () => {
    expect(inferCategory({ ...base, moduleCategories: ['sast'], tags: [`${EXPLICIT_CATEGORY_TAG}quality`] })).toBe('sast')
    expect(inferCategory({ ...base, moduleCategories: ['quality', 'sast'], tags: [`${EXPLICIT_CATEGORY_TAG}iac`] })).toBe('sast')
  })
  it('jamais au-dessus des secrets', () => {
    expect(inferCategory({ ...base, moduleCategories: ['quality', 'sast'], tags: ['secret', `${EXPLICIT_CATEGORY_TAG}quality`] })).toBe('secrets')
    expect(inferCategory({ ...base, moduleCategories: ['quality'], tags: [`${EXPLICIT_CATEGORY_TAG}quality`], cwe: ['CWE-798'] })).toBe('secrets')
  })
})

describe('SonarQube : SARIF du convertisseur', () => {
  const m = manifest('sonar-scanner')
  const out = parseSarif(recorded('sonar-scanner'), { moduleId: 'sonar-scanner', moduleCategories: m.categories })
  const byRule = Object.fromEntries(out.findings.map(f => [f.ruleId, f]))

  it('lit tous les résultats, sans problème de lecture', () => {
    expect(out.issues).toEqual([])
    expect(out.findings).toHaveLength(7)
  })
  it('code smells et bugs en qualité, vulnérabilités et hotspots en SAST', () => {
    expect(byRule['python:S1481']!.category).toBe('quality')
    expect(byRule['python:S1192']!.category).toBe('quality')
    expect(byRule['python:S2068']!.category).toBe('sast')
    expect(byRule['python:S2077']!.category).toBe('sast')
    // Issues de sécurité (VULNERABILITY) en SAST, bugs de fiabilité en qualité.
    expect(byRule['python:S4830']!.category).toBe('sast')
    expect(byRule['python:S1656']!.category).toBe('quality')
    expect(byRule['python:S1862']!.category).toBe('quality')
  })
  it('gravité native lisible, normalisée par la table du manifeste', () => {
    expect(byRule['python:S1481']!.nativeSeverity).toBe('low')
    expect(byRule['python:S1192']!.nativeSeverity).toBe('high')
    expect(byRule['python:S2068']!.nativeSeverity).toBe('high')
    expect(originSeverity('major', m.scan.severity_map)).toBe('medium')
    expect(originSeverity('critical', m.scan.severity_map)).toBe('high')
    expect(originSeverity('blocker', m.scan.severity_map)).toBe('critical')
    expect(originSeverity('minor', m.scan.severity_map)).toBe('low')
  })
  it('empreinte stable fondée sur la clé SonarQube, indépendante de la ligne (G19)', () => {
    const doc = recorded('sonar-scanner') as { runs: { results: { locations: { physicalLocation: { region: { startLine: number } } }[] }[] }[] }
    for (const r of doc.runs[0]!.results) r.locations[0]!.physicalLocation.region.startLine += 7
    const moved = parseSarif(doc, { moduleId: 'sonar-scanner', moduleCategories: m.categories })
    expect(moved.findings.map(f => f.fingerprint).sort()).toEqual(out.findings.map(f => f.fingerprint).sort())
  })
})

describe('modules existants : catégories inchangées', () => {
  const cats = (id: string) => {
    const doc = recorded(id)
    expect(JSON.stringify(doc)).not.toContain(EXPLICIT_CATEGORY_TAG)
    return parseSarif(doc, { moduleId: id, moduleCategories: manifest(id).categories }).findings.map(f => f.category).sort()
  }
  it('gitleaks, OSV-Scanner et Trivy', () => {
    expect(cats('gitleaks')).toEqual(['secrets', 'secrets', 'secrets'])
    expect(new Set(cats('osv-scanner'))).toEqual(new Set(['sca']))
    expect(new Set(cats('trivy'))).toEqual(new Set(TRIVY))
  })
})
const TRIVY = ['iac', 'sca']

describe('tâche du runner : champs facultatifs de la 0.4', () => {
  const job = (src: Record<string, unknown> = {}, extra: Record<string, unknown> = {}) => ({
    schema: 1, id: '0b0b0b0b-0b0b-4b0b-8b0b-0b0b0b0b0b0b', scan_id: '1c1c1c1c-1c1c-4c1c-8c1c-1c1c1c1c1c1c',
    created_at: '2026-11-24T10:00:00Z',
    source: { kind: 'git', url: 'https://forge.exemple.test/a.git', ref: 'main', history: 'shallow', ...src },
    modules: [{ id: 'sonar-scanner', version: '1.0.0' }],
    ...extra,
  })
  it('accepte une tâche sans les nouveaux champs', () => {
    expect(scanJobSchema.safeParse(job()).success).toBe(true)
  })
  it('accepte project_id et default_branch', () => {
    expect(scanJobSchema.safeParse(job({ default_branch: 'main' }, { project_id: '2d2d2d2d-2d2d-4d2d-8d2d-2d2d2d2d2d2d' })).success).toBe(true)
  })
  it.each(['--upload-pack=x', 'a/../b', 'a//b', 'x@{1}', ''])('refuse la branche par défaut hostile %j', (b) => {
    expect(scanJobSchema.safeParse(job({ default_branch: b })).success).toBe(false)
  })
  it('refuse un projet qui n’est pas un uuid', () => {
    expect(scanJobSchema.safeParse(job({}, { project_id: '../x' })).success).toBe(false)
  })
})
