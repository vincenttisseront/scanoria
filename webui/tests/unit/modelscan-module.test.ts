// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// K8 (0.6) : SARIF enregistré de ModelScan (modules/modelscan/tests/recorded.sarif)
// lu par la console, gravités critical pour l'exécution de code au chargement,
// catégorie sast et verdict bloquant par défaut ; détection F1 des fichiers de
// modèle et proposition du module.

import { randomUUID } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'
import { parse as parseYaml } from 'yaml'
import { parseSarif } from '../../server/findings/parse'
import { defaultSeverity } from '../../server/findings/severity'
import { computeVerdict, type GateFinding } from '../../server/gates/evaluate'
import { detectRepository, isModelFile, moduleRelevance, suggestModules, type CatalogModuleLite } from '../../server/projects/detect'
import { GateRules } from '#shared/analysis'

const MODULE = fileURLToPath(new URL('../../../modules/modelscan/', import.meta.url))
const manifest = parseYaml(readFileSync(`${MODULE}module.yaml`, 'utf8')) as { id: string, type: string, categories: string[], license: { restrictions: string } }
const recorded = JSON.parse(readFileSync(`${MODULE}tests/recorded.sarif`, 'utf8')) as unknown

describe('modelscan : SARIF enregistré', () => {
  const out = parseSarif(recorded, { moduleId: 'modelscan', moduleCategories: manifest.categories })

  it('chaque résultat est lu, sans défaut, en catégorie sast', () => {
    expect(out.issues).toEqual([])
    expect(out.findings.length).toBe(5)
    expect(new Set(out.findings.map(f => f.category))).toEqual(new Set(['sast']))
    expect(out.findings.every(f => f.cwe.length === 1)).toBe(true)
  })

  it('exécution de code au chargement → critical ; accès fichiers TensorFlow → high', () => {
    const sev = Object.fromEntries(out.findings.map(f => [f.ruleId, defaultSeverity(f.nativeSeverity)]))
    expect(sev['modelscan/pickle-unsafe-op']).toBe('critical')
    expect(sev['modelscan/keras-lambda']).toBe('critical')
    expect(sev['modelscan/unsafe-op']).toBe('critical')
    expect(sev['modelscan/tensorflow-unsafe-op']).toBe('high')
  })

  it('quality gate par défaut : bloquant', () => {
    const findings: GateFinding[] = out.findings.map(f => ({
      id: randomUUID(), tool: 'modelscan', rule_id: f.ruleId, category: f.category, severity: defaultSeverity(f.nativeSeverity),
      path: f.path, vuln_ids: [], package_name: null, malicious: false, secret_type: null, status: 'new', status_until: null, is_new: true,
    }))
    const v = computeVerdict({
      gateId: randomUUID(), rules: GateRules.parse({}), modules: [{ module_id: 'modelscan', status: 'ok' }], findings, exceptions: [],
      coverage: null, today: '2026-11-24', evaluatedAt: '2026-11-24T10:00:00Z',
    })
    expect(v.verdict).toBe('failed')
    expect(v.reasons.find(r => r.blocking)).toMatchObject({ code: 'sast', severity: 'critical' })
  })
})

describe('modelscan : détection F1', () => {
  it('fichiers de modèle reconnus, fichiers ordinaires ignorés', () => {
    for (const p of ['models/clf.pkl', 'a/b/model.pt', 'w.ckpt', 'x.npy', 'm.h5', 'net.keras', 'export/saved_model.pb', 'weights/layer.bin', 'pytorch_model-00001.bin', 'm.joblib'])
      expect(isModelFile(p), p).toBe(true)
    for (const p of ['src/app.py', 'firmware.bin', 'data/x.csv', 'README.md', 'proto/api.pb'])
      expect(isModelFile(p), p).toBe(false)
  })

  it('un dépôt avec un modèle propose modelscan, un dépôt sans modèle non', async () => {
    const tree = (paths: string[]) => ({
      tree: { entries: paths.map(path => ({ path, type: 'file' as const, size: 10 })), truncated: false },
      read: async () => null, ref: 'main', commit: 'a'.repeat(40), now: new Date('2026-11-24T10:00:00Z'),
    })
    const lite: CatalogModuleLite = { id: 'modelscan', type: 'scanner', categories: manifest.categories, license: { restrictions: manifest.license.restrictions } } as CatalogModuleLite
    const withModel = await detectRepository(tree(['train.py', 'models/clf.pkl']))
    expect(withModel.models).toEqual(['models/clf.pkl'])
    expect(withModel.categories).toContain('sast')
    expect(moduleRelevance(lite, withModel)).toBe('models')
    const sug = suggestModules(withModel, [lite], [])
    expect(sug.modules.some(m => m.id === 'modelscan' && m.reason === 'models')).toBe(true)
    const without = await detectRepository(tree(['train.py']))
    expect(moduleRelevance(lite, without)).toBeNull()
  })

  it('le manifeste : scanner sans réseau, image épinglée, licence sans restriction', () => {
    const m = parseYaml(readFileSync(`${MODULE}module.yaml`, 'utf8')) as { image: string, scan: { network: string, inputs: string[] } }
    expect(manifest.type).toBe('scanner')
    expect(m.image).toMatch(/@sha256:[0-9a-f]{64}$/)
    expect(m.scan.network).toBe('none')
    expect(m.scan.inputs).toEqual(expect.arrayContaining(['repo', 'image']))
    expect(manifest.license.restrictions).toBe('none')
  })
})
