// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Jeux de règles G4 (0.7 chantier A) : contrôles statiques (mêmes règles que
// rulesets.py du runner), écart entre versions, résolution du plan (jeux du
// profil attribués aux modules de leur moteur, Semgrep sans jeu écarté avec
// un trou de couverture), plan figé relu (G11), tâche du runner.

import { randomUUID } from 'node:crypto'
import { describe, expect, it } from 'vitest'
import { lineDiff, sha256Hex, staticIssues } from '../../server/rulesets/store'
import { parsePlan, resolveProfile, type PlanCatalogEntry, type ScanPlan, PLAN_VERSION } from '../../server/scans/plan'
import { scanJobSchema } from '../../server/scans/contract'
import type { InstalledModule } from '../../server/utils/catalog'
import { GateRules } from '#shared/analysis'

describe('ruleset : contrôles statiques', () => {
  it('Opengrep, Semgrep : clé rules obligatoire ; contenu vide, octet nul ou trop gros refusé', () => {
    expect(staticIssues('opengrep', 'rules:\n  - id: a\n')).toEqual([])
    expect(staticIssues('semgrep', 'regles: []\n')).toEqual(['missing-rules-key'])
    expect(staticIssues('opengrep', '  \n')).toEqual(['empty'])
    expect(staticIssues('opengrep', 'rules: []\n\u0000')).toEqual(['nul-byte'])
    expect(staticIssues('opengrep', `rules:\n${'#'.repeat(1024 * 1024)}`)).toEqual(['too-large'])
  })

  it('gitleaks : [extend] ne désigne ni fichier ni adresse', () => {
    expect(staticIssues('gitleaks', '[extend]\nuseDefault = true\n')).toEqual([])
    expect(staticIssues('gitleaks', '[extend]\npath = "/etc/passwd"\n')).toEqual(['gitleaks-extend-include'])
    expect(staticIssues('gitleaks', '[extend]\n  url = "https://exemple.test/x.toml"\n')).toEqual(['gitleaks-extend-include'])
    // « path » d'une autre table (allowlist) reste permis.
    expect(staticIssues('gitleaks', '[extend]\nuseDefault = true\n[allowlist]\npaths = ["^tests/"]\n')).toEqual([])
  })

  it('Checkov : metadata et definition ; KICS : JSON { queries } strict, identifiants uniques', () => {
    expect(staticIssues('checkov', 'metadata:\n  id: CKV2_INT_1\ndefinition:\n  cond_type: attribute\n')).toEqual([])
    expect(staticIssues('checkov', 'foo: 1\n')).toEqual(['missing-policy-keys'])
    const q = { id: 'interne-1', metadata: { id: 'interne-1' }, query: 'package Cx\nCxPolicy[result] { false }' }
    expect(staticIssues('kics', JSON.stringify({ queries: [q] }))).toEqual([])
    expect(staticIssues('kics', '{')).toEqual(['invalid-json'])
    expect(staticIssues('kics', JSON.stringify({ queries: [{ ...q, id: '../x' }] }))).toEqual(['kics-structure'])
    expect(staticIssues('kics', JSON.stringify({ queries: [q], extra: 1 }))).toEqual(['kics-structure'])
    expect(staticIssues('kics', JSON.stringify({ queries: [q, q] }))).toEqual(['kics-duplicate-id'])
  })
})

describe('ruleset : écart entre versions', () => {
  it('lignes ajoutées, retirées, inchangées ; trop grand = null', () => {
    expect(lineDiff('a\nb\nc', 'a\nc\nd')).toEqual([{ op: ' ', text: 'a' }, { op: '-', text: 'b' }, { op: ' ', text: 'c' }, { op: '+', text: 'd' }])
    expect(lineDiff('x', 'x')).toEqual([{ op: ' ', text: 'x' }])
    expect(lineDiff('a\n'.repeat(5000), 'b')).toBeNull()
  })
})

describe('ruleset : plan figé', () => {
  const installed = (id: string): InstalledModule => ({
    id, version: '1.0.0', type: 'scanner', status: 'healthy', enabled: true, installed_at: null, options: {}, testbed: null, route: null, last_error: null,
  })
  const entry = (id: string, rulesets?: { engine: 'opengrep' | 'semgrep' | 'gitleaks', required?: boolean }): PlanCatalogEntry => ({
    id, version: '1.0.0', type: 'scanner', categories: id === 'gitleaks' ? ['secrets'] : ['sast'], image: `ghcr.io/exemple/${id}@sha256:${'a'.repeat(64)}`,
    restrictions: 'none', feeds: [], outputs: ['sarif'], options: null, scan: { inputs: ['repo', 'archive'], timeout_s: 600, ...(rulesets ? { rulesets } : {}) },
  })
  const catalog = new Map([entry('opengrep', { engine: 'opengrep' }), entry('semgrep', { engine: 'semgrep', required: true }), entry('gitleaks', { engine: 'gitleaks' })]
    .map(e => [`${e.id}@${e.version}`, e]))
  const profile = (include: string[] = []) => ({ id: randomUUID(), slug: 'complet', categories: ['sast', 'secrets'], include_modules: include, exclude_modules: [] })
  const rs = (slug: string, engine: 'opengrep' | 'semgrep' | 'gitleaks', version = 1) => ({ slug, engine, version, sha256: sha256Hex(`${slug}${version}`) })
  const mods = ['opengrep', 'semgrep', 'gitleaks'].map(installed)

  it('chaque module reçoit les jeux de son moteur ; Semgrep sans jeu n’est pas planifié', () => {
    const r = resolveProfile({ profile: profile(), sourceKind: 'git', projectLicense: null, installed: mods, catalog,
      rulesets: [rs('interne', 'opengrep', 3), rs('equipe', 'opengrep'), rs('gl', 'gitleaks')] })
    expect(r.modules.map(m => [m.id, m.rulesets?.map(x => `${x.slug}@${x.version}`)])).toEqual([
      ['gitleaks', ['gl@1']], ['opengrep', ['interne@3', 'equipe@1']]])
    expect(r.gaps).toEqual([])
  })

  it('Semgrep demandé explicitement sans jeu : trou de couverture « no-ruleset » ; avec un jeu : planifié', () => {
    const none = resolveProfile({ profile: profile(['semgrep']), sourceKind: 'git', projectLicense: null, installed: mods, catalog })
    expect(none.gaps).toEqual([{ kind: 'profile-module', category: null, module: 'semgrep', reason: 'no-ruleset' }])
    const some = resolveProfile({ profile: profile(['semgrep']), sourceKind: 'git', projectLicense: null, installed: mods, catalog, rulesets: [rs('officiel', 'semgrep')] })
    expect(some.modules.find(m => m.id === 'semgrep')?.rulesets).toEqual([rs('officiel', 'semgrep')])
  })

  it('le plan enregistré garde slug, version et empreinte ; la tâche du runner les accepte', () => {
    const r = resolveProfile({ profile: profile(), sourceKind: 'git', projectLicense: null, installed: mods, catalog, rulesets: [rs('interne', 'opengrep', 2)] })
    const plan: ScanPlan = {
      version: PLAN_VERSION, created_at: '2026-11-25T10:00:00Z', source: { kind: 'git', ref: 'main', commit: null, history: 'shallow' },
      profile: profile(), gate: { id: randomUUID(), slug: 'defaut', rules: GateRules.parse({}) }, modules: r.modules, gaps: [], timeout_s: 1200,
    }
    const back = parsePlan(JSON.parse(JSON.stringify(plan)))
    expect(back?.modules.find(m => m.id === 'opengrep')?.rulesets).toEqual([rs('interne', 'opengrep', 2)])
    expect(parsePlan(JSON.parse(JSON.stringify({ ...plan, modules: [{ ...r.modules[1], rulesets: [{ ...rs('x', 'opengrep'), sha256: 'zz' }] }] })))).toBeNull()
    const og = r.modules.find(m => m.id === 'opengrep')!
    const job = scanJobSchema.safeParse({
      schema: 1, id: randomUUID(), scan_id: randomUUID(), project_id: randomUUID(), created_at: '2026-11-25T10:00:00Z',
      source: { kind: 'archive', upload_id: randomUUID() }, cache: true,
      modules: [{ id: og.id, version: og.version, options: {}, rulesets: og.rulesets }],
    })
    expect(job.success, JSON.stringify(job.error?.issues)).toBe(true)
    const bad = scanJobSchema.safeParse({
      schema: 1, id: randomUUID(), scan_id: randomUUID(), project_id: randomUUID(), created_at: '2026-11-25T10:00:00Z',
      source: { kind: 'archive', upload_id: randomUUID() }, cache: true,
      modules: [{ id: 'opengrep', version: '1.0.0', options: {}, rulesets: [{ ...og.rulesets![0]!, slug: '../x' }] }],
    })
    expect(bad.success).toBe(false)
  })
})
