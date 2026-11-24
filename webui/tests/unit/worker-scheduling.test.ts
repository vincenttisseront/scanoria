// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Ordonnancement (G17) et résolution des profils (G7, G11) de scanoria-worker :
// priorités, anti-famine, quotas par projet, relances (G12), trous de couverture.

import { mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { SCAN_PRIORITY } from '#shared/analysis'
import { AGING_CAP, AGING_STEP_S, effectivePriority, pickNext, retryDelayS, type QueueEntry } from '../../server/scans/priority'
import {
  catalogEntry, parsePlan, planHistory, planTimeout, readPlanCatalog, replayAvailability, resolveProfile,
  type PlanCatalogEntry, type ScanPlan,
} from '../../server/scans/plan'
import { loadWorkerConfig } from '../../server/scans/config'
import type { InstalledModule } from '../../server/utils/catalog'

const MIN = 60_000

describe('priorité effective et anti-famine', () => {
  it('release garde toujours sa priorité, les autres gagnent 1 point par palier', () => {
    expect(effectivePriority(SCAN_PRIORITY.release, 10 * 3600_000)).toBe(SCAN_PRIORITY.release)
    expect(effectivePriority(SCAN_PRIORITY.schedule, 0)).toBe(SCAN_PRIORITY.schedule)
    expect(effectivePriority(SCAN_PRIORITY.schedule, AGING_STEP_S * 1000 - 1)).toBe(SCAN_PRIORITY.schedule)
    expect(effectivePriority(SCAN_PRIORITY.schedule, AGING_STEP_S * 1000)).toBe(SCAN_PRIORITY.schedule + 1)
    expect(effectivePriority(SCAN_PRIORITY.schedule, -5000)).toBe(SCAN_PRIORITY.schedule)
  })

  it('plafond sous la release : une analyse vieillie ne la dépasse jamais', () => {
    expect(AGING_CAP).toBe(SCAN_PRIORITY.release - 1)
    expect(effectivePriority(SCAN_PRIORITY.schedule, 1000 * 24 * 3600_000)).toBe(AGING_CAP)
  })

  const now = new Date('2026-11-24T12:00:00Z')
  const at = (minutesAgo: number) => new Date(now.getTime() - minutesAgo * MIN)
  const e = (id: string, projectId: string, priority: number, minutesAgo: number, notBefore?: Date): QueueEntry =>
    ({ id, projectId, priority, queuedAt: at(minutesAgo), notBefore })

  it('plus haute priorité, puis la plus ancienne', () => {
    const q = [e('a', 'p1', SCAN_PRIORITY.schedule, 1), e('b', 'p2', SCAN_PRIORITY.manual, 1), e('c', 'p3', SCAN_PRIORITY.manual, 2)]
    expect(pickNext(q, new Map(), 2, now)?.id).toBe('c')
    expect(pickNext([e('r', 'p1', SCAN_PRIORITY.release, 0), ...q], new Map(), 2, now)?.id).toBe('r')
  })

  it('aucune famine : une analyse planifiée qui attend finit par passer devant les manuelles récentes', () => {
    const old = e('old', 'p1', SCAN_PRIORITY.schedule, (SCAN_PRIORITY.manual - SCAN_PRIORITY.schedule + 1) * AGING_STEP_S / 60)
    const fresh = e('fresh', 'p2', SCAN_PRIORITY.manual, 0)
    expect(pickNext([fresh, old], new Map(), 2, now)?.id).toBe('old')
    // mais jamais devant une release
    expect(pickNext([fresh, e('old2', 'p1', 0, 100_000), e('rel', 'p3', SCAN_PRIORITY.release, 0)], new Map(), 2, now)?.id).toBe('rel')
  })

  it('quota par projet et relances pas encore dues', () => {
    const q = [e('a', 'p1', SCAN_PRIORITY.release, 5), e('b', 'p2', SCAN_PRIORITY.schedule, 1)]
    expect(pickNext(q, new Map([['p1', 2]]), 2, now)?.id).toBe('b')
    expect(pickNext(q, new Map([['p1', 1]]), 2, now)?.id).toBe('a')
    expect(pickNext([e('x', 'p1', 50, 1, new Date(now.getTime() + 1000))], new Map(), 2, now)).toBeUndefined()
    expect(pickNext([e('x', 'p1', 50, 1, new Date(now.getTime() - 1000))], new Map(), 2, now)?.id).toBe('x')
    expect(pickNext([], new Map(), 2, now)).toBeUndefined()
  })

  it('recul des relances infra : base puis double', () => {
    expect([1, 2, 3].map(a => retryDelayS(a, 60))).toEqual([60, 120, 240])
    expect(retryDelayS(0, 30)).toBe(30)
  })
})

describe('configuration du worker', () => {
  it('défauts sûrs, valeurs hors bornes ignorées', () => {
    const d = loadWorkerConfig({})
    expect(d).toMatchObject({ scansDir: '/var/lib/scanoria/scans', runnerStateFile: '/run/scanoria/runner.json', perProjectLimit: 2, maxInfraRetries: 2 })
    expect(loadWorkerConfig({ SCANORIA_SCANS_PER_PROJECT: '0', SCANORIA_INFRA_RETRIES: '99' })).toMatchObject({ perProjectLimit: 2, maxInfraRetries: 2 })
    expect(loadWorkerConfig({ SCANORIA_SCANS_DIR: '/tmp/x', SCANORIA_SCANS_PER_PROJECT: '4' })).toMatchObject({ scansDir: '/tmp/x', perProjectLimit: 4 })
  })
})

const installed = (id: string, version: string, extra: Partial<InstalledModule> = {}): InstalledModule => ({
  id, version, type: 'scanner', status: 'healthy', enabled: true, installed_at: null, options: {}, testbed: null, route: null, last_error: null, ...extra,
})
const entry = (id: string, version: string, categories: string[], extra: Partial<PlanCatalogEntry> = {}): PlanCatalogEntry => ({
  id, version, type: 'scanner', categories, image: `ghcr.io/exemple/${id}@sha256:${'a'.repeat(64)}`, restrictions: 'none',
  feeds: [], outputs: ['sarif'], options: null, scan: { inputs: ['repo', 'archive'], timeout_s: 600 }, ...extra,
})
const catalogOf = (...entries: PlanCatalogEntry[]) => new Map(entries.map(x => [`${x.id}@${x.version}`, x]))
const profile = (categories: string[], include: string[] = [], exclude: string[] = []) =>
  ({ id: '3f1c2a9e-7b4d-4e2a-9c1f-0a1b2c3d4e5f', slug: 'test', categories, include_modules: include, exclude_modules: exclude })

describe('résolution des profils (G7)', () => {
  const catalog = catalogOf(
    entry('gitleaks', '8.30.1', ['secrets'], {
      scan: { inputs: ['repo', 'archive'], timeout_s: 900, history: 'full' },
      options: { type: 'object', properties: { history: { type: 'boolean', default: true }, max_target_megabytes: { type: 'integer', default: 10 } } },
    }),
    entry('trivy', '0.76.2', ['sca', 'iac', 'secrets'], { feeds: ['trivy-db'] }),
    entry('osv-scanner', '2.7.1', ['sca'], { scan: { inputs: ['repo'], timeout_s: 300 } }),
    entry('codeql', '2.23.0', ['sast'], { restrictions: 'private-code-forbidden' }),
    entry('zap', '2.16.0', ['dast'], { scan: { inputs: ['url'], timeout_s: 3600 } }),
    entry('trivy-db', '2', [], { type: 'feed', scan: null }),
    entry('git-fetch', '2.47.0', ['system']),
  )
  const all = [
    installed('gitleaks', '8.30.1', { options: { max_target_megabytes: 20 } }),
    installed('trivy', '0.76.2'),
    installed('osv-scanner', '2.7.1'),
    installed('codeql', '2.23.0'),
    installed('zap', '2.16.0'),
    installed('trivy-db', '2', { type: 'feed' }),
    installed('git-fetch', '2.47.0'),
  ]

  it('catégories → modules installés, sains, actifs ; options et bases figées ; raison montrée', () => {
    const r = resolveProfile({ profile: profile(['secrets', 'sca']), sourceKind: 'git', projectLicense: null, installed: all, catalog })
    expect(r.modules.map(m => m.id)).toEqual(['gitleaks', 'osv-scanner', 'trivy'])
    const gl = r.modules[0]!
    expect(gl).toMatchObject({ version: '8.30.1', image_digest: `sha256:${'a'.repeat(64)}`, history: 'full', reason: 'category', timeout_s: 900 })
    expect(gl.options).toEqual({ history: true, max_target_megabytes: 20 })
    expect(r.modules[2]!.feeds).toEqual([{ id: 'trivy-db', version: '2' }])
    expect(r.gaps).toEqual([])
    expect(planHistory(r.modules)).toBe('full')
    expect(planTimeout(r.modules)).toBe(900 + 300 + 600)
  })

  it('l’option history=false de gitleaks ramène un clone superficiel', () => {
    const mods = [installed('gitleaks', '8.30.1', { options: { history: false } })]
    const r = resolveProfile({ profile: profile(['secrets']), sourceKind: 'git', projectLicense: null, installed: mods, catalog })
    expect(planHistory(r.modules)).toBe('shallow')
  })

  it('trous de couverture : catégorie sans module, entrée incompatible (archive, DAST)', () => {
    const r = resolveProfile({ profile: profile(['sca', 'quality', 'dast']), sourceKind: 'archive', projectLicense: null, installed: all, catalog })
    expect(r.modules.map(m => m.id)).toEqual(['trivy'])
    expect(r.gaps).toEqual([
      { kind: 'profile-category', category: 'quality', module: null, reason: 'no-module' },
      { kind: 'profile-category', category: 'dast', module: null, reason: 'no-module' },
    ])
  })

  it('modules désactivés, en échec ou inconnus de l’index : écartés', () => {
    const mods = [
      installed('trivy', '0.76.2', { status: 'disabled', enabled: false }),
      installed('osv-scanner', '2.7.1', { status: 'failed' }),
      installed('gitleaks', '9.9.9'),
    ]
    const r = resolveProfile({ profile: profile(['sca', 'secrets']), sourceKind: 'git', projectLicense: null, installed: mods, catalog })
    expect(r.modules).toEqual([])
    expect(r.gaps.map(g => g.category)).toEqual(['sca', 'secrets'])
  })

  it('include et exclude ; module demandé indisponible signalé avec sa raison', () => {
    const mods = [...all, installed('broken', '1.0.0', { status: 'failed' })]
    const r = resolveProfile({
      profile: profile(['sca'], ['gitleaks', 'absent', 'broken', 'osv-scanner', 'git-fetch'], ['osv-scanner']),
      sourceKind: 'git', projectLicense: null, installed: mods, catalog,
    })
    expect(r.modules.map(m => [m.id, m.reason])).toEqual([['gitleaks', 'included'], ['trivy', 'category']])
    expect(r.gaps).toEqual([
      { kind: 'profile-module', category: null, module: 'broken', reason: 'unhealthy' },
      { kind: 'profile-module', category: null, module: 'absent', reason: 'not-installed' },
      { kind: 'profile-module', category: null, module: 'git-fetch', reason: 'not-installed' },
    ])
  })

  it('licence réservée au code open source : seulement si le projet déclare une licence (CodeQL)', () => {
    const priv = resolveProfile({ profile: profile(['sast'], ['codeql']), sourceKind: 'git', projectLicense: null, installed: all, catalog })
    expect(priv.modules).toEqual([])
    expect(priv.gaps).toContainEqual({ kind: 'profile-module', category: null, module: 'codeql', reason: 'license' })
    const open = resolveProfile({ profile: profile(['sast']), sourceKind: 'git', projectLicense: 'MIT', installed: all, catalog })
    expect(open.modules.map(m => m.id)).toEqual(['codeql'])
  })

  it('catégorie inconnue ignorée pour la résolution mais signalée', () => {
    const r = resolveProfile({ profile: profile(['bogus']), sourceKind: 'git', projectLicense: null, installed: all, catalog })
    expect(r.modules).toEqual([])
    expect(r.gaps).toEqual([{ kind: 'profile-category', category: 'bogus', module: null, reason: 'no-module' }])
  })
})

describe('plan figé (G11)', () => {
  const plan: ScanPlan = {
    version: 1,
    created_at: '2026-11-24T10:00:00.000Z',
    source: { kind: 'git', ref: 'main', commit: 'a'.repeat(40), history: 'shallow' },
    profile: profile(['secrets']),
    gate: { id: '3f1c2a9e-7b4d-4e2a-9c1f-0a1b2c3d4e5f', slug: 'defaut', rules: { new_code_only: true, max_secrets: 0, vuln_block_from: 'high', sast_block_from: 'high', iac_block_from: 'high', block_malicious: true, inconclusive_blocks: true, license_denied_blocks: true, kev_blocks: true, epss_block_from: 0.1, quarantine_days: 7 } },
    modules: [
      { id: 'gitleaks', version: '8.30.1', image: null, image_digest: null, categories: ['secrets'], options: {}, feeds: [], timeout_s: 900, history: 'full', outputs: ['sarif'], reason: 'category' },
      { id: 'trivy', version: '0.76.2', image: null, image_digest: null, categories: ['secrets'], options: {}, feeds: [], timeout_s: 600, history: 'shallow', outputs: ['sarif'], reason: 'category' },
    ],
    gaps: [],
    timeout_s: 1500,
  }

  it('rejeu : modules disparus, désactivés ou changés de version constatés manquants', () => {
    const r = replayAvailability(plan, [installed('gitleaks', '8.30.1'), installed('trivy', '0.77.0')])
    expect(r.available.map(m => m.id)).toEqual(['gitleaks'])
    expect(r.missing.map(m => m.id)).toEqual(['trivy'])
    expect(replayAvailability(plan, [installed('gitleaks', '8.30.1', { enabled: false })]).available).toEqual([])
  })

  it('relecture validée ; un plan mal formé est refusé', () => {
    expect(parsePlan(JSON.parse(JSON.stringify(plan)))).toEqual(plan)
    expect(parsePlan(null)).toBeNull()
    expect(parsePlan({ ...plan, version: 2 })).toBeNull()
    expect(parsePlan({ ...plan, gate: { ...plan.gate, rules: { ...plan.gate.rules, block_malicious: false } } })).toBeNull()
  })

  it('index : entrées lues sans confiance (id, champ scan), fichier absent ou trop gros → vide', async () => {
    expect(catalogEntry({ id: '../x', version: '1', type: 'scanner' })).toBeNull()
    expect(catalogEntry({ id: 'ok', version: '1', type: 'scanner', scan: { timeout_s: 'x' } })).toBeNull()
    expect(catalogEntry(null)).toBeNull()
    expect(catalogEntry({ id: 'ok', version: '1', type: 'scanner', categories: ['sca', 3], requires: { feeds: ['f1'] }, needs: { feeds: ['f1', 'f2'] }, outputs: { sarif: {}, other: {} } }))
      .toMatchObject({ categories: ['sca'], feeds: ['f1', 'f2'], outputs: ['sarif'], scan: null, image: null, restrictions: 'none' })
    const dir = await mkdtemp(join(tmpdir(), 'scanoria-plan-'))
    try {
      expect((await readPlanCatalog(join(dir, 'absent.json'))).size).toBe(0)
      await writeFile(join(dir, 'bad.json'), '{')
      expect((await readPlanCatalog(join(dir, 'bad.json'))).size).toBe(0)
      await writeFile(join(dir, 'idx.json'), JSON.stringify({ modules: [{ id: 'gitleaks', version: '8.30.1', type: 'scanner', categories: ['secrets'], scan: { inputs: ['repo'], timeout_s: 900, command: ['x'] } }, { id: 'Bad Id' }] }))
      const idx = await readPlanCatalog(join(dir, 'idx.json'))
      expect([...idx.keys()]).toEqual(['gitleaks@8.30.1'])
      expect(idx.get('gitleaks@8.30.1')!.scan).toEqual({ inputs: ['repo'], timeout_s: 900 })
    }
    finally {
      await rm(dir, { recursive: true, force: true })
    }
  })
})
