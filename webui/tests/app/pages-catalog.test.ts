// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Section Catalogue : sélection conseillée, packs, liste et compatibilité,
// plan d'installation (dépendances ajoutées, licences à cocher), détail d'un
// module (options générées, banc d'essai, activation, mise à jour,
// désinstallation irréversible), état DNS, page publique d'indisponibilité.

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { enableAutoUnmount } from '@vue/test-utils'
import { mockNuxtImport } from '@nuxt/test-utils/runtime'
import {
  apiFail, bodyText, button, buttons, callsTo, clearBody, click, mountIn, resetApi, route, setLocale, settle, setUser,
} from './helpers'
import CatalogPage from '~/pages/catalog/index.vue'
import ModulePage from '~/pages/catalog/[id].vue'
import DnsPage from '~/pages/catalog/dns.vue'
import UnavailablePage from '~/pages/modules/unavailable.vue'
import ModuleOptionsForm from '~/components/ModuleOptionsForm.vue'
import type { CatalogEntry, CatalogView, InstallPlan, PlanItem } from '~/composables/useCatalog'

const { toastAdd } = vi.hoisted(() => ({ toastAdd: vi.fn() }))
mockNuxtImport('useToast', () => () => ({ add: toastAdd }))

enableAutoUnmount(afterEach)

beforeEach(async () => {
  await setLocale('fr')
  toastAdd.mockReset()
})
afterEach(() => {
  vi.useRealTimers()
  resetApi()
  clearBody()
  try {
    localStorage.clear()
  }
  catch {
    // sans objet
  }
})

const LICENSE = { spdx: 'MIT', restrictions: 'none' as const }
const RES = { min_ram_mb: 256, min_cpu: 1, disk_mb: 200 }

function entry(id: string, patch: Partial<CatalogEntry> = {}): CatalogEntry {
  return {
    id, name: id.toUpperCase(), type: 'scanner', version: '1.0.0', description: { fr: `Module ${id}`, en: `Module ${id} (en)` }, categories: ['sca'],
    license: LICENSE, upstream: { homepage: 'https://exemple.test/h', source: 'https://exemple.test/s' }, resources: RES,
    hostname: null, requires: { modules: [], feeds: [], appliance: '>=0.2.0' }, conflicts: [], sysctl: {}, postgres: false,
    has_testbed: true, installed: null, update_available: null, compatible: true, blockers: [], auto_added: [], dependents: [],
    ...patch,
  }
}

function item(id: string, patch: Partial<PlanItem> = {}): PlanItem {
  return {
    id, name: id.toUpperCase(), version: '1.0.0', type: 'scanner', reason: 'requested', required_by: [], license: LICENSE,
    needs_acceptance: false, options: {}, changed_options: [], resources: RES, hostname: null, ...patch,
  }
}

const CHECKS: InstallPlan['checks'] = [
  { kind: 'ram', needed: 2560, available: 8192, ok: true },
  { kind: 'cpu', needed: 1, available: 4, ok: true },
  { kind: 'disk', needed: 400, available: 20000, ok: true },
]

function plan(patch: Partial<InstallPlan> = {}): InstallPlan {
  return { ok: true, items: [], skipped: [], checks: CHECKS, blockers: [], warnings: [], licenses_to_accept: [], sysctl: [], ...patch }
}

function view(patch: Partial<CatalogView> = {}): CatalogView {
  const installedGitleaks = { id: 'gitleaks', version: '8.27.0', type: 'scanner' as const, status: 'healthy' as const, enabled: true, options: {} }
  return {
    index: { available: true, version: 7, generated_at: '2026-11-23T06:00:00Z', rejected: 1 },
    state_available: true,
    machine: { cpu_count: 4, memory_mb: 8192, disks: [] },
    appliance_version: '0.2.0',
    modules: [
      entry('gitleaks', { installed: installedGitleaks, update_available: '8.28.0', categories: ['secrets'] }),
      entry('trivy', { auto_added: ['trivy-db'] }),
      entry('trivy-db', { type: 'feed', installed: { ...installedGitleaks, id: 'trivy-db', type: 'feed', enabled: false, status: 'disabled' } }),
      entry('futur', { compatible: false, blockers: [{ code: 'E_APPLIANCE_VERSION', module: 'futur', other: '>=9.0.0' }] }),
      entry('codeql', { license: { spdx: 'Proprietary', restrictions: 'private-code-forbidden' } }),
      entry('broken', { installed: { ...installedGitleaks, id: 'broken', status: 'failed' } }),
      entry('busy', { installed: { ...installedGitleaks, id: 'busy', status: 'installing' } }),
    ],
    orphans: [{ id: 'ancien', version: '1.0.0', type: 'scanner', status: 'healthy', enabled: true, options: {} }],
    packs: [
      { id: 'iac', name: 'IaC', modules: ['trivy', 'checkov'], technologies: ['terraform'], description: { fr: 'Infra', en: 'Infra' }, unknown_modules: ['checkov'], installed_modules: [], pending_modules: ['trivy'], plan: plan({ checks: [{ kind: 'ram', needed: 99999, available: 8192, ok: false }, ...CHECKS.slice(1)] }) },
      { id: 'base', name: 'Base', modules: ['gitleaks'], technologies: [], unknown_modules: [], installed_modules: ['gitleaks'], pending_modules: [], plan: null },
      { id: 'ok', name: 'Pack OK', modules: ['trivy'], technologies: [], unknown_modules: [], installed_modules: [], pending_modules: ['trivy'], plan: plan() },
      // Modules absents du catalogue, rien d'installé : le pack n'est pas « complet ».
      { id: 'vide', name: 'Pack vide', modules: ['inconnu'], technologies: [], unknown_modules: ['inconnu'], installed_modules: [], pending_modules: [], plan: null },
    ],
    graph: [
      { from: 'trivy', to: 'trivy-db', kind: 'feed' },
      { from: 'semgrep', to: 'opengrep', kind: 'conflict' },
      { from: 'osv-scanner', to: 'osv-db', kind: 'module' },
    ],
    recommended: { ids: ['trivy', 'osv-scanner'], first_access: true, plan: plan({ items: [item('trivy'), item('trivy-db', { reason: 'feed', required_by: ['trivy'] }), item('osv-scanner')] }) },
    operations: [
      { id: 'op2', kind: 'install', module: 'shellcheck', step: 'pull', progress: 40, started_at: '2026-11-23T08:00:00Z', finished_at: null },
      { id: 'op1', kind: 'install', module: 'trivy', step: 'rollback', started_at: '2026-11-21T10:00:00Z', finished_at: '2026-11-21T10:12:00Z', result: 'failed', message: 'banc d’essai : 0 résultat' },
      { id: 'op0', kind: 'weird', module: null, started_at: '2026-11-20T10:00:00Z', finished_at: '2026-11-20T10:12:00Z', result: 'ok' },
      { id: 'op-1', kind: 'update', module: 'x', started_at: '2026-11-19T10:00:00Z', finished_at: '2026-11-19T10:12:00Z' },
    ],
    dns: null,
    ...patch,
  }
}

function helperRoute(path: string, id: string, final: Record<string, unknown> = { status: 'ok', code: 'OK' }) {
  route('POST', path, () => ({ request_id: id }))
  route('GET', `/api/requests/${id}`, () => ({ id, type: 'x', step: null, message: null, output: null, ...final }))
}

function fakeClock(): void {
  vi.useFakeTimers({ toFake: ['setTimeout', 'setInterval', 'clearTimeout', 'clearInterval'] })
}

async function drive(rounds = 3): Promise<void> {
  for (let i = 0; i < rounds; i++) await vi.advanceTimersByTimeAsync(2100)
  await settle()
}

describe('catalogue', () => {
  it('lecteur : index, sélection conseillée, packs, liste, opérations, graphe, sans action', async () => {
    setUser('viewer')
    route('GET', '/api/catalog', () => view())
    const w = await mountIn(CatalogPage)
    await settle()
    const text = w.text()
    expect(text).toContain('Catalogue n° 7')
    expect(text).toContain('1 entrée(s) mal formée(s) écartée(s)')
    expect(text).toContain('Sélection conseillée')
    expect(text).toContain('1 base(s) de vulnérabilités nécessaire(s) seront ajoutées automatiquement.')
    expect(text).toContain('Réservé aux administrateurs.')
    expect(text).toContain('Absent(s) du catalogue : checkov')
    expect(text).toContain('Ressources insuffisantes pour tout le pack')
    expect(text).toContain('Tous les modules du pack sont installés.')
    const vide = document.body.querySelector('[data-pack="vide"]')!.textContent!
    expect(vide).not.toContain('Tous les modules du pack sont installés.')
    expect(vide).toContain('inconnu')
    expect(text).toContain('La machine a les ressources pour tout le pack.')
    expect(text).toContain('version 8.28.0 disponible')
    expect(text).toContain('incompatible')
    expect(text).toContain('futur exige une appliance >=9.0.0.')
    expect(text).toContain('interdit sur du code privé')
    expect(text).toContain('en échec')
    expect(text).toContain('désactivé')
    expect(text).toContain('installation')
    expect(text).toContain('Installation : shellcheck')
    expect(text).toContain('récupération de l’image')
    expect(text).toContain('échec, retour arrière effectué')
    expect(text).toContain('banc d’essai : 0 résultat')
    expect(text).toContain('Modules installés absents du catalogue')
    expect(text).toContain('base TRIVY-DB')
    expect(text).toContain('incompatible avec opengrep')
    expect(text).toContain('requiert osv-db')
    expect(buttons('Actualiser le catalogue')).toHaveLength(0)
    expect(buttons('Installer la sélection conseillée')).toHaveLength(0)
  })

  it('filtres par texte et par type', async () => {
    setUser('viewer')
    route('GET', '/api/catalog', () => view())
    const w = await mountIn(CatalogPage)
    await settle()
    const vm = w.vm as unknown as { search: string, typeFilter: string }
    vm.search = 'secrets'
    await settle()
    expect(w.findAll('tbody tr')).toHaveLength(1)
    vm.search = ''
    vm.typeFilter = 'feed'
    await settle()
    expect(w.findAll('tbody tr')).toHaveLength(1)
    vm.search = 'zzz'
    await settle()
    expect(w.text()).toContain('Aucun module ne correspond.')
  })

  it('index absent, état absent, erreur de chargement', async () => {
    setUser('admin')
    route('GET', '/api/catalog', () => view({
      index: { available: false, version: null, generated_at: null, rejected: 0 }, state_available: false,
      modules: [], packs: [], orphans: [], graph: [], operations: [], recommended: { ids: [], first_access: true, plan: null },
    }))
    const w = await mountIn(CatalogPage)
    await settle()
    expect(w.text()).toContain('Catalogue pas encore disponible')
    expect(w.text()).toContain('aucun module installé n’est connu')
    expect(w.text()).toContain('Aucune dépendance déclarée.')
    expect(w.text()).not.toContain('Sélection conseillée')
    w.unmount()
    resetApi()
    route('GET', '/api/catalog', () => apiFail(500, 'E_INTERNAL'))
    const w2 = await mountIn(CatalogPage)
    await settle()
    expect(w2.text()).toContain('Une erreur est survenue')
  })

  it('sélection conseillée masquable une fois des modules installés', async () => {
    setUser('admin')
    route('GET', '/api/catalog', () => view({ recommended: { ids: ['trivy'], first_access: false, plan: plan({ items: [item('trivy')] }) } }))
    const w = await mountIn(CatalogPage)
    await settle()
    expect(w.find('[data-recommended]').exists()).toBe(true)
    await click(button('Masquer la sélection conseillée'))
    expect(w.find('[data-recommended]').exists()).toBe(false)
    expect(localStorage.getItem('scanoria.catalog.hideRecommended')).toBe('1')
  })

  it('actualisation de l’index par un administrateur', async () => {
    setUser('admin')
    route('GET', '/api/catalog', () => view())
    helperRoute('/api/catalog/refresh', 'r1')
    await mountIn(CatalogPage)
    await settle()
    fakeClock()
    await click(button('Actualiser le catalogue'))
    await drive()
    expect(callsTo('POST', '/api/catalog/refresh')[0]!.body).toEqual({})
    expect(callsTo('GET', '/api/catalog').length).toBeGreaterThanOrEqual(2)
  })

  it('installation de la sélection : plan affiché (ajouts expliqués), licence à cocher, une confirmation', async () => {
    setUser('admin')
    route('GET', '/api/catalog', () => view())
    route('POST', '/api/catalog/plan', () => plan({
      items: [
        item('trivy'),
        item('trivy-db', { reason: 'feed', required_by: ['trivy'], type: 'feed' }),
        item('osv-scanner', { needs_acceptance: true, license: { spdx: 'X', restrictions: 'no-redistribution', note: 'Usage interne' } }),
      ],
      skipped: ['gitleaks'],
      sysctl: [{ module: 'trivy', key: 'vm.max_map_count', value: 524288 }],
      warnings: [{ code: 'W_DNS', module: 'trivy', other: 'trivy.analyse.exemple.test' }],
      blockers: [{ code: 'E_LICENSE_REQUIRED', other: 'osv-scanner' }],
      licenses_to_accept: ['osv-scanner'],
    }))
    helperRoute('/api/catalog/install', 'i1')
    await mountIn(CatalogPage)
    await settle()
    fakeClock()
    await click(button('Installer la sélection conseillée'))
    await settle()
    const text = bodyText()
    expect(callsTo('POST', '/api/catalog/plan')[0]!.body).toEqual({ modules: [{ id: 'trivy' }, { id: 'osv-scanner' }] })
    expect(text).toContain('ajouté : base de trivy')
    expect(text).toContain('Les modules marqués « ajouté »')
    expect(text).toContain('Déjà installés, laissés tels quels : gitleaks')
    expect(text).toContain('Mémoire : 2,5 Go nécessaires')
    expect(text).toContain('vm.max_map_count = 524288')
    expect(text).toContain('ne résout pas encore')
    expect(text).toContain('Usage interne')
    expect(text).not.toContain('Licence à accepter explicitement')
    expect(button('Installer (3)').disabled).toBe(true)
    await click(document.body.querySelector('[data-accept="osv-scanner"] [role="checkbox"], [data-accept="osv-scanner"][role="checkbox"]')!)
    expect(button('Installer (3)').disabled).toBe(false)
    await click(document.body.querySelector('[data-accept="osv-scanner"] [role="checkbox"], [data-accept="osv-scanner"][role="checkbox"]')!)
    expect(button('Installer (3)').disabled).toBe(true)
    await click(document.body.querySelector('[data-accept="osv-scanner"] [role="checkbox"], [data-accept="osv-scanner"][role="checkbox"]')!)
    button('Installer (3)').dispatchEvent(new MouseEvent('click', { bubbles: true }))
    await drive()
    expect(callsTo('POST', '/api/catalog/install')[0]!.body).toEqual({ modules: [{ id: 'trivy' }, { id: 'osv-scanner' }], accept_licenses: ['osv-scanner'] })
  })

  it('pack : plan bloqué affiché, installation impossible ; plan en erreur', async () => {
    setUser('admin')
    route('GET', '/api/catalog', () => view())
    let fail = false
    route('POST', '/api/catalog/plan', () => (fail
      ? apiFail(503, 'E_CATALOG_UNAVAILABLE')
      : plan({ ok: false, items: [item('trivy')], blockers: [{ code: 'E_RESOURCES', other: 'ram' }, { code: 'E_OPTIONS', module: 'trivy', options: [{ key: 'severity', code: 'enum' }] }] })))
    await mountIn(CatalogPage)
    await settle()
    await click(buttons('Installer (1 module(s))')[0]!)
    await settle()
    expect(callsTo('POST', '/api/catalog/plan')[0]!.body).toEqual({ pack: 'iac' })
    expect(bodyText()).toContain('Installer le pack IaC')
    expect(bodyText()).toContain('Ressources insuffisantes : mémoire.')
    expect(bodyText()).toContain('Options invalides pour trivy : severity.')
    expect(button('Installer (1)').disabled).toBe(true)
    await click(button('Annuler'))
    fail = true
    await click(buttons('Installer (1 module(s))')[0]!)
    await settle()
    expect(bodyText()).toContain('Le catalogue n’est pas encore disponible.')
  })
})

const DETAIL = {
  module: {
    ...entry('sonarqube'), name: 'SonarQube', type: 'service', hostname: 'sonarqube', postgres: true,
    sysctl: { 'vm.max_map_count': 524288 }, license: { spdx: 'LGPL-3.0-only', restrictions: 'none', url: 'https://exemple.test/l', note: 'Note' },
  },
  options_schema: {
    type: 'object',
    properties: {
      edition: { type: 'string', default: 'community', enum: ['community', 'other'], title: 'Edition' },
      heap_mb: { type: 'integer', default: 2048, minimum: 512, maximum: 8192, title: 'Heap' },
      telemetry: { type: 'boolean', default: false, title: 'Telemetry' },
      excludes: { type: 'array', default: ['vendor/**'], title: 'Excludes' },
      prefix: { type: 'string', default: 'scan', pattern: '^[a-z]+$', title: 'Prefix' },
    },
  },
  options_i18n: { heap_mb: { fr: { title: 'Mémoire Java', description: 'En Mo' } } },
  versions: ['25.10.0', '25.9.0'],
  installed: null,
  update_available: null,
  plan: plan({ checks: [{ kind: 'ram', needed: 6144, available: 4096, ok: false }, ...CHECKS.slice(1)], blockers: [{ code: 'E_RESOURCES', other: 'ram' }, { code: 'E_LICENSE_REQUIRED', other: 'x' }] }),
  dependents: [],
  operations: [],
  dns: { fqdn: 'analyse.exemple.test', records: [{ name: '*.analyse.exemple.test', type: 'A', expected: '192.0.2.10', resolved: [], ok: false }] },
}

describe('détail d’un module', () => {
  it('non installé : licence, ressources, nom, options générées et installation avec options', async () => {
    setUser('admin')
    route('GET', '/api/catalog', () => view())
    route('GET', '/api/catalog/modules/sonarqube', () => DETAIL)
    route('POST', '/api/catalog/plan', () => plan({ items: [item('sonarqube')] }))
    const w = await mountIn(ModulePage, { route: '/catalog/sonarqube' })
    await settle()
    const text = w.text()
    expect(text).toContain('LGPL-3.0-only')
    expect(text).toContain('sans restriction')
    expect(text).toContain('Versions au catalogue : 25.10.0, 25.9.0')
    expect(text).toContain('Une base PostgreSQL dédiée est créée automatiquement.')
    expect(text).toContain('https://sonarqube.analyse.exemple.test')
    expect(text).toContain('ne résout pas')
    expect(text).toContain('Mémoire : 6 Go nécessaires')
    expect(text).toContain('Ressources insuffisantes : mémoire.')
    expect(text).toContain('Mémoire Java')
    expect(text).toContain('En Mo')
    const vm = w.vm as unknown as { options: Record<string, unknown> }
    expect(vm.options).toEqual({ edition: 'community', heap_mb: 2048, telemetry: false, excludes: ['vendor/**'], prefix: 'scan' })
    vm.options = { ...vm.options, prefix: 'A1' }
    await settle()
    expect(w.text()).toContain('Format invalide.')
    expect(button('Installer').disabled).toBe(true)
    await click(button('Revenir à la valeur par défaut'))
    expect(button('Installer').disabled).toBe(false)
    vm.options = { ...vm.options, heap_mb: 4096 }
    await settle()
    await click(button('Installer'))
    await settle()
    expect(callsTo('POST', '/api/catalog/plan')[0]!.body).toEqual({
      modules: [{ id: 'sonarqube', options: { edition: 'community', heap_mb: 4096, telemetry: false, excludes: ['vendor/**'], prefix: 'scan' } }],
    })
    expect(bodyText()).toContain('Installer SonarQube')
  })

  it('installé : banc d’essai, erreur, désactivation confirmée, mise à jour avec sauvegarde', async () => {
    setUser('admin')
    route('GET', '/api/catalog', () => view({ operations: [] }))
    route('GET', '/api/catalog/modules/sonarqube', () => ({
      ...DETAIL,
      plan: null,
      update_available: '25.11.0',
      update_license: { spdx: 'Other-1.0', restrictions: 'other' },
      dependents: ['dtrack'],
      installed: {
        id: 'sonarqube', version: '25.10.0', type: 'service', status: 'healthy', enabled: true, installed_at: '2026-11-20T10:00:00Z',
        options: { edition: 'community' }, testbed: { passed: true, at: '2026-11-20T10:05:00Z', details: [{ rule: null, category: 'secrets', min: 1, found: 3, ok: true }, { rule: 'r1', category: null, min: 2, found: 0, ok: false }, 'x'] },
        route: { hostname: 'sonarqube.analyse.exemple.test', url: 'https://sonarqube.analyse.exemple.test' },
        last_error: { code: 'E_TIMEOUT', message: 'lent' },
      },
      operations: [{ id: 'o', kind: 'update', module: 'sonarqube', step: 'backup', progress: null, started_at: '2026-11-23T08:00:00Z', finished_at: null }],
      dns: { fqdn: 'analyse.exemple.test', records: [{ name: 'sonarqube.analyse.exemple.test', type: 'A', expected: '192.0.2.10', resolved: ['192.0.2.10'], ok: true }] },
    }))
    helperRoute('/api/catalog/modules/sonarqube/state', 's1')
    helperRoute('/api/catalog/modules/sonarqube/update', 'u1')
    const w = await mountIn(ModulePage, { route: '/catalog/sonarqube' })
    await settle()
    fakeClock()
    const text = w.text()
    expect(text).toContain('Version 25.10.0, installée le')
    expect(text).toContain('Réussi le')
    expect(text).toContain('secrets : 3 trouvé(s), 1 attendu(s) au minimum')
    expect(text).toContain('r1 : 0 trouvé(s), 2 attendu(s) au minimum')
    expect(text).toContain('Délai dépassé. — lent')
    expect(text).toContain('résout')
    expect(text).toContain('Désinstallation impossible tant que ces modules en dépendent : dtrack.')
    expect(text).toContain('Utilisé par : dtrack')
    expect(text).toContain('Mise à jour : sonarqube')
    expect(text).toContain('Options appliquées à l’installation.')
    expect(button('Désinstaller').disabled).toBe(true)
    await click(button('Désactiver'))
    expect(bodyText()).toContain('Ces modules en dépendent et pourraient ne plus fonctionner : dtrack.')
    button('Désactiver').dispatchEvent(new MouseEvent('click', { bubbles: true }))
    await drive()
    expect(callsTo('POST', '/api/catalog/modules/sonarqube/state')[0]!.body).toEqual({ enabled: false })
    await click(button('Mettre à jour vers 25.11.0'))
    expect(bodyText()).toContain('sauvegardé automatiquement avant la mise à jour')
    expect(bodyText()).toContain('La version 25.11.0 est sous licence Other-1.0 (restrictions particulières)')
    expect(buttons('Mettre à jour vers 25.11.0').pop()!.disabled).toBe(true)
    await click(document.body.querySelector('[role="dialog"] [role="checkbox"]')!)
    buttons('Mettre à jour vers 25.11.0').pop()!.dispatchEvent(new MouseEvent('click', { bubbles: true }))
    await drive()
    expect(callsTo('POST', '/api/catalog/modules/sonarqube/update')[0]!.body).toEqual({ version: '25.11.0', accept_licenses: ['sonarqube'] })
  })

  it('opération en cours ailleurs : actions bloquées, fiche rechargée à la fin', async () => {
    setUser('admin')
    const running = [{ id: 'o9', kind: 'install', module: 'trivy', step: 'pull', progress: 10, started_at: '2026-11-23T08:00:00Z', finished_at: null }]
    let ops: CatalogView['operations'] = running
    route('GET', '/api/catalog', () => view({ operations: ops }))
    route('GET', '/api/catalog/modules/sonarqube', () => ({
      ...DETAIL, plan: null, dependents: [],
      installed: { id: 'sonarqube', version: '25.10.0', type: 'service', status: 'healthy', enabled: true, options: {} },
    }))
    const w = await mountIn(ModulePage, { route: '/catalog/sonarqube' })
    await settle()
    expect(button('Désinstaller').disabled).toBe(true)
    expect(button('Désactiver').disabled).toBe(true)
    const before = callsTo('GET', '/api/catalog/modules/sonarqube').length
    ops = [{ ...running[0]!, finished_at: '2026-11-23T08:05:00Z', result: 'ok' }]
    await (w.vm as unknown as { refreshCatalog: () => Promise<void> }).refreshCatalog()
    await settle()
    expect(callsTo('GET', '/api/catalog/modules/sonarqube').length).toBeGreaterThan(before)
    expect(button('Désinstaller').disabled).toBe(false)
  })

  it('désinstallation : garder par défaut, suppression des données avec case à cocher, activation', async () => {
    setUser('admin')
    route('GET', '/api/catalog', () => view({ operations: [] }))
    route('GET', '/api/catalog/modules/gitleaks', () => ({
      ...DETAIL,
      module: entry('gitleaks'),
      options_schema: null,
      plan: null,
      dns: null,
      installed: { id: 'gitleaks', version: '8.27.0', type: 'scanner', status: 'failed', enabled: false, options: {}, testbed: { passed: false, at: '2026-11-20T10:05:00Z', details: { raw: '0 résultat' } }, last_error: 'cassé' },
    }))
    helperRoute('/api/catalog/modules/gitleaks/uninstall', 'd1')
    helperRoute('/api/catalog/modules/gitleaks/state', 'e1')
    const w = await mountIn(ModulePage, { route: '/catalog/gitleaks' })
    await settle()
    fakeClock()
    expect(w.text()).toContain('Échoué le')
    expect(w.text()).toContain('0 résultat')
    expect(w.text()).toContain('cassé')
    expect(w.text()).toContain('Ce module n’a aucune option.')
    await click(button('Activer'))
    await drive()
    expect(callsTo('POST', '/api/catalog/modules/gitleaks/state')[0]!.body).toEqual({ enabled: true })
    await click(button('Désinstaller'))
    expect(bodyText()).toContain('Cette action est irréversible.')
    const vm = w.vm as unknown as { keepData: string }
    vm.keepData = 'delete'
    await settle()
    expect(buttons('Désinstaller').pop()!.disabled).toBe(true)
    await click(document.body.querySelector('[role="dialog"] [role="checkbox"]')!)
    buttons('Désinstaller').pop()!.dispatchEvent(new MouseEvent('click', { bubbles: true }))
    await drive()
    expect(callsTo('POST', '/api/catalog/modules/gitleaks/uninstall')[0]!.body).toEqual({ keep_data: false })
  })

  it('base d’un feed : âge, échec signalé, mise à jour immédiate ; âge dans la liste', async () => {
    setUser('admin')
    const feedRow = entry('trivy-db', {
      type: 'feed',
      installed: { id: 'trivy-db', version: '2', type: 'feed', status: 'healthy', enabled: true, options: {} },
      feed: { id: 'trivy-db', updated_at: '2026-11-24T03:00:00Z', size_mb: 1732.8, status: 'stale', error: 'mirror.gcr.io: HTTP 429' },
    })
    const absentRow = entry('osv-db', {
      type: 'feed',
      installed: { id: 'osv-db', version: '1', type: 'feed', status: 'healthy', enabled: true, options: {} },
      feed: { id: 'osv-db', updated_at: null, size_mb: null, status: 'missing' },
    })
    route('GET', '/api/catalog', () => view({ modules: [feedRow, absentRow], operations: [] }))
    const list = await mountIn(CatalogPage, { route: '/catalog' })
    await settle()
    expect(list.findAll('[data-feed-age]').map(x => x.text())).toEqual([expect.stringContaining('Base du'), 'Base absente'])
    list.unmount()
    route('GET', '/api/catalog/modules/trivy-db', () => ({
      ...DETAIL, module: feedRow, options_schema: null, plan: null, dns: null,
      installed: feedRow.installed, feed: feedRow.feed,
    }))
    helperRoute('/api/catalog/feeds/refresh', 'f1')
    const w = await mountIn(ModulePage, { route: '/catalog/trivy-db' })
    await settle()
    fakeClock()
    expect(w.find('[data-feed]').text()).toContain('1732.8 Mo')
    expect(w.find('[data-feed]').text()).toContain('mirror.gcr.io: HTTP 429')
    await click(button('Mettre à jour maintenant'))
    await drive()
    expect(callsTo('POST', '/api/catalog/feeds/refresh')[0]!.body).toEqual({ ids: ['trivy-db'] })
  })

  it('base d’un feed jamais téléchargée ; lecteur sans bouton', async () => {
    setUser('viewer')
    const row = entry('osv-db', {
      type: 'feed',
      installed: { id: 'osv-db', version: '1', type: 'feed', status: 'healthy', enabled: true, options: {} },
    })
    route('GET', '/api/catalog', () => view({ operations: [] }))
    route('GET', '/api/catalog/modules/osv-db', () => ({
      ...DETAIL, module: row, options_schema: null, plan: null, dns: null, installed: row.installed,
      feed: { id: 'osv-db', updated_at: null, size_mb: null, status: 'missing' },
    }))
    const w = await mountIn(ModulePage, { route: '/catalog/osv-db' })
    await settle()
    expect(w.find('[data-feed]').text()).toContain('Aucune base téléchargée')
    expect(w.text()).not.toContain('Mettre à jour maintenant')
  })

  it('module absent du catalogue mais installé ; module introuvable', async () => {
    setUser('viewer')
    route('GET', '/api/catalog', () => view({ operations: [] }))
    route('GET', '/api/catalog/modules/ancien', () => ({
      ...DETAIL, module: null, options_schema: null, plan: null, versions: [],
      installed: { id: 'ancien', version: '1.0.0', type: 'scanner', status: 'healthy', enabled: true, options: {}, testbed: null },
    }))
    const w = await mountIn(ModulePage, { route: '/catalog/ancien' })
    await settle()
    expect(w.text()).toContain('ne figure plus dans le catalogue')
    expect(w.text()).toContain('Pas encore exécuté.')
    expect(buttons('Désinstaller')).toHaveLength(0)
    w.unmount()
    route('GET', '/api/catalog/modules/nope', () => apiFail(404, 'E_NOT_FOUND'))
    const w2 = await mountIn(ModulePage, { route: '/catalog/nope' })
    await settle()
    expect(w2.text()).toContain('Élément introuvable.')
  })
})

describe('formulaire d’options', () => {
  it('signale chaque erreur et émet la validité', async () => {
    const w = await mountIn(ModuleOptionsForm, {
      props: {
        schema: {
          properties: {
            n: { type: 'number', default: 1, minimum: 0 },
            s: { type: 'string', default: 'a', title: 'S', description: 'Aide' },
            l: { type: 'array', default: [] },
          },
        },
        modelValue: { n: -1 },
      },
    })
    await settle()
    expect(w.text()).toContain('Valeur trop petite.')
    expect(w.emitted('valid')!.pop()).toEqual([false])
    const vm = w.vm as unknown as { setList: (f: { key: string }, raw: string) => void }
    vm.setList({ key: 'l' }, 'a\n\n b \n')
    await settle()
    expect((w.emitted('update:modelValue')!.pop() as [Record<string, unknown>])[0].l).toEqual(['a', 'b'])
  })
})

describe('état DNS', () => {
  it('enregistrements à créer, dernier contrôle, vérification immédiate', async () => {
    setUser('admin')
    route('GET', '/api/dns', () => ({
      fqdn: 'analyse.exemple.test',
      status: { fqdn: 'analyse.exemple.test', checked_at: '2026-11-23T07:30:00Z', records: [
        { name: 'analyse.exemple.test', type: 'A', expected: '192.0.2.10', resolved: ['192.0.2.10'], ok: true },
        { name: '*.analyse.exemple.test', type: 'A', expected: '192.0.2.10', resolved: [], ok: false },
      ] },
      required: [{ name: '*.analyse.exemple.test', type: 'A', value: '192.0.2.10' }],
    }))
    helperRoute('/api/dns/check', 'c1')
    const w = await mountIn(DnsPage)
    await settle()
    fakeClock()
    expect(w.text()).toContain('Le générique *.analyse.exemple.test couvre toutes les applications')
    expect(w.text()).toContain('des noms ne résolvent pas')
    expect(w.text()).toContain('aucune réponse')
    await click(button('Vérifier maintenant'))
    await drive()
    expect(callsTo('POST', '/api/dns/check')[0]!.body).toEqual({})
    expect(callsTo('GET', '/api/dns').length).toBeGreaterThanOrEqual(2)
  })

  it('sans nom, sans contrôle, en anglais ; erreur', async () => {
    await setLocale('en')
    setUser('viewer')
    route('GET', '/api/dns', () => ({ fqdn: null, status: { fqdn: null, records: [] }, required: [] }))
    const w = await mountIn(DnsPage)
    await settle()
    expect(w.text()).toContain('The appliance has no name yet')
    expect(w.text()).toContain('No record checked.')
    expect(buttons('Check now')).toHaveLength(0)
    w.unmount()
    resetApi()
    route('GET', '/api/dns', () => ({ fqdn: 'a.exemple.test', status: null, required: [] }))
    const w2 = await mountIn(DnsPage)
    await settle()
    expect(w2.text()).toContain('Create a.exemple.test and *.a.exemple.test')
    expect(w2.text()).toContain('Never checked')
    w2.unmount()
    resetApi()
    route('GET', '/api/dns', () => apiFail(500, 'E_INTERNAL'))
    const w3 = await mountIn(DnsPage)
    await settle()
    expect(w3.text()).toContain('Console internal error.')
  })
})

describe('application indisponible (page publique)', () => {
  it('nomme le module, ignore un identifiant invalide', async () => {
    setUser(null)
    const w = await mountIn(UnavailablePage, { route: '/modules/unavailable?m=sonarqube' })
    await settle()
    expect(w.text()).toContain('Le module « sonarqube » n’est pas installé ou il est désactivé.')
    w.unmount()
    const w2 = await mountIn(UnavailablePage, { route: '/modules/unavailable?m=%3Cscript%3E' })
    await settle()
    expect(w2.text()).toContain('Aucune application n’est servie à cette adresse.')
  })
})
