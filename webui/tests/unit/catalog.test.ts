// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Catalogue vu par la console : lecture méfiante des fichiers publiés par le
// helper, versions, options typées (G3), plan d'installation (G1, F11) avec
// dépendances ajoutées, conflits, licences et ressources, vue du catalogue.

import { existsSync, readFileSync } from 'node:fs'
import { mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import Ajv2020 from 'ajv/dist/2020.js'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import {
  compareVersions, findModule, latestModules, readCatalogIndex, readDnsStatus, readModulesState, satisfiesAppliance,
  type CatalogIndex, type DnsStatus, type InstalledModule,
} from '../../server/utils/catalog'
import { buildInstallPlan, containersDisk, dependentsOf, resourceChecks, type Machine, type PlanContext } from '../../server/utils/module-plan'
import { buildCatalogView, dependencyEdges, updateAvailable, type CatalogContext } from '../../server/utils/catalog-view'
import { changedOptions, checkOption, optionDefaults, optionFields, resolveOptions } from '#shared/module-options'

const FIXTURES = fileURLToPath(new URL('../fixtures/', import.meta.url))
const SCHEMAS = fileURLToPath(new URL('../../../src/rootfs/usr/share/scanoria/schemas/', import.meta.url))
const MACHINE: Machine = { cpu_count: 4, memory_mb: 8192, disks: [{ mount: '/', size_mb: 40960, avail_mb: 20000 }] }

let index: CatalogIndex
let installed: InstalledModule[]
let dns: DnsStatus
let tmp: string

beforeAll(async () => {
  index = (await readCatalogIndex(join(FIXTURES, 'catalog-index.json')))!
  installed = (await readModulesState(join(FIXTURES, 'modules-state.json'))).modules
  dns = (await readDnsStatus(join(FIXTURES, 'dns-status.json')))!
  tmp = await mkdtemp(join(tmpdir(), 'scanoria-catalog-'))
})
afterAll(async () => {
  await rm(tmp, { recursive: true, force: true })
})

const ctx = (patch: Partial<PlanContext> = {}): PlanContext => ({
  index, installed: [], machine: MACHINE, applianceVersion: '0.2.0', dns, ...patch,
})

describe('lecture des fichiers publiés', () => {
  it('écarte les entrées mal formées de l’index et garde les autres', () => {
    expect(index.version).toBe(7)
    expect(index.generated_at).toBe('2026-11-23T06:00:00Z')
    expect(index.rejected).toBe(1)
    expect(index.modules.some(m => m.id === '../evil')).toBe(false)
    expect(index.packs.map(p => p.id)).toEqual(['secrets', 'iac', 'base'])
  })

  it('refuse un index absent, illisible, trop gros ou d’un autre schéma', async () => {
    const write = async (name: string, content: string) => {
      await writeFile(join(tmp, name), content)
      return join(tmp, name)
    }
    expect(await readCatalogIndex(join(tmp, 'absent.json'))).toBeNull()
    expect(await readCatalogIndex(await write('bad.json', '{'))).toBeNull()
    expect(await readCatalogIndex(await write('arr.json', '[]'))).toBeNull()
    expect(await readCatalogIndex(await write('v2.json', JSON.stringify({ schema: 2, version: 1, modules: [] })))).toBeNull()
    const minimal = await readCatalogIndex(await write('min.json', JSON.stringify({ schema: 1, version: 1, generated_at: 'hier', modules: 'x' })))
    expect(minimal).toEqual({ version: 1, generated_at: null, modules: [], packs: [], rejected: 0 })
    expect(await readCatalogIndex(await write('big.json', ' '.repeat(8 * 1024 * 1024 + 1)))).toBeNull()
  })

  it('lit l’état des modules en écartant les entrées invalides', async () => {
    const state = await readModulesState(join(FIXTURES, 'modules-state.json'))
    expect(state.available).toBe(true)
    expect(state.modules.map(m => m.id)).toEqual(['gitleaks', 'trivy-db', 'trivy', 'ancien'])
    expect(state.operations).toHaveLength(2)
    expect(await readModulesState(join(tmp, 'absent.json'))).toEqual({ available: false, modules: [], operations: [] })
  })

  // Contrat 4 : le jeu d'essai suit les schémas des chantiers B et C dès qu'ils sont fusionnés
  // (entrée « Bad Id » et module « ../evil » mis à part : ils testent la lecture méfiante).
  it.runIf(existsSync(`${SCHEMAS}modules-state.schema.json`))('jeu d’essai conforme à modules-state.schema.json', () => {
    const schema = JSON.parse(readFileSync(`${SCHEMAS}modules-state.schema.json`, 'utf8'))
    const doc = JSON.parse(readFileSync(join(FIXTURES, 'modules-state.json'), 'utf8')) as { modules: { id: string }[] }
    doc.modules = doc.modules.filter(m => m.id !== 'Bad Id')
    const validate = new Ajv2020({ strict: false, allErrors: true }).compile(schema)
    expect(validate(doc), JSON.stringify(validate.errors)).toBe(true)
  })

  it.runIf(existsSync(`${SCHEMAS}catalog-index.schema.json`))('jeu d’essai conforme à catalog-index.schema.json', () => {
    const schema = JSON.parse(readFileSync(`${SCHEMAS}catalog-index.schema.json`, 'utf8'))
    const doc = JSON.parse(readFileSync(join(FIXTURES, 'catalog-index.json'), 'utf8')) as { modules: { id: string }[] }
    doc.modules = doc.modules.filter(m => m.id !== '../evil')
    const validate = new Ajv2020({ strict: false, allErrors: true }).compile(schema)
    expect(validate(doc), JSON.stringify(validate.errors)).toBe(true)
  })

  it('lit l’état DNS ou renvoie null', async () => {
    expect(dns.records).toHaveLength(3)
    await writeFile(join(tmp, 'dns.json'), JSON.stringify({ fqdn: 'a.test', records: [{ name: 'a.test', type: 'MX' }] }))
    expect(await readDnsStatus(join(tmp, 'dns.json'))).toBeNull()
  })
})

describe('versions', () => {
  it('compare numériquement puis textuellement', () => {
    expect(compareVersions('0.10.0', '0.9.9')).toBeGreaterThan(0)
    expect(compareVersions('1.0.0', '1.0.0')).toBe(0)
    expect(compareVersions('1.0', '1.0.1')).toBeLessThan(0)
    expect(compareVersions('1.0.1', '1.0')).toBeGreaterThan(0)
    expect(compareVersions('1.0.0-rc1', '1.0.0-rc2')).toBeLessThan(0)
    expect(compareVersions('1.0.b', '1.0.a')).toBeGreaterThan(0)
  })

  it('retient la dernière version de chaque module', () => {
    expect(latestModules(index).get('trivy')?.version).toBe('0.67.2')
    expect(findModule(index, 'trivy', '0.66.0')?.version).toBe('0.66.0')
    expect(findModule(index, 'trivy', '9.9.9')).toBeUndefined()
    expect(latestModules(null).size).toBe(0)
  })

  it('contrôle la version minimale de l’appliance', () => {
    expect(satisfiesAppliance(undefined, '0.2.0')).toBe(true)
    expect(satisfiesAppliance('>=0.2.0', '0.2.0')).toBe(true)
    expect(satisfiesAppliance('>= 0.3.0', '0.2.9')).toBe(false)
    expect(satisfiesAppliance('~0.2', '0.2.0')).toBe(false)
  })
})

describe('options typées (G3)', () => {
  const gitleaks = () => findModule(index, 'gitleaks')!

  it('construit les champs, les défauts et les traductions', () => {
    const fields = optionFields(gitleaks().options, gitleaks().options_i18n)
    expect(fields.map(f => f.key)).toEqual(['scan_history', 'max_target_megabytes', 'redact'])
    expect(fields[0]!.i18n?.fr?.title).toBe('Analyser l’historique')
    expect(optionDefaults(fields)).toEqual({ scan_history: true, max_target_megabytes: 50, redact: 'full' })
    expect(optionFields(null)).toEqual([])
    expect(optionFields({ properties: [] })).toEqual([])
    expect(optionFields({ properties: { 'bad key': { type: 'string' }, 'x': { type: 'object' }, 'y': null } })).toEqual([])
  })

  it('valide chaque type et chaque contrainte', () => {
    const f = { key: 'k', default: '' }
    expect(checkOption({ ...f, type: 'boolean' }, 'oui')).toBe('type')
    expect(checkOption({ ...f, type: 'integer', minimum: 1 }, 1.5)).toBe('type')
    expect(checkOption({ ...f, type: 'integer', minimum: 1 }, 0)).toBe('minimum')
    expect(checkOption({ ...f, type: 'number', maximum: 2 }, 3)).toBe('maximum')
    expect(checkOption({ ...f, type: 'number' }, Number.NaN)).toBe('type')
    expect(checkOption({ ...f, type: 'string', minLength: 2 }, 'a')).toBe('minLength')
    expect(checkOption({ ...f, type: 'string', maxLength: 2 }, 'abc')).toBe('maxLength')
    expect(checkOption({ ...f, type: 'string' }, 'a'.repeat(5000))).toBe('maxLength')
    expect(checkOption({ ...f, type: 'string', pattern: '^[a-z]+$' }, 'A1')).toBe('pattern')
    expect(checkOption({ ...f, type: 'string', pattern: '(' }, 'a')).toBe('schema')
    expect(checkOption({ ...f, type: 'string', enum: ['a'] }, 'b')).toBe('enum')
    expect(checkOption({ ...f, type: 'string' }, 1)).toBe('type')
    expect(checkOption({ ...f, type: 'array' }, 'a')).toBe('type')
    expect(checkOption({ ...f, type: 'array', enum: ['a'] }, ['b'])).toBe('enum')
    expect(checkOption({ ...f, type: 'array', maxLength: 3 }, ['abcd'])).toBe('maxLength')
    expect(checkOption({ ...f, type: 'array' }, ['a', 'b'])).toBeNull()
  })

  it('complète par les défauts, refuse les clés inconnues, liste les changements', () => {
    const schema = gitleaks().options
    expect(resolveOptions(schema).issues).toEqual([])
    const r = resolveOptions(schema, { max_target_megabytes: 0, extra: 1 })
    expect(r.issues).toEqual([{ key: 'extra', code: 'unknown' }, { key: 'max_target_megabytes', code: 'minimum' }])
    expect(changedOptions(schema, { scan_history: false, max_target_megabytes: 50, redact: 'full' })).toEqual(['scan_history'])
  })
})

describe('plan d’installation', () => {
  it('ajoute les bases et dépendances automatiquement, avec la raison', () => {
    const plan = buildInstallPlan([{ id: 'trivy' }, { id: 'osv-scanner' }], ctx())
    expect(plan.ok).toBe(true)
    expect(plan.items.map(i => [i.id, i.reason, i.required_by])).toEqual([
      ['trivy', 'requested', []],
      ['trivy-db', 'feed', ['trivy']],
      ['osv-scanner', 'requested', []],
      ['osv-db', 'feed', ['osv-scanner']],
    ])
    expect(plan.items[0]!.options).toEqual({ severity: 'HIGH', skip_dirs: [], timeout_s: 900 })
  })

  it('ne réinstalle pas un module présent et le signale', () => {
    const plan = buildInstallPlan([{ id: 'gitleaks' }, { id: 'trivy' }], ctx({ installed }))
    expect(plan.skipped).toEqual(['gitleaks', 'trivy'])
    expect(plan.warnings.map(w => w.code)).toEqual(['W_INSTALLED', 'W_INSTALLED'])
    expect(plan.ok).toBe(false)
  })

  it('refuse un module inconnu, une dépendance absente, un doublon, des options invalides', () => {
    const plan = buildInstallPlan([
      { id: 'inconnu' }, { id: 'orphelin-dep' }, { id: 'gitleaks', options: { redact: 'none' } }, { id: 'gitleaks' },
    ], ctx())
    expect(plan.blockers.map(b => b.code).sort()).toEqual(['E_DEPENDENCY', 'E_DUPLICATE', 'E_NOT_FOUND', 'E_OPTIONS'])
    expect(plan.blockers.find(b => b.code === 'E_DEPENDENCY')).toMatchObject({ module: 'orphelin-dep', other: 'inexistant' })
  })

  it('détecte les conflits (dans le plan et avec l’installé) et la version d’appliance', () => {
    const both = buildInstallPlan([{ id: 'semgrep' }, { id: 'opengrep' }], ctx({ acceptLicenses: ['semgrep'] }))
    expect(both.blockers).toEqual([{ code: 'E_CONFLICT', module: 'semgrep', other: 'opengrep' }])
    const withInstalled = buildInstallPlan([{ id: 'opengrep' }], ctx({ installed: [{ ...installed[0]!, id: 'semgrep', version: '1.140.0' }] }))
    expect(withInstalled.blockers).toEqual([{ code: 'E_CONFLICT', module: 'opengrep', other: 'semgrep' }])
    expect(buildInstallPlan([{ id: 'futur' }], ctx()).blockers).toEqual([{ code: 'E_APPLIANCE_VERSION', module: 'futur', other: '>=9.0.0' }])
  })

  it('exige l’acceptation explicite des licences à restriction', () => {
    const plan = buildInstallPlan([{ id: 'codeql' }, { id: 'semgrep' }], ctx())
    expect(plan.licenses_to_accept).toEqual(['codeql', 'semgrep'])
    expect(plan.blockers).toEqual([{ code: 'E_LICENSE_REQUIRED', other: 'codeql,semgrep' }])
    expect(buildInstallPlan([{ id: 'codeql' }], ctx({ acceptLicenses: ['codeql'] })).ok).toBe(true)
  })

  it('contrôle les ressources, signale les réglages noyau et le DNS d’une application', () => {
    const small = { cpu_count: 1, memory_mb: 4096, disks: [{ mount: '/', size_mb: 40960, avail_mb: 5000 }] }
    const plan = buildInstallPlan([{ id: 'sonarqube' }], ctx({ machine: small }))
    expect(plan.checks).toEqual([
      { kind: 'ram', needed: 2048 + 4096, available: 4096, ok: false },
      { kind: 'cpu', needed: 2, available: 1, ok: false },
      { kind: 'disk', needed: 10000, available: 5000, ok: false },
    ])
    expect(plan.blockers.filter(b => b.code === 'E_RESOURCES').map(b => b.other)).toEqual(['ram', 'cpu', 'disk'])
    expect(plan.sysctl).toEqual([{ module: 'sonarqube', key: 'vm.max_map_count', value: 524288 }])
    expect(plan.warnings).toEqual([{ code: 'W_DNS', module: 'sonarqube', other: 'sonarqube.analyse.exemple.test' }])
    const dnsOk = { ...dns, records: dns.records.map(r => ({ ...r, ok: true })) }
    expect(buildInstallPlan([{ id: 'sonarqube' }], ctx({ dns: dnsOk })).warnings).toEqual([])
    expect(buildInstallPlan([{ id: 'sonarqube' }], ctx({ dns: { fqdn: null, records: [] } })).warnings.map(w => w.code)).toEqual(['W_DNS'])
  })

  it('machine inconnue : avertissement, le helper tranchera', () => {
    const plan = buildInstallPlan([{ id: 'gitleaks' }], ctx({ machine: null }))
    expect(plan.ok).toBe(true)
    expect(plan.warnings).toEqual([{ code: 'W_RESOURCES_UNKNOWN' }])
    expect(plan.checks.every(c => c.ok && c.available === null)).toBe(true)
  })

  it('compte les modules permanents installés et le disque des conteneurs', () => {
    const service = { type: 'service' as const, resources: { min_ram_mb: 3000, min_cpu: 1, disk_mb: 0 } }
    const checks = resourceChecks([service], [{ module: service, enabled: true }, { module: service, enabled: false }], MACHINE)
    expect(checks[0]).toEqual({ kind: 'ram', needed: 2048 + 6000, available: 8192, ok: true })
    expect(containersDisk([{ mount: '/', size_mb: 1, avail_mb: 1 }, { mount: '/var', size_mb: 2, avail_mb: 2 }, { mount: '/var/lib/containers', size_mb: 3, avail_mb: 3 }, { mount: '/srv', size_mb: 4, avail_mb: 4 }])?.mount)
      .toBe('/var/lib/containers')
    expect(containersDisk([{ mount: '/home', size_mb: 1, avail_mb: 1 }])).toBeUndefined()
  })

  it('liste les modules installés qui dépendent d’un module (G1)', () => {
    expect(dependentsOf('trivy-db', { index, installed })).toEqual(['trivy'])
    expect(dependentsOf('gitleaks', { index, installed })).toEqual([])
  })
})

describe('vue du catalogue', () => {
  const view = () => buildCatalogView({ ...ctx({ installed }), operations: [], stateAvailable: true } as CatalogContext)

  it('fusionne index et état : installé, mise à jour, compatibilité, orphelins', () => {
    const v = view()
    const byId = Object.fromEntries(v.modules.map(m => [m.id, m]))
    expect(byId.gitleaks!.installed?.version).toBe('8.27.0')
    expect(byId.gitleaks!.update_available).toBe('8.28.0')
    expect(byId.osv_scanner).toBeUndefined()
    expect(byId['osv-scanner']!.auto_added).toEqual(['osv-db'])
    expect(byId.futur!.compatible).toBe(false)
    expect(byId.codeql!.compatible).toBe(true)
    expect(byId['trivy-db']!.dependents).toEqual(['trivy'])
    expect(v.orphans.map(o => o.id)).toEqual(['ancien'])
    expect(v.index).toEqual({ available: true, version: 7, generated_at: '2026-11-23T06:00:00Z', rejected: 1 })
  })

  it('packs : modules inconnus, installés, restants et plan global', () => {
    const packs = Object.fromEntries(view().packs.map(p => [p.id, p]))
    expect(packs.iac!.unknown_modules).toEqual(['checkov'])
    expect(packs.secrets!.installed_modules).toEqual(['gitleaks', 'trivy'])
    expect(packs.secrets!.plan).toBeNull()
    expect(packs.iac!.pending_modules).toEqual([])
  })

  it('sélection conseillée : modules présents non installés', () => {
    const v = view()
    expect(v.recommended.ids).toEqual(['osv-scanner', 'shellcheck'])
    expect(v.recommended.first_access).toBe(false)
    expect(v.recommended.plan?.items.map(i => i.id)).toEqual(['osv-scanner', 'osv-db', 'shellcheck'])
    const fresh = buildCatalogView({ ...ctx(), operations: [], stateAvailable: false } as CatalogContext)
    expect(fresh.recommended.first_access).toBe(true)
    expect(fresh.recommended.ids).toEqual(['gitleaks', 'osv-scanner', 'trivy', 'shellcheck'])
  })

  it('graphe et index absent', () => {
    expect(dependencyEdges(index)).toEqual(expect.arrayContaining([
      { from: 'trivy', to: 'trivy-db', kind: 'feed' },
      { from: 'semgrep', to: 'opengrep', kind: 'conflict' },
      { from: 'orphelin-dep', to: 'inexistant', kind: 'module' },
    ]))
    const empty = buildCatalogView({ ...ctx({ index: null, installed }), operations: [], stateAvailable: true } as CatalogContext)
    expect(empty.index.available).toBe(false)
    expect(empty.modules).toEqual([])
    expect(empty.orphans).toHaveLength(4)
    expect(empty.recommended.plan).toBeNull()
    expect(updateAvailable(undefined, undefined)).toBeNull()
  })
})
