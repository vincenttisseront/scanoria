// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Les contraintes zod de la console doivent correspondre exactement aux
// schémas JSON du contrat (src/rootfs/usr/share/scanoria/requests/) :
// mêmes expressions régulières, et mêmes verdicts sur des exemples valides
// et hostiles (validés aussi par ajv, JSON Schema 2020-12).

import { existsSync, readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import Ajv2020 from 'ajv/dist/2020.js'
import { describe, expect, it } from 'vitest'
import {
  ADDRESS_RE, CERT_PEM_RE, CIDR_RE, FQDN_RE, KEY_PEM_RE, MODULE_ID_RE, MODULE_VERSION_RE, REQUEST_TYPES, RESULT_CODES, TIMESTAMP_RE,
  USERNAME_RE, UUID_V4_RE, VERSION_RE, WINDOW_START_RE, envelopeSchema, resultSchema, type RequestType,
} from '#shared/schemas'

const CONTRACT_DIR = fileURLToPath(new URL('../../../src/rootfs/usr/share/scanoria/requests/', import.meta.url))
const loadSchema = (name: string) => JSON.parse(readFileSync(`${CONTRACT_DIR}${name}.schema.json`, 'utf8'))
/**
 * Les schémas des demandes de la 0.2 sont livrés par les chantiers C (modules)
 * et D (DNS). Tant qu'un schéma n'est pas fusionné, son type est absent du
 * contrat : la comparaison porte alors sur les types déjà livrés.
 */
const hasContract = (name: string) => existsSync(`${CONTRACT_DIR}${name}.schema.json`)

const ajv = new Ajv2020({ strict: false, allErrors: true })
const validators = new Map<string, ReturnType<typeof ajv.compile>>()
function contractValidator(name: string) {
  if (!validators.has(name)) validators.set(name, ajv.compile(loadSchema(name)))
  return validators.get(name)!
}

const ID = '3f1c2a9e-7b4d-4e2a-9c1f-0a1b2c3d4e5f'
const envelope = (type: RequestType, params: unknown, extra: Record<string, unknown> = {}) => ({
  version: 1,
  id: ID,
  type,
  created_at: '2026-11-23T08:00:00Z',
  requested_by: { user_id: 1, username: 'admin', address: '192.0.2.10' },
  params,
  ...extra,
})

const CERT = '-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n'
// En-tête de clé factice construit à l'exécution : rien qui ressemble à une
// clé privée n'apparaît en clair dans le dépôt (gitleaks, check-repo).
const PK = ['PRIVATE', 'KEY'].join(' ')
const KEY = `-----BEGIN ${PK}-----\nMIIE\n-----END ${PK}-----\n`

const CASES: Record<RequestType, { valid: unknown[], invalid: unknown[] }> = {
  'set-hostname': {
    valid: [{ fqdn: 'analyse.exemple.test' }, { fqdn: 'a-1.b.test' }],
    invalid: [
      { fqdn: 'localhost' }, { fqdn: 'Analyse.Exemple.Test' }, { fqdn: '*.exemple.test' },
      { fqdn: 'a.exemple.test;reboot' }, { fqdn: '-a.exemple.test' }, { fqdn: 'exemple.test.' },
      { fqdn: 'a.exemple.test', extra: 1 }, {}, { fqdn: 'x'.repeat(250) + '.test' }, { fqdn: 'a.123' },
    ],
  },
  'set-admin-networks': {
    valid: [
      { networks: ['192.0.2.0/24'] },
      { networks: ['192.0.2.0/24', '2001:db8::/32'], allow_self_lockout: true },
    ],
    invalid: [
      { networks: [] }, { networks: ['192.0.2.0'] }, { networks: ['192.0.2.0/33'] },
      { networks: ['256.0.0.0/8'] }, { networks: ['192.0.2.0/24', '192.0.2.0/24'] },
      { networks: ['192.0.2.0/24; flush ruleset'] }, { networks: ['2001:DB8::/32'] },
      { networks: Array.from({ length: 65 }, (_, i) => `10.0.${i}.0/24`) },
      { networks: ['192.0.2.0/24'], allow_self_lockout: 'yes' },
    ],
  },
  'issue-certificate': {
    valid: [{}, { force: true }],
    invalid: [{ force: 'true' }, { force: true, other: 1 }],
  },
  'import-certificate': {
    valid: [{ cert_pem: CERT, key_pem: KEY }, { cert_pem: CERT, key_pem: KEY.replace('PRIVATE', 'EC PRIVATE').replace('PRIVATE KEY-----\n', 'PRIVATE KEY-----\n'), chain_pem: CERT }],
    invalid: [
      { cert_pem: CERT }, { cert_pem: 'garbage', key_pem: KEY },
      { cert_pem: CERT, key_pem: '-----BEGIN ENCRYPTED PRIVATE KEY-----\nX\n' },
      { cert_pem: CERT, key_pem: KEY, chain_pem: 'x' },
      { cert_pem: CERT + 'A'.repeat(16384), key_pem: KEY },
    ],
  },
  'check-update': {
    valid: [{}, { channel: 'stable' }, { channel: 'prerelease' }],
    invalid: [{ channel: 'beta' }, { channel: 'stable', x: 1 }],
  },
  'apply-update': {
    valid: [{ source: 'github', version: '0.2.0' }, { source: 'upload', upload_id: ID }],
    invalid: [
      { source: 'github', version: '0.2.0-rc1' }, { source: 'github', version: '01.2.0' },
      { source: 'github', upload_id: ID }, { source: 'upload', upload_id: '../../etc' },
      { source: 'ftp', version: '0.2.0' }, { source: 'github', version: '0.2.0', upload_id: ID }, {},
    ],
  },
  'rollback-update': {
    valid: [{ expected_current: '0.2.0', expected_target: '0.1.0' }],
    invalid: [{ expected_current: '0.2.0' }, { expected_current: 'v0.2.0', expected_target: '0.1.0' }],
  },
  'set-update-policy': {
    valid: [
      { channel: 'stable', auto_check: true, auto_apply: false, maintenance_window: null },
      { channel: 'prerelease', auto_check: true, auto_apply: true, maintenance_window: { days: ['sat', 'sun'], start: '03:00', duration_minutes: 120 } },
    ],
    invalid: [
      { channel: 'stable', auto_check: true, auto_apply: true, maintenance_window: null },
      { channel: 'stable', auto_check: true, auto_apply: false, maintenance_window: { days: [], start: '03:00', duration_minutes: 120 } },
      { channel: 'stable', auto_check: true, auto_apply: false, maintenance_window: { days: ['sun', 'sun'], start: '03:00', duration_minutes: 120 } },
      { channel: 'stable', auto_check: true, auto_apply: false, maintenance_window: { days: ['sun'], start: '24:00', duration_minutes: 120 } },
      { channel: 'stable', auto_check: true, auto_apply: false, maintenance_window: { days: ['sun'], start: '03:00', duration_minutes: 10 } },
      { channel: 'stable', auto_check: true, auto_apply: false },
    ],
  },
  'run-selftest': {
    valid: [{}, { quick: true }],
    invalid: [{ quick: 1 }, { full: true }],
  },
  'refresh-catalog': {
    valid: [{}],
    invalid: [{ force: true }],
  },
  'install-modules': {
    valid: [
      { modules: [{ id: 'gitleaks', version: '8.28.0', options: {} }], accept_licenses: [] },
      { modules: [{ id: 'trivy', version: '0.67.2', options: { severity: 'HIGH' } }, { id: 'trivy-db', version: '2', options: {} }], accept_licenses: ['trivy'] },
    ],
    invalid: [
      { modules: [], accept_licenses: [] },
      { modules: [{ id: 'gitleaks', version: '8.28.0', options: {} }] },
      { modules: [{ id: 'gitleaks', version: '8.28.0' }], accept_licenses: [] },
      { modules: [{ id: '../etc', version: '1', options: {} }], accept_licenses: [] },
      { modules: [{ id: 'Gitleaks', version: '1', options: {} }], accept_licenses: [] },
      { modules: [{ id: 'gitleaks', version: '1; rm -rf /', options: {} }], accept_licenses: [] },
      { modules: [{ id: 'gitleaks', version: '1', options: [] }], accept_licenses: [] },
      { modules: [{ id: 'gitleaks', version: '1', options: {}, image: 'x' }], accept_licenses: [] },
      { modules: [{ id: 'gitleaks', version: '1', options: {} }], accept_licenses: ['a', 'a'] },
      { modules: Array.from({ length: 33 }, (_, i) => ({ id: `m${i}x`, version: '1', options: {} })), accept_licenses: [] },
      { modules: [{ id: 'gitleaks', version: '1', options: {} }], accept_licenses: [], extra: 1 },
    ],
  },
  'uninstall-module': {
    valid: [{ id: 'gitleaks', keep_data: true }, { id: 'osv-scanner', keep_data: false }],
    invalid: [{ id: 'gitleaks' }, { id: 'gitleaks', keep_data: 'no' }, { id: '-x', keep_data: true }],
  },
  'set-module-state': {
    valid: [{ id: 'trivy', enabled: false }],
    invalid: [{ id: 'trivy' }, { id: 'trivy', enabled: 1 }, { id: 'trivy', enabled: true, x: 1 }],
  },
  'update-module': {
    valid: [{ id: 'trivy', version: '0.68.0' }],
    invalid: [{ id: 'trivy' }, { id: 'trivy', version: '' }, { id: 'trivy', version: '.1' }],
  },
  'check-dns': {
    valid: [{}],
    invalid: [{ name: 'x' }],
  },
}

describe('expressions régulières identiques au contrat', () => {
  it('reprend mot pour mot les motifs des schémas JSON', () => {
    const hostname = loadSchema('set-hostname')
    const networks = loadSchema('set-admin-networks')
    const importCert = loadSchema('import-certificate')
    const apply = loadSchema('apply-update')
    const policy = loadSchema('set-update-policy')
    expect(UUID_V4_RE.source).toBe(hostname.properties.id.pattern)
    expect(TIMESTAMP_RE.source).toBe(hostname.properties.created_at.pattern.replace('(\\.', '(\\.'))
    expect(USERNAME_RE.source).toBe(hostname.properties.requested_by.properties.username.pattern)
    expect(ADDRESS_RE.source).toBe(hostname.properties.requested_by.properties.address.pattern)
    expect(FQDN_RE.source).toBe(hostname.properties.params.properties.fqdn.pattern)
    expect(CIDR_RE.source.replace(/\\\//g, '/')).toBe(networks.properties.params.properties.networks.items.pattern)
    expect(CERT_PEM_RE.source).toBe(importCert.properties.params.properties.cert_pem.pattern)
    expect(KEY_PEM_RE.source).toBe(importCert.properties.params.properties.key_pem.pattern)
    expect(VERSION_RE.source).toBe(apply.properties.params.oneOf[0].properties.version.pattern)
    expect(WINDOW_START_RE.source).toBe(policy.properties.params.properties.maintenance_window.oneOf[1].properties.start.pattern)
  })

  it.runIf(hasContract('install-modules'))('reprend les motifs des demandes de modules', () => {
    const install = loadSchema('install-modules')
    const item = install.properties.params.properties.modules.items
    expect(MODULE_ID_RE.source).toBe(item.properties.id.pattern)
    expect(MODULE_VERSION_RE.source).toBe(item.properties.version.pattern)
  })

  it('reprend la liste fermée des types et des codes', () => {
    const result = loadSchema('result')
    const contractTypes: string[] = result.properties.type.oneOf[1].enum
    // Ordre identique ; un type absent du contrat n'a pas encore son schéma (chantier non fusionné).
    expect(REQUEST_TYPES.filter(t => contractTypes.includes(t))).toEqual(contractTypes)
    for (const t of REQUEST_TYPES.filter(t => !contractTypes.includes(t))) expect(hasContract(t), t).toBe(false)
    const contractCodes: string[] = result.properties.code.enum
    expect(RESULT_CODES.filter(c => contractCodes.includes(c))).toEqual(contractCodes)
    if (hasContract('install-modules')) expect([...RESULT_CODES]).toEqual(contractCodes)
  })
})

describe('zod et JSON Schema donnent le même verdict', () => {
  for (const type of REQUEST_TYPES) {
    const zodEnvelope = envelopeSchema(type)
    for (const params of CASES[type].valid) {
      it(`${type} accepte ${JSON.stringify(params).slice(0, 60)}`, () => {
        const doc = envelope(type, params)
        if (hasContract(type)) expect(contractValidator(type)(doc)).toBe(true)
        expect(zodEnvelope.safeParse(doc).success).toBe(true)
      })
    }
    for (const params of CASES[type].invalid) {
      it(`${type} refuse ${JSON.stringify(params).slice(0, 60)}`, () => {
        const doc = envelope(type, params)
        if (hasContract(type)) expect(contractValidator(type)(doc)).toBe(false)
        expect(zodEnvelope.safeParse(doc).success).toBe(false)
      })
    }
  }

  const hostileEnvelopes: [string, Record<string, unknown>][] = [
    ['version 2', { version: 2 }],
    ['id majuscule', { id: ID.toUpperCase() }],
    ['id v1', { id: '3f1c2a9e-7b4d-1e2a-9c1f-0a1b2c3d4e5f' }],
    ['date sans Z', { created_at: '2026-11-23T08:00:00+01:00' }],
    ['utilisateur négatif', { requested_by: { user_id: -1, username: 'admin' } }],
    ['nom invalide', { requested_by: { user_id: 1, username: 'Admin' } }],
    ['adresse piégée', { requested_by: { user_id: 1, username: 'admin', address: '192.0.2.1;id' } }],
    ['champ inconnu', { extra: true }],
    ['type différent', { type: 'run-selftest' }],
  ]
  for (const [label, patch] of hostileEnvelopes) {
    it(`enveloppe refusée : ${label}`, () => {
      const doc = envelope('set-hostname', { fqdn: 'analyse.exemple.test' }, patch)
      expect(contractValidator('set-hostname')(doc)).toBe(false)
      expect(envelopeSchema('set-hostname').safeParse(doc).success).toBe(false)
    })
  }
})

describe('résultat du helper', () => {
  const base = {
    version: 1, id: ID, type: 'set-hostname', origin: 'console', status: 'ok', code: 'OK', message: 'hostname set',
    received_at: '2026-11-23T08:00:01Z', started_at: '2026-11-23T08:00:01Z', finished_at: '2026-11-23T08:00:09Z',
    output: { fqdn: 'analyse.exemple.test' },
  }
  const cases: [string, Record<string, unknown>, boolean][] = [
    ['succès', {}, true],
    ['échec cohérent', { status: 'error', code: 'E_LOCKOUT' }, true],
    ['rejet sans id', { status: 'rejected', code: 'E_INVALID_NAME', id: null, type: null }, true],
    ['ok avec code d’erreur', { code: 'E_INTERNAL' }, false],
    ['erreur avec OK', { status: 'error' }, false],
    ['code inconnu', { status: 'error', code: 'E_WHATEVER' }, false],
    ['champ inconnu', { secret: 'x' }, false],
  ]
  for (const [label, patch, expected] of cases) {
    it(label, () => {
      const doc = { ...base, ...patch }
      expect(contractValidator('result')(doc)).toBe(expected)
      expect(resultSchema.safeParse(doc).success).toBe(expected)
    })
  }
})
