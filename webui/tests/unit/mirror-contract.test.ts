// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Contrat 22 (0.6, chantier C) : le résultat du runner peut dire comment la
// source a été obtenue (miroir Git local, V2), où elle a été extraite (V9) et
// ce qui a été exclu (G15). zod et le schéma JSON rendent les mêmes verdicts.

import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import Ajv2020 from 'ajv/dist/2020.js'
import { describe, expect, it } from 'vitest'
import { scanResultSchema } from '../../server/scans/contract'
import { requestParamSchemas } from '#shared/schemas'

const schema = (name: string) => JSON.parse(readFileSync(fileURLToPath(new URL(`../../../src/rootfs/usr/share/scanoria/${name}.schema.json`, import.meta.url)), 'utf8'))
const resultV = new Ajv2020({ strict: false, allErrors: true }).compile(schema('schemas/scan-result'))

const ID = '3f1c2a9e-7b4d-4e2a-9c1f-0a1b2c3d4e5f'
const SCAN = '8b2d4f6a-1c3e-4a5b-8c7d-9e0f1a2b3c4d'
const result = (source: Record<string, unknown>) => ({
  schema: 1, id: ID, scan_id: SCAN, status: 'ok', started_at: '2026-11-24T10:00:00Z', finished_at: '2026-11-24T10:01:00Z',
  source: { kind: 'git', commit: 'c'.repeat(40), history: 'shallow', files: 10, bytes: 1000, skipped: [], ...source },
  modules: [],
})

const VALID = [
  {},
  { mirror: 'hit', workdir: 'tmpfs' },
  { mirror: 'fetched', workdir: 'disk', excluded: [{ pattern: '**/node_modules/**', count: 120 }, { pattern: '**/*.png', count: 3 }] },
  { mirror: 'created' },
  { mirror: 'ephemeral', excluded: [] },
]
const INVALID = [
  { mirror: 'remote' },
  { workdir: 'ram' },
  { excluded: [{ pattern: '', count: 1 }] },
  { excluded: [{ pattern: '**/x', count: 0 }] },
  { excluded: [{ pattern: '**/x', count: 1, extra: true }] },
  { excluded: [{ pattern: 'x'.repeat(101), count: 1 }] },
  { excluded: Array.from({ length: 101 }, (_, i) => ({ pattern: `**/*.e${i}`, count: 1 })) },
]

describe('contrat 22 : source du résultat', () => {
  it.each(VALID.map((v, i) => [i, v]))('accepté %i', (_i, v) => {
    const r = result(v)
    expect(resultV(r), JSON.stringify(resultV.errors)).toBe(true)
    expect(scanResultSchema.safeParse(r).success).toBe(true)
  })
  it.each(INVALID.map((v, i) => [i, v]))('refusé %i', (_i, v) => {
    const r = result(v)
    expect(resultV(r)).toBe(false)
    expect(scanResultSchema.safeParse(r).success).toBe(false)
  })
})

describe('contrat 22 : version de base montée (V7, G11)', () => {
  const withFeed = (feed: Record<string, unknown>) => ({
    ...result({}),
    modules: [{ id: 'trivy', version: '0.76.2', status: 'ok', image_digest: null, feeds: [{ id: 'trivy-db', version: null, updated_at: '2026-11-24T01:00:00Z', ...feed }], outputs: {}, log: null }],
  })
  it.each([[{}], [{ revision: '20261124T010000Z-0a1b2c3d' }]])('accepté %j', (f) => {
    expect(resultV(withFeed(f)), JSON.stringify(resultV.errors)).toBe(true)
    expect(scanResultSchema.safeParse(withFeed(f)).success).toBe(true)
  })
  it.each([[{ revision: '../x' }], [{ revision: 'legacy-0a1b2c3d' }], [{ revision: null }]])('refusé %j', (f) => {
    expect(resultV(withFeed(f))).toBe(false)
    expect(scanResultSchema.safeParse(withFeed(f)).success).toBe(false)
  })
})

describe('demande prefetch-images', () => {
  const pin = { module_id: 'gitleaks', version: '8.30.1', image_digest: `sha256:${'a'.repeat(64)}` }
  it('paramètres : versions figées seulement, empreintes complètes', () => {
    const s = requestParamSchemas['prefetch-images']
    expect(s.safeParse({}).success).toBe(true)
    expect(s.safeParse({ pins: [pin] }).success).toBe(true)
    expect(s.safeParse({ pins: [{ ...pin, image_digest: 'sha256:abc' }] }).success).toBe(false)
    expect(s.safeParse({ pins: [{ ...pin, image: 'docker.io/x' }] }).success).toBe(false)
    expect(s.safeParse({ pins: [{ ...pin, module_id: '../x' }] }).success).toBe(false)
    expect(s.safeParse({ other: 1 }).success).toBe(false)
  })
  it('même verdict que le schéma JSON du helper', () => {
    const v = new Ajv2020({ strict: false }).compile(schema('requests/prefetch-images'))
    const env = (params: unknown) => ({ version: 1, id: ID, type: 'prefetch-images', created_at: '2026-11-24T10:00:00Z', requested_by: { user_id: 0, username: 'system' }, params })
    expect(v(env({ pins: [pin] })), JSON.stringify(v.errors)).toBe(true)
    expect(v(env({ pins: [{ ...pin, image_digest: 'sha256:abc' }] }))).toBe(false)
  })
})
