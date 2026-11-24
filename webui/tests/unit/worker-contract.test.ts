// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Les schémas zod du worker (server/scans/contract.ts) rendent les mêmes
// verdicts qu'ajv sur les schémas JSON du contrat 8 (scan-job, scan-result),
// pour des exemples valides et hostiles.

import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import Ajv2020 from 'ajv/dist/2020.js'
import { describe, expect, it } from 'vitest'
import { scanJobSchema, scanResultSchema } from '../../server/scans/contract'

const schema = (name: string) => JSON.parse(readFileSync(fileURLToPath(new URL(`../../../src/rootfs/usr/share/scanoria/schemas/${name}.schema.json`, import.meta.url)), 'utf8'))
const ajv = new Ajv2020({ strict: false, allErrors: true })
const jobV = ajv.compile(schema('scan-job'))
const resultV = ajv.compile(schema('scan-result'))

const ID = '3f1c2a9e-7b4d-4e2a-9c1f-0a1b2c3d4e5f'
const SCAN = '8b2d4f6a-1c3e-4a5b-8c7d-9e0f1a2b3c4d'
const tok = () => `scn_${'x'.repeat(40)}`
const SSH = ['-----BEGIN OPENSSH', 'PRIVATE KEY-----\nAAAA\n'].join(' ')

const job = (source: unknown, extra: Record<string, unknown> = {}) => ({
  schema: 1, id: ID, scan_id: SCAN, created_at: '2026-11-24T10:00:00.123Z', source,
  modules: [{ id: 'gitleaks', version: '8.30.1', options: { history: true } }], ...extra,
})
const git = (extra: Record<string, unknown> = {}) => ({ kind: 'git', url: 'https://forge.exemple.test/a/b.git', ref: 'main', history: 'shallow', ...extra })

const JOBS: { valid: unknown[], invalid: unknown[] } = {
  valid: [
    job(git()),
    job(git({ commit: 'a'.repeat(40), credential: null, history: 'full' })),
    job(git({ credential: { kind: 'token', token: tok() } })),
    job(git({ credential: { kind: 'token', token: tok(), username: 'ci' } })),
    job(git({ url: 'ssh://git@forge.exemple.test/a/b.git', credential: { kind: 'ssh-key', private_key: SSH, known_hosts: 'forge.exemple.test ssh-ed25519 AAAA' } })),
    job(git({ url: 'git@forge.exemple.test:a/b.git', ref: 'release/1.2' })),
    job({ kind: 'archive', upload_id: ID }),
  ],
  invalid: [
    job(git({ url: 'file:///etc' })), job(git({ url: 'ext::sh -c id' })), job(git({ url: 'https://user:pw@forge.exemple.test/a' })),
    job(git({ ref: '--upload-pack=id' })), job(git({ ref: 'a..b' })), job(git({ ref: 'a//b' })), job(git({ ref: 'a@{1}' })), job(git({ ref: '' })),
    job(git({ ref: 'a b' })), job(git({ commit: 'abc' })), job(git({ history: 'deep' })), job(git({ extra: 1 })),
    job(git({ credential: { kind: 'token', token: 'a b' } })), job(git({ credential: { kind: 'token', token: tok(), username: 'a:b' } })),
    job(git({ credential: { kind: 'ssh-key', private_key: 'nope', known_hosts: 'x' } })),
    job(git({ credential: { kind: 'ssh-key', private_key: SSH, known_hosts: '' } })),
    job({ kind: 'archive', upload_id: 'x' }), job({ kind: 'archive' }),
    job(git(), { modules: [] }), job(git(), { modules: [{ id: '../x', version: '1' }] }), job(git(), { modules: [{ id: 'ok', version: '' }] }),
    job(git(), { modules: [{ id: 'ok', version: '1' }, { id: 'ok', version: '1' }] }),
    job(git(), { schema: 2 }), job(git(), { id: 'x' }), job(git(), { created_at: '2026-11-24 10:00:00' }), job(git(), { extra: true }),
  ],
}

const mod = (extra: Record<string, unknown> = {}) => ({
  id: 'gitleaks', version: '8.30.1', status: 'ok', image_digest: `sha256:${'b'.repeat(64)}`, feeds: [], outputs: { sarif: 'gitleaks/result.sarif' }, log: 'gitleaks/module.log', ...extra,
})
const result = (extra: Record<string, unknown> = {}, modules: unknown[] = [mod()]) => ({
  schema: 1, id: ID, scan_id: SCAN, status: 'ok', started_at: '2026-11-24T10:00:00Z', finished_at: '2026-11-24T10:01:00Z',
  source: { kind: 'git', commit: 'c'.repeat(40), history: 'shallow', files: 10, bytes: 1000, skipped: [{ path: 'big.bin', reason: 'size' }] },
  modules, ...extra,
})

const RESULTS: { valid: unknown[], invalid: unknown[] } = {
  valid: [
    result(),
    result({ status: 'error', error: { code: 'E_FETCH', class: 'input', message: 'unreachable' } }, []),
    result({ error: null }, [mod({ status: 'oom', error: { code: 'E_OOM', class: 'infra', message: 'oom' }, image_digest: null, log: null, outputs: {} })]),
    result({}, [mod({ feeds: [{ id: 'trivy-db', version: null, updated_at: '2026-11-24T00:00:00Z' }], stats: { duration_ms: 1, peak_memory_mb: 2, cpu_ms: 3 }, exit_code: 0, started_at: null, finished_at: '2026-11-24T10:00:59Z' })]),
  ],
  invalid: [
    result({ status: 'partial' }), result({ error: { code: 'bad', class: 'infra', message: 'x' } }), result({ error: { code: 'E_X', class: 'other', message: 'x' } }),
    result({}, [mod({ outputs: { sarif: '../etc/passwd' } })]), result({}, [mod({ outputs: { sarif: '/abs' } })]), result({}, [mod({ log: 'a/./b' })]),
    result({}, [mod({ outputs: { other: 'x' } })]), result({}, [mod({ status: 'pending' })]), result({}, [mod({ image_digest: 'sha256:short' })]),
    result({}, [mod({ stats: { duration_ms: -1 } })]), result({}, [mod({ feeds: [{ id: 'x' }] })]), result({ extra: 1 }),
    result({ source: { kind: 'git', commit: 'zz', history: 'shallow', files: 0, bytes: 0, skipped: [] } }),
    result({ source: { kind: 'git', commit: null, history: 'shallow', files: 0, bytes: 0, skipped: [{ path: 'x', reason: 'virus' }] } }),
  ],
}

describe('contrat 8 : zod = schémas JSON', () => {
  it.each(JOBS.valid.map((v, i) => [i, v]))('tâche valide %i', (_i, v) => {
    expect(jobV(v), JSON.stringify(jobV.errors)).toBe(true)
    expect(scanJobSchema.safeParse(v).success).toBe(true)
  })
  it.each(JOBS.invalid.map((v, i) => [i, v]))('tâche refusée %i', (_i, v) => {
    expect(jobV(v)).toBe(false)
    expect(scanJobSchema.safeParse(v).success).toBe(false)
  })
  it.each(RESULTS.valid.map((v, i) => [i, v]))('résultat valide %i', (_i, v) => {
    expect(resultV(v), JSON.stringify(resultV.errors)).toBe(true)
    expect(scanResultSchema.safeParse(v).success).toBe(true)
  })
  it.each(RESULTS.invalid.map((v, i) => [i, v]))('résultat refusé %i', (_i, v) => {
    expect(resultV(v)).toBe(false)
    expect(scanResultSchema.safeParse(v).success).toBe(false)
  })
})
