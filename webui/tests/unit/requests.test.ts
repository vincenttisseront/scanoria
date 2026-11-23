// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Écriture des demandes : nom, enveloppe, écriture atomique tmp → incoming,
// droits 0600, taille maximale, aucun secret dans les paramètres enregistrés.

import { mkdir, mkdtemp, readFile, readdir, rm, stat, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import {
  MAX_REQUEST_BYTES, RequestTooLargeError, RequestValidationError, buildEnvelope, isoSeconds,
  requestFileName, sanitizeParams, validateParams, writeRequestFile,
} from '../../server/utils/requests'
import { REQUEST_FILE_RE, envelopeSchema } from '#shared/schemas'

let dir: string
beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), 'scanoria-requests-'))
  await mkdir(join(dir, 'tmp'), { mode: 0o700 })
  await mkdir(join(dir, 'incoming'), { mode: 0o700 })
})
afterEach(async () => {
  await rm(dir, { recursive: true, force: true })
})

describe('nom et enveloppe', () => {
  it('nomme le fichier AAAAMMJJTHHMMSSZ-<uuid>.json', () => {
    const id = '3f1c2a9e-7b4d-4e2a-9c1f-0a1b2c3d4e5f'
    expect(requestFileName('2026-11-23T08:00:00Z', id)).toBe(`20261123T080000Z-${id}.json`)
    expect(isoSeconds(new Date('2026-11-23T08:00:00.987Z'))).toBe('2026-11-23T08:00:00Z')
    expect(() => requestFileName('2026-11-23T08:00:00Z', 'not-a-uuid')).toThrow()
  })

  it('construit une enveloppe conforme au contrat', () => {
    const env = buildEnvelope('set-hostname', { fqdn: 'analyse.exemple.test' }, { userId: 3, username: 'alice', address: '198.51.100.7' })
    expect(envelopeSchema('set-hostname').safeParse(env).success).toBe(true)
    expect(env.requested_by).toEqual({ user_id: 3, username: 'alice', address: '198.51.100.7' })
    expect(REQUEST_FILE_RE.test(requestFileName(env.created_at, env.id))).toBe(true)
  })

  it('omet une adresse absente et refuse des paramètres hostiles', () => {
    const env = buildEnvelope('run-selftest', { quick: true }, { userId: 1, username: 'admin' })
    expect('address' in env.requested_by).toBe(false)
    expect(() => validateParams('set-hostname', { fqdn: 'x;reboot' })).toThrow(RequestValidationError)
    expect(() => validateParams('set-admin-networks', { networks: ['0.0.0.0/0', '0.0.0.0/0'] })).toThrow(RequestValidationError)
  })

  it('ne garde jamais la clé privée dans les paramètres enregistrés', () => {
    const params = { cert_pem: '-----BEGIN CERTIFICATE-----\nA\n', key_pem: '-----BEGIN PRIVATE KEY-----\nSECRET\n' }
    const stored = JSON.stringify(sanitizeParams('import-certificate', params))
    expect(stored).not.toContain('SECRET')
    expect(stored).not.toContain('PRIVATE')
  })
})

describe('écriture atomique', () => {
  it('écrit dans incoming/ en 0600 sans laisser de fichier .part', async () => {
    const name = '20261123T080000Z-3f1c2a9e-7b4d-4e2a-9c1f-0a1b2c3d4e5f.json'
    await writeRequestFile(dir, name, '{"a":1}\n')
    expect(await readdir(join(dir, 'tmp'))).toEqual([])
    expect(await readFile(join(dir, 'incoming', name), 'utf8')).toBe('{"a":1}\n')
    expect((await stat(join(dir, 'incoming', name))).mode & 0o777).toBe(0o600)
  })

  it('refuse un nom non conforme ou un contenu trop gros', async () => {
    await expect(writeRequestFile(dir, '../evil.json', '{}')).rejects.toThrow()
    const name = '20261123T080000Z-3f1c2a9e-7b4d-4e2a-9c1f-0a1b2c3d4e5f.json'
    await expect(writeRequestFile(dir, name, 'x'.repeat(MAX_REQUEST_BYTES + 1))).rejects.toThrow(RequestTooLargeError)
    expect(await readdir(join(dir, 'incoming'))).toEqual([])
  })

  it('ne réutilise jamais un fichier temporaire existant (création exclusive)', async () => {
    const name = '20261123T080000Z-3f1c2a9e-7b4d-4e2a-9c1f-0a1b2c3d4e5f.json'
    await writeFile(join(dir, 'tmp', `${name}.part`), 'planted')
    await expect(writeRequestFile(dir, name, '{}')).rejects.toThrow(/EEXIST/)
    expect(await readdir(join(dir, 'incoming'))).toEqual([])
  })
})
