// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Client Ollama en https face à un certificat autosigné : refusé par défaut,
// accepté avec l'AC fournie, ou quand l'administrateur a désactivé la
// vérification (skip_tls_verify). Certificat et clé générés à l'exécution.

import { execFileSync } from 'node:child_process'
import { mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { createServer, type Server } from 'node:https'
import type { AddressInfo } from 'node:net'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { OllamaClient, OllamaError } from '../../server/ai/ollama'

const HOST = 'ollama.exemple.test'
let dir: string
let server: Server
let port: number
let certPem: string

beforeAll(async () => {
  dir = mkdtempSync(join(tmpdir(), 'scanoria-tls-'))
  execFileSync('openssl', [
    'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes', '-days', '1',
    '-subj', `/CN=${HOST}`, '-addext', `subjectAltName=DNS:${HOST}`,
    '-keyout', join(dir, 'key.pem'), '-out', join(dir, 'cert.pem'),
  ], { stdio: 'ignore' })
  certPem = readFileSync(join(dir, 'cert.pem'), 'utf8')
  server = createServer({ key: readFileSync(join(dir, 'key.pem')), cert: certPem }, (_req, res) => {
    res.setHeader('content-type', 'application/json')
    res.end(JSON.stringify({ version: '0.12.3' }))
  })
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve))
  port = (server.address() as AddressInfo).port
})

afterAll(async () => {
  await new Promise<void>(resolve => server.close(() => resolve()))
  rmSync(dir, { recursive: true, force: true })
})

const client = (extra: { caPem?: string, verifyTls?: boolean } = {}) =>
  new OllamaClient({ scheme: 'https', host: HOST, port, addresses: ['127.0.0.1'], ...extra })

describe('client Ollama en https, certificat autosigné', () => {
  it('refuse le certificat par défaut (vérification active)', async () => {
    await expect(client().version(5000)).rejects.toBeInstanceOf(OllamaError)
    await expect(client({ verifyTls: true }).version(5000)).rejects.toBeInstanceOf(OllamaError)
  })

  it('l\'accepte avec son AC fournie', async () => {
    expect(await client({ caPem: certPem }).version(5000)).toBe('0.12.3')
  })

  it('l\'accepte quand la vérification est désactivée, et ignore alors l\'AC', async () => {
    expect(await client({ verifyTls: false }).version(5000)).toBe('0.12.3')
    const other = `-----BEGIN CERTIFICATE-----\n${'Q'.repeat(80)}\n-----END CERTIFICATE-----\n`
    expect(await client({ verifyTls: false, caPem: other }).version(5000)).toBe('0.12.3')
  })
})
