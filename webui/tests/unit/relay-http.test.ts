// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// 0.7 (contrat 31) : relais IA servi en HTTPS sur un socket Unix par
// startRelay, comme dans scanoria-ai : certificat ai-relay.<nom> d'une AC de
// test (openssl), socket 0666, routes compatibles OpenAI (/v1/models,
// /v1/chat/completions avec ou sans flux, /v1/embeddings), vérification
// préalable du runner (/v1/relay/check), corps borné, route inconnue, jeton
// d'un autre module ou expiré, et aucun service sans certificat.

import { execFileSync } from 'node:child_process'
import { randomBytes, randomUUID } from 'node:crypto'
import { mkdtemp, rm, stat, writeFile } from 'node:fs/promises'
import { request } from 'node:https'
import type { Server } from 'node:https'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { RELAY_KEY } from '../../server/ai/models'
import { RELAY_MAX_BODY, RELAY_SOCKET, tokenHash, type RelayToken } from '../../server/ai/relay'
import { startRelay } from '../../server/ai/runtime'
import { AiService, type OllamaLike } from '../../server/ai/service'
import type { Queryable } from '../../server/utils/db'

const HOST = 'ai-relay.analyse.exemple.test'
const MODEL = { model: 'qwen-test:7b', digest: 'c'.repeat(64), context: 32768, reason: 'best-balance' }

function openssl(args: string[], cwd: string) {
  execFileSync('openssl', args, { cwd, stdio: 'ignore' })
}

describe('relais IA en HTTPS sur socket Unix (startRelay)', () => {
  let dir: string
  let tokens: string
  let server: Server | null
  let ca: string
  const projectId = randomUUID()
  const calls: { sql: string, params: unknown[] }[] = []
  const good = `scr_${randomBytes(36).toString('base64url')}`
  const expired = `scr_${randomBytes(36).toString('base64url')}`

  const db: Queryable = {
    query: (async (sql: string, params: unknown[] = []) => {
      calls.push({ sql, params })
      if (sql.includes(`kind = 'probe' AND status = 'done'`)) {
        return { rows: [{ output: { selection: { tasks: { [RELAY_KEY]: MODEL }, embedding: { ...MODEL, model: 'embed-test' } } }, finished_at: new Date() }], rowCount: 1 }
      }
      if (sql.startsWith('SELECT ai_opt_out')) return { rows: params[0] === projectId ? [{ ai_opt_out: false, archived_at: null }] : [], rowCount: 1 }
      return { rows: [], rowCount: 0 }
    }) as Queryable['query'],
  }
  const client: OllamaLike = {
    version: async () => '0.12.3',
    tags: async () => [],
    show: async () => ({}),
    chat: async () => ({ content: 'Looks fine.', bytesSent: 100, durationMs: 5 }),
    embed: async (_m, input) => ({ embeddings: input.map(() => Array.from({ length: 8 }, () => 0.25)), bytesSent: 10, durationMs: 1 }),
  }

  function call(method: 'GET' | 'POST', path: string, token: string | null, body?: unknown, raw?: Buffer): Promise<{ status: number, text: string, type: string }> {
    return new Promise((resolve, reject) => {
      const payload = raw ?? (body === undefined ? undefined : Buffer.from(JSON.stringify(body)))
      const headers: Record<string, string> = { host: HOST }
      if (token) headers.authorization = `Bearer ${token}`
      if (payload) {
        headers['content-type'] = 'application/json'
        headers['content-length'] = String(payload.length)
      }
      const req = request({ socketPath: join(dir, RELAY_SOCKET), servername: HOST, ca, method, path, headers, agent: false }, (res) => {
        const chunks: Buffer[] = []
        res.on('data', c => chunks.push(c))
        res.on('end', () => resolve({ status: res.statusCode ?? 0, text: Buffer.concat(chunks).toString('utf8'), type: String(res.headers['content-type']) }))
      })
      req.on('error', reject)
      if (payload) req.write(payload)
      req.end()
    })
  }

  beforeAll(async () => {
    dir = await mkdtemp(join(tmpdir(), 'relay-https-'))
    tokens = join(dir, 'tokens')
    execFileSync('mkdir', ['-p', tokens])
    openssl(['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes', '-keyout', 'ca.key', '-out', 'ca.crt', '-days', '2', '-subj', '/CN=Scanoria CA test'], dir)
    openssl(['req', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes', '-keyout', 'relay.key', '-out', 'relay.csr', '-subj', `/CN=${HOST}`], dir)
    await writeFile(join(dir, 'ext.cnf'), `subjectAltName = DNS:${HOST}\nextendedKeyUsage = serverAuth\n`)
    openssl(['x509', '-req', '-in', 'relay.csr', '-CA', 'ca.crt', '-CAkey', 'ca.key', '-CAcreateserial', '-out', 'relay.crt', '-days', '2', '-extfile', 'ext.cnf'], dir)
    ca = execFileSync('cat', [join(dir, 'ca.crt')]).toString()
    await writeFile(join(dir, 'ai.json'), JSON.stringify({ version: 1, enabled: true, literal: false, url: 'https://ollama.exemple.test:11434', scheme: 'https', host: 'ollama.exemple.test', port: 11434, addresses: ['192.0.2.10'], insecure: false, token: false, ca: false, pinned_at: '2026-11-25T08:00:00Z' }))
    const rec = (expiresIn: number): RelayToken => ({ v: 1, purpose: 'scan', module_id: 'pr-agent', project_id: projectId, scan_id: randomUUID(), expires_at: Math.floor(Date.now() / 1000) + expiresIn })
    await writeFile(join(tokens, `${tokenHash(good)}.json`), JSON.stringify(rec(600)))
    await writeFile(join(tokens, `${tokenHash(expired)}.json`), JSON.stringify(rec(-1)))
    const opts = { db, runtimeDir: dir }
    const service = new AiService({ db, loadEndpoint: async () => ({ enabled: false }) as never, clientFor: async () => client })
    const { fileTokenLookup } = await import('../../server/ai/relay')
    server = await startRelay(opts, service, async () => client, fileTokenLookup(tokens))
  })

  afterAll(async () => {
    if (server) await new Promise(resolve => server!.close(resolve))
    await rm(dir, { recursive: true, force: true })
  })

  it('socket créé en 0666 (joint par l’utilisateur 65534 du conteneur à travers son seul montage)', async () => {
    expect(server).not.toBeNull()
    expect((await stat(join(dir, RELAY_SOCKET))).mode & 0o777).toBe(0o666)
  })

  it('vérification préalable : prête, avec le modèle retenu ; jeton expiré ou absent : 401', async () => {
    const ok = await call('GET', '/v1/relay/check', good)
    expect(ok.status).toBe(200)
    expect(JSON.parse(ok.text)).toEqual({ ready: true, model: `qwen-test:7b@${'c'.repeat(12)}` })
    expect((await call('GET', '/v1/relay/check', expired)).status).toBe(401)
    expect((await call('GET', '/v1/relay/check', null)).status).toBe(401)
  })

  it('/v1/models : seul l’alias « scanoria » est exposé', async () => {
    const r = await call('GET', '/v1/models', good)
    expect(JSON.parse(r.text).data.map((m: { id: string }) => m.id)).toEqual(['scanoria'])
  })

  it('/v1/chat/completions : réponse au format OpenAI, sous l’alias du modèle', async () => {
    const r = await call('POST', '/v1/chat/completions', good, { model: 'gpt-4o', messages: [{ role: 'user', content: 'hello' }] })
    expect(r.status).toBe(200)
    const doc = JSON.parse(r.text)
    expect(doc.object).toBe('chat.completion')
    expect(doc.model).toBe('scanoria')
    expect(doc.choices[0].message).toEqual({ role: 'assistant', content: 'Looks fine.' })
    const log = calls.find(c => c.sql.includes('INSERT INTO ai_calls'))
    expect(log?.params.slice(5)).toEqual(['ok', 'pr-agent'])
  })

  it('flux demandé : SSE en un morceau, puis [DONE]', async () => {
    const r = await call('POST', '/v1/chat/completions', good, { messages: [{ role: 'user', content: 'stream me' }], stream: true })
    expect(r.status).toBe(200)
    expect(r.type).toContain('text/event-stream')
    const events = r.text.split('\n\n').filter(Boolean)
    expect(events.at(-1)).toBe('data: [DONE]')
    expect(JSON.parse(events[0]!.slice(6)).choices[0].delta.content).toBe('Looks fine.')
  })

  it('/v1/embeddings : un vecteur par entrée', async () => {
    const r = await call('POST', '/v1/embeddings', good, { input: ['a', 'b'] })
    expect(r.status).toBe(200)
    expect(JSON.parse(r.text).data).toHaveLength(2)
  })

  it('corps trop gros : 413 ; JSON invalide : 400 ; route inconnue : 404 ; sans jeton, le corps n’est pas lu', async () => {
    expect((await call('POST', '/v1/chat/completions', good, undefined, Buffer.alloc(RELAY_MAX_BODY + 10, 'a'))).status).toBe(413)
    expect((await call('POST', '/v1/chat/completions', good, undefined, Buffer.from('{'))).status).toBe(400)
    expect((await call('GET', '/v1/completions', good)).status).toBe(404)
    expect((await call('POST', '/v1/chat/completions', null, { messages: [{ role: 'user', content: 'x' }] })).status).toBe(401)
  })

  it('sans certificat : relais non servi (modules K « skipped » par la vérification du runner)', async () => {
    const empty = await mkdtemp(join(tmpdir(), 'relay-nocert-'))
    try {
      const service = new AiService({ db, loadEndpoint: async () => ({ enabled: false }) as never, clientFor: async () => client })
      expect(await startRelay({ db, runtimeDir: empty }, service, async () => client)).toBeNull()
    }
    finally {
      await rm(empty, { recursive: true, force: true })
    }
  })
})
