// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Client Ollama contre le faux serveur : adresses épinglées (aucune
// résolution du nom), corps de chat sans outil ni flux, jeton, pannes.

import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { OllamaClient, OllamaError, pinnedLookup } from '../../server/ai/ollama'
import { startFakeOllama, type FakeOllama } from '../helpers/fake-ollama'

let fake: FakeOllama
beforeAll(async () => {
  fake = await startFakeOllama()
})
afterAll(async () => {
  await fake.close()
})

// Nom de documentation qui ne résout pas : seule l'adresse épinglée est utilisée.
const client = (token: string | null = null) => new OllamaClient({ scheme: 'http', host: 'ollama.exemple.test', port: fake.port, addresses: ['127.0.0.1'], token })

describe('client Ollama', () => {
  it('joint l\'adresse épinglée sans résoudre le nom, avec l\'en-tête Host d\'origine', async () => {
    expect(await client().version()).toBe('0.12.3')
    const last = fake.requests.at(-1)!
    expect(last.headers.host).toBe(`ollama.exemple.test:${fake.port}`)
  })

  it('liste et décrit les modèles', async () => {
    const tags = await client().tags()
    expect(tags.map(t => t.name)).toEqual(['qwen-test:14b', 'embed-test:latest'])
    expect((await client().show('qwen-test:14b')).capabilities).toEqual(['completion', 'tools'])
  })

  it('envoie un chat sans outil ni flux, avec le schéma et le jeton', async () => {
    const token = `t-${Date.now()}`
    const r = await client(token).chat({
      model: 'qwen-test:14b',
      messages: [{ role: 'user', content: '<data-00>\n{"rule_id":"r","title":"t"}\n</data-00>' }],
      format: { type: 'object', required: ['summary', 'blocking', 'actions'] },
      numCtx: 4096,
    }, 5000)
    expect(JSON.parse(r.content)).toHaveProperty('summary')
    expect(r.bytesSent).toBeGreaterThan(0)
    const last = fake.requests.at(-1)!
    const body = JSON.parse(last.body) as Record<string, unknown>
    expect(Object.keys(body).sort()).toEqual(['format', 'keep_alive', 'messages', 'model', 'options', 'stream'])
    expect(body.stream).toBe(false)
    expect(body).not.toHaveProperty('tools')
    expect(last.headers.authorization).toBe(`Bearer ${token}`)
  })

  it('signale une panne, une lenteur, une réponse illisible', async () => {
    fake.mode = 'down'
    await expect(client().version()).rejects.toMatchObject({ kind: 'http', status: 503 })
    fake.mode = 'slow'
    fake.delayMs = 400
    await expect(client().version(100)).rejects.toMatchObject({ kind: 'timeout' })
    fake.mode = 'ok'
    fake.delayMs = 0
    await expect(new OllamaClient({ scheme: 'http', host: 'x.exemple.test', port: 1, addresses: ['127.0.0.1'] }).version(2000))
      .rejects.toBeInstanceOf(OllamaError)
    expect(() => new OllamaClient({ scheme: 'http', host: 'x', port: 1, addresses: [] })).toThrow()
  })

  it('accepte un échange sans message et écarte un modèle sans empreinte valide', async () => {
    await expect(client().chat({ model: 'x', messages: [], format: {}, numCtx: 1 }, 2000)).resolves.toBeDefined()
    fake.models.push({ name: 'nodigest', digest: 'zz' })
    expect((await client().tags()).map(t => t.name)).not.toContain('nodigest')
    fake.models.pop()
  })

  it('la recherche épinglée renvoie toujours les adresses fournies', () => {
    const lookup = pinnedLookup(['192.0.2.10', '2001:db8::10'])
    const seen: unknown[] = []
    lookup('ignored', { all: true } as never, (...args: unknown[]) => seen.push(args[1]))
    lookup('ignored', {} as never, (...args: unknown[]) => seen.push(args[1], args[2]))
    lookup('ignored', {} as never, (...args: unknown[]) => seen.push(args[1], args[2]))
    expect(seen).toEqual([[{ address: '192.0.2.10', family: 4 }, { address: '2001:db8::10', family: 6 }], '192.0.2.10', 4, '2001:db8::10', 6])
  })
})
