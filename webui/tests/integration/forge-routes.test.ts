// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Routes du chantier D (0.7, J1) contre un vrai PostgreSQL et une fausse
// application GitHub : manifeste (administrateur seulement, adresse de la
// console exigée), conversion (état signé, une seule fois), installation
// vérifiée auprès de GitHub, et webhook public (corps borné, signature).

import { createHmac, randomUUID } from 'node:crypto'
import { mkdtemp, rm } from 'node:fs/promises'
import { createServer, type Server } from 'node:http'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { createApp, createRouter, defineEventHandler, getHeader, toNodeListener } from 'h3'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { DATABASE_URL, createTestDatabase, type TestDatabase } from '../helpers/db'
import { startFakePrForge, type FakePrForge } from '../helpers/fake-pr-forge'
import { loadConfig, setConfig } from '../../server/utils/config'
import { closePool } from '../../server/utils/db'
import { createUser } from '../../server/utils/users'
import { setForgeRetryDelays } from '../../server/forges/http'
import { setConsoleUrl } from '../../server/forges/context'
import { getForgeApp, webhookSecret } from '../../server/forges/apps'
import manifestPost from '../../server/api/forges/github/manifest.post'
import convertPost from '../../server/api/forges/github/convert.post'
import installPost from '../../server/api/forges/github/install.post'
import webhookPost from '../../server/api/forges/[id]/webhook.post'
import type { Role } from '#shared/schemas'

const CONSOLE = 'https://analyse.exemple.test'

describe.skipIf(!DATABASE_URL)('routes des forges (chantier D, PostgreSQL)', () => {
  let db: TestDatabase
  let dir: string
  let fake: FakePrForge
  let server: Server
  let base: string
  const users: Record<Role, number> = { viewer: 0, operator: 0, admin: 0 }

  async function call(path: string, role: Role | null, init: { json?: unknown, raw?: string, headers?: Record<string, string> } = {}) {
    const res = await fetch(`${base}${path}`, {
      method: 'POST',
      headers: { ...(role ? { 'x-test-role': role } : {}), 'content-type': 'application/json', ...init.headers },
      body: init.raw ?? JSON.stringify(init.json ?? {}),
    })
    return { status: res.status, data: await res.json().catch(() => ({})) as Record<string, unknown> }
  }

  beforeAll(async () => {
    db = await createTestDatabase()
    dir = await mkdtemp(join(tmpdir(), 'scanoria-forge-routes-'))
    process.env.NUXT_SECRET_KEY_FILE = join(dir, 'secret.key')
    setConfig(loadConfig({
      NUXT_DATABASE_URL: db.url,
      NUXT_UPLOADS_DIR: join(dir, 'uploads'),
      NUXT_CATALOG_INDEX_FILE: join(dir, 'absent-index.json'),
      NUXT_MODULES_STATE_FILE: join(dir, 'absent-state.json'),
    }))
    setForgeRetryDelays([1, 1])
    fake = await startFakePrForge('github.com')
    for (const role of ['viewer', 'operator', 'admin'] as const) {
      users[role] = Number((await createUser(db.pool, { username: role, role, password: `${role}-long-password` })).id)
    }
    const app = createApp()
    app.use(defineEventHandler((event) => {
      const role = getHeader(event, 'x-test-role') as Role | undefined
      if (role) event.context.auth = { user: { id: users[role], username: role, displayName: null, role, locale: 'fr', mustChangePassword: false }, tokenHash: 'x', csrf: 'x' }
    }))
    const router = createRouter()
    router.post('/api/forges/github/manifest', manifestPost)
    router.post('/api/forges/github/convert', convertPost)
    router.post('/api/forges/github/install', installPost)
    router.post('/api/forges/:id/webhook', webhookPost)
    app.use(router)
    server = createServer(toNodeListener(app))
    await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve))
    const addr = server.address()
    base = `http://127.0.0.1:${typeof addr === 'object' && addr ? addr.port : 0}`
  })

  afterAll(async () => {
    setConsoleUrl()
    setForgeRetryDelays()
    if (server) await new Promise(resolve => server.close(resolve))
    await fake?.close()
    await closePool()
    await db?.drop()
    delete process.env.NUXT_SECRET_KEY_FILE
    if (dir) await rm(dir, { recursive: true, force: true })
  })

  it('manifeste, conversion, installation, puis webhooks reçus et vérifiés', async () => {
    // Adresse de la console inconnue : pas d'application possible (webhooks et retours).
    setConsoleUrl(null)
    expect((await call('/api/forges/github/manifest', 'admin', { json: { name: 'GitHub' } })).data).toMatchObject({ data: { code: 'E_FORGEAPP_CONSOLE_URL' } })
    setConsoleUrl(CONSOLE)
    expect((await call('/api/forges/github/manifest', 'operator', { json: { name: 'GitHub' } })).status).toBe(403)

    const m = await call('/api/forges/github/manifest', 'admin', { json: { name: 'GitHub', org: 'equipe', reachable: true } })
    expect(m.status).toBe(200)
    const action = new URL(m.data.action as string)
    expect(action.origin + action.pathname).toBe('https://github.com/organizations/equipe/settings/apps/new')
    const state = action.searchParams.get('state')!
    const manifest = JSON.parse(m.data.manifest as string) as { hook_attributes: { url: string, active: boolean }, redirect_url: string }
    expect(manifest.redirect_url).toBe(`${CONSOLE}/forges/github`)
    expect(manifest.hook_attributes.active).toBe(true)

    // État d'un autre administrateur ou falsifié : refusé.
    expect((await call('/api/forges/github/convert', 'admin', { json: { code: 'code-0001', state: `${state}x` } })).data).toMatchObject({ data: { code: 'E_FORGEAPP_STATE' } })
    fake.app.codes.add('code-0001')
    const conv = await call('/api/forges/github/convert', 'admin', { json: { code: 'code-0001', state } })
    expect(conv.status).toBe(201)
    expect(conv.data).toMatchObject({ slug: 'scanoria-test', install_url: 'https://github.com/apps/scanoria-test/installations/new' })
    const forgeId = conv.data.forge_id as string
    // Un second échange du même état : la forge existe déjà.
    expect((await call('/api/forges/github/convert', 'admin', { json: { code: 'code-0001', state } })).status).toBe(409)

    // Installation : vérifiée auprès de GitHub avec le JWT de l'application.
    expect((await call('/api/forges/github/install', 'admin', { json: { forge_id: forgeId, installation_id: '77' } })).data).toMatchObject({ data: { code: 'E_FORGEAPP_INSTALLATION' } })
    expect((await call('/api/forges/github/install', 'admin', { json: { forge_id: randomUUID(), installation_id: '77' } })).data).toMatchObject({ data: { code: 'E_FORGEAPP_KIND' } })
    fake.app.installations.push(77)
    const inst = await call('/api/forges/github/install', 'admin', { json: { forge_id: forgeId, installation_id: '77' } })
    expect(inst).toMatchObject({ status: 200, data: { forge_id: forgeId, added: true } })
    expect((await getForgeApp(db.pool, forgeId))!.installation_ids).toEqual(['77'])

    // Webhook public : sans session, signature du secret de l'application.
    const secret = (await webhookSecret(db.pool, forgeId))!
    const body = JSON.stringify({ zen: 'Keep it logically awesome.', hook_id: 1 })
    const sig = `sha256=${createHmac('sha256', secret).update(body).digest('hex')}`
    const ok = await call(`/api/forges/${forgeId}/webhook`, null, { raw: body, headers: { 'x-github-event': 'ping', 'x-github-delivery': randomUUID(), 'x-hub-signature-256': sig } })
    expect(ok).toMatchObject({ status: 202, data: { code: 'accepted' } })
    const bad = await call(`/api/forges/${forgeId}/webhook`, null, { raw: body, headers: { 'x-github-event': 'ping', 'x-github-delivery': randomUUID(), 'x-hub-signature-256': 'sha256=00' } })
    expect(bad).toMatchObject({ status: 401, data: { code: 'E_WEBHOOK_SIGNATURE' } })
    const big = await call(`/api/forges/${forgeId}/webhook`, null, { raw: 'x'.repeat(1024 * 1024 + 10), headers: { 'x-github-event': 'ping' } })
    expect(big).toMatchObject({ status: 413, data: { code: 'E_WEBHOOK_TOO_LARGE' } })
    expect((await call(`/api/forges/${randomUUID()}/webhook`, null, { raw: body })).status).toBe(404)
  })
})
