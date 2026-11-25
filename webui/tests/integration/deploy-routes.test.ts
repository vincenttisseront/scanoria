// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// API de déploiement (0.8, chantier D) contre PostgreSQL : rôles (lecture
// pour les vues, administrateur pour les cibles), validation zod, jeton
// jamais rendu, fusion automatique réservée au GitOps, audit, chaîne d'un
// projet, enveloppe DSSE téléchargeable.

import { mkdir, mkdtemp, rm } from 'node:fs/promises'
import { createServer, type Server } from 'node:http'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { createApp, createRouter, defineEventHandler, getHeader, toNodeListener } from 'h3'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { DATABASE_URL, createTestDatabase, type TestDatabase } from '../helpers/db'
import { fakeToken } from '../helpers/fake-forge'
import { loadConfig, setConfig } from '../../server/utils/config'
import { closePool } from '../../server/utils/db'
import { createUser } from '../../server/utils/users'
import type { Role } from '#shared/schemas'
import targetsGet from '../../server/api/deploy/projects/[id]/targets.get'
import targetsPost from '../../server/api/deploy/projects/[id]/targets.post'
import proposalsGet from '../../server/api/deploy/projects/[id]/proposals.get'
import chainGet from '../../server/api/deploy/projects/[id]/chain.get'
import targetPatch from '../../server/api/deploy/targets/[id].patch'
import targetDelete from '../../server/api/deploy/targets/[id].delete'
import attestationGet from '../../server/api/deploy/attestations/[id].get'
import scanGet from '../../server/api/deploy/scans/[id].get'

const REG = 'registre.exemple.test'

describe.skipIf(!DATABASE_URL)('API de déploiement (PostgreSQL réel)', () => {
  let db: TestDatabase
  let root: string
  let server: Server
  let base: string
  let project: string
  const users: Record<Role, number> = { viewer: 0, operator: 0, admin: 0 }

  async function call(path: string, role: Role, init: { method?: string, json?: unknown } = {}) {
    const res = await fetch(`${base}${path}`, {
      method: init.method ?? 'GET',
      headers: { 'x-test-role': role, ...(init.json === undefined ? {} : { 'content-type': 'application/json' }) },
      body: init.json === undefined ? undefined : JSON.stringify(init.json),
    })
    const text = await res.text()
    // eslint-disable-next-line @typescript-eslint/no-explicit-any -- réponses JSON lues librement par les assertions
    let data: Record<string, any> = {}
    try {
      data = JSON.parse(text)
    }
    catch { /* corps vide */ }
    return { status: res.status, data, text, type: res.headers.get('content-type') }
  }

  beforeAll(async () => {
    db = await createTestDatabase()
    root = await mkdtemp(join(tmpdir(), 'scanoria-deploy-api-'))
    for (const d of ['requests/incoming', 'requests/tmp']) await mkdir(join(root, d), { recursive: true })
    process.env.NUXT_SECRET_KEY_FILE = join(root, 'secret.key')
    setConfig(loadConfig({
      NUXT_DATABASE_URL: db.url, NUXT_REQUESTS_DIR: join(root, 'requests'),
      NUXT_CATALOG_INDEX_FILE: join(root, 'absent-index.json'), NUXT_MODULES_STATE_FILE: join(root, 'absent-state.json'),
    }))
    for (const role of ['viewer', 'operator', 'admin'] as const) {
      users[role] = Number((await createUser(db.pool, { username: role, role, password: `${role}-long-password` })).id)
    }
    project = (await db.pool.query<{ id: string }>(
      `INSERT INTO projects (slug, name, source_kind, profile_id, gate_id)
       VALUES ('dep', 'Déploiement', 'archive', (SELECT id FROM profiles WHERE slug = 'rapide'), (SELECT id FROM gates WHERE slug = 'defaut')) RETURNING id`)).rows[0]!.id

    const app = createApp()
    app.use(defineEventHandler((event) => {
      const role = getHeader(event, 'x-test-role') as Role | undefined
      if (role) event.context.auth = { user: { id: users[role], username: role, displayName: null, role, locale: 'fr', mustChangePassword: false }, tokenHash: 'x', csrf: 'x' }
    }))
    const router = createRouter()
    router.get('/api/deploy/projects/:id/targets', targetsGet)
    router.post('/api/deploy/projects/:id/targets', targetsPost)
    router.get('/api/deploy/projects/:id/proposals', proposalsGet)
    router.get('/api/deploy/projects/:id/chain', chainGet)
    router.patch('/api/deploy/targets/:id', targetPatch)
    router.delete('/api/deploy/targets/:id', targetDelete)
    router.get('/api/deploy/attestations/:id', attestationGet)
    router.get('/api/deploy/scans/:id', scanGet)
    app.use(router)
    server = createServer(toNodeListener(app))
    await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve))
    const addr = server.address()
    base = `http://127.0.0.1:${typeof addr === 'object' && addr ? addr.port : 0}`
  })

  afterAll(async () => {
    if (server) await new Promise(resolve => server.close(resolve))
    await closePool()
    delete process.env.NUXT_SECRET_KEY_FILE
    await db?.drop()
    if (root) await rm(root, { recursive: true, force: true })
  })

  const registry = { kind: 'registry-promotion', environment: 'production', config: { source: `${REG}/candidat/app`, destination: `${REG}/valide/app` } }

  it('cibles : administrateur seulement pour écrire, validation, doublon refusé, jeton jamais rendu', async () => {
    const path = `/api/deploy/projects/${project}/targets`
    expect((await call(path, 'operator', { method: 'POST', json: registry })).status).toBe(403)
    expect((await call(path, 'admin', { method: 'POST', json: { ...registry, config: { source: `${REG}/a`, destination: `${REG}/a` } } })).status).toBe(400)
    expect((await call(path, 'admin', { method: 'POST', json: { ...registry, environment: 'Prod Ü' } })).status).toBe(400)
    expect((await call(path, 'admin', { method: 'POST', json: { kind: 'cd-trigger', environment: 'recette', on_trigger: 'branch', config: { provider: 'forge', workflow: 'deploy.yml' } } })).status).toBe(400)
    expect((await call(path, 'admin', { method: 'POST', json: { kind: 'cd-trigger', environment: 'x', config: { provider: 'jenkins', url: 'https://127.0.0.1/', job: 'a' } } })).status).toBe(400)
    const token = fakeToken()
    const created = await call(path, 'admin', { method: 'POST', json: { ...registry, credential: { username: 'robot', value: token } } })
    expect(created.status).toBe(201)
    expect(created.text).not.toContain(token)
    expect(created.data.target).toMatchObject({ kind: 'registry-promotion', environment: 'production', enabled: true, auto_merge: false })
    expect((await call(path, 'admin', { method: 'POST', json: registry })).status).toBe(409)
    const list = await call(path, 'viewer')
    expect(list.status).toBe(200)
    expect(list.text).not.toContain(token)
    expect(list.data.items ?? list.data.targets).toHaveLength(1)
    const audit = await db.pool.query<{ details: Record<string, unknown> }>(`SELECT details FROM audit_log WHERE action = 'deploy.target.create'`)
    expect(audit.rows).toHaveLength(1)
    expect(JSON.stringify(audit.rows[0]!.details)).not.toContain(token)
  })

  it('mise à jour : fusion automatique réservée au GitOps, tracée avec son auteur', async () => {
    const path = `/api/deploy/projects/${project}/targets`
    const git = await call(path, 'admin', { method: 'POST', json: { kind: 'gitops-pr', environment: 'production', config: { repo: 'equipe/deploiement', files: [{ path: 'apps/app.yaml', image: `${REG}/valide/app` }] } } })
    expect(git.status).toBe(201)
    const reg = (await call(path, 'viewer')).data
    const regId = (reg.items ?? reg.targets).find((t: { kind: string }) => t.kind === 'registry-promotion').id
    expect((await call(`/api/deploy/targets/${regId}`, 'admin', { method: 'PATCH', json: { auto_merge: true } })).status).toBe(400)
    expect((await call(`/api/deploy/targets/${git.data.target.id}`, 'operator', { method: 'PATCH', json: { auto_merge: true } })).status).toBe(403)
    const on = await call(`/api/deploy/targets/${git.data.target.id}`, 'admin', { method: 'PATCH', json: { auto_merge: true } })
    expect(on.status).toBe(200)
    expect(on.data.target.auto_merge).toBe(true)
    const by = await db.pool.query<{ auto_merge_by: string }>('SELECT auto_merge_by FROM deploy_targets WHERE id = $1', [git.data.target.id])
    expect(Number(by.rows[0]!.auto_merge_by)).toBe(users.admin)
    expect((await call(`/api/deploy/targets/${git.data.target.id}`, 'admin', { method: 'PATCH', json: { enabled: 'oui' } })).status).toBe(400)
    expect((await call(`/api/deploy/targets/00000000-0000-4000-8000-000000000000`, 'admin', { method: 'PATCH', json: { enabled: false } })).status).toBe(404)
    expect((await call(`/api/deploy/targets/${git.data.target.id}`, 'operator', { method: 'DELETE' })).status).toBe(403)
    expect((await call(`/api/deploy/targets/${git.data.target.id}`, 'admin', { method: 'DELETE' })).status).toBe(204)
    expect(Number((await db.pool.query<{ n: string }>(`SELECT count(*) AS n FROM audit_log WHERE action LIKE 'deploy.target.%'`)).rows[0]!.n)).toBe(4)
  })

  it('vues : chaîne du projet, propositions sans forge, analyse et attestation', async () => {
    const chain = await call(`/api/deploy/projects/${project}/chain`, 'viewer')
    expect(chain.status).toBe(200)
    expect(chain.data).toMatchObject({ autonomous: false, pull_requests: [], releases: [] })
    expect((await call(`/api/deploy/projects/${project}/proposals`, 'viewer')).status).toBe(403)
    const props = await call(`/api/deploy/projects/${project}/proposals`, 'admin')
    expect(props.status).toBe(200)
    expect(props.data.items).toEqual([])
    expect((await call(`/api/deploy/projects/00000000-0000-4000-8000-000000000000/chain`, 'viewer')).status).toBe(404)

    const scan = (await db.pool.query<{ id: string }>(
      `INSERT INTO scans (project_id, number, trigger, priority, ref, commit_sha, profile_id, gate_id, status, verdict, finished_at)
       SELECT id, 1, 'release', 50, 'refs/tags/v1.0.0', $2, profile_id, gate_id, 'done', 'passed', now() FROM projects WHERE id = $1 RETURNING id::text`,
      [project, 'd'.repeat(40)])).rows[0]!.id
    const envelope = { payloadType: 'application/vnd.in-toto+json', payload: 'e30=', signatures: [{ keyid: 'f'.repeat(64), sig: `${'A'.repeat(86)}==` }] }
    const att = (await db.pool.query<{ id: string }>(
      `INSERT INTO attestations (scan_id, subject_name, subject_digest, predicate_type, envelope, status)
       VALUES ($1, $2, $3, 'https://github.com/vincenttisseront/scanoria/attestation/release-verdict/v1', $4, 'signed') RETURNING id::text`,
      [scan, `${REG}/valide/app`, `sha256:${'e'.repeat(64)}`, JSON.stringify(envelope)])).rows[0]!.id
    const s = await call(`/api/deploy/scans/${scan}`, 'viewer')
    expect(s.status).toBe(200)
    expect(s.data.attestations).toEqual([expect.objectContaining({ id: att, downloadable: true })])
    expect(s.text).not.toContain('signatures')
    expect((await call('/api/deploy/scans/..%2Fetc', 'viewer')).status).toBe(404)
    const dl = await call(`/api/deploy/attestations/${att}`, 'viewer')
    expect(dl.status).toBe(200)
    expect(dl.type).toContain('application/vnd.dsse.envelope.v1+json')
    expect(dl.data).toEqual(envelope)
    expect((await call('/api/deploy/attestations/00000000-0000-4000-8000-000000000000', 'viewer')).status).toBe(404)
    expect((await fetch(`${base}/api/deploy/scans/${scan}`)).status).toBe(401)
  })
})
