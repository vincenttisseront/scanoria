// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Routes de l'intégration CI (0.8, chantier C) contre PostgreSQL : rôles
// exigés, validation des entrées, confirmation littérale de la décision de
// protection, 404 et 409, audit, modèles CI (liste fermée, rendu pour un
// projet), case « chaîne autonome » (J16) et liaisons OIDC (J4).

import { randomBytes } from 'node:crypto'
import { mkdtemp, rm } from 'node:fs/promises'
import { createServer, type Server } from 'node:http'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { createApp, createRouter, defineEventHandler, getHeader, toNodeListener } from 'h3'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { DATABASE_URL, createTestDatabase, type TestDatabase } from '../helpers/db'
import { loadConfig, setConfig } from '../../server/utils/config'
import { closePool } from '../../server/utils/db'
import { encryptSecret } from '../../server/utils/secrets'
import { createUser } from '../../server/utils/users'
import { createProject } from '../../server/projects/service'
import { setConsoleUrl } from '../../server/forges/context'
import type { Role } from '#shared/schemas'
import issuersGet from '../../server/api/ci/issuers.get'
import issuersPost from '../../server/api/ci/issuers.post'
import issuerPatch from '../../server/api/ci/issuers/[id].patch'
import templatesGet from '../../server/api/ci/templates.get'
import ciGet from '../../server/api/projects/[id]/ci/index.get'
import prPost from '../../server/api/projects/[id]/ci/pr.post'
import protectionPost from '../../server/api/projects/[id]/ci/protection.post'
import protectionRequestPost from '../../server/api/projects/[id]/ci/protection-request.post'
import settingsPatch from '../../server/api/projects/[id]/ci/settings.patch'
import bindingsPost from '../../server/api/projects/[id]/ci/bindings.post'
import bindingPatch from '../../server/api/projects/[id]/ci/bindings/[binding].patch'
import bindingDelete from '../../server/api/projects/[id]/ci/bindings/[binding].delete'

const FORGE = 'https://forge.exemple.test'
const TEMPLATES = resolve(__dirname, '../../../src/rootfs/usr/share/scanoria/ci-templates')

describe.skipIf(!DATABASE_URL)('routes de l’intégration CI (PostgreSQL)', () => {
  let db: TestDatabase
  let dir: string
  let server: Server
  let base: string
  let projectId: string
  let looseId: string
  const users: Partial<Record<Role, number>> = {}

  async function call(role: Role | null, method: string, path: string, json?: unknown) {
    const res = await fetch(`${base}${path}`, {
      method,
      headers: { ...(role ? { 'x-test-role': role } : {}), 'content-type': 'application/json' },
      ...(json !== undefined ? { body: JSON.stringify(json) } : {}),
    })
    const text = await res.text()
    let data: Record<string, unknown>
    try {
      data = JSON.parse(text) as Record<string, unknown>
    }
    catch {
      data = { text }
    }
    return { status: res.status, data, headers: res.headers }
  }
  const code = (r: { data: Record<string, unknown> }) => (r.data.data as { code?: string } | undefined)?.code ?? (r.data as { code?: string }).code
  const audits = async (action: string) => (await db.pool.query<{ details: Record<string, unknown> }>(
    'SELECT details FROM audit_log WHERE action = $1 ORDER BY id', [action])).rows

  beforeAll(async () => {
    db = await createTestDatabase()
    dir = await mkdtemp(join(tmpdir(), 'scanoria-ci-routes-'))
    process.env.NUXT_SECRET_KEY_FILE = join(dir, 'secret.key')
    process.env.NUXT_CI_TEMPLATES_DIR = TEMPLATES
    setConfig(loadConfig({
      NUXT_DATABASE_URL: db.url,
      NUXT_UPLOADS_DIR: join(dir, 'uploads'),
      NUXT_CATALOG_INDEX_FILE: join(dir, 'absent-index.json'),
      NUXT_MODULES_STATE_FILE: join(dir, 'absent-state.json'),
    }))
    setConsoleUrl('https://analyse.exemple.test')
    for (const role of ['viewer', 'operator', 'admin'] as const) {
      users[role] = Number((await createUser(db.pool, { username: role, role, password: `${role}-long-password` })).id)
    }
    const cred = await encryptSecret(db.pool, { kind: 'token', value: randomBytes(20).toString('hex'), username: 'scanoria-bot', createdBy: null })
    const forgeId = (await db.pool.query<{ id: string }>(
      `INSERT INTO forges (kind, name, base_url, credential_id, discovery) VALUES ('forgejo', 'Forge', $1, $2, false) RETURNING id::text`, [FORGE, cred])).rows[0]!.id
    projectId = (await createProject(db.pool, { name: 'equipe/app', sourceKind: 'git', forgeId, repoFullName: 'equipe/app', repoUrl: `${FORGE}/equipe/app.git`, defaultBranch: 'main' })).id
    looseId = (await createProject(db.pool, { name: 'libre', sourceKind: 'git', repoUrl: `${FORGE}/equipe/libre.git`, defaultBranch: 'main' })).id

    const app = createApp()
    app.use(defineEventHandler((event) => {
      const role = getHeader(event, 'x-test-role') as Role | undefined
      if (role) event.context.auth = { user: { id: users[role]!, username: role, displayName: null, role, locale: 'fr', mustChangePassword: false }, tokenHash: 'x', csrf: 'x' }
    }))
    const router = createRouter()
    router.get('/api/ci/issuers', issuersGet)
    router.post('/api/ci/issuers', issuersPost)
    router.patch('/api/ci/issuers/:id', issuerPatch)
    router.get('/api/ci/templates', templatesGet)
    router.get('/api/projects/:id/ci', ciGet)
    router.post('/api/projects/:id/ci/pr', prPost)
    router.post('/api/projects/:id/ci/protection', protectionPost)
    router.post('/api/projects/:id/ci/protection-request', protectionRequestPost)
    router.patch('/api/projects/:id/ci/settings', settingsPatch)
    router.post('/api/projects/:id/ci/bindings', bindingsPost)
    router.patch('/api/projects/:id/ci/bindings/:binding', bindingPatch)
    router.delete('/api/projects/:id/ci/bindings/:binding', bindingDelete)
    app.use(router)
    server = createServer(toNodeListener(app))
    await new Promise<void>(r => server.listen(0, '127.0.0.1', r))
    const addr = server.address()
    base = `http://127.0.0.1:${typeof addr === 'object' && addr ? addr.port : 0}`
  })

  afterAll(async () => {
    delete process.env.NUXT_CI_TEMPLATES_DIR
    setConsoleUrl(undefined)
    await new Promise<void>(r => server?.close(() => r()))
    await closePool()
    await db?.drop()
    await rm(dir, { recursive: true, force: true })
  })

  it('émetteurs : administrateur seulement, validation, doublon refusé, activation tracée', async () => {
    expect((await call(null, 'GET', '/api/ci/issuers')).status).toBe(401)
    expect((await call('operator', 'GET', '/api/ci/issuers')).status).toBe(403)
    expect((await call('operator', 'POST', '/api/ci/issuers', { kind: 'forgejo', issuer: `${FORGE}/api/actions` })).status).toBe(403)
    // Schéma : HTTPS seulement, champs inconnus refusés.
    expect((await call('admin', 'POST', '/api/ci/issuers', { kind: 'forgejo', issuer: 'ftp://forge.exemple.test' })).status).toBe(400)
    expect((await call('admin', 'POST', '/api/ci/issuers', { kind: 'forgejo', issuer: `${FORGE}/api/actions`, jwks: {} })).status).toBe(400)
    const created = await call('admin', 'POST', '/api/ci/issuers', { kind: 'forgejo', issuer: `${FORGE}/api/actions` })
    expect(created.status).toBe(201)
    const dup = await call('admin', 'POST', '/api/ci/issuers', { kind: 'forgejo', issuer: `${FORGE}/api/actions` })
    expect(dup.status).toBe(409)
    expect(code(dup)).toBe('E_EXISTS')
    const list = await call('admin', 'GET', '/api/ci/issuers')
    const issuers = list.data.issuers as { id: string, enabled: boolean, audience: string }[]
    expect(issuers).toHaveLength(1)
    expect(issuers[0]!.audience).toBe('scanoria')
    expect(list.data.refusals).toBeTypeOf('object')
    const id = issuers[0]!.id
    expect((await call('admin', 'PATCH', `/api/ci/issuers/${id}`, { enabled: false })).status).toBe(200)
    expect((await call('admin', 'PATCH', '/api/ci/issuers/00000000-0000-4000-8000-000000000001', { enabled: true })).status).toBe(404)
    expect((await call('admin', 'PATCH', `/api/ci/issuers/${id}`, { enabled: 'oui' })).status).toBe(400)
    expect((await call('admin', 'PATCH', `/api/ci/issuers/${id}`, { enabled: true })).status).toBe(200)
    expect((await audits('ci.oidc-issuer-create')).length).toBe(1)
  })

  it('liaisons OIDC : création, motifs validés, modification, suppression, auditées', async () => {
    const issuerId = ((await call('admin', 'GET', '/api/ci/issuers')).data.issuers as { id: string }[])[0]!.id
    expect((await call('operator', 'POST', `/api/projects/${projectId}/ci/bindings`, { issuer_id: issuerId, repository: 'equipe/app' })).status).toBe(403)
    expect((await call('admin', 'POST', `/api/projects/${projectId}/ci/bindings`, { issuer_id: issuerId, repository: '../etc' })).status).toBe(400)
    expect((await call('admin', 'POST', `/api/projects/${projectId}/ci/bindings`, { issuer_id: issuerId, repository: 'equipe/app', ref_patterns: ['refs/*/main'] })).status).toBe(400)
    const b = await call('admin', 'POST', `/api/projects/${projectId}/ci/bindings`, { issuer_id: issuerId, repository: 'equipe/app-ci', ref_patterns: ['refs/heads/main'] })
    expect(b.status).toBe(201)
    const bindingId = b.data.id as string
    expect((await call('admin', 'PATCH', `/api/projects/${projectId}/ci/bindings/${bindingId}`, { ref_patterns: ['refs/tags/*'] })).status).toBe(200)
    // Liaison d'un autre projet : introuvable par ce chemin.
    expect((await call('admin', 'PATCH', `/api/projects/${looseId}/ci/bindings/${bindingId}`, { ref_patterns: ['refs/tags/*'] })).status).toBe(404)
    const state = await call('viewer', 'GET', `/api/projects/${projectId}/ci`)
    const bindings = state.data.bindings as { id: string, ref_patterns: string[] }[]
    expect(bindings.find(x => x.id === bindingId)?.ref_patterns).toEqual(['refs/tags/*'])
    // Les émetteurs ne sont listés qu'à l'administrateur.
    expect(state.data.issuers).toEqual([])
    expect(((await call('admin', 'GET', `/api/projects/${projectId}/ci`)).data.issuers as unknown[]).length).toBe(1)
    // Épingle de l'identifiant du dépôt : réinitialisée par un administrateur, auditée.
    await db.pool.query(`UPDATE oidc_bindings SET repository_id = '77' WHERE id = $1`, [bindingId])
    expect((await call('admin', 'PATCH', `/api/projects/${projectId}/ci/bindings/${bindingId}`, {})).status).toBe(400)
    expect((await call('operator', 'PATCH', `/api/projects/${projectId}/ci/bindings/${bindingId}`, { reset_repository_id: true })).status).toBe(403)
    const reset = await call('admin', 'PATCH', `/api/projects/${projectId}/ci/bindings/${bindingId}`, { reset_repository_id: true })
    expect(reset.status).toBe(200)
    expect(reset.data.repository_id).toBeNull()
    expect((await audits('ci.oidc-binding-reset-pin'))[0]!.details).toMatchObject({ previous_repository_id: '77' })
    expect((await call('admin', 'DELETE', `/api/projects/${projectId}/ci/bindings/${bindingId}`)).status).toBe(204)
    expect((await call('admin', 'DELETE', `/api/projects/${projectId}/ci/bindings/${bindingId}`)).status).toBe(404)
    for (const a of ['ci.oidc-binding-create', 'ci.oidc-binding-update', 'ci.oidc-binding-delete']) expect((await audits(a)).length).toBe(1)
  })

  it('état CI du projet : lecture pour tous les rôles, 404 sinon', async () => {
    expect((await call(null, 'GET', `/api/projects/${projectId}/ci`)).status).toBe(401)
    const r = await call('viewer', 'GET', `/api/projects/${projectId}/ci`)
    expect(r.status).toBe(200)
    expect(r.data).toMatchObject({ release_mode: 'pull', autonomous_chain: false, repository: 'equipe/app', default_branch: 'main', console_url: 'https://analyse.exemple.test' })
    expect(r.data.contexts).toEqual({ pr: 'scanoria/rapide', release_gate: 'scanoria/release-gate' })
    expect((await call('viewer', 'GET', '/api/projects/00000000-0000-4000-8000-000000000002/ci')).status).toBe(404)
    expect((await call('viewer', 'GET', '/api/projects/pas-un-uuid/ci')).status).toBe(404)
  })

  it('PR d’intégration : opérateur, projet sans forge non concerné', async () => {
    expect((await call('viewer', 'POST', `/api/projects/${projectId}/ci/pr`)).status).toBe(403)
    expect((await call('operator', 'POST', `/api/projects/${looseId}/ci/pr`)).status).toBe(404)
    // Projet de forge sans détection : réponse explicite, aucune PR.
    const r = await call('operator', 'POST', `/api/projects/${projectId}/ci/pr`)
    expect(r.status).toBe(200)
    expect(r.data.outcome).toBe('pending-detection')
  })

  it('protection : proposée par un opérateur, décidée par un administrateur avec confirmation littérale', async () => {
    expect((await call('viewer', 'POST', `/api/projects/${projectId}/ci/protection-request`)).status).toBe(403)
    expect((await call('operator', 'POST', `/api/projects/${looseId}/ci/protection-request`)).status).toBe(404)
    const req = await call('operator', 'POST', `/api/projects/${projectId}/ci/protection-request`)
    expect(req.status).toBe(200)
    const requestId = req.data.request_id as string
    const decision = { request_id: requestId, action: 'decline' }
    expect((await call('operator', 'POST', `/api/projects/${projectId}/ci/protection`, { ...decision, confirm: true })).status).toBe(403)
    expect((await call('admin', 'POST', `/api/projects/${projectId}/ci/protection`, decision)).status).toBe(400)
    expect((await call('admin', 'POST', `/api/projects/${projectId}/ci/protection`, { ...decision, confirm: 'true' })).status).toBe(400)
    expect((await call('admin', 'POST', `/api/projects/${projectId}/ci/protection`, { ...decision, request_id: '00000000-0000-4000-8000-000000000003', confirm: true })).status).toBe(404)
    const done = await call('admin', 'POST', `/api/projects/${projectId}/ci/protection`, { ...decision, confirm: true })
    expect(done.status).toBe(200)
    expect(done.data).toMatchObject({ state: 'declined', decided_by_username: 'admin' })
    const again = await call('admin', 'POST', `/api/projects/${projectId}/ci/protection`, { ...decision, confirm: true })
    expect(again.status).toBe(409)
    expect(code(again)).toBe('E_INTEGRATION_STATE')
    expect((await audits('integration.protection-decline')).length).toBe(1)
  })

  it('chaîne autonome (J16) : administrateur, tracée seulement quand elle change', async () => {
    expect((await call('operator', 'PATCH', `/api/projects/${projectId}/ci/settings`, { autonomous_chain: true })).status).toBe(403)
    expect((await call('admin', 'PATCH', `/api/projects/${projectId}/ci/settings`, { autonomous_chain: 'oui' })).status).toBe(400)
    expect((await call('admin', 'PATCH', `/api/projects/${projectId}/ci/settings`, { autonomous_chain: true })).status).toBe(200)
    expect((await call('admin', 'PATCH', `/api/projects/${projectId}/ci/settings`, { autonomous_chain: true })).status).toBe(200)
    expect((await call('viewer', 'GET', `/api/projects/${projectId}/ci`)).data.autonomous_chain).toBe(true)
    expect((await audits('project.autonomous-chain')).length).toBe(1)
  })

  it('modèles CI : liste fermée, fichier téléchargé, workflow rendu pour le projet', async () => {
    expect((await call(null, 'GET', '/api/ci/templates')).status).toBe(401)
    const list = await call('viewer', 'GET', '/api/ci/templates')
    expect((list.data.templates as { file: string }[]).map(t => t.file)).toContain('github/scanoria.yml')
    expect((await call('viewer', 'GET', '/api/ci/templates?file=../../etc/passwd')).status).toBeGreaterThanOrEqual(400)
    expect((await call('viewer', 'GET', '/api/ci/templates?file=autre.yml')).status).toBeGreaterThanOrEqual(400)
    const raw = await call('viewer', 'GET', '/api/ci/templates?file=github/scanoria.yml')
    expect(raw.status).toBe(200)
    expect(raw.headers.get('content-disposition')).toContain('scanoria.yml')
    expect(raw.data.text).toContain('analyse.exemple.test')
    const rendered = await call('viewer', 'GET', `/api/ci/templates?file=forgejo/scanoria.yml&project=${projectId}`)
    expect(rendered.status).toBe(200)
    expect(rendered.data.text).toContain(projectId)
    // Projet en mode tiré : le workflow attend le statut de release, sans déclencheur de PR.
    expect(rendered.data.text).toContain('SCANORIA_MODE: pull')
    expect(rendered.data.text).not.toContain('pull_request')
    expect((await call('viewer', 'GET', '/api/ci/templates?file=github/scanoria.yml&project=00000000-0000-4000-8000-000000000004')).status).toBe(404)
  })
})
