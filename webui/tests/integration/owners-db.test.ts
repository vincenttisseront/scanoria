// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Chantier B (0.7) : responsables CODEOWNERS (F6) contre un vrai PostgreSQL 16.
// Lecture du fichier déposé par le runner (lien symbolique, lien dur, taille
// refusés), remplissage de findings.owners, correspondances éditables par un
// administrateur, filtres « responsable » et « Mes résultats ».

import { randomBytes } from 'node:crypto'
import { link, mkdir, mkdtemp, rm, symlink, writeFile } from 'node:fs/promises'
import { createServer, type Server } from 'node:http'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { createApp, createRouter, defineEventHandler, getHeader, toNodeListener } from 'h3'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { DATABASE_URL, createTestDatabase, type TestDatabase } from '../helpers/db'
import { loadConfig, setConfig } from '../../server/utils/config'
import { closePool } from '../../server/utils/db'
import { createUser } from '../../server/utils/users'
import { assignOwners, CODEOWNERS_FILE, ownerAliases, readCodeowners } from '../../server/findings/owners'
import { MAX_CODEOWNERS_BYTES, parseCodeowners } from '../../server/findings/codeowners'
import { listFindings } from '../../server/findings/triage'
import type { Role } from '#shared/schemas'

import listRoute from '../../server/api/owner-mappings/index.get'
import addRoute from '../../server/api/owner-mappings/index.post'
import removeRoute from '../../server/api/owner-mappings/index.delete'
import findingsRoute from '../../server/api/findings/index.get'

describe.skipIf(!DATABASE_URL)('responsables CODEOWNERS (F6, PostgreSQL réel)', () => {
  let db: TestDatabase
  let root: string
  let server: Server
  let base: string
  let projectId: string
  let otherId: string
  const users: Record<Role, number> = { viewer: 0, operator: 0, admin: 0 }
  const ids: Record<string, string> = {}

  async function call(path: string, role: Role | null, init: { method?: string, json?: unknown } = {}) {
    const headers: Record<string, string> = {}
    if (role) headers['x-test-role'] = role
    if (init.json !== undefined) headers['content-type'] = 'application/json'
    const res = await fetch(`${base}${path}`, { method: init.method ?? 'GET', headers, body: init.json === undefined ? undefined : JSON.stringify(init.json) })
    const text = await res.text()
    let data: Record<string, unknown> = {}
    try {
      data = JSON.parse(text)
    }
    catch {
      // corps vide
    }
    return { status: res.status, data }
  }

  async function finding(project: string, path: string | null): Promise<string> {
    const r = await db.pool.query<{ id: string }>(
      `INSERT INTO findings (project_id, fingerprint, tool, rule_id, category, severity, title, path)
       VALUES ($1, $2, 'trivy', 'R', 'sca', 'high', 't', $3) RETURNING id`,
      [project, randomBytes(32).toString('hex'), path],
    )
    return r.rows[0]!.id
  }

  beforeAll(async () => {
    db = await createTestDatabase()
    root = await mkdtemp(join(tmpdir(), 'scanoria-owners-'))
    setConfig(loadConfig({ NUXT_DATABASE_URL: db.url }))
    for (const role of ['viewer', 'operator', 'admin'] as const) {
      users[role] = Number((await createUser(db.pool, { username: role, role, email: `${role}@exemple.test`, password: `${role}-long-password` })).id)
    }
    const mk = async (slug: string) => (await db.pool.query<{ id: string }>(
      `INSERT INTO projects (slug, name, source_kind, profile_id, gate_id)
       VALUES ($1, $1, 'archive', (SELECT id FROM profiles WHERE slug = 'rapide'), (SELECT id FROM gates WHERE slug = 'defaut')) RETURNING id`, [slug],
    )).rows[0]!.id
    projectId = await mk('prop')
    otherId = await mk('autre')
    ids.front = await finding(projectId, 'web/app.js')
    ids.infra = await finding(projectId, 'infra/main.tf')
    ids.none = await finding(projectId, null)
    ids.other = await finding(otherId, 'web/app.js')

    const app = createApp()
    app.use(defineEventHandler((event) => {
      const role = getHeader(event, 'x-test-role') as Role | undefined
      if (role) event.context.auth = { user: { id: users[role], username: role, displayName: null, role, locale: 'fr', mustChangePassword: false }, tokenHash: 'x', csrf: 'x' }
    }))
    const router = createRouter()
    router.get('/api/owner-mappings', listRoute)
    router.post('/api/owner-mappings', addRoute)
    router.delete('/api/owner-mappings', removeRoute)
    router.get('/api/findings', findingsRoute)
    app.use(router)
    server = createServer(toNodeListener(app))
    await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve))
    const addr = server.address()
    base = `http://127.0.0.1:${typeof addr === 'object' && addr ? addr.port : 0}`
  })

  afterAll(async () => {
    if (server) await new Promise(resolve => server.close(resolve))
    await closePool()
    await db?.drop()
    if (root) await rm(root, { recursive: true, force: true })
  })

  it('lecture du fichier déposé : ordinaire seulement, sans lien, borné', async () => {
    const ok = join(root, 'ok')
    await mkdir(ok)
    await writeFile(join(ok, CODEOWNERS_FILE), '*.js @front\n/infra/ @org/infra operator@exemple.test\n')
    expect((await readCodeowners(ok))!.rules).toHaveLength(2)
    expect(await readCodeowners(join(root, 'absent'))).toBeNull()

    const sym = join(root, 'sym')
    await mkdir(sym)
    await symlink(join(ok, CODEOWNERS_FILE), join(sym, CODEOWNERS_FILE))
    expect(await readCodeowners(sym)).toBeNull()

    const hard = join(root, 'hard')
    await mkdir(hard)
    await link(join(ok, CODEOWNERS_FILE), join(hard, CODEOWNERS_FILE))
    expect(await readCodeowners(hard)).toBeNull()
    expect(await readCodeowners(ok)).toBeNull() // le fichier d'origine a maintenant deux liens
    await rm(join(hard, CODEOWNERS_FILE))

    const big = join(root, 'big')
    await mkdir(big)
    await writeFile(join(big, CODEOWNERS_FILE), `* @x\n${'#'.repeat(MAX_CODEOWNERS_BYTES)}`)
    expect(await readCodeowners(big)).toBeNull()

    const dir = join(root, 'dir')
    await mkdir(join(dir, CODEOWNERS_FILE), { recursive: true })
    expect(await readCodeowners(dir)).toBeNull()
  })

  it('ingestion : findings.owners rempli selon le chemin, vidé sans fichier', async () => {
    const parsed = parseCodeowners('*.js @front\n/infra/ @org/infra operator@exemple.test\n')
    expect(await assignOwners(db.pool, projectId, [ids.front!, ids.infra!, ids.none!], parsed)).toBe(2)
    const row = async (id: string) => (await db.pool.query<{ owners: string[] }>('SELECT owners FROM findings WHERE id = $1', [id])).rows[0]!.owners
    expect(await row(ids.front!)).toEqual(['@front'])
    expect(await row(ids.infra!)).toEqual(['@org/infra', 'operator@exemple.test'])
    expect(await row(ids.none!)).toEqual([])
    // Un résultat d'un autre projet n'est jamais touché.
    expect(await assignOwners(db.pool, projectId, [ids.other!], parsed)).toBe(0)
    expect(await assignOwners(db.pool, projectId, [ids.front!, ids.infra!], parsed)).toBe(0)
    expect(await assignOwners(db.pool, projectId, [], parsed)).toBe(0)
    await assignOwners(db.pool, otherId, [ids.other!], parsed)
  })

  it('« Mes résultats » : adresse directe, puis correspondance de projet ou globale', async () => {
    expect(await ownerAliases(db.pool, users.operator)).toEqual(['@operator', 'operator@exemple.test'])
    expect(await ownerAliases(db.pool, 999999)).toEqual([])
    const mine = async (role: Role) => (await listFindings(db.pool, { limit: 50, offset: 0, mine: { userId: users[role], aliases: await ownerAliases(db.pool, users[role]) } })).items.map(i => i.id).sort()
    expect(await mine('operator')).toEqual([ids.infra])
    expect(await mine('viewer')).toEqual([])
    await db.pool.query('INSERT INTO owner_mappings (project_id, owner, user_id) VALUES ($1, $2, $3)', [projectId, '@FRONT', users.viewer])
    expect(await mine('viewer')).toEqual([ids.front])
    await db.pool.query('INSERT INTO owner_mappings (project_id, owner, user_id) VALUES (NULL, $1, $2)', ['@front', users.viewer])
    expect(await mine('viewer')).toEqual([ids.front, ids.other].sort())
    await db.pool.query('DELETE FROM owner_mappings')
    const byOwner = await listFindings(db.pool, { limit: 50, offset: 0, owner: '@Org/Infra' })
    expect(byOwner.items.map(i => i.id)).toEqual([ids.infra])
    expect(byOwner.items[0]!.owners).toEqual(['@org/infra', 'operator@exemple.test'])
  })

  it('API : correspondances par un administrateur, auditées ; « mine » toujours le compte connecté', async () => {
    const body = { project_id: projectId, owner: '@front', user_id: users.viewer }
    expect((await call('/api/owner-mappings', 'operator', { method: 'POST', json: body })).status).toBe(403)
    expect((await call('/api/owner-mappings', 'admin', { method: 'POST', json: { ...body, owner: 'a b' } })).status).toBe(400)
    expect((await call('/api/owner-mappings', 'admin', { method: 'POST', json: { ...body, user_id: 999999 } })).status).toBe(404)
    expect((await call('/api/owner-mappings', 'admin', { method: 'POST', json: { ...body, project_id: crypto.randomUUID() } })).status).toBe(404)
    expect((await call('/api/owner-mappings', 'admin', { method: 'POST', json: body })).status).toBe(201)
    expect((await call('/api/owner-mappings', 'admin', { method: 'POST', json: body })).data).toEqual({ added: false })
    expect((await call('/api/owner-mappings', 'admin', { method: 'POST', json: { ...body, project_id: null } })).status).toBe(201)
    const list = await call(`/api/owner-mappings?project_id=${projectId}`, 'viewer')
    expect(list.data.items).toHaveLength(2)
    expect(list.data.items).toEqual(expect.arrayContaining([
      expect.objectContaining({ project_slug: null, owner: '@front', username: 'viewer' }),
      expect.objectContaining({ project_slug: 'prop', owner: '@front', username: 'viewer' }),
    ]))
    expect((await db.pool.query(`SELECT 1 FROM audit_log WHERE action = 'owner-mapping.add'`)).rowCount).toBe(2)
    const mine = await call('/api/findings?mine=true', 'viewer')
    expect((mine.data.items as { id: string }[]).map(i => i.id).sort()).toEqual([ids.front, ids.other].sort())
    expect((await call('/api/findings?mine=true', 'admin')).data.total).toBe(0)
    expect((await call('/api/owner-mappings', 'operator', { method: 'DELETE', json: body })).status).toBe(403)
    expect((await call('/api/owner-mappings', 'admin', { method: 'DELETE', json: body })).data).toEqual({ removed: true })
    expect((await call('/api/owner-mappings', 'admin', { method: 'DELETE', json: body })).status).toBe(404)
    expect((await db.pool.query(`SELECT 1 FROM audit_log WHERE action = 'owner-mapping.remove'`)).rowCount).toBe(1)
  })
})
