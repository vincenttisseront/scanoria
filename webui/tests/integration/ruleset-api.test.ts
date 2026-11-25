// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Jeux de règles gérés (G4, 0.7 chantier A) contre un vrai PostgreSQL 16 :
// rôles, création et import (rappel des conditions Semgrep), contrôles
// statiques, versions, écart, retour arrière (nouvelle version), archivage,
// rattachement aux profils (dernière ou épinglée, un seul jeu gitleaks),
// validation déposée au helper (contenu dans jobs/rulesets/<sha256>), audit,
// et résolution des versions pour le plan figé.

import { mkdir, mkdtemp, readFile, readdir, rm, stat, writeFile } from 'node:fs/promises'
import { createServer, type Server } from 'node:http'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { createApp, createRouter, defineEventHandler, getHeader, toNodeListener } from 'h3'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { DATABASE_URL, createTestDatabase, type TestDatabase } from '../helpers/db'
import { loadConfig, setConfig } from '../../server/utils/config'
import { closePool } from '../../server/utils/db'
import { createUser } from '../../server/utils/users'
import type { Role } from '#shared/schemas'
import listGet from '../../server/api/rulesets/index.get'
import createPost from '../../server/api/rulesets/index.post'
import builtinGet from '../../server/api/rulesets/builtin.get'
import validatePost from '../../server/api/rulesets/validate.post'
import oneGet from '../../server/api/rulesets/[id]/index.get'
import onePatch from '../../server/api/rulesets/[id]/index.patch'
import versionPost from '../../server/api/rulesets/[id]/versions/index.post'
import versionGet from '../../server/api/rulesets/[id]/versions/[version].get'
import rollbackPost from '../../server/api/rulesets/[id]/rollback.post'
import profilesPut from '../../server/api/rulesets/[id]/profiles.put'
import { addRulesetVersion, createRuleset, profileRulesets, sha256Hex } from '../../server/rulesets/store'
import { stageRulesets } from '../../server/rulesets/files'

const RULES_V1 = 'rules:\n  - id: interne-eval\n    pattern: eval(...)\n    message: eval\n    languages: [python]\n    severity: ERROR\n'
const RULES_V2 = `${RULES_V1}  - id: interne-exec\n    pattern: exec(...)\n    message: exec\n    languages: [python]\n    severity: WARNING\n`

describe.skipIf(!DATABASE_URL)('API des jeux de règles (PostgreSQL réel)', () => {
  let db: TestDatabase
  let root: string
  let server: Server
  let base: string
  const users: Record<Role, number> = { viewer: 0, operator: 0, admin: 0 }
  let profileId = ''
  let otherProfileId = ''

  async function call(path: string, role: Role, init: { method?: string, json?: unknown } = {}) {
    const res = await fetch(`${base}${path}`, {
      method: init.method ?? 'GET',
      headers: { 'x-test-role': role, ...(init.json === undefined ? {} : { 'content-type': 'application/json' }) },
      body: init.json === undefined ? undefined : JSON.stringify(init.json),
    })
    // eslint-disable-next-line @typescript-eslint/no-explicit-any -- réponses JSON lues librement par les assertions
    const json = await res.json().catch(() => ({})) as Record<string, any>
    // Erreur h3 : code, issues et reason sont dans « data ».
    return { status: res.status, data: res.ok ? json : { ...json, ...(json.data ?? {}) } }
  }
  const audit = async (action: string) => (await db.pool.query('SELECT details FROM audit_log WHERE action = $1 ORDER BY id', [action])).rows

  beforeAll(async () => {
    db = await createTestDatabase()
    root = await mkdtemp(join(tmpdir(), 'scanoria-rulesets-'))
    for (const d of ['requests/incoming', 'requests/tmp', 'scans/jobs/tmp', 'scans/jobs/rulesets']) await mkdir(join(root, d), { recursive: true })
    await writeFile(join(root, 'base.yaml'), RULES_V1)
    process.env.SCANORIA_SCANS_DIR = join(root, 'scans')
    process.env.SCANORIA_BUILTIN_RULES = join(root, 'base.yaml')
    setConfig(loadConfig({ NUXT_DATABASE_URL: db.url, NUXT_REQUESTS_DIR: join(root, 'requests'), NUXT_STATE_FILE: join(root, 'state.json') }))
    for (const role of ['viewer', 'operator', 'admin'] as const) {
      users[role] = Number((await createUser(db.pool, { username: role, role, password: `${role}-long-password` })).id)
    }
    profileId = (await db.pool.query<{ id: string }>(`SELECT id FROM profiles WHERE slug = 'complet'`)).rows[0]!.id
    otherProfileId = (await db.pool.query<{ id: string }>(`SELECT id FROM profiles WHERE slug = 'rapide'`)).rows[0]!.id
    const app = createApp()
    app.use(defineEventHandler((event) => {
      const role = getHeader(event, 'x-test-role') as Role | undefined
      if (role) event.context.auth = { user: { id: users[role], username: role, displayName: null, role, locale: 'fr', mustChangePassword: false }, tokenHash: 'x', csrf: 'x' }
    }))
    const router = createRouter()
    router.get('/api/rulesets', listGet)
    router.post('/api/rulesets', createPost)
    router.get('/api/rulesets/builtin', builtinGet)
    router.post('/api/rulesets/validate', validatePost)
    router.get('/api/rulesets/:id', oneGet)
    router.patch('/api/rulesets/:id', onePatch)
    router.post('/api/rulesets/:id/versions', versionPost)
    router.get('/api/rulesets/:id/versions/:version', versionGet)
    router.post('/api/rulesets/:id/rollback', rollbackPost)
    router.put('/api/rulesets/:id/profiles', profilesPut)
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
    delete process.env.SCANORIA_SCANS_DIR
    delete process.env.SCANORIA_BUILTIN_RULES
  })

  it('ruleset-api : création réservée à l’administrateur, slug réservé, contenu contrôlé', async () => {
    const body = { slug: 'interne', engine: 'opengrep', name: 'Règles internes', content: RULES_V1 }
    expect((await call('/api/rulesets', 'operator', { method: 'POST', json: body })).status).toBe(403)
    expect((await call('/api/rulesets', 'admin', { method: 'POST', json: { ...body, slug: 'scanoria-base' } })).status).toBe(400)
    expect((await call('/api/rulesets', 'admin', { method: 'POST', json: { ...body, slug: 'vide', content: 'foo: 1\n' } })).data.issues)
      .toEqual([{ path: 'content', code: 'missing-rules-key' }])
    const r = await call('/api/rulesets', 'admin', { method: 'POST', json: body })
    expect(r.status).toBe(201)
    expect(r.data).toMatchObject({ version: 1, sha256: sha256Hex(RULES_V1) })
    expect((await call('/api/rulesets', 'admin', { method: 'POST', json: body })).status).toBe(409)
    const list = await call('/api/rulesets', 'viewer')
    expect(list.data.items).toEqual([expect.objectContaining({ slug: 'interne', latest_version: 1, latest_origin: 'manual', profiles: 0 })])
    expect(await audit('ruleset.create')).toHaveLength(1)
  })

  it('ruleset-api : import Semgrep refusé sans reconnaissance des conditions, tracée sinon', async () => {
    const body = { slug: 'semgrep-officiel', engine: 'semgrep', name: 'Semgrep', content: RULES_V1, origin: 'import' }
    const no = await call('/api/rulesets', 'admin', { method: 'POST', json: body })
    expect(no.status).toBe(400)
    expect(no.data.issues).toEqual([{ path: 'license_ack', code: 'required' }])
    expect((await call('/api/rulesets', 'admin', { method: 'POST', json: { ...body, license_ack: true } })).status).toBe(201)
    expect(await audit('ruleset.license-ack')).toEqual([{ details: expect.objectContaining({ slug: 'semgrep-officiel', license: 'Semgrep Rules License' }) }])
  })

  it('ruleset-api : versions, écart, retour arrière en nouvelle version', async () => {
    const id = (await call('/api/rulesets', 'viewer')).data.items.find((x: { slug: string }) => x.slug === 'interne').id
    expect((await call(`/api/rulesets/${id}/versions`, 'admin', { method: 'POST', json: { content: RULES_V1 } })).status).toBe(409)
    const v2 = await call(`/api/rulesets/${id}/versions`, 'admin', { method: 'POST', json: { content: RULES_V2, comment: 'exec' } })
    expect(v2.data.version).toBe(2)
    const d = await call(`/api/rulesets/${id}/versions/2?diff=1`, 'viewer')
    expect(d.data.diff.filter((l: { op: string }) => l.op === '+').map((l: { text: string }) => l.text)).toContain('  - id: interne-exec')
    expect(d.data.diff.some((l: { op: string }) => l.op === '-')).toBe(false)
    expect((await call(`/api/rulesets/${id}/versions/9`, 'viewer')).status).toBe(404)
    const rb = await call(`/api/rulesets/${id}/rollback`, 'admin', { method: 'POST', json: { version: 1 } })
    expect(rb.data).toEqual({ version: 3, sha256: sha256Hex(RULES_V1) })
    const one = await call(`/api/rulesets/${id}`, 'viewer')
    expect(one.data.versions.map((v: { version: number }) => v.version)).toEqual([3, 2, 1])
    expect(one.data.versions[0].comment).toBe('Retour à la version 1')
    expect(await audit('ruleset.rollback')).toEqual([{ details: expect.objectContaining({ version: 3, restored_from: 1 }) }])
  })

  it('ruleset-api : profils (dernière ou épinglée), plan résolu, archivage', async () => {
    const id = (await call('/api/rulesets', 'viewer')).data.items.find((x: { slug: string }) => x.slug === 'interne').id
    expect((await call(`/api/rulesets/${id}/profiles`, 'admin', { method: 'PUT', json: { profiles: [{ profile_id: profileId, pinned_version: 9 }] } })).status).toBe(400)
    const put = await call(`/api/rulesets/${id}/profiles`, 'admin', { method: 'PUT', json: { profiles: [
      { profile_id: profileId, pinned_version: null }, { profile_id: otherProfileId, pinned_version: 2 }] } })
    expect(put.status).toBe(200)
    expect(await profileRulesets(db.pool, profileId)).toEqual([expect.objectContaining({ slug: 'interne', version: 3, sha256: sha256Hex(RULES_V1) })])
    expect(await profileRulesets(db.pool, otherProfileId)).toEqual([expect.objectContaining({ version: 2, sha256: sha256Hex(RULES_V2) })])
    // Contenus déposés pour le runner, empreinte revérifiée ; version inconnue signalée.
    const bad = await stageRulesets(db.pool, join(root, 'scans'), [{ rulesets: [
      { slug: 'interne', version: 2, sha256: sha256Hex(RULES_V2) }, { slug: 'interne', version: 7, sha256: 'f'.repeat(64) }] }])
    expect(bad).toEqual(['interne@7'])
    const file = join(root, 'scans', 'jobs', 'rulesets', sha256Hex(RULES_V2))
    expect(await readFile(file, 'utf8')).toBe(RULES_V2)
    expect((await stat(file)).mode & 0o777).toBe(0o600)
    // Archivage refusé tant que des profils montent le jeu.
    expect((await call(`/api/rulesets/${id}`, 'admin', { method: 'PATCH', json: { archived: true } })).status).toBe(409)
    await call(`/api/rulesets/${id}/profiles`, 'admin', { method: 'PUT', json: { profiles: [] } })
    expect((await call(`/api/rulesets/${id}`, 'admin', { method: 'PATCH', json: { archived: true } })).status).toBe(200)
    expect((await call('/api/rulesets', 'viewer')).data.items.some((x: { slug: string }) => x.slug === 'interne')).toBe(false)
    expect((await call('/api/rulesets?archived=1', 'viewer')).data.items.some((x: { slug: string }) => x.slug === 'interne')).toBe(true)
    expect((await call(`/api/rulesets/${id}/versions`, 'admin', { method: 'POST', json: { content: RULES_V2 } })).status).toBe(409)
    expect((await call(`/api/rulesets/${id}`, 'admin', { method: 'PATCH', json: { archived: false } })).status).toBe(200)
  })

  it('ruleset-api : un seul jeu gitleaks par profil', async () => {
    const toml = '[extend]\nuseDefault = true\n\n[[rules]]\nid = "interne"\nregex = \'\'\'interne_[a-z0-9]{32}\'\'\'\n'
    const a = await createRuleset(db.pool, { slug: 'gl-a', engine: 'gitleaks', name: 'A', userId: users.admin })
    const b = await createRuleset(db.pool, { slug: 'gl-b', engine: 'gitleaks', name: 'B', userId: users.admin })
    await addRulesetVersion(db.pool, { rulesetId: a.id, content: toml, origin: 'manual', userId: users.admin })
    await addRulesetVersion(db.pool, { rulesetId: b.id, content: `${toml}# b\n`, origin: 'manual', userId: users.admin })
    expect((await call(`/api/rulesets/${a.id}/profiles`, 'admin', { method: 'PUT', json: { profiles: [{ profile_id: profileId, pinned_version: null }] } })).status).toBe(200)
    expect((await call(`/api/rulesets/${b.id}/profiles`, 'admin', { method: 'PUT', json: { profiles: [{ profile_id: profileId, pinned_version: null }] } })).status).toBe(409)
    // [extend] qui inclut un fichier : refusé avant même le moteur.
    await expect(addRulesetVersion(db.pool, { rulesetId: a.id, content: '[extend]\npath = "/etc/passwd"\n', origin: 'manual', userId: users.admin }))
      .rejects.toMatchObject({ code: 'E_VALIDATION', issues: ['gitleaks-extend-include'] })
  })

  it('ruleset-api : validation déposée au helper, contenu rangé par empreinte', async () => {
    const body = { engine: 'opengrep', content: RULES_V2, samples: [{ name: 'app.py', content: 'eval(x)\n' }] }
    expect((await call('/api/rulesets/validate', 'operator', { method: 'POST', json: body })).status).toBe(403)
    expect((await call('/api/rulesets/validate', 'admin', { method: 'POST', json: { ...body, samples: [{ name: '../x', content: '' }] } })).status).toBe(400)
    expect((await call('/api/rulesets/validate', 'admin', { method: 'POST', json: { ...body, content: 'x: 1\n' } })).status).toBe(400)
    const r = await call('/api/rulesets/validate', 'admin', { method: 'POST', json: body })
    expect(r.status).toBe(202)
    const files = await readdir(join(root, 'requests', 'incoming'))
    expect(files).toHaveLength(1)
    const req = JSON.parse(await readFile(join(root, 'requests', 'incoming', files[0]!), 'utf8'))
    expect(req).toMatchObject({ type: 'validate-ruleset', params: { engine: 'opengrep', sha256: sha256Hex(RULES_V2), samples: body.samples } })
    expect(await readFile(join(root, 'scans', 'jobs', 'rulesets', sha256Hex(RULES_V2)), 'utf8')).toBe(RULES_V2)
  })

  it('ruleset-api : règles maison en lecture seule', async () => {
    const r = await call('/api/rulesets/builtin', 'viewer')
    expect(r.data.items).toEqual([expect.objectContaining({ slug: 'scanoria-base', engine: 'opengrep', license: 'AGPL-3.0-or-later', rules: 1 })])
  })
})
