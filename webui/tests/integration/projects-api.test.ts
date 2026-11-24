// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// API des forges et des projets (chantier A) servie par h3 dans le processus,
// contre PostgreSQL et un faux Forgejo : rôles, ajout par forge, par URL et
// par archive, demandes hostiles, archivage, suppression confirmée, audit
// sans aucun secret.

import { readdirSync } from 'node:fs'
import { mkdir, mkdtemp, readFile, readdir, rm, stat, writeFile } from 'node:fs/promises'
import { createServer, type Server } from 'node:http'
import { tmpdir } from 'node:os'
import { join, relative, sep } from 'node:path'
import { fileURLToPath } from 'node:url'
import { createApp, createRouter, toNodeListener, type EventHandler } from 'h3'
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest'
import { DATABASE_URL, MIGRATIONS_DIR, createTestDatabase, type TestDatabase } from '../helpers/db'
import { fakeSha, newFakeForge, startFakeForges, type FakeForge, type FakeForgeServer } from '../helpers/fake-forge'
import { hashPassword } from '../../server/utils/password'
import { loadConfig, setConfig } from '../../server/utils/config'
import { closePool } from '../../server/utils/db'
import { waitReady } from '../../server/utils/runtime'
import { createUser } from '../../server/utils/users'
import { setKeyscan } from '../../server/projects/ssh'

const API_DIR = fileURLToPath(new URL('../../server/api', import.meta.url))
const STARTUP_PLUGIN = fileURLToPath(new URL('../../server/plugins/startup.ts', import.meta.url))
const ADMIN_PASSWORD = 'projects-admin-password'
const FORGE = 'forge.exemple.test'
const KEY_B64 = Buffer.from('cle-hote-de-test').toString('base64')
// Clé SSH factice construite à l'exécution (aucun motif de clé réelle dans le dépôt).
const FAKE_SSH_KEY = ['-----BEGIN OPENSSH', 'PRIVATE KEY-----'].join(' ') + '\nZmF1c3NlLWNsZS1kZS10ZXN0LXNhbnMtdmFsZXVy\n'

function apiRoutes(): { method: string, path: string, file: string }[] {
  const out: { method: string, path: string, file: string }[] = []
  const walk = (dir: string) => {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const full = join(dir, entry.name)
      if (entry.isDirectory()) {
        walk(full)
        continue
      }
      const m = /^(.+)\.(get|post|put|patch|delete)\.ts$/.exec(entry.name)
      if (!m) continue
      const segments = relative(API_DIR, dir).split(sep).filter(Boolean)
      if (m[1] !== 'index') segments.push(m[1]!)
      out.push({ method: m[2]!, path: `/api/${segments.map(s => s.replace(/^\[(.+)\]$/, ':$1')).join('/')}`.replace(/\/$/, ''), file: full })
    }
  }
  walk(API_DIR)
  // Routes statiques avant les routes à paramètre (comme Nitro).
  return out.sort((a, b) => Number(a.path.includes(':')) - Number(b.path.includes(':')))
}

interface Client {
  cookie: string
  csrf: string
}
type Res = { status: number, data: Record<string, unknown> & { data?: { code?: string } } }

describe.skipIf(!DATABASE_URL)('API des forges et des projets', () => {
  let db: TestDatabase
  let root: string
  let server: Server
  let base: string
  let closeHook: (() => Promise<void>) | undefined
  let fake: FakeForgeServer
  let forgejo: FakeForge
  let admin: Client
  let operator: Client
  let viewer: Client
  let ip = 10

  async function call(path: string, init: { method?: string, client?: Client, json?: unknown, body?: Buffer, headers?: Record<string, string> } = {}): Promise<Res> {
    const headers = new Headers(init.headers)
    if (init.client) {
      headers.set('cookie', init.client.cookie)
      if (init.method && init.method !== 'GET') headers.set('x-csrf-token', init.client.csrf)
    }
    headers.set('x-real-ip', `192.0.2.${ip++ % 200}`)
    let body: BodyInit | undefined = init.body ? new Uint8Array(init.body) : undefined
    if (init.json !== undefined) {
      headers.set('content-type', 'application/json')
      body = JSON.stringify(init.json)
    }
    const res = await fetch(`${base}${path}`, { method: init.method ?? 'GET', headers, body })
    const text = await res.text()
    let data: unknown = text
    try {
      data = JSON.parse(text)
    }
    catch {
      // texte brut
    }
    return { status: res.status, data: data as Res['data'] }
  }
  const code = (r: Res) => r.data.data?.code

  async function login(username: string, password: string): Promise<Client> {
    const res = await fetch(`${base}/api/auth/login`, {
      method: 'POST', headers: { 'content-type': 'application/json', 'x-real-ip': `198.51.100.${ip++ % 200}` },
      body: JSON.stringify({ username, password }),
    })
    const data = await res.json() as { csrf: string }
    return { cookie: (res.headers.get('set-cookie') ?? '').split(';')[0]!, csrf: data.csrf }
  }
  async function newUser(username: string, role: 'viewer' | 'operator'): Promise<Client> {
    await createUser(db.pool, { username, role, password: `${username}-long-password`, mustChangePassword: false })
    return login(username, `${username}-long-password`)
  }

  beforeAll(async () => {
    db = await createTestDatabase({ migrate: false })
    root = await mkdtemp(join(tmpdir(), 'scanoria-projects-api-'))
    for (const d of ['requests/tmp', 'requests/incoming', 'uploads', 'bootstrap', 'public']) await mkdir(join(root, d), { recursive: true, mode: 0o700 })
    await writeFile(join(root, 'bootstrap', 'admin.json'), JSON.stringify({ username: 'admin', password_hash: await hashPassword(ADMIN_PASSWORD) }), { mode: 0o600 })
    process.env.NUXT_SECRET_KEY_FILE = join(root, 'console', 'secret.key')
    setConfig(loadConfig({
      NUXT_DATABASE_URL: db.url,
      NUXT_REQUESTS_DIR: join(root, 'requests'),
      NUXT_UPLOADS_DIR: join(root, 'uploads'),
      NUXT_BOOTSTRAP_DIR: join(root, 'bootstrap'),
      NUXT_PUBLIC_FILES_DIR: join(root, 'public'),
      NUXT_STATE_FILE: join(root, 'state.json'),
      NUXT_VERSION_FILE: join(root, 'VERSION'),
      NUXT_CATALOG_INDEX_FILE: join(root, 'catalog-index.json'),
      NUXT_MODULES_STATE_FILE: join(root, 'modules-state.json'),
      NUXT_DNS_STATUS_FILE: join(root, 'dns-status.json'),
      NUXT_INGEST_INTERVAL_MS: '60000',
    }))
    vi.stubGlobal('defineNitroPlugin', (fn: unknown) => fn)
    vi.stubGlobal('useRuntimeConfig', () => ({ buildVersion: '0.3.0', buildSourceRepo: 'exemple/scanoria' }))
    vi.stubGlobal('useStorage', () => ({
      getKeys: async () => (await readdir(MIGRATIONS_DIR)).map(n => `assets:migrations:${n}`),
      getItemRaw: async (key: string) => readFile(join(MIGRATIONS_DIR, key.split(':').pop()!)),
    }))
    const plugin = (await import(STARTUP_PLUGIN)).default as unknown as (app: unknown) => void
    plugin({
      hooks: {
        hook: (_n: string, fn: () => Promise<void>) => {
          closeHook = fn
        },
      },
    })
    expect(await waitReady(30_000)).toBe(true)

    const app = createApp()
    app.use((await import('../../server/middleware/auth')).default)
    const router = createRouter()
    for (const r of apiRoutes()) router[r.method as 'get'](r.path, (await import(r.file)).default as EventHandler)
    app.use(router)
    server = createServer(toNodeListener(app))
    await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve))
    const addr = server.address()
    base = `http://127.0.0.1:${typeof addr === 'object' && addr ? addr.port : 0}`

    forgejo = newFakeForge('forgejo', FORGE, [
      { full_name: 'equipe/api', default_branch: 'main', files: { 'pyproject.toml': '', 'uv.lock': '', 'app/main.py': '', 'LICENSE': 'SPDX-License-Identifier: Apache-2.0' } },
      { full_name: 'equipe/web', default_branch: 'main', files: { 'package.json': '{}', 'index.js': '' } },
    ])
    fake = await startFakeForges([forgejo, newFakeForge('github', 'github.com', [{ full_name: 'libre/outil', default_branch: 'main', files: { 'main.go': '' } }])])
    setKeyscan(async (host, port) => `${port === 22 ? host : `[${host}]:${port}`} ssh-ed25519 ${KEY_B64}\n`)

    admin = await login('admin', ADMIN_PASSWORD)
    operator = await newUser('ops', 'operator')
    viewer = await newUser('lecteur', 'viewer')
  })

  afterAll(async () => {
    setKeyscan()
    await fake?.close()
    await new Promise(resolve => server?.close(resolve))
    if (closeHook) await closeHook()
    else await closePool()
    vi.unstubAllGlobals()
    delete process.env.NUXT_SECRET_KEY_FILE
    await db?.drop()
    if (root) await rm(root, { recursive: true, force: true })
  })

  let forgeId: string
  let apiProject: Record<string, unknown>

  it('forges : rôles, ajout vérifié, jamais le jeton en réponse', async () => {
    const body = { kind: 'forgejo', name: 'Forge', base_url: `https://${FORGE}`, token: forgejo.token, discovery: false }
    expect((await call('/api/forges', { method: 'POST', client: operator, json: body })).status).toBe(403)
    expect((await call('/api/forges')).status).toBe(401)
    const bad = await call('/api/forges', { method: 'POST', client: admin, json: { ...body, base_url: 'file:///etc' } })
    expect([bad.status, code(bad)]).toEqual([400, 'E_FORGE_URL'])
    const extra = await call('/api/forges', { method: 'POST', client: admin, json: { ...body, secret: 1 } })
    expect(extra.status).toBe(400)
    const created = await call('/api/forges', { method: 'POST', client: admin, json: body })
    expect(created.status).toBe(201)
    expect(JSON.stringify(created.data)).not.toContain(forgejo.token)
    forgeId = (created.data.forge as { id: string }).id
    expect(created.data).toMatchObject({ login: 'robot', discovery_started: false })
    const list = await call('/api/forges', { client: viewer })
    expect((list.data.items as unknown[]).length).toBe(1)
    expect(JSON.stringify(list.data)).not.toContain(forgejo.token)
    const repos = await call(`/api/forges/${forgeId}/repos`, { client: operator })
    expect((repos.data.items as { full_name: string, project_id: null }[]).map(r => r.full_name)).toEqual(['equipe/api', 'equipe/web'])
    expect((await call(`/api/forges/${forgeId}/repos`, { client: viewer })).status).toBe(403)
    expect((await call('/api/forges/pas-un-uuid', { client: viewer })).status).toBe(404)
  })

  it('aperçu F1 puis ajout depuis la forge ; doublon refusé', async () => {
    const preview = await call('/api/projects/preview', { method: 'POST', client: operator, json: { forge_id: forgeId, repo: 'equipe/api' } })
    expect(preview.status).toBe(200)
    expect(preview.data).toMatchObject({ branches: ['main'], detection: { languages: ['python'], license: { spdx: 'Apache-2.0' } } })
    expect((await call('/api/projects/preview', { method: 'POST', client: viewer, json: { forge_id: forgeId, repo: 'equipe/api' } })).status).toBe(403)
    const created = await call('/api/projects', { method: 'POST', client: operator, json: { source: 'forge', forge_id: forgeId, repo: 'equipe/api' } })
    expect(created.status).toBe(201)
    apiProject = created.data.project as Record<string, unknown>
    expect(apiProject).toMatchObject({
      slug: 'equipe-api', schedule: 'on-commit', profile_slug: 'complet', gate_slug: 'defaut', spdx_license: 'Apache-2.0',
      has_credential: true, credential_hint: `…${forgejo.token.slice(-4)}`,
    })
    expect(apiProject).not.toHaveProperty('credential_id')
    const dup = await call('/api/projects', { method: 'POST', client: operator, json: { source: 'forge', forge_id: forgeId, repo: 'equipe/api' } })
    expect([dup.status, code(dup)]).toEqual([409, 'E_PROJECT_EXISTS'])
    const missing = await call('/api/projects', { method: 'POST', client: operator, json: { source: 'forge', forge_id: forgeId, repo: 'equipe/absent' } })
    expect([missing.status, code(missing)]).toEqual([422, 'E_FORGE_NOT_FOUND'])
    const detail = await call(`/api/projects/${apiProject.id}`, { client: viewer })
    expect(detail.data).toMatchObject({ project: { id: apiProject.id }, schedule: { poll_interval_s: 300 } })
    expect((detail.data.choices as { profiles: { slug: string }[] }).profiles.map(p => p.slug)).toContain('rapide')
    expect((await call(`/api/projects/${apiProject.id}/branches`, { client: viewer })).data).toEqual({ live: true, items: ['main'] })
    const redetect = await call(`/api/projects/${apiProject.id}/detect`, { method: 'POST', client: operator })
    expect(redetect.data).toMatchObject({ project: { detection: { languages: ['python'] } } })
  })

  it('URL libre : HTTPS + jeton, dépôt public de github.com, SSH avec clés d’hôte confirmées', async () => {
    const https = await call('/api/projects', {
      method: 'POST', client: operator,
      json: { source: 'git', url: 'https://git.exemple.test/equipe/interne.git', auth: { kind: 'token', token: forgejo.token, username: 'robot' } },
    })
    expect(https.status).toBe(201)
    expect(https.data.project).toMatchObject({ schedule: 'daily', credential_kind: 'token', default_branch: 'main', detection: { error: 'E_NO_FORGE_ACCESS' } })
    const gh = await call('/api/projects', { method: 'POST', client: operator, json: { source: 'git', url: 'https://github.com/libre/outil' } })
    expect(gh.data.project).toMatchObject({ schedule: 'on-commit', repo_full_name: 'libre/outil', has_credential: false, detection: { languages: ['go'] } })

    const keys = await call('/api/projects/ssh-hostkeys', { method: 'POST', client: operator, json: { url: 'ssh://git@git.exemple.test:2222/equipe/ssh.git' } })
    expect(keys.status).toBe(200)
    expect(keys.data.host).toBe('[git.exemple.test]:2222')
    expect((keys.data.keys as { fingerprint: string }[])[0]!.fingerprint).toMatch(/^SHA256:/)
    const noHosts = await call('/api/projects', {
      method: 'POST', client: operator, json: { source: 'git', url: 'ssh://git@git.exemple.test:2222/equipe/ssh.git' },
    })
    expect([noHosts.status, code(noHosts)]).toEqual([400, 'E_KNOWN_HOSTS'])
    const wrongHost = await call('/api/projects', {
      method: 'POST', client: operator,
      json: { source: 'git', url: 'ssh://git@git.exemple.test:2222/equipe/ssh.git', auth: { kind: 'ssh-key', private_key: FAKE_SSH_KEY, known_hosts: `autre.exemple.test ssh-ed25519 ${KEY_B64}` } },
    })
    expect(code(wrongHost)).toBe('E_KNOWN_HOSTS')
    const ssh = await call('/api/projects', {
      method: 'POST', client: operator,
      json: { source: 'git', url: 'ssh://git@git.exemple.test:2222/equipe/ssh.git', auth: { kind: 'ssh-key', private_key: FAKE_SSH_KEY, known_hosts: keys.data.known_hosts } },
    })
    expect(ssh.status).toBe(201)
    expect(ssh.data.project).toMatchObject({ credential_kind: 'ssh-key', ssh_known_hosts: keys.data.known_hosts, schedule: 'daily' })
    expect(JSON.stringify(ssh.data)).not.toContain('ZmF1c3Nl')

    // Nouvelle clé SSH et clés d'hôte reconfirmées : même secret, valeur remplacée.
    const sshId = (ssh.data.project as { id: string }).id
    const rotated = await call(`/api/projects/${sshId}`, {
      method: 'PATCH', client: operator, json: { ssh: { private_key: FAKE_SSH_KEY.replace('ZmF1', 'QXV0'), known_hosts: keys.data.known_hosts } },
    })
    expect(rotated.status).toBe(200)
    const badHosts = await call(`/api/projects/${sshId}`, { method: 'PATCH', client: operator, json: { ssh: { known_hosts: 'x y z' } } })
    expect(code(badHosts)).toBe('E_KNOWN_HOSTS')
    const tokenOnSsh = await call(`/api/projects/${sshId}`, { method: 'PATCH', client: operator, json: { token: 'jeton-de-test' } })
    expect(code(tokenOnSsh)).toBe('E_GIT_URL')
    // Jeton d'un dépôt HTTPS : remplacé puis retiré (le secret disparaît).
    const httpsId = (https.data.project as { id: string }).id
    expect((await call(`/api/projects/${httpsId}`, { method: 'PATCH', client: operator, json: { token: 'autre-jeton-de-test' } })).status).toBe(200)
    const none = await call(`/api/projects/${httpsId}`, { method: 'PATCH', client: operator, json: { token: null } })
    expect(none.data.project).toMatchObject({ has_credential: false })
    const sshOnHttps = await call(`/api/projects/${httpsId}`, { method: 'PATCH', client: operator, json: { ssh: { known_hosts: 'x' } } })
    expect(code(sshOnHttps)).toBe('E_GIT_URL')
    const uploadOnGit = await call(`/api/projects/${httpsId}`, { method: 'PATCH', client: operator, json: { upload_id: '00000000-0000-4000-8000-000000000000' } })
    expect(code(uploadOnGit)).toBe('E_UPLOAD_MISSING')
    expect((await call(`/api/projects/${httpsId}/branches`, { client: viewer })).data).toEqual({ live: false, items: ['main'] })
    const ghPreview = await call('/api/projects/preview', { method: 'POST', client: operator, json: { url: 'https://github.com/libre/outil' } })
    expect(ghPreview.data).toMatchObject({ detection: { languages: ['go'] } })
    const otherPreview = await call('/api/projects/preview', { method: 'POST', client: operator, json: { url: 'https://git.exemple.test/a/b' } })
    expect(code(otherPreview)).toBe('E_NO_FORGE_ACCESS')
    const httpsKeys = await call('/api/projects/ssh-hostkeys', { method: 'POST', client: operator, json: { url: 'https://git.exemple.test/a/b' } })
    expect(code(httpsKeys)).toBe('E_GIT_URL')
  })

  it.each([
    'file:///srv/depot', 'ext::sh -c id', 'https://jeton@git.exemple.test/a/b', 'https://127.0.0.1/a/b', 'git://git.exemple.test/a/b',
    'git@git.exemple.test:-oProxyCommand=id',
  ])('URL hostile refusée : %s', async (url) => {
    const r = await call('/api/projects', { method: 'POST', client: operator, json: { source: 'git', url } })
    expect([r.status, code(r)]).toEqual([400, 'E_GIT_URL'])
  })

  it('branche « --upload-pack » refusée à la validation', async () => {
    const r = await call('/api/projects', {
      method: 'POST', client: operator, json: { source: 'git', url: 'https://git.exemple.test/a/b', tracked_branches: ['--upload-pack=id'] },
    })
    expect(r.status).toBe(400)
    const patch = await call(`/api/projects/${apiProject.id}`, { method: 'PATCH', client: operator, json: { tracked_branches: ['a..b'] } })
    expect(patch.status).toBe(400)
  })

  it('archive : en-tête vérifié, fichier source.<format> 0600, projet créé, nouvelle archive', async () => {
    const zip = Buffer.concat([Buffer.from([0x50, 0x4b, 0x03, 0x04]), Buffer.alloc(100)])
    const up = await call('/api/projects/uploads', { method: 'PUT', client: operator, body: zip, headers: { 'content-type': 'application/octet-stream' } })
    expect(up.status).toBe(201)
    const uploadId = up.data.upload_id as string
    const files = await readdir(join(root, 'uploads', uploadId))
    expect(files).toEqual(['source.zip'])
    expect((await stat(join(root, 'uploads', uploadId, 'source.zip'))).mode & 0o777).toBe(0o600)
    const script = await call('/api/projects/uploads', { method: 'PUT', client: operator, body: Buffer.from('#!/bin/sh\nid\n') })
    expect([script.status, code(script)]).toEqual([415, 'E_ARCHIVE_FORMAT'])
    const big = await call('/api/projects/uploads', { method: 'PUT', client: operator, body: Buffer.alloc(10), headers: { 'content-length': String(600 * 1024 * 1024) } }).catch(() => null)
    if (big) expect(big.status).toBe(413)
    expect((await call('/api/projects/uploads', { method: 'PUT', client: viewer, body: zip })).status).toBe(403)

    const missing = await call('/api/projects', { method: 'POST', client: operator, json: { source: 'archive', upload_id: '00000000-0000-4000-8000-000000000000', name: 'Archive' } })
    expect(code(missing)).toBe('E_UPLOAD_MISSING')
    const created = await call('/api/projects', { method: 'POST', client: operator, json: { source: 'archive', upload_id: uploadId, name: 'Livraison fournisseur' } })
    expect(created.status).toBe(201)
    expect(created.data.project).toMatchObject({ source_kind: 'archive', upload_id: uploadId, schedule: 'daily', slug: 'livraison-fournisseur' })
    const again = await call('/api/projects', { method: 'POST', client: operator, json: { source: 'archive', upload_id: uploadId, name: 'Doublon' } })
    expect(code(again)).toBe('E_UPLOAD_MISSING')

    const tgz = Buffer.from([0x1f, 0x8b, 8, 0, 0, 0, 0, 0])
    const up2 = await call('/api/projects/uploads', { method: 'PUT', client: operator, body: tgz })
    const id = (created.data.project as { id: string }).id
    const patched = await call(`/api/projects/${id}`, { method: 'PATCH', client: operator, json: { upload_id: up2.data.upload_id } })
    expect(patched.data.project).toMatchObject({ upload_id: up2.data.upload_id })
    await expect(stat(join(root, 'uploads', uploadId))).rejects.toThrow()
    // L'archive d'un autre projet ne peut pas être reprise (ni donc effacée).
    const up3 = await call('/api/projects/uploads', { method: 'PUT', client: operator, body: tgz })
    const other = await call('/api/projects', { method: 'POST', client: operator, json: { source: 'archive', upload_id: up3.data.upload_id, name: 'Autre livraison' } })
    const steal = await call(`/api/projects/${(other.data.project as { id: string }).id}`, { method: 'PATCH', client: operator, json: { upload_id: up2.data.upload_id } })
    expect([steal.status, code(steal)]).toEqual([422, 'E_UPLOAD_MISSING'])
    expect((await stat(join(root, 'uploads', up2.data.upload_id as string))).isDirectory()).toBe(true)
  })

  it('modification, archivage, suppression confirmée (admin), audit sans secret', async () => {
    const id = apiProject.id as string
    const profiles = (await call(`/api/projects/${id}`, { client: viewer })).data.choices as { profiles: { id: string, slug: string }[] }
    const rapide = profiles.profiles.find(p => p.slug === 'rapide')!
    expect((await call(`/api/projects/${id}`, { method: 'PATCH', client: viewer, json: { schedule: 'daily' } })).status).toBe(403)
    const patched = await call(`/api/projects/${id}`, { method: 'PATCH', client: operator, json: { schedule: 'daily', profile_id: rapide.id, ai_opt_out: true, name: 'API' } })
    expect(patched.data.project).toMatchObject({ schedule: 'daily', profile_slug: 'rapide', ai_opt_out: true, name: 'API' })
    // Le quality gate ne change que par un admin.
    const gates = ((await call(`/api/projects/${id}`, { client: viewer })).data.choices as { gates: { id: string }[] }).gates
    const otherGate = gates.find(g => g.id !== apiProject.gate_id)
    if (otherGate) {
      expect((await call(`/api/projects/${id}`, { method: 'PATCH', client: operator, json: { gate_id: otherGate.id } })).status).toBe(403)
      expect((await call(`/api/projects/${id}`, { method: 'PATCH', client: admin, json: { gate_id: otherGate.id } })).status).toBe(200)
      expect((await call(`/api/projects/${id}`, { method: 'PATCH', client: admin, json: { gate_id: apiProject.gate_id } })).status).toBe(200)
    }
    expect((await call(`/api/projects/${id}`, { method: 'PATCH', client: operator, json: { gate_id: apiProject.gate_id } })).status).toBe(200)
    const badProfile = await call(`/api/projects/${id}`, { method: 'PATCH', client: operator, json: { profile_id: '00000000-0000-4000-8000-000000000000' } })
    expect(badProfile.status).toBe(400)
    // Le jeton partagé avec la forge n'est pas modifié depuis un projet : un secret propre est créé.
    const token = await call(`/api/projects/${id}`, { method: 'PATCH', client: operator, json: { token: forgejo.token.split('').reverse().join('') } })
    expect(token.status).toBe(200)
    const forgeView = await call(`/api/forges/${forgeId}`, { client: viewer })
    expect((forgeView.data.forge as { token_hint: string }).token_hint).toBe(`…${forgejo.token.slice(-4)}`)

    const archived = await call(`/api/projects/${id}/archive`, { method: 'POST', client: operator, json: { archived: true } })
    expect((archived.data.project as { archived_at: string }).archived_at).toMatch(/Z$/)
    expect((await call('/api/projects', { client: viewer })).data.items).not.toContainEqual(expect.objectContaining({ id }))
    expect((await call('/api/projects?archived=1', { client: viewer })).data.items).toContainEqual(expect.objectContaining({ id }))
    expect(code(await call(`/api/projects/${id}`, { method: 'PATCH', client: operator, json: { name: 'x' } }))).toBe('E_ARCHIVED')

    const inUse = await call(`/api/forges/${forgeId}`, { method: 'DELETE', client: admin })
    expect([inUse.status, code(inUse)]).toEqual([409, 'E_FORGE_IN_USE'])
    expect((await call(`/api/projects/${id}`, { method: 'DELETE', client: operator, json: { confirm: 'equipe-api' } })).status).toBe(403)
    const wrong = await call(`/api/projects/${id}`, { method: 'DELETE', client: admin, json: { confirm: 'autre' } })
    expect([wrong.status, code(wrong)]).toEqual([400, 'E_CONFIRM'])
    // Découverte active : le dépôt reviendrait, la suppression est refusée.
    await call(`/api/forges/${forgeId}`, { method: 'PATCH', client: admin, json: { discovery: true } })
    const discovered = await call(`/api/projects/${id}`, { method: 'DELETE', client: admin, json: { confirm: 'equipe-api' } })
    expect([discovered.status, code(discovered)]).toEqual([409, 'E_PROJECT_DISCOVERED'])
    await call(`/api/forges/${forgeId}`, { method: 'PATCH', client: admin, json: { discovery: false } })
    const deleted = await call(`/api/projects/${id}`, { method: 'DELETE', client: admin, json: { confirm: 'equipe-api' } })
    expect(deleted.status).toBe(200)
    expect((await call(`/api/projects/${id}`, { client: viewer })).status).toBe(404)

    const audit = await db.pool.query<{ action: string, details: unknown }>(`SELECT action, details FROM audit_log WHERE action LIKE 'project.%' OR action LIKE 'forge.%'`)
    const actions = audit.rows.map(r => r.action)
    for (const a of ['forge.create', 'project.create', 'project.update', 'project.archive', 'project.delete', 'project.detect']) expect(actions).toContain(a)
    const dump = JSON.stringify(audit.rows)
    expect(dump).not.toContain(forgejo.token)
    expect(dump).not.toContain(forgejo.token.split('').reverse().join(''))
    expect(dump).not.toContain('ZmF1c3Nl')
  })

  it('forge : jeton remplacé (vérifié), retiré, découverte manuelle, suppression', async () => {
    const wrong = await call(`/api/forges/${forgeId}`, { method: 'PATCH', client: admin, json: { token: 'scn_faux' } })
    expect([wrong.status, code(wrong)]).toEqual([422, 'E_FORGE_AUTH'])
    const discover = await call(`/api/forges/${forgeId}/discover`, { method: 'POST', client: operator })
    expect(discover.data).toMatchObject({ repos: 2, error: null })
    // equipe/api a été supprimé : il est redécouvert, comme equipe/web.
    expect((discover.data.created as string[]).length).toBe(2)
    const removed = await call(`/api/forges/${forgeId}`, { method: 'PATCH', client: admin, json: { token: null, discovery: false, name: 'Forge interne' } })
    expect(removed.data.forge).toMatchObject({ has_token: false, discovery: false, name: 'Forge interne' })
    expect(code(await call(`/api/forges/${forgeId}/discover`, { method: 'POST', client: operator }))).toBe('E_NO_FORGE_ACCESS')
    await db.pool.query('DELETE FROM projects WHERE forge_id = $1', [forgeId])
    expect((await call(`/api/forges/${forgeId}`, { method: 'DELETE', client: admin })).status).toBe(200)
    const left = await db.pool.query<{ n: string }>('SELECT count(*) AS n FROM credentials WHERE kind = \'token\' AND id NOT IN (SELECT credential_id FROM projects WHERE credential_id IS NOT NULL)')
    expect(Number(left.rows[0]!.n)).toBe(0)
    expect(fakeSha()).toMatch(/^[0-9a-f]{40}$/)
  })
})
