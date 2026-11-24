// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Quality gates et API de la CI (chantier E) contre un vrai PostgreSQL 16 :
// evaluateGate sur des données en base, gates (CRUD, audit, verrous H4/G13),
// jetons d'API (création, liste, révocation, expiration, mauvais projet,
// portée, débit), dépôt d'une analyse, verdict, badge, client scanoria-scan.
// enqueueScan (contrat 4, chantier C) est remplacé par un bouchon de test.

import { execFile } from 'node:child_process'
import { randomBytes, randomUUID } from 'node:crypto'
import { readdirSync } from 'node:fs'
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises'
import { createServer, type Server } from 'node:http'
import { tmpdir } from 'node:os'
import { join, relative, sep } from 'node:path'
import { fileURLToPath } from 'node:url'
import { promisify } from 'node:util'
import { createApp, createRouter, toNodeListener, type EventHandler } from 'h3'
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest'
import { DATABASE_URL, createTestDatabase, type TestDatabase } from '../helpers/db'
import { loadConfig, setConfig } from '../../server/utils/config'
import { closePool } from '../../server/utils/db'
import { startConsole, stopConsole, waitReady } from '../../server/utils/runtime'
import { createUser } from '../../server/utils/users'
import { evaluateGate, ScanNotFoundError } from '../../server/gates/evaluate'
import { badTokenLimiter, publicLimiter, tokenLimiter } from '../../server/middleware/api-token'
import { VerdictDetails } from '#shared/analysis'
import { clearConnectorCache } from '../../server/ai/enqueue'

const enqueued = vi.hoisted(() => ({ calls: [] as Record<string, unknown>[], fail: '' as string }))
vi.mock('../../server/scans/enqueue', async () => {
  const { getPool } = await import('../../server/utils/db')
  return {
    enqueueScan: async (_db: unknown, p: Record<string, unknown>) => {
      enqueued.calls.push(p)
      if (enqueued.fail) throw Object.assign(new Error('refusée'), { code: enqueued.fail })
      const pool = getPool()
      const res = await pool.query<{ id: string, number: number }>(
        `INSERT INTO scans (project_id, number, trigger, priority, ref, profile_id, gate_id, api_token_id, requested_by)
         SELECT p.id, COALESCE((SELECT max(number) FROM scans WHERE project_id = p.id), 0) + 1, $2, 70, $3,
                p.profile_id, p.gate_id, $4, $5
           FROM projects p WHERE p.id = $1
         RETURNING id, number`,
        [p.projectId, p.trigger, p.ref, p.apiTokenId ?? null, p.requestedBy ?? null],
      )
      return { scanId: res.rows[0]!.id, number: res.rows[0]!.number }
    },
  }
})

const API_DIR = fileURLToPath(new URL('../../server/api', import.meta.url))
const CLIENT = fileURLToPath(new URL('../../../src/rootfs/usr/share/scanoria/client/scanoria-scan', import.meta.url))
const run = promisify(execFile)

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
  // Routes statiques avant les routes à paramètre (comme le routeur de Nitro).
  return out.sort((a, b) => a.path.split(':').length - b.path.split(':').length)
}

// Réponses JSON lues en profondeur dans les assertions.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Json = Record<string, any>

interface Client {
  cookie: string
  csrf: string
}

describe.skipIf(!DATABASE_URL)('quality gates et API de la CI (PostgreSQL réel)', () => {
  let db: TestDatabase
  let root: string
  let server: Server
  let base: string
  let admin: Client
  let operator: Client
  let viewer: Client
  let gateId: string
  let profileId: string
  let projectA: string
  let projectB: string
  let ipCounter = 10

  const nextIp = () => `198.51.100.${ipCounter++}`

  async function call(path: string, init: RequestInit & { client?: Client, json?: unknown, ip?: string, bearer?: string } = {}) {
    const headers = new Headers(init.headers)
    if (init.client) {
      headers.set('cookie', init.client.cookie)
      if (init.method && init.method !== 'GET') headers.set('x-csrf-token', init.client.csrf)
    }
    if (init.bearer) headers.set('authorization', `Bearer ${init.bearer}`)
    headers.set('x-real-ip', init.ip ?? '192.0.2.10')
    let body = init.body
    if (init.json !== undefined) {
      headers.set('content-type', 'application/json')
      body = JSON.stringify(init.json)
    }
    const res = await fetch(`${base}${path}`, { ...init, headers, body })
    const text = await res.text()
    let data: unknown = text
    try {
      data = JSON.parse(text)
    }
    catch {
      // texte brut (SVG, script)
    }
    return { status: res.status, headers: res.headers, text, data: data as Json }
  }
  const code = (res: { data: Json }) => res.data?.data?.code

  async function login(username: string, role: 'viewer' | 'operator' | 'admin'): Promise<Client> {
    const password = `${username}-long-password`
    await createUser(db.pool, { username, role, password, mustChangePassword: false })
    const res = await call('/api/auth/login', { method: 'POST', json: { username, password }, ip: nextIp() })
    expect(res.status).toBe(200)
    return { cookie: (res.headers.get('set-cookie') ?? '').split(';')[0]!, csrf: String(res.data.csrf) }
  }

  async function newProject(slug: string, extra: Record<string, unknown> = {}): Promise<string> {
    const res = await db.pool.query<{ id: string }>(
      `INSERT INTO projects (slug, name, source_kind, profile_id, gate_id, default_branch, archived_at)
       VALUES ($1, $2, 'archive', $3, $4, 'main', $5) RETURNING id`,
      [slug, `Projet ${slug}`, profileId, gateId, extra.archived ? new Date() : null],
    )
    return res.rows[0]!.id
  }

  async function newToken(projectId: string, client = operator, body: Record<string, unknown> = { name: 'ci' }) {
    const res = await call(`/api/projects/${projectId}/tokens`, { method: 'POST', client, json: body })
    expect(res.status, JSON.stringify(res.data)).toBe(201)
    return res.data as { id: string, value: string, prefix: string }
  }

  async function newScan(projectId: string, p: { status?: string, verdict?: string | null, details?: unknown, ref?: string } = {}): Promise<string> {
    const res = await db.pool.query<{ id: string }>(
      `INSERT INTO scans (project_id, number, trigger, priority, ref, profile_id, gate_id, status, verdict, verdict_details, finished_at)
       VALUES ($1, COALESCE((SELECT max(number) FROM scans WHERE project_id = $1), 0) + 1, 'manual', 50, $2, $3, $4, $5, $6, $7,
               CASE WHEN $5 = 'done' THEN now() END)
       RETURNING id`,
      [projectId, p.ref ?? 'main', profileId, gateId, p.status ?? 'queued', p.verdict ?? null, p.details ? JSON.stringify(p.details) : null],
    )
    return res.rows[0]!.id
  }

  beforeAll(async () => {
    db = await createTestDatabase()
    root = await mkdtemp(join(tmpdir(), 'scanoria-gates-'))
    for (const d of ['requests/tmp', 'requests/incoming', 'requests/done', 'requests/failed', 'bootstrap']) {
      await mkdir(join(root, d), { recursive: true, mode: 0o700 })
    }
    setConfig(loadConfig({
      NUXT_DATABASE_URL: db.url,
      NUXT_REQUESTS_DIR: join(root, 'requests'),
      NUXT_BOOTSTRAP_DIR: join(root, 'bootstrap'),
      NUXT_STATE_FILE: join(root, 'state.json'),
      NUXT_VERSION_FILE: join(root, 'VERSION'),
      NUXT_MIGRATE_ON_START: '0',
      NUXT_INGEST_INTERVAL_MS: '60000',
    }))
    process.env.NUXT_SCANORIA_SCAN_CLIENT = CLIENT
    void startConsole(async () => [])
    expect(await waitReady(30_000)).toBe(true)

    const app = createApp()
    app.use((await import('../../server/middleware/api-token')).default)
    app.use((await import('../../server/middleware/auth')).default)
    const router = createRouter()
    for (const r of apiRoutes()) router[r.method as 'get'](r.path, (await import(r.file)).default as EventHandler)
    app.use(router)
    server = createServer(toNodeListener(app))
    await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve))
    const addr = server.address()
    base = `http://127.0.0.1:${typeof addr === 'object' && addr ? addr.port : 0}`

    gateId = (await db.pool.query<{ id: string }>('SELECT id FROM gates WHERE slug = \'defaut\'')).rows[0]!.id
    profileId = (await db.pool.query<{ id: string }>('SELECT id FROM profiles WHERE slug = \'rapide\'')).rows[0]!.id
    projectA = await newProject('alpha')
    projectB = await newProject('beta')
    admin = await login('gadmin', 'admin')
    operator = await login('goperator', 'operator')
    viewer = await login('gviewer', 'viewer')
  })

  afterAll(async () => {
    await new Promise(resolve => server?.close(resolve))
    stopConsole()
    await closePool()
    await db?.drop()
    if (root) await rm(root, { recursive: true, force: true })
    delete process.env.NUXT_SCANORIA_SCAN_CLIENT
  })

  beforeEach(() => {
    enqueued.calls.length = 0
    enqueued.fail = ''
    tokenLimiter.reset('x')
  })

  describe('evaluateGate en base', () => {
    it('lit modules, résultats, exceptions actives et couverture', async () => {
      const project = await newProject('eval')
      const scan = await newScan(project, { status: 'ingesting' })
      await db.pool.query(
        `INSERT INTO scan_modules (scan_id, module_id, module_version, status) VALUES ($1, 'gitleaks', '8.0.0', 'ok'), ($1, 'trivy', '0.1.0', 'ok')`,
        [scan],
      )
      const ins = async (p: Record<string, unknown>) => {
        const fp = randomBytes(32).toString('hex')
        const r = await db.pool.query<{ id: string }>(
          `INSERT INTO findings (project_id, fingerprint, tool, rule_id, category, severity, title, path, vuln_ids, package, malicious, secret_type, status, status_until, status_reason)
           VALUES ($1, $2, $3, $4, $5, $6, 't', $7, $8, $9, $10, $11, $12, $13, $14) RETURNING id`,
          [project, fp, p.tool ?? 'trivy', p.rule_id ?? 'R', p.category ?? 'sca', p.severity ?? 'high', p.path ?? 'src/a.js',
            p.vuln_ids ?? [], p.package ? JSON.stringify(p.package) : null, p.malicious ?? false, p.secret_type ?? null,
            p.status ?? 'new', p.status_until ?? null, p.status_until ? 'motif' : null],
        )
        await db.pool.query('INSERT INTO scan_findings (scan_id, finding_id, is_new) VALUES ($1, $2, $3)', [scan, r.rows[0]!.id, p.is_new ?? true])
        return r.rows[0]!.id
      }
      const vuln = await ins({ vuln_ids: ['CVE-2026-0002'], package: { ecosystem: 'npm', name: 'lodash', version: '1.0.0' } })
      await ins({ category: 'secrets', secret_type: 'generic', path: 'tests/fixture.env', tool: 'gitleaks' })
      await ins({ severity: 'critical', is_new: false })
      await ins({ severity: 'critical', status: 'accepted', status_until: '2099-01-01' })
      await db.pool.query(
        `INSERT INTO exceptions (project_id, kind, target, reason, expires_on) VALUES
           ($1, 'path', '{"glob": "tests/**"}', 'jeux d''essai', current_date + 30),
           ($1, 'vuln', '{"vuln_id": "CVE-2026-0002"}', 'expirée', current_date - 1),
           ($1, 'rule', '{"rule_id": "R"}', 'révoquée', current_date + 30)`,
        [project],
      )
      await db.pool.query('UPDATE exceptions SET revoked_at = now() WHERE reason = \'révoquée\'')
      await db.pool.query(`UPDATE scans SET coverage = '{"gaps": [{"kind": "lockfile-missing"}]}' WHERE id = $1`, [scan])

      let v = await evaluateGate(db.pool, scan)
      expect(VerdictDetails.safeParse(v).success).toBe(true)
      expect(v.verdict).toBe('failed')
      expect(v.reasons.map(r => r.code)).toEqual(['vuln', 'coverage-gap'])
      expect(v.reasons[0]!.finding_ids).toEqual([vuln])
      expect(v.exceptions_applied.map(e => e.reason)).toEqual(['jeux d\'essai'])
      expect(v.counts.high).toBe(1)

      // Règles figées dans le plan (G11) prioritaires sur celles du gate.
      await db.pool.query(`UPDATE scans SET plan = '{"gate": {"rules": {"vuln_block_from": null}}}' WHERE id = $1`, [scan])
      v = await evaluateGate(db.pool, scan)
      expect(v.verdict).toBe('passed')
      expect(v.rules.vuln_block_from).toBeNull()

      await db.pool.query(`UPDATE scan_modules SET status = 'invalid-output' WHERE scan_id = $1 AND module_id = 'trivy'`, [scan])
      v = await evaluateGate(db.pool, scan)
      expect(v.verdict).toBe('inconclusive')
      expect(v.reasons[0]).toMatchObject({ code: 'output-invalid', module: 'trivy', blocking: true })

      await expect(evaluateGate(db.pool, randomUUID())).rejects.toBeInstanceOf(ScanNotFoundError)
    })
  })

  describe('gates', () => {
    it('liste et détail pour un lecteur, champs verrouillés', async () => {
      const list = await call('/api/gates', { client: viewer })
      expect(list.status).toBe(200)
      expect(list.data.items[0]).toMatchObject({ slug: 'defaut', builtin: true })
      const detail = await call(`/api/gates/${gateId}`, { client: viewer })
      expect(detail.data).toMatchObject({ slug: 'defaut', locked: { block_malicious: 'H4', inconclusive_blocks: 'G13' } })
      expect(detail.data.project_list.length).toBeGreaterThanOrEqual(2)
      expect((await call(`/api/gates/${randomUUID()}`, { client: viewer })).status).toBe(404)
      expect((await call('/api/gates/pas-un-uuid', { client: viewer })).status).toBe(404)
      expect((await call('/api/gates')).status).toBe(401)
    })

    it('création par copie, édition, affectation, suppression (admin seulement, audit)', async () => {
      expect((await call('/api/gates', { method: 'POST', client: operator, json: { slug: 'strict' } })).status).toBe(403)
      const created = await call('/api/gates', { method: 'POST', client: admin, json: { slug: 'strict' } })
      expect(created.status).toBe(201)
      expect(created.data).toMatchObject({ slug: 'strict', builtin: false, rules: { max_secrets: 0, vuln_block_from: 'high' } })
      const id = created.data.id as string
      expect(code(await call('/api/gates', { method: 'POST', client: admin, json: { slug: 'strict' } }))).toBe('E_SLUG_TAKEN')
      expect((await call('/api/gates', { method: 'POST', client: admin, json: { slug: 'x', copy_from: randomUUID() } })).status).toBe(404)

      const rules = { ...created.data.rules, vuln_block_from: 'medium', max_secrets: 1 }
      const patched = await call(`/api/gates/${id}`, { method: 'PATCH', client: admin, json: { rules } })
      expect(patched.status).toBe(200)
      expect(patched.data.rules).toMatchObject({ vuln_block_from: 'medium', max_secrets: 1 })
      expect(patched.data.updated_by_username).toBe('gadmin')
      for (const bad of [{ ...rules, block_malicious: false }, { ...rules, inconclusive_blocks: false }, { ...rules, max_secrets: -1 }, { ...rules, extra: 1 }]) {
        expect((await call(`/api/gates/${id}`, { method: 'PATCH', client: admin, json: { rules: bad } })).status).toBe(400)
      }
      expect((await call(`/api/gates/${id}`, { method: 'PATCH', client: operator, json: { rules } })).status).toBe(403)

      const copied = await call('/api/gates', { method: 'POST', client: admin, json: { slug: 'copie', copy_from: id } })
      expect(copied.data.rules).toMatchObject({ vuln_block_from: 'medium' })

      const assigned = await call(`/api/gates/${id}/assign`, { method: 'POST', client: admin, json: { project_id: projectA } })
      expect(assigned.status).toBe(200)
      expect((await call(`/api/gates/projects/${projectA}`, { client: viewer })).data.gate).toMatchObject({ id, slug: 'strict' })
      expect((await call(`/api/gates/${id}/assign`, { method: 'POST', client: admin, json: { project_id: randomUUID() } })).status).toBe(404)
      const archived = await newProject('archivé-non'.replace('é', 'e'), { archived: true })
      expect(code(await call(`/api/gates/${id}/assign`, { method: 'POST', client: admin, json: { project_id: archived } }))).toBe('E_PROJECT_ARCHIVED')

      expect(code(await call(`/api/gates/${id}`, { method: 'DELETE', client: admin }))).toBe('E_GATE_IN_USE')
      expect(code(await call(`/api/gates/${gateId}`, { method: 'DELETE', client: admin }))).toBe('E_GATE_BUILTIN')
      expect((await call(`/api/gates/${copied.data.id}`, { method: 'DELETE', client: admin })).status).toBe(204)
      expect((await call(`/api/gates/${copied.data.id}`, { method: 'DELETE', client: admin })).status).toBe(404)
      await call(`/api/gates/${gateId}/assign`, { method: 'POST', client: admin, json: { project_id: projectA } })

      const audit = await db.pool.query<{ action: string }>('SELECT action FROM audit_log WHERE action LIKE \'gate.%\' ORDER BY id')
      expect(audit.rows.map(r => r.action)).toEqual(['gate.create', 'gate.update', 'gate.create', 'gate.assign', 'gate.delete', 'gate.assign'])
    })
  })

  describe('jetons d’API', () => {
    it('création (une seule fois la valeur), liste sans empreinte, révocation, audit', async () => {
      expect((await call(`/api/projects/${projectA}/tokens`, { method: 'POST', client: viewer, json: { name: 'ci' } })).status).toBe(403)
      const tok = await newToken(projectA)
      expect(tok.value).toMatch(/^scn_[A-Za-z0-9]{40}$/)
      expect(tok.prefix).toBe(tok.value.slice(0, 8))
      const stored = await db.pool.query<{ token_hash: string }>('SELECT token_hash FROM api_tokens WHERE id = $1', [tok.id])
      expect(stored.rows[0]!.token_hash).not.toContain(tok.value)

      const list = await call(`/api/projects/${projectA}/tokens`, { client: operator })
      expect(list.text).not.toContain(tok.value)
      expect(list.text).not.toContain(stored.rows[0]!.token_hash)
      expect(list.data.items[0]).toMatchObject({ id: tok.id, name: 'ci', created_by_username: 'goperator', revoked_at: null })
      expect((await call(`/api/projects/${projectA}/tokens`, { client: viewer })).status).toBe(403)
      expect((await call(`/api/projects/${randomUUID()}/tokens`, { client: operator })).status).toBe(404)

      const revoked = await call(`/api/projects/${projectA}/tokens/${tok.id}`, { method: 'DELETE', client: operator })
      expect(revoked.data.revoked_at).toBeTruthy()
      expect((await call(`/api/projects/${projectB}/tokens/${tok.id}`, { method: 'DELETE', client: operator })).status).toBe(404)

      const audit = await db.pool.query<{ action: string, details: Record<string, unknown> }>(
        'SELECT action, details FROM audit_log WHERE action LIKE \'api-token.%\' ORDER BY id',
      )
      expect(audit.rows.map(r => r.action)).toEqual(['api-token.create', 'api-token.revoke'])
      expect(JSON.stringify(audit.rows)).not.toContain(tok.value)
    })

    it('dépôt d’une analyse et lecture du verdict par jeton', async () => {
      const tok = await newToken(projectA)
      const res = await call(`/api/projects/${projectA}/scans`, { method: 'POST', bearer: tok.value, json: { ref: 'v1.2.0', profile: 'rapide' } })
      expect(res.status, JSON.stringify(res.data)).toBe(202)
      expect(res.data).toMatchObject({ number: 1, url: `/scans/${res.data.scan_id}` })
      expect(enqueued.calls[0]).toMatchObject({ projectId: projectA, ref: 'v1.2.0', trigger: 'api', profileSlug: 'rapide', apiTokenId: tok.id })

      const pending = await call(`/api/scans/${res.data.scan_id}/verdict`, { bearer: tok.value })
      expect(pending.status).toBe(200)
      expect(pending.data).toMatchObject({ status: 'queued', verdict: null, details: null, project_id: projectA })

      const last = await db.pool.query<{ last_used_at: Date | null }>('SELECT last_used_at FROM api_tokens WHERE id = $1', [tok.id])
      expect(last.rows[0]!.last_used_at).toBeTruthy()

      // Session : operator pour déposer (trigger manual), viewer pour lire.
      const manual = await call(`/api/projects/${projectA}/scans`, { method: 'POST', client: operator, json: { ref: 'main' } })
      expect(manual.status).toBe(202)
      expect(enqueued.calls[1]).toMatchObject({ trigger: 'manual', requestedBy: expect.any(Number) })
      expect((await call(`/api/projects/${projectA}/scans`, { method: 'POST', client: viewer, json: { ref: 'main' } })).status).toBe(403)
      expect((await call(`/api/scans/${res.data.scan_id}/verdict`, { client: viewer })).status).toBe(200)

      // Corps invalides, profil inconnu, refus de enqueueScan.
      for (const body of [{ ref: '--upload-pack=x' }, { ref: '' }, { ref: 'main', extra: 1 }, {}]) {
        expect((await call(`/api/projects/${projectA}/scans`, { method: 'POST', bearer: tok.value, json: body })).status).toBe(400)
      }
      expect((await call(`/api/projects/${projectA}/scans`, { method: 'POST', bearer: tok.value, json: { ref: 'main', profile: 'inconnu' } })).status).toBe(400)
      const refused = async (reason: string) => {
        enqueued.fail = reason
        return call(`/api/projects/${projectA}/scans`, { method: 'POST', bearer: tok.value, json: { ref: 'main' } })
      }
      const source = await refused('E_SCAN_SOURCE')
      expect(source.status).toBe(409)
      expect(source.data.data).toMatchObject({ code: 'E_SCAN_REFUSED', reason: 'E_SCAN_SOURCE' })
      expect(code(await refused('E_SCAN_PROJECT_ARCHIVED'))).toBe('E_PROJECT_ARCHIVED')
      expect((await refused('E_SCAN_PROJECT_NOT_FOUND')).status).toBe(404)
      expect((await refused('E_SCAN_REF')).data.data.issues[0]).toEqual({ path: 'ref', code: 'E_SCAN_REF' })
      expect((await refused('E_SCAN_PROFILE')).status).toBe(400)
      expect((await refused('inattendue')).status).toBe(500)
      enqueued.fail = ''

      const audit = await db.pool.query<{ actor_username: string }>('SELECT actor_username FROM audit_log WHERE action = \'scan.request\' ORDER BY id')
      expect(audit.rows.map(r => r.actor_username)).toEqual([`api-token:${tok.prefix}`, 'goperator'])
    })

    it('mauvais projet, portée, révoqué, expiré, invalide', async () => {
      const tok = await newToken(projectA)
      const scanB = await newScan(projectB)
      expect(code(await call(`/api/projects/${projectB}/scans`, { method: 'POST', bearer: tok.value, json: { ref: 'main' } }))).toBe('E_TOKEN_SCOPE')
      expect((await call(`/api/scans/${scanB}/verdict`, { bearer: tok.value })).status).toBe(404)
      // Le jeton n'ouvre aucune autre route, même en lecture.
      expect(code(await call('/api/gates', { bearer: tok.value }))).toBe('E_TOKEN_SCOPE')
      expect(code(await call(`/api/projects/${projectA}/tokens`, { bearer: tok.value }))).toBe('E_TOKEN_SCOPE')
      // Portée réduite en base : lecture seule.
      await db.pool.query(`UPDATE api_tokens SET scopes = '{scan:read}' WHERE id = $1`, [tok.id])
      expect(code(await call(`/api/projects/${projectA}/scans`, { method: 'POST', bearer: tok.value, json: { ref: 'main' } }))).toBe('E_TOKEN_SCOPE')

      const ip = nextIp()
      await db.pool.query('UPDATE api_tokens SET revoked_at = now() WHERE id = $1', [tok.id])
      expect(code(await call(`/api/scans/${scanB}/verdict`, { bearer: tok.value, ip }))).toBe('E_TOKEN_REVOKED')
      const exp = await newToken(projectA, operator, { name: 'court', expires_in_days: 1 })
      await db.pool.query(`UPDATE api_tokens SET expires_at = now() - interval '1 second' WHERE id = $1`, [exp.id])
      expect(code(await call(`/api/scans/${scanB}/verdict`, { bearer: exp.value, ip }))).toBe('E_TOKEN_EXPIRED')
      const fake = `scn_${'A'.repeat(40)}`
      expect(code(await call(`/api/scans/${scanB}/verdict`, { bearer: fake, ip }))).toBe('E_TOKEN_INVALID')
      expect(code(await call(`/api/scans/${scanB}/verdict`, { bearer: 'pas-un-jeton', ip }))).toBe('E_TOKEN_INVALID')
      // Projet archivé : ses jetons sont refusés.
      const live = await newToken(projectA)
      await db.pool.query('UPDATE projects SET archived_at = now() WHERE id = $1', [projectA])
      expect(code(await call(`/api/scans/${scanB}/verdict`, { bearer: live.value, ip }))).toBe('E_TOKEN_REVOKED')
      await db.pool.query('UPDATE projects SET archived_at = NULL WHERE id = $1', [projectA])
    })

    it('limite de débit : par jeton et par adresse après des jetons refusés', async () => {
      const tok = await newToken(projectA)
      const scan = await newScan(projectA)
      for (let i = 0; i < 300; i++) tokenLimiter.hit(tok.id)
      const limited = await call(`/api/scans/${scan}/verdict`, { bearer: tok.value })
      expect(limited.status).toBe(429)
      expect(Number(limited.headers.get('retry-after'))).toBeGreaterThan(0)
      tokenLimiter.reset(tok.id)
      expect((await call(`/api/scans/${scan}/verdict`, { bearer: tok.value })).status).toBe(200)

      const ip = nextIp()
      for (let i = 0; i < 30; i++) badTokenLimiter.hit(ip)
      expect((await call(`/api/scans/${scan}/verdict`, { bearer: `scn_${'B'.repeat(40)}`, ip })).status).toBe(429)
      // Un jeton valide de la même adresse passe toujours.
      expect((await call(`/api/scans/${scan}/verdict`, { bearer: tok.value, ip })).status).toBe(200)
      badTokenLimiter.reset(ip)
    })
  })

  describe('verdict, badge et client', () => {
    const details = (verdict: 'passed' | 'failed' | 'inconclusive') => ({
      verdict, gate_id: '3f1c2b9a-1d2e-4f3a-8b4c-5d6e7f8a9b0c',
      rules: { new_code_only: true, max_secrets: 0, vuln_block_from: 'high', sast_block_from: 'high', iac_block_from: 'high', block_malicious: true, inconclusive_blocks: true },
      evaluated_at: '2026-11-24T10:00:00Z', new_code_only: true, counts: { critical: 0, high: 2, medium: 0, low: 0, info: 0 },
      reasons: verdict === 'passed' ? [] : [{ code: 'secret', blocking: true, count: 2, severity: 'high', module: null, finding_ids: [], actions: ['fix', 'request-exception'] }],
      exceptions_applied: [],
    })

    it('verdict complet avec texte IA (I9) dans la langue demandée', async () => {
      const scan = await newScan(projectA, { status: 'done', verdict: 'failed', details: details('failed') })
      await db.pool.query(
        `INSERT INTO ai_tasks (kind, project_id, subject_type, subject_id, locale, status, model, model_digest, output, finished_at)
         VALUES ('explain-verdict', $1, 'scan', $2, 'en', 'done', 'm', 'sha256:x', '{"summary": "Two secrets."}', now()),
                ('explain-verdict', $1, 'scan', $2, 'fr', 'done', 'm', 'sha256:x', '{"summary": "Deux secrets."}', now())`,
        [projectA, scan],
      )
      // Sans connecteur IA : aucun texte IA, la réponse est celle d'une appliance sans IA.
      const aiDir = await mkdtemp(join(tmpdir(), 'scanoria-gates-ai-'))
      process.env.NUXT_AI_ENDPOINT_FILE = join(aiDir, 'ai.json')
      clearConnectorCache()
      expect((await call(`/api/scans/${scan}/verdict`, { client: viewer })).data.ai_summary).toBeUndefined()
      await writeFile(process.env.NUXT_AI_ENDPOINT_FILE, JSON.stringify({
        version: 1, enabled: true, url: 'https://ollama.exemple.test:11434', scheme: 'https', host: 'ollama.exemple.test',
        port: 11434, addresses: ['192.0.2.10'], insecure: false, token: false, ca: false, literal: false, pinned_at: '2026-11-24T09:00:00Z',
      }))
      clearConnectorCache()
      const fr = await call(`/api/scans/${scan}/verdict`, { client: viewer })
      expect(fr.data).toMatchObject({ verdict: 'failed', status: 'done', ai_summary: { summary: 'Deux secrets.', model: 'm' } })
      expect(VerdictDetails.safeParse(fr.data.details).success).toBe(true)
      expect((await call(`/api/scans/${scan}/verdict?locale=en`, { client: viewer })).data.ai_summary.summary).toBe('Two secrets.')
      const other = await newScan(projectA, { status: 'done', verdict: 'passed', details: details('passed') })
      expect((await call(`/api/scans/${other}/verdict`, { client: viewer })).data.ai_summary).toBeUndefined()
      expect((await call(`/api/scans/${randomUUID()}/verdict`, { client: viewer })).status).toBe(404)
      delete process.env.NUXT_AI_ENDPOINT_FILE
      clearConnectorCache()
      await rm(aiDir, { recursive: true, force: true })
    })

    it('badge : 404 tant qu’il n’est pas activé, puis dernier verdict de la branche par défaut', async () => {
      const project = await newProject('badge')
      await newScan(project, { status: 'done', verdict: 'passed', details: details('passed'), ref: 'main' })
      await newScan(project, { status: 'done', verdict: 'failed', details: details('failed'), ref: 'feat/x' })
      expect((await call('/api/badges/badge.svg')).status).toBe(404)
      expect((await call('/api/badges/inconnu.svg')).status).toBe(404)
      expect((await call(`/api/badges/projects/${project}`, { method: 'PUT', client: viewer, json: { enabled: true } })).status).toBe(403)
      const on = await call(`/api/badges/projects/${project}`, { method: 'PUT', client: operator, json: { enabled: true } })
      expect(on.data).toMatchObject({ enabled: true, path: '/api/badges/badge.svg' })
      const svg = await call('/api/badges/badge.svg')
      expect(svg.status).toBe(200)
      expect(svg.headers.get('content-type')).toContain('image/svg+xml')
      expect(svg.text).toContain('>passed<')
      expect((await call(`/api/gates/projects/${project}`, { client: viewer })).data).toMatchObject({ badge: { enabled: true }, active_tokens: 0 })
      await call(`/api/badges/projects/${project}`, { method: 'PUT', client: operator, json: { enabled: false } })
      expect((await call('/api/badges/badge.svg')).status).toBe(404)
      const ip = nextIp()
      for (let i = 0; i < 300; i++) publicLimiter.hit(ip)
      expect((await call('/api/gates/client', { ip })).status).toBe(429)
      publicLimiter.reset(ip)
    })

    it('client scanoria-scan : dépôt, attente, codes de sortie 0, 1, 2, 3', async () => {
      const dl = await call('/api/gates/client')
      expect(dl.status).toBe(200)
      expect(dl.text.startsWith('#!/bin/sh')).toBe(true)

      const tok = await newToken(projectA)
      const env = { ...process.env, SCANORIA_TOKEN: tok.value, SCANORIA_ALLOW_HTTP: '1', SCANORIA_INTERVAL: '1', SCANORIA_LANG: 'fr' }
      const client = (args: string[], e: NodeJS.ProcessEnv = env) => run('sh', [CLIENT, ...args], { env: e, timeout: 60_000 })
        .then(r => ({ code: 0, ...r }))
        .catch((err: { code: number, stdout: string, stderr: string }) => ({ code: err.code, stdout: err.stdout, stderr: err.stderr }))

      // Sans --wait : 0 dès le dépôt, l'identifiant de l'analyse sur la sortie standard.
      const queued = await client(['--url', base, '--project', projectA, '--ref', 'main'])
      expect(queued.code, queued.stderr).toBe(0)
      const scanId = queued.stdout.trim()
      expect(scanId).toMatch(/^[0-9a-f-]{36}$/)

      // Avec --wait : le verdict arrive pendant l'attente.
      for (const [verdict, exit] of [['passed', 0], ['failed', 1], ['inconclusive', 2]] as const) {
        const pending = client(['--url', base, '--scan', scanId, '--wait', '--timeout', '30'])
        await new Promise(resolve => setTimeout(resolve, 1500))
        await db.pool.query(`UPDATE scans SET status = 'done', verdict = $2, verdict_details = $3, finished_at = now() WHERE id = $1`, [scanId, verdict, JSON.stringify(details(verdict))])
        const res = await pending
        expect(res.code, res.stderr).toBe(exit)
        expect(res.stdout).toContain(`verdict : ${verdict}`)
        if (verdict !== 'passed') expect(res.stdout).toContain('[bloquant] secret ×2 high')
        await db.pool.query(`UPDATE scans SET status = 'running', verdict = NULL, verdict_details = NULL WHERE id = $1`, [scanId])
      }

      // Délai dépassé → 2 ; analyse en erreur sans verdict → 2.
      expect((await client(['--url', base, '--scan', scanId, '--timeout', '1'])).code).toBe(2)
      await db.pool.query(`UPDATE scans SET status = 'error' WHERE id = $1`, [scanId])
      expect((await client(['--url', base, '--scan', scanId])).code).toBe(2)

      // Erreurs d'utilisation et d'accès → 3, jeton jamais accepté en argument.
      expect((await client(['--url', base, '--project', projectA])).code).toBe(3)
      expect((await client(['--url', base, '--project', projectA, '--ref', 'main', '--token', tok.value])).code).toBe(3)
      expect((await client(['--url', base.replace('http:', 'ftp:'), '--project', projectA, '--ref', 'main'])).code).toBe(3)
      expect((await client(['--url', base, '--project', projectA, '--ref', 'main'], { ...env, SCANORIA_ALLOW_HTTP: '0' })).code).toBe(3)
      expect((await client(['--url', base, '--project', projectA, '--ref', 'main'], { ...env, SCANORIA_TOKEN: '' })).code).toBe(3)
      const denied = await client(['--url', base, '--project', projectB, '--ref', 'main'])
      expect(denied.code).toBe(3)
      expect(denied.stderr).toContain('E_TOKEN_SCOPE')
      const unreachable = await client(['--url', 'http://127.0.0.1:9', '--project', projectA, '--ref', 'main'])
      expect(unreachable.code).toBe(3)
      // Le jeton n'apparaît dans aucune sortie.
      expect(`${denied.stdout}${denied.stderr}`).not.toContain(tok.value)
    }, 120_000)
  })
})
