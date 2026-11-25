// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// J4 (0.8, chantier C) contre PostgreSQL : émetteurs et liaisons créés à
// l'enrôlement, JWKS en cache (rafraîchi seulement sur kid inconnu, une fois
// par minute au plus), jetons hostiles refusés, comptés et audités sans le
// jeton, et authenticateCi (contrat 41) derrière le vrai intergiciel : jeton
// d'API inchangé, jeton OIDC accepté pour le bon dépôt et la bonne ref,
// refusé pour un autre ; identité toujours non humaine.

import { randomBytes } from 'node:crypto'
import { mkdtemp, rm } from 'node:fs/promises'
import { createServer, type Server } from 'node:http'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { createApp, createRouter, defineEventHandler, toNodeListener } from 'h3'
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest'
import { DATABASE_URL, createTestDatabase, type TestDatabase } from '../helpers/db'
import { actionsClaims, ecKey, hs256WithPublicKey, rsaKey, signJwt, startFakeCi, unsignedJwt, type FakeCi, type FakeIssuer } from '../helpers/fake-ci'
import { loadConfig, setConfig } from '../../server/utils/config'
import { closePool } from '../../server/utils/db'
import { encryptSecret } from '../../server/utils/secrets'
import { createProject } from '../../server/projects/service'
import { createApiToken } from '../../server/gates/tokens'
import {
  JWKS_REFRESH_MIN_MS, JWKS_TTL_MS, bindEnrolledProject, createBinding, createIssuer, defaultIssuerFor, deleteBinding, ensureForgeOidc,
  listBindings, listIssuers, resetBindingPin, resetJwksThrottle, setIssuerEnabled, updateBinding, verifyOidcToken,
} from '../../server/ci/oidc'
import { authenticateCi, oidcRefusalCounts, resetOidcRefusalCounts } from '../../server/ci/auth'
import apiTokenMiddleware from '../../server/middleware/api-token'
import scansPost from '../../server/api/projects/[id]/scans.post'
import verdictGet from '../../server/api/scans/[id]/verdict.get'
import exceptionRequestsPost from '../../server/api/projects/[id]/exception-requests.post'

const FORGE = 'https://forge.exemple.test'
const ISS = `${FORGE}/api/actions`

describe.skipIf(!DATABASE_URL)('OIDC de CI (J4, PostgreSQL)', () => {
  let db: TestDatabase
  let dir: string
  let fake: FakeCi
  let issuer: FakeIssuer
  let forgeId: string
  let projectId: string
  let otherProjectId: string
  let server: Server
  let base: string
  const rsa = rsaKey('k1')
  const ec = ecKey('k2')

  const token = (repo = 'equipe/app', ref = 'refs/heads/main', extra: Record<string, unknown> = {}) => signJwt(rsa, actionsClaims(ISS, repo, ref, extra))
  async function call(method: string, path: string, bearer: string | null, json?: unknown) {
    const res = await fetch(`${base}${path}`, {
      method,
      headers: { ...(bearer ? { authorization: `Bearer ${bearer}` } : {}), 'content-type': 'application/json' },
      ...(json ? { body: JSON.stringify(json) } : {}),
    })
    return { status: res.status, data: await res.json().catch(() => ({})) as Record<string, unknown> }
  }
  const audits = async (action: string) => (await db.pool.query<{ details: Record<string, unknown>, outcome: string }>(
    'SELECT details, outcome FROM audit_log WHERE action = $1 ORDER BY id', [action])).rows

  beforeAll(async () => {
    db = await createTestDatabase()
    dir = await mkdtemp(join(tmpdir(), 'scanoria-oidc-'))
    process.env.NUXT_SECRET_KEY_FILE = join(dir, 'secret.key')
    setConfig(loadConfig({
      NUXT_DATABASE_URL: db.url,
      NUXT_UPLOADS_DIR: join(dir, 'uploads'),
      NUXT_CATALOG_INDEX_FILE: join(dir, 'absent-index.json'),
      NUXT_MODULES_STATE_FILE: join(dir, 'absent-state.json'),
    }))
    fake = startFakeCi()
    issuer = fake.addIssuer(ISS, [rsa, ec])
    const cred = await encryptSecret(db.pool, { kind: 'token', value: randomBytes(20).toString('hex'), username: 'scanoria-bot', createdBy: null })
    forgeId = (await db.pool.query<{ id: string }>(
      `INSERT INTO forges (kind, name, base_url, credential_id, discovery) VALUES ('forgejo', 'Forge', $1, $2, false) RETURNING id::text`, [FORGE, cred])).rows[0]!.id
    // Projet enrôlé avant l'émetteur : lié à la création de l'émetteur.
    projectId = (await createProject(db.pool, { name: 'equipe/app', sourceKind: 'git', forgeId, repoFullName: 'equipe/app', repoUrl: `${FORGE}/equipe/app.git`, defaultBranch: 'main' })).id
    otherProjectId = (await createProject(db.pool, { name: 'equipe/autre', sourceKind: 'git', repoUrl: `${FORGE}/equipe/autre.git`, defaultBranch: 'main' })).id

    const app = createApp()
    app.use(apiTokenMiddleware)
    const router = createRouter()
    router.post('/api/projects/:id/scans', scansPost)
    router.get('/api/scans/:id/verdict', verdictGet)
    router.post('/api/projects/:id/exception-requests', exceptionRequestsPost)
    router.get('/api/ci/whoami', defineEventHandler(event => event.context.ciAuth ?? null))
    app.use(router)
    server = createServer(toNodeListener(app))
    await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve))
    const addr = server.address()
    base = `http://127.0.0.1:${typeof addr === 'object' && addr ? addr.port : 0}`
  })

  afterAll(async () => {
    fake?.restore()
    if (server) await new Promise(resolve => server.close(resolve))
    await closePool()
    await db?.drop()
    delete process.env.NUXT_SECRET_KEY_FILE
    if (dir) await rm(dir, { recursive: true, force: true })
  })

  beforeEach(() => {
    resetJwksThrottle()
  })

  it('émetteur Actions connu de chaque forge', () => {
    expect(defaultIssuerFor({ kind: 'github', base_url: 'https://github.com' })).toBe('https://token.actions.githubusercontent.com')
    expect(defaultIssuerFor({ kind: 'github', base_url: 'https://ghe.exemple.test' })).toBe('https://ghe.exemple.test/_services/token')
    expect(defaultIssuerFor({ kind: 'gitlab', base_url: 'https://gitlab.exemple.test/' })).toBe('https://gitlab.exemple.test')
    expect(defaultIssuerFor({ kind: 'forgejo', base_url: FORGE })).toBe(ISS)
    expect(defaultIssuerFor({ kind: 'autre', base_url: FORGE })).toBeNull()
    expect(() => defaultIssuerFor({ kind: 'forgejo', base_url: 'http://forge.exemple.test' })).toThrow()
  })

  it('émetteur déclaré une fois pour la forge, liaisons des projets déjà enrôlés (main et tags)', async () => {
    const first = await ensureForgeOidc(db.pool, { id: forgeId, kind: 'forgejo', base_url: FORGE })
    expect(first.bound).toBe(1)
    const again = await ensureForgeOidc(db.pool, { id: forgeId, kind: 'forgejo', base_url: FORGE })
    expect(again).toEqual({ issuerId: first.issuerId, bound: 0 })
    const [b] = await listBindings(db.pool, projectId)
    expect(b).toMatchObject({ repository: 'equipe/app', repository_id: null, ref_patterns: ['refs/heads/main', 'refs/tags/*', 'refs/pull/*'], scopes: ['scan:create', 'scan:read'], issuer: ISS })
    const [i] = await listIssuers(db.pool)
    expect(i).toMatchObject({ kind: 'forgejo', audience: 'scanoria', enabled: true, bindings: 1 })
    // Un projet enrôlé ensuite est lié à son tour, une seule fois.
    const late = (await createProject(db.pool, { name: 'equipe/neuf', sourceKind: 'git', forgeId, repoFullName: 'equipe/neuf', repoUrl: `${FORGE}/equipe/neuf.git`, defaultBranch: 'main' })).id
    expect(await bindEnrolledProject(db.pool, { id: forgeId, kind: 'forgejo', base_url: FORGE }, late, 'equipe/neuf')).toMatch(/^[0-9a-f-]{36}$/)
    expect(await bindEnrolledProject(db.pool, { id: forgeId, kind: 'forgejo', base_url: FORGE }, late, 'equipe/neuf')).toBeNull()
    expect(await bindEnrolledProject(db.pool, { id: forgeId, kind: 'autre', base_url: FORGE }, late, 'equipe/neuf')).toBeNull()
  })

  it('identifiant du dépôt : épinglé à l’enrôlement ou au premier jeton ; dépôt recréé sous le même nom refusé ; refs de PR', async () => {
    const forge = { id: forgeId, kind: 'forgejo', base_url: FORGE }
    const refusal = async (t: string) => verifyOidcToken(db.pool, t).then(() => 'ok', (e: { code: string }) => e.code)
    // Enrôlement : l'API de la forge donne l'identifiant, épinglé tout de suite.
    const enrolled = (await createProject(db.pool, { name: 'equipe/epingle', sourceKind: 'git', forgeId, repoFullName: 'equipe/epingle', repoUrl: `${FORGE}/equipe/epingle.git`, defaultBranch: 'main' })).id
    await bindEnrolledProject(db.pool, forge, enrolled, 'equipe/epingle', { id: '900', defaultBranch: 'main' })
    expect((await listBindings(db.pool, enrolled))[0]).toMatchObject({ repository_id: '900', ref_patterns: ['refs/heads/main', 'refs/tags/*', 'refs/pull/*'] })
    expect(await refusal(token('equipe/epingle', 'refs/heads/main', { repository_id: 900 }))).toBe('ok')
    expect(await refusal(token('equipe/epingle', 'refs/pull/4/merge', { repository_id: '900' }))).toBe('ok')
    expect(await refusal(token('equipe/epingle', 'refs/heads/main', { repository_id: 901 }))).toBe('E_OIDC_REPOSITORY_ID')
    expect(await refusal(token('equipe/epingle', 'refs/heads/main'))).toBe('E_OIDC_REPOSITORY_ID')
    expect(await refusal(token('equipe/epingle', 'refs/heads/feature'))).toBe('E_OIDC_BINDING')

    // Sans identifiant à l'enrôlement : épinglé par le premier jeton accepté, jamais écrasé ensuite.
    const later = (await createProject(db.pool, { name: 'equipe/recree', sourceKind: 'git', forgeId, repoFullName: 'equipe/recree', repoUrl: `${FORGE}/equipe/recree.git`, defaultBranch: 'main' })).id
    const bindingId = (await createBinding(db.pool, { issuerId: (await listIssuers(db.pool))[0]!.id, projectId: later, repository: 'equipe/recree' }))!
    expect(await refusal(token('equipe/recree', 'refs/heads/main', { repository_id: 31 }))).toBe('ok')
    expect((await listBindings(db.pool, later))[0]!.repository_id).toBe('31')
    expect(await refusal(token('equipe/recree', 'refs/heads/main', { repository_id: 32 }))).toBe('E_OIDC_REPOSITORY_ID')
    expect((await listBindings(db.pool, later))[0]!.repository_id).toBe('31')
    // Dépôt légitimement recréé : l'administrateur réinitialise l'épingle.
    expect(await resetBindingPin(db.pool, later, bindingId)).toBe(true)
    expect(await refusal(token('equipe/recree', 'refs/heads/main', { repository_id: 32 }))).toBe('ok')
    expect((await listBindings(db.pool, later))[0]!.repository_id).toBe('32')
    await db.pool.query('UPDATE projects SET archived_at = now() WHERE id = ANY($1::uuid[])', [[enrolled, later]])
  })

  it('jeton valide : liaison du bon projet ; JWKS lu une fois puis gardé en cache', async () => {
    const r = await verifyOidcToken(db.pool, token())
    expect(r.matches.map(m => m.projectId)).toEqual([projectId])
    expect(r.claims).toMatchObject({ repository: 'equipe/app', ref: 'refs/heads/main' })
    const fetched = issuer.fetches.jwks
    await verifyOidcToken(db.pool, signJwt(ec, actionsClaims(ISS, 'equipe/app', 'refs/tags/v1.0.0')))
    expect(issuer.fetches.jwks).toBe(fetched)
    // Dépôt en casse différente : même dépôt pour la forge.
    expect((await verifyOidcToken(db.pool, token('Equipe/App'))).matches).toHaveLength(1)
  })

  it('kid inconnu : un seul rafraîchissement par minute ; nouvelle clé de la forge acceptée après rotation', async () => {
    const rotated = rsaKey('k3')
    const before = issuer.fetches.jwks
    const bad = signJwt(rotated, actionsClaims(ISS, 'equipe/app', 'refs/heads/main'))
    await expect(verifyOidcToken(db.pool, bad)).rejects.toMatchObject({ code: 'E_OIDC_KID' })
    await expect(verifyOidcToken(db.pool, bad)).rejects.toMatchObject({ code: 'E_OIDC_KID' })
    expect(issuer.fetches.jwks).toBe(before + 1)
    issuer.keys.push(rotated)
    // Avant une minute : toujours refusé, sans nouvelle lecture.
    await expect(verifyOidcToken(db.pool, bad)).rejects.toMatchObject({ code: 'E_OIDC_KID' })
    expect(issuer.fetches.jwks).toBe(before + 1)
    expect((await verifyOidcToken(db.pool, bad, Date.now() + JWKS_REFRESH_MIN_MS + 1000)).matches).toHaveLength(1)
    expect(issuer.fetches.jwks).toBe(before + 2)
    // JWKS de plus d'une heure : relu.
    resetJwksThrottle()
    await verifyOidcToken(db.pool, token(), Date.now() + JWKS_TTL_MS + 5 * 60_000).catch(() => null)
    expect(issuer.fetches.jwks).toBe(before + 3)
  })

  it('jetons hostiles : chaque refus a sa raison', async () => {
    const claims = actionsClaims(ISS, 'equipe/app', 'refs/heads/main')
    const cases: [string, string][] = [
      [unsignedJwt(claims), 'E_OIDC_ALG'],
      [hs256WithPublicKey(rsa, claims), 'E_OIDC_ALG'],
      [signJwt(rsaKey('k1'), claims), 'E_OIDC_SIGNATURE'],
      [signJwt(rsa, { ...claims, aud: 'https://forge.exemple.test/equipe' }), 'E_OIDC_AUDIENCE'],
      [signJwt(rsa, { ...claims, iss: 'https://autre.exemple.test' }), 'E_OIDC_ISSUER'],
      [signJwt(rsa, { ...claims, exp: Math.floor(Date.now() / 1000) - 3600, iat: Math.floor(Date.now() / 1000) - 3900, nbf: undefined }), 'E_OIDC_EXPIRED'],
      [signJwt(rsa, { ...claims, nbf: Math.floor(Date.now() / 1000) + 3600 }), 'E_OIDC_NOT_YET_VALID'],
      [token('equipe/autre'), 'E_OIDC_BINDING'],
      [token('equipe/app', 'refs/heads/feature'), 'E_OIDC_BINDING'],
      [token('equipe/app', 'refs/heads/main', { repository: undefined }), 'E_OIDC_CLAIMS'],
      [signJwt(rsa, { ...claims, pad: 'x'.repeat(9000) }), 'E_OIDC_TOO_LARGE'],
    ]
    for (const [t, c] of cases) await expect(verifyOidcToken(db.pool, t), c).rejects.toMatchObject({ code: c })
  })

  it('émetteur désactivé : tout jeton refusé ; réactivé : accepté', async () => {
    const [i] = await listIssuers(db.pool)
    await setIssuerEnabled(db.pool, i!.id, false)
    await expect(verifyOidcToken(db.pool, token())).rejects.toMatchObject({ code: 'E_OIDC_DISABLED' })
    // Jamais réactivé par la découverte de la forge.
    await ensureForgeOidc(db.pool, { id: forgeId, kind: 'forgejo', base_url: FORGE })
    expect((await listIssuers(db.pool))[0]!.enabled).toBe(false)
    await setIssuerEnabled(db.pool, i!.id, true)
    expect((await verifyOidcToken(db.pool, token())).matches).toHaveLength(1)
  })

  it('JWKS injoignable ou incohérent : refus E_OIDC_JWKS', async () => {
    const lonely = await createIssuer(db.pool, { kind: 'github', issuer: 'https://ci.exemple.test' })
    const k = rsaKey('x')
    const t = signJwt(k, { ...actionsClaims('https://ci.exemple.test', 'equipe/app', 'refs/heads/main') })
    await expect(verifyOidcToken(db.pool, t)).rejects.toMatchObject({ code: 'E_OIDC_JWKS' })
    // Découverte qui renvoie vers un autre hôte : refusée.
    fake.handlers.unshift(req => req.url === 'https://ci.exemple.test/.well-known/openid-configuration'
      ? { status: 200, body: { issuer: 'https://ci.exemple.test', jwks_uri: 'https://ailleurs.exemple.test/jwks' } }
      : null)
    resetJwksThrottle()
    await expect(verifyOidcToken(db.pool, t)).rejects.toMatchObject({ code: 'E_OIDC_JWKS' })
    fake.handlers.shift()
    expect(lonely.created).toBe(true)
  })

  it('liaisons : motifs modifiés, liaison retirée → refus immédiat', async () => {
    const [b] = await listBindings(db.pool, projectId)
    expect(await updateBinding(db.pool, projectId, b!.id, { refPatterns: ['refs/heads/*'] })).toBe(true)
    expect((await verifyOidcToken(db.pool, token('equipe/app', 'refs/heads/feature'))).matches).toHaveLength(1)
    await expect(verifyOidcToken(db.pool, token('equipe/app', 'refs/tags/v1'))).rejects.toMatchObject({ code: 'E_OIDC_BINDING' })
    await updateBinding(db.pool, projectId, b!.id, { refPatterns: ['refs/heads/main', 'refs/tags/*'] })
    // Même dépôt lié à un second projet : deux correspondances.
    const second = await createBinding(db.pool, { issuerId: b!.issuer_id, projectId: otherProjectId, repository: 'equipe/app' })
    expect((await verifyOidcToken(db.pool, token())).matches).toHaveLength(2)
    expect(await deleteBinding(db.pool, otherProjectId, second!)).toBe(true)
    expect(await deleteBinding(db.pool, otherProjectId, second!)).toBe(false)
  })

  describe('authenticateCi derrière l’intergiciel (contrat 41)', () => {
    it('jeton OIDC : analyse déposée pour le projet lié, identité non humaine, aucun jeton d’API en base', async () => {
      const r = await call('POST', `/api/projects/${projectId}/scans`, token(), { ref: 'main' })
      expect(r.status).toBe(202)
      const scan = (await db.pool.query<{ trigger: string, api_token_id: string | null }>('SELECT trigger, api_token_id FROM scans WHERE id = $1', [r.data.scan_id])).rows[0]
      expect(scan).toEqual({ trigger: 'api', api_token_id: null })
      const [a] = (await db.pool.query<{ actor_username: string, details: Record<string, unknown> }>(
        `SELECT actor_username, details FROM audit_log WHERE action = 'scan.request' ORDER BY id DESC LIMIT 1`)).rows
      expect(a!.actor_username).toBe('oidc:equipe/app@refs/heads/main')
      // Verdict lisible par le même jeton (un seul projet lié), pas par un autre dépôt.
      expect((await call('GET', `/api/scans/${r.data.scan_id}/verdict`, token())).status).toBe(200)
      expect((await call('GET', `/api/scans/${r.data.scan_id}/verdict`, token('equipe/autre'))).status).toBe(403)
    })

    it('jeton OIDC refusé pour un autre projet (403) ; jeton invalide 401 ; refus comptés et audités sans le jeton', async () => {
      resetOidcRefusalCounts()
      const t = token()
      expect((await call('POST', `/api/projects/${otherProjectId}/scans`, t, { ref: 'main' })).data).toMatchObject({ data: { code: 'E_TOKEN_SCOPE' } })
      const bad = unsignedJwt(actionsClaims(ISS, 'equipe/app', 'refs/heads/main'))
      const r = await call('POST', `/api/projects/${projectId}/scans`, bad, { ref: 'main' })
      expect(r.status).toBe(401)
      expect(r.data).toMatchObject({ data: { code: 'E_TOKEN_INVALID' } })
      expect(oidcRefusalCounts()).toMatchObject({ E_OIDC_BINDING: 1, E_OIDC_ALG: 1 })
      const rows = await audits('ci.oidc-refuse')
      expect(rows.at(-1)).toMatchObject({ outcome: 'denied', details: { reason: 'E_OIDC_ALG' } })
      expect(rows.findLast(x => x.details.reason === 'E_OIDC_BINDING')?.details).toMatchObject({ repository: 'equipe/app', ref: 'refs/heads/main', issuer: 'forge.exemple.test' })
      const all = JSON.stringify((await db.pool.query('SELECT * FROM audit_log')).rows)
      expect(all).not.toContain(t.split('.')[2])
      expect(all).not.toContain(bad.split('.')[1])
    })

    it('jeton d’API : inchangé (projet du jeton seulement), libellé api-token', async () => {
      const { token: api, row } = await createApiToken(db.pool, { projectId, name: 'ci', expiresInDays: null, createdBy: null as unknown as number })
      const r = await call('POST', `/api/projects/${projectId}/scans`, api, { ref: 'v1.0.0' })
      expect(r.status).toBe(202)
      const scan = (await db.pool.query<{ api_token_id: string | null }>('SELECT api_token_id FROM scans WHERE id = $1', [r.data.scan_id])).rows[0]
      expect(scan!.api_token_id).toBe(row.id)
      expect((await call('POST', `/api/projects/${otherProjectId}/scans`, api, { ref: 'main' })).status).toBe(403)
      expect((await call('POST', `/api/projects/${projectId}/scans`, 'scn_inconnu', { ref: 'main' })).status).toBe(401)
    })

    it('une identité OIDC demande une exception (jamais une décision) ; aucune autre route n’accepte le jeton', async () => {
      expect((await call('GET', '/api/ci/whoami', token())).status).toBe(403)
      const event = { context: {}, node: { req: { headers: { authorization: `Bearer ${token()}` } } } }
      const auth = await authenticateCi(event as never, db.pool, projectId)
      expect(auth.identity).toMatchObject({ kind: 'oidc', isHuman: false })
      expect(auth.apiTokenId).toBeNull()
      // Mémorisé dans le contexte de la requête.
      expect(await authenticateCi(event as never, db.pool, projectId)).toBe(auth)
      await expect(authenticateCi({ context: {}, node: { req: { headers: {} } } } as never, db.pool)).rejects.toMatchObject({ status: 401 })
    })
  })
})
