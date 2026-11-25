// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// b39-live (chantier C de la 0.8) : intégration CI contre un VRAI Forgejo
// (conteneur lancé par tests/b39-live.sh, HTTPS avec une AC jetable) :
//   1. forge enregistrée avec le jeton d'un compte de service, découverte :
//      projet enrôlé, émetteur OIDC de la forge déclaré et projet lié (J4) ;
//   2. passe périodique (runCiIntegration) : une PR d'intégration ouverte dans
//      Forgejo, workflow rendu pour le projet et étape commune, jamais
//      fusionnée ; protection de branche seulement proposée ;
//   3. protection appliquée dans Forgejo après la décision d'un administrateur,
//      auditée ; état de la PR suivi (fermée dans Forgejo → « closed ») ;
//   4. OIDC : émetteur de test servi en HTTPS (AC de test), le vrai script de
//      l'étape (scanoria-ci.sh) obtient son jeton comme dans Forgejo Actions,
//      télécharge et vérifie le client, lance l'analyse sans aucun secret et
//      rend le verdict ; un jeton d'un autre dépôt est refusé (403), et le
//      jeton n'apparaît ni dans la sortie ni dans l'audit.
// Ignoré sans SCANORIA_FORGEJO_URL (lancé seulement par b39-live).

import { spawn } from 'node:child_process'
import { createHash, createSign, generateKeyPairSync, randomBytes } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { createServer, type Server } from 'node:https'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { createApp, createRouter, toNodeListener, type EventHandler } from 'h3'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { DATABASE_URL, createTestDatabase, type TestDatabase } from '../helpers/db'
import { loadConfig, setConfig } from '../../server/utils/config'
import { closePool } from '../../server/utils/db'
import { startConsole, stopConsole, waitReady } from '../../server/utils/runtime'
import { createUser } from '../../server/utils/users'
import { createHttpsTransport, setForgeTransport } from '../../server/forges/http'
import { setConsoleUrl } from '../../server/forges/context'
import { createForge } from '../../server/projects/forges'
import { discoverForge } from '../../server/projects/discover'
import { getForge } from '../../server/forges'
import { createBinding, createIssuer, defaultRefPatterns, listBindings, listIssuers, resetJwksThrottle } from '../../server/ci/oidc'
import { decideProtection, listIntegrationRequests, runCiIntegration } from '../../server/ci/integration'
import { badTokenLimiter, publicLimiter, tokenLimiter } from '../../server/middleware/api-token'

const FORGEJO = process.env.SCANORIA_FORGEJO_URL ?? ''
const ROOT = fileURLToPath(new URL('../../../', import.meta.url))
const CLIENT = join(ROOT, 'src/rootfs/usr/share/scanoria/client/scanoria-scan')
const CI_SCRIPT = join(ROOT, 'src/rootfs/usr/share/scanoria/ci-templates/scanoria-ci.sh')
const route = (p: string) => fileURLToPath(new URL(`../../server/api/${p}`, import.meta.url))

// Réponses JSON de Forgejo lues en profondeur.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Json = any

describe.skipIf(!DATABASE_URL || !FORGEJO)('b39-live : vrai Forgejo, PR d’intégration, protection, OIDC', { timeout: 120_000 }, () => {
  let db: TestDatabase
  let dir: string
  let consoleServer: Server
  let oidcServer: Server
  let consoleUrl: string
  let oidcUrl: string
  let forgeId: string
  let projectId: string
  let adminId: number
  const tokens = JSON.parse(readFileSync(process.env.SCANORIA_FORGEJO_TOKENS ?? '/dev/null', 'utf8') || '{}') as Record<'admin' | 'bot', string>
  const caFile = process.env.SCANORIA_FORGE_CA ?? '/dev/null'
  const ca = readFileSync(caFile, 'utf8')
  const transport = createHttpsTransport({ ca, refuseAddress: () => false })
  // Clé de signature de l'émetteur de test (jamais écrite sur disque).
  const key = generateKeyPairSync('rsa', { modulusLength: 2048 })
  const jwk = { ...key.publicKey.export({ format: 'jwk' }), kid: 'b39', alg: 'RS256', use: 'sig' }
  const runnerSecret = randomBytes(16).toString('hex')
  let tokenRepo = 'equipe/app'
  let tokenRef = 'refs/heads/main'
  let repoId = 0
  let issuedTokens: string[] = []

  async function fj(token: string, method: string, path: string, body?: unknown): Promise<Json> {
    const res = await transport(`${FORGEJO}/api/v1${path}`, {
      method, headers: { 'authorization': `token ${token}`, 'content-type': 'application/json', 'accept': 'application/json' },
      ...(body ? { body: JSON.stringify(body) } : {}),
    })
    const text = await res.text()
    if (res.status >= 400) throw new Error(`Forgejo ${method} ${path} : ${res.status} ${text.slice(0, 300)}`)
    return text ? JSON.parse(text) : null
  }

  function sign(claims: Record<string, unknown>): string {
    const b64 = (o: unknown) => Buffer.from(JSON.stringify(o)).toString('base64url')
    const input = `${b64({ alg: 'RS256', typ: 'JWT', kid: 'b39' })}.${b64(claims)}`
    return `${input}.${createSign('RSA-SHA256').update(input).sign(key.privateKey).toString('base64url')}`
  }

  /** Lance le vrai script de l'étape, avec l'environnement d'un job Forgejo Actions. */
  function runStep(env: Record<string, string>): Promise<{ code: number | null, out: string }> {
    return new Promise((resolve) => {
      const child = spawn('sh', [CI_SCRIPT], { env: { PATH: process.env.PATH ?? '/usr/bin:/bin', HOME: dir, ...env } })
      let out = ''
      const add = (d: Buffer) => {
        out += d.toString()
      }
      child.stdout.on('data', add)
      child.stderr.on('data', add)
      child.on('close', code => resolve({ code, out }))
    })
  }

  async function until<T>(what: string, fn: () => Promise<T | null | undefined | false>, ms = 60_000): Promise<T> {
    const end = Date.now() + ms
    for (;;) {
      const v = await fn()
      if (v) return v
      if (Date.now() > end) throw new Error(`délai dépassé : ${what}`)
      await new Promise(r => setTimeout(r, 300))
    }
  }

  beforeAll(async () => {
    db = await createTestDatabase()
    dir = await mkdtemp(join(tmpdir(), 'scanoria-b39-'))
    process.env.NUXT_SECRET_KEY_FILE = join(dir, 'secret.key')
    process.env.NUXT_SCANORIA_SCAN_CLIENT = CLIENT
    process.env.NUXT_CI_TEMPLATES_DIR = join(ROOT, 'src/rootfs/usr/share/scanoria/ci-templates')
    setConfig(loadConfig({
      NUXT_DATABASE_URL: db.url,
      NUXT_UPLOADS_DIR: join(dir, 'uploads'),
      NUXT_CATALOG_INDEX_FILE: join(dir, 'absent-index.json'),
      NUXT_MODULES_STATE_FILE: join(dir, 'absent-state.json'),
      NUXT_STATE_FILE: join(dir, 'state.json'),
      NUXT_MIGRATE_ON_START: '0',
      NUXT_INGEST_INTERVAL_MS: '600000',
    }))
    setForgeTransport(transport)
    void startConsole(async () => [])
    expect(await waitReady(30_000)).toBe(true)
    adminId = Number((await createUser(db.pool, { username: 'admin-b39', role: 'admin', password: randomBytes(12).toString('hex') })).id)

    // Console vue par la CI : vraies routes, derrière les vrais intergiciels.
    const app = createApp()
    app.use((await import('../../server/middleware/api-token')).default)
    app.use((await import('../../server/middleware/auth')).default)
    const router = createRouter()
    router.get('/api/gates/client', (await import(route('gates/client.get.ts'))).default as EventHandler)
    router.post('/api/projects/:id/scans', (await import(route('projects/[id]/scans.post.ts'))).default as EventHandler)
    router.get('/api/scans/:id/verdict', (await import(route('scans/[id]/verdict.get.ts'))).default as EventHandler)
    app.use(router)
    const tls = (name: string) => ({ cert: readFileSync(process.env[`SCANORIA_${name}_CERT`]!), key: readFileSync(process.env[`SCANORIA_${name}_KEY`]!) })
    consoleServer = createServer(tls('CONSOLE'), toNodeListener(app))
    await new Promise<void>(r => consoleServer.listen(0, '127.0.0.1', r))
    const caddr = consoleServer.address()
    consoleUrl = `https://analyse.exemple.test:${typeof caddr === 'object' && caddr ? caddr.port : 0}`
    setConsoleUrl(consoleUrl)

    // Émetteur OIDC de test : découverte, JWKS et service de jetons d'un runner
    // (ACTIONS_ID_TOKEN_REQUEST_URL), en HTTPS avec l'AC de test.
    oidcServer = createServer(tls('OIDC'), (req, res) => {
      const url = new URL(req.url ?? '/', oidcUrl)
      const json = (status: number, body: unknown) => {
        res.writeHead(status, { 'content-type': 'application/json' })
        res.end(JSON.stringify(body))
      }
      if (url.pathname === '/.well-known/openid-configuration') return json(200, { issuer: oidcUrl, jwks_uri: `${oidcUrl}/jwks` })
      if (url.pathname === '/jwks') return json(200, { keys: [jwk] })
      if (url.pathname === '/token') {
        if (req.headers.authorization !== `Bearer ${runnerSecret}`) return json(401, { message: 'jeton du runner invalide' })
        const now = Math.floor(Date.now() / 1000)
        const t = sign({ iss: oidcUrl, aud: url.searchParams.get('audience'), iat: now, nbf: now, exp: now + 300, repository: tokenRepo, repository_id: repoId, ref: tokenRef, run_id: '7', actor: 'dev-une' })
        issuedTokens.push(t)
        return json(200, { value: t })
      }
      json(404, {})
    })
    await new Promise<void>(r => oidcServer.listen(0, '127.0.0.1', r))
    const oaddr = oidcServer.address()
    oidcUrl = `https://oidc.exemple.test:${typeof oaddr === 'object' && oaddr ? oaddr.port : 0}`

    // Dépôt de l'équipe, avec une CI Forgejo déjà en place.
    await fj(tokens.admin, 'POST', '/orgs', { username: 'equipe', visibility: 'private' })
    await fj(tokens.admin, 'POST', '/orgs/equipe/repos', { name: 'app', auto_init: true, default_branch: 'main', private: true })
    await fj(tokens.admin, 'PUT', '/repos/equipe/app/collaborators/scanoria-bot', { permission: 'admin' })
    await fj(tokens.admin, 'POST', '/repos/equipe/app/contents/.forgejo/workflows/ci.yml', {
      content: Buffer.from('on: push\njobs:\n  tests:\n    runs-on: docker\n    steps:\n      - run: echo ok\n').toString('base64'), message: 'ci', branch: 'main',
    })
  }, 150_000)

  afterAll(async () => {
    setConsoleUrl()
    setForgeTransport()
    delete process.env.NUXT_SCANORIA_SCAN_CLIENT
    delete process.env.NUXT_CI_TEMPLATES_DIR
    await new Promise(r => consoleServer?.close(r))
    await new Promise(r => oidcServer?.close(r))
    stopConsole()
    await closePool()
    delete process.env.NUXT_SECRET_KEY_FILE
    await db?.drop()
    if (dir) await rm(dir, { recursive: true, force: true })
  })

  it('1. enrôlement : projet, émetteur OIDC de la forge déclaré et projet lié', async () => {
    const res = await createForge(db.pool, { kind: 'forgejo', name: 'Forgejo', base_url: FORGEJO, token: tokens.bot, discovery: true }, { type: 'system' })
    forgeId = res.forge.id
    const r = await discoverForge(db.pool, (await getForge(db.pool, forgeId))!)
    expect(r.error).toBeNull()
    expect(r.created).toHaveLength(1)
    projectId = r.created[0]!
    const issuers = await listIssuers(db.pool)
    expect(issuers).toEqual([expect.objectContaining({ kind: 'forgejo', issuer: `${FORGEJO}/api/actions`, audience: 'scanoria', enabled: true })])
    // Identifiant immuable du dépôt épinglé dès l'enrôlement (API de Forgejo).
    repoId = (await fj(tokens.admin, 'GET', '/repos/equipe/app')).id
    expect((await listBindings(db.pool, projectId)).map(b => [b.repository, b.repository_id, b.ref_patterns])).toEqual([['equipe/app', String(repoId), ['refs/heads/main', 'refs/tags/*', 'refs/pull/*']]])
  })

  it('2. passe périodique : une PR d’intégration dans Forgejo, jamais fusionnée ; protection proposée', async () => {
    // Détection F1 (normalement faite par la même passe) et mode poussé.
    await db.pool.query(`UPDATE projects SET release_mode = 'push', detection = $2 WHERE id = $1`, [projectId, JSON.stringify({
      version: 1, analyzed_at: new Date().toISOString(), ref: 'main', commit: null, truncated: false, files: 2, languages: [], language_files: {},
      package_managers: [], missing_lockfiles: [], containers: [], iac: { terraform: false, kubernetes: false, helm: false, ansible: false },
      ci: [{ kind: 'forgejo-actions', path: '.forgejo/workflows/ci.yml' }], shell_scripts: 0, license: null, categories: [], profile: 'complet', pr_profile: 'rapide', modules: [], coverage_gaps: [],
    })])
    const out = await runCiIntegration(db.pool)
    expect(out.errors).toBe(0)
    const pulls = (await fj(tokens.admin, 'GET', '/repos/equipe/app/pulls?state=all')) as Json[]
    expect(pulls).toHaveLength(1)
    const pr = pulls[0]
    expect(pr).toMatchObject({ state: 'open', merged: false, base: { ref: 'main' } })
    expect(pr.head.ref).toMatch(/^scanoria\/integration-/)
    expect(pr.user.login).toBe('scanoria-bot')
    const file = async (path: string) => Buffer.from((await fj(tokens.admin, 'GET', `/repos/equipe/app/contents/${path}?ref=${encodeURIComponent(pr.head.ref)}`)).content, 'base64').toString()
    const wf = await file('.forgejo/workflows/scanoria.yml')
    expect(wf).toContain(`SCANORIA_URL: ${consoleUrl}`)
    expect(wf).toContain(`SCANORIA_PROJECT: ${projectId}`)
    expect(wf).toContain('enable-openid-connect: true')
    const sha = createHash('sha256').update(await readFile(CLIENT)).digest('hex')
    expect(wf).toContain(`SCANORIA_CLIENT_SHA256: "${sha}"`)
    expect(await file('.forgejo/scanoria/scanoria-ci.sh')).toBe(await readFile(CI_SCRIPT, 'utf8'))
    // Rien sur main tant que la PR n'est pas fusionnée par une personne.
    await expect(fj(tokens.admin, 'GET', '/repos/equipe/app/contents/.forgejo/workflows/scanoria.yml?ref=main')).rejects.toThrow(/404/)
    expect((await fj(tokens.admin, 'GET', '/repos/equipe/app/branch_protections')) as Json[]).toEqual([])
    const reqs = await listIntegrationRequests(db.pool, projectId)
    expect(reqs.map(x => `${x.kind}:${x.state}`).sort()).toEqual(['branch-protection:proposed', 'ci-pr:open'])
    // Seconde passe : aucune nouvelle PR.
    await runCiIntegration(db.pool)
    expect((await fj(tokens.admin, 'GET', '/repos/equipe/app/pulls?state=all')) as Json[]).toHaveLength(1)
  })

  it('3. protection appliquée après la décision d’un administrateur ; PR fermée suivie', async () => {
    const req = (await listIntegrationRequests(db.pool, projectId)).find(x => x.kind === 'branch-protection')!
    const out = await decideProtection(db.pool, projectId, req.id, { action: 'apply', userId: adminId, username: 'admin-b39' })
    expect(out).toMatchObject({ state: 'applied', decided_by_username: 'admin-b39' })
    const rules = (await fj(tokens.admin, 'GET', '/repos/equipe/app/branch_protections')) as Json[]
    expect(rules).toHaveLength(1)
    expect(rules[0]).toMatchObject({ enable_status_check: true, status_check_contexts: ['scanoria/rapide'] })
    expect((await db.pool.query(`SELECT count(*)::int AS n FROM audit_log WHERE action = 'integration.protection-apply' AND outcome = 'success'`)).rows[0].n).toBe(1)
    // La PR fermée par une personne dans Forgejo : état suivi, jamais rouverte seule.
    await fj(tokens.admin, 'PATCH', '/repos/equipe/app/pulls/1', { state: 'closed' })
    await runCiIntegration(db.pool)
    expect((await listIntegrationRequests(db.pool, projectId)).find(x => x.kind === 'ci-pr')!.state).toBe('closed')
    expect(((await fj(tokens.admin, 'GET', '/repos/equipe/app/pulls?state=all')) as Json[]).map(p => p.state)).toEqual(['closed'])
  })

  it('4. OIDC : l’étape Forgejo lance l’analyse sans secret ; un autre dépôt est refusé', async () => {
    const { id: issuerId } = await createIssuer(db.pool, { kind: 'forgejo', issuer: oidcUrl })
    expect(await createBinding(db.pool, { issuerId, projectId, repository: 'equipe/app', repositoryId: String(repoId), refPatterns: defaultRefPatterns('forgejo', 'main') })).toBeTruthy()
    resetJwksThrottle()
    for (const l of [publicLimiter, badTokenLimiter, tokenLimiter]) l.reset('127.0.0.1')
    const env = {
      SCANORIA_URL: consoleUrl, SCANORIA_PROJECT: projectId, SCANORIA_MODE: 'push', SCANORIA_CACERT: caFile,
      SCANORIA_CLIENT_SHA256: createHash('sha256').update(await readFile(CLIENT)).digest('hex'), SCANORIA_TIMEOUT: '60', SCANORIA_INTERVAL: '1',
      ACTIONS_ID_TOKEN_REQUEST_URL: `${oidcUrl}/token?api-version=2.0`, ACTIONS_ID_TOKEN_REQUEST_TOKEN: runnerSecret, SCANORIA_OIDC_CACERT: caFile,
      GITHUB_REF_NAME: 'main', GITHUB_OUTPUT: join(dir, 'output'),
    }
    // Le runner crée le fichier des sorties de l'étape avant le job.
    await writeFile(join(dir, 'output'), '')
    const seen = new Set<string>()
    // Le worker n'est pas lancé ici : l'analyse créée par l'étape est terminée à la main.
    async function runAndPass(extra: Record<string, string> = {}) {
      let done: { code: number | null, out: string } | null = null
      const step = runStep({ ...env, ...extra }).then(r => (done = r))
      const scan = await until('analyse créée par la CI', async () => {
        if (done) throw new Error(`étape terminée sans analyse (code ${done.code}) :\n${done.out}`)
        return (await db.pool.query(
          `SELECT id, ref, api_token_id FROM scans WHERE project_id = $1 AND NOT (id::text = ANY($2::text[]))`, [projectId, [...seen]])).rows[0]
      })
      seen.add(scan.id)
      expect(scan.api_token_id).toBeNull()
      await db.pool.query(`UPDATE scans SET status = 'done', finished_at = now(), verdict = 'passed', verdict_details = $2 WHERE id = $1`,
        [scan.id, JSON.stringify({ verdict: 'passed', reasons: [], exceptions_applied: [] })])
      return { ...(await step), scan }
    }
    const ok = await runAndPass()
    const scan = ok.scan
    expect(ok.out).toContain('scanoria')
    expect(ok.code).toBe(0)
    expect(await readFile(join(dir, 'output'), 'utf8')).toContain('verdict=passed')
    const audit = (await db.pool.query<{ actor_username: string }>(
      `SELECT actor_username FROM audit_log WHERE action = 'scan.request' AND target_id = $1`, [scan.id])).rows
    expect(audit).toEqual([{ actor_username: 'oidc:equipe/app@refs/heads/main' }])

    // Étape d'une PR (ref refs/pull/N/merge, comme dans Forgejo Actions) : acceptée.
    tokenRef = 'refs/pull/1/merge'
    const pr = await runAndPass()
    expect(pr.code).toBe(0)
    tokenRef = 'refs/heads/main'

    // Même nom, autre identifiant (dépôt recréé par un tiers) : refusé.
    repoId += 1000
    const recreated = await runStep(env)
    expect(recreated.code).toBe(3)
    expect((await db.pool.query<{ details: Json }>(`SELECT details FROM audit_log WHERE action = 'ci.oidc-refuse' ORDER BY id DESC LIMIT 1`)).rows[0]!.details.reason).toBe('E_OIDC_REPOSITORY_ID')
    repoId -= 1000

    // Jeton d'un autre dépôt, même émetteur : 403, et code 3 du client.
    tokenRepo = 'equipe/autre'
    const refused = await runStep(env)
    expect(refused.code).toBe(3)
    expect(refused.out).toMatch(/liaison OIDC/)
    const refusal = (await db.pool.query<{ details: Json }>(`SELECT details FROM audit_log WHERE action = 'ci.oidc-refuse' ORDER BY id DESC LIMIT 1`)).rows[0]!
    expect(refusal.details).toMatchObject({ reason: 'E_OIDC_BINDING', repository: 'equipe/autre' })
    // Aucun jeton dans la sortie de l'étape ni dans l'audit.
    const all = JSON.stringify((await db.pool.query('SELECT details FROM audit_log')).rows)
    for (const t of issuedTokens) {
      const sig = t.split('.')[2]!
      expect([ok.out, pr.out, recreated.out, refused.out, all].some(x => x.includes(sig))).toBe(false)
    }
    issuedTokens = []
  })
})
