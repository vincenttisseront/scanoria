// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// b34-live (chantier D de la 0.7) : chaîne complète contre un VRAI Forgejo
// (conteneur lancé par tests/b34-live.sh, HTTPS avec une AC jetable) :
//   1. forge enregistrée avec le jeton d'un compte de service, découverte :
//      projet créé, webhook signé posé dans Forgejo ;
//   2. un développeur pousse un faux secret sur une branche et ouvre une PR :
//      Forgejo livre le webhook signé à la console, l'analyse de PR est mise
//      en file (fichiers modifiés lus dans Forgejo) ;
//   3. le premier module terminé trouve le secret : statut d'échec anticipé
//      publié dans Forgejo avant la fin de l'analyse (V8) ;
//   4. fin de l'analyse : un seul commentaire de synthèse, annotation sur la
//      ligne, statut d'échec ;
//   5. une relectrice commente /scanoria accept dans Forgejo : demande
//      d'exception (jamais une approbation) et réponse dans la PR ;
//   6. approbation dans la console par un administrateur, verdict réévalué
//      sans réanalyse : le statut passe au vert dans Forgejo.
// Ignoré sans SCANORIA_FORGEJO_URL (lancé seulement par b34-live).

import { randomBytes, randomUUID } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
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
import { publishScan } from '../../server/forges/publish'
import { shortId } from '../../server/forges/summary'
import { finalizeScanFindings, ingestModuleOutputs } from '../../server/findings/ingest'
import { evaluateGate } from '../../server/gates/evaluate'
import { applyPullRequestBaseline } from '../../server/gates/pr-baseline'
import { checkEarlyFailure } from '../../server/scans/early'
import { publicLimiter } from '../../server/middleware/api-token'

const FORGEJO = process.env.SCANORIA_FORGEJO_URL ?? ''
const MODULES = fileURLToPath(new URL('../../../modules/', import.meta.url))
const ROUTE = fileURLToPath(new URL('../../server/api/forges/[id]/webhook.post.ts', import.meta.url))

// Réponses JSON de Forgejo lues en profondeur.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Json = any

describe.skipIf(!DATABASE_URL || !FORGEJO)('b34-live : vrai Forgejo, PR, webhooks, /scanoria accept', { timeout: 90_000 }, () => {
  let db: TestDatabase
  let dir: string
  let server: Server
  let consoleUrl: string
  let forgeId: string
  let projectId: string
  let scanId: string
  let headSha: string
  let findingId: string
  let adminId: number
  const tokens = JSON.parse(readFileSync(process.env.SCANORIA_FORGEJO_TOKENS ?? '/dev/null', 'utf8') || '{}') as Record<'admin' | 'bot' | 'dev' | 'reviewer', string>
  const ca = readFileSync(process.env.SCANORIA_FORGE_CA ?? '/dev/null', 'utf8')
  const transport = createHttpsTransport({ ca, refuseAddress: () => false })
  const scansDir = () => join(dir, 'scans')

  /** Appel direct de l'API de Forgejo (préparation et vérifications du test). */
  async function fj(token: string, method: string, path: string, body?: unknown): Promise<Json> {
    const res = await transport(`${FORGEJO}/api/v1${path}`, {
      method, headers: { 'authorization': `token ${token}`, 'content-type': 'application/json', 'accept': 'application/json' },
      ...(body ? { body: JSON.stringify(body) } : {}),
    })
    const text = await res.text()
    if (res.status >= 400) throw new Error(`Forgejo ${method} ${path} : ${res.status} ${text.slice(0, 300)}`)
    return text ? JSON.parse(text) : null
  }

  async function until<T>(what: string, fn: () => Promise<T | null | undefined | false>, ms = 60_000): Promise<T> {
    const end = Date.now() + ms
    for (;;) {
      const v = await fn()
      if (v) return v
      if (Date.now() > end) throw new Error(`délai dépassé : ${what}`)
      await new Promise(r => setTimeout(r, 500))
    }
  }

  const statuses = async () => (await fj(tokens.admin, 'GET', `/repos/equipe/app/commits/${headSha}/statuses`)) as Json[]
  const botComments = async (n: number) => ((await fj(tokens.admin, 'GET', `/repos/equipe/app/issues/${n}/comments`)) as Json[]).filter(c => c.user.login === 'scanoria-bot')

  beforeAll(async () => {
    db = await createTestDatabase()
    dir = await mkdtemp(join(tmpdir(), 'scanoria-b34-'))
    process.env.NUXT_SECRET_KEY_FILE = join(dir, 'secret.key')
    const index = { schema: 1, version: 1, modules: [{ id: 'gitleaks', version: '1.0.0', categories: ['secrets'] }, { id: 'trivy', version: '1.0.0', categories: ['sca'] }] }
    await writeFile(join(dir, 'catalog-index.json'), JSON.stringify(index))
    setConfig(loadConfig({
      NUXT_DATABASE_URL: db.url,
      NUXT_UPLOADS_DIR: join(dir, 'uploads'),
      NUXT_CATALOG_INDEX_FILE: join(dir, 'catalog-index.json'),
      NUXT_MODULES_STATE_FILE: join(dir, 'absent-state.json'),
      NUXT_STATE_FILE: join(dir, 'state.json'),
      NUXT_MIGRATE_ON_START: '0',
      NUXT_INGEST_INTERVAL_MS: '600000',
    }))
    setForgeTransport(transport)
    void startConsole(async () => [])
    expect(await waitReady(30_000)).toBe(true)
    adminId = Number((await createUser(db.pool, { username: 'admin-b34', role: 'admin', password: randomBytes(12).toString('hex') })).id)

    // Console vue par Forgejo : la vraie route du webhook, derrière les vrais intergiciels.
    const app = createApp()
    app.use((await import('../../server/middleware/api-token')).default)
    app.use((await import('../../server/middleware/auth')).default)
    const router = createRouter()
    router.post('/api/forges/:id/webhook', (await import(ROUTE)).default as EventHandler)
    app.use(router)
    server = createServer({ cert: readFileSync(process.env.SCANORIA_CONSOLE_CERT!), key: readFileSync(process.env.SCANORIA_CONSOLE_KEY!) }, toNodeListener(app))
    await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve))
    const addr = server.address()
    consoleUrl = `https://analyse.exemple.test:${typeof addr === 'object' && addr ? addr.port : 0}`
    setConsoleUrl(consoleUrl)
    publicLimiter.reset('127.0.0.1')

    // Dépôt de l'équipe : le compte de service et le développeur y écrivent.
    await fj(tokens.admin, 'POST', '/orgs', { username: 'equipe', visibility: 'private' })
    await fj(tokens.admin, 'POST', '/orgs/equipe/repos', { name: 'app', auto_init: true, default_branch: 'main', private: true })
    // Le compte de service administre le dépôt (webhooks) ; les personnes y écrivent.
    for (const [user, permission] of [['scanoria-bot', 'admin'], ['dev-une', 'write'], ['relectrice', 'write']]) {
      await fj(tokens.admin, 'PUT', `/repos/equipe/app/collaborators/${user}`, { permission })
    }
  }, 120_000)

  afterAll(async () => {
    setConsoleUrl()
    setForgeTransport()
    await new Promise(resolve => server?.close(resolve))
    stopConsole()
    await closePool()
    delete process.env.NUXT_SECRET_KEY_FILE
    await db?.drop()
    if (dir) await rm(dir, { recursive: true, force: true })
  })

  it('1. jeton de service, découverte : projet et webhook signé dans Forgejo', async () => {
    const res = await createForge(db.pool, { kind: 'forgejo', name: 'Forgejo', base_url: FORGEJO, token: tokens.bot, discovery: true }, { type: 'system' })
    forgeId = res.forge.id
    expect(res.login).toBe('scanoria-bot')
    expect(res.forge.integration.app).toBe('forgejo-token')
    const r = await discoverForge(db.pool, (await getForge(db.pool, forgeId))!)
    expect(r.error).toBeNull()
    expect(r.created).toHaveLength(1)
    projectId = r.created[0]!
    expect(r.webhooks).toBe(1)
    const hooks = (await fj(tokens.admin, 'GET', '/repos/equipe/app/hooks')) as Json[]
    expect(hooks.map(h => h.config.url)).toEqual([`${consoleUrl}/api/forges/${forgeId}/webhook`])
  })

  it('2. PR avec un faux secret : webhook signé reçu, analyse de PR incrémentale en file', async () => {
    // Faux secret généré à l'exécution (aucune valeur fixe dans le dépôt).
    const fake = `API_KEY=${randomBytes(20).toString('hex')}\n`
    await fj(tokens.dev, 'POST', '/repos/equipe/app/contents/config/settings.env', {
      content: Buffer.from(fake).toString('base64'), message: 'ajoute la configuration', branch: 'main', new_branch: 'feat/config',
    })
    const pr = await fj(tokens.dev, 'POST', '/repos/equipe/app/pulls', { head: 'feat/config', base: 'main', title: 'Configuration' })
    headSha = pr.head.sha
    const scan = await until('analyse de la PR', async () => (await db.pool.query(
      `SELECT id, ref, commit_sha, incremental, pull_request FROM scans WHERE project_id = $1 AND pull_request IS NOT NULL`, [projectId])).rows[0])
    scanId = scan.id
    expect(scan).toMatchObject({ ref: `refs/pull/${pr.number}/head`, commit_sha: headSha, incremental: true })
    expect(scan.pull_request).toMatchObject({ number: pr.number, changed_files: ['config/settings.env'], author: 'dev-une' })
    const deliveries = await db.pool.query(`SELECT status FROM webhook_deliveries WHERE forge_id = $1 AND status = 'accepted'`, [forgeId])
    expect(deliveries.rowCount).toBeGreaterThan(0)
  })

  it('3. secret trouvé par le premier module : échec anticipé publié dans Forgejo (V8)', async () => {
    const jobId = randomUUID()
    await db.pool.query(`UPDATE scans SET status = 'running', job_id = $2, started_at = now(), plan = $3 WHERE id = $1`,
      [scanId, jobId, JSON.stringify({ modules: [{ id: 'gitleaks' }, { id: 'trivy' }] })])
    for (const m of ['gitleaks', 'trivy']) await db.pool.query(`INSERT INTO scan_modules (scan_id, module_id, module_version, status) VALUES ($1, $2, '1.0.0', 'running')`, [scanId, m])
    // Sortie réelle de gitleaks (enregistrement du module), placée sur le fichier de la PR.
    const sarif = JSON.parse(await readFile(`${MODULES}gitleaks/tests/recorded.sarif`, 'utf8'))
    const result = sarif.runs[0].results[0]
    result.locations[0].physicalLocation.artifactLocation.uri = 'config/settings.env'
    result.locations[0].physicalLocation.region = { startLine: 1, endLine: 1 }
    sarif.runs[0].results = [result]
    const rdir = join(scansDir(), 'results', jobId)
    await mkdir(join(rdir, 'gitleaks'), { recursive: true })
    await writeFile(join(rdir, 'gitleaks', 'result.sarif'), JSON.stringify(sarif))
    await writeFile(join(rdir, 'progress.json'), JSON.stringify({ schema: 1, modules: [{ id: 'gitleaks', status: 'ok', outputs: { sarif: 'gitleaks/result.sarif' } }] }))
    const scan = { id: scanId, job_id: jobId, plan: { modules: [{ id: 'gitleaks' }, { id: 'trivy' }] } }
    const reasons = await checkEarlyFailure(db.pool, {
      ingestModuleOutputs, finalizeScanFindings, evaluateGate,
      publish: (pool, id, why) => publishScan(pool, id, { phase: 'early', earlyReasons: why }),
    }, scan, scansDir(), new Set())
    expect(reasons).toEqual(['secret'])
    const st = await statuses()
    expect(st[0]).toMatchObject({ status: 'failure' })
    expect(st[0].context).toMatch(/^scanoria\//)
    expect(st[0].target_url.startsWith(`${consoleUrl}/`)).toBe(true)
    expect((await db.pool.query('SELECT status FROM scans WHERE id = $1', [scanId])).rows[0].status).toBe('running')
  })

  it('4. fin de l’analyse : un seul commentaire, annotation sur la ligne, statut d’échec', async () => {
    await db.pool.query(`UPDATE scan_modules SET status = 'ok', finished_at = now() WHERE scan_id = $1`, [scanId])
    await finalizeScanFindings(db.pool, scanId, { complete: false })
    await applyPullRequestBaseline(db.pool, scanId)
    const details = await evaluateGate(db.pool, scanId)
    expect(details.verdict).toBe('failed')
    findingId = details.reasons.find(r => r.code === 'secret')!.finding_ids[0]!
    await db.pool.query(`UPDATE scans SET status = 'done', finished_at = now(), verdict = $2, verdict_details = $3 WHERE id = $1`,
      [scanId, details.verdict, JSON.stringify(details)])
    expect(await publishScan(db.pool, scanId, { phase: 'final' })).toBe('published')
    const comments = await botComments(1)
    expect(comments).toHaveLength(1)
    expect(comments[0].body).toContain(shortId(findingId))
    expect(comments[0].body).toContain('/scanoria accept')
    const reviews = (await fj(tokens.admin, 'GET', '/repos/equipe/app/pulls/1/reviews')) as Json[]
    expect(reviews.length).toBeGreaterThan(0)
    const rc = (await fj(tokens.admin, 'GET', `/repos/equipe/app/pulls/1/reviews/${reviews.at(-1).id}/comments`)) as Json[]
    expect(rc[0]).toMatchObject({ path: 'config/settings.env' })
    expect((await statuses())[0].status).toBe('failure')
  })

  it('5. /scanoria accept par une relectrice : demande d’exception, réponse dans la PR', async () => {
    const day = new Date(Date.now() + 30 * 86400_000).toISOString().slice(0, 10)
    await fj(tokens.reviewer, 'POST', '/repos/equipe/app/issues/1/comments', { body: `/scanoria accept ${shortId(findingId)} --until ${day} --reason "valeur factice de test"` })
    const ex = await until('demande d’exception', async () => (await db.pool.query(
      `SELECT id, status, requested_via, requester_label, requester_is_human, commit_authors, created_by FROM exceptions WHERE project_id = $1`, [projectId])).rows[0])
    expect(ex).toMatchObject({ status: 'requested', requested_via: 'pr-comment', requester_label: 'forgejo:relectrice', requester_is_human: false, created_by: null })
    expect(ex.commit_authors).toEqual(expect.arrayContaining(['dev-une']))
    await until('réponse dans la PR', async () => (await botComments(1)).length === 2)
    // Une commande malformée reçoit une aide, rien n'est créé.
    await fj(tokens.reviewer, 'POST', '/repos/equipe/app/issues/1/comments', { body: '/scanoria accept' })
    await until('aide dans la PR', async () => (await botComments(1)).length === 3)
    expect((await db.pool.query('SELECT count(*)::int AS n FROM exceptions WHERE project_id = $1', [projectId])).rows[0].n).toBe(1)
    // Toujours rouge : une demande ne débloque rien.
    expect((await statuses())[0].status).toBe('failure')
  })

  it('6. approbation dans la console, verdict réévalué sans réanalyse : statut vert', async () => {
    const before = (await db.pool.query('SELECT count(*)::int AS n FROM scans WHERE project_id = $1', [projectId])).rows[0].n
    // Décision d'un administrateur humain, ni demandeur ni auteur du commit (circuit du contrat 27).
    await db.pool.query(`UPDATE exceptions SET status = 'approved', decided_by = $2, decided_at = now(), decision_reason = 'vu en revue' WHERE project_id = $1`, [projectId, adminId])
    const details = await evaluateGate(db.pool, scanId)
    expect(details.verdict).toBe('passed')
    expect(details.exceptions_applied.length).toBe(1)
    await db.pool.query('UPDATE scans SET verdict = $2, verdict_details = $3 WHERE id = $1', [scanId, details.verdict, JSON.stringify(details)])
    expect(await publishScan(db.pool, scanId, { phase: 'final' })).toBe('published')
    expect((await statuses())[0].status).toBe('success')
    expect((await botComments(1)).filter(c => String(c.body).startsWith('### '))).toHaveLength(1)
    expect((await db.pool.query('SELECT count(*)::int AS n FROM scans WHERE project_id = $1', [projectId])).rows[0].n).toBe(before)
  })
})
