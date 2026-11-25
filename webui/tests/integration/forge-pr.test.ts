// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Chantier D de la 0.7 contre PostgreSQL et une fausse forge en écriture :
// enrôlement (J1 : webhooks posés, dépôt archivé suspendu puis repris),
// webhooks signés (rejets comptés, rejeu refusé), analyse de PR incrémentale
// (G18), publication (statut, commentaire unique mis à jour, annotations),
// /scanoria accept (J15 : demande seulement), mode tiré, base de la PR,
// application GitHub en un clic.

import { createHmac, createPublicKey, randomBytes, randomUUID, verify } from 'node:crypto'
import { mkdtemp, rm } from 'node:fs/promises'
import type { IncomingMessage } from 'node:http'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { Readable } from 'node:stream'
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest'
import { DATABASE_URL, createTestDatabase, type TestDatabase } from '../helpers/db'
import { addComment, addPr, addRepo, startFakePrForge, type FakePrForge, type FakeRepoState } from '../helpers/fake-pr-forge'
import { loadConfig, setConfig } from '../../server/utils/config'
import { setForgeRetryDelays } from '../../server/forges/http'
import { createForge } from '../../server/projects/forges'
import { discoverForge } from '../../server/projects/discover'
import { getForge } from '../../server/forges'
import { setConsoleUrl } from '../../server/forges/context'
import { MAX_REJECTS_PER_HOUR, readBounded, receiveWebhook } from '../../server/forges/webhook'
import { publishScan } from '../../server/forges/publish'
import { shortId } from '../../server/forges/summary'
import { MAX_COMMANDS_PER_HOUR } from '../../server/forges/pr'
import { forgeMode, forgeIntegration } from '../../server/forges/status'
import { nightlyFullScans, pollPullRequests, resetPullRequestPolling } from '../../server/forges/poll'
import { applyPullRequestBaseline, isPullRequestScan, pullRequestBaseline } from '../../server/gates/pr-baseline'
import {
  addInstallation, removeInstallation, appJwt, clearInstallationTokens, convertManifest, getForgeApp, installationToken, manifestTarget,
  refreshAppCredential, saveGithubApp, startGithubManifest, verifyInstallation, verifyManifestState, webhookSecret,
} from '../../server/forges/apps'

const HOST = 'forge.exemple.test'
const CONSOLE = 'https://analyse.exemple.test'

describe.skipIf(!DATABASE_URL)('forges, PR et webhooks (chantier D, PostgreSQL)', () => {
  let db: TestDatabase
  let dir: string
  let fake: FakePrForge
  let app: FakeRepoState
  let forgeId: string
  let projectId: string
  let secret: string
  const actor = { type: 'system' as const }

  const sign = (body: string) => createHmac('sha256', secret).update(body).digest('hex')
  async function hook(event: string, payload: unknown, opts: { delivery?: string, sig?: string } = {}) {
    const body = Buffer.from(JSON.stringify(payload))
    const out = await receiveWebhook(db.pool, forgeId, {
      'x-forgejo-event': event,
      'x-forgejo-delivery': opts.delivery ?? randomUUID(),
      'x-forgejo-signature': opts.sig ?? sign(body.toString()),
    }, body)
    const work = out.work ? await out.work : null
    return { ...out, work }
  }
  const prEvent = (n: number) => ({ action: 'opened', number: n, pull_request: { number: n }, repository: { full_name: 'equipe/app' } })
  const commentEvent = (n: number, c: { id: number, body: string, user: { login: string, type: string } }) => ({
    action: 'created', is_pull: true, issue: { number: n, pull_request: {} }, comment: c, repository: { full_name: 'equipe/app' },
  })

  async function finding(scanId: string, p: { fp?: string, tool?: string, severity?: string, path?: string, line?: number, malicious?: boolean } = {}) {
    const r = await db.pool.query<{ id: string }>(
      `INSERT INTO findings (project_id, fingerprint, tool, rule_id, category, severity, title, path, start_line, malicious, secret_type, status)
       VALUES ($1, $2, $3, 'generic-api-key', 'secrets', $4, 'Secret probable', $5, $6, $7, 'generic', 'new')
       ON CONFLICT (project_id, fingerprint) DO UPDATE SET title = EXCLUDED.title RETURNING id`,
      [projectId, p.fp ?? randomBytes(32).toString('hex'), p.tool ?? 'gitleaks', p.severity ?? 'high', p.path ?? 'src/a.ts', p.line ?? 3, p.malicious ?? false])
    await db.pool.query('INSERT INTO scan_findings (scan_id, finding_id, is_new) VALUES ($1, $2, true) ON CONFLICT DO NOTHING', [scanId, r.rows[0]!.id])
    return r.rows[0]!.id
  }

  beforeAll(async () => {
    db = await createTestDatabase()
    dir = await mkdtemp(join(tmpdir(), 'scanoria-forge-pr-'))
    process.env.NUXT_SECRET_KEY_FILE = join(dir, 'secret.key')
    setConfig(loadConfig({
      NUXT_DATABASE_URL: db.url,
      NUXT_UPLOADS_DIR: join(dir, 'uploads'),
      NUXT_CATALOG_INDEX_FILE: join(dir, 'absent-index.json'),
      NUXT_MODULES_STATE_FILE: join(dir, 'absent-state.json'),
    }))
    setConsoleUrl(CONSOLE)
    setForgeRetryDelays([1, 1])
    fake = await startFakePrForge(HOST)
    app = addRepo(fake, 'equipe/app')
    app.permissions.relectrice = 'write'
    addRepo(fake, 'equipe/vieux', true)
    const res = await createForge(db.pool, { kind: 'forgejo', name: 'Forge', base_url: `https://${HOST}`, token: fake.token, discovery: true }, actor)
    forgeId = res.forge.id
    secret = (await webhookSecret(db.pool, forgeId))!
  })

  afterAll(async () => {
    setConsoleUrl()
    setForgeRetryDelays()
    await fake?.close()
    delete process.env.NUXT_SECRET_KEY_FILE
    await db?.drop()
    if (dir) await rm(dir, { recursive: true, force: true })
  })

  beforeEach(() => {
    resetPullRequestPolling()
  })

  describe('enrôlement (J1)', () => {
    it('jeton de service : application « forgejo-token », secret de webhook, portées affichées', async () => {
      const a = await getForgeApp(db.pool, forgeId)
      expect(a?.kind).toBe('forgejo-token')
      expect(secret).toMatch(/^[0-9a-f]{64}$/)
      const i = await forgeIntegration(db.pool, forgeId)
      expect(i.scopes).toContain('write:repository')
      expect(i.mode).toBe('pull')
    })

    it('découverte : projet créé, webhook signé posé une fois, dépôt archivé ignoré', async () => {
      const r = await discoverForge(db.pool, (await getForge(db.pool, forgeId))!)
      expect(r.error).toBeNull()
      expect(r.created).toHaveLength(1)
      projectId = r.created[0]!
      expect(app.hooks).toHaveLength(1)
      expect(app.hooks[0]!.config.url).toBe(`${CONSOLE}/api/forges/${forgeId}/webhook`)
      expect(app.hooks[0]!.config.secret).toBe(secret)
      expect(app.hooks[0]!.events).toContain('issue_comment')
      await discoverForge(db.pool, (await getForge(db.pool, forgeId))!)
      expect(app.hooks).toHaveLength(1)
    })

    it('dépôt archivé dans la forge : projet suspendu puis repris, audit à chaque fois', async () => {
      app.archived = true
      let r = await discoverForge(db.pool, (await getForge(db.pool, forgeId))!)
      expect(r.suspended).toEqual([projectId])
      const p = await db.pool.query('SELECT suspended_at, suspended_reason FROM projects WHERE id = $1', [projectId])
      expect(p.rows[0].suspended_reason).toBe('forge-archived')
      app.archived = false
      r = await discoverForge(db.pool, (await getForge(db.pool, forgeId))!)
      expect(r.resumed).toEqual([projectId])
      const audit = await db.pool.query(`SELECT action FROM audit_log WHERE target_id = $1 AND action LIKE 'project.%' ORDER BY id`, [projectId])
      expect(audit.rows.map(x => x.action)).toEqual(['project.suspend', 'project.resume'])
    })
  })

  describe('webhooks signés', () => {
    it('refus : forge inconnue, trop gros, signature fausse, sans identifiant ; chaque rejet compté', async () => {
      expect((await receiveWebhook(db.pool, randomUUID(), {}, Buffer.from('{}'))).status).toBe(404)
      expect((await receiveWebhook(db.pool, 'pas-un-uuid', {}, Buffer.from('{}'))).status).toBe(404)
      expect((await receiveWebhook(db.pool, forgeId, { 'x-forgejo-event': 'push' }, Buffer.alloc(1024 * 1024 + 1))).status).toBe(413)
      expect((await hook('push', { ref: 'refs/heads/main' }, { sig: sign('autre') })).status).toBe(401)
      const body = Buffer.from('{}')
      expect((await receiveWebhook(db.pool, forgeId, { 'x-forgejo-event': 'push', 'x-forgejo-signature': sign('{}') }, body)).status).toBe(400)
      const n = await db.pool.query(`SELECT count(*)::int AS n FROM webhook_deliveries WHERE forge_id = $1 AND status = 'rejected'`, [forgeId])
      expect(n.rows[0].n).toBeGreaterThanOrEqual(3)
      expect((await forgeIntegration(db.pool, forgeId)).rejected_webhooks_30d).toBeGreaterThanOrEqual(3)
    })

    it('PR ouverte : analyse incrémentale de la tête, fichiers modifiés de la forge ; rejeu refusé', async () => {
      const pr = addPr(app, { number: 1, files: ['src/a.ts', 'package.json'] })
      const delivery = randomUUID()
      const out = await hook('pull_request', prEvent(1), { delivery })
      expect(out.status).toBe(202)
      expect(out.work).toBe('ok')
      const s = await db.pool.query(`SELECT ref, commit_sha, incremental, pull_request, trigger FROM scans WHERE project_id = $1 AND pull_request IS NOT NULL`, [projectId])
      expect(s.rows).toHaveLength(1)
      expect(s.rows[0]).toMatchObject({ ref: 'refs/pull/1/head', commit_sha: pr.head, incremental: true, trigger: 'webhook' })
      expect(s.rows[0].pull_request).toMatchObject({ number: 1, base_sha: pr.base, changed_files: ['src/a.ts', 'package.json'], author: 'dev-une' })
      expect((await hook('pull_request', prEvent(1), { delivery })).status).toBe(409)
      // Même corps signé sous un autre identifiant (non signé) : rejeu aussi.
      expect((await hook('pull_request', prEvent(1))).status).toBe(409)
      // Même tête : aucune seconde analyse.
      await hook('pull_request', { ...prEvent(1), action: 'synchronized' })
      expect((await db.pool.query(`SELECT count(*)::int AS n FROM scans WHERE project_id = $1 AND pull_request IS NOT NULL`, [projectId])).rows[0].n).toBe(1)
      expect(await forgeMode(db.pool, forgeId)).toBe('push')
    })

    it('traitement en échec (forge injoignable) : la livraison est oubliée, la redélivrance est acceptée', async () => {
      addPr(app, { number: 7 })
      const delivery = randomUUID()
      const token = fake.token
      fake.token = 'jeton-change-0000000000000000'
      const first = await hook('pull_request', prEvent(7), { delivery })
      fake.token = token
      expect(first.status).toBe(202)
      expect(first.work).toBe('error')
      const again = await hook('pull_request', prEvent(7), { delivery })
      expect(again.status).toBe(202)
      expect(again.work).toBe('ok')
    })

    it('flot de rejets : au plus MAX_REJECTS_PER_HOUR lignes par forge et par heure', async () => {
      await db.pool.query(
        `INSERT INTO webhook_deliveries (forge_id, delivery_id, event, status, detail)
         SELECT $1, 'x-flot-' || g, 'push', 'rejected', 'signature' FROM generate_series(1, $2) g`, [forgeId, MAX_REJECTS_PER_HOUR])
      const count = async () => (await db.pool.query(`SELECT count(*)::int AS n FROM webhook_deliveries WHERE forge_id = $1 AND status = 'rejected'`, [forgeId])).rows[0].n as number
      const before = await count()
      expect((await hook('push', { ref: 'refs/heads/main' }, { sig: sign('autre') })).status).toBe(401)
      expect(await count()).toBe(before)
      await db.pool.query(`DELETE FROM webhook_deliveries WHERE forge_id = $1 AND delivery_id LIKE 'x-flot-%'`, [forgeId])
    })

    it('corps lu en flux : borne appliquée sans content-length (chunked), content-length invalide refusé', async () => {
      const req = (chunks: Buffer[], headers: Record<string, string> = {}) => Object.assign(Readable.from(chunks), { headers }) as unknown as IncomingMessage
      expect(await readBounded(req([Buffer.alloc(600), Buffer.alloc(600)]), 1000)).toBe('too-large')
      expect((await readBounded(req([Buffer.from('{"a":'), Buffer.from('1}')]), 1000) as Buffer).toString()).toBe('{"a":1}')
      expect(await readBounded(req([Buffer.from('{}')], { 'content-length': 'abc' }), 1000)).toBe('too-large')
      expect(await readBounded(req([Buffer.from('{}')], { 'content-length': '5000' }), 1000)).toBe('too-large')
    })

    it('évènements ignorés : action inutile, dépôt inconnu, branche non suivie', async () => {
      expect((await hook('pull_request', { ...prEvent(1), action: 'closed' })).work).toBe('pr-ignored')
      expect((await hook('pull_request', { ...prEvent(1), repository: { full_name: 'equipe/inconnu' } })).work).toBe('unknown-repository')
      expect((await hook('push', { ref: 'refs/heads/autre', after: 'a'.repeat(40), repository: { full_name: 'equipe/app' } })).work).toBe('branch-not-tracked')
      expect((await hook('star', {})).code).toBe('ignored')
    })
  })

  describe('publication dans la PR', () => {
    let scanId: string
    let fid: string

    beforeAll(async () => {
      scanId = (await db.pool.query<{ id: string }>(`SELECT id FROM scans WHERE project_id = $1 AND (pull_request ->> 'number')::int = 1`, [projectId])).rows[0]!.id
      fid = await finding(scanId)
      await db.pool.query(`UPDATE scans SET status = 'done', finished_at = now(), verdict = 'failed', verdict_details = $2 WHERE id = $1`, [scanId, JSON.stringify({
        verdict: 'failed', gate_id: randomUUID(), rules: {}, evaluated_at: new Date().toISOString(), new_code_only: true,
        counts: { critical: 0, high: 1, medium: 0, low: 0, info: 0 },
        reasons: [{ code: 'secret', blocking: true, count: 1, severity: 'high', module: 'gitleaks', finding_ids: [fid], actions: ['fix', 'request-exception'] }],
        exceptions_applied: [],
      })])
    })

    it('statut, commentaire unique (mis à jour en place) et annotations publiées une fois', async () => {
      expect(await publishScan(db.pool, scanId, { phase: 'final' })).toBe('published')
      const pr = app.prs.find(p => p.number === 1)!
      const st = app.statuses.filter(s => s.sha === pr.head)
      expect(st.at(-1)).toMatchObject({ state: 'failure' })
      expect(st.at(-1)!.context).toMatch(/^scanoria\//)
      expect(st.at(-1)!.target_url!.startsWith(`${CONSOLE}/`)).toBe(true)
      const bot = () => (app.comments.get(1) ?? []).filter(c => c.user.login === fake.login)
      expect(bot()).toHaveLength(1)
      expect(bot()[0]!.body).toContain(shortId(fid))
      expect(app.reviews).toHaveLength(1)
      expect(app.reviews[0]!.comments[0]).toMatchObject({ path: 'src/a.ts', new_position: 3 })
      await publishScan(db.pool, scanId, { phase: 'final' })
      expect(bot()).toHaveLength(1)
      expect(app.reviews).toHaveLength(1)
      const pubs = await db.pool.query(`SELECT kind, state FROM forge_publications WHERE scan_id = $1 ORDER BY kind`, [scanId])
      expect(pubs.rows.map(r => r.kind)).toEqual(expect.arrayContaining(['commit-status', 'pr-comment']))
    })

    it('/scanoria accept : demande d’exception par l’identité de la forge, auteurs du commit exclus', async () => {
      const c = addComment(fake, app, 1, 'relectrice', `/scanoria accept ${shortId(fid)} --until 2099-01-01 --reason "valeur factice de test"`)
      // Date trop lointaine : refusée sans exception.
      expect((await hook('issue_comment', commentEvent(1, c))).work).toBe('refused')
      const until = new Date(Date.now() + 30 * 86400_000).toISOString().slice(0, 10)
      const c2 = addComment(fake, app, 1, 'relectrice', `/scanoria accept ${shortId(fid)} --until ${until} --reason "valeur factice de test"`)
      expect((await hook('issue_comment', commentEvent(1, c2))).work).toBe('requested')
      const ex = await db.pool.query(`SELECT status, requested_via, requester_label, requester_is_human, commit_authors, created_by FROM exceptions WHERE project_id = $1`, [projectId])
      expect(ex.rows).toHaveLength(1)
      expect(ex.rows[0]).toMatchObject({ status: 'requested', requested_via: 'pr-comment', requester_label: 'forgejo:relectrice', requester_is_human: false, created_by: null })
      expect(ex.rows[0].commit_authors).toEqual(expect.arrayContaining(['dev-une']))
      // Le même commentaire, relu par l'interrogation : traité une seule fois.
      expect((await hook('issue_comment', { ...commentEvent(1, c2), sender: { login: 'relance' } })).work).toBe('ignored')
      const replies = (app.comments.get(1) ?? []).filter(x => x.user.login === fake.login)
      expect(replies.at(-1)!.body).toMatch(/Demande d.exception enregistrée/)
    })

    it('commande malformée : aide ; robot et réponse de Scanoria : ignorés', async () => {
      const c = addComment(fake, app, 1, 'relectrice', '/scanoria accept')
      expect((await hook('issue_comment', commentEvent(1, c))).work).toBe('help')
      expect((app.comments.get(1) ?? []).at(-1)!.body).toMatch(/Utilisation/)
      const robot = addComment(fake, app, 1, 'autre-robot', '/scanoria accept 1a2b3c4d --until 2027-01-01 --reason "abc"', 'Bot')
      expect((await hook('issue_comment', commentEvent(1, robot))).work).toBe('ignored')
      const self = addComment(fake, app, 1, fake.login, '/scanoria aide')
      expect((await hook('issue_comment', commentEvent(1, self))).work).toBe('ignored')
    })

    it('dépôt public : un compte sans droit d’écriture est refusé ; l’auteur de la PR peut demander', async () => {
      const until = new Date(Date.now() + 20 * 86400_000).toISOString().slice(0, 10)
      const cmd = `/scanoria accept ${shortId(fid)} --until ${until} --reason "valeur factice de test"`
      app.permissions.passant = 'read'
      const before = (await db.pool.query(`SELECT count(*)::int AS n FROM exceptions WHERE project_id = $1`, [projectId])).rows[0].n as number
      for (const login of ['inconnu', 'passant']) {
        const c = addComment(fake, app, 1, login, cmd)
        expect((await hook('issue_comment', commentEvent(1, c))).work).toBe('refused')
        expect((app.comments.get(1) ?? []).at(-1)!.body).toMatch(/Seuls l.auteur de la PR et les comptes qui ont le droit d.écriture/)
      }
      expect((await db.pool.query(`SELECT count(*)::int AS n FROM exceptions WHERE project_id = $1`, [projectId])).rows[0].n).toBe(before)
      // dev-une, autrice de la PR n° 1, sans droit déclaré sur le dépôt.
      const own = addComment(fake, app, 1, 'dev-une', cmd)
      expect((await hook('issue_comment', commentEvent(1, own))).work).toBe('requested')
      expect((await db.pool.query(`SELECT requester_label FROM exceptions WHERE project_id = $1 ORDER BY created_at DESC LIMIT 1`, [projectId])).rows[0].requester_label).toBe('forgejo:dev-une')
    })

    it('au plus MAX_COMMANDS_PER_HOUR commandes par PR et par identité ; une seule réponse au dépassement', async () => {
      app.permissions.bavard = 'write'
      const outcomes: string[] = []
      for (let i = 0; i < MAX_COMMANDS_PER_HOUR + 2; i++) {
        const c = addComment(fake, app, 1, 'bavard', '/scanoria aide')
        outcomes.push(String((await hook('issue_comment', commentEvent(1, c))).work))
      }
      expect(outcomes.slice(0, MAX_COMMANDS_PER_HOUR).every(o => o === 'help')).toBe(true)
      expect(outcomes.slice(MAX_COMMANDS_PER_HOUR)).toEqual(['limited', 'limited'])
      const mine = (app.comments.get(1) ?? []).filter(x => x.user.login === fake.login && /Trop de commandes Scanoria/.test(x.body))
      expect(mine).toHaveLength(1)
      expect(mine[0]!.body).toContain(`au plus ${MAX_COMMANDS_PER_HOUR} par heure`)
      // Autre PR, même identité : compteur distinct.
      const other = addComment(fake, app, 2, 'bavard', '/scanoria aide')
      expect((await hook('issue_comment', commentEvent(2, other))).work).toBe('help')
    })
  })

  describe('mode tiré et analyse nocturne (G18)', () => {
    it('sans webhook récent, les PR ouvertes et leurs commentaires sont interrogés', async () => {
      await db.pool.query(`UPDATE webhook_deliveries SET received_at = now() - interval '2 hours' WHERE forge_id = $1`, [forgeId])
      expect(await forgeMode(db.pool, forgeId)).toBe('pull')
      addPr(app, { number: 2, files: ['README.md'] })
      addComment(fake, app, 2, 'relectrice', '/scanoria aide')
      const r = await pollPullRequests(db.pool)
      expect(r.errors).toBe(0)
      expect(r.scans).toBe(1)
      expect(r.comments).toBe(1)
      // Deuxième passe immédiate : rien (5 minutes entre deux interrogations d'un projet).
      expect((await pollPullRequests(db.pool)).projects).toBe(0)
    })

    it('analyse complète nocturne de la branche principale après des analyses de PR', async () => {
      const night = new Date()
      night.setUTCHours(2, 0, 0, 0)
      expect(await nightlyFullScans(db.pool, night)).toBe(1)
      const s = await db.pool.query(`SELECT ref, trigger, incremental FROM scans WHERE project_id = $1 AND trigger = 'schedule'`, [projectId])
      expect(s.rows[0]).toMatchObject({ ref: 'main', incremental: false })
      const noon = new Date()
      noon.setUTCHours(12, 0, 0, 0)
      expect(await nightlyFullScans(db.pool, noon)).toBe(0)
    })
  })

  describe('base de la PR (contrat 33)', () => {
    it('« nouveau » = absent de la dernière analyse de la branche cible', async () => {
      const pr = app.prs.find(p => p.number === 2)!
      const ins = async (extra: string, args: unknown[]) => (await db.pool.query<{ id: string }>(
        `INSERT INTO scans (project_id, number, trigger, priority, ref, commit_sha, profile_id, gate_id, status, finished_at ${extra ? `, ${extra}` : ''})
         SELECT id, COALESCE((SELECT max(number) FROM scans WHERE project_id = $1), 0) + 1, 'manual', 50, $2, $3, profile_id, gate_id, 'done', now() ${extra ? ', $4' : ''}
           FROM projects WHERE id = $1 RETURNING id`, args)).rows[0]!.id
      const base = await ins('', [projectId, 'main', pr.base])
      const head = await ins('pull_request', [projectId, 'refs/pull/2/head', pr.head, JSON.stringify({ number: 2, base_sha: pr.base, base_ref: 'main' })])
      const old = await finding(base, { fp: 'a'.repeat(64) })
      await finding(head, { fp: 'a'.repeat(64) })
      const fresh = await finding(head, { fp: 'b'.repeat(64) })
      expect(await isPullRequestScan(db.pool, head)).toBe(true)
      expect(await isPullRequestScan(db.pool, base)).toBe(false)
      expect([...(await pullRequestBaseline(db.pool, head))!]).toEqual([old])
      expect(await pullRequestBaseline(db.pool, base)).toBeNull()
      await applyPullRequestBaseline(db.pool, head)
      const rows = await db.pool.query('SELECT finding_id, is_new FROM scan_findings WHERE scan_id = $1', [head])
      expect(Object.fromEntries(rows.rows.map(r => [r.finding_id, r.is_new]))).toEqual({ [old]: false, [fresh]: true })
    })
  })

  describe('application GitHub en un clic (J1)', () => {
    it('manifeste, état signé et lié à l’administrateur, conversion, installation vérifiée, jeton', async () => {
      const baseUrl = `https://${HOST}`
      const m = await startGithubManifest({ base_url: baseUrl, org: 'equipe', name: 'GitHub test', consoleUrl: CONSOLE, userId: 7, reachable: false })
      expect(m.action.startsWith(`${baseUrl}/organizations/equipe/settings/apps/new?state=`)).toBe(true)
      expect(m.manifest.hook_attributes).toEqual({ url: `${CONSOLE}/api/forges/${m.forge_id}/webhook`, active: false })
      expect(m.manifest.redirect_url).toBe(`${CONSOLE}/forges/github`)
      expect(m.manifest.default_permissions).not.toHaveProperty('administration')
      expect(await verifyManifestState(m.state, 8)).toBeNull()
      expect(await verifyManifestState(`${m.state.slice(0, -2)}AA`, 7)).toBeNull()
      expect(await verifyManifestState(m.state, 7, Date.now() + 31 * 60_000)).toBeNull()
      const state = (await verifyManifestState(m.state, 7))!
      expect(state.forge_id).toBe(m.forge_id)
      await expect(convertManifest(baseUrl, 'code-inconnu-0001')).rejects.toMatchObject({ code: 'E_FORGE_NOT_FOUND' })
      fake.app.codes.add('code-valide-0001')
      const conv = await convertManifest(baseUrl, 'code-valide-0001')
      const id = await saveGithubApp(db.pool, state, conv, { type: 'user', userId: null, username: 'admin' })
      const forge = (await getForge(db.pool, id))!
      expect(forge.kind).toBe('github')
      const a = (await getForgeApp(db.pool, id))!
      expect(a).toMatchObject({ kind: 'github-app', slug: 'scanoria-test', app_id: '4242' })
      expect(await webhookSecret(db.pool, id)).toBe(fake.app.webhook_secret)
      // Installation : retenue seulement si GitHub la confirme.
      expect(await verifyInstallation(db.pool, forge, '99')).toBe(false)
      fake.app.installations.push(99)
      expect(await verifyInstallation(db.pool, forge, '99')).toBe(true)
      expect(await addInstallation(db.pool, id, '99', actor)).toBe(true)
      expect(await addInstallation(db.pool, id, '99', actor)).toBe(false)
      // Réinstallation : la plus récente passe en tête ; une désinstallation la retire.
      expect(await addInstallation(db.pool, id, '100', actor)).toBe(true)
      expect((await getForgeApp(db.pool, id))!.installation_ids).toEqual(['100', '99'])
      expect(await removeInstallation(db.pool, id, '100', 'deleted', actor)).toBe(true)
      expect(await removeInstallation(db.pool, id, '100', 'deleted', actor)).toBe(false)
      expect((await getForgeApp(db.pool, id))!.installation_ids).toEqual(['99'])
      clearInstallationTokens()
      expect(await installationToken(db.pool, forge.base_url, (await getForgeApp(db.pool, id))!)).toBe(fake.token)
      expect(await refreshAppCredential(db.pool, forge)).toBe(true)
      expect((await getForge(db.pool, id))!.credential_id).not.toBeNull()
      // JWT RS256 vérifiable avec la clé publique de l'application.
      const jwt = appJwt('4242', fake.app.pem, 1_800_000_000)
      const [h, b, s] = jwt.split('.')
      expect(verify('RSA-SHA256', Buffer.from(`${h}.${b}`), createPublicKey(fake.app.pem), Buffer.from(s!, 'base64url'))).toBe(true)
      expect(JSON.parse(Buffer.from(b!, 'base64url').toString())).toEqual({ iat: 1_800_000_000 - 60, exp: 1_800_000_000 + 540, iss: '4242' })
      expect(manifestTarget('https://api.github.com', null)).toBe('https://github.com/settings/apps/new')
    })
  })
})
