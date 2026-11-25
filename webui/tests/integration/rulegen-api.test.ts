// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// I12 (0.7) contre un vrai PostgreSQL 16 et le faux serveur Ollama : règle
// proposée depuis un résultat, un exemple ou une phrase, testée sur ses
// exemples positif et négatif par le moteur des jeux de règles (chantier A,
// remplacé ici par un faux moteur qui applique le motif) ; une règle qui
// échoue ne peut pas être enregistrée ; enregistrement par un administrateur
// humain seulement, confirmé, en version origin 'ai' tracée dans l'audit ;
// rien n'est enregistré automatiquement ; projet « aucun envoi à l'IA »
// jamais envoyé ; sortie mal formée rejetée ; console identique sans connecteur.

import { randomBytes, randomUUID } from 'node:crypto'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { DATABASE_URL } from '../helpers/db'
import { startAiConsole, type AiConsole, type Client, type Json } from '../helpers/ai-console'
import { judgeTest, setRulesetBackend, type RulesetBackend, type RulesetSummary } from '../../server/ai/rulegen'
import { cleanCode, ruleLooksValid } from '../../server/ai/tasks/rulegen'

/** Faux moteur : applique le motif de la règle (eval(...), regex gitleaks, valeur Checkov) aux échantillons. */
function fakeBackend() {
  const rulesets: (RulesetSummary & { versions: { content: string, origin: string, comment?: string }[] })[] = []
  const calls = { test: 0, add: 0 }
  const matcher = (engine: string, content: string): ((s: string) => number) => {
    if (engine === 'gitleaks') {
      const re = new RegExp(/regex = '''(.+)'''/.exec(content)?.[1] ?? '^$', 'g')
      return s => (s.match(re) ?? []).length
    }
    if (engine === 'checkov') {
      const v = /value: (\S+)/.exec(content)?.[1] ?? '\0'
      return s => (s.includes(`"${v}"`) ? 1 : 0)
    }
    const fn = /pattern: (\w+)\(\.\.\.\)/.exec(content)?.[1] ?? '\0'
    return s => (s.match(new RegExp(`\\b${fn}\\(`, 'g')) ?? []).length
  }
  const backend: RulesetBackend = {
    async testRuleset(_db, { engine, content, samples }) {
      calls.test++
      const m = matcher(engine, content)
      return { ok: true, errors: [], samples: samples.map(s => ({ name: s.name, matches: m(s.content) })) }
    },
    async listRulesets(_db, { engine, includeArchived }) {
      return rulesets.filter(r => (!engine || r.engine === engine) && (includeArchived || !r.archived_at))
    },
    async createRuleset(_db, { slug, engine, name }) {
      const r = { id: randomUUID(), slug, engine, name, latest_version: null, archived_at: null, versions: [] }
      rulesets.push(r)
      return { id: r.id }
    },
    async addRulesetVersion(_db, { rulesetId, content, origin, comment }) {
      calls.add++
      const r = rulesets.find(x => x.id === rulesetId)!
      r.versions.push({ content, origin, comment })
      r.latest_version = r.versions.length
      return { version: r.versions.length, sha256: 'f'.repeat(64) }
    },
  }
  return { backend, rulesets, calls }
}

describe.skipIf(!DATABASE_URL)('générateur de règles I12 (PostgreSQL réel, faux Ollama)', () => {
  let c: AiConsole
  let admin: Client
  let operator: Client
  let viewer: Client
  let findingId: string
  let optOutFinding: string
  let fb: ReturnType<typeof fakeBackend>
  const secret = `glpat-${randomBytes(20).toString('hex').slice(0, 20)}`

  async function generate(client: Client, json: Json): Promise<{ subject: string, state: Json }> {
    const post = await c.call('/api/ai/rules', { method: 'POST', client, json })
    expect(post.status).toBe(202)
    await c.drain()
    const get = await c.call(`/api/ai/rules?subject_id=${post.data.subject_id}`, { client })
    expect(get.status).toBe(200)
    return { subject: String(post.data.subject_id), state: get.data }
  }
  const audit = async () => (await c.db.pool.query<{ action: string, outcome: string, details: Json }>(
    `SELECT action, outcome, details FROM audit_log WHERE action = 'ai.rule.save' ORDER BY id`,
  )).rows

  beforeAll(async () => {
    c = await startAiConsole('rulegen')
    admin = await c.login('rg-admin', 'admin')
    operator = await c.login('rg-operator', 'operator')
    viewer = await c.login('rg-viewer', 'viewer')
    const { p, g } = (await c.db.pool.query<{ p: string, g: string }>(
      `SELECT (SELECT id FROM profiles WHERE slug = 'rapide') AS p, (SELECT id FROM gates WHERE slug = 'defaut') AS g`,
    )).rows[0]!
    const mk = async (slug: string, optOut: boolean) => (await c.db.pool.query<{ id: string }>(
      `INSERT INTO projects (slug, name, source_kind, profile_id, gate_id, ai_opt_out) VALUES ($1, $1, 'archive', $2, $3, $4) RETURNING id`,
      [slug, p, g, optOut],
    )).rows[0]!.id
    const finding = async (project: string, fp: string) => (await c.db.pool.query<{ id: string }>(
      `INSERT INTO findings (project_id, fingerprint, tool, rule_id, category, severity, title, path, start_line, snippet)
       VALUES ($1, $2, 'bandit', 'B307', 'sast', 'medium', 'Use of possibly insecure function eval', 'app/calc.py', 3, $3) RETURNING id`,
      [project, fp, `token = "${secret}"\nresult = eval(request.args["x"])`],
    )).rows[0]!.id
    findingId = await finding(await mk('calcul', false), 'd'.repeat(64))
    optOutFinding = await finding(await mk('prive', true), 'e'.repeat(64))
  })

  afterAll(async () => {
    setRulesetBackend(null)
    await c?.close()
  })

  it('sans connecteur : rien n’est proposé, aucune tâche', async () => {
    expect((await c.call('/api/ai/rules', { client: operator })).data).toMatchObject({ enabled: false, task: null })
    const post = await c.call('/api/ai/rules', { method: 'POST', client: operator, json: { engine: 'opengrep', source: 'phrase', description: 'eval on data' } })
    expect(post.status).toBe(200)
    expect(post.data).toEqual({ subject_id: null, task_id: null })
    expect(Number((await c.db.pool.query<{ n: string }>('SELECT count(*) AS n FROM ai_tasks')).rows[0]!.n)).toBe(0)
  })

  it('droits et formes : opérateur pour proposer et tester, administrateur pour enregistrer', async () => {
    await c.setConnector(true)
    expect((await c.call('/api/ai/rules', { method: 'POST', client: viewer, json: { engine: 'opengrep', source: 'phrase', description: 'eval' } })).status).toBe(403)
    expect((await c.call('/api/ai/rules', { method: 'POST', client: operator, json: { engine: 'kics', source: 'phrase', description: 'eval' } })).status).toBe(400)
    expect((await c.call('/api/ai/rules', { method: 'POST', client: operator, json: { engine: 'opengrep', source: 'finding' } })).status).toBe(400)
    expect((await c.call('/api/ai/rules', { method: 'POST', client: operator, json: { engine: 'opengrep', source: 'finding', finding_id: randomUUID() } })).status).toBe(404)
    expect((await c.call('/api/ai/rules/rulesets?engine=opengrep', { client: operator })).status).toBe(403)
    expect((await c.call('/api/ai/rules/save', { method: 'POST', client: operator, json: { subject_id: `rg:${'0'.repeat(64)}`, new_ruleset: { slug: 'x', name: 'x' }, confirmed: true } })).status).toBe(403)
  })

  it('projet « aucun envoi à l’IA » : rien n’est envoyé', async () => {
    const before = c.fake.chatCount()
    const post = await c.call('/api/ai/rules', { method: 'POST', client: operator, json: { engine: 'opengrep', source: 'finding', finding_id: optOutFinding } })
    expect(post.status).toBe(404)
    await c.drain()
    expect(c.fake.chatCount()).toBe(before)
  })

  it('jeux de règles absents : la règle est proposée mais ni testée ni enregistrable', async () => {
    const { subject, state } = await generate(operator, { engine: 'opengrep', source: 'finding', finding_id: findingId, language: 'python' })
    expect(state.task.status).toBe('done')
    expect(state.available).toBe(false)
    expect(state.engine).toBe('opengrep')
    expect(state.task.output.rule).toContain('eval(...)')
    const sent = c.fake.requests.filter(r => r.path === '/api/chat').map(r => r.body).join('\n')
    expect(sent).not.toContain(secret)
    expect(sent).toContain('B307')
    expect((await c.call('/api/ai/rules/test', { method: 'POST', client: operator, json: { subject_id: subject } })).status).toBe(503)
  })

  it('règle testée sur ses exemples, enregistrée après confirmation par un administrateur, version IA tracée', async () => {
    fb = fakeBackend()
    setRulesetBackend(fb.backend)
    const { subject, state } = await generate(operator, { engine: 'opengrep', source: 'phrase', description: 'Interdire eval() sur une donnée', language: 'python' })
    expect(state.available).toBe(true)
    expect(fb.calls.add).toBe(0)
    const test = await c.call('/api/ai/rules/test', { method: 'POST', client: operator, json: { subject_id: subject } })
    expect(test.data).toMatchObject({ passed: true, positive_matches: 1, negative_matches: 0, engine: 'opengrep' })
    // Rien d'enregistré sans confirmation, ni par un opérateur.
    expect(fb.calls.add).toBe(0)
    expect((await c.call('/api/ai/rules/save', { method: 'POST', client: admin, json: { subject_id: subject, new_ruleset: { slug: 'maison', name: 'Règles maison' } } })).status).toBe(400)
    const saved = await c.call('/api/ai/rules/save', { method: 'POST', client: admin, json: { subject_id: subject, new_ruleset: { slug: 'maison', name: 'Règles maison' }, confirmed: true } })
    expect(saved.status).toBe(200)
    expect(saved.data).toMatchObject({ version: 1, engine: 'opengrep', rule_id: 'no-eval', model: 'qwen-test:14b' })
    expect(fb.rulesets[0]!.versions[0]).toMatchObject({ origin: 'ai' })
    expect(fb.rulesets[0]!.versions[0]!.comment).toMatch(/^Proposé par IA : qwen-test:14b/)
    const list = await c.call('/api/ai/rules/rulesets?engine=opengrep', { client: admin })
    expect(list.data.items.map((r: Json) => r.slug)).toEqual(['maison'])
    expect((await c.call('/api/ai/rules/rulesets?engine=gitleaks', { client: admin })).data.items).toEqual([])
    // Nouvelle version d'un jeu existant ; moteur différent refusé.
    const again = await c.call('/api/ai/rules/save', { method: 'POST', client: admin, json: { subject_id: subject, ruleset_id: fb.rulesets[0]!.id, confirmed: true } })
    expect(again.data.version).toBe(2)
    const gl = await generate(operator, { engine: 'gitleaks', source: 'phrase', description: 'Jeton interne EXT_ suivi de 32 caractères hexadécimaux' })
    const mismatch = await c.call('/api/ai/rules/save', { method: 'POST', client: admin, json: { subject_id: gl.subject, ruleset_id: fb.rulesets[0]!.id, confirmed: true } })
    expect(mismatch.status).toBe(409)
    expect(mismatch.data.data?.reason ?? mismatch.data.reason).toBe('engine-mismatch')
    const rows = await audit()
    expect(rows.filter(r => r.outcome === 'success')).toHaveLength(2)
    expect(rows[0]!.details).toMatchObject({ origin: 'ai', source: 'I12', engine: 'opengrep', test: { positive: 1, negative: 0 } })
  })

  it('gitleaks et Checkov : test du motif sur les deux exemples', async () => {
    for (const [engine, description] of [['gitleaks', 'Jeton interne EXT_'], ['checkov', 'Refuser un bucket public-read']] as const) {
      const { subject } = await generate(operator, { engine, source: 'phrase', description })
      const test = await c.call('/api/ai/rules/test', { method: 'POST', client: operator, json: { subject_id: subject } })
      expect(test.data).toMatchObject({ passed: true, engine })
    }
  })

  it('règle qui échoue au test : jamais enregistrée, refus tracé', async () => {
    const { subject } = await generate(operator, { engine: 'opengrep', source: 'phrase', description: 'BROKEN rule for eval' })
    const test = await c.call('/api/ai/rules/test', { method: 'POST', client: operator, json: { subject_id: subject } })
    expect(test.data).toMatchObject({ passed: false, positive_matches: 0 })
    const before = fb.calls.add
    const save = await c.call('/api/ai/rules/save', { method: 'POST', client: admin, json: { subject_id: subject, new_ruleset: { slug: 'cassee', name: 'Cassée' }, confirmed: true } })
    expect(save.status).toBe(409)
    expect(fb.calls.add).toBe(before)
    expect(fb.rulesets.find(r => r.slug === 'cassee')).toBeUndefined()
    expect((await audit()).at(-1)).toMatchObject({ outcome: 'failure', details: { reason: 'test-failed' } })
  })

  it('identité non humaine : jamais d’enregistrement', async () => {
    const { subject } = await generate(operator, { engine: 'opengrep', source: 'phrase', description: 'Interdire eval() sur une donnée' })
    const bot = await c.login('rg-bot', 'admin')
    await c.db.pool.query(`UPDATE users SET kind = 'agent' WHERE username = 'rg-bot'`)
    const save = await c.call('/api/ai/rules/save', { method: 'POST', client: bot, json: { subject_id: subject, new_ruleset: { slug: 'bot', name: 'Bot' }, confirmed: true } })
    expect(save.status).toBe(403)
    expect((await audit()).at(-1)).toMatchObject({ outcome: 'denied' })
  })

  it('sortie mal formée : rejetée par le contrôle du moteur, jamais montrée', async () => {
    c.fake.mode = 'invalid-schema'
    try {
      const post = await c.call('/api/ai/rules', { method: 'POST', client: operator, json: { engine: 'semgrep', source: 'example', example: 'os.system(cmd)' } })
      await c.drain()
      const get = await c.call(`/api/ai/rules?subject_id=${post.data.subject_id}`, { client: operator })
      expect(get.data.task.status).toBe('error')
      expect(get.data.task.output).toBeNull()
    }
    finally {
      c.fake.mode = 'ok'
    }
  })

  it('contrôles textuels et nettoyage', () => {
    expect(ruleLooksValid('opengrep', 'rules:\n  - id: a\n    message: m\n    languages: [python]\n    pattern: eval(...)\n')).toBe(true)
    expect(ruleLooksValid('opengrep', 'rules:\n  - id: a\n    message: !!python/object x\n    pattern: eval(...)\n')).toBe(false)
    expect(ruleLooksValid('semgrep', 'rules:\n  - id: a\n    message: m\n    pattern: x\ninclude: /etc\n')).toBe(false)
    expect(ruleLooksValid('gitleaks', '[extend]\npath = "/etc/x"\n[[rules]]\nid = "a"\nregex = \'\'\'x\'\'\'\n')).toBe(false)
    expect(ruleLooksValid('checkov', 'metadata:\n  id: CKV2_X\ndefinition:\n  cond_type: attribute\n')).toBe(true)
    expect(ruleLooksValid('checkov', 'nothing')).toBe(false)
    expect(cleanCode('a\u202eb\r\nc\u0007', 100)).toBe('ab\nc')
    expect(judgeTest({ ok: true, errors: [], samples: [{ name: 'positive', matches: 2 }, { name: 'negative', matches: 1 }] }).passed).toBe(false)
    expect(judgeTest({ ok: false, errors: ['parse error'], samples: [] })).toMatchObject({ passed: false, positive_matches: -1, errors: ['parse error'] })
  })
})
