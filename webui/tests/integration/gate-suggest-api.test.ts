// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Chantier B (0.8) : I19, seuils de quality gate suggérés, contre un vrai
// PostgreSQL 16, le faux serveur Ollama et le vrai service scanoria-ai.
// Seules des métadonnées partent (ni chemin, ni message, ni extrait) ; projet
// « aucun envoi à l'IA » et console sans connecteur : rien ; la proposition
// passe automatiquement dans le simulateur (origin « ai »), une seule fois ;
// exceptions candidates limitées à l'historique, jamais MAL- ; enregistrement
// par un administrateur, audité « proposé par IA ».

import { randomBytes } from 'node:crypto'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { DATABASE_URL } from '../helpers/db'
import { extractData } from '../helpers/fake-ollama'
import { startAiConsole, type AiConsole, type Client } from '../helpers/ai-console'

describe.skipIf(!DATABASE_URL)('seuils suggérés I19 (PostgreSQL réel, faux Ollama)', () => {
  let c: AiConsole
  let admin: Client
  let viewer: Client
  let operator: Client
  let projectId: string
  let optOutId: string
  let gateId: string

  async function seed(slug: string, optOut: boolean): Promise<string> {
    const id = (await c.db.pool.query<{ id: string }>(
      `INSERT INTO projects (slug, name, source_kind, profile_id, gate_id, ai_opt_out)
       VALUES ($1, $1, 'archive', (SELECT id FROM profiles WHERE slug = 'rapide'), $2, $3) RETURNING id`, [slug, gateId, optOut])).rows[0]!.id
    for (let n = 1; n <= 3; n++) {
      const scan = (await c.db.pool.query<{ id: string }>(
        `INSERT INTO scans (project_id, number, trigger, priority, ref, profile_id, gate_id, status, finished_at, verdict, verdict_details)
         VALUES ($1, $2, $3, 50, 'main', (SELECT id FROM profiles WHERE slug = 'rapide'), $4, 'done', now() - interval '2 days', 'failed',
                 '{"reasons": [{"code": "sast", "blocking": true}]}') RETURNING id`,
        [id, n, n === 3 ? 'release' : 'manual', gateId])).rows[0]!.id
      await c.db.pool.query(`INSERT INTO scan_modules (scan_id, module_id, module_version, status) VALUES ($1, 'semgrep', '1', 'ok')`, [scan])
      const f = (await c.db.pool.query<{ id: string }>(
        `INSERT INTO findings (project_id, fingerprint, tool, rule_id, category, severity, title, message, path, snippet)
         VALUES ($1, $2, 'semgrep', 'javascript.audit.regexp', 'sast', 'medium', 'Regexp', 'message-sensible', 'src/chemin-sensible.js', 'code-sensible')
         RETURNING id`, [id, randomBytes(32).toString('hex')])).rows[0]!.id
      await c.db.pool.query('INSERT INTO scan_findings (scan_id, finding_id, is_new) VALUES ($1, $2, true)', [scan, f])
    }
    return id
  }

  beforeAll(async () => {
    c = await startAiConsole('gate-suggest')
    admin = await c.login('gs-admin', 'admin')
    viewer = await c.login('gs-viewer', 'viewer')
    operator = await c.login('gs-operator', 'operator')
    gateId = (await c.db.pool.query<{ id: string }>(`SELECT id FROM gates WHERE slug = 'defaut'`)).rows[0]!.id
    projectId = await seed('boutique', false)
    optOutId = await seed('confidentiel', true)
  })

  afterAll(async () => {
    await c?.close()
  })

  it('sans connecteur : aucune tâche, aucune simulation, page identique', async () => {
    const r = await c.call('/api/ai/explain', { method: 'POST', client: viewer, json: { kind: 'suggest-gate', subject_id: projectId } })
    expect(r.data).toEqual({ task_id: null })
    expect((await c.call(`/api/gates/projects/${projectId}/suggestion/simulate`, { method: 'POST', client: operator })).status).toBe(404)
    expect((await c.call(`/api/gates/projects/${projectId}`, { client: viewer })).status).toBe(200)
  })

  it('proposition : métadonnées seulement, exceptions filtrées, simulée automatiquement une seule fois', async () => {
    await c.setConnector(true)
    const r = await c.call('/api/ai/explain', { method: 'POST', client: viewer, json: { kind: 'suggest-gate', subject_id: projectId } })
    expect(r.status).toBe(202)
    await c.drain()
    const chat = c.fake.requests.filter(q => q.path === '/api/chat').at(-1)!
    const body = JSON.parse(chat.body) as { messages: { content: string }[] }
    const data = extractData(body.messages.at(-1)!.content)!
    expect(data).toMatchObject({ window_days: 90, scans: { total: 3, failed: 3, releases: 1, releases_blocked: 1 } })
    expect(data.rules).toEqual([{ tool: 'semgrep', rule_id: 'javascript.audit.regexp', category: 'sast', severity: 'medium', findings: 3, scans: 3 }])
    expect(data.blocking_reasons).toEqual([{ code: 'sast', scans: 3 }])
    for (const leak of ['chemin-sensible', 'message-sensible', 'code-sensible', 'confidentiel']) expect(chat.body).not.toContain(leak)

    const out = await c.call(`/api/ai/output?kind=suggest-gate&subject_id=${projectId}`, { client: viewer })
    expect(out.data.task.status).toBe('done')
    const output = out.data.task.output as { exceptions: { rule_id: string }[], rules: Record<string, unknown> }
    expect(output.exceptions.map(e => e.rule_id)).toEqual(['javascript.audit.regexp'])
    expect(output.rules).toMatchObject({ iac_block_from: 'none', new_code_only: true })

    // Lancer un rejeu demande le rôle operator.
    expect((await c.call(`/api/gates/projects/${projectId}/suggestion/simulate`, { method: 'POST', client: viewer })).status).toBe(403)
    const s1 = await c.call(`/api/gates/projects/${projectId}/suggestion/simulate`, { method: 'POST', client: operator })
    expect(s1.status).toBe(200)
    expect(s1.data.simulation).toMatchObject({ origin: 'ai', status: 'done', project_id: projectId })
    // Seuils seulement : KEV, EPSS, licences, quarantaine et fraîcheur restent ceux du gate.
    expect(s1.data.rules).toMatchObject({ iac_block_from: null, kev_blocks: true, license_denied_blocks: true, quarantine_days: 7, feed_max_age_days: 7 })
    expect(s1.data.simulation.result.scans.total).toBe(3)
    const s2 = await c.call(`/api/gates/projects/${projectId}/suggestion/simulate`, { method: 'POST', client: operator })
    expect(s2.data.simulation.id).toBe(s1.data.simulation.id)

    // Enregistrement : clic d'un administrateur, audité « proposé par IA ».
    const sug = await c.call(`/api/gates/suggestions/${s1.data.task_id}`, { client: viewer })
    expect(sug.data).toMatchObject({ gate_id: gateId, project_id: projectId })
    expect(sug.data.model).toBeTruthy()
    expect((await c.call(`/api/gates/${gateId}`, { method: 'PATCH', client: viewer, json: { rules: sug.data.rules, ai_task_id: s1.data.task_id } })).status).toBe(403)
    const other = (await c.db.pool.query<{ id: string }>(`INSERT INTO gates (slug, builtin, rules) VALUES ('autre', false, '{}') RETURNING id`)).rows[0]!.id
    expect((await c.call(`/api/gates/${other}`, { method: 'PATCH', client: admin, json: { rules: sug.data.rules, ai_task_id: s1.data.task_id } })).status).toBe(400)
    const saved = await c.call(`/api/gates/${gateId}`, { method: 'PATCH', client: admin, json: { rules: sug.data.rules, ai_task_id: s1.data.task_id } })
    expect(saved.status).toBe(200)
    const audit = (await c.db.pool.query<{ details: Record<string, unknown> }>(
      `SELECT details FROM audit_log WHERE action = 'gate.update' AND target_id = $1 ORDER BY id DESC LIMIT 1`, [gateId])).rows[0]!.details
    expect(audit.proposed_by_ai).toMatchObject({ task_id: s1.data.task_id, project_id: projectId, modified: false })
    // Sans ai_task_id : aucune mention IA.
    await c.call(`/api/gates/${gateId}`, { method: 'PATCH', client: admin, json: { rules: { ...sug.data.rules, max_secrets: 1 } } })
    const plain = (await c.db.pool.query<{ details: Record<string, unknown> }>(
      `SELECT details FROM audit_log WHERE action = 'gate.update' AND target_id = $1 ORDER BY id DESC LIMIT 1`, [gateId])).rows[0]!.details
    expect(plain.proposed_by_ai).toBeUndefined()
  })

  it('projet « aucun envoi à l\'IA » : rien envoyé, rien simulé', async () => {
    const before = c.fake.chatCount()
    const r = await c.call('/api/ai/explain', { method: 'POST', client: viewer, json: { kind: 'suggest-gate', subject_id: optOutId } })
    expect(r.data).toEqual({ task_id: null })
    await c.drain()
    expect(c.fake.chatCount()).toBe(before)
    expect((await c.call(`/api/gates/projects/${optOutId}/suggestion/simulate`, { method: 'POST', client: operator })).status).toBe(404)
    expect((await c.call(`/api/gates/suggestions/${crypto.randomUUID()}`, { client: viewer })).status).toBe(404)
  })
})
