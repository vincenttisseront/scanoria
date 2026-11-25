// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Banc du relais IA pour la partie « relais » de tests/b36-live.sh (0.7,
// chantier F) : le même vrai relais que relay-harness.ts (contrat 31), avec un
// faux Ollama qui répond comme un modèle aux trois modules d'analyse par IA
// du chantier F, selon l'invite reçue (après les garde-fous du relais) :
//   - mcp-scanner-llm : analyse de menace (threat_analysis) d'une définition MCP ;
//   - skill-scanner-llm : verdict du juge, preuves citées par leurs identifiants SRC:… ;
//   - vulnhuntr : résumé du README (sans format), puis rapports (format JSON)
//     qui signalent SSRF et RCE quand le code cité les contient.
// Journaux : $RELAY_LIVE_DIR/ollama.jsonl et calls.jsonl, comme relay-harness.ts.

import { appendFileSync } from 'node:fs'
import { join } from 'node:path'
import { fileTokenLookup } from '../../server/ai/relay'
import { startRelay } from '../../server/ai/runtime'
import { AiService, type OllamaLike } from '../../server/ai/service'
import { RELAY_KEY } from '../../server/ai/models'
import type { Queryable } from '../../server/utils/db'

const runtimeDir = process.env.RELAY_RUNTIME_DIR ?? ''
const out = process.env.RELAY_LIVE_DIR ?? ''
const optOut = process.env.RELAY_OPT_OUT ?? ''
if (!runtimeDir || !out) {
  console.error('RELAY_RUNTIME_DIR and RELAY_LIVE_DIR are required')
  process.exit(2)
}
const record = (file: string, doc: unknown) => appendFileSync(join(out, file), `${JSON.stringify(doc)}\n`)
const MODEL = { model: 'faux-modele:7b', digest: 'e'.repeat(64), context: 32768, reason: 'best-balance' }

const db: Queryable = {
  query: (async (sql: string, params: unknown[] = []) => {
    if (sql.includes(`kind = 'probe' AND status = 'done'`)) {
      return { rows: [{ output: { selection: { tasks: { [RELAY_KEY]: MODEL }, embedding: null } }, finished_at: new Date() }], rowCount: 1 }
    }
    if (sql.startsWith('SELECT ai_opt_out')) {
      return { rows: [{ ai_opt_out: params[0] === optOut, archived_at: null }], rowCount: 1 }
    }
    if (sql.includes('INSERT INTO ai_calls')) {
      const [kind, project, model, bytes, , outcome, module] = params
      record('calls.jsonl', { kind, project, model, bytes, outcome, module })
    }
    return { rows: [], rowCount: 0 }
  }) as Queryable['query'],
}

function answer(messages: { role: string, content: string }[], format: unknown): string {
  const all = messages.map(m => m.content).join(' ')
  const prompt = messages.at(-1)?.content ?? ''
  if (all.includes('threat_analysis')) {
    const bad = /ignore|exfiltr/i.test(prompt)
    return JSON.stringify({ threat_analysis: { overall_risk: bad ? 'HIGH' : 'SAFE', primary_threats: bad ? ['PROMPT INJECTION'] : [], threat_summary: 'x', malicious_content_detected: bad } })
  }
  if (all.includes('SKILL.md')) {
    const ev = /SRC:[0-9a-f]{16}/.exec(all)?.[0] ?? 'SRC:0000000000000000'
    return JSON.stringify({
      verdict: 'MALICIOUS', overall_assessment: 'Hidden instructions.', primary_threats: ['prompt injection'],
      findings: [{
        severity: 'HIGH', aitech: 'AITech-1.1', aisubtech: null, category: 'prompt_injection', evidence_ids: [ev],
        title: 'Prompt injection in SKILL.md', description: 'The skill tells the agent to ignore its instructions.',
        location: 'SKILL.md:1', evidence: 'ignore', remediation: 'Remove it.', verdict: 'TRUE_POSITIVE', confidence: 'HIGH',
      }],
    })
  }
  if (format === null || format === undefined) return '<summary>Flask demo application.</summary>'
  const types = [...(prompt.includes('requests.get') ? ['SSRF'] : []), ...(prompt.includes('shell=True') ? ['RCE'] : [])]
  const second = prompt.includes('previous_analysis') && !prompt.includes('<previous_analysis></previous_analysis>')
  return JSON.stringify({
    scratchpad: 's', analysis: 'User input reaches a dangerous sink.', poc: 'curl /fetch?url=https://192.0.2.1/',
    confidence_score: second ? 9 : 8, vulnerability_types: types, context_code: [],
  })
}

const client: OllamaLike = {
  version: async () => '0.12.3',
  tags: async () => [],
  show: async () => ({}),
  chat: async (req) => {
    record('ollama.jsonl', { model: req.model, messages: req.messages, keys: Object.keys(req) })
    const content = answer(req.messages as { role: string, content: string }[], req.format)
    return { content, bytesSent: JSON.stringify(req.messages).length, durationMs: 1 }
  },
}

const service = new AiService({ db, loadEndpoint: async () => ({ version: 1, enabled: false }), clientFor: async () => client })
const server = await startRelay({ db, runtimeDir, log: m => console.error(m) }, service, async () => client, fileTokenLookup(process.env.RELAY_TOKEN_DIR))
if (!server) {
  console.error('relay not started')
  process.exit(1)
}
for (const sig of ['SIGTERM', 'SIGINT'] as const) process.on(sig, () => server.close(() => process.exit(0)))
