// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Banc du relais IA pour tests/b35-live.sh (0.7, contrat 31) : le vrai relais
// (startRelay, garde-fous de relay.ts) servi en HTTPS sur le socket Unix du
// runner, avec un faux Ollama en mémoire et une base factice. Regroupé par
// esbuild puis lancé par node, en root, à côté du vrai runner et du vrai
// podman. Journaux (une ligne JSON par événement) :
//   - $RELAY_LIVE_DIR/ollama.jsonl : ce qu'Ollama aurait reçu (messages, outils) ;
//   - $RELAY_LIVE_DIR/calls.jsonl  : lignes ai_calls écrites par le relais.
// Variables : RELAY_RUNTIME_DIR (relay.crt, relay.key, ai.json ; socket créé
// ici), RELAY_TOKEN_DIR, RELAY_OPT_OUT (projet « aucun envoi à l'IA »).
// Réponse du faux modèle : un JSON qui décrit un résultat, repris en SARIF par
// l'outil du module de test.

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

const client: OllamaLike = {
  version: async () => '0.12.3',
  tags: async () => [],
  show: async () => ({}),
  chat: async (req) => {
    record('ollama.jsonl', { model: req.model, messages: req.messages, keys: Object.keys(req) })
    const content = JSON.stringify({ rule: 'ai-injection', message: 'Entrée utilisateur non filtrée (faux modèle)', path: 'app.py', line: 2 })
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
