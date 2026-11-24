// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Faux serveur Ollama pour la CI (CLAUDE.md § 12) : réponses déterministes,
// pannes, lenteurs, sorties invalides, empreinte de modèle qui change, et
// enregistrement de chaque requête reçue (pour vérifier ce qui sort de
// l'appliance). Écoute sur 127.0.0.1, port aléatoire.

import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http'
import type { AddressInfo } from 'node:net'

export interface FakeModel {
  name: string
  digest: string
  capabilities?: string[]
  context?: number
  parameterSize?: string
  family?: string
}

export type FakeMode = 'ok' | 'down' | 'slow' | 'invalid-json' | 'invalid-schema' | 'echo-data' | 'uncited' | 'unauthorized'

export interface RecordedRequest {
  method: string
  path: string
  headers: Record<string, string | string[] | undefined>
  body: string
}

export interface FakeOllama {
  url: string
  port: number
  requests: RecordedRequest[]
  models: FakeModel[]
  mode: FakeMode
  delayMs: number
  chatCount: () => number
  close: () => Promise<void>
}

/** Données JSON de l'invite, entre <data-…> et </data-…>. */
export function extractData(content: string): Record<string, unknown> | null {
  const m = /<(data-[0-9a-f]+)>\n([\s\S]*)\n<\/\1>/.exec(content)
  if (!m) return null
  try {
    return JSON.parse(m[2]!) as Record<string, unknown>
  }
  catch {
    return null
  }
}

/** Tâches de la 0.4 : réponses sages, déterministes, jamais une consigne des données. */
function wellBehaved04(required: string[], data: Record<string, unknown>): Record<string, unknown> | null {
  if (required.includes('suggestion')) {
    const f = (data.finding ?? {}) as Record<string, unknown>
    const hints = (data.path_hints ?? {}) as Record<string, boolean>
    const fp = hints.test || hints.example
    return {
      suggestion: fp ? 'likely-false-positive' : 'likely-true-positive',
      summary: fp ? 'Located in test or example code.' : `Reachable code in ${String(f.path)}.`,
      reasons: [{ kind: fp ? 'test-code' : 'real-risk', quote: String(f.path ?? ''), explanation: 'Based on the file location.' }],
    }
  }
  if (required.includes('headline')) {
    const reasons = (data.blocking_reasons as { code: string, module: string | null }[] | undefined) ?? []
    const gaps = (data.not_covered as { kind: string, detail: string }[] | undefined) ?? []
    const cands = (data.candidates as { ref: number, tool: string, rule_id: string }[] | undefined) ?? []
    const counts = (data.new_by_severity ?? {}) as Record<string, number>
    return {
      headline: `Analysis ${String(data.scan_number)}: verdict ${String(data.verdict)}.`,
      changes: `New findings: ${Object.entries(counts).map(([k, v]) => `${k} ${v}`).join(', ')}; fixed ${String(data.fixed_count)}.`,
      priorities: cands.slice(0, 3).map(c => ({ ref: c.ref, why: `${c.tool} rule ${c.rule_id}.` })),
      blocking: reasons.length ? reasons.map(r => `${r.code}${r.module ? ` (${r.module})` : ''}`).join(', ') : 'nothing',
      not_covered: gaps.length ? gaps.map(g => `${g.kind}: ${g.detail}`).join('; ') : 'everything was covered',
    }
  }
  if (required.includes('class')) {
    const hints = (data.path_hints ?? {}) as Record<string, boolean>
    const msg = String(data.message ?? '')
    const cls = hints.test || hints.example ? 'likely-false-positive' : /password/i.test(msg) ? 'password' : 'internal-token'
    return { class: cls, confidence: 'medium', summary: `Probably ${cls}.`, reasons: [`File ${String(data.path)}.`] }
  }
  if (required.includes('cause')) {
    const mods = (data.modules as { module: string, status: string }[] | undefined) ?? []
    const logs = JSON.stringify(data.logs ?? [])
    const m = mods[0]
    const cause = m?.status === 'oom' ? 'memory' : m?.status === 'timeout' ? 'timeout' : /config/i.test(logs) ? 'tool-error' : 'unknown'
    return {
      cause,
      module: m?.module ?? null,
      summary: `Module ${m?.module ?? '?'} failed (${m?.status ?? '?'}): ${cause}.`,
      fix: cause === 'tool-error' ? 'Check the configuration of the module.' : cause === 'memory' ? 'Give the module more memory.' : 'Raise the timeout of the module, then rerun.',
      steps: ['Rerun the analysis.'],
    }
  }
  if (required.includes('translation')) return { translation: `Traduction : ${String(data.text)}` }
  return null
}

/** Tâches de la 0.5 (I11, I18) : réponses sages et déterministes. */
function wellBehaved05(required: string[], data: Record<string, unknown>): Record<string, unknown> | null {
  if (required.includes('reachability')) {
    const locs = (data.locations as { ref: number, kind: string, path: string }[] | undefined) ?? []
    const call = locs.find(l => l.kind === 'call')
    if (call) return { reachability: 'probable', summary: `The component is called in ${call.path}.`, reasons: [{ ref: call.ref, explanation: `Call in ${call.path}.` }] }
    if (!locs.length) return { reachability: 'improbable', summary: 'The component is never imported.', reasons: [{ ref: 0, explanation: 'No import found.' }] }
    return { reachability: 'indeterminate', summary: `Imported in ${locs[0]!.path} (test code) but no call of zipObjectDeep found.`, reasons: [{ ref: locs[0]!.ref, explanation: 'Import only.' }] }
  }
  if (required.includes('compatibility')) {
    const lic = String(data.license)
    return {
      summary: `${lic} is a licence with source obligations (copyleft for GPL family; per-file for MPL; library for LGPL).`,
      obligations: [`Keep the ${lic} notice.`],
      compatibility: 'conditional',
      compatibility_note: `Check how ${lic} combines with ${String(data.project_license)}.`,
      to_check: ['How the component is linked.'],
    }
  }
  return null
}

/** Embedding déterministe : mots hachés dans 64 dimensions, normalisé (textes semblables = vecteurs proches). */
export function fakeEmbedding(text: string, dims = 64): number[] {
  const v = Array.from({ length: dims }, () => 0)
  for (const w of text.toLowerCase().match(/[a-z0-9]{3,}/g) ?? []) {
    let h = 2166136261
    for (const c of w) h = Math.imul(h ^ c.charCodeAt(0), 16777619) >>> 0
    v[h % dims]! += 1
  }
  const n = Math.sqrt(v.reduce((a, b) => a + b * b, 0)) || 1
  return v.map(x => x / n)
}

/** Réponse sage : reprend le titre, le message et les métadonnées, jamais l'extrait de code. */
function wellBehaved(required: string[], data: Record<string, unknown>): Record<string, unknown> {
  const v04 = wellBehaved04(required, data) ?? wellBehaved05(required, data)
  if (v04) return v04
  if (required.includes('detects')) {
    const pkg = data.package as { name?: string, fixed?: string[] } | null
    const fixed = pkg?.fixed?.length ? ` Upgrade ${pkg.name} to ${pkg.fixed[0]}.` : ''
    return {
      summary: `${String(data.title)} (${String(data.rule_id)}).`,
      detects: `The rule ${String(data.rule_id)} detects: ${String(data.title)}.`,
      risk: `${String(data.message ?? data.title)} Found in ${String(data.path)}.`,
      impact: 'An attacker could abuse this weakness.',
      fix: `Apply the recommended fix.${fixed} See https://cwe.mitre.org/data/definitions/20.html <b>now</b>`,
      references: [
        { label: 'Evil', url: 'https://evil.exemple.test/x' },
        { label: 'OSV', url: 'https://osv.dev/list' },
      ],
    }
  }
  const reasons = (data.reasons as { code: string, module: string | null }[] | undefined) ?? []
  const parts = reasons.map(r => `${r.code}${r.module ? ` (${r.module})` : ''}`)
  return {
    summary: `Verdict ${String(data.verdict)}: ${parts.join(', ') || 'no blocking reason'}. @admin #12`,
    blocking: parts[0] ?? 'none',
    actions: reasons.flatMap(r => (r as unknown as { actions: string[] }).actions ?? []).slice(0, 8),
  }
}

export async function startFakeOllama(models: FakeModel[] = [
  { name: 'qwen-test:14b', digest: 'a'.repeat(64), capabilities: ['completion', 'tools'], context: 32768, parameterSize: '14.8B', family: 'qwen2' },
  { name: 'embed-test:latest', digest: 'b'.repeat(64), capabilities: ['embedding'], context: 8192, parameterSize: '137M', family: 'nomic-bert' },
]): Promise<FakeOllama> {
  const state = { mode: 'ok' as FakeMode, delayMs: 0, chats: 0 }
  const requests: RecordedRequest[] = []
  const fake = {} as FakeOllama

  const send = (res: ServerResponse, status: number, body: unknown) => {
    const text = typeof body === 'string' ? body : JSON.stringify(body)
    res.writeHead(status, { 'content-type': 'application/json' })
    res.end(text)
  }

  const handle = async (req: IncomingMessage, res: ServerResponse) => {
    const chunks: Buffer[] = []
    for await (const c of req) chunks.push(c as Buffer)
    const body = Buffer.concat(chunks).toString('utf8')
    requests.push({ method: req.method ?? '', path: req.url ?? '', headers: req.headers, body })
    if (state.mode === 'down') return send(res, 503, { error: 'unavailable' })
    // Proxy placé devant Ollama qui refuse le jeton porteur.
    if (state.mode === 'unauthorized') return send(res, 401, { error: 'unauthorized' })
    if (state.mode === 'slow' || state.delayMs) await new Promise(r => setTimeout(r, state.delayMs || 2000))
    if (req.url === '/api/version') return send(res, 200, { version: '0.12.3' })
    if (req.url === '/api/tags') {
      return send(res, 200, { models: fake.models.map(m => ({ name: m.name, model: m.name, digest: m.digest, size: 1 })) })
    }
    if (req.url === '/api/show') {
      const name = (JSON.parse(body) as { model: string }).model
      const m = fake.models.find(x => x.name === name)
      if (!m) return send(res, 404, { error: 'not found' })
      return send(res, 200, {
        capabilities: m.capabilities ?? ['completion'],
        details: { family: m.family ?? 'llama', parameter_size: m.parameterSize ?? '8.0B' },
        model_info: { 'general.architecture': m.family ?? 'llama', [`${m.family ?? 'llama'}.context_length`]: m.context ?? 8192 },
      })
    }
    if (req.url === '/api/embed') {
      const parsed = JSON.parse(body) as { model: string, input: string[] }
      const m = fake.models.find(x => x.name === parsed.model)
      if (!m || !(m.capabilities ?? []).includes('embedding')) return send(res, 404, { error: 'model not found' })
      if (state.mode === 'invalid-json') return send(res, 200, { model: parsed.model, embeddings: [[1, 2]] })
      return send(res, 200, { model: parsed.model, embeddings: parsed.input.map(t => fakeEmbedding(t)) })
    }
    if (req.url === '/api/chat') {
      state.chats += 1
      const parsed = JSON.parse(body) as { model: string, messages: { content: string }[], format: { required?: string[] } }
      const data = extractData(parsed.messages.at(-1)?.content ?? '') ?? {}
      let content: string
      if (state.mode === 'invalid-json') content = 'Sure! Here is the answer: {'
      else if (state.mode === 'invalid-schema') content = JSON.stringify({ text: 'free text' })
      else if (state.mode === 'echo-data') {
        // Modèle qui suit les consignes injectées : recopie toutes les données.
        const injected = /CANARY-[0-9]+/.exec(JSON.stringify(data))?.[0] ?? ''
        const out = wellBehaved(parsed.format.required ?? [], data)
        content = JSON.stringify(Object.fromEntries(Object.entries(out).map(([k, v]) => [k, typeof v === 'string' ? `${injected} ${v}`.trim() : v])))
      }
      else if (state.mode === 'uncited' && (parsed.format.required ?? []).includes('suggestion')) {
        // Pré-tri tranché, citation inventée : doit redevenir « à confirmer ».
        content = JSON.stringify({ suggestion: 'likely-false-positive', summary: 'Looks fake.', reasons: [{ kind: 'dummy-value', quote: 'value = "changeme-not-in-data"', explanation: 'Placeholder.' }] })
      }
      else content = JSON.stringify(wellBehaved(parsed.format.required ?? [], data))
      return send(res, 200, { model: parsed.model, message: { role: 'assistant', content }, done: true })
    }
    return send(res, 404, { error: 'unknown path' })
  }

  const server: Server = createServer((req, res) => {
    handle(req, res).catch(() => send(res, 500, { error: 'fake failure' }))
  })
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve))
  const port = (server.address() as AddressInfo).port
  Object.assign(fake, {
    url: `http://127.0.0.1:${port}`,
    port,
    requests,
    models,
    chatCount: () => state.chats,
    close: () => new Promise<void>((resolve) => {
      server.closeAllConnections()
      server.close(() => resolve())
    }),
  })
  Object.defineProperty(fake, 'mode', {
    get: () => state.mode,
    set: (v: FakeMode) => {
      state.mode = v
    },
  })
  Object.defineProperty(fake, 'delayMs', {
    get: () => state.delayMs,
    set: (v: number) => {
      state.delayMs = v
    },
  })
  return fake
}
