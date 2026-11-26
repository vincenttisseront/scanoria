// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Client de l'API HTTP d'Ollama (/api/version, /api/tags, /api/show,
// /api/chat, /api/embed), utilisé seulement par le service scanoria-ai (CLAUDE.md § 3.5).
// La connexion part toujours vers une adresse épinglée par le helper : le nom
// n'est jamais résolu ici (pas de rebond DNS), il ne sert qu'à l'en-tête Host
// et au nom TLS. Le corps d'une requête de chat est construit champ par
// champ : jamais d'outil (« tools »), jamais de flux.

import http from 'node:http'
import https from 'node:https'
import { rootCertificates } from 'node:tls'
import { isIP } from 'node:net'
import type { LookupFunction } from 'node:net'

export interface OllamaTarget {
  scheme: 'https' | 'http'
  host: string
  port: number
  addresses: string[]
  token?: string | null
  caPem?: string | null
  /** false : certificat du serveur accepté sans vérification (autosigné). Absent : vérifié. */
  verifyTls?: boolean
}

export class OllamaError extends Error {
  constructor(public readonly kind: 'timeout' | 'network' | 'http' | 'protocol', message: string, public readonly status?: number) {
    super(message)
    this.name = 'OllamaError'
  }
}

export interface ChatMessage {
  role: 'system' | 'user' | 'assistant'
  content: string
}

export interface ChatRequest {
  model: string
  messages: ChatMessage[]
  /** Schéma JSON imposé, « json » (JSON libre) ou null (texte, relais IA de la 0.7). */
  format: Record<string, unknown> | 'json' | null
  numCtx: number
  temperature?: number
  /** Longueur maximale de la réponse en jetons (relais IA, max_tokens) ; absent : défaut d'Ollama. */
  maxTokens?: number
}

export interface ChatResult {
  content: string
  bytesSent: number
  durationMs: number
}

export interface EmbedResult {
  embeddings: number[][]
  bytesSent: number
  durationMs: number
}

const MAX_RESPONSE = 4 * 1024 * 1024
/** Bornes d'un vecteur (ai_embeddings.vector, migration 009). */
export const EMBED_MIN_DIMS = 8
export const EMBED_MAX_DIMS = 8192
// 16 vecteurs de 8192 dimensions tiennent dans MAX_RESPONSE.
export const EMBED_MAX_INPUTS = 16

/** Vecteurs d'une réponse /api/embed : un par entrée, mêmes dimensions, nombres finis. */
/**
 * Retire les blocs de raisonnement `<think>…</think>` que certains modèles (Qwen3,
 * DeepSeek-R1…) placent dans leur réponse : l'appliance ne dépend d'aucun modèle,
 * et ni les tâches de la console ni les outils du relais ne savent les lire.
 * Un bloc non refermé est laissé tel quel (rien n'est deviné).
 */
export function stripReasoning(content: string): string {
  if (!content.includes('<think>')) return content
  return content.replace(/<think>[\s\S]*?<\/think>\s*/gi, '')
}

export function parseEmbeddings(json: unknown, expected: number): number[][] {
  const list = (json as { embeddings?: unknown })?.embeddings
  if (!Array.isArray(list) || list.length !== expected) throw new OllamaError('protocol', 'invalid embeddings')
  const dims = Array.isArray(list[0]) ? list[0].length : 0
  if (dims < EMBED_MIN_DIMS || dims > EMBED_MAX_DIMS) throw new OllamaError('protocol', 'invalid embedding size')
  for (const v of list) {
    if (!Array.isArray(v) || v.length !== dims || !v.every(x => typeof x === 'number' && Number.isFinite(x))) {
      throw new OllamaError('protocol', 'invalid embedding vector')
    }
  }
  return list as number[][]
}

/** Recherche de nom figée sur les adresses épinglées (aucune requête DNS). */
export function pinnedLookup(addresses: string[]): LookupFunction {
  let next = 0
  return ((_hostname: string, options: { all?: boolean }, callback: (...args: unknown[]) => void) => {
    const list = addresses.map(a => ({ address: a, family: isIP(a) }))
    if (options && typeof options === 'object' && options.all) {
      callback(null, list)
      return
    }
    const pick = list[next++ % list.length]!
    callback(null, pick.address, pick.family)
  }) as unknown as LookupFunction
}

export class OllamaClient {
  constructor(private readonly target: OllamaTarget) {
    if (target.addresses.length === 0) throw new Error('no pinned address')
  }

  private request(method: 'GET' | 'POST', path: string, body: unknown, timeoutMs: number): Promise<{ json: unknown, bytesSent: number }> {
    const t = this.target
    const payload = body === undefined ? undefined : Buffer.from(JSON.stringify(body), 'utf8')
    const headers: Record<string, string> = { 'accept': 'application/json', 'user-agent': 'scanoria-ai' }
    if (payload) {
      headers['content-type'] = 'application/json'
      headers['content-length'] = String(payload.length)
    }
    if (t.token) headers.authorization = `Bearer ${t.token}`
    const options: https.RequestOptions = {
      method,
      host: t.host,
      port: t.port,
      path,
      headers,
      lookup: pinnedLookup(t.addresses),
      agent: false,
      timeout: timeoutMs,
    }
    if (t.scheme === 'https') {
      options.servername = isIP(t.host) ? undefined : t.host
      // Vérification du certificat sauf choix explicite de l'administrateur
      // (skip_tls_verify) : le chiffrement reste, l'identité du serveur n'est plus prouvée.
      const verify = t.verifyTls !== false
      options.ca = verify && t.caPem ? [...rootCertificates, t.caPem] : undefined
      options.rejectUnauthorized = verify
      options.minVersion = 'TLSv1.2'
    }
    const mod = t.scheme === 'https' ? https : http
    return new Promise((resolve, reject) => {
      let settled = false
      const fail = (err: OllamaError) => {
        if (settled) return
        settled = true
        reject(err)
      }
      const req = mod.request(options, (res) => {
        const chunks: Buffer[] = []
        let size = 0
        res.on('data', (c: Buffer) => {
          size += c.length
          if (size > MAX_RESPONSE) {
            req.destroy()
            fail(new OllamaError('protocol', 'response too large'))
            return
          }
          chunks.push(c)
        })
        res.on('end', () => {
          if (settled) return
          const status = res.statusCode ?? 0
          if (status < 200 || status >= 300) {
            fail(new OllamaError('http', `HTTP ${status}`, status))
            return
          }
          try {
            const json: unknown = JSON.parse(Buffer.concat(chunks).toString('utf8'))
            settled = true
            resolve({ json, bytesSent: payload?.length ?? 0 })
          }
          catch {
            fail(new OllamaError('protocol', 'invalid JSON response'))
          }
        })
        res.on('error', () => fail(new OllamaError('network', 'response error')))
      })
      const timer = setTimeout(() => {
        req.destroy()
        fail(new OllamaError('timeout', `timed out after ${timeoutMs} ms`))
      }, timeoutMs)
      req.on('timeout', () => {
        req.destroy()
        fail(new OllamaError('timeout', `timed out after ${timeoutMs} ms`))
      })
      req.on('error', (err: Error) => fail(new OllamaError('network', err.message.slice(0, 200))))
      req.on('close', () => clearTimeout(timer))
      if (payload) req.write(payload)
      req.end()
    })
  }

  async version(timeoutMs = 5000): Promise<string> {
    const { json } = await this.request('GET', '/api/version', undefined, timeoutMs)
    const v = (json as { version?: unknown }).version
    if (typeof v !== 'string' || !/^[0-9A-Za-z][0-9A-Za-z.+_-]{0,63}$/.test(v)) throw new OllamaError('protocol', 'invalid version')
    return v
  }

  async tags(timeoutMs = 10_000): Promise<{ name: string, digest: string, size: number }[]> {
    const { json } = await this.request('GET', '/api/tags', undefined, timeoutMs)
    const models = (json as { models?: unknown }).models
    if (!Array.isArray(models)) throw new OllamaError('protocol', 'invalid tags')
    return models.slice(0, 200).flatMap((m: unknown) => {
      const o = m as { name?: unknown, model?: unknown, digest?: unknown, size?: unknown }
      const name = typeof o.name === 'string' ? o.name : typeof o.model === 'string' ? o.model : null
      if (!name || name.length > 200 || typeof o.digest !== 'string' || !/^(sha256:)?[0-9a-f]{12,64}$/.test(o.digest)) return []
      return [{ name, digest: o.digest.replace(/^sha256:/, ''), size: typeof o.size === 'number' ? o.size : 0 }]
    })
  }

  async show(model: string, timeoutMs = 10_000): Promise<Record<string, unknown>> {
    const { json } = await this.request('POST', '/api/show', { model }, timeoutMs)
    if (!json || typeof json !== 'object') throw new OllamaError('protocol', 'invalid show')
    return json as Record<string, unknown>
  }

  /** Une réponse complète, contrainte par le schéma de la tâche (ou texte libre pour le relais). */
  async chat(req: ChatRequest, timeoutMs: number): Promise<ChatResult> {
    const options: Record<string, number> = { num_ctx: req.numCtx, temperature: req.temperature ?? 0.1 }
    if (req.maxTokens) options.num_predict = req.maxTokens
    const body: Record<string, unknown> = {
      model: req.model,
      messages: req.messages.map(m => ({ role: m.role, content: m.content })),
      stream: false,
      options,
      keep_alive: '10m',
    }
    if (req.format !== null) body.format = req.format
    const started = Date.now()
    const { json, bytesSent } = await this.request('POST', '/api/chat', body, timeoutMs)
    const content = (json as { message?: { content?: unknown } }).message?.content
    if (typeof content !== 'string') throw new OllamaError('protocol', 'missing message content')
    return { content: stripReasoning(content), bytesSent, durationMs: Date.now() - started }
  }

  /** Embeddings (I7) : une liste de textes déjà masqués, un vecteur par texte. */
  async embed(model: string, input: string[], timeoutMs: number): Promise<EmbedResult> {
    if (input.length === 0 || input.length > EMBED_MAX_INPUTS) throw new OllamaError('protocol', 'invalid embed batch')
    const started = Date.now()
    const { json, bytesSent } = await this.request('POST', '/api/embed', { model, input, truncate: true, keep_alive: '10m' }, timeoutMs)
    return { embeddings: parseEmbeddings(json, input.length), bytesSent, durationMs: Date.now() - started }
  }
}
