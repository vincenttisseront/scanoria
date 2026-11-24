// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Boucle du service scanoria-ai (CLAUDE.md § 3.5) : configuration lue dans
// /run/scanoria-ai (copiée par scanoria-ai-setup prestart), découverte des
// modèles rafraîchie, une tâche à la fois, attente quand la file est vide ou
// que le disjoncteur est ouvert. Un changement de connecteur redémarre le
// service (helper), qui relit alors tout.

import { readFile } from 'node:fs/promises'
import { join } from 'node:path'
import type { Queryable } from '../utils/db'
import { loadAiSettings, loadEndpoint, type ActiveEndpoint } from './config'
import { OllamaClient } from './ollama'
import { AiService, type OllamaLike } from './service'
import { runtimeTokenStore, type TokenStore } from './token'

export interface RuntimeOptions {
  db: Queryable
  runtimeDir: string
  idleMs?: number
  probeEveryMs?: number
  log?: (msg: string) => void
}

/** Client Ollama du service ; le jeton est lu avec la seule clé copiée dans runtimeDir (ai-token.key). */
export async function clientFor(db: Queryable, endpoint: ActiveEndpoint, runtimeDir: string, tokens: TokenStore = runtimeTokenStore(runtimeDir)): Promise<OllamaLike> {
  const caPem = endpoint.ca ? await readFile(join(runtimeDir, 'ca.pem'), 'utf8') : null
  let token: string | null = null
  if (endpoint.token) {
    const { tokenCredentialId } = await loadAiSettings(db)
    if (!tokenCredentialId) throw new Error('token configured but not stored')
    token = await tokens.read(db, tokenCredentialId)
  }
  return new OllamaClient({
    scheme: endpoint.scheme, host: endpoint.host, port: endpoint.port, addresses: endpoint.addresses, token, caPem,
  })
}

export function createService(opts: RuntimeOptions): AiService {
  let cached: { at: number, client: OllamaLike } | undefined
  return new AiService({
    db: opts.db,
    loadEndpoint: () => loadEndpoint(join(opts.runtimeDir, 'ai.json')),
    clientFor: async (ep) => {
      if (!cached || Date.now() - cached.at > 300_000) cached = { at: Date.now(), client: await clientFor(opts.db, ep, opts.runtimeDir) }
      return cached.client
    },
    log: opts.log,
  })
}

const sleep = (ms: number, signal: AbortSignal) => new Promise<void>((resolve) => {
  if (signal.aborted) return resolve()
  const t = setTimeout(resolve, ms)
  signal.addEventListener('abort', () => {
    clearTimeout(t)
    resolve()
  }, { once: true })
})

/** Boucle principale ; s'arrête proprement quand signal est levé. */
export async function runLoop(opts: RuntimeOptions, signal: AbortSignal): Promise<void> {
  const log = opts.log ?? ((m: string) => console.log(`[scanoria-ai] ${m}`))
  const service = createService({ ...opts, log })
  const idle = opts.idleMs ?? 3000
  const probeEvery = opts.probeEveryMs ?? 600_000
  const recovered = await service.recover()
  if (recovered) log(`${recovered} interrupted task(s) queued again`)
  let lastProbeCheck = 0
  while (!signal.aborted) {
    const endpoint = await loadEndpoint(join(opts.runtimeDir, 'ai.json'))
    if (endpoint.enabled && Date.now() - lastProbeCheck > probeEvery) {
      lastProbeCheck = Date.now()
      await service.ensureFreshProbe().catch(err => log(`probe scheduling failed: ${(err as Error).message}`))
    }
    let r
    try {
      r = await service.tick()
    }
    catch (err) {
      log(`queue error: ${(err as Error).message}`)
      r = { state: 'waiting' as const, ms: 10_000 }
    }
    if (r.state === 'idle') await sleep(endpoint.enabled ? idle : idle * 10, signal)
    else if (r.state === 'waiting') await sleep(Math.max(r.ms, 500), signal)
  }
}
