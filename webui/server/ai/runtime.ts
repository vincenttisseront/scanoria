// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Boucle du service scanoria-ai (CLAUDE.md § 3.5) : configuration lue dans
// /run/scanoria-ai (copiée par scanoria-ai-setup prestart), découverte des
// modèles rafraîchie, une tâche à la fois, attente quand la file est vide ou
// que le disjoncteur est ouvert. Un changement de connecteur redémarre le
// service (helper), qui relit alors tout.

import { chmod, readFile, unlink } from 'node:fs/promises'
import { createServer, type Server } from 'node:https'
import { join } from 'node:path'
import type { Queryable } from '../utils/db'
import { loadAiSettings, loadEndpoint, type ActiveEndpoint } from './config'
import { OllamaClient } from './ollama'
import { fileTokenLookup, Relay, RELAY_CERT_FILE, RELAY_KEY_FILE, RELAY_SOCKET, relayHandler, type TokenLookup } from './relay'
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
  const verifyTls = endpoint.tls_verify !== false
  const caPem = verifyTls && endpoint.ca ? await readFile(join(runtimeDir, 'ca.pem'), 'utf8') : null
  let token: string | null = null
  if (endpoint.token) {
    const { tokenCredentialId } = await loadAiSettings(db)
    if (!tokenCredentialId) throw new Error('token configured but not stored')
    token = await tokens.read(db, tokenCredentialId)
  }
  return new OllamaClient({
    scheme: endpoint.scheme, host: endpoint.host, port: endpoint.port, addresses: endpoint.addresses, token, caPem, verifyTls,
  })
}

function cachedClient(opts: RuntimeOptions): (ep: ActiveEndpoint) => Promise<OllamaLike> {
  let cached: { at: number, client: OllamaLike } | undefined
  return async (ep) => {
    if (!cached || Date.now() - cached.at > 300_000) cached = { at: Date.now(), client: await clientFor(opts.db, ep, opts.runtimeDir) }
    return cached.client
  }
}

export function createService(opts: RuntimeOptions, client = cachedClient(opts)): AiService {
  return new AiService({
    db: opts.db,
    loadEndpoint: () => loadEndpoint(join(opts.runtimeDir, 'ai.json')),
    clientFor: client,
    log: opts.log,
  })
}

/**
 * Relais IA des modules (0.7, contrat 31) : HTTPS sur le socket Unix
 * runtimeDir/relay.sock, certificat ai-relay.<nom> de l'AC interne copié par
 * scanoria-ai-setup prestart. Sans certificat, le relais n'est pas servi et
 * les modules K sont « skipped » (vérification préalable du runner).
 * Le disjoncteur et la découverte des modèles sont ceux de la file.
 */
export async function startRelay(opts: RuntimeOptions, service: AiService, client: (ep: ActiveEndpoint) => Promise<OllamaLike>, tokens: TokenLookup = fileTokenLookup()): Promise<Server | null> {
  const log = opts.log ?? (() => {})
  let cert: string, key: string
  try {
    cert = await readFile(join(opts.runtimeDir, RELAY_CERT_FILE), 'utf8')
    key = await readFile(join(opts.runtimeDir, RELAY_KEY_FILE), 'utf8')
  }
  catch {
    log('relay: no certificate, AI modules relay not served')
    return null
  }
  const relay = new Relay({
    db: opts.db,
    tokens,
    loadEndpoint: () => loadEndpoint(join(opts.runtimeDir, 'ai.json')),
    clientFor: client,
    circuit: service.circuit,
    selection: async () => (await service.latestProbe())?.selection ?? null,
    log,
  })
  const server = createServer({ cert, key, minVersion: 'TLSv1.2' }, relayHandler(relay, log))
  server.headersTimeout = 10_000
  server.requestTimeout = 360_000
  server.maxConnections = 32
  const path = join(opts.runtimeDir, RELAY_SOCKET)
  await unlink(path).catch(() => {})
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject)
    server.listen(path, () => resolve())
  })
  // Joignable par l'utilisateur du conteneur (65534) à travers le seul montage
  // du socket ; le répertoire runtimeDir reste 0700, inaccessible sur l'hôte.
  await chmod(path, 0o666)
  log(`relay: listening on ${path}`)
  return server
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
  const client = cachedClient({ ...opts, log })
  const service = createService({ ...opts, log }, client)
  const relay = await startRelay({ ...opts, log }, service, client).catch((err: Error) => {
    log(`relay: cannot start: ${err.message}`)
    return null
  })
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
  if (relay) await new Promise<void>(resolve => relay.close(() => resolve()))
}
