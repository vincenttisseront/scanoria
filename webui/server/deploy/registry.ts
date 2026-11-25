// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// J9 et J13 (0.8, chantier D) : client minimal de registre OCI (distribution
// spec v1.1), dans le service sans privilège, jamais en root :
// - empreinte d'une étiquette, manifestes, blobs (montage entre dépôts d'un
//   même registre, sinon copie en flux avec empreinte recalculée) ;
// - copie d'une image PAR EMPREINTE (index multi-architecture compris),
//   empreinte relue dans la destination après la copie ;
// - attestation au format cosign (étiquette sha256-<hex>.att, couche DSSE).
// HTTPS seulement, résolution contrôlée (aucune adresse de bouclage ni de lien
// local), délais et tailles bornés, aucune redirection vers un autre hôte que
// le registre ou son serveur de jetons. Le jeton n'apparaît dans aucune erreur.

import { createHash } from 'node:crypto'
import { request as httpsRequest } from 'node:https'
import type { IncomingHttpHeaders } from 'node:http'
import { Readable, Transform } from 'node:stream'
import { pipeline } from 'node:stream/promises'
import { forbiddenResolvedAddress, forgeGuardedLookup } from '../forges/http'

export class RegistryError extends Error {
  constructor(public readonly code: RegistryErrorCode, public readonly status: number | null = null) {
    super(status ? `${code} (HTTP ${status})` : code)
    this.name = 'RegistryError'
  }
}
export const REGISTRY_ERROR_CODES = [
  'E_REGISTRY_REF', 'E_REGISTRY_UNREACHABLE', 'E_REGISTRY_AUTH', 'E_REGISTRY_DENIED', 'E_REGISTRY_NOT_FOUND',
  'E_REGISTRY_TOO_LARGE', 'E_REGISTRY_RESPONSE', 'E_REGISTRY_DIGEST', 'E_REGISTRY_TIMEOUT',
] as const
export type RegistryErrorCode = (typeof REGISTRY_ERROR_CODES)[number]

export interface RegistryResponse {
  status: number
  headers: IncomingHttpHeaders
  body: Readable
}
export interface RegistryRequestInit {
  method: 'GET' | 'HEAD' | 'POST' | 'PUT'
  headers: Record<string, string>
  body?: Buffer | Readable
  timeoutMs: number
}
export type RegistryTransport = (url: string, init: RegistryRequestInit) => Promise<RegistryResponse>

export interface TransportOptions {
  ca?: string
  refuseAddress?: (address: string) => boolean
}

export function createRegistryTransport(opts: TransportOptions = {}): RegistryTransport {
  const lookup = forgeGuardedLookup(opts.refuseAddress ?? forbiddenResolvedAddress)
  return (url, init) => new Promise((resolve, reject) => {
    const target = new URL(url)
    if (target.protocol !== 'https:' || target.username || target.password) return reject(new RegistryError('E_REGISTRY_REF'))
    const req = httpsRequest(target, {
      method: init.method,
      headers: { 'user-agent': 'scanoria-console', 'accept-encoding': 'identity', ...init.headers },
      lookup: lookup as never,
      timeout: init.timeoutMs,
      ...(opts.ca ? { ca: opts.ca } : {}),
    }, res => resolve({ status: res.statusCode ?? 0, headers: res.headers, body: res }))
    req.on('timeout', () => req.destroy(new RegistryError('E_REGISTRY_TIMEOUT')))
    req.on('error', err => reject(err instanceof RegistryError ? err : new RegistryError('E_REGISTRY_UNREACHABLE')))
    if (init.body instanceof Readable) {
      init.body.on('error', err => req.destroy(err))
      init.body.pipe(req)
    }
    else req.end(init.body)
  })
}

let transport: RegistryTransport = createRegistryTransport()

/** Tests : transport imposé (faux registre ou AC jetable) ; sans argument, rétablit le défaut. */
export function setRegistryTransport(t?: RegistryTransport): void {
  transport = t ?? createRegistryTransport()
}

export const MANIFEST_TYPES = [
  'application/vnd.oci.image.manifest.v1+json',
  'application/vnd.oci.image.index.v1+json',
  'application/vnd.docker.distribution.manifest.v2+json',
  'application/vnd.docker.distribution.manifest.list.v2+json',
] as const
const INDEX_TYPES = new Set<string>([MANIFEST_TYPES[1], MANIFEST_TYPES[3]])
export const MAX_MANIFEST_BYTES = 4 * 1024 * 1024
export const MAX_BLOB_BYTES = 20 * 1024 ** 3
export const MAX_INDEX_ENTRIES = 64
const API_TIMEOUT_MS = 15_000
const BLOB_TIMEOUT_MS = 120_000
const DIGEST_RE = /^sha256:[0-9a-f]{64}$/
const HOST_RE = /^(?=.{1,253}(:|$))[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+(:\d{1,5})?$/
const REPO_RE = /^[a-z0-9]+([._-][a-z0-9]+)*(\/[a-z0-9]+([._-][a-z0-9]+)*){0,9}$/
const TAG_RE = /^[A-Za-z0-9_][A-Za-z0-9._-]{0,127}$/

export interface ImageRepo {
  host: string
  repo: string
}

/** « registre.exemple.test/equipe/app » → {host, repo} ; refuse étiquette, empreinte, schéma. */
export function parseRepository(ref: string): ImageRepo {
  const i = ref.indexOf('/')
  const host = i > 0 ? ref.slice(0, i) : ''
  const repo = i > 0 ? ref.slice(i + 1) : ''
  if (ref.length > 500 || !HOST_RE.test(host) || !REPO_RE.test(repo)) throw new RegistryError('E_REGISTRY_REF')
  return { host, repo }
}

export function checkDigest(d: unknown): string {
  if (typeof d !== 'string' || !DIGEST_RE.test(d)) throw new RegistryError('E_REGISTRY_DIGEST')
  return d
}

export function checkTag(t: string): string {
  if (!TAG_RE.test(t)) throw new RegistryError('E_REGISTRY_REF')
  return t
}

export interface Credentials {
  username: string | null
  password: string | null
}

async function readAll(body: Readable, max: number): Promise<Buffer> {
  const chunks: Buffer[] = []
  let total = 0
  for await (const chunk of body) {
    total += (chunk as Buffer).length
    if (total > max) {
      body.destroy()
      throw new RegistryError('E_REGISTRY_TOO_LARGE')
    }
    chunks.push(chunk as Buffer)
  }
  return Buffer.concat(chunks)
}

function drain(res: RegistryResponse): void {
  res.body.resume()
}

/** Paramètres d'un en-tête WWW-Authenticate « Bearer realm=…,service=…,scope=… ». */
export function parseChallenge(header: string | undefined): { scheme: string, params: Record<string, string> } | null {
  if (!header || header.length > 2000) return null
  const m = /^(\w+)\s*(.*)$/s.exec(header.trim())
  if (!m) return null
  const params: Record<string, string> = {}
  for (const p of m[2]!.matchAll(/(\w+)="([^"]*)"/g)) params[p[1]!.toLowerCase()] = p[2]!
  return { scheme: m[1]!.toLowerCase(), params }
}

export class RegistryClient {
  private tokens = new Map<string, string>()
  readonly base: string

  constructor(readonly host: string, private readonly creds: Credentials = { username: null, password: null }) {
    if (!HOST_RE.test(host)) throw new RegistryError('E_REGISTRY_REF')
    this.base = `https://${host}`
  }

  private basic(): string | null {
    if (!this.creds.password) return null
    return `Basic ${Buffer.from(`${this.creds.username ?? 'scanoria'}:${this.creds.password}`).toString('base64')}`
  }

  private async token(challenge: { params: Record<string, string> }, scope: string): Promise<string> {
    const realm = challenge.params.realm
    let url: URL
    try {
      url = new URL(realm ?? '')
    }
    catch {
      throw new RegistryError('E_REGISTRY_AUTH')
    }
    // Le serveur de jetons est en HTTPS ; les identifiants n'y partent que
    // s'il est sur le même hôte que le registre (Harbor, distribution).
    if (url.protocol !== 'https:' || url.username || url.password) throw new RegistryError('E_REGISTRY_AUTH')
    if (challenge.params.service) url.searchParams.set('service', challenge.params.service)
    url.searchParams.set('scope', scope)
    const headers: Record<string, string> = { accept: 'application/json' }
    const basic = this.basic()
    if (basic && url.host === this.host) headers.authorization = basic
    const res = await this.send(url.toString(), { method: 'GET', headers, timeoutMs: API_TIMEOUT_MS })
    if (res.status !== 200) {
      drain(res)
      throw new RegistryError(res.status === 401 || res.status === 403 ? 'E_REGISTRY_AUTH' : 'E_REGISTRY_RESPONSE', res.status)
    }
    const data = JSON.parse((await readAll(res.body, 64 * 1024)).toString('utf8')) as { token?: unknown, access_token?: unknown }
    const tok = typeof data.token === 'string' ? data.token : typeof data.access_token === 'string' ? data.access_token : null
    if (!tok || tok.length > 16384) throw new RegistryError('E_REGISTRY_AUTH')
    return tok
  }

  private async send(url: string, init: RegistryRequestInit): Promise<RegistryResponse> {
    try {
      return await transport(url, init)
    }
    catch (err) {
      throw err instanceof RegistryError ? err : new RegistryError('E_REGISTRY_UNREACHABLE')
    }
  }

  /**
   * Requête vers /v2/<repo>/… avec authentification : Basic si le registre la
   * demande, sinon jeton Bearer obtenu pour la portée (pull ou pull,push).
   * Un corps en flux n'est jamais rejoué : l'authentification est d'abord
   * obtenue par une requête sans corps.
   */
  async request(repo: string, path: string, init: Omit<RegistryRequestInit, 'timeoutMs'> & { timeoutMs?: number, push?: boolean, location?: string }): Promise<RegistryResponse> {
    const scope = `repository:${repo}:${init.push ? 'pull,push' : 'pull'}`
    const url = init.location ?? `${this.base}/v2/${repo}${path}`
    const auth = (): Record<string, string> => {
      const tok = this.tokens.get(scope)
      return tok ? { authorization: `Bearer ${tok}` } : this.tokens.has('basic') ? { authorization: this.basic()! } : {}
    }
    if (init.body instanceof Readable && !this.tokens.has(scope) && !this.tokens.has('basic')) await this.authorize(repo, scope)
    const timeoutMs = init.timeoutMs ?? API_TIMEOUT_MS
    let res = await this.send(url, { ...init, headers: { ...init.headers, ...auth() }, timeoutMs })
    if (res.status === 401 && !(init.body instanceof Readable)) {
      drain(res)
      await this.authorize(repo, scope, res.headers['www-authenticate'] as string | undefined)
      res = await this.send(url, { ...init, headers: { ...init.headers, ...auth() }, timeoutMs })
    }
    if (res.status === 401) {
      drain(res)
      throw new RegistryError('E_REGISTRY_AUTH', 401)
    }
    if (res.status === 403) {
      drain(res)
      throw new RegistryError('E_REGISTRY_DENIED', 403)
    }
    return res
  }

  private async authorize(repo: string, scope: string, header?: string): Promise<void> {
    let challenge = parseChallenge(header)
    if (!challenge) {
      const probe = await this.send(`${this.base}/v2/`, { method: 'GET', headers: {}, timeoutMs: API_TIMEOUT_MS })
      drain(probe)
      if (probe.status !== 401) return
      challenge = parseChallenge(probe.headers['www-authenticate'] as string | undefined)
    }
    if (challenge?.scheme === 'basic') {
      if (!this.basic()) throw new RegistryError('E_REGISTRY_AUTH', 401)
      this.tokens.set('basic', '1')
      return
    }
    if (challenge?.scheme !== 'bearer') throw new RegistryError('E_REGISTRY_AUTH', 401)
    this.tokens.set(scope, await this.token(challenge, scope))
    void repo
  }

  /** Empreinte d'une étiquette (ou d'une empreinte) dans un dépôt. */
  async resolve(repo: string, reference: string): Promise<string> {
    return (await this.manifest(repo, reference)).digest
  }

  async manifest(repo: string, reference: string): Promise<{ mediaType: string, body: Buffer, digest: string }> {
    const ref = DIGEST_RE.test(reference) ? reference : checkTag(reference)
    const res = await this.request(repo, `/manifests/${ref}`, { method: 'GET', headers: { accept: MANIFEST_TYPES.join(', ') } })
    if (res.status === 404) {
      drain(res)
      throw new RegistryError('E_REGISTRY_NOT_FOUND', 404)
    }
    if (res.status !== 200) {
      drain(res)
      throw new RegistryError('E_REGISTRY_RESPONSE', res.status)
    }
    const body = await readAll(res.body, MAX_MANIFEST_BYTES)
    const digest = `sha256:${createHash('sha256').update(body).digest('hex')}`
    if (DIGEST_RE.test(reference) && digest !== reference) throw new RegistryError('E_REGISTRY_DIGEST')
    let mediaType = String(res.headers['content-type'] ?? '').split(';')[0]!.trim()
    try {
      const parsed = JSON.parse(body.toString('utf8')) as { mediaType?: unknown }
      if (typeof parsed.mediaType === 'string') mediaType = parsed.mediaType
    }
    catch {
      throw new RegistryError('E_REGISTRY_RESPONSE')
    }
    if (!(MANIFEST_TYPES as readonly string[]).includes(mediaType)) throw new RegistryError('E_REGISTRY_RESPONSE')
    return { mediaType, body, digest }
  }

  async hasBlob(repo: string, digest: string): Promise<boolean> {
    const res = await this.request(repo, `/blobs/${checkDigest(digest)}`, { method: 'HEAD', headers: {}, push: true })
    drain(res)
    return res.status === 200
  }

  /** Montage d'un blob depuis un autre dépôt du même registre ; faux si le registre refuse. */
  async mountBlob(repo: string, digest: string, from: string): Promise<boolean> {
    const res = await this.request(repo, `/blobs/uploads/?mount=${encodeURIComponent(checkDigest(digest))}&from=${encodeURIComponent(from)}`, { method: 'POST', headers: { 'content-length': '0' }, push: true })
    drain(res)
    if (res.status === 202 && typeof res.headers.location === 'string') {
      // Session ouverte sans montage : elle expire seule côté registre.
      return false
    }
    return res.status === 201
  }

  private uploadUrl(location: string): URL {
    const u = new URL(location, this.base)
    if (u.origin !== this.base) throw new RegistryError('E_REGISTRY_RESPONSE')
    return u
  }

  /** Téléversement monolithique (POST puis PUT ?digest=), corps en mémoire ou en flux. */
  async putBlob(repo: string, digest: string, body: Buffer | Readable, size: number): Promise<void> {
    if (size > MAX_BLOB_BYTES) throw new RegistryError('E_REGISTRY_TOO_LARGE')
    const start = await this.request(repo, '/blobs/uploads/', { method: 'POST', headers: { 'content-length': '0' }, push: true })
    drain(start)
    const loc = start.headers.location
    if (start.status !== 202 || typeof loc !== 'string') throw new RegistryError('E_REGISTRY_RESPONSE', start.status)
    const url = this.uploadUrl(loc)
    url.searchParams.set('digest', checkDigest(digest))
    const res = await this.request(repo, '', {
      method: 'PUT', push: true, location: url.toString(), timeoutMs: BLOB_TIMEOUT_MS,
      headers: { 'content-type': 'application/octet-stream', 'content-length': String(size) }, body,
    })
    drain(res)
    if (res.status !== 201) throw new RegistryError(res.status === 400 ? 'E_REGISTRY_DIGEST' : 'E_REGISTRY_RESPONSE', res.status)
  }

  /** Flux d'un blob (vérifié à la volée par l'appelant). */
  async blobStream(repo: string, digest: string): Promise<{ body: Readable, size: number }> {
    const res = await this.request(repo, `/blobs/${checkDigest(digest)}`, { method: 'GET', headers: {}, timeoutMs: BLOB_TIMEOUT_MS })
    if (res.status !== 200) {
      drain(res)
      throw new RegistryError(res.status === 404 ? 'E_REGISTRY_NOT_FOUND' : 'E_REGISTRY_RESPONSE', res.status)
    }
    const size = Number(res.headers['content-length'] ?? Number.NaN)
    if (!Number.isSafeInteger(size) || size < 0 || size > MAX_BLOB_BYTES) {
      res.body.destroy()
      throw new RegistryError('E_REGISTRY_TOO_LARGE')
    }
    return { body: res.body, size }
  }

  async putManifest(repo: string, reference: string, mediaType: string, body: Buffer): Promise<string> {
    const ref = DIGEST_RE.test(reference) ? reference : checkTag(reference)
    const res = await this.request(repo, `/manifests/${ref}`, {
      method: 'PUT', push: true, headers: { 'content-type': mediaType, 'content-length': String(body.length) }, body,
    })
    drain(res)
    if (res.status !== 201) throw new RegistryError('E_REGISTRY_RESPONSE', res.status)
    return `sha256:${createHash('sha256').update(body).digest('hex')}`
  }
}

/** Flux qui calcule le SHA-256 de ce qui passe et refuse un écart en fin de flux. */
export function digestGuard(expected: string, size: number): Transform {
  const hash = createHash('sha256')
  let seen = 0
  return new Transform({
    transform(chunk: Buffer, _enc, cb) {
      seen += chunk.length
      if (seen > size) return cb(new RegistryError('E_REGISTRY_TOO_LARGE'))
      hash.update(chunk)
      cb(null, chunk)
    },
    flush(cb) {
      if (seen !== size || `sha256:${hash.digest('hex')}` !== expected) return cb(new RegistryError('E_REGISTRY_DIGEST'))
      cb()
    },
  })
}

async function copyBlob(src: RegistryClient, srcRepo: string, dst: RegistryClient, dstRepo: string, digest: string): Promise<void> {
  if (await dst.hasBlob(dstRepo, digest)) return
  if (src.host === dst.host && await dst.mountBlob(dstRepo, digest, srcRepo)) return
  const { body, size } = await src.blobStream(srcRepo, digest)
  const guard = digestGuard(digest, size)
  // Les deux côtés sont attendus jusqu'au bout ; au moindre échec, les deux
  // flux sont détruits (aucune connexion laissée ouverte vers l'un ou l'autre registre).
  const [pipe, upload] = await Promise.allSettled([pipeline(body, guard), dst.putBlob(dstRepo, digest, guard, size)])
  const failed = [pipe, upload].find(r => r.status === 'rejected')
  if (failed) {
    body.destroy()
    guard.destroy()
    throw failed.reason
  }
}

const MAX_CONFIG_BYTES = 1024 * 1024
const REVISION_LABEL = 'org.opencontainers.image.revision'

/**
 * Commits déclarés par l'image (étiquette OCI `org.opencontainers.image.revision`
 * de l'index, des manifestes et de leur configuration). Sert à refuser une
 * étiquette candidate repoussée depuis l'analyse avec une image d'un autre commit.
 */
export async function imageRevisions(client: RegistryClient, repo: string, digest: string): Promise<Set<string>> {
  const out = new Set<string>()
  const note = (v: unknown) => {
    if (typeof v === 'string' && v.trim()) out.add(v.trim().toLowerCase())
  }
  const visit = async (m: { mediaType: string, body: Buffer }, depth: number) => {
    const parsed = JSON.parse(m.body.toString('utf8')) as { annotations?: Record<string, unknown> }
    note(parsed.annotations?.[REVISION_LABEL])
    const d = descriptors(m.body)
    if (INDEX_TYPES.has(m.mediaType)) {
      if (depth > 0 || d.manifests.length > MAX_INDEX_ENTRIES) throw new RegistryError('E_REGISTRY_RESPONSE')
      for (const child of d.manifests) await visit(await client.manifest(repo, child), depth + 1)
      return
    }
    if (!d.config) return
    const { body, size } = await client.blobStream(repo, d.config)
    if (size > MAX_CONFIG_BYTES) {
      body.destroy()
      throw new RegistryError('E_REGISTRY_TOO_LARGE')
    }
    const raw = await readAll(body, MAX_CONFIG_BYTES)
    if (`sha256:${createHash('sha256').update(raw).digest('hex')}` !== d.config) throw new RegistryError('E_REGISTRY_DIGEST')
    try {
      const cfg = JSON.parse(raw.toString('utf8')) as { config?: { Labels?: Record<string, unknown> } }
      note(cfg.config?.Labels?.[REVISION_LABEL])
    }
    catch {
      throw new RegistryError('E_REGISTRY_RESPONSE')
    }
  }
  await visit(await client.manifest(repo, checkDigest(digest)), 0)
  return out
}

interface Descriptor { mediaType?: unknown, digest?: unknown, size?: unknown }

function descriptors(body: Buffer): { config: string | null, layers: string[], manifests: string[] } {
  const m = JSON.parse(body.toString('utf8')) as { config?: Descriptor, layers?: Descriptor[], manifests?: Descriptor[] }
  const list = (x: Descriptor[] | undefined) => (Array.isArray(x) ? x : []).map(d => checkDigest(d?.digest))
  return { config: m.config ? checkDigest(m.config.digest) : null, layers: list(m.layers), manifests: list(m.manifests) }
}

/**
 * J13 : copie l'image `digest` de src vers dst, par empreinte (index et ses
 * manifestes compris), puis relit l'empreinte dans la destination. `tag`
 * facultatif : étiquette posée en plus, sur les mêmes octets.
 */
export async function copyImage(src: RegistryClient, srcRepo: string, dst: RegistryClient, dstRepo: string, digest: string, tag?: string | null): Promise<void> {
  const top = await src.manifest(srcRepo, checkDigest(digest))
  const copyManifest = async (m: { mediaType: string, body: Buffer, digest: string }) => {
    const d = descriptors(m.body)
    for (const blob of [...(d.config ? [d.config] : []), ...d.layers]) await copyBlob(src, srcRepo, dst, dstRepo, blob)
    await dst.putManifest(dstRepo, m.digest, m.mediaType, m.body)
  }
  if (INDEX_TYPES.has(top.mediaType)) {
    const children = descriptors(top.body).manifests
    if (children.length > MAX_INDEX_ENTRIES) throw new RegistryError('E_REGISTRY_TOO_LARGE')
    for (const child of children) {
      const cm = await src.manifest(srcRepo, child)
      if (INDEX_TYPES.has(cm.mediaType)) throw new RegistryError('E_REGISTRY_RESPONSE')
      await copyManifest(cm)
    }
    await dst.putManifest(dstRepo, top.digest, top.mediaType, top.body)
  }
  else await copyManifest(top)
  if (tag) await dst.putManifest(dstRepo, checkTag(tag), top.mediaType, top.body)
  if (await dst.resolve(dstRepo, digest) !== digest) throw new RegistryError('E_REGISTRY_DIGEST')
}

export const COSIGN_SIGNATURE_ANNOTATION = 'dev.cosignproject.cosign/signature'

/** Étiquette cosign d'une attestation : sha256-<hex>.att */
export function attestationTag(digest: string): string {
  return `${checkDigest(digest).replace(':', '-')}.att`
}

/**
 * J9 : pousse l'enveloppe DSSE au format cosign (manifeste OCI à l'étiquette
 * sha256-<hex>.att, une couche par attestation). Les attestations déjà
 * présentes sont gardées ; la même enveloppe n'est jamais ajoutée deux fois.
 */
export async function pushAttestation(client: RegistryClient, repo: string, digest: string, envelope: Buffer, predicateType: string): Promise<string> {
  const tag = attestationTag(digest)
  const layerDigest = `sha256:${createHash('sha256').update(envelope).digest('hex')}`
  type Layer = { mediaType: string, digest: string, size: number, annotations?: Record<string, string> }
  let layers: Layer[] = []
  try {
    const existing = await client.manifest(repo, tag)
    const parsed = JSON.parse(existing.body.toString('utf8')) as { layers?: Layer[] }
    layers = (Array.isArray(parsed.layers) ? parsed.layers : []).filter(l => typeof l?.digest === 'string' && DIGEST_RE.test(l.digest)).slice(0, 50)
  }
  catch (err) {
    if (!(err instanceof RegistryError) || err.code !== 'E_REGISTRY_NOT_FOUND') throw err
  }
  if (!layers.some(l => l.digest === layerDigest)) {
    await client.putBlob(repo, layerDigest, envelope, envelope.length)
    layers.push({
      mediaType: 'application/vnd.dsse.envelope.v1+json',
      digest: layerDigest,
      size: envelope.length,
      annotations: { [COSIGN_SIGNATURE_ANNOTATION]: '', predicateType },
    })
  }
  const config = Buffer.from(JSON.stringify({
    architecture: '', config: {}, created: '0001-01-01T00:00:00Z', history: [{ created: '0001-01-01T00:00:00Z' }], os: '',
    rootfs: { type: 'layers', diff_ids: layers.map(l => l.digest) },
  }))
  const configDigest = `sha256:${createHash('sha256').update(config).digest('hex')}`
  if (!await client.hasBlob(repo, configDigest)) await client.putBlob(repo, configDigest, config, config.length)
  const manifest = Buffer.from(JSON.stringify({
    schemaVersion: 2,
    mediaType: MANIFEST_TYPES[0],
    config: { mediaType: 'application/vnd.oci.image.config.v1+json', size: config.length, digest: configDigest },
    layers,
  }))
  await client.putManifest(repo, tag, MANIFEST_TYPES[0], manifest)
  return `${client.host}/${repo}:${tag}`
}
