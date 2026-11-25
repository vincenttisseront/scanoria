// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Faux registre OCI en mémoire pour les tests (0.8, chantier D) : API
// distribution v2 (manifestes, blobs, montage entre dépôts, téléversement
// monolithique), jeton Bearer obligatoire en option, journal des requêtes.

import { createHash } from 'node:crypto'
import { Readable } from 'node:stream'
import type { RegistryRequestInit, RegistryResponse, RegistryTransport } from '../../server/deploy/registry'

export interface FakeRegistry {
  transport: RegistryTransport
  blobs: Map<string, Map<string, Buffer>>
  manifests: Map<string, Map<string, { type: string, body: Buffer }>>
  log: string[]
  /** Dépôts refusés en écriture (403 sur PUT et POST). */
  readOnly: Set<string>
  addImage: (repo: string, tag: string) => string
  addIndex: (repo: string, tag: string) => string
  corruptBlobs: boolean
}

const sha = (b: Buffer) => `sha256:${createHash('sha256').update(b).digest('hex')}`

async function body(b: Buffer | Readable | undefined): Promise<Buffer> {
  if (!b) return Buffer.alloc(0)
  if (Buffer.isBuffer(b)) return b
  const chunks: Buffer[] = []
  for await (const c of b) chunks.push(c as Buffer)
  return Buffer.concat(chunks)
}

function res(status: number, headers: Record<string, string> = {}, data: Buffer | string = ''): RegistryResponse {
  return { status, headers: Object.fromEntries(Object.entries(headers).map(([k, v]) => [k.toLowerCase(), v])), body: Readable.from([Buffer.from(data)]) }
}

export function fakeRegistry(host: string, opts: { token?: string, basic?: string } = {}): FakeRegistry {
  const reg: FakeRegistry = {
    blobs: new Map(), manifests: new Map(), log: [], readOnly: new Set(), corruptBlobs: false,
    transport: async () => res(500),
    addImage(repo, tag) {
      const layer = Buffer.from(`couche ${repo} ${tag}`)
      const config = Buffer.from(JSON.stringify({ architecture: 'amd64', os: 'linux', tag }))
      put(repo, 'blob', sha(layer), layer)
      put(repo, 'blob', sha(config), config)
      const m = Buffer.from(JSON.stringify({ schemaVersion: 2, mediaType: 'application/vnd.oci.image.manifest.v1+json',
        config: { mediaType: 'application/vnd.oci.image.config.v1+json', digest: sha(config), size: config.length },
        layers: [{ mediaType: 'application/vnd.oci.image.layer.v1.tar+gzip', digest: sha(layer), size: layer.length }] }))
      put(repo, 'manifest', sha(m), m, 'application/vnd.oci.image.manifest.v1+json')
      put(repo, 'manifest', tag, m, 'application/vnd.oci.image.manifest.v1+json')
      return sha(m)
    },
    addIndex(repo, tag) {
      const a = reg.addImage(repo, `${tag}-amd64`)
      const b = reg.addImage(repo, `${tag}-arm64`)
      const idx = Buffer.from(JSON.stringify({ schemaVersion: 2, mediaType: 'application/vnd.oci.image.index.v1+json',
        manifests: [a, b].map(d => ({ mediaType: 'application/vnd.oci.image.manifest.v1+json', digest: d, size: 1 })) }))
      put(repo, 'manifest', sha(idx), idx, 'application/vnd.oci.image.index.v1+json')
      put(repo, 'manifest', tag, idx, 'application/vnd.oci.image.index.v1+json')
      return sha(idx)
    },
  }
  function put(repo: string, kind: 'blob' | 'manifest', ref: string, data: Buffer, type = '') {
    if (kind === 'blob') {
      if (!reg.blobs.has(repo)) reg.blobs.set(repo, new Map())
      reg.blobs.get(repo)!.set(ref, data)
    }
    else {
      if (!reg.manifests.has(repo)) reg.manifests.set(repo, new Map())
      reg.manifests.get(repo)!.set(ref, { type, body: data })
    }
  }
  reg.transport = async (url: string, init: RegistryRequestInit) => {
    const u = new URL(url)
    reg.log.push(`${init.method} ${u.pathname}${u.search}`)
    if (u.host !== host) return res(404)
    if (u.pathname === '/token') {
      if (opts.basic && init.headers.authorization !== `Basic ${opts.basic}`) return res(401)
      return res(200, { 'content-type': 'application/json' }, JSON.stringify({ token: opts.token }))
    }
    if (opts.token && init.headers.authorization !== `Bearer ${opts.token}`) {
      await body(init.body)
      return res(401, { 'www-authenticate': `Bearer realm="https://${host}/token",service="${host}"` })
    }
    if (u.pathname === '/v2/') return res(200)
    const m = /^\/v2\/(.+)\/(manifests|blobs)\/(.+)$/.exec(u.pathname)
    const up = /^\/v2\/(.+)\/blobs\/uploads\/(.*)$/.exec(u.pathname)
    if (up) {
      const repo = up[1]!
      if (reg.readOnly.has(repo)) return res(403)
      if (init.method === 'POST') {
        const mount = u.searchParams.get('mount')
        const from = u.searchParams.get('from')
        if (mount && from && reg.blobs.get(from)?.has(mount)) {
          put(repo, 'blob', mount, reg.blobs.get(from)!.get(mount)!)
          return res(201)
        }
        return res(202, { location: `/v2/${repo}/blobs/uploads/session-${reg.log.length}` })
      }
      if (init.method === 'PUT') {
        const data = await body(init.body)
        const digest = u.searchParams.get('digest') ?? ''
        if (sha(data) !== digest) return res(400)
        put(repo, 'blob', digest, data)
        return res(201)
      }
    }
    if (!m) return res(404)
    const [, repo, kind, ref] = m as unknown as [string, string, string, string]
    if (kind === 'blobs') {
      const b = reg.blobs.get(repo)?.get(ref)
      if (!b) return res(404)
      const data = reg.corruptBlobs ? Buffer.concat([b, Buffer.from('x')]) : b
      return init.method === 'HEAD' ? res(200, { 'content-length': String(b.length) }) : res(200, { 'content-length': String(data.length) }, data)
    }
    if (init.method === 'PUT') {
      if (reg.readOnly.has(repo)) return res(403)
      const data = await body(init.body)
      put(repo, 'manifest', ref, data, init.headers['content-type'] ?? '')
      if (!ref.startsWith('sha256:')) put(repo, 'manifest', sha(data), data, init.headers['content-type'] ?? '')
      return res(201)
    }
    const man = reg.manifests.get(repo)?.get(ref)
    if (!man) return res(404)
    return res(200, { 'content-type': man.type }, man.body)
  }
  return reg
}
