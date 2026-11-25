// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// J9, J13 (0.8, chantier D) : client OCI contre un faux registre : jeton
// Bearer, copie par empreinte (montage, flux, index), empreinte relue,
// attestation au format cosign, références et réponses hostiles.

import { createHash } from 'node:crypto'
import { afterEach, describe, expect, it } from 'vitest'
import {
  RegistryClient, RegistryError, attestationTag, checkDigest, copyImage, imageRevisions, parseChallenge, parseRepository, pushAttestation, setRegistryTransport,
} from '../../server/deploy/registry'
import { fakeRegistry } from '../helpers/fake-registry'

const HOST = 'registre.exemple.test'
const code = async (p: Promise<unknown>) => p.then(() => null, (e: unknown) => (e instanceof RegistryError ? e.code : String(e)))

describe('deploy-registry', () => {
  afterEach(() => setRegistryTransport())

  it('références : dépôt seul, sans étiquette, sans schéma, sans ..', () => {
    expect(parseRepository('registre.exemple.test/valide/app')).toEqual({ host: HOST, repo: 'valide/app' })
    expect(parseRepository('registre.exemple.test:5000/a')).toEqual({ host: 'registre.exemple.test:5000', repo: 'a' })
    for (const bad of ['app', 'https://registre.exemple.test/a', 'registre.exemple.test/A', 'registre.exemple.test/a:v1', 'registre.exemple.test/../a', 'registre.exemple.test/a@sha256:00']) {
      expect(() => parseRepository(bad), bad).toThrow(RegistryError)
    }
    expect(() => checkDigest('sha256:zz')).toThrow(RegistryError)
    expect(attestationTag(`sha256:${'a'.repeat(64)}`)).toBe(`sha256-${'a'.repeat(64)}.att`)
    expect(parseChallenge('Bearer realm="https://r/token",service="r"')).toEqual({ scheme: 'bearer', params: { realm: 'https://r/token', service: 'r' } })
    expect(parseChallenge(undefined)).toBeNull()
  })

  it('copie par empreinte dans le même registre : montage, étiquette, empreinte relue', async () => {
    const reg = fakeRegistry(HOST, { token: 'jeton-de-test' })
    setRegistryTransport(reg.transport)
    const digest = reg.addImage('candidat/app', 'v1.0.0')
    const c = new RegistryClient(HOST, { username: 'robot', password: 'mot-de-passe' })
    expect(await c.resolve('candidat/app', 'v1.0.0')).toBe(digest)
    await copyImage(c, 'candidat/app', c, 'valide/app', digest, 'v1.0.0')
    expect(reg.manifests.get('valide/app')?.has(digest)).toBe(true)
    expect(reg.manifests.get('valide/app')?.has('v1.0.0')).toBe(true)
    expect(reg.log.some(l => l.includes('mount='))).toBe(true)
    expect(reg.log.filter(l => l.startsWith('GET /v2/candidat/app/blobs/'))).toHaveLength(0)
  })

  it('copie entre deux registres en flux, index multi-architecture compris', async () => {
    const a = fakeRegistry('a.exemple.test')
    const b = fakeRegistry('b.exemple.test')
    setRegistryTransport((url, init) => (new URL(url).host === 'a.exemple.test' ? a.transport(url, init) : b.transport(url, init)))
    const digest = a.addIndex('candidat/app', 'v2')
    await copyImage(new RegistryClient('a.exemple.test'), 'candidat/app', new RegistryClient('b.exemple.test'), 'valide/app', digest, null)
    expect(b.manifests.get('valide/app')?.has(digest)).toBe(true)
    expect(b.blobs.get('valide/app')?.size).toBe(4)
  })

  it('blob altéré en route : copie refusée', async () => {
    const a = fakeRegistry('a.exemple.test')
    const b = fakeRegistry('b.exemple.test')
    setRegistryTransport((url, init) => (new URL(url).host === 'a.exemple.test' ? a.transport(url, init) : b.transport(url, init)))
    const digest = a.addImage('candidat/app', 'v3')
    a.corruptBlobs = true
    expect(await code(copyImage(new RegistryClient('a.exemple.test'), 'candidat/app', new RegistryClient('b.exemple.test'), 'valide/app', digest, null)))
      .toMatch(/E_REGISTRY_(DIGEST|TOO_LARGE|RESPONSE)/)
  })

  it('erreurs : étiquette absente, empreinte qui ne correspond pas, accès refusé, jeton faux', async () => {
    const reg = fakeRegistry(HOST, { token: 'bon', basic: Buffer.from('robot:bon-mdp').toString('base64') })
    setRegistryTransport(reg.transport)
    reg.addImage('candidat/app', 'v1')
    const good = new RegistryClient(HOST, { username: 'robot', password: 'bon-mdp' })
    expect(await code(good.resolve('candidat/app', 'absente'))).toBe('E_REGISTRY_NOT_FOUND')
    expect(await code(good.manifest('candidat/app', `sha256:${'0'.repeat(64)}`))).toBe('E_REGISTRY_NOT_FOUND')
    expect(await code(new RegistryClient(HOST, { username: 'robot', password: 'faux' }).resolve('candidat/app', 'v1'))).toBe('E_REGISTRY_AUTH')
    expect(await code(good.resolve('candidat/app', '../x'))).toBe('E_REGISTRY_REF')
    expect(() => new RegistryClient('https://x')).toThrow(RegistryError)
  })

  it('attestation au format cosign : couche DSSE ajoutée une seule fois, couches existantes gardées', async () => {
    const reg = fakeRegistry(HOST)
    setRegistryTransport(reg.transport)
    const digest = reg.addImage('valide/app', 'v1')
    const c = new RegistryClient(HOST)
    const env = Buffer.from('{"payloadType":"application/vnd.in-toto+json","payload":"e30=","signatures":[]}')
    const where = await pushAttestation(c, 'valide/app', digest, env, 'urn:test')
    expect(where).toBe(`${HOST}/valide/app:${attestationTag(digest)}`)
    await pushAttestation(c, 'valide/app', digest, env, 'urn:test')
    const env2 = Buffer.from(`${env.toString()} `)
    await pushAttestation(c, 'valide/app', digest, env2, 'urn:test')
    const m = JSON.parse(reg.manifests.get('valide/app')!.get(attestationTag(digest))!.body.toString())
    expect(m.layers).toHaveLength(2)
    expect(m.layers[0]).toMatchObject({ mediaType: 'application/vnd.dsse.envelope.v1+json', digest: `sha256:${createHash('sha256').update(env).digest('hex')}`,
      annotations: { 'dev.cosignproject.cosign/signature': '', 'predicateType': 'urn:test' } })
    reg.readOnly.add('valide/app')
    expect(await code(pushAttestation(c, 'valide/app', digest, Buffer.from('{}'), 'urn:test'))).toBe('E_REGISTRY_DENIED')
  })

  it('révisions déclarées : étiquette OCI de la configuration et des annotations, index compris', async () => {
    const reg = fakeRegistry(HOST)
    setRegistryTransport(reg.transport)
    const c = new RegistryClient(HOST)
    const plain = reg.addImage('candidat/app', 'sans')
    expect([...await imageRevisions(c, 'candidat/app', plain)]).toEqual([])
    const labelled = reg.addImage('candidat/app', 'avec', { 'org.opencontainers.image.revision': ` ${'A'.repeat(40)} ` })
    expect([...await imageRevisions(c, 'candidat/app', labelled)]).toEqual(['a'.repeat(40)])
    const idx = reg.addIndex('candidat/app', 'multi')
    expect([...await imageRevisions(c, 'candidat/app', idx)]).toEqual([])
    reg.corruptBlobs = true
    await expect(imageRevisions(c, 'candidat/app', labelled)).rejects.toThrow()
  })
})
