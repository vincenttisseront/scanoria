// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Transport des forges : cause réseau précise (DNS, sortie refusée sur
// l'appliance, TLS, délai, injoignable), adresse résolue de bouclage refusée,
// et transport HTTPS réel contre un serveur local (certificat généré).
// Régression 0.4.0 : « Forge injoignable » sans cause, alors que la sortie
// réseau de la console était coupée par systemd (EPERM).

import { execFileSync } from 'node:child_process'
import { mkdtemp, readFile, rm } from 'node:fs/promises'
import { createServer, type Server } from 'node:https'
import type { AddressInfo } from 'node:net'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest'
import {
  ForgeError, classifyNetworkError, createHttpsTransport, forbiddenResolvedAddress, forgeGet, forgeGetJson, setForgeTransport,
} from '../../server/forges/http'

const sysErr = (code: string) => Object.assign(new TypeError('fetch failed'), { cause: Object.assign(new Error('x'), { code }) })

describe('cause réseau d\'une erreur de forge', () => {
  it.each([
    ['ENOTFOUND', 'E_FORGE_DNS'],
    ['EAI_AGAIN', 'E_FORGE_DNS'],
    ['EPERM', 'E_FORGE_BLOCKED'],
    ['EACCES', 'E_FORGE_BLOCKED'],
    ['CERT_HAS_EXPIRED', 'E_FORGE_TLS'],
    ['DEPTH_ZERO_SELF_SIGNED_CERT', 'E_FORGE_TLS'],
    ['UNABLE_TO_VERIFY_LEAF_SIGNATURE', 'E_FORGE_TLS'],
    ['ERR_TLS_CERT_ALTNAME_INVALID', 'E_FORGE_TLS'],
    ['ETIMEDOUT', 'E_FORGE_TIMEOUT'],
    ['ECONNREFUSED', 'E_FORGE_UNREACHABLE'],
    ['EHOSTUNREACH', 'E_FORGE_UNREACHABLE'],
  ])('%s → %s, code système gardé en détail', (code, expected) => {
    for (const err of [sysErr(code), Object.assign(new Error('x'), { code })]) {
      const f = classifyNetworkError(err)
      expect(f.code).toBe(expected)
      expect(f.detail).toBe(code)
      expect(f.message).toBe(`${expected} (${code})`)
    }
  })

  it('délai dépassé et cause inconnue', () => {
    expect(classifyNetworkError(Object.assign(new Error('t'), { name: 'TimeoutError' })).code).toBe('E_FORGE_TIMEOUT')
    const unknown = classifyNetworkError(new Error('https://jeton@exemple.test/'))
    expect(unknown.code).toBe('E_FORGE_UNREACHABLE')
    expect(unknown.detail).toBeNull()
    expect(unknown.message).not.toContain('exemple')
    // Un « code » qui n'est pas un code système n'est jamais repris.
    expect(classifyNetworkError(Object.assign(new Error('x'), { code: '<b>x</b>' })).detail).toBeNull()
  })

  it('forgeGet lève la cause précise du transport', async () => {
    setForgeTransport(async () => {
      throw sysErr('EPERM')
    })
    try {
      const err = await forgeGet('https://forge.exemple.test/api', { authScheme: 'token', token: 'x' }).catch(e => e)
      expect(err).toBeInstanceOf(ForgeError)
      expect(err.code).toBe('E_FORGE_BLOCKED')
      expect(err.detail).toBe('EPERM')
    }
    finally {
      setForgeTransport()
    }
  })
})

describe('adresses résolues refusées', () => {
  it('bouclage, lien local, non spécifiée et multidiffusion', () => {
    for (const a of ['127.0.0.1', '127.8.9.1', '::1', '0.0.0.0', '169.254.169.254', 'fe80::1', '::ffff:127.0.0.1', '224.0.0.1', 'ff02::1']) {
      expect(forbiddenResolvedAddress(a), a).toBe(true)
    }
    for (const a of ['192.0.2.10', '198.51.100.4', '10.1.2.3', '2001:db8::1']) {
      expect(forbiddenResolvedAddress(a), a).toBe(false)
    }
  })

  it('un nom qui résout vers le bouclage est refusé à la connexion', async () => {
    const err = await forgeGet('https://localhost:9/api', { authScheme: 'token' }).catch(e => e)
    expect(err).toBeInstanceOf(ForgeError)
    expect(err.code).toBe('E_FORGE_URL')
    expect(err.detail).toBe('RESOLVED_LOCAL')
  })
})

const hasOpenssl = (() => {
  try {
    execFileSync('openssl', ['version'], { stdio: 'ignore' })
    return true
  }
  catch {
    return false
  }
})()

describe.skipIf(!hasOpenssl)('transport HTTPS réel (serveur local)', () => {
  let dir: string
  let server: Server
  let port: number
  let cert: string
  const allowLoopback = { refuseAddress: () => false }

  beforeAll(async () => {
    dir = await mkdtemp(join(tmpdir(), 'scanoria-forge-tls-'))
    execFileSync('openssl', [
      'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes', '-days', '1',
      '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost',
      '-keyout', join(dir, 'k.pem'), '-out', join(dir, 'c.pem'),
    ], { stdio: 'ignore' })
    cert = await readFile(join(dir, 'c.pem'), 'utf8')
    server = createServer({ key: await readFile(join(dir, 'k.pem')), cert }, (req, res) => {
      if (req.url === '/redir') {
        res.writeHead(302, { location: '/ok' }).end()
        return
      }
      if (req.url === '/vide') {
        res.writeHead(204).end()
        return
      }
      res.writeHead(200, { 'content-type': 'application/json', 'x-auth': String(req.headers.authorization ?? '') })
      res.end(JSON.stringify({ path: req.url, encoding: req.headers['accept-encoding'] }))
    })
    await new Promise<void>(r => server.listen(0, '127.0.0.1', r))
    port = (server.address() as AddressInfo).port
  })

  afterEach(() => setForgeTransport())

  afterAll(async () => {
    await new Promise<void>(r => server.close(() => r()))
    await rm(dir, { recursive: true, force: true })
  })

  it('lit une réponse JSON, suit une redirection du même hôte', async () => {
    setForgeTransport(createHttpsTransport({ ...allowLoopback, ca: cert }))
    const { data, headers } = await forgeGetJson<{ path: string, encoding: string }>(`https://localhost:${port}/redir`, { authScheme: 'Bearer', token: 'jeton-test' })
    expect(data).toEqual({ path: '/ok', encoding: 'identity' })
    expect(headers.get('x-auth')).toBe('Bearer jeton-test')
    const empty = await forgeGet(`https://localhost:${port}/vide`, { authScheme: 'token' })
    expect(empty.status).toBe(204)
    expect(empty.body.length).toBe(0)
  })

  it('certificat inconnu → E_FORGE_TLS avec sa cause', async () => {
    setForgeTransport(createHttpsTransport(allowLoopback))
    const err = await forgeGet(`https://localhost:${port}/ok`, { authScheme: 'token' }).catch(e => e)
    expect(err).toBeInstanceOf(ForgeError)
    expect(err.code).toBe('E_FORGE_TLS')
    expect(err.detail).toMatch(/SELF_SIGNED|UNABLE_TO|CERT/)
  })

  it('port fermé → E_FORGE_UNREACHABLE (ECONNREFUSED)', async () => {
    setForgeTransport(createHttpsTransport({ ...allowLoopback, ca: cert }))
    const err = await forgeGet('https://localhost:9/ok', { authScheme: 'token' }).catch(e => e)
    expect(err.code).toBe('E_FORGE_UNREACHABLE')
    expect(err.detail).toBe('ECONNREFUSED')
  })
})
