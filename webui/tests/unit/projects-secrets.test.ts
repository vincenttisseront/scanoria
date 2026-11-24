// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Secrets (contrat 2) sans base : format, altérations, clé créée atomiquement
// en 0600, clé recréée qui rend les anciens secrets illisibles, indices.

import { mkdtemp, readFile, rm, stat, unlink, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { SecretError, loadSecretKey, openSecret, sealSecret, secretHint, secretKeyFile } from '../../server/utils/secrets'

describe('secrets : chiffrement AES-256-GCM', () => {
  let dir: string
  beforeAll(async () => {
    dir = await mkdtemp(join(tmpdir(), 'scanoria-secret-'))
  })
  afterAll(async () => {
    await rm(dir, { recursive: true, force: true })
  })

  it('chemin de la clé : défaut de l’appliance, surchargeable', () => {
    expect(secretKeyFile({})).toBe('/var/lib/scanoria/console/secret.key')
    expect(secretKeyFile({ NUXT_SECRET_KEY_FILE: '/tmp/k' })).toBe('/tmp/k')
  })

  it('crée la clé au premier usage (32 octets, 0600), puis la relit à l’identique', async () => {
    const path = join(dir, 'sub', 'secret.key')
    const [a, b] = await Promise.all([loadSecretKey(path), loadSecretKey(path)])
    expect(a.length).toBe(32)
    expect(b.equals(a)).toBe(true)
    expect((await stat(path)).mode & 0o777).toBe(0o600)
    expect((await loadSecretKey(path)).equals(a)).toBe(true)
  })

  it('refuse une clé de mauvaise taille', async () => {
    const path = join(dir, 'short.key')
    await writeFile(path, Buffer.alloc(8))
    await expect(loadSecretKey(path)).rejects.toThrow(SecretError)
  })

  it('format 0x01 | nonce | chiffré | étiquette ; aller-retour', async () => {
    const key = await loadSecretKey(join(dir, 'k1'))
    const id = '00000000-0000-4000-8000-000000000001'
    const sealed = sealSecret(key, id, 'valeur-de-test')
    expect(sealed[0]).toBe(1)
    expect(sealed.length).toBe(1 + 12 + 'valeur-de-test'.length + 16)
    expect(sealed.includes(Buffer.from('valeur-de-test'))).toBe(false)
    expect(openSecret(key, id, sealed)).toBe('valeur-de-test')
    // Deux chiffrements de la même valeur diffèrent (nonce aléatoire).
    expect(sealSecret(key, id, 'valeur-de-test').equals(sealed)).toBe(false)
  })

  it('chiffré altéré, étiquette altérée, version inconnue, trop court : illisible', async () => {
    const key = await loadSecretKey(join(dir, 'k2'))
    const id = '00000000-0000-4000-8000-000000000002'
    const sealed = sealSecret(key, id, 'abc')
    for (const i of [13, sealed.length - 1]) {
      const bad = Buffer.from(sealed)
      bad[i] = bad[i]! ^ 0xff
      expect(() => openSecret(key, id, bad)).toThrow('E_SECRET_UNREADABLE')
    }
    const v2 = Buffer.from(sealed)
    v2[0] = 2
    expect(() => openSecret(key, id, v2)).toThrow('E_SECRET_UNREADABLE')
    expect(() => openSecret(key, id, sealed.subarray(0, 20))).toThrow('E_SECRET_UNREADABLE')
  })

  it('mauvais identifiant associé : illisible (un secret ne se déplace pas d’une ligne à l’autre)', async () => {
    const key = await loadSecretKey(join(dir, 'k3'))
    const sealed = sealSecret(key, '00000000-0000-4000-8000-000000000003', 'abc')
    expect(() => openSecret(key, '00000000-0000-4000-8000-000000000004', sealed)).toThrow('E_SECRET_UNREADABLE')
  })

  it('clé absente puis recréée : les anciens secrets échouent proprement, sans valeur dans l’erreur', async () => {
    const path = join(dir, 'k4')
    const key = await loadSecretKey(path)
    const sealed = sealSecret(key, 'id', 'valeur-perdue')
    await unlink(path)
    const fresh = await loadSecretKey(path)
    expect(fresh.equals(key)).toBe(false)
    let caught: unknown
    try {
      openSecret(fresh, 'id', sealed)
    }
    catch (err) {
      caught = err
    }
    expect(caught).toBeInstanceOf(SecretError)
    expect(String((caught as Error).message)).not.toContain('valeur-perdue')
    expect((await readFile(path)).length).toBe(32)
  })

  it('indice : 4 derniers caractères, armure PEM ignorée, rien pour une valeur courte', () => {
    expect(secretHint('abcdefghijklmnop')).toBe('…mnop')
    expect(secretHint('court')).toBe('…')
    const pem = ['-----BEGIN TEST BLOCK-----', 'QUJDREVGR0hJSktMTU5PUFFSU1RVVldY', 'WVo=', '-----END TEST BLOCK-----'].join('\n')
    expect(secretHint(pem)).toBe('…YWVo')
  })
})
