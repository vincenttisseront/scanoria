// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront

import { pbkdf2Sync } from 'node:crypto'
import { describe, expect, it } from 'vitest'
import { PBKDF2_ITERATIONS, hashPassword, isValidPhc, parsePhc, verifyPassword } from '../../server/utils/password'

const PHC_DB_RE = /^\$pbkdf2-sha256\$i=[0-9]{6,7}\$[A-Za-z0-9+/]{22}\$[A-Za-z0-9+/]{43}$/

describe('PBKDF2-SHA256 (format PHC)', () => {
  it('produit le format attendu par la base, 600 000 itérations, sel aléatoire', async () => {
    const a = await hashPassword('correct horse battery staple')
    const b = await hashPassword('correct horse battery staple')
    expect(a).toMatch(PHC_DB_RE)
    expect(a.startsWith(`$pbkdf2-sha256$i=${PBKDF2_ITERATIONS}$`)).toBe(true)
    expect(PBKDF2_ITERATIONS).toBeGreaterThanOrEqual(600_000)
    expect(a).not.toBe(b)
    expect(parsePhc(a)?.salt.length).toBe(16)
    expect(parsePhc(a)?.hash.length).toBe(32)
  })

  it('vérifie le bon mot de passe et refuse les autres', async () => {
    const phc = await hashPassword('motdepasse-très-long-é')
    expect(await verifyPassword('motdepasse-très-long-é', phc)).toBe(true)
    expect(await verifyPassword('motdepasse-tres-long-e', phc)).toBe(false)
    expect(await verifyPassword('', phc)).toBe(false)
  })

  it('accepte un hash produit ailleurs (premier démarrage, Python hashlib) avec les mêmes paramètres', async () => {
    const salt = Buffer.from('00112233445566778899aabbccddeeff', 'hex')
    const hash = pbkdf2Sync('admin-password-42', salt, 600_000, 32, 'sha256')
    const b64 = (b: Buffer) => b.toString('base64').replace(/=+$/, '')
    const phc = `$pbkdf2-sha256$i=600000$${b64(salt)}$${b64(hash)}`
    expect(isValidPhc(phc)).toBe(true)
    expect(await verifyPassword('admin-password-42', phc)).toBe(true)
  })

  it('refuse les formats invalides ou trop faibles', async () => {
    const salt = 'AAAAAAAAAAAAAAAAAAAAAA'
    const hash = 'A'.repeat(43)
    expect(isValidPhc(`$pbkdf2-sha256$i=100000$${salt}$${hash}`)).toBe(false)
    expect(isValidPhc(`$pbkdf2-sha512$i=600000$${salt}$${hash}`)).toBe(false)
    expect(isValidPhc(`$pbkdf2-sha256$i=600000$${salt}==$${hash}`)).toBe(false)
    expect(isValidPhc('plaintext')).toBe(false)
    expect(await verifyPassword('x', 'plaintext')).toBe(false)
    await expect(hashPassword('x', 1000)).rejects.toThrow(RangeError)
  })
})
