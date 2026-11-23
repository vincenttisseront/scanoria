// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Mots de passe : PBKDF2-HMAC-SHA256, 600 000 itérations, sel aléatoire de
// 16 octets, hash de 32 octets, format PHC (docs/ARCHITECTURE.md § 9.3) :
//   $pbkdf2-sha256$i=600000$<sel base64 sans =>$<hash base64 sans =>

import { pbkdf2, randomBytes, timingSafeEqual } from 'node:crypto'
import { promisify } from 'node:util'

const pbkdf2Async = promisify(pbkdf2)

export const PBKDF2_ITERATIONS = 600_000
export const PBKDF2_MIN_ITERATIONS = 600_000
export const PBKDF2_MAX_ITERATIONS = 9_999_999
const SALT_BYTES = 16
const HASH_BYTES = 32
const PHC_RE = /^\$pbkdf2-sha256\$i=([0-9]{6,7})\$([A-Za-z0-9+/]{22})\$([A-Za-z0-9+/]{43})$/

const b64 = (buf: Buffer) => {
  const s = buf.toString('base64')
  let end = s.length
  while (end > 0 && s[end - 1] === '=') end--
  return s.slice(0, end)
}

export async function hashPassword(password: string, iterations = PBKDF2_ITERATIONS): Promise<string> {
  if (iterations < PBKDF2_MIN_ITERATIONS || iterations > PBKDF2_MAX_ITERATIONS) {
    throw new RangeError('iterations out of range')
  }
  const salt = randomBytes(SALT_BYTES)
  const hash = await pbkdf2Async(password, salt, iterations, HASH_BYTES, 'sha256')
  return `$pbkdf2-sha256$i=${iterations}$${b64(salt)}$${b64(hash)}`
}

export interface ParsedPhc { iterations: number, salt: Buffer, hash: Buffer }

export function parsePhc(phc: string): ParsedPhc | null {
  const m = PHC_RE.exec(phc)
  if (!m) return null
  const iterations = Number(m[1])
  if (iterations < PBKDF2_MIN_ITERATIONS || iterations > PBKDF2_MAX_ITERATIONS) return null
  const salt = Buffer.from(m[2]!, 'base64')
  const hash = Buffer.from(m[3]!, 'base64')
  if (salt.length !== SALT_BYTES || hash.length !== HASH_BYTES) return null
  return { iterations, salt, hash }
}

export function isValidPhc(phc: string): boolean {
  return parsePhc(phc) !== null
}

/** Comparaison à temps constant ; un format invalide renvoie false. */
export async function verifyPassword(password: string, phc: string): Promise<boolean> {
  const parsed = parsePhc(phc)
  if (!parsed) return false
  const candidate = await pbkdf2Async(password, parsed.salt, parsed.iterations, HASH_BYTES, 'sha256')
  return timingSafeEqual(candidate, parsed.hash)
}

let dummyHash: Promise<string> | undefined
/** Calcul factice pour un compte inconnu ou inactif : même coût qu'une vérification réelle. */
export async function burnPasswordCheck(password: string): Promise<void> {
  dummyHash ??= hashPassword('scanoria-dummy-password')
  await verifyPassword(password, await dummyHash)
}
