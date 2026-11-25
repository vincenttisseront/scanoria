// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Secrets en base (contrat 2 de la 0.3, docs/ARCHITECTURE.md § 12.3) :
// AES-256-GCM, secret_enc = 0x01 | nonce (12) | chiffré | étiquette (16),
// données associées = credentials.id. La clé (32 octets) vit dans
// /var/lib/scanoria/console/secret.key (0600), créée atomiquement au premier
// usage ; NUXT_SECRET_KEY_FILE la déplace (tests). Aucune valeur ne passe dans
// un message d'erreur, un journal ou l'audit : seul `hint` s'affiche.

import { createCipheriv, createDecipheriv, randomBytes, randomUUID } from 'node:crypto'
import { link, mkdir, readFile, unlink, writeFile } from 'node:fs/promises'
import { dirname } from 'node:path'
import type { Queryable } from './db'
import { trimEnd } from './text'

export const SECRET_KINDS = ['token', 'ssh-key', 'ai-token', 'app-key', 'webhook-secret', 'oauth-secret'] as const
export type SecretKind = (typeof SECRET_KINDS)[number]

const VERSION = 0x01
const KEY_BYTES = 32
const NONCE_BYTES = 12
const TAG_BYTES = 16
const MAX_VALUE_BYTES = 16_384

export const DEFAULT_SECRET_KEY_FILE = '/var/lib/scanoria/console/secret.key'

/** Erreur sans aucune donnée secrète : seul un code stable est exposé. */
export class SecretError extends Error {
  constructor(public readonly code: 'E_SECRET_KEY' | 'E_SECRET_UNREADABLE' | 'E_SECRET_NOT_FOUND' | 'E_SECRET_INVALID') {
    super(code)
    this.name = 'SecretError'
  }
}

export function secretKeyFile(env: NodeJS.ProcessEnv = process.env): string {
  return env.NUXT_SECRET_KEY_FILE || DEFAULT_SECRET_KEY_FILE
}

/**
 * Lit la clé, ou la crée si elle n'existe pas : écriture dans un fichier
 * temporaire 0600 puis lien physique (échoue si un autre processus a gagné la
 * course, auquel cas sa clé est relue). Une clé de mauvaise taille est refusée.
 */
export async function loadSecretKey(path = secretKeyFile()): Promise<Buffer> {
  try {
    return checkKey(await readFile(path))
  }
  catch (err) {
    if (err instanceof SecretError) throw err
    if ((err as NodeJS.ErrnoException).code !== 'ENOENT') throw new SecretError('E_SECRET_KEY')
  }
  await mkdir(dirname(path), { recursive: true, mode: 0o700 })
  const tmp = `${path}.${randomUUID()}.tmp`
  try {
    await writeFile(tmp, randomBytes(KEY_BYTES), { mode: 0o600, flag: 'wx' })
    await link(tmp, path).catch((err: NodeJS.ErrnoException) => {
      if (err.code !== 'EEXIST') throw err
    })
  }
  catch {
    throw new SecretError('E_SECRET_KEY')
  }
  finally {
    await unlink(tmp).catch(() => {})
  }
  return checkKey(await readFile(path).catch(() => Buffer.alloc(0)))
}

function checkKey(buf: Buffer): Buffer {
  if (buf.length !== KEY_BYTES) throw new SecretError('E_SECRET_KEY')
  return buf
}

/** Chiffre une valeur ; `aad` = identifiant de la ligne credentials. */
export function sealSecret(key: Buffer, aad: string, value: string): Buffer {
  const nonce = randomBytes(NONCE_BYTES)
  const cipher = createCipheriv('aes-256-gcm', key, nonce)
  cipher.setAAD(Buffer.from(aad, 'utf8'))
  const enc = Buffer.concat([cipher.update(value, 'utf8'), cipher.final()])
  return Buffer.concat([Buffer.from([VERSION]), nonce, enc, cipher.getAuthTag()])
}

/** Déchiffre ; toute altération (chiffré, étiquette, id, clé) donne E_SECRET_UNREADABLE. */
export function openSecret(key: Buffer, aad: string, sealed: Buffer): string {
  if (sealed.length < 1 + NONCE_BYTES + TAG_BYTES || sealed[0] !== VERSION) throw new SecretError('E_SECRET_UNREADABLE')
  try {
    const nonce = sealed.subarray(1, 1 + NONCE_BYTES)
    const tag = sealed.subarray(sealed.length - TAG_BYTES)
    const decipher = createDecipheriv('aes-256-gcm', key, nonce)
    decipher.setAAD(Buffer.from(aad, 'utf8'))
    decipher.setAuthTag(tag)
    return Buffer.concat([decipher.update(sealed.subarray(1 + NONCE_BYTES, sealed.length - TAG_BYTES)), decipher.final()]).toString('utf8')
  }
  catch {
    throw new SecretError('E_SECRET_UNREADABLE')
  }
}

/**
 * Indice affichable : les 4 derniers caractères d'un jeton (« …a1b2 »), ou du
 * corps d'une clé SSH (armure PEM et espaces retirés). Rien sous 12 caractères.
 */
export function secretHint(value: string): string {
  let body = value
    .split(/\r?\n/)
    .filter(l => !/^-{5}(BEGIN|END) /.test(l))
    .join('')
    .replace(/\s+/g, '')
  body = trimEnd(body, '=')
  if (body.length < 12) return '…'
  return `…${body.slice(-4)}`
}

function checkValue(value: string): void {
  if (!value || Buffer.byteLength(value, 'utf8') > MAX_VALUE_BYTES) throw new SecretError('E_SECRET_INVALID')
}

export interface EncryptInput {
  kind: SecretKind
  value: string
  username?: string | null
  createdBy?: number | null
}

/** Enregistre un secret chiffré ; renvoie credentials.id. */
export async function encryptSecret(db: Queryable, input: EncryptInput): Promise<string> {
  if (!(SECRET_KINDS as readonly string[]).includes(input.kind)) throw new SecretError('E_SECRET_INVALID')
  checkValue(input.value)
  const key = await loadSecretKey()
  const id = randomUUID()
  await db.query(
    `INSERT INTO credentials (id, kind, username, secret_enc, hint, created_by) VALUES ($1, $2, $3, $4, $5, $6)`,
    [id, input.kind, input.username ?? null, sealSecret(key, id, input.value), secretHint(input.value), input.createdBy ?? null],
  )
  return id
}

/** Remplace la valeur d'un secret existant (rotation) ; même id, nouveau nonce. */
export async function rotateSecret(db: Queryable, credentialId: string, value: string, username?: string | null): Promise<void> {
  checkValue(value)
  const key = await loadSecretKey()
  const res = await db.query(
    `UPDATE credentials SET secret_enc = $2, hint = $3, username = COALESCE($4, username), rotated_at = now() WHERE id = $1`,
    [credentialId, sealSecret(key, credentialId, value), secretHint(value), username ?? null],
  )
  if (!res.rowCount) throw new SecretError('E_SECRET_NOT_FOUND')
}

export interface DecryptedSecret {
  kind: SecretKind
  value: string
  username: string | null
}

/**
 * Déchiffre un secret. Réservé aux usages prévus par le contrat 2 : tâche du
 * runner (C), jeton IA (F), et clients de forge (A, côté serveur seulement).
 */
export async function decryptSecret(db: Queryable, credentialId: string): Promise<DecryptedSecret> {
  const { rows } = await db.query<{ id: string, kind: SecretKind, username: string | null, secret_enc: Buffer }>(
    `SELECT id::text, kind, username, secret_enc FROM credentials WHERE id = $1`,
    [credentialId],
  )
  const row = rows[0]
  if (!row) throw new SecretError('E_SECRET_NOT_FOUND')
  const key = await loadSecretKey()
  return { kind: row.kind, value: openSecret(key, row.id, row.secret_enc), username: row.username }
}

/** Supprime un secret (la valeur disparaît de la base). */
export async function deleteSecret(db: Queryable, credentialId: string): Promise<void> {
  await db.query(`DELETE FROM credentials WHERE id = $1`, [credentialId])
}

/** Ce que l'API peut montrer d'un secret : jamais la valeur. */
export async function secretInfo(db: Queryable, credentialId: string | null): Promise<{ kind: SecretKind, username: string | null, hint: string, rotated_at: string | null } | null> {
  if (!credentialId) return null
  const { rows } = await db.query<{ kind: SecretKind, username: string | null, hint: string, rotated_at: string | null }>(
    `SELECT kind, username, hint, to_char(rotated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS rotated_at
       FROM credentials WHERE id = $1`,
    [credentialId],
  )
  return rows[0] ?? null
}
