// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Jeton porteur facultatif du connecteur IA (CLAUDE.md § 3.5), chiffré en
// base selon le contrat 2 (webui/server/utils/secrets.ts : AES-256-GCM,
// type « ai-token », données associées = credentials.id), mais avec une clé
// DÉDIÉE, ai-token.key, distincte de secret.key :
// - la console (utilisateur scanoria) crée la clé au premier jeton et chiffre ;
// - scanoria-ai-setup prestart copie cette seule clé dans /run/scanoria-ai ;
// - scanoria-ai ne lit en base que la ligne « ai-token » (politique
//   credentials_ai_token_read) et ne détient aucune clé capable d'ouvrir un
//   jeton de forge ou une clé SSH : il ne peut déchiffrer que le jeton IA.
// Aucune valeur ne passe dans un journal, une erreur ou l'audit.

import { join } from 'node:path'
import { randomUUID } from 'node:crypto'
import { readFile } from 'node:fs/promises'
import type { Queryable } from '../utils/db'
import { loadSecretKey, openSecret, sealSecret, secretHint, SecretError } from '../utils/secrets'

export const DEFAULT_AI_TOKEN_KEY_FILE = '/var/lib/scanoria/console/ai-token.key'
/** Nom de la copie lue par scanoria-ai dans son répertoire d'exécution. */
export const RUNTIME_KEY_NAME = 'ai-token.key'

export interface TokenStore {
  save: (db: Queryable, value: string, createdBy: number) => Promise<string>
  read: (db: Queryable, credentialId: string) => Promise<string>
}

export function aiTokenKeyFile(env: NodeJS.ProcessEnv = process.env): string {
  return env.NUXT_AI_TOKEN_KEY_FILE || DEFAULT_AI_TOKEN_KEY_FILE
}

/** Magasin de la console : crée la clé dédiée si besoin, chiffre, lit. */
export function consoleTokenStore(keyFile?: string): TokenStore {
  // Chemin relu à chaque appel : NUXT_AI_TOKEN_KEY_FILE peut être posé après le chargement (tests).
  const path = () => keyFile ?? aiTokenKeyFile()
  return {
    async save(db, value, createdBy) {
      if (!value || Buffer.byteLength(value, 'utf8') > 4096) throw new SecretError('E_SECRET_INVALID')
      const key = await loadSecretKey(path())
      const id = randomUUID()
      await db.query(
        `INSERT INTO credentials (id, kind, secret_enc, hint, created_by) VALUES ($1, 'ai-token', $2, $3, $4)`,
        [id, sealSecret(key, id, value), secretHint(value), createdBy],
      )
      return id
    },
    // Lecture stricte : une lecture ne crée jamais de clé (elle ne déchiffrerait rien).
    read: (db, id) => readWithKey(db, id, () => strictKey(path())),
  }
}

async function strictKey(path: string): Promise<Buffer> {
  const buf = await readFile(path).catch(() => Buffer.alloc(0))
  if (buf.length !== 32) throw new SecretError('E_SECRET_KEY')
  return buf
}

/** Magasin de scanoria-ai : lecture seule, clé copiée dans le répertoire d'exécution (jamais créée). */
export function runtimeTokenStore(runtimeDir: string): TokenStore {
  return {
    save: async () => {
      throw new SecretError('E_SECRET_KEY')
    },
    read: (db, id) => readWithKey(db, id, () => strictKey(join(runtimeDir, RUNTIME_KEY_NAME))),
  }
}

async function readWithKey(db: Queryable, credentialId: string, key: () => Promise<Buffer>): Promise<string> {
  const { rows } = await db.query<{ id: string, secret_enc: Buffer }>(
    `SELECT id::text, secret_enc FROM credentials WHERE id = $1 AND kind = 'ai-token'`,
    [credentialId],
  )
  const row = rows[0]
  if (!row) throw new SecretError('E_SECRET_NOT_FOUND')
  return openSecret(await key(), row.id, row.secret_enc)
}

let store: TokenStore = consoleTokenStore()

/** Remplace le magasin (tests). null rétablit celui de la console. */
export function setTokenStore(s: TokenStore | null): void {
  store = s ?? consoleTokenStore()
}

export async function saveToken(db: Queryable, value: string, createdBy: number): Promise<string> {
  return store.save(db, value, createdBy)
}

export async function readToken(db: Queryable, credentialId: string): Promise<string> {
  return store.read(db, credentialId)
}

/** Retire un jeton IA (la valeur disparaît de la base). */
export async function deleteToken(db: Queryable, credentialId: string | null): Promise<void> {
  if (credentialId) await db.query(`DELETE FROM credentials WHERE id = $1 AND kind = 'ai-token'`, [credentialId])
}
