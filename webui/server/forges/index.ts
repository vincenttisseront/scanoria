// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Contrat 3 de la 0.3 : forgeClient(forge) → client commun. Forgejo d'abord
// (D4), GitHub ensuite ; GitLab n'est pas pris en charge en 0.3.

import type { Queryable } from '../utils/db'
import { decryptSecret } from '../utils/secrets'
import { ForgeError, normalizeBaseUrl } from './http'
import { forgejoClient } from './forgejo'
import { githubClient } from './github'
import type { ForgeAccess, ForgeClient } from './types'

export { ForgeError, FORGE_ERROR_CODES, normalizeBaseUrl, setForgeTransport } from './http'
export type { ForgeErrorCode } from './http'
export type { ForgeAccess, ForgeClient, ForgeRepo, ForgeTree, TreeEntry } from './types'
export { checkFullName, checkRef, isSafeRef } from './types'

function gitlabStub(): ForgeClient {
  const unsupported = async (): Promise<never> => {
    throw new ForgeError('E_FORGE_UNSUPPORTED')
  }
  return {
    kind: 'gitlab',
    check: unsupported,
    listRepos: unsupported,
    repo: unsupported,
    branches: unsupported,
    latestCommit: unsupported,
    listTree: unsupported,
    readFile: unsupported,
  }
}

export function forgeClient(forge: ForgeAccess): ForgeClient {
  const access = { ...forge, base_url: normalizeBaseUrl(forge.base_url) }
  switch (forge.kind) {
    case 'forgejo': return forgejoClient(access)
    case 'github': return githubClient(access)
    case 'gitlab': return gitlabStub()
    default: throw new ForgeError('E_FORGE_UNSUPPORTED')
  }
}

export interface ForgeRow {
  id: string
  kind: 'forgejo' | 'github' | 'gitlab'
  name: string
  base_url: string
  credential_id: string | null
  discovery: boolean
  last_discovery_at: string | null
  last_error: string | null
  created_at: string
}

const ts = (col: string) => `to_char(${col} AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS ${col}`
export const FORGE_COLUMNS = `id::text, kind, name, base_url, credential_id::text, discovery,
  ${ts('last_discovery_at')}, last_error, ${ts('created_at')}`

export async function getForge(db: Queryable, id: string): Promise<ForgeRow | null> {
  const { rows } = await db.query<ForgeRow>(`SELECT ${FORGE_COLUMNS} FROM forges WHERE id = $1`, [id])
  return rows[0] ?? null
}

/** Client d'une forge enregistrée (jeton déchiffré côté serveur seulement). */
export async function openForge(db: Queryable, forge: ForgeRow): Promise<ForgeClient> {
  const token = forge.credential_id ? (await decryptSecret(db, forge.credential_id)).value : null
  return forgeClient({ kind: forge.kind, base_url: forge.base_url, token })
}
