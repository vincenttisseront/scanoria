// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Contexte de publication d'un projet vers sa forge (contrat 30) : forge,
// dépôt, client de lecture, client de publication et adresse de la console.
// Un projet sans forge, suspendu, archivé ou sans accès en écriture n'a pas
// de contexte : rien n'est publié (sans erreur).

import { getConfig } from '../utils/config'
import type { Queryable } from '../utils/db'
import { readPublishedState } from '../utils/appliance'
import { forgeAccess, forgeClient, getForge, type ForgeClient, type ForgeRow } from './index'
import { forgePublisher, type ForgePublisher } from './client'
import { getForgeApp, type ForgeAppRow } from './apps'

const FQDN_RE = /^(?=.{4,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i

let override: string | null | undefined

/** Tests : adresse de la console imposée (undefined : rétablit la lecture de l'état). */
export function setConsoleUrl(url?: string | null): void {
  override = url
}

/**
 * Adresse de la console, vue par la forge et dans les liens publiés :
 * https://<nom de l'appliance> (état publié par scanoria-state). Inconnue :
 * null, et aucun lien n'est publié.
 */
export async function consoleUrl(): Promise<string | null> {
  if (override !== undefined) return override
  const fromEnv = process.env.NUXT_CONSOLE_URL
  if (fromEnv && /^https:\/\/[A-Za-z0-9.-]+(:\d{1,5})?$/.test(fromEnv)) return fromEnv
  try {
    const st = await readPublishedState(getConfig().stateFile)
    const fqdn = (st.state?.appliance as { fqdn?: unknown } | undefined)?.fqdn
    return typeof fqdn === 'string' && FQDN_RE.test(fqdn) ? `https://${fqdn.toLowerCase()}` : null
  }
  catch {
    return null
  }
}

export interface ProjectForge {
  projectId: string
  forge: ForgeRow
  app: ForgeAppRow | null
  repo: string
  client: ForgeClient
  publisher: ForgePublisher
  consoleUrl: string | null
}

export interface ProjectForgeRow {
  id: string
  forge_id: string | null
  repo_full_name: string | null
  archived_at: Date | string | null
  suspended_at: Date | string | null
}

/** Contexte de la forge d'un projet, ou null (aucune publication possible). */
export async function projectForge(db: Queryable, projectId: string): Promise<ProjectForge | null> {
  const r = await db.query<ProjectForgeRow>(
    'SELECT id, forge_id::text, repo_full_name, archived_at, suspended_at FROM projects WHERE id = $1', [projectId])
  const p = r.rows[0]
  if (!p?.forge_id || !p.repo_full_name || p.archived_at || p.suspended_at) return null
  const forge = await getForge(db, p.forge_id)
  if (!forge) return null
  const access = await forgeAccess(db, forge)
  if (!access.token) return null
  const url = await consoleUrl()
  return {
    projectId,
    forge,
    app: await getForgeApp(db, forge.id),
    repo: p.repo_full_name,
    client: forgeClient(access),
    publisher: forgePublisher(access, { consoleUrl: url }),
    consoleUrl: url,
  }
}
