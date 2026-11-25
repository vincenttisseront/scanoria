// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Délais d'exécution (0.6, chantier C) côté worker :
// - V1 : une image absente (E_IMAGE_MISSING, erreur infra G12) fait déposer
//   une demande prefetch-images avant la relance ; une seule demande en cours
//   à la fois, et au plus une par PREFETCH_EVERY_MS ;
// - V2 et V10 : liste des projets existants publiée pour le runner
//   (jobs/tmp/live-projects.json, contrat 8), qui supprime les miroirs Git et
//   les caches des projets disparus.

import { constants } from 'node:fs'
import { mkdir, open, rename } from 'node:fs/promises'
import { join } from 'node:path'
import type { Queryable } from '../utils/db'
import { submitRequest } from '../utils/requests'
import { jobsTmpDir } from './files'
import type { ScanResult } from './contract'

export const PREFETCH_EVERY_MS = 10 * 60_000
export const LIVE_PROJECTS_EVERY_MS = 5 * 60_000
export const LIVE_PROJECTS_FILE = 'live-projects.json'
const SYSTEM = { userId: 0, username: 'system' }

/** Codes d'erreur qui appellent un préchargement des images (V1). */
export const PREFETCH_CODES = new Set(['E_IMAGE_MISSING'])

export function needsPrefetch(result: Pick<ScanResult, 'error' | 'modules'>): boolean {
  if (result.error && PREFETCH_CODES.has(result.error.code)) return true
  return result.modules.some(m => !!m.error && PREFETCH_CODES.has(m.error.code))
}

/** Dépose prefetch-images sauf si une demande est en cours ou récente ; retourne son id ou null. */
export async function requestPrefetch(db: Queryable, requestsDir: string, now = new Date()): Promise<string | null> {
  const recent = await db.query<{ n: number }>(
    `SELECT count(*)::int AS n FROM helper_requests
      WHERE type = 'prefetch-images' AND (status IN ('pending', 'running') OR created_at > $1)`,
    [new Date(now.getTime() - PREFETCH_EVERY_MS).toISOString()])
  if ((recent.rows[0]?.n ?? 0) > 0) return null
  const req = await submitRequest(db, requestsDir, 'prefetch-images', {}, SYSTEM, now, { reason: 'image-missing' })
  return req.id
}

/** Écrit la liste des projets existants pour le runner (écriture atomique, 0600). */
export async function publishLiveProjects(db: Queryable, scansDir: string, now = new Date()): Promise<number> {
  const r = await db.query<{ id: string }>('SELECT id FROM projects ORDER BY id')
  const dir = jobsTmpDir(scansDir)
  await mkdir(dir, { recursive: true, mode: 0o700 })
  const file = join(dir, LIVE_PROJECTS_FILE)
  const tmp = `${file}.${process.pid}.part`
  const fh = await open(tmp, constants.O_WRONLY | constants.O_CREAT | constants.O_TRUNC | constants.O_NOFOLLOW, 0o600)
  try {
    await fh.writeFile(`${JSON.stringify({ schema: 1, at: now.toISOString(), projects: r.rows.map(x => x.id) })}\n`)
  }
  finally {
    await fh.close()
  }
  await rename(tmp, file)
  return r.rows.length
}
