// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Résultats réutilisés (0.6, V4, contrat 21), côté console. Le runner calcule
// la clé de chaque module réutilisable et la publie (cache_key) ; après une
// ingestion réussie, le worker range ici les sorties validées :
//   <cache>/<clé>/meta.json   {v: 1, key, module_id, image_digest, outputs: {sarif: "sarif.json"}}
//   <cache>/<clé>/<type>.json
// et en garde la trace dans result_cache. Le runner relit, revalide (G2) et
// recopie l'entrée avant de lancer le module ; le worker l'ingère alors comme
// une sortie neuve (reused_from). Une analyse d'essai (F13) ou externe (J6)
// n'écrit jamais ici. Éviction : entrées d'une image qui n'est plus installée
// ni figée (G6), puis les moins récemment utilisées au-delà de la taille
// maximale (2 Gio par défaut).

import { randomBytes } from 'node:crypto'
import { mkdir, readdir, rename, rm, writeFile } from 'node:fs/promises'
import { join } from 'node:path'
import type { Queryable } from '../utils/db'
import { readContainedFile, resultFile, resultsRoot } from './files'

export const CACHE_KEY_RE = /^[0-9a-f]{64}$/
export const OUTPUT_KINDS = ['sarif', 'cyclonedx'] as const
/** Même borne que le runner (testbed.MAX_OUTPUT). */
export const MAX_CACHED_OUTPUT = 64 * 1024 * 1024
export const DEFAULT_CACHE_MAX_BYTES = 2 * 1024 ** 3

export function resultCacheDir(env: NodeJS.ProcessEnv = process.env): string {
  return env.SCANORIA_RESULT_CACHE || '/var/lib/scanoria/console/result-cache'
}

export function resultCacheMaxBytes(env: NodeJS.ProcessEnv = process.env): number {
  const mb = Number.parseInt(env.SCANORIA_RESULT_CACHE_MAX_MB ?? '', 10)
  return Number.isFinite(mb) && mb >= 16 && mb <= 1024 * 1024 ? mb * 1024 * 1024 : DEFAULT_CACHE_MAX_BYTES
}

export interface StoreInput {
  cacheDir: string
  scansDir: string
  jobId: string
  scanId: string
  key: string
  moduleId: string
  imageDigest: string | null
  /** Sorties publiées par le runner ({type: « <module>/<fichier> »}). */
  outputs: Record<string, string>
  resultsCount: number | null
  durationMs: number | null
}

/** Range les sorties d'un module « ok » ; false si rien n'est rangé (clé invalide, déjà présente, sortie illisible). */
export async function storeCachedOutputs(db: Queryable, input: StoreInput): Promise<boolean> {
  if (!CACHE_KEY_RE.test(input.key) || !input.imageDigest || !/^sha256:[0-9a-f]{64}$/.test(input.imageDigest)) return false
  const kinds = Object.keys(input.outputs).filter((k): k is typeof OUTPUT_KINDS[number] => (OUTPUT_KINDS as readonly string[]).includes(k))
  if (!kinds.length || kinds.length !== Object.keys(input.outputs).length) return false
  const exists = await db.query('SELECT 1 FROM result_cache WHERE cache_key = $1', [input.key])
  if (exists.rowCount) return false
  const files: { name: string, data: Buffer }[] = []
  for (const kind of kinds) {
    const full = resultFile(input.scansDir, input.jobId, input.outputs[kind]!)
    if (!full) return false
    const data = await readContainedFile(resultsRoot(input.scansDir), full, MAX_CACHED_OUTPUT)
    if (!Buffer.isBuffer(data)) return false
    files.push({ name: `${kind}.json`, data })
  }
  const meta = { v: 1, key: input.key, module_id: input.moduleId, image_digest: input.imageDigest,
    outputs: Object.fromEntries(kinds.map(k => [k, `${k}.json`])) }
  await mkdir(input.cacheDir, { recursive: true, mode: 0o750 })
  const tmp = join(input.cacheDir, `.tmp-${input.key}-${randomBytes(4).toString('hex')}`)
  await mkdir(tmp, { mode: 0o750 })
  try {
    let size = 0
    for (const f of files) {
      await writeFile(join(tmp, f.name), f.data, { mode: 0o640, flag: 'wx' })
      size += f.data.length
    }
    await writeFile(join(tmp, 'meta.json'), JSON.stringify(meta), { mode: 0o640, flag: 'wx' })
    await rm(join(input.cacheDir, input.key), { recursive: true, force: true })
    await rename(tmp, join(input.cacheDir, input.key))
    const r = await db.query(
      `INSERT INTO result_cache (cache_key, module_id, image_digest, source_scan, results_count, duration_ms, size_bytes)
       VALUES ($1, $2, $3, $4, $5, $6, $7) ON CONFLICT (cache_key) DO NOTHING`,
      [input.key, input.moduleId, input.imageDigest, input.scanId, input.resultsCount ?? 0, input.durationMs, size])
    return (r.rowCount ?? 0) > 0
  }
  catch (e) {
    await rm(tmp, { recursive: true, force: true })
    throw e
  }
}

/** Sortie reprise par le runner : compteur et date d'usage (LRU) ; renvoie la clé si l'entrée existe encore. */
export async function recordCacheHit(db: Queryable, key: string): Promise<string | null> {
  if (!CACHE_KEY_RE.test(key)) return null
  const r = await db.query<{ cache_key: string }>(
    'UPDATE result_cache SET hits = hits + 1, last_hit_at = now() WHERE cache_key = $1 RETURNING cache_key', [key])
  return r.rows[0]?.cache_key ?? null
}

export interface PurgeInput {
  cacheDir: string
  maxBytes: number
  /**
   * Empreintes d'image encore utilisables par module (installées ou figées
   * par un projet, G6) ; null : état des modules illisible, aucune purge par empreinte.
   */
  liveDigests: Map<string, Set<string>> | null
}

/** Éviction : images retirées, puis LRU au-delà de la taille maximale, puis répertoires orphelins. */
export async function purgeResultCache(db: Queryable, input: PurgeInput): Promise<{ removed: number }> {
  const rows = (await db.query<{ cache_key: string, module_id: string, image_digest: string, size_bytes: string | number }>(
    `SELECT cache_key, module_id, image_digest, size_bytes FROM result_cache
      ORDER BY coalesce(last_hit_at, created_at) DESC, cache_key`)).rows
  const drop: string[] = []
  let total = 0
  for (const row of rows) {
    const live = input.liveDigests?.get(row.module_id)
    if (input.liveDigests && !live?.has(row.image_digest)) {
      drop.push(row.cache_key)
      continue
    }
    total += Number(row.size_bytes)
    if (total > input.maxBytes) drop.push(row.cache_key)
  }
  for (const key of drop) {
    await rm(join(input.cacheDir, key), { recursive: true, force: true })
    await db.query('DELETE FROM result_cache WHERE cache_key = $1', [key])
  }
  const kept = new Set(rows.map(r => r.cache_key).filter(k => !drop.includes(k)))
  let names: string[]
  try {
    names = await readdir(input.cacheDir)
  }
  catch {
    return { removed: drop.length }
  }
  for (const name of names) {
    if (kept.has(name)) continue
    // Entrée sans ligne (écriture interrompue, ligne supprimée) ou reste d'écriture.
    if (CACHE_KEY_RE.test(name) || name.startsWith('.tmp-')) await rm(join(input.cacheDir, name), { recursive: true, force: true })
  }
  return { removed: drop.length }
}

/** Empreintes vivantes : modules installés (empreinte de l'index) et versions figées par un projet (G6). */
export async function liveDigests(db: Queryable, installed: { id: string, digest: string | null }[]): Promise<Map<string, Set<string>>> {
  const map = new Map<string, Set<string>>()
  const add = (id: string, d: string | null) => {
    if (!d) return
    if (!map.has(id)) map.set(id, new Set())
    map.get(id)!.add(d)
  }
  for (const m of installed) add(m.id, m.digest)
  const pins = await db.query<{ module_id: string, image_digest: string }>('SELECT module_id, image_digest FROM project_module_pins')
  for (const p of pins.rows) add(p.module_id, p.image_digest)
  return map
}
