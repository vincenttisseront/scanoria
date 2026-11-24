// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// H3 : import des bases EPSS et KEV exportées par le helper (contrat 17 de la
// 0.5) dans vuln_intel. Le helper écrit, après chaque mise à jour réussie,
// /var/lib/scanoria/feeds-export/<id>.jsonl.gz (une ligne par CVE). La console
// vérifie l'état publié (feeds[]) et l'empreinte du fichier, puis importe par
// lots, dans une transaction, de façon idempotente :
// - une CVE absente du nouvel export KEV repasse kev = false ;
// - une CVE absente du nouvel export EPSS perd son score ;
// - un feed désinstallé (absent de l'état et sans export) efface ses valeurs.
// La console ne lit jamais /var/lib/scanoria/feeds/. Le verdict d'une analyse
// passée ne change pas (G11) : seul l'affichage suit les nouvelles valeurs.

import { createHash } from 'node:crypto'
import { createReadStream } from 'node:fs'
import { lstat } from 'node:fs/promises'
import { join } from 'node:path'
import { createInterface } from 'node:readline'
import { Transform } from 'node:stream'
import { createGunzip } from 'node:zlib'
import type pg from 'pg'
import { z } from 'zod'
import { withTransaction, type Queryable } from '../utils/db'
import { readModulesState } from '../utils/catalog'

export const INTEL_FEEDS = ['epss', 'kev'] as const
export type IntelFeed = (typeof INTEL_FEEDS)[number]

export const MAX_EXPORT_BYTES = 256 * 1024 * 1024
export const MAX_EXPORT_UNCOMPRESSED = 1024 * 1024 * 1024
export const MAX_EXPORT_LINES = 3_000_000
const BATCH = 5000

export function feedsExportDir(): string {
  return process.env.NUXT_FEEDS_EXPORT_DIR || '/var/lib/scanoria/feeds-export'
}

const CVE = z.string().regex(/^CVE-[0-9]{4}-[0-9]{4,12}$/)
const unit = z.number().finite().min(0).max(1)
const day = z.string().regex(/^[0-9]{4}-[0-9]{2}-[0-9]{2}$/).refine(d => !Number.isNaN(Date.parse(`${d}T00:00:00Z`)) && new Date(`${d}T00:00:00Z`).toISOString().startsWith(d))
const LINE = {
  epss: z.strictObject({ vuln_id: CVE, epss: unit, epss_percentile: unit }),
  kev: z.strictObject({ vuln_id: CVE, kev: z.literal(true), kev_added: day }),
} as const

export interface ImportState {
  /** Dernier export refusé (taille et date) : pas relu tant qu'il ne change pas. */
  failed?: { size: number, mtime_ms: number, error: string } | null
  size: number
  mtime_ms: number
  sha256: string
  rows: number
  skipped: number
  imported_at: string
  source_updated_at: string | null
}

export class IntelImportError extends Error {
  constructor(public code: 'not-regular' | 'too-large' | 'unreadable' | 'too-many-lines') {
    super(code)
  }
}

/** Lit l'export (gzip, une ligne JSON par CVE) ; lignes invalides comptées et ignorées. */
export async function readExport(feed: IntelFeed, file: string): Promise<{ rows: Map<string, z.infer<(typeof LINE)[IntelFeed]>>, skipped: number, sha256: string }> {
  const st = await lstat(file)
  if (!st.isFile()) throw new IntelImportError('not-regular')
  if (st.size > MAX_EXPORT_BYTES) throw new IntelImportError('too-large')
  const hash = createHash('sha256')
  let inflated = 0
  const raw = createReadStream(file, { flags: 'r' })
  raw.on('data', chunk => hash.update(chunk))
  const gunzip = createGunzip()
  const bound = new Transform({
    transform(chunk: Buffer, _enc, cb) {
      inflated += chunk.length
      if (inflated > MAX_EXPORT_UNCOMPRESSED) cb(new IntelImportError('too-large'))
      else cb(null, chunk)
    },
  })
  const fail = (err: Error) => bound.destroy(err)
  raw.on('error', fail)
  gunzip.on('error', fail)
  raw.pipe(gunzip).pipe(bound)
  const rows = new Map<string, z.infer<(typeof LINE)[IntelFeed]>>()
  let skipped = 0
  let n = 0
  const schema = LINE[feed]
  try {
    for await (const line of createInterface({ input: bound, crlfDelay: Infinity })) {
      if (!line) continue
      if (++n > MAX_EXPORT_LINES) throw new IntelImportError('too-many-lines')
      let doc: unknown
      try {
        doc = line.length <= 4096 ? JSON.parse(line) : null
      }
      catch {
        doc = null
      }
      const p = schema.safeParse(doc)
      if (p.success) rows.set(p.data.vuln_id, p.data)
      else skipped++
    }
  }
  catch (err) {
    raw.destroy()
    if (err instanceof IntelImportError) throw err
    throw new IntelImportError('unreadable')
  }
  return { rows, skipped, sha256: hash.digest('hex') }
}

type Db = pg.Pool | Queryable

async function inTransaction<T>(db: Db, fn: (q: Queryable) => Promise<T>): Promise<T> {
  if ('connect' in db && typeof db.connect === 'function') return withTransaction(db as pg.Pool, fn)
  // Client reçu : point de sauvegarde, qui exige une transaction ouverte par l'appelant
  // (sinon PostgreSQL refuse : jamais d'import à moitié en autocommit).
  await db.query('SAVEPOINT intel_import')
  try {
    const out = await fn(db)
    await db.query('RELEASE SAVEPOINT intel_import')
    return out
  }
  catch (err) {
    await db.query('ROLLBACK TO SAVEPOINT intel_import').catch(() => {})
    throw err
  }
}

export const settingKey = (feed: IntelFeed) => `intel.import_${feed}`

/** Applique un export complet : upsert par lots puis retrait de ce qui n'y figure plus. */
export async function applyIntel(db: Db, feed: IntelFeed, rows: Map<string, Record<string, unknown>>): Promise<{ changed: number, cleared: number }> {
  return inTransaction(db, async (q) => {
    await q.query('SELECT pg_advisory_xact_lock(hashtext($1))', [`scanoria.intel.${feed}`])
    await q.query(`CREATE TEMP TABLE IF NOT EXISTS intel_import (vuln_id text PRIMARY KEY, a real, b real, d date) ON COMMIT DROP`)
    await q.query('TRUNCATE intel_import')
    const list = [...rows.values()]
    for (let i = 0; i < list.length; i += BATCH) {
      const part = list.slice(i, i + BATCH)
      await q.query(
        `INSERT INTO intel_import (vuln_id, a, b, d)
         SELECT * FROM unnest($1::text[], $2::real[], $3::real[], $4::date[])`,
        feed === 'epss'
          ? [part.map(r => r.vuln_id), part.map(r => r.epss), part.map(r => r.epss_percentile), part.map(() => null)]
          : [part.map(r => r.vuln_id), part.map(() => null), part.map(() => null), part.map(r => r.kev_added)],
      )
    }
    let changed: number
    let cleared: number
    if (feed === 'epss') {
      changed = (await q.query(
        `INSERT INTO vuln_intel AS v (vuln_id, epss, epss_percentile) SELECT vuln_id, a, b FROM intel_import
         ON CONFLICT (vuln_id) DO UPDATE SET epss = EXCLUDED.epss, epss_percentile = EXCLUDED.epss_percentile, updated_at = now()
          WHERE v.epss IS DISTINCT FROM EXCLUDED.epss OR v.epss_percentile IS DISTINCT FROM EXCLUDED.epss_percentile`,
      )).rowCount ?? 0
      cleared = (await q.query(
        `UPDATE vuln_intel v SET epss = NULL, epss_percentile = NULL, updated_at = now()
          WHERE (v.epss IS NOT NULL OR v.epss_percentile IS NOT NULL)
            AND NOT EXISTS (SELECT 1 FROM intel_import i WHERE i.vuln_id = v.vuln_id)`,
      )).rowCount ?? 0
    }
    else {
      changed = (await q.query(
        `INSERT INTO vuln_intel AS v (vuln_id, kev, kev_added) SELECT vuln_id, true, d FROM intel_import
         ON CONFLICT (vuln_id) DO UPDATE SET kev = true, kev_added = EXCLUDED.kev_added, updated_at = now()
          WHERE NOT v.kev OR v.kev_added IS DISTINCT FROM EXCLUDED.kev_added`,
      )).rowCount ?? 0
      cleared = (await q.query(
        `UPDATE vuln_intel v SET kev = false, kev_added = NULL, updated_at = now()
          WHERE v.kev AND NOT EXISTS (SELECT 1 FROM intel_import i WHERE i.vuln_id = v.vuln_id)`,
      )).rowCount ?? 0
    }
    await q.query(`DELETE FROM vuln_intel WHERE epss IS NULL AND epss_percentile IS NULL AND NOT kev AND cardinality(aliases) = 0`)
    return { changed, cleared }
  })
}

/** Efface les valeurs d'un feed retiré (désinstallé). */
export async function clearIntel(db: Db, feed: IntelFeed): Promise<number> {
  return applyIntel(db, feed, new Map()).then(r => r.cleared)
}

async function readState(db: Queryable, feed: IntelFeed): Promise<ImportState | null> {
  const r = await db.query<{ value: ImportState }>('SELECT value FROM appliance_settings WHERE key = $1', [settingKey(feed)])
  return r.rows[0]?.value ?? null
}

async function writeState(db: Queryable, feed: IntelFeed, st: ImportState | null): Promise<void> {
  if (!st) {
    await db.query('DELETE FROM appliance_settings WHERE key = $1', [settingKey(feed)])
    return
  }
  await db.query(
    `INSERT INTO appliance_settings (key, value, updated_at) VALUES ($1, $2::jsonb, now())
     ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()`,
    [settingKey(feed), JSON.stringify(st)],
  )
}

export interface SyncOutcome {
  feed: IntelFeed
  action: 'imported' | 'unchanged' | 'cleared' | 'absent' | 'error'
  rows?: number
  changed?: number
  cleared?: number
  skipped?: number
  error?: string
}

/**
 * Importe chaque export EPSS / KEV nouveau. Appelé par la boucle de la console
 * (environ chaque minute) : sans changement de fichier, rien n'est relu.
 */
export async function syncIntel(db: pg.Pool | Queryable, opts: { modulesStateFile: string, exportDir?: string, now?: Date }): Promise<SyncOutcome[]> {
  const dir = opts.exportDir ?? feedsExportDir()
  const state = await readModulesState(opts.modulesStateFile)
  const out: SyncOutcome[] = []
  for (const feed of INTEL_FEEDS) {
    const file = join(dir, `${feed}.jsonl.gz`)
    const prev = await readState(db, feed)
    const published = state.feeds.find(f => f.id === feed)
    const st = await lstat(file).catch(() => null)
    if (!st) {
      // Feed retiré : plus dans l'état publié, plus d'export. Ses valeurs sont effacées.
      if (prev && state.available && !published) {
        const cleared = await clearIntel(db, feed)
        await writeState(db, feed, null)
        out.push({ feed, action: 'cleared', cleared })
      }
      else {
        out.push({ feed, action: 'absent' })
      }
      continue
    }
    const mtime = Math.trunc(st.mtimeMs)
    if (prev && ((prev.size === st.size && prev.mtime_ms === mtime) || (prev.failed?.size === st.size && prev.failed.mtime_ms === mtime))) {
      out.push(prev.failed?.size === st.size && prev.failed.mtime_ms === mtime ? { feed, action: 'error', error: prev.failed.error } : { feed, action: 'unchanged' })
      continue
    }
    try {
      const { rows, skipped, sha256 } = await readExport(feed, file)
      const base = { failed: null, size: st.size, mtime_ms: mtime, sha256, rows: rows.size, skipped, source_updated_at: published?.updated_at ?? null }
      if (prev && prev.sha256 === sha256) {
        await writeState(db, feed, { ...prev, ...base, imported_at: prev.imported_at })
        out.push({ feed, action: 'unchanged' })
        continue
      }
      const r = await applyIntel(db, feed, rows)
      await writeState(db, feed, { ...base, imported_at: (opts.now ?? new Date()).toISOString() })
      out.push({ feed, action: 'imported', rows: rows.size, skipped, ...r })
    }
    catch (err) {
      const error = err instanceof IntelImportError ? err.code : (err as Error).message
      // Mémorisé : le même fichier n'est pas relu chaque minute ; les valeurs précédentes restent.
      await writeState(db, feed, { ...(prev ?? { size: 0, mtime_ms: 0, sha256: '', rows: 0, skipped: 0, imported_at: '', source_updated_at: null }), failed: { size: st.size, mtime_ms: mtime, error: error.slice(0, 200) } })
      out.push({ feed, action: 'error', error })
    }
  }
  return out
}

export interface IntelStatus {
  id: IntelFeed
  rows: number | null
  imported_at: string | null
  source_updated_at: string | null
}

/** État de l'import par feed (affiché dans les Résultats : « EPSS du … »). */
export async function intelStatus(db: Queryable): Promise<IntelStatus[]> {
  const out: IntelStatus[] = []
  for (const feed of INTEL_FEEDS) {
    const st = await readState(db, feed)
    out.push({ id: feed, rows: st?.imported_at ? st.rows : null, imported_at: st?.imported_at || null, source_updated_at: st?.imported_at ? st.source_updated_at : null })
  }
  return out
}
