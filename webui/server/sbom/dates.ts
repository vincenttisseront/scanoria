// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// H5 : dates de publication des versions (sbom_components.published_at).
// La console, seule à pouvoir déposer une demande au helper, fait le travail
// dans sa boucle d'ingestion (packageDatesTick, toutes les 5 s environ) :
//   1. composants sans date d'une analyse récente : d'abord recopiés depuis un
//      autre SBOM qui connaît déjà la même version (cache en base) ;
//   2. le reste, pour les écosystèmes dont le helper connaît le registre, part
//      dans une demande « package-dates » (lots de 2 000 purl au plus) ;
//   3. au retour de la demande, les dates sont recopiées dans tous les SBOM
//      qui ont ce purl ; ce qui reste inconnu (hors ligne, registre muet) est
//      signalé dans la couverture de l'analyse (G15), sans échec.
// Le worker attend ces dates, pendant un temps borné, avant le verdict d'une
// release (awaitPackageDates), seul cas où la quarantaine bloque.

import type pg from 'pg'
import type { Queryable } from '../utils/db'
import { submitRequest, type Requester } from '../utils/requests'

/** Types de purl dont le helper connaît le registre (pkgdates.py). */
export const DATED_PURL_TYPES = ['npm', 'pypi', 'cargo', 'golang', 'maven', 'gem', 'nuget', 'composer'] as const
const DATED_SQL = `(c.version IS NOT NULL AND c.purl ~ '^pkg:(${DATED_PURL_TYPES.join('|')})/')`
export const MAX_BATCH = 2000
/** Taille utile d'un lot : la demande entière doit rester sous 128 Kio. */
const MAX_BATCH_BYTES = 100 * 1024
/** Analyses plus anciennes : plus aucune demande (le SBOM n'est plus le dernier). */
const RECENT = `interval '2 days'`
export const SYSTEM_REQUESTER: Requester = { userId: 0, username: 'system' }
export const DATES_GAP_KIND = 'package-dates-unknown'

/** Recopie les dates déjà connues ailleurs (même purl) ; renvoie le nombre de composants complétés. */
export async function fillKnownDates(db: Queryable, scanId: string): Promise<number> {
  const r = await db.query(
    `UPDATE sbom_components c SET published_at = o.published_at
       FROM (SELECT DISTINCT ON (k.purl) k.purl, k.published_at FROM sbom_components k
              WHERE k.published_at IS NOT NULL
                AND k.purl IN (SELECT x.purl FROM sbom_components x WHERE x.scan_id = $1 AND x.published_at IS NULL)) o
      WHERE c.scan_id = $1 AND c.published_at IS NULL AND c.purl = o.purl`, [scanId])
  return r.rowCount ?? 0
}

/** Découpe une liste de purl en lots de MAX_BATCH au plus et de taille bornée. */
export function batches(purls: string[]): string[][] {
  const out: string[][] = []
  let cur: string[] = []
  let size = 0
  for (const p of purls) {
    const len = Buffer.byteLength(p, 'utf8') + 3
    if (cur.length && (cur.length >= MAX_BATCH || size + len > MAX_BATCH_BYTES)) {
      out.push(cur)
      cur = []
      size = 0
    }
    cur.push(p)
    size += len
  }
  if (cur.length) out.push(cur)
  return out
}

/** Analyses récentes qui ont des composants datables sans date ni demande déjà faite. */
async function scansNeedingDates(db: Queryable, limit: number): Promise<string[]> {
  const r = await db.query<{ scan_id: string }>(
    `SELECT DISTINCT c.scan_id::text AS scan_id
       FROM sbom_components c JOIN scans s ON s.id = c.scan_id
      WHERE c.published_at IS NULL AND ${DATED_SQL} AND s.queued_at > now() - ${RECENT}
        AND NOT EXISTS (SELECT 1 FROM helper_requests r
                         WHERE r.type = 'package-dates' AND r.params ->> 'scan_id' = c.scan_id::text)
      LIMIT $1`, [limit])
  return r.rows.map(x => x.scan_id)
}

/** Dépose les demandes d'une analyse ; renvoie le nombre de purl demandés. */
export async function requestScanDates(db: Queryable, requestsDir: string, scanId: string, now = new Date()): Promise<number> {
  await fillKnownDates(db, scanId)
  const r = await db.query<{ purl: string }>(
    `SELECT c.purl FROM sbom_components c WHERE c.scan_id = $1 AND c.published_at IS NULL AND ${DATED_SQL} ORDER BY c.purl LIMIT 50000`,
    [scanId])
  const list = batches(r.rows.map(x => x.purl))
  for (const [i, purls] of list.entries()) {
    await submitRequest(db, requestsDir, 'package-dates', { purls }, SYSTEM_REQUESTER, now, { scan_id: scanId, batch: i, batches: list.length })
  }
  if (!list.length) await recordDatesGap(db, scanId)
  return r.rows.length
}

const DATE_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/

/** Dates valides d'une sortie de demande (les autres valeurs sont ignorées). */
export function datesFromOutput(output: unknown): Map<string, string | null> {
  const out = new Map<string, string | null>()
  const dates = (output as { dates?: unknown } | null)?.dates
  if (!dates || typeof dates !== 'object' || Array.isArray(dates)) return out
  for (const [purl, d] of Object.entries(dates as Record<string, unknown>).slice(0, MAX_BATCH)) {
    if (!purl.startsWith('pkg:') || purl.length > 1024) continue
    if (d === null) out.set(purl, null)
    else if (typeof d === 'string' && DATE_RE.test(d) && Number.isFinite(Date.parse(d))) out.set(purl, d)
  }
  return out
}

/** Couverture (G15) : composants datables restés sans date. */
export async function recordDatesGap(db: Queryable, scanId: string, offline = false): Promise<void> {
  const r = await db.query<{ n: number }>(
    `SELECT count(*)::int AS n FROM sbom_components c WHERE c.scan_id = $1 AND c.published_at IS NULL AND ${DATED_SQL}`, [scanId])
  const n = r.rows[0]?.n ?? 0
  await db.query(
    `UPDATE scans SET coverage = jsonb_set(COALESCE(coverage, '{}'::jsonb), '{gaps}',
            COALESCE((SELECT jsonb_agg(g) FROM jsonb_array_elements(
                        CASE WHEN jsonb_typeof(coverage -> 'gaps') = 'array' THEN coverage -> 'gaps' ELSE '[]'::jsonb END) g
                       WHERE g ->> 'kind' IS DISTINCT FROM $2), '[]'::jsonb)
            || CASE WHEN $3::int > 0 THEN jsonb_build_array(jsonb_build_object('kind', $2::text, 'count', $3::int, 'offline', $4::boolean))
                    ELSE '[]'::jsonb END)
      WHERE id = $1`, [scanId, DATES_GAP_KIND, n, offline])
}

/** Applique les demandes terminées pas encore recopiées ; renvoie le nombre de demandes traitées. */
export async function applyDateResults(db: Queryable): Promise<number> {
  const r = await db.query<{ id: string, scan_id: string | null, status: string, output: unknown }>(
    `SELECT id::text, params ->> 'scan_id' AS scan_id, status, output FROM helper_requests
      WHERE type = 'package-dates' AND status IN ('ok', 'error', 'rejected', 'lost') AND NOT (params ? 'applied')
      ORDER BY created_at LIMIT 20`)
  for (const req of r.rows) {
    const dates = req.status === 'ok' ? datesFromOutput(req.output) : new Map<string, string | null>()
    const known = [...dates].filter((e): e is [string, string] => e[1] !== null)
    if (known.length) {
      // Toutes les analyses qui ont ce purl sans date en profitent.
      await db.query(
        `UPDATE sbom_components c SET published_at = d.published_at::timestamptz
           FROM unnest($1::text[], $2::text[]) AS d(purl, published_at)
          WHERE c.purl = d.purl AND c.published_at IS NULL`,
        [known.map(k => k[0]), known.map(k => k[1])])
    }
    await db.query(`UPDATE helper_requests SET params = params || '{"applied": true}'::jsonb WHERE id = $1`, [req.id])
    if (req.scan_id && /^[0-9a-f-]{36}$/.test(req.scan_id)) {
      const offline = (req.output as { stats?: { offline?: unknown } } | null)?.stats?.offline === true || req.status !== 'ok'
      await recordDatesGap(db, req.scan_id, offline)
    }
  }
  return r.rows.length
}

/** Une passe (boucle d'ingestion de la console) ; ne lève jamais. */
export async function packageDatesTick(db: Queryable, requestsDir: string, log: (m: string) => void = console.warn): Promise<void> {
  try {
    await applyDateResults(db)
    for (const scanId of await scansNeedingDates(db, 3)) await requestScanDates(db, requestsDir, scanId)
  }
  catch (err) {
    log(`[package-dates] ${(err as Error).message}`)
  }
}

/** Composants datables encore sans date et sans demande close pour cette analyse. */
async function datesPending(db: Queryable, scanId: string): Promise<boolean> {
  const r = await db.query<{ missing: boolean, open: boolean, asked: boolean }>(
    `SELECT EXISTS (SELECT 1 FROM sbom_components c WHERE c.scan_id = $1 AND c.published_at IS NULL AND ${DATED_SQL}) AS missing,
            EXISTS (SELECT 1 FROM helper_requests r WHERE r.type = 'package-dates' AND r.params ->> 'scan_id' = $1::text
                     AND NOT (r.params ? 'applied')) AS open,
            EXISTS (SELECT 1 FROM helper_requests r WHERE r.type = 'package-dates' AND r.params ->> 'scan_id' = $1::text) AS asked`,
    [scanId])
  const row = r.rows[0]!
  return row.missing && (row.open || !row.asked)
}

/**
 * Avant le verdict d'une release : attend (au plus timeoutMs) que les dates
 * des composants soient connues ou que le helper ait répondu. Sans effet pour
 * les autres déclencheurs (la quarantaine y est seulement signalée).
 */
export async function awaitPackageDates(db: Pick<pg.Pool, 'query'>, scanId: string, opts: { timeoutMs?: number, pollMs?: number } = {}): Promise<boolean> {
  const t = await db.query<{ trigger: string }>('SELECT trigger FROM scans WHERE id = $1', [scanId])
  if (t.rows[0]?.trigger !== 'release') return true
  const end = Date.now() + (opts.timeoutMs ?? 90_000)
  for (;;) {
    if (!(await datesPending(db, scanId))) return true
    if (Date.now() >= end) return false
    await new Promise(resolve => setTimeout(resolve, opts.pollMs ?? 2000))
  }
}
