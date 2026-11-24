// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// F3 : recherche transverse « qui utilise tel composant, telle version, tel
// CVE ? ». Elle porte sur le DERNIER SBOM de chaque projet visible (dernière
// analyse terminée qui en a un), et rend, par projet : l'analyse, les
// composants trouvés (version, licences, dépendance directe, date de
// publication) et les résultats ouverts qui les concernent.
// Filtres : purl (exact avec @version, sinon toutes les versions), nom
// (contient, casse ignorée), écosystème, intervalle de versions (règle de
// l'écosystème quand elle est connue, sinon égalité), avis (CVE, GHSA, OSV,
// alias compris : composants visés par un résultat ouvert sur cet avis).
// Visibilité : tous les projets actifs pour un viewer ; les projets archivés
// pour un administrateur seulement (la 0.5 n'a pas de droits par projet).
// Pagination par curseur sur les projets (slug), bornée.

import { z } from 'zod'
import type { Queryable } from '../utils/db'
import type { Role } from '#shared/schemas'
import { inRange } from './versions'

export const VULN_ID_RE = /^[A-Za-z][A-Za-z0-9]*-[A-Za-z0-9._:-]{1,120}$/
const MAX_ROWS = 20_000

export const componentQuerySchema = z.object({
  purl: z.string().min(5).max(1024).regex(/^pkg:[a-z][a-z0-9.+-]{0,31}\/\S+$/i).optional(),
  name: z.string().trim().min(1).max(512).optional(),
  ecosystem: z.string().trim().min(1).max(64).regex(/^[a-z0-9.+-]+$/i).optional(),
  version: z.string().trim().min(1).max(256).optional(),
  version_from: z.string().trim().min(1).max(256).optional(),
  version_to: z.string().trim().min(1).max(256).optional(),
  vuln: z.string().trim().regex(VULN_ID_RE).optional(),
  project_id: z.string().uuid().optional(),
  cursor: z.string().max(400).regex(/^[A-Za-z0-9_-]+$/).optional(),
  limit: z.coerce.number().int().min(1).max(100).default(20),
}).strict().refine(q => !!(q.purl || q.name || q.vuln), { message: 'purl, name or vuln is required', path: ['name'] })
export type ComponentQuery = z.infer<typeof componentQuerySchema>

export interface LinkedFinding { id: string, tool: string, severity: string, status: string, vuln_ids: string[], title: string }
export interface ComponentHit {
  purl: string
  ecosystem: string
  name: string
  version: string | null
  licenses: string[]
  direct: boolean | null
  published_at: string | null
  findings: LinkedFinding[]
}
export interface ProjectHit {
  project: { id: string, slug: string, name: string, archived: boolean }
  scan: { id: string, number: number, ref: string, finished_at: string | null }
  components: ComponentHit[]
}

export function encodeCursor(slug: string): string {
  return Buffer.from(JSON.stringify({ s: slug }), 'utf8').toString('base64url')
}
export function decodeCursor(cursor: string | undefined): string | null {
  if (!cursor) return null
  try {
    const v = JSON.parse(Buffer.from(cursor, 'base64url').toString('utf8')) as { s?: unknown }
    return typeof v.s === 'string' && v.s.length <= 64 ? v.s : null
  }
  catch {
    return null
  }
}

/** Identifiants équivalents à un avis (alias de vuln_intel compris). */
async function vulnAliases(db: Queryable, id: string): Promise<string[]> {
  const r = await db.query<{ ids: string[] }>(
    `SELECT array_agg(DISTINCT x) AS ids FROM (
       SELECT upper($1::text) AS x
       UNION SELECT upper(i.vuln_id) FROM vuln_intel i WHERE upper(i.vuln_id) = upper($1) OR upper($1) = ANY (SELECT upper(a) FROM unnest(i.aliases) a)
       UNION SELECT upper(a) FROM vuln_intel i, unnest(i.aliases) a WHERE upper(i.vuln_id) = upper($1) OR upper($1) = ANY (SELECT upper(b) FROM unnest(i.aliases) b)
     ) t`, [id])
  return r.rows[0]?.ids ?? [id.toUpperCase()]
}

interface Row {
  project_id: string
  slug: string
  project_name: string
  archived: boolean
  scan_id: string
  number: number
  ref: string
  finished_at: string | null
  purl: string
  ecosystem: string
  name: string
  version: string | null
  licenses: string[]
  direct: boolean | null
  published_at: string | null
}

const like = (s: string) => `%${s.replace(/[\\%_]/g, c => `\\${c}`)}%`

/** Lignes candidates (sans pagination) ; tronqué à MAX_ROWS. */
async function candidates(db: Queryable, q: Omit<ComponentQuery, 'cursor' | 'limit'>, role: Role): Promise<{ rows: Row[], truncated: boolean }> {
  const where: string[] = []
  const args: unknown[] = []
  const arg = (v: unknown) => {
    args.push(v)
    return `$${args.length}`
  }
  if (role !== 'admin') where.push('p.archived_at IS NULL')
  if (q.project_id) where.push(`p.id = ${arg(q.project_id)}::uuid`)
  if (q.purl) {
    const base = q.purl.split('?')[0]!.split('#')[0]!
    if (/@[^/]+$/.test(base)) where.push(`lower(split_part(split_part(c.purl, '?', 1), '#', 1)) = lower(${arg(base)})`)
    else where.push(`lower(c.purl) LIKE lower(${arg(`${base.replace(/[\\%_]/g, ch => `\\${ch}`)}@%`)})`)
  }
  if (q.name) where.push(`c.name ILIKE ${arg(like(q.name))}`)
  if (q.ecosystem) where.push(`lower(c.ecosystem) = lower(${arg(q.ecosystem)})`)
  if (q.version) where.push(`c.version = ${arg(q.version)}`)
  if (q.vuln) {
    const ids = await vulnAliases(db, q.vuln)
    where.push(`EXISTS (SELECT 1 FROM findings f
                         WHERE f.project_id = c.project_id AND f.status <> 'fixed'
                           AND EXISTS (SELECT 1 FROM unnest(f.vuln_ids) v WHERE upper(v) = ANY (${arg(ids)}::text[]))
                           AND f.package ->> 'name' = c.name
                           AND (f.package ->> 'version' IS NULL OR f.package ->> 'version' = c.version))`)
  }
  const r = await db.query<Row>(
    `WITH latest AS (
       SELECT DISTINCT ON (s.project_id) s.project_id, s.id, s.number, s.ref, s.finished_at
         FROM scans s
        WHERE s.status = 'done' AND EXISTS (SELECT 1 FROM sbom_components x WHERE x.scan_id = s.id)
        ORDER BY s.project_id, s.finished_at DESC NULLS LAST, s.queued_at DESC)
     SELECT p.id::text AS project_id, p.slug, p.name AS project_name, (p.archived_at IS NOT NULL) AS archived,
            l.id::text AS scan_id, l.number, l.ref,
            to_char(l.finished_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS finished_at,
            c.purl, c.ecosystem, c.name, c.version, c.licenses, c.direct,
            to_char(c.published_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS published_at
       FROM latest l JOIN projects p ON p.id = l.project_id
       JOIN sbom_components c ON c.scan_id = l.id
      ${where.length ? `WHERE ${where.join(' AND ')}` : ''}
      ORDER BY p.slug, c.name, c.version NULLS FIRST, c.purl
      LIMIT ${MAX_ROWS + 1}`, args)
  const rows = r.rows.filter(x => inRange(x.ecosystem, x.version, q.version_from, q.version_to))
  return { rows: rows.slice(0, MAX_ROWS), truncated: r.rows.length > MAX_ROWS }
}

/** Résultats ouverts liés aux composants (même projet, même nom, même version ou version inconnue). */
async function linkedFindings(db: Queryable, rows: Row[]): Promise<Map<string, LinkedFinding[]>> {
  const out = new Map<string, LinkedFinding[]>()
  if (!rows.length) return out
  const r = await db.query<LinkedFinding & { project_id: string, pname: string, pversion: string | null }>(
    `SELECT f.id::text, f.tool, f.severity, f.status, f.vuln_ids, f.title, f.project_id::text,
            f.package ->> 'name' AS pname, f.package ->> 'version' AS pversion
       FROM findings f
       JOIN unnest($1::uuid[], $2::text[]) AS k(project_id, name) ON k.project_id = f.project_id AND f.package ->> 'name' = k.name
      WHERE f.status <> 'fixed' AND cardinality(f.vuln_ids) > 0
      ORDER BY CASE f.severity WHEN 'critical' THEN 5 WHEN 'high' THEN 4 WHEN 'medium' THEN 3 WHEN 'low' THEN 2 ELSE 1 END DESC
      LIMIT 5000`,
    [rows.map(x => x.project_id), rows.map(x => x.name)])
  for (const f of r.rows) {
    for (const c of rows) {
      if (c.project_id !== f.project_id || c.name !== f.pname || (f.pversion !== null && f.pversion !== c.version)) continue
      const key = `${c.project_id}|${c.purl}`
      const list = out.get(key) ?? []
      if (list.length < 20) list.push({ id: f.id, tool: f.tool, severity: f.severity, status: f.status, vuln_ids: f.vuln_ids.slice(0, 10), title: f.title })
      out.set(key, list)
    }
  }
  return out
}

function group(rows: Row[], findings: Map<string, LinkedFinding[]>): ProjectHit[] {
  const out: ProjectHit[] = []
  for (const r of rows) {
    let hit = out[out.length - 1]
    if (!hit || hit.project.id !== r.project_id) {
      hit = {
        project: { id: r.project_id, slug: r.slug, name: r.project_name, archived: r.archived },
        scan: { id: r.scan_id, number: r.number, ref: r.ref, finished_at: r.finished_at },
        components: [],
      }
      out.push(hit)
    }
    hit.components.push({
      purl: r.purl, ecosystem: r.ecosystem, name: r.name, version: r.version, licenses: r.licenses,
      direct: r.direct, published_at: r.published_at, findings: findings.get(`${r.project_id}|${r.purl}`) ?? [],
    })
  }
  return out
}

/** Recherche paginée par projet. */
export async function searchComponents(db: Queryable, q: ComponentQuery, role: Role): Promise<{ items: ProjectHit[], next_cursor: string | null, total_projects: number, total_components: number, truncated: boolean }> {
  const { rows, truncated } = await candidates(db, q, role)
  const after = decodeCursor(q.cursor)
  const slugs = [...new Set(rows.map(r => r.slug))]
  const pageSlugs = slugs.filter(s => after === null || s > after).slice(0, q.limit)
  const keep = new Set(pageSlugs)
  const page = rows.filter(r => keep.has(r.slug))
  const lastSlug = pageSlugs[pageSlugs.length - 1]
  const more = lastSlug !== undefined && slugs.some(s => s > lastSlug)
  return {
    items: group(page, await linkedFindings(db, page)),
    next_cursor: more ? encodeCursor(lastSlug!) : null,
    total_projects: slugs.length,
    total_components: rows.length,
    truncated,
  }
}

/** Cellule CSV sûre : guillemets doublés, formule neutralisée (=, +, -, @, tabulation). */
export function csvCell(v: unknown): string {
  let s = v === null || v === undefined ? '' : Array.isArray(v) ? v.join(' ') : String(v)
  s = s.replace(/[\r\n]+/g, ' ')
  if (/^[=+\-@\t]/.test(s)) s = `'${s}`
  return /[",;]/.test(s) || s !== s.trim() ? `"${s.replace(/"/g, '""')}"` : s
}

export const CSV_COLUMNS = ['project', 'scan', 'purl', 'ecosystem', 'name', 'version', 'licenses', 'direct', 'published_at', 'vulnerabilities'] as const

/** Export CSV de toute la recherche (au plus MAX_ROWS lignes). */
export async function componentsCsv(db: Queryable, q: Omit<ComponentQuery, 'cursor' | 'limit'>, role: Role): Promise<string> {
  const { rows } = await candidates(db, q, role)
  const findings = await linkedFindings(db, rows)
  const lines = [CSV_COLUMNS.join(',')]
  for (const r of rows) {
    const vulns = [...new Set((findings.get(`${r.project_id}|${r.purl}`) ?? []).flatMap(f => f.vuln_ids))]
    lines.push([r.slug, r.number, r.purl, r.ecosystem, r.name, r.version, r.licenses, r.direct, r.published_at, vulns].map(csvCell).join(','))
  }
  return `${lines.join('\r\n')}\r\n`
}
