// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Lecture des SBOM pour l'onglet « SBOM » d'une analyse (0.5, chantier A) :
// composants filtrés, triés et paginés côté serveur (jusqu'à 50 000 par
// analyse), facettes, couverture (G15) et lien vers le projet Dependency-Track.

import { z } from 'zod'
import type { Queryable } from '../utils/db'
import { getConfig } from '../utils/config'
import { readModulesState } from '../utils/catalog'
import type { SbomCoverage, SbomRow } from './ingest'

export const SBOM_SORTS = ['name', 'ecosystem', 'version', 'license', 'direct'] as const

export const sbomQuery = z.object({
  q: z.string().trim().max(200).optional(),
  ecosystem: z.string().regex(/^[a-z][a-z0-9.+-]{0,63}$/).optional(),
  license: z.string().trim().min(1).max(256).optional(),
  direct: z.enum(['true', 'false']).optional(),
  sort: z.enum(SBOM_SORTS).default('name'),
  order: z.enum(['asc', 'desc']).default('asc'),
  page: z.coerce.number().int().min(1).max(10_000).default(1),
  per_page: z.coerce.number().int().min(1).max(200).default(50),
}).strict()
export type SbomQuery = z.infer<typeof sbomQuery>

export interface SbomPage {
  scan_id: string
  project_id: string
  total: number
  matched: number
  page: number
  per_page: number
  components: SbomRow[]
  ecosystems: { ecosystem: string, count: number }[]
  licenses: { license: string, count: number }[]
  coverage: (Partial<SbomCoverage> & { module?: string | null }) | null
  dtrack: { project: string, url: string | null } | null
}

const ORDER: Record<(typeof SBOM_SORTS)[number], string> = {
  name: 'name {o}, version {o} NULLS FIRST, purl',
  ecosystem: 'ecosystem {o}, name, version NULLS FIRST, purl',
  version: 'version {o} NULLS LAST, name, purl',
  license: `COALESCE(licenses[1], '') {o}, name, purl`,
  direct: 'direct {o} NULLS LAST, name, purl',
}

const escapeLike = (s: string) => s.replace(/[\\%_]/g, m => `\\${m}`)

/** URL du projet dans l'interface de Dependency-Track, si le module est installé, actif et routé. */
export async function dtrackProjectUrl(uuid: string, stateFile = getConfig().modulesStateFile): Promise<string | null> {
  const state = await readModulesState(stateFile)
  const mod = state.modules.find(m => m.id === 'dependency-track' && m.enabled)
  const base = mod?.route?.url
  if (!base) return null
  let end = base.length
  while (end > 0 && base[end - 1] === '/') end--
  return `${base.slice(0, end)}/projects/${uuid}`
}

export async function sbomPage(db: Queryable, scan: { id: string, project_id: string, coverage: unknown }, query: SbomQuery, stateFile?: string): Promise<SbomPage> {
  const where = ['scan_id = $1']
  const params: unknown[] = [scan.id]
  if (query.q) {
    params.push(`%${escapeLike(query.q.toLowerCase())}%`)
    where.push(`(lower(name) LIKE $${params.length} OR lower(purl) LIKE $${params.length})`)
  }
  if (query.ecosystem) {
    params.push(query.ecosystem)
    where.push(`ecosystem = $${params.length}`)
  }
  if (query.license) {
    params.push(query.license)
    where.push(`$${params.length} = ANY(licenses)`)
  }
  if (query.direct) where.push(query.direct === 'true' ? 'direct IS TRUE' : 'direct IS NOT TRUE')
  const order = ORDER[query.sort].replaceAll('{o}', query.order === 'desc' ? 'DESC' : 'ASC')
  const cond = where.join(' AND ')
  const [rows, counts, ecos, lics] = await Promise.all([
    db.query<SbomRow>(
      `SELECT purl, ecosystem, name, version, licenses, direct, paths,
              to_char(published_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS published_at
         FROM sbom_components WHERE ${cond} ORDER BY ${order}
        LIMIT ${query.per_page} OFFSET ${(query.page - 1) * query.per_page}`, params),
    db.query<{ total: number, matched: number }>(
      `SELECT (SELECT count(*)::int FROM sbom_components WHERE scan_id = $1) AS total,
              (SELECT count(*)::int FROM sbom_components WHERE ${cond}) AS matched`, params),
    db.query<{ ecosystem: string, count: number }>(
      `SELECT ecosystem, count(*)::int AS count FROM sbom_components WHERE scan_id = $1
        GROUP BY ecosystem ORDER BY count DESC, ecosystem LIMIT 50`, [scan.id]),
    db.query<{ license: string, count: number }>(
      `SELECT l AS license, count(*)::int AS count FROM sbom_components, unnest(licenses) AS l
        WHERE scan_id = $1 GROUP BY l ORDER BY count DESC, l LIMIT 100`, [scan.id]),
  ])
  const cov = (scan.coverage as { sbom?: Record<string, unknown> } | null)?.sbom ?? null
  const uuid = typeof cov?.dtrack_project === 'string' ? cov.dtrack_project : null
  return {
    scan_id: scan.id,
    project_id: scan.project_id,
    total: counts.rows[0]?.total ?? 0,
    matched: counts.rows[0]?.matched ?? 0,
    page: query.page,
    per_page: query.per_page,
    components: rows.rows,
    ecosystems: ecos.rows,
    licenses: lics.rows,
    coverage: cov ? { ...cov } as SbomPage['coverage'] : null,
    dtrack: uuid ? { project: uuid, url: await dtrackProjectUrl(uuid, stateFile) } : null,
  }
}

export async function scanForSbom(db: Queryable, id: string) {
  const { rows } = await db.query<{ id: string, project_id: string, coverage: unknown, project_name: string, project_slug: string, number: number, finished_at: string | null }>(
    `SELECT s.id, s.project_id, s.coverage, p.name AS project_name, p.slug AS project_slug, s.number,
            to_char(s.finished_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS finished_at
       FROM scans s JOIN projects p ON p.id = s.project_id WHERE s.id = $1`, [id])
  return rows[0] ?? null
}
