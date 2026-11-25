// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// H7 : déclarations VEX tirées des exceptions approuvées (contrat 38).
// syncExceptionVex est appelé par le circuit des exceptions (contrat 27)
// après une approbation et après une révocation : il matérialise les
// déclarations dans vex_statements, ou les révoque (revoked_at). Une
// exception échue cesse d'elle-même d'en produire (buildVex ne lit que les
// exceptions en vigueur). Ce fichier ne dépend pas du circuit des exceptions,
// qui l'importe.

import type { Queryable } from '../utils/db'
import { justificationFromReason, validPurl, VULN_ID_RE, type VexStatement, type VexStatus } from './format'

/** Produits (purl) au plus par déclaration tirée d'une exception. */
export const MAX_PRODUCTS_PER_EXCEPTION = 20

const ECOSYSTEM_TO_PURL: Record<string, string> = {
  'npm': 'npm', 'PyPI': 'pypi', 'Go': 'golang', 'crates.io': 'cargo', 'Maven': 'maven', 'RubyGems': 'gem',
  'Packagist': 'composer', 'NuGet': 'nuget', 'Debian': 'deb', 'Alpine': 'apk', 'RPM': 'rpm', 'Hex': 'hex', 'Pub': 'pub',
}

const enc = (v: string) => encodeURIComponent(v).replace(/%2F/gi, '/')

/** purl reconstruit depuis le paquet d'un résultat (écosystème, nom, version), ou générique. */
export function purlOf(pkg: { ecosystem?: string | null, name?: string | null, version?: string | null }): string | null {
  if (!pkg.name) return null
  const type = (pkg.ecosystem && ECOSYSTEM_TO_PURL[pkg.ecosystem]) || (pkg.ecosystem && /^[a-z][a-z0-9.+-]{0,31}$/.test(pkg.ecosystem) ? pkg.ecosystem : 'generic')
  const name = pkg.name.startsWith('@') ? `%40${enc(pkg.name.slice(1))}` : enc(pkg.name)
  const p = `pkg:${type}/${name}${pkg.version ? `@${encodeURIComponent(pkg.version)}` : ''}`
  return validPurl(p) ? p : null
}

export interface ExceptionVexRow {
  id: string
  project_id: string
  kind: string
  target: Record<string, unknown>
  reason: string
  vex_status: VexStatus
  decided_at: Date
}

/** Vulnérabilité et produits visés par une exception vuln ou finding ; null si elle ne vise aucune vulnérabilité. */
async function exceptionSubjects(db: Queryable, e: ExceptionVexRow): Promise<{ vulnIds: string[], products: string[] } | null> {
  let vulnIds: string[]
  let pkgName: string | null
  let findingPkgs: { ecosystem?: string, name?: string, version?: string }[] = []
  if (e.kind === 'vuln') {
    vulnIds = [String(e.target.vuln_id)]
    pkgName = typeof e.target.package === 'string' ? e.target.package : null
    const f = await db.query<{ package: { ecosystem?: string, name?: string, version?: string } | null }>(
      `SELECT DISTINCT package FROM findings
        WHERE project_id = $1 AND package IS NOT NULL AND EXISTS (SELECT 1 FROM unnest(vuln_ids) v WHERE upper(v) = upper($2))
          AND ($3::text IS NULL OR package->>'name' = $3) LIMIT ${MAX_PRODUCTS_PER_EXCEPTION}`,
      [e.project_id, vulnIds[0], pkgName])
    findingPkgs = f.rows.map(r => r.package!).filter(Boolean)
  }
  else if (e.kind === 'finding') {
    const f = await db.query<{ vuln_ids: string[], package: { ecosystem?: string, name?: string, version?: string } | null }>(
      'SELECT vuln_ids, package FROM findings WHERE id::text = $1 AND project_id = $2', [String(e.target.finding_id), e.project_id])
    if (!f.rows[0]) return null
    vulnIds = f.rows[0].vuln_ids
    if (f.rows[0].package) findingPkgs = [f.rows[0].package]
    pkgName = f.rows[0].package?.name ?? null
  }
  else {
    return null
  }
  vulnIds = [...new Set(vulnIds.filter(v => VULN_ID_RE.test(v)))].slice(0, 10)
  if (!vulnIds.length) return null
  // Le SBOM du projet donne le purl exact (avec qualificatifs) ; à défaut, le paquet du résultat.
  const names = [...new Set([pkgName, ...findingPkgs.map(p => p.name)].filter((n): n is string => !!n))]
  const products = new Set<string>()
  if (names.length) {
    const s = await db.query<{ purl: string }>(
      `SELECT DISTINCT c.purl FROM sbom_components c
        WHERE c.project_id = $1 AND c.name = ANY($2::text[])
          AND c.scan_id = (SELECT c2.scan_id FROM sbom_components c2 JOIN scans s ON s.id = c2.scan_id
                            WHERE c2.project_id = $1 ORDER BY s.queued_at DESC, s.id LIMIT 1)
        ORDER BY c.purl LIMIT ${MAX_PRODUCTS_PER_EXCEPTION}`, [e.project_id, names])
    for (const r of s.rows) if (validPurl(r.purl)) products.add(r.purl)
  }
  if (!products.size) {
    for (const p of findingPkgs) {
      const purl = purlOf(p)
      if (purl) products.add(purl)
    }
  }
  if (!products.size && pkgName) {
    const purl = purlOf({ name: pkgName })
    if (purl) products.add(purl)
  }
  if (!products.size) return null
  return { vulnIds, products: [...products].sort().slice(0, MAX_PRODUCTS_PER_EXCEPTION) }
}

export const ISO = (d: Date) => d.toISOString().replace(/\.\d{3}Z$/, 'Z')

/** Déclarations VEX d'une exception (sans écrire). */
export async function statementsOfException(db: Queryable, e: ExceptionVexRow): Promise<VexStatement[]> {
  const subjects = await exceptionSubjects(db, e)
  if (!subjects) return []
  const { justification, text } = justificationFromReason(e.reason)
  const out: VexStatement[] = []
  for (const vuln of subjects.vulnIds) {
    for (const product of subjects.products) {
      out.push({
        vuln_id: vuln, product, status: e.vex_status, justification: e.vex_status === 'not_affected' ? justification : null,
        impact_statement: e.vex_status === 'affected' ? null : text.slice(0, 2000),
        action_statement: e.vex_status === 'affected' ? text.slice(0, 2000) : null,
        timestamp: ISO(e.decided_at),
      })
    }
  }
  return out
}

export const EXCEPTION_COLUMNS = `id, project_id, kind, target, reason, vex_status, decided_at`
export const activeException = (t: string) => `${t}.status = 'approved' AND ${t}.revoked_at IS NULL AND ${t}.expires_on >= current_date AND ${t}.vex_status IS NOT NULL`

/**
 * Matérialise (ou révoque) les déclarations VEX d'une exception : appelé après
 * son approbation et après sa révocation. Sans effet pour une exception sans
 * vex_status. Rend le nombre de déclarations actives de l'exception.
 */
export async function syncExceptionVex(db: Queryable, exceptionId: string): Promise<number> {
  const r = await db.query<ExceptionVexRow & { active: boolean }>(
    `SELECT ${EXCEPTION_COLUMNS}, (${activeException('x')}) AS active FROM exceptions x WHERE id = $1`, [exceptionId])
  const e = r.rows[0]
  if (!e || !e.active) {
    await db.query('UPDATE vex_statements SET revoked_at = now() WHERE exception_id = $1 AND revoked_at IS NULL', [exceptionId])
    return 0
  }
  const statements = await statementsOfException(db, e)
  const existing = await db.query<{ vuln_id: string, product: string }>(
    'SELECT vuln_id, product FROM vex_statements WHERE exception_id = $1 AND revoked_at IS NULL', [exceptionId])
  const have = new Set(existing.rows.map(x => `${x.vuln_id}\u0000${x.product}`))
  for (const s of statements) {
    if (have.has(`${s.vuln_id}\u0000${s.product}`)) continue
    await db.query(
      `INSERT INTO vex_statements (project_id, vuln_id, product, status, justification, impact_statement, action_statement,
                                   source, exception_id, created_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, 'exception', $8, $9)`,
      [e.project_id, s.vuln_id, s.product, s.status, s.justification, s.impact_statement, s.action_statement, exceptionId, e.decided_at])
  }
  return statements.length
}
