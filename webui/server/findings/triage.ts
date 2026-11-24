// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Consultation et tri des résultats unifiés (§ 6.3) : liste filtrée et
// paginée côté serveur, détail, changement de statut, suivi des secrets (F7).
// Un résultat malveillant (H4) ne peut être ni accepté ni classé faux positif.

import type { Queryable } from '../utils/db'
import { redact } from './redact'
import { INTEL_COLUMNS, intelJoin } from '../intel/lookup'
import { groupsFor, type FindingGroup } from './correlation'

/** Statut effectif : une acceptation échue redevient « nouveau » d'elle-même. */
export const EFFECTIVE_STATUS = `CASE WHEN f.status = 'accepted' AND f.status_until < current_date THEN 'new' ELSE f.status END`

/** Nouveau : apparu dans la dernière analyse où il a été vu, et pas encore corrigé. */
const IS_NEW = `f.status <> 'fixed' AND EXISTS (SELECT 1 FROM scan_findings n WHERE n.finding_id = f.id AND n.scan_id = f.last_scan_id AND n.is_new)`

export interface FindingFilter {
  project_id?: string
  scan_id?: string
  tool?: string
  severity?: string[]
  category?: string
  status?: string[]
  is_new?: boolean
  secret?: boolean
  malicious?: boolean
  q?: string
  /** H3 (0.5) : EPSS minimal (0 à 1), CVE du catalogue KEV. */
  epss_min?: number
  kev?: boolean
  /** F16 (0.5) : un résultat par problème (groupe de résultats recoupés). */
  grouped?: boolean
  limit: number
  offset: number
}

export interface FindingRow {
  id: string
  project_id: string
  project_slug: string
  project_name: string
  fingerprint: string
  tool: string
  rule_id: string
  category: string
  severity: string
  native_severity: string | null
  title: string
  path: string | null
  start_line: number | null
  vuln_ids: string[]
  package: { ecosystem: string | null, name: string, version: string | null, fixed: string[] } | null
  malicious: boolean
  secret_type: string | null
  secret_state: string | null
  status: string
  status_until: string | null
  is_new: boolean
  first_seen_at: string
  updated_at: string
  /** H3 (0.5) */
  epss: number | null
  epss_percentile: number | null
  kev: boolean
  kev_added: string | null
  /** F16 (0.5) : groupe de résultats recoupés (null sans clé de recoupement). */
  correlation_key: string | null
  group?: FindingGroup | null
}

const TS = (col: string) => `to_char(${col} AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"')`

function where(f: Omit<FindingFilter, 'limit' | 'offset'>, params: unknown[]): string {
  const clauses: string[] = []
  const add = (sql: string, value: unknown) => {
    params.push(value)
    clauses.push(sql.replace('?', `$${params.length}`))
  }
  if (f.project_id) add('f.project_id = ?', f.project_id)
  if (f.scan_id) add('EXISTS (SELECT 1 FROM scan_findings x WHERE x.scan_id = ? AND x.finding_id = f.id)', f.scan_id)
  if (f.tool) add('f.tool = ?', f.tool)
  if (f.severity?.length) add('f.severity = ANY(?::text[])', f.severity)
  if (f.category) add('f.category = ?', f.category)
  if (f.status?.length) add(`(${EFFECTIVE_STATUS}) = ANY(?::text[])`, f.status)
  if (f.is_new !== undefined) {
    clauses.push(`${f.is_new ? '' : 'NOT '}(${IS_NEW})`)
  }
  if (f.secret !== undefined) clauses.push(`f.secret_type IS ${f.secret ? 'NOT ' : ''}NULL`)
  if (f.malicious !== undefined) add('f.malicious = ?', f.malicious)
  if (f.epss_min !== undefined) add('intel.epss >= ?', f.epss_min)
  if (f.kev !== undefined) clauses.push(f.kev ? 'intel.kev' : 'NOT intel.kev')
  if (f.q) {
    const like = `%${f.q.replace(/[\\%_]/g, m => `\\${m}`)}%`
    add('(f.title ILIKE ? OR f.rule_id ILIKE $X OR f.path ILIKE $X OR array_to_string(f.vuln_ids, \' \') ILIKE $X OR f.package->>\'name\' ILIKE $X)'.replace(/\$X/g, `$${params.length + 1}`), like)
  }
  return clauses.length ? `WHERE ${clauses.join(' AND ')}` : ''
}

const LIST_COLUMNS = `f.id, f.project_id, p.slug AS project_slug, p.name AS project_name, f.fingerprint, f.tool, f.rule_id,
  f.category, f.severity, f.native_severity, f.title, f.path, f.start_line, f.vuln_ids, f.package, f.malicious,
  f.secret_type, f.secret_state, ${EFFECTIVE_STATUS} AS status, to_char(f.status_until, 'YYYY-MM-DD') AS status_until,
  (${IS_NEW}) AS is_new,
  ${TS('f.created_at')} AS first_seen_at, ${TS('f.updated_at')} AS updated_at,
  ${INTEL_COLUMNS}, f.correlation_key`

const SEV_RANK = `CASE f.severity WHEN 'critical' THEN 5 WHEN 'high' THEN 4 WHEN 'medium' THEN 3 WHEN 'low' THEN 2 ELSE 1 END`
const VULN_CATEGORIES = new Set(['sca', 'container', 'sbom'])

/**
 * Tri par défaut : paquets malveillants, puis CVE exploitées (KEV) ; pour les
 * vulnérabilités, EPSS avant la gravité (H3), sinon la gravité avant l'EPSS.
 */
function orderBy(filter: FindingFilter): string {
  const vulns = !!filter.category && VULN_CATEGORIES.has(filter.category)
  const epss = 'x.epss DESC NULLS LAST'
  const sev = 'x.sev_rank DESC'
  return `ORDER BY x.malicious DESC, x.kev DESC, ${vulns ? `${epss}, ${sev}` : `${sev}, ${epss}`}, x.updated_at DESC, x.id`
}

export async function listFindings(db: Queryable, filter: FindingFilter): Promise<{ items: FindingRow[], total: number }> {
  const params: unknown[] = []
  const clause = where(filter, params)
  const from = `FROM findings f JOIN projects p ON p.id = f.project_id ${intelJoin('f')} ${clause}`
  // F16 : en mode groupé, un seul résultat par (projet, clé de recoupement) : le plus grave.
  const group = `PARTITION BY f.project_id, COALESCE(f.correlation_key, f.id::text)`
  const total = await db.query<{ n: string }>(
    filter.grouped
      ? `SELECT count(*) AS n FROM (SELECT DISTINCT f.project_id, COALESCE(f.correlation_key, f.id::text) ${from}) g`
      : `SELECT count(*) AS n ${from}`,
    params,
  )
  params.push(filter.limit, filter.offset)
  const rows = await db.query<FindingRow & { sev_rank?: number, grp_rn?: number }>(
    `SELECT x.* FROM (
       SELECT ${LIST_COLUMNS}, ${SEV_RANK} AS sev_rank,
              row_number() OVER (${group} ORDER BY f.malicious DESC, ${SEV_RANK} DESC, f.id) AS grp_rn
         ${from}
     ) x ${filter.grouped ? 'WHERE x.grp_rn = 1' : ''}
     ${orderBy(filter)}
     LIMIT $${params.length - 1} OFFSET $${params.length}`,
    params,
  )
  const items = rows.rows.map(({ sev_rank: _s, grp_rn: _g, ...r }) => r as FindingRow)
  await attachGroups(db, items)
  return { items, total: Number(total.rows[0]?.n ?? 0) }
}

/** « Confirmé par N outils » : groupe de chaque résultat qui a une clé de recoupement. */
async function attachGroups(db: Queryable, items: FindingRow[]): Promise<void> {
  const groups = await groupsFor(db, items.filter(i => i.correlation_key).map(i => ({ project_id: i.project_id, key: i.correlation_key! })))
  for (const i of items) i.group = i.correlation_key ? groups.get(`${i.project_id}|${i.correlation_key}`) ?? null : null
}

export interface FindingDetail extends FindingRow {
  message: string | null
  end_line: number | null
  snippet: string | null
  cwe: string[]
  status_reason: string | null
  status_by: string | null
  status_at: string | null
  secret_state_by: string | null
  secret_state_at: string | null
  first_commit: string | null
  last_commit: string | null
  accepted_expired: boolean
  /** Jours depuis la découverte d'un secret encore à révoquer (relance, F7). */
  revoke_pending_days: number | null
  scans: { id: string, number: number, ref: string, is_new: boolean, queued_at: string }[]
}

export async function getFinding(db: Queryable, id: string): Promise<FindingDetail | null> {
  const r = await db.query<FindingDetail>(
    `SELECT ${LIST_COLUMNS}, f.message, f.end_line, f.snippet, f.cwe, f.status_reason,
            ub.username AS status_by, ${TS('f.status_at')} AS status_at,
            us.username AS secret_state_by, ${TS('f.secret_state_at')} AS secret_state_at,
            f.first_commit, f.last_commit,
            (f.status = 'accepted' AND f.status_until < current_date) AS accepted_expired,
            CASE WHEN f.secret_state = 'to-revoke' THEN (current_date - f.created_at::date) END AS revoke_pending_days
       FROM findings f JOIN projects p ON p.id = f.project_id
       ${intelJoin('f')}
       LEFT JOIN users ub ON ub.id = f.status_by
       LEFT JOIN users us ON us.id = f.secret_state_by
      WHERE f.id = $1`,
    [id],
  )
  const row = r.rows[0]
  if (!row) return null
  const scans = await db.query<FindingDetail['scans'][number]>(
    `SELECT s.id, s.number, s.ref, sf.is_new, ${TS('s.queued_at')} AS queued_at
       FROM scan_findings sf JOIN scans s ON s.id = sf.scan_id
      WHERE sf.finding_id = $1 ORDER BY s.queued_at DESC LIMIT 20`,
    [id],
  )
  const detail = { ...row, scans: scans.rows }
  await attachGroups(db, [detail])
  return detail
}

export interface SummaryRow {
  project_id: string
  project_slug: string
  project_name: string
  open: number
  critical: number
  high: number
  medium: number
  low: number
  info: number
  secrets_to_revoke: number
  malicious: number
}

/** Synthèse par projet des résultats ouverts (nouveau ou confirmé). */
export async function findingsSummary(db: Queryable): Promise<SummaryRow[]> {
  const r = await db.query<SummaryRow>(
    `SELECT p.id AS project_id, p.slug AS project_slug, p.name AS project_name,
            count(f.id) FILTER (WHERE o.open)::int AS open,
            count(f.id) FILTER (WHERE o.open AND f.severity = 'critical')::int AS critical,
            count(f.id) FILTER (WHERE o.open AND f.severity = 'high')::int AS high,
            count(f.id) FILTER (WHERE o.open AND f.severity = 'medium')::int AS medium,
            count(f.id) FILTER (WHERE o.open AND f.severity = 'low')::int AS low,
            count(f.id) FILTER (WHERE o.open AND f.severity = 'info')::int AS info,
            count(f.id) FILTER (WHERE f.secret_state = 'to-revoke')::int AS secrets_to_revoke,
            count(f.id) FILTER (WHERE f.malicious AND f.status <> 'fixed')::int AS malicious
       FROM projects p
       LEFT JOIN findings f ON f.project_id = p.id
       LEFT JOIN LATERAL (SELECT (${EFFECTIVE_STATUS}) IN ('new', 'confirmed') AS open) o ON true
      WHERE p.archived_at IS NULL
      GROUP BY p.id ORDER BY p.name`,
  )
  return r.rows
}

export class TriageError extends Error {
  constructor(public code: 'E_NOT_FOUND' | 'E_MALICIOUS' | 'E_NOT_SECRET' | 'E_VALIDATION') {
    super(code)
  }
}

export interface StatusChange {
  status: 'new' | 'confirmed' | 'false-positive' | 'accepted'
  reason?: string | null
  until?: string | null
}

interface Current {
  id: string
  project_id: string
  status: string
  malicious: boolean
  secret_type: string | null
  secret_state: string | null
}

async function lockFinding(db: Queryable, id: string): Promise<Current> {
  const r = await db.query<Current>('SELECT id, project_id, status, malicious, secret_type, secret_state FROM findings WHERE id = $1 FOR UPDATE', [id])
  if (!r.rows[0]) throw new TriageError('E_NOT_FOUND')
  return r.rows[0]
}

/** Tri d'un résultat ; renvoie l'ancien statut pour l'audit. */
export async function setFindingStatus(db: Queryable, id: string, change: StatusChange, userId: number | null): Promise<{ before: Current }> {
  const cur = await lockFinding(db, id)
  // H4 : un paquet malveillant reste bloquant, sans exception possible.
  if (cur.malicious && (change.status === 'accepted' || change.status === 'false-positive')) throw new TriageError('E_MALICIOUS')
  if (change.status === 'accepted' && (!change.reason || !change.until)) throw new TriageError('E_VALIDATION')
  await db.query(
    `UPDATE findings SET status = $2, status_reason = $3, status_until = $4::date, status_by = $5, status_at = now(), updated_at = now()
      WHERE id = $1`,
    [id, change.status, change.reason ? redact(change.reason) : null, change.status === 'accepted' ? change.until : null, userId],
  )
  return { before: cur }
}

/** Suivi d'un secret (F7) : à révoquer → révoqué ou faux positif, avec date et auteur. */
export async function setSecretState(db: Queryable, id: string, state: 'to-revoke' | 'revoked' | 'false-positive', userId: number | null): Promise<{ before: Current }> {
  const cur = await lockFinding(db, id)
  if (!cur.secret_type) throw new TriageError('E_NOT_SECRET')
  // H4 : « pas un secret » classerait faux positif un résultat malveillant.
  if (cur.malicious && state === 'false-positive') throw new TriageError('E_MALICIOUS')
  await db.query(
    `UPDATE findings SET secret_state = $2, secret_state_by = $3, secret_state_at = now(), updated_at = now(),
            status = CASE WHEN $2 = 'false-positive' THEN 'false-positive'
                          WHEN status = 'false-positive' THEN 'new' ELSE status END,
            status_by = CASE WHEN $2 = 'false-positive' OR status = 'false-positive' THEN $3 ELSE status_by END,
            status_at = CASE WHEN $2 = 'false-positive' OR status = 'false-positive' THEN now() ELSE status_at END,
            status_until = CASE WHEN $2 = 'false-positive' OR status = 'false-positive' THEN NULL ELSE status_until END
      WHERE id = $1`,
    [id, state, userId],
  )
  return { before: cur }
}
