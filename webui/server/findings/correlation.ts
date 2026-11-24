// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// F16 : recoupement entre outils (contrat 18 de la 0.5). Un même problème vu
// par plusieurs outils partage une clé de recoupement :
// - vulnérabilité de dépendance : SHA-256 de « vuln:<id canonique>|<purl sans
//   version> », l'id canonique étant le CVE quand l'un des alias en est un
//   (GHSA, OSV… ramenés au CVE), sinon le GHSA, sinon le premier avis trié ;
// - SAST et IaC : SHA-256 de « cwe:<n>|<chemin>|<empreinte de contexte> »,
//   l'empreinte de contexte étant celle de G19 sans l'outil ni la règle
//   (texte autour du résultat, espaces repliés), ou la ligne quand l'outil ne
//   donne aucun extrait ;
// - sinon (secrets, qualité, lint…) : null.
// La clé est calculée à l'ingestion et ne change jamais l'empreinte G19
// (findings.fingerprint). Le groupe d'un résultat est l'ensemble des
// résultats de son projet qui partagent sa clé ; son indice de confiance est
// le nombre d'outils distincts du groupe (« confirmé par N outils »).

import type { Queryable } from '../utils/db'
import { SEVERITY_RANK, type Severity } from '#shared/analysis'
import { collapseWhitespace, sha256 } from './normalize'

export interface CorrelationInput {
  category: string
  cwe: string[] | null
  vuln_ids: string[] | null
  package: { ecosystem?: string | null, name?: string | null } | null
  path: string | null
  snippet: string | null
  start_line: number | null
  secret_type: string | null
}

const SAST_IAC = new Set(['sast', 'iac'])
/** Écosystème (findings.package.ecosystem) → type de purl. */
const PURL_TYPE: Record<string, string> = {
  'npm': 'npm', 'pypi': 'pypi', 'go': 'golang', 'crates.io': 'cargo', 'maven': 'maven', 'rubygems': 'gem',
  'packagist': 'composer', 'nuget': 'nuget', 'debian': 'deb', 'alpine': 'apk', 'rpm': 'rpm', 'hex': 'hex', 'pub': 'pub',
}
/** Extrait entièrement masqué (maskToken) : aucun contexte exploitable. */
const MASKED_SNIPPET_RE = /^\[secret masqué : [^\]]*\]$/

/** Avis canonique : CVE (le plus petit, trié), sinon GHSA, sinon le premier avis trié ; en majuscules. */
/** Ordre des points de code, indépendant de la locale : la clé reste stable d'une machine à l'autre. */
export function byCodePoint(a: string, b: string): number {
  if (a === b) return 0
  return a < b ? -1 : 1
}

export function canonicalVulnId(ids: readonly string[] | null | undefined): string | null {
  const list = [...new Set((ids ?? []).filter(i => typeof i === 'string' && i.length > 0).map(i => i.toUpperCase()))].sort(byCodePoint)
  return list.find(i => i.startsWith('CVE-')) ?? list.find(i => i.startsWith('GHSA-')) ?? list[0] ?? null
}

/** « pkg:<type>/<nom> » sans version, nom en minuscules (PyPI : séparateurs ramenés à « - », PEP 503). */
export function purlWithoutVersion(pkg: CorrelationInput['package']): string | null {
  const name = pkg?.name?.trim()
  if (!name) return null
  const eco = (pkg?.ecosystem ?? '').trim().toLowerCase()
  const type = PURL_TYPE[eco] ?? (eco.replace(/[^a-z0-9.+-]/g, '') || 'generic')
  let n = name.toLowerCase()
  if (type === 'pypi') n = n.replace(/[-_.]+/g, '-')
  return `pkg:${type}/${n}`
}

/** Plus petit CWE numérique (« CWE-79 » → « 79 »). */
function primaryCwe(cwe: readonly string[] | null | undefined): string | null {
  const nums = (cwe ?? []).map(c => /^CWE-([0-9]{1,5})$/i.exec(c)?.[1]).filter((n): n is string => !!n).map(Number)
  return nums.length ? String(Math.min(...nums)) : null
}

function contextPrint(f: CorrelationInput): string | null {
  const snippet = collapseWhitespace(f.snippet ?? '')
  if (snippet && !MASKED_SNIPPET_RE.test(snippet)) return sha256(`ctx\u001f${snippet}`)
  return f.start_line ? `L${f.start_line}` : null
}

/** Contrat 18 : clé de recoupement d'un résultat (hex 64) ou null. */
export function correlationKey(f: CorrelationInput): string | null {
  if (f.secret_type || f.category === 'secrets') return null
  const vuln = canonicalVulnId(f.vuln_ids)
  const purl = purlWithoutVersion(f.package)
  if (vuln && purl) return sha256(`vuln:${vuln}|${purl}`)
  if (SAST_IAC.has(f.category) && f.path) {
    const cwe = primaryCwe(f.cwe)
    const ctx = contextPrint(f)
    if (cwe && ctx) return sha256(`cwe:${cwe}|${f.path}|${ctx}`)
  }
  return null
}

const SELECT_INPUT = `id, category, cwe, vuln_ids, package, path, snippet, start_line, secret_type, correlation_key`
type Row = CorrelationInput & { id: string, correlation_key: string | null }

async function updateKeys(db: Queryable, rows: Row[]): Promise<number> {
  const changed = rows.map(r => ({ id: r.id, key: correlationKey(r), old: r.correlation_key })).filter(r => r.key !== r.old)
  if (!changed.length) return 0
  await db.query(
    `UPDATE findings f SET correlation_key = x.key
       FROM unnest($1::uuid[], $2::text[]) AS x(id, key)
      WHERE f.id = x.id AND f.correlation_key IS DISTINCT FROM x.key`,
    [changed.map(r => r.id), changed.map(r => r.key)],
  )
  return changed.length
}

/** Calcule la clé des résultats donnés (appelé par l'ingestion, dans sa transaction). */
export async function assignCorrelationKeys(db: Queryable, ids: string[]): Promise<number> {
  let n = 0
  for (let i = 0; i < ids.length; i += 1000) {
    const r = await db.query<Row>(`SELECT ${SELECT_INPUT} FROM findings WHERE id = ANY($1::uuid[])`, [ids.slice(i, i + 1000)])
    n += await updateKeys(db, r.rows)
  }
  return n
}

export const BACKFILL_SETTING = 'findings.correlation_backfill'
/** À changer si la définition de la clé change : la reprise recalcule alors tout. */
export const CORRELATION_VERSION = 1

/**
 * Reprise idempotente des résultats d'avant la 0.5, par lots, au démarrage de la
 * console. L'avancement est gardé dans appliance_settings : une reprise
 * interrompue repart du dernier lot, une reprise finie ne relit plus rien.
 */
export async function backfillCorrelationKeys(db: Queryable, opts: { batch?: number } = {}): Promise<{ scanned: number, updated: number }> {
  const batch = Math.max(1, Math.min(5000, opts.batch ?? 1000))
  const s = await db.query<{ value: { version?: number, last_id?: string | null, done?: boolean } }>(
    'SELECT value FROM appliance_settings WHERE key = $1', [BACKFILL_SETTING],
  )
  const st = s.rows[0]?.value
  if (st?.version === CORRELATION_VERSION && st.done) return { scanned: 0, updated: 0 }
  let last = st?.version === CORRELATION_VERSION && typeof st.last_id === 'string' ? st.last_id : '00000000-0000-0000-0000-000000000000'
  let scanned = 0
  let updated = 0
  for (;;) {
    const r = await db.query<Row>(`SELECT ${SELECT_INPUT} FROM findings WHERE id > $1 ORDER BY id LIMIT $2`, [last, batch])
    scanned += r.rows.length
    updated += await updateKeys(db, r.rows)
    const done = r.rows.length < batch
    if (r.rows.length) last = r.rows[r.rows.length - 1]!.id
    await db.query(
      `INSERT INTO appliance_settings (key, value, updated_at) VALUES ($1, $2::jsonb, now())
       ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()`,
      [BACKFILL_SETTING, JSON.stringify({ version: CORRELATION_VERSION, last_id: last, done })],
    )
    if (done) return { scanned, updated }
  }
}

export interface Correlated {
  id: string
  severity: Severity
  malicious: boolean
  correlation_key?: string | null
  kev?: boolean | null
  epss?: number | null
}

/**
 * F16 dans le quality gate : un groupe compte une seule fois, à la gravité la
 * plus haute du groupe (un paquet malveillant passe en tête). Le représentant
 * reçoit le KEV et l'EPSS le plus haut du groupe. Un résultat sans clé reste tel quel.
 */
export function collapseCorrelated<T extends Correlated>(list: readonly T[]): T[] {
  const groups = new Map<string, T[]>()
  const out: (T | string)[] = []
  for (const f of list) {
    if (!f.correlation_key) {
      out.push(f)
      continue
    }
    const g = groups.get(f.correlation_key)
    if (g) g.push(f)
    else {
      groups.set(f.correlation_key, [f])
      out.push(f.correlation_key)
    }
  }
  return out.map((x) => {
    if (typeof x !== 'string') return x
    const members = groups.get(x)!
    if (members.length === 1) return members[0]!
    const best = [...members].sort((a, b) => Number(b.malicious) - Number(a.malicious)
      || SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] || (a.id < b.id ? -1 : 1))[0]!
    const kev = members.some(m => m.kev)
    const epssList = members.map(m => m.epss).filter((e): e is number => typeof e === 'number')
    return { ...best, kev, epss: epssList.length ? Math.max(...epssList) : (best.epss ?? null) }
  })
}

export interface GroupMember {
  id: string
  tool: string
  severity: string
  status: string
}

export interface FindingGroup {
  key: string
  project_id: string
  /** Nombre d'outils distincts : indice de confiance. */
  confirmations: number
  tools: string[]
  /** Nombre total de résultats du groupe (members est limité à 50). */
  size: number
  members: GroupMember[]
}

const MAX_MEMBERS = 50

/** Groupes (hors résultats corrigés) des clés données, par projet. */
export async function groupsFor(db: Queryable, pairs: { project_id: string, key: string }[]): Promise<Map<string, FindingGroup>> {
  const out = new Map<string, FindingGroup>()
  const uniq = [...new Map(pairs.map(p => [`${p.project_id}|${p.key}`, p])).values()]
  if (!uniq.length) return out
  const r = await db.query<GroupMember & { project_id: string, correlation_key: string }>(
    `SELECT f.id, f.tool, f.severity, f.status, f.project_id, f.correlation_key
       FROM findings f JOIN unnest($1::uuid[], $2::text[]) AS x(project_id, key)
         ON f.project_id = x.project_id AND f.correlation_key = x.key
      WHERE f.status <> 'fixed'
      ORDER BY f.tool, f.id`,
    [uniq.map(p => p.project_id), uniq.map(p => p.key)],
  )
  for (const m of r.rows) {
    const id = `${m.project_id}|${m.correlation_key}`
    const g = out.get(id) ?? { key: m.correlation_key, project_id: m.project_id, confirmations: 0, tools: [], size: 0, members: [] }
    if (!g.tools.includes(m.tool)) g.tools.push(m.tool)
    g.size++
    if (g.members.length < MAX_MEMBERS) g.members.push({ id: m.id, tool: m.tool, severity: m.severity, status: m.status })
    g.confirmations = g.tools.length
    out.set(id, g)
  }
  return out
}

/** Tous les résultats (hors corrigés) du groupe d'un résultat, sans plafond, triés par id. */
export async function groupMemberIds(db: Queryable, findingId: string): Promise<string[] | null> {
  const r = await db.query<{ id: string }>(
    `SELECT g.id FROM findings f JOIN findings g ON g.project_id = f.project_id AND g.correlation_key = f.correlation_key
      WHERE f.id = $1 AND g.status <> 'fixed' ORDER BY g.id`,
    [findingId],
  )
  return r.rows.length ? r.rows.map(x => x.id) : null
}

/** Groupe d'un résultat (lui compris), ou null s'il n'a pas de clé. */
export async function groupOf(db: Queryable, findingId: string): Promise<FindingGroup | null> {
  const r = await db.query<{ project_id: string, correlation_key: string | null }>(
    'SELECT project_id, correlation_key FROM findings WHERE id = $1', [findingId],
  )
  const row = r.rows[0]
  if (!row?.correlation_key) return null
  return (await groupsFor(db, [{ project_id: row.project_id, key: row.correlation_key }])).get(`${row.project_id}|${row.correlation_key}`) ?? null
}
