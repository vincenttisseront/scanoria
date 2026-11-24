// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// SBOM d'une analyse (contrat 14 de la 0.5, chantier A).
//
// Le module syft publie un CycloneDX 1.5 ou 1.6, validé par le runner (G2) ;
// le worker le lit puis appelle ingestSbom, qui remplit sbom_components :
//   - purl normalisé (schéma et type en minuscules, nom PyPI normalisé,
//     qualificatifs triés), écosystème = type du purl ;
//   - licences en identifiants ou expressions SPDX ;
//   - direct si le graphe de dépendances le dit (sinon NULL) ;
//   - fichiers d'origine (propriétés syft:location:*:path, evidence) ;
//   - au plus MAX_COMPONENTS composants : au-delà, ou pour un document
//     invalide, rien n'est rangé (jamais d'ingestion partielle) et le module
//     devient « invalid-output ».
// Les composants sans purl utilisable sont ignorés et comptés dans la
// couverture de l'analyse (G15) : scans.coverage.sbom.
// La table est la forme durable du SBOM (les sorties du runner sont purgées
// après 24 h) : sbomDocument en régénère un CycloneDX 1.6 pour l'export et la
// re-corrélation (F3).

import type pg from 'pg'
import type { Queryable } from '../utils/db'
import { withTransaction } from '../utils/db'
import { readOutput } from '../findings/ingest'

export const MAX_COMPONENTS = 50_000
const MAX_DEPTH = 16
const MAX_LICENSES = 20
const MAX_PATHS = 20
const DTRACK_PROPERTY = 'scanoria:dtrack:project'
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/
const TYPE_RE = /^[a-z][a-z0-9.+-]{0,63}$/
const SPEC_RE = /^1\.[3-6]$/

export class SbomError extends Error {
  constructor(readonly code: 'not-cyclonedx' | 'unsupported-version' | 'malformed' | 'too-many-components', detail: string) {
    super(detail)
  }
}

export interface SbomComponent {
  purl: string
  ecosystem: string
  name: string
  version: string | null
  licenses: string[]
  direct: boolean | null
  paths: string[]
}

export interface SbomCoverage {
  components: number
  ignored_no_purl: number
  ignored_invalid_purl: number
  direct_known: boolean
  spec_version: string
}

export interface ParsedPurl { type: string, namespace: string[], name: string, version: string | null, purl: string }

function decode(s: string): string | null {
  try {
    return decodeURIComponent(s)
  }
  catch {
    return null
  }
}

// Encodage d'un segment de purl : celui d'encodeURIComponent, « : » gardé (spécification purl).
const enc = (s: string) => encodeURIComponent(s).replace(/%3A/gi, ':')

/** Purl normalisé, ou null s'il est illisible (spécification package-url). */
export function normalizePurl(raw: unknown): ParsedPurl | null {
  if (typeof raw !== 'string' || raw.length < 5 || raw.length > 2048 || !/^pkg:/i.test(raw)) return null
  // eslint-disable-next-line no-control-regex
  if (/[\s\u0000-\u001f]/.test(raw)) return null
  let rest = raw.slice(4).replace(/^\/+/, '')
  let subpath = ''
  const hash = rest.indexOf('#')
  if (hash >= 0) {
    subpath = rest.slice(hash + 1).split('/').filter(x => x && x !== '.' && x !== '..').join('/')
    rest = rest.slice(0, hash)
  }
  let qualifiers: [string, string][] = []
  const q = rest.indexOf('?')
  if (q >= 0) {
    for (const pair of rest.slice(q + 1).split('&')) {
      const eq = pair.indexOf('=')
      if (eq <= 0) continue
      const k = pair.slice(0, eq).toLowerCase()
      const v = decode(pair.slice(eq + 1))
      if (v === null || !/^[a-z][a-z0-9._-]{0,63}$/.test(k)) return null
      if (v) qualifiers.push([k, v])
    }
    qualifiers = qualifiers.sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0))
    rest = rest.slice(0, q)
  }
  let version: string | null = null
  const at = rest.lastIndexOf('@')
  if (at > rest.lastIndexOf('/')) {
    version = decode(rest.slice(at + 1))
    if (version === null) return null
    version = version || null
    rest = rest.slice(0, at)
  }
  const parts = rest.split('/').filter(Boolean).map(decode)
  if (parts.length < 2 || parts.some(p => p === null)) return null
  const segs = parts as string[]
  const type = segs[0]!.toLowerCase()
  if (!TYPE_RE.test(type)) return null
  let namespace = segs.slice(1, -1)
  let name = segs[segs.length - 1]!
  if (['github', 'bitbucket', 'pypi'].includes(type)) {
    namespace = namespace.map(s => s.toLowerCase())
    name = name.toLowerCase()
  }
  if (type === 'pypi') name = name.replace(/[_.]+/g, '-').replace(/-+/g, '-')
  if (!name) return null
  let purl = `pkg:${type}/${[...namespace, name].map(enc).join('/')}`
  if (version) purl += `@${enc(version)}`
  if (qualifiers.length) purl += `?${qualifiers.map(([k, v]) => `${k}=${enc(v)}`).join('&')}`
  if (subpath) purl += `#${subpath.split('/').map(enc).join('/')}`
  if (purl.length > 1024) return null
  return { type, namespace, name, version, purl }
}

/** Nom affiché et recherché (F3) : espace de noms compris (« @scope/nom », « github.com/x/y », « groupe:artefact »). */
export function displayName(p: ParsedPurl): string {
  if (!p.namespace.length) return p.name
  return p.type === 'maven' ? `${p.namespace.join('.')}:${p.name}` : `${p.namespace.join('/')}/${p.name}`
}

const str = (v: unknown, max: number): string | null => (typeof v === 'string' && v.trim() && v.length <= max ? v.trim() : null)

function licensesOf(c: Record<string, unknown>): string[] {
  const out = new Set<string>()
  const list = Array.isArray(c.licenses) ? c.licenses : []
  for (const item of list) {
    if (!item || typeof item !== 'object') continue
    const it = item as Record<string, unknown>
    const expr = str(it.expression, 256)
    if (expr) {
      out.add(expr)
      continue
    }
    const lic = it.license && typeof it.license === 'object' ? it.license as Record<string, unknown> : null
    const v = str(lic?.id, 128) ?? str(lic?.name, 128)
    if (v) out.add(v)
  }
  return [...out].slice(0, MAX_LICENSES)
}

function pathsOf(c: Record<string, unknown>): string[] {
  const out = new Set<string>()
  const add = (v: unknown) => {
    const s = str(v, 1024)
    if (s) out.add(s.replace(/^\/+/, '') || '/')
  }
  for (const p of Array.isArray(c.properties) ? c.properties : []) {
    const pr = p as { name?: unknown, value?: unknown } | null
    if (pr && typeof pr.name === 'string' && /^syft:location:\d+:path$/.test(pr.name)) add(pr.value)
  }
  const ev = c.evidence && typeof c.evidence === 'object' ? c.evidence as Record<string, unknown> : null
  for (const o of Array.isArray(ev?.occurrences) ? ev!.occurrences as unknown[] : []) add((o as { location?: unknown } | null)?.location)
  return [...out].slice(0, MAX_PATHS)
}

/** Dépendances directes : celles de la racine (metadata.component) dans le graphe, si elle y figure. */
function directRefs(doc: Record<string, unknown>): Set<string> | null {
  const meta = doc.metadata && typeof doc.metadata === 'object' ? doc.metadata as Record<string, unknown> : null
  const root = meta?.component && typeof meta.component === 'object' ? (meta.component as Record<string, unknown>)['bom-ref'] : null
  if (typeof root !== 'string' || !Array.isArray(doc.dependencies)) return null
  const entry = (doc.dependencies as unknown[]).find(d => (d as { ref?: unknown } | null)?.ref === root) as { dependsOn?: unknown } | undefined
  if (!entry || !Array.isArray(entry.dependsOn)) return null
  return new Set(entry.dependsOn.filter((x): x is string => typeof x === 'string'))
}

/** Lecture complète d'un document CycloneDX ; lève SbomError sans rien ranger. */
export function parseSbom(doc: unknown): { components: SbomComponent[], coverage: SbomCoverage } {
  if (!doc || typeof doc !== 'object' || Array.isArray(doc)) throw new SbomError('not-cyclonedx', 'not a JSON object')
  const d = doc as Record<string, unknown>
  if (d.bomFormat !== 'CycloneDX') throw new SbomError('not-cyclonedx', 'bomFormat is not CycloneDX')
  if (typeof d.specVersion !== 'string' || !SPEC_RE.test(d.specVersion)) throw new SbomError('unsupported-version', `specVersion ${String(d.specVersion)}`)
  if (d.components !== undefined && !Array.isArray(d.components)) throw new SbomError('malformed', 'components is not an array')
  const direct = directRefs(d)
  const byPurl = new Map<string, SbomComponent>()
  let seen = 0
  let noPurl = 0
  let badPurl = 0
  const visit = (items: unknown, depth: number) => {
    if (items === undefined) return
    if (!Array.isArray(items)) throw new SbomError('malformed', 'nested components is not an array')
    if (depth > MAX_DEPTH) throw new SbomError('malformed', 'components nested too deeply')
    for (const item of items) {
      if (!item || typeof item !== 'object' || Array.isArray(item)) throw new SbomError('malformed', 'component is not an object')
      seen++
      if (seen > MAX_COMPONENTS) throw new SbomError('too-many-components', `more than ${MAX_COMPONENTS} components`)
      const c = item as Record<string, unknown>
      if (typeof c.purl !== 'string' || !c.purl) noPurl++
      else {
        const p = normalizePurl(c.purl)
        if (!p) badPurl++
        else {
          const ref = typeof c['bom-ref'] === 'string' ? c['bom-ref'] : null
          const isDirect = direct ? (ref !== null && direct.has(ref)) : null
          const name = displayName(p).slice(0, 512)
          const prev = byPurl.get(p.purl)
          if (prev) {
            prev.licenses = [...new Set([...prev.licenses, ...licensesOf(c)])].slice(0, MAX_LICENSES)
            prev.paths = [...new Set([...prev.paths, ...pathsOf(c)])].slice(0, MAX_PATHS)
            if (isDirect !== null) prev.direct = (prev.direct ?? false) || isDirect
          }
          else {
            byPurl.set(p.purl, { purl: p.purl, ecosystem: p.type, name, version: p.version?.slice(0, 256) ?? null,
              licenses: licensesOf(c), direct: isDirect, paths: pathsOf(c) })
          }
        }
      }
      visit(c.components, depth + 1)
    }
  }
  visit(d.components, 0)
  const components = [...byPurl.values()].sort((a, b) => (a.purl < b.purl ? -1 : a.purl > b.purl ? 1 : 0))
  return { components, coverage: { components: components.length, ignored_no_purl: noPurl, ignored_invalid_purl: badPurl,
    direct_known: direct !== null, spec_version: d.specVersion } }
}

/** Identifiant du projet Dependency-Track porté par la sortie de dtrack-upload, ou null. */
export function dtrackProjectOf(doc: unknown): string | null {
  const meta = (doc as { metadata?: { properties?: unknown } } | null)?.metadata
  const props = Array.isArray(meta?.properties) ? meta!.properties as unknown[] : []
  const v = (props.find(p => (p as { name?: unknown } | null)?.name === DTRACK_PROPERTY) as { value?: unknown } | undefined)?.value
  return typeof v === 'string' && UUID_RE.test(v) ? v : null
}

const BATCH = 2000

/**
 * Contrat 14 : remplit sbom_components pour l'analyse (remplace un relevé
 * précédent de la même analyse) et la couverture scans.coverage.sbom, en une
 * transaction. Lève SbomError pour un document invalide ou trop grand.
 */
export async function ingestSbom(db: pg.Pool, args: { scanId: string, projectId: string, doc: unknown, moduleId?: string }): Promise<SbomCoverage> {
  const { components, coverage } = parseSbom(args.doc)
  await withTransaction(db, async (c) => {
    await c.query('DELETE FROM sbom_components WHERE scan_id = $1', [args.scanId])
    for (let i = 0; i < components.length; i += BATCH) {
      const part = components.slice(i, i + BATCH)
      await c.query(
        `INSERT INTO sbom_components (scan_id, project_id, purl, ecosystem, name, version, licenses, direct, paths)
         SELECT $1, $2, x.purl, x.ecosystem, x.name, x.version,
                ARRAY(SELECT jsonb_array_elements_text(x.licenses)), x.direct, ARRAY(SELECT jsonb_array_elements_text(x.paths))
           FROM jsonb_to_recordset($3::jsonb) AS x(purl text, ecosystem text, name text, version text, licenses jsonb, direct boolean, paths jsonb)`,
        [args.scanId, args.projectId, JSON.stringify(part)])
    }
    await c.query(
      `UPDATE scans SET coverage = COALESCE(coverage, '{}'::jsonb)
              || jsonb_build_object('sbom', COALESCE(coverage -> 'sbom', '{}'::jsonb) || $2::jsonb) WHERE id = $1`,
      [args.scanId, JSON.stringify({ ...coverage, module: args.moduleId ?? null })])
  })
  return coverage
}

/** Rattache l'analyse à son projet Dependency-Track (lien de l'onglet SBOM). */
export async function recordDtrackProject(db: Queryable, scanId: string, uuid: string): Promise<void> {
  if (!UUID_RE.test(uuid)) return
  await db.query(
    `UPDATE scans SET coverage = COALESCE(coverage, '{}'::jsonb)
            || jsonb_build_object('sbom', COALESCE(coverage -> 'sbom', '{}'::jsonb) || jsonb_build_object('dtrack_project', $2::text)) WHERE id = $1`,
    [scanId, uuid])
}

export interface SbomRow extends SbomComponent { published_at: string | null }

/**
 * Sortie CycloneDX d'un module, lue par le worker (contrat 14) : un SBOM est
 * rangé s'il est le premier de l'analyse ; la sortie de dtrack-upload ne fait
 * que rattacher le projet Dependency-Track.
 */
export async function ingestSbomOutput(db: pg.Pool, args: { scanId: string, projectId: string, moduleId: string, doc: unknown }): Promise<'ingested' | 'linked' | 'ignored'> {
  const dtrack = dtrackProjectOf(args.doc)
  if (dtrack) {
    parseSbom(args.doc) // sortie non conforme : module non concluant, comme un SBOM
    await recordDtrackProject(db, args.scanId, dtrack)
    return 'linked'
  }
  const { rows } = await db.query<{ module: string | null }>(`SELECT coverage -> 'sbom' ->> 'module' AS module FROM scans WHERE id = $1`, [args.scanId])
  const owner = rows[0]?.module
  if (owner && owner !== args.moduleId) {
    parseSbom(args.doc)
    return 'ignored'
  }
  await ingestSbom(db, args)
  return 'ingested'
}

/** Lecture de la sortie publiée par le runner (sans lien, bornée), puis ingestSbomOutput. */
export async function ingestSbomFile(db: pg.Pool, args: { scanId: string, projectId: string, moduleId: string, resultDir: string, path: string }) {
  const { doc, error } = await readOutput(args.resultDir, args.path)
  if (error) throw new SbomError('malformed', `SBOM output: ${error.code}`)
  return ingestSbomOutput(db, { scanId: args.scanId, projectId: args.projectId, moduleId: args.moduleId, doc })
}

/** Analyse terminée la plus récente du projet qui a un SBOM, ou null. */
export async function latestSbomScan(db: Queryable, projectId: string): Promise<string | null> {
  const { rows } = await db.query<{ id: string }>(
    `SELECT s.id FROM scans s
      WHERE s.project_id = $1 AND s.status = 'done' AND EXISTS (SELECT 1 FROM sbom_components c WHERE c.scan_id = s.id)
      ORDER BY s.finished_at DESC NULLS LAST, s.queued_at DESC LIMIT 1`, [projectId])
  return rows[0]?.id ?? null
}

/** Contrat 14 : composants de la dernière analyse terminée du projet qui a un SBOM. */
export async function latestSbom(db: Queryable, projectId: string): Promise<{ scanId: string, components: SbomRow[] } | null> {
  const scanId = await latestSbomScan(db, projectId)
  if (!scanId) return null
  return { scanId, components: await scanSbom(db, scanId) }
}

export async function scanSbom(db: Queryable, scanId: string): Promise<SbomRow[]> {
  const { rows } = await db.query<SbomRow>(
    `SELECT purl, ecosystem, name, version, licenses, direct, paths, to_char(published_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS published_at
       FROM sbom_components WHERE scan_id = $1 ORDER BY ecosystem, name, version NULLS FIRST, purl`, [scanId])
  return rows
}

const SPDX_LIKE_RE = /^[A-Za-z0-9.+:()-]+(?: (?:AND|OR|WITH) [A-Za-z0-9.+:()-]+)*$/

/** CycloneDX 1.6 régénéré depuis sbom_components (export, re-corrélation F3). */
export function sbomDocument(rows: SbomComponent[], meta: { scanId: string, project: string, createdAt?: string | null }): Record<string, unknown> {
  return {
    bomFormat: 'CycloneDX',
    specVersion: '1.6',
    serialNumber: `urn:uuid:${meta.scanId}`,
    version: 1,
    metadata: {
      ...(meta.createdAt ? { timestamp: meta.createdAt } : {}),
      tools: { components: [{ type: 'application', name: 'Scanoria' }] },
      component: { 'type': 'application', 'bom-ref': 'scanoria-project', 'name': meta.project },
    },
    components: rows.map(r => ({
      'type': 'library',
      'bom-ref': r.purl,
      'name': r.name,
      ...(r.version ? { version: r.version } : {}),
      'purl': r.purl,
      // Un identifiant ou une expression SPDX seule : « expression » (non contrainte par
      // l'énumération SPDX du schéma) ; plusieurs licences : leurs noms.
      ...(r.licenses.length === 1 && SPDX_LIKE_RE.test(r.licenses[0]!)
        ? { licenses: [{ expression: r.licenses[0] }] }
        : r.licenses.length ? { licenses: r.licenses.map(l => ({ license: { name: l } })) } : {}),
      ...(r.paths.length ? { evidence: { occurrences: r.paths.map(p => ({ location: p })) } } : {}),
    })),
    ...(rows.some(r => r.direct !== null)
      ? { dependencies: [{ ref: 'scanoria-project', dependsOn: rows.filter(r => r.direct).map(r => r.purl) }] }
      : {}),
  }
}
