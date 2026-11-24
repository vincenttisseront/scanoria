// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// I11, côté console : lecture de l'index du module reach-index et dépôt des
// tâches assess-reachability. Appelé par la file d'analyses après le verdict
// (utilisateur scanoria, qui lit le dossier de résultats du runner pendant
// 24 h) ; scanoria-ai n'a aucun accès aux fichiers et ne reçoit que le
// contexte joint, masqué et borné (ai_tasks.context, 16 Ko).
//
// L'index est un SARIF 2.1.0 dont les résultats sont « informational »
// (jamais des résultats d'analyse : l'ingestion les ignore) :
//   ruleId reach-index/import | reach-index/call, emplacement (chemin, ligne,
//   extrait), properties { language, module, symbol } ;
//   runs[0].properties["scanoria/reach-index"] = { version, languages, files, truncated }.
// Le contenu de l'index vient du code analysé : il est traité comme donnée
// hostile (validé champ par champ, borné, masqué, jamais interprété).

import { join } from 'node:path'
import type { Queryable } from '../utils/db'
import { readContainedFile, readResult, resultDir, resultsRoot } from '../scans/files'
import { pickPackage } from './task-kit'
import { redactText } from './redact'
import { AI_PRIORITY, connectorEnabled, enqueueAiTask } from './enqueue'
import { boundContext, MAX_EXCERPT_CHARS, MAX_REACH_LOCATIONS, moduleMatches, type ReachContext, type ReachLocationCtx } from './reach-context'

export const REACH_MODULE = 'reach-index'
export const REACH_PROPS = 'scanoria/reach-index'
const MAX_INDEX_BYTES = 32 * 1024 * 1024
const MAX_ENTRIES = 200_000
/** Vulnérabilités évaluées automatiquement par analyse ; les autres à la demande. */
export const MAX_REACH_TASKS = 100
const LANGUAGES = new Set(['javascript', 'typescript', 'python', 'go', 'java'])

export interface ReachEntry {
  kind: 'import' | 'call'
  path: string
  line: number
  module: string
  symbol: string
  excerpt: string
}

export interface ReachIndex {
  languages: string[]
  files: number
  truncated: boolean
  entries: ReachEntry[]
}

const str = (v: unknown, max: number) => (typeof v === 'string' && v.length > 0 ? v.slice(0, max) : null)
const SAFE_PATH = /^[^\0\n\r]{1,512}$/

/** Chemin relatif d'une URI d'artefact (encodée en pourcentage par reach-index) ; null si douteux. */
export function artifactPath(uri: unknown): string | null {
  const raw = str(uri, 2048)
  if (!raw) return null
  let path: string
  try {
    path = decodeURIComponent(raw)
  }
  catch {
    return null
  }
  if (!SAFE_PATH.test(path) || path.startsWith('/') || path.split('/').includes('..')) return null
  return path
}

/** Index reach-index lu dans un document SARIF, ou null s'il n'en est pas un. */
export function parseReachSarif(doc: unknown): ReachIndex | null {
  const run = (doc as { version?: unknown, runs?: unknown[] })?.runs?.[0] as Record<string, unknown> | undefined
  if ((doc as { version?: unknown })?.version !== '2.1.0' || !run || typeof run !== 'object') return null
  const driver = (run.tool as { driver?: { name?: unknown } } | undefined)?.driver
  if (driver?.name !== REACH_MODULE) return null
  const meta = ((run.properties as Record<string, unknown> | undefined)?.[REACH_PROPS] ?? {}) as Record<string, unknown>
  const languages = Array.isArray(meta.languages) ? meta.languages.filter((l): l is string => typeof l === 'string' && LANGUAGES.has(l)) : []
  const results = Array.isArray(run.results) ? run.results : []
  const entries: ReachEntry[] = []
  for (const r of results.slice(0, MAX_ENTRIES)) {
    if (!r || typeof r !== 'object') continue
    const o = r as Record<string, unknown>
    const kind = o.ruleId === 'reach-index/import' ? 'import' : o.ruleId === 'reach-index/call' ? 'call' : null
    const props = (o.properties ?? {}) as Record<string, unknown>
    const loc = (Array.isArray(o.locations) ? o.locations[0] : null) as { physicalLocation?: { artifactLocation?: { uri?: unknown }, region?: { startLine?: unknown, snippet?: { text?: unknown } } } } | null
    const pl = loc?.physicalLocation
    const path = artifactPath(pl?.artifactLocation?.uri)
    const line = pl?.region?.startLine
    const module = str(props.module, 300)
    if (!kind || !path || typeof line !== 'number' || !Number.isInteger(line) || line < 1 || !module) continue
    entries.push({
      kind,
      path,
      line,
      module,
      symbol: str(props.symbol, 200) ?? '',
      excerpt: (str(pl?.region?.snippet?.text, 2000) ?? '').replace(/\s+/g, ' ').trim(),
    })
  }
  return {
    languages: [...new Set(languages)].slice(0, 10),
    files: typeof meta.files === 'number' && Number.isInteger(meta.files) && meta.files >= 0 ? Math.min(meta.files, 10_000_000) : 0,
    // Index incomplet (fichiers sautés ou illisibles, erreurs de syntaxe) : traité comme tronqué.
    truncated: meta.truncated === true || results.length > MAX_ENTRIES
      || (typeof meta.skipped === 'number' && meta.skipped > 0) || (typeof meta.errors === 'number' && meta.errors > 0),
    entries,
  }
}

/**
 * Contexte d'une vulnérabilité : imports du composant, puis appels qui le
 * visent (symboles vulnérables d'abord), extraits masqués, 16 Ko au plus.
 */
export function reachContext(index: ReachIndex, pkg: { ecosystem?: string, name?: string }, symbols: string[] = []): ReachContext {
  const matching = index.entries.filter(e => moduleMatches(pkg.ecosystem, pkg.name ?? '', e.module))
  const wanted = symbols.map(s => s.toLowerCase())
  const hitsSymbol = (e: ReachEntry) => wanted.some(s => e.symbol.toLowerCase().endsWith(s))
  const rank = (e: ReachEntry) => (e.kind === 'call' && hitsSymbol(e) ? 0 : e.kind === 'import' ? 1 : 2)
  const sorted = [...matching].sort((a, b) => rank(a) - rank(b) || a.path.localeCompare(b.path) || a.line - b.line)
  const locations: ReachLocationCtx[] = sorted.slice(0, MAX_REACH_LOCATIONS).map(e => ({
    kind: e.kind,
    // Tout ce qui vient de l'index est masqué : chemin, module, symbole et extrait.
    path: redactText(e.path).text.slice(0, 512),
    line: e.line,
    symbol: redactText(e.symbol).text.slice(0, 200),
    module: redactText(e.module).text.slice(0, 300),
    // Masqué avant découpe (aucun secret coupé et donc méconnu), puis après.
    excerpt: redactText(redactText(e.excerpt).text.slice(0, MAX_EXCERPT_CHARS)).text.slice(0, MAX_EXCERPT_CHARS),
  }))
  return boundContext({
    index: { languages: index.languages as ReachContext['index']['languages'], files: index.files, truncated: index.truncated || matching.length > MAX_REACH_LOCATIONS },
    symbols: symbols.slice(0, 20).map(s => redactText(s).text.slice(0, 200)).filter(Boolean),
    locations,
  })
}

/** Index de l'analyse, lu dans le dossier de résultats du runner ; null s'il n'existe pas ou plus. */
export async function readScanIndex(scansDir: string, jobId: string): Promise<ReachIndex | null> {
  const res = await readResult(scansDir, jobId)
  if (res.kind !== 'ok') return null
  const m = res.result.modules.find(x => x.id === REACH_MODULE)
  const rel = m?.status === 'ok' ? m.outputs?.sarif : null
  if (typeof rel !== 'string') return null
  const raw = await readContainedFile(resultsRoot(scansDir), join(resultDir(scansDir, jobId), rel), MAX_INDEX_BYTES)
  if (!Buffer.isBuffer(raw)) return null
  try {
    return parseReachSarif(JSON.parse(raw.toString('utf8')))
  }
  catch {
    return null
  }
}

const symbolsOf = (pkg: unknown): string[] => {
  const s = (pkg as { symbols?: unknown } | null)?.symbols
  return Array.isArray(s) ? s.filter((x): x is string => typeof x === 'string' && x.length > 0).slice(0, 20) : []
}

/**
 * Après le verdict : une tâche assess-reachability par vulnérabilité de
 * dépendance critical / high de l'analyse, avec son contexte. Sans connecteur,
 * sans index ou pour un projet exclu : rien. Ne lève jamais d'erreur.
 */
export async function enqueueReachability(db: Queryable, input: { scanId: string, projectId: string, scansDir: string }): Promise<number> {
  try {
    if (!(await connectorEnabled())) return 0
    // Projet exclu : l'index n'est même pas lu.
    const s = await db.query<{ job_id: string | null }>(
      `SELECT s.job_id FROM scans s JOIN projects p ON p.id = s.project_id
        WHERE s.id = $1 AND s.project_id = $2 AND NOT p.ai_opt_out AND p.archived_at IS NULL`, [input.scanId, input.projectId])
    const jobId = s.rows[0]?.job_id
    if (!jobId) return 0
    const index = await readScanIndex(input.scansDir, jobId)
    if (!index) return 0
    const { rows } = await db.query<{ id: string, package: unknown }>(
      `SELECT f.id, f.package FROM scan_findings sf JOIN findings f ON f.id = sf.finding_id
        WHERE sf.scan_id = $1 AND f.project_id = $2 AND f.category = 'sca' AND f.severity IN ('critical', 'high')
          AND f.status <> 'fixed' AND f.package IS NOT NULL AND cardinality(f.vuln_ids) > 0
        ORDER BY (f.severity = 'critical') DESC, f.id LIMIT $3`,
      [input.scanId, input.projectId, MAX_REACH_TASKS],
    )
    let n = 0
    for (const f of rows) {
      const pkg = pickPackage(f.package)
      if (!pkg?.name) continue
      const id = await enqueueAiTask(db, {
        kind: 'assess-reachability', subjectType: 'finding', subjectId: f.id, projectId: input.projectId,
        priority: AI_PRIORITY.precompute, context: reachContext(index, pkg, symbolsOf(f.package)),
      })
      if (id) n++
    }
    return n
  }
  catch (err) {
    console.error('[ai] reachability not queued:', (err as Error).message)
    return 0
  }
}
