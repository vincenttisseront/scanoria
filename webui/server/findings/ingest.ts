// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Contrat 5 de la 0.3 (chantiers-0.3/README.md), appelé par la file
// d'analyses (C) :
// - ingestModuleOutputs : sorties SARIF / CycloneDX d'un module « ok » →
//   findings dédupliqués par empreinte stable (G19), gravités normalisées
//   (G5), secrets masqués (F7), avis MAL- marqués (H4) ;
// - finalizeScanFindings : nouveau code (scan_findings.is_new), résultats
//   corrigés ou réapparus, couverture d'analyse (G15).

import { lstat, readFile, realpath } from 'node:fs/promises'
import { join, sep } from 'node:path'
import type pg from 'pg'
import { CATEGORIES } from '#shared/analysis'
import { enqueueFindingTasks } from '../ai/hooks'
import type { Queryable } from '../utils/db'
import { readModuleHints } from './manifest'
import { parseCycloneDx, parseSarif, type ParsedFinding, type ParseIssue } from './parse'
import { resolveSeverities } from './severity'
import { computeCoverage, mergeCoverageGaps, type CoverageGap } from './coverage'
import { assignCorrelationKeys } from './correlation'

export const MAX_OUTPUT_BYTES = 64 * 1024 * 1024
const OUTPUT_PATH_RE = /^[A-Za-z0-9._-]+(\/[A-Za-z0-9._-]+)*$/
const BATCH = 500
/** Erreurs qui rendent la sortie d'un module inexploitable (rien ne peut passer « corrigé »). */
const UNREADABLE = new Set<string>(['output-unreadable', 'output-too-large', 'output-path', 'invalid-json', 'invalid-document'])

export interface IngestInput {
  scanId: string
  moduleId: string
  /** results/<job-id>/ du runner. */
  resultDir: string
  /** Chemins relatifs à resultDir (scan-result.schema.json, modules[].outputs). */
  outputs: { sarif?: string | null, cyclonedx?: string | null }
  /** J6 (0.6) : catégories d'un outil externe, qui n'a pas de manifeste. */
  categories?: string[]
}

export interface IngestError {
  code: 'output-unreadable' | 'output-too-large' | 'output-path' | 'invalid-json' | ParseIssue['code']
  output?: 'sarif' | 'cyclonedx'
  detail?: string
}

export interface IngestOutcome {
  /** Résultats enregistrés pour ce module dans cette analyse. */
  count: number
  /** Résultats jamais vus auparavant dans le projet. */
  newCount: number
  errors: IngestError[]
}

type Db = pg.Pool | Queryable

async function inTransaction<T>(db: Db, fn: (q: Queryable) => Promise<T>): Promise<T> {
  if ('connect' in db && typeof db.connect === 'function') {
    const client = await (db as pg.Pool).connect()
    try {
      await client.query('BEGIN')
      const out = await fn(client)
      await client.query('COMMIT')
      return out
    }
    catch (err) {
      await client.query('ROLLBACK').catch(() => {})
      throw err
    }
    finally {
      client.release()
    }
  }
  return fn(db) // l'appelant tient déjà une transaction
}

/** Lit une sortie sans suivre de lien, sans sortir de resultDir, taille bornée. */
export async function readOutput(resultDir: string, rel: string): Promise<{ doc?: unknown, error?: IngestError }> {
  if (!OUTPUT_PATH_RE.test(rel) || rel.split('/').some(s => s === '.' || s === '..')) return { error: { code: 'output-path' } }
  let root: string
  try {
    root = await realpath(resultDir)
  }
  catch {
    return { error: { code: 'output-unreadable' } }
  }
  const full = join(root, rel)
  try {
    // Aucun composant du chemin ne doit être un lien symbolique.
    let cur = root
    for (const seg of rel.split('/')) {
      cur = join(cur, seg)
      if ((await lstat(cur)).isSymbolicLink()) return { error: { code: 'output-path' } }
    }
    const st = await lstat(full)
    if (!st.isFile() || st.nlink > 1) return { error: { code: 'output-unreadable' } }
    if (st.size > MAX_OUTPUT_BYTES) return { error: { code: 'output-too-large', detail: `${st.size}` } }
    const real = await realpath(full)
    if (!real.startsWith(root + sep)) return { error: { code: 'output-path' } }
    const raw = await readFile(real, 'utf8')
    try {
      return { doc: JSON.parse(raw) }
    }
    catch {
      return { error: { code: 'invalid-json' } }
    }
  }
  catch {
    return { error: { code: 'output-unreadable' } }
  }
}

interface ScanRow {
  id: string
  project_id: string
  ref: string
  commit_sha: string | null
}

async function loadScan(db: Queryable, scanId: string): Promise<ScanRow> {
  const r = await db.query<ScanRow>('SELECT id, project_id, ref, commit_sha FROM scans WHERE id = $1', [scanId])
  const scan = r.rows[0]
  if (!scan) throw new Error(`scan not found: ${scanId}`)
  return scan
}

async function moduleVersion(db: Queryable, scanId: string, moduleId: string): Promise<string | null> {
  const r = await db.query<{ module_version: string }>('SELECT module_version FROM scan_modules WHERE scan_id = $1 AND module_id = $2', [scanId, moduleId])
  return r.rows[0]?.module_version ?? null
}

interface UpsertRow {
  id: string
  inserted: boolean
  severity: string
  tool: string
  rule_id: string
  category: string
  secret_type: string | null
}

async function upsert(db: Queryable, scan: ScanRow, findings: (ParsedFinding & { severity: string })[]): Promise<UpsertRow[]> {
  const out: UpsertRow[] = []
  for (let i = 0; i < findings.length; i += BATCH) {
    const batch = findings.slice(i, i + BATCH).map(f => ({
      fingerprint: f.fingerprint,
      tool: f.tool,
      rule_id: f.ruleId,
      category: f.category,
      severity: f.severity,
      native_severity: f.nativeSeverity,
      title: f.title,
      message: f.message,
      path: f.path,
      start_line: f.startLine,
      end_line: f.endLine,
      snippet: f.snippet,
      cwe: f.cwe,
      vuln_ids: f.vulnIds,
      package: f.package,
      malicious: f.malicious,
      secret_type: f.secretType,
    }))
    // Réapparition : « corrigé » ou acceptation échue redevient « nouveau » (§ 12.6) ;
    // faux positif et acceptation en cours sont conservés.
    const res = await db.query<UpsertRow>(
      `INSERT INTO findings AS f (project_id, fingerprint, tool, rule_id, category, severity, native_severity,
              title, message, path, start_line, end_line, snippet, cwe, vuln_ids, package, malicious,
              secret_type, secret_state, first_scan_id, first_commit, last_scan_id, last_commit)
       SELECT $1, x.fingerprint, x.tool, x.rule_id, x.category, x.severity, x.native_severity,
              x.title, x.message, x.path, x.start_line, x.end_line, x.snippet, x.cwe, x.vuln_ids, x.package, x.malicious,
              x.secret_type, CASE WHEN x.secret_type IS NOT NULL THEN 'to-revoke' END, $2, $3, $2, $3
         FROM jsonb_to_recordset($4::jsonb) AS x(fingerprint text, tool text, rule_id text, category text, severity text,
              native_severity text, title text, message text, path text, start_line integer, end_line integer, snippet text,
              cwe text[], vuln_ids text[], package jsonb, malicious boolean, secret_type text)
       ON CONFLICT (project_id, fingerprint) DO UPDATE SET
              tool = EXCLUDED.tool, rule_id = EXCLUDED.rule_id, category = EXCLUDED.category,
              severity = EXCLUDED.severity, native_severity = EXCLUDED.native_severity,
              title = EXCLUDED.title, message = EXCLUDED.message, path = EXCLUDED.path,
              start_line = EXCLUDED.start_line, end_line = EXCLUDED.end_line, snippet = EXCLUDED.snippet,
              cwe = EXCLUDED.cwe, vuln_ids = EXCLUDED.vuln_ids, package = EXCLUDED.package,
              malicious = f.malicious OR EXCLUDED.malicious,
              secret_type = COALESCE(f.secret_type, EXCLUDED.secret_type),
              secret_state = COALESCE(f.secret_state, EXCLUDED.secret_state),
              status = CASE WHEN f.status = 'fixed' OR (f.status = 'accepted' AND f.status_until < current_date)
                            THEN 'new' ELSE f.status END,
              status_until = CASE WHEN f.status = 'fixed' OR (f.status = 'accepted' AND f.status_until < current_date)
                                  THEN NULL ELSE f.status_until END,
              status_by = CASE WHEN f.status = 'fixed' OR (f.status = 'accepted' AND f.status_until < current_date)
                               THEN NULL ELSE f.status_by END,
              status_at = CASE WHEN f.status = 'fixed' OR (f.status = 'accepted' AND f.status_until < current_date)
                               THEN now() ELSE f.status_at END,
              last_scan_id = EXCLUDED.last_scan_id, last_commit = EXCLUDED.last_commit, updated_at = now()
       RETURNING id, (xmax = 0) AS inserted, severity, tool, rule_id, category, secret_type`,
      [scan.project_id, scan.id, scan.commit_sha, JSON.stringify(batch)],
    )
    out.push(...res.rows)
    await db.query(
      `INSERT INTO scan_findings (scan_id, finding_id, is_new)
       SELECT $1, unnest($2::uuid[]), false
       ON CONFLICT (scan_id, finding_id) DO NOTHING`,
      [scan.id, res.rows.map(r => r.id)],
    )
  }
  return out
}

/** Contrat 5 : sorties d'un module « ok » → résultats unifiés. */
export async function ingestModuleOutputs(db: Db, input: IngestInput): Promise<IngestOutcome> {
  const errors: IngestError[] = []
  const scan = await loadScan(db, input.scanId)
  const hints = await readModuleHints(input.moduleId, await moduleVersion(db, input.scanId, input.moduleId))
  const ctx = { moduleId: input.moduleId, moduleCategories: (input.categories ?? hints.categories).filter(c => (CATEGORIES as readonly string[]).includes(c)) }

  const parsed: ParsedFinding[] = []
  for (const kind of ['sarif', 'cyclonedx'] as const) {
    const rel = input.outputs[kind]
    if (!rel) continue
    const { doc, error } = await readOutput(input.resultDir, rel)
    if (error) {
      errors.push({ ...error, output: kind })
      continue
    }
    const out = kind === 'sarif' ? parseSarif(doc, ctx) : parseCycloneDx(doc, ctx)
    for (const issue of out.issues) errors.push({ ...issue, output: kind })
    parsed.push(...out.findings)
  }
  // Deux sorties du même module peuvent décrire le même résultat : une seule ligne.
  const unique = [...new Map(parsed.map(f => [f.fingerprint, f])).values()]

  const rows = await inTransaction(db, async (q) => {
    const severities = await resolveSeverities(q, input.moduleId, unique.map(f => f.nativeSeverity), hints.severityMap)
    const withSeverity = unique.map(f => ({ ...f, severity: severities.get(f.nativeSeverity) ?? 'medium' }))
    const res = await upsert(q, scan, withSeverity)
    // F16 (0.5, contrat 18) : clé de recoupement entre outils, sans toucher à l'empreinte G19.
    await assignCorrelationKeys(q, res.map(r => r.id))
    // G15 : sortie tronquée ou illisible consignée dans la couverture. Une sortie
    // illisible empêche aussi de déclarer « corrigés » les résultats de ce module.
    const gaps: CoverageGap[] = []
    if (errors.some(e => e.code === 'truncated')) gaps.push({ kind: 'output-truncated', module: input.moduleId })
    const unreadable = errors.find(e => UNREADABLE.has(e.code))
    if (unreadable) gaps.push({ kind: 'output-error', module: input.moduleId, code: unreadable.code })
    await mergeCoverageGaps(q, scan.id, gaps, ['output-truncated', 'output-error'], input.moduleId)
    return res
  })

  // Précalculs IA (contrat 7) : I2 explication, I3 pré-tri, I14 typage des secrets, I17 traduction.
  await enqueueFindingTasks(db, scan.project_id, rows, await moduleVersion(db, input.scanId, input.moduleId))
  return { count: rows.length, newCount: rows.filter(r => r.inserted).length, errors }
}

export interface FinalizeOutcome {
  total: number
  newCount: number
  fixedCount: number
  coverage: CoverageGap[]
}

/**
 * Contrat 5 : après le dernier module.
 * - is_new : absent de la dernière analyse réussie de la même branche (tout est
 *   nouveau au premier passage) ;
 * - complete : un résultat présent dans l'analyse réussie précédente de la même
 *   branche, d'un module qui a tourné et dont la sortie a été lue, et absent de
 *   celle-ci passe « corrigé » (sans analyse précédente, rien n'est corrigé) ;
 * - couverture (G15) dans scans.coverage.gaps.
 */
export async function finalizeScanFindings(db: Db, scanId: string, opts: { complete: boolean }): Promise<FinalizeOutcome> {
  return inTransaction(db, async (q) => {
    const scan = await loadScan(q, scanId)
    // J6 (0.6) : une analyse externe se compare seulement à la précédente du même
    // outil externe, et une analyse de l'appliance jamais à une analyse externe ;
    // sinon un téléversement rendrait « nouveaux » tous les résultats suivants.
    const prev = await q.query<{ id: string }>(
      `SELECT s.id FROM scans s, (SELECT queued_at, trigger, external_source->>'tool' AS ext_tool FROM scans WHERE id = $3) cur
        WHERE s.project_id = $1 AND s.ref = $2 AND s.id <> $3 AND s.status = 'done'
          AND s.queued_at <= cur.queued_at
          AND (s.trigger = 'external') = (cur.trigger = 'external')
          AND (cur.trigger <> 'external' OR s.external_source->>'tool' = cur.ext_tool)
        ORDER BY s.finished_at DESC NULLS LAST, s.queued_at DESC LIMIT 1`,
      [scan.project_id, scan.ref, scan.id],
    )
    const prevId = prev.rows[0]?.id ?? null
    await q.query(
      `UPDATE scan_findings sf SET is_new = ($2::uuid IS NULL OR NOT EXISTS (
              SELECT 1 FROM scan_findings p WHERE p.scan_id = $2 AND p.finding_id = sf.finding_id))
        WHERE sf.scan_id = $1`,
      [scan.id, prevId],
    )
    let fixedCount = 0
    if (opts.complete && prevId) {
      const fixed = await q.query(
        `UPDATE findings f SET status = 'fixed', status_until = NULL, status_by = NULL, status_at = now(), updated_at = now()
          WHERE f.project_id = $1
            AND (f.status IN ('new', 'confirmed') OR (f.status = 'accepted' AND f.status_until < current_date))
            AND f.tool IN (SELECT module_id FROM scan_modules WHERE scan_id = $2 AND status = 'ok')
            AND f.tool NOT IN (SELECT g->>'module' FROM scans s, jsonb_array_elements(
                  CASE WHEN jsonb_typeof(s.coverage->'gaps') = 'array' THEN s.coverage->'gaps' ELSE '[]'::jsonb END) g
                 WHERE s.id = $2 AND g->>'kind' = 'output-error')
            AND EXISTS (SELECT 1 FROM scan_findings p WHERE p.scan_id = $3 AND p.finding_id = f.id)
            AND NOT EXISTS (SELECT 1 FROM scan_findings sf WHERE sf.scan_id = $2 AND sf.finding_id = f.id)`,
        [scan.project_id, scan.id, prevId],
      )
      fixedCount = fixed.rowCount ?? 0
    }
    const counts = await q.query<{ total: string, fresh: string }>(
      'SELECT count(*) AS total, count(*) FILTER (WHERE is_new) AS fresh FROM scan_findings WHERE scan_id = $1',
      [scan.id],
    )
    const gaps = await computeCoverage(q, scan.id)
    await mergeCoverageGaps(q, scan.id, gaps, ['skipped-files', 'language-without-module', 'lockfile-missing'])
    return {
      total: Number(counts.rows[0]?.total ?? 0),
      newCount: Number(counts.rows[0]?.fresh ?? 0),
      fixedCount,
      coverage: gaps,
    }
  })
}
