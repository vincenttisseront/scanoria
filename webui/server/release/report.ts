// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Contrat 36 : rapport de release (CLAUDE.md § 7.3), en forme canonique
// (canonical.ts). buildReleaseReport(db, scanId) rend l'objet, ses octets
// canoniques et leur empreinte (report_sha256) : la signature du helper porte
// sur ces octets exactement. Contenu :
// - schema, analyse, projet, tag, commit, verdict et raisons (I9) ;
// - modules et versions exactes, empreintes d'image (G11), âge des bases ;
// - résultats par gravité et par outil ;
// - exceptions appliquées : motif, date de fin, demandeur, décideur (contrat 27) ;
// - comparaison F2 avec la release précédente ;
// - vex : référence au document VEX du chantier B (contrat 38), par empreinte ;
// - empreintes du SARIF fusionné et du SBOM CycloneDX (artifacts.ts).
// Aucun horodatage de construction : deux constructions de la même analyse
// rendent les mêmes octets. Aucune donnée IA (l'annexe I6 est à part).

import type { Queryable } from '../utils/db'
import { feedAgeDays, SEVERITIES, VerdictDetails, type Severity } from '#shared/analysis'
import { canonicalBytes, sha256Hex, toSafeJson } from './canonical'
import { compareScans, previousRelease, type CompareBucket } from './compare'
import { mergedSarif, type ReleaseArtifacts } from './artifacts'
import { sbomDocument, scanSbom } from '../sbom/ingest'
import { releaseVex } from './vex-ref'

export const REPORT_SCHEMA = 'scanoria-release-report/1'
/** Taille maximale des octets canoniques (release_reports.report, contrat 37). */
export const MAX_REPORT_BYTES = 4 * 1024 * 1024
const MAX_EXCEPTIONS = 500

export class ReleaseReportError extends Error {
  constructor(public readonly code: 'E_RELEASE_NOT_FOUND' | 'E_RELEASE_NOT_FINISHED' | 'E_RELEASE_TOO_LARGE' | 'E_RELEASE_NOT_RELEASE') {
    super(code)
  }
}

interface ScanRow {
  id: string
  number: number
  project_id: string
  project_slug: string
  project_name: string
  ref: string
  commit_sha: string | null
  trigger: string
  profile_slug: string
  status: string
  verdict: string | null
  verdict_details: unknown
  coverage: unknown
  finished_at: string | null
  tag: string | null
  tag_commit: string | null
  source: string | null
}

async function loadScan(db: Queryable, scanId: string): Promise<ScanRow | null> {
  const r = await db.query<ScanRow>(
    `SELECT s.id::text, s.number, s.project_id::text, p.slug AS project_slug, p.name AS project_name, s.ref, s.commit_sha,
            s.trigger, COALESCE(s.plan -> 'profile' ->> 'slug', pr.slug) AS profile_slug, s.status, s.verdict, s.verdict_details, s.coverage,
            to_char(s.finished_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS finished_at,
            rc.tag, rc.commit_sha AS tag_commit, rc.source
       FROM scans s JOIN projects p ON p.id = s.project_id JOIN profiles pr ON pr.id = s.profile_id
       LEFT JOIN release_candidates rc ON rc.scan_id = s.id
      WHERE s.id = $1
      ORDER BY rc.seen_at LIMIT 1`, [scanId])
  return r.rows[0] ?? null
}

function counts(): Record<Severity, number> {
  return Object.fromEntries(SEVERITIES.map(s => [s, 0])) as Record<Severity, number>
}

async function findingCounts(db: Queryable, scanId: string) {
  const r = await db.query<{ tool: string, severity: Severity, status: string, n: number }>(
    `SELECT f.tool, f.severity, f.status, count(*)::int AS n FROM scan_findings sf JOIN findings f ON f.id = sf.finding_id
      WHERE sf.scan_id = $1 GROUP BY 1, 2, 3`, [scanId])
  const total = counts()
  const open = counts()
  const byTool: Record<string, Record<Severity, number>> = {}
  const byStatus: Record<string, number> = {}
  for (const x of r.rows) {
    total[x.severity] += x.n
    if (x.status === 'new' || x.status === 'confirmed') open[x.severity] += x.n
    byTool[x.tool] ??= counts()
    byTool[x.tool]![x.severity] += x.n
    byStatus[x.status] = (byStatus[x.status] ?? 0) + x.n
  }
  return { total, open, by_tool: byTool, by_status: byStatus }
}

async function modulesOf(db: Queryable, scanId: string, at: number) {
  const r = await db.query<{ module_id: string, module_version: string, image_digest: string | null, status: string, feeds: unknown }>(
    'SELECT module_id, module_version, image_digest, status, feeds FROM scan_modules WHERE scan_id = $1 ORDER BY module_id', [scanId])
  const feeds = new Map<string, { id: string, version: string | null, updated_at: string | null, age_days: number | null }>()
  const modules = r.rows.map((m) => {
    const list = Array.isArray(m.feeds) ? m.feeds as { id?: unknown, version?: unknown, updated_at?: unknown }[] : []
    for (const f of list) {
      if (typeof f?.id !== 'string' || feeds.has(f.id)) continue
      const updated = typeof f.updated_at === 'string' ? f.updated_at : null
      feeds.set(f.id, { id: f.id, version: typeof f.version === 'string' ? f.version : null, updated_at: updated, age_days: feedAgeDays(updated, at) })
    }
    return { id: m.module_id, version: m.module_version, image_digest: m.image_digest, status: m.status, feeds: list.map(f => f?.id).filter(x => typeof x === 'string') }
  })
  return { modules, feeds: [...feeds.values()].sort((a, b) => a.id.localeCompare(b.id)) }
}

async function appliedExceptions(db: Queryable, ids: string[]) {
  if (!ids.length) return []
  const r = await db.query(
    `SELECT e.id::text, e.kind, e.target, e.reason, to_char(e.expires_on, 'YYYY-MM-DD') AS expires_on, e.status, e.vex_status,
            e.requested_via, COALESCE(cu.username, e.requester_label) AS requested_by, e.requester_is_human,
            du.username AS decided_by, to_char(e.decided_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS decided_at
       FROM exceptions e LEFT JOIN users cu ON cu.id = e.created_by LEFT JOIN users du ON du.id = e.decided_by
      WHERE e.id = ANY($1::uuid[]) ORDER BY e.id LIMIT ${MAX_EXCEPTIONS}`, [ids])
  return r.rows
}

/** Une ligne de comparaison sans le détail des titres (le rapport reste borné). */
function compact(b: CompareBucket) {
  return { total: b.total, by_severity: b.by_severity, by_tool: b.by_tool, findings: b.items.map(f => ({ id: f.id, fingerprint: f.fingerprint, tool: f.tool, rule_id: f.rule_id, severity: f.severity })) }
}

async function artifactsInMemory(db: Queryable, scan: ScanRow): Promise<ReleaseArtifacts> {
  const sarif = await mergedSarif(db, scan.id)
  const rows = await scanSbom(db, scan.id)
  return {
    sarif_sha256: sha256Hex(canonicalBytes(toSafeJson(sarif.doc))),
    sarif_truncated: sarif.truncated,
    sbom_sha256: rows.length ? sha256Hex(canonicalBytes(toSafeJson(sbomDocument(rows, { scanId: scan.id, project: scan.project_name, createdAt: scan.finished_at })))) : null,
    sbom_components: rows.length,
  }
}

export interface BuiltReport {
  report: Record<string, unknown>
  bytes: Buffer
  sha256: string
  tag: string
  commitSha: string
  previousScanId: string | null
}

export interface BuildOptions {
  /** Empreintes des fichiers déjà rangés (sinon recalculées en mémoire). */
  artifacts?: ReleaseArtifacts
  /** Release de comparaison choisie (F2) ; sinon la précédente, trouvée seule. */
  previousScanId?: string | null
}

/** Contrat 36. Lève ReleaseReportError si l'analyse n'est pas une release terminée. */
export async function buildReleaseReport(db: Queryable, scanId: string, opts: BuildOptions = {}): Promise<BuiltReport> {
  const scan = await loadScan(db, scanId)
  if (!scan) throw new ReleaseReportError('E_RELEASE_NOT_FOUND')
  if (!scan.tag || scan.trigger !== 'release') throw new ReleaseReportError('E_RELEASE_NOT_RELEASE')
  if (!scan.verdict || !scan.finished_at) throw new ReleaseReportError('E_RELEASE_NOT_FINISHED')
  const commit = scan.commit_sha ?? scan.tag_commit!
  const details = VerdictDetails.safeParse(scan.verdict_details)
  const at = Date.parse(scan.finished_at)
  const { modules, feeds } = await modulesOf(db, scan.id, at)
  const previous = opts.previousScanId === undefined
    ? await previousRelease(db, scan.project_id, scan.id, scan.tag)
    : opts.previousScanId
      ? (await db.query<{ scan_id: string, tag: string, commit_sha: string }>(
          'SELECT scan_id::text, tag, commit_sha FROM release_reports WHERE scan_id = $1 AND project_id = $2', [opts.previousScanId, scan.project_id])).rows[0] ?? null
      : null
  const comparison = previous ? await compareScans(db, previous.scan_id, scan.id) : null
  const vex = await releaseVex(db, scan.project_id, scan.id)
  const artifacts = opts.artifacts ?? await artifactsInMemory(db, scan)
  const coverage = (scan.coverage && typeof scan.coverage === 'object') ? scan.coverage as Record<string, unknown> : {}
  const report = toSafeJson({
    schema: REPORT_SCHEMA,
    scan_id: scan.id,
    scan_number: scan.number,
    project: { id: scan.project_id, slug: scan.project_slug, name: scan.project_name },
    tag: scan.tag,
    commit_sha: commit,
    source: scan.source,
    profile: scan.profile_slug,
    finished_at: scan.finished_at,
    verdict: {
      value: scan.verdict,
      gate_id: details.success ? details.data.gate_id : null,
      rules: details.success ? details.data.rules : null,
      evaluated_at: details.success ? details.data.evaluated_at : null,
      new_code_only: details.success ? details.data.new_code_only : null,
      counts: details.success ? details.data.counts : null,
      reasons: details.success ? details.data.reasons : [],
    },
    modules,
    feeds,
    findings: await findingCounts(db, scan.id),
    coverage: { gaps: Array.isArray(coverage.gaps) ? coverage.gaps : [] },
    exceptions: await appliedExceptions(db, details.success ? details.data.exceptions_applied.map(e => e.id) : []),
    comparison: comparison && previous
      ? { previous: { scan_id: previous.scan_id, tag: previous.tag, commit: previous.commit_sha }, introduced: compact(comparison.introduced), fixed: compact(comparison.fixed), unchanged: { total: comparison.unchanged.total, by_severity: comparison.unchanged.by_severity } }
      : null,
    vex,
    artifacts: {
      sarif: { name: 'results.sarif', sha256: artifacts.sarif_sha256, truncated: artifacts.sarif_truncated },
      sbom: artifacts.sbom_sha256 ? { name: 'sbom.cdx.json', sha256: artifacts.sbom_sha256, components: artifacts.sbom_components } : null,
    },
  }) as Record<string, unknown>
  const bytes = canonicalBytes(report)
  if (bytes.length > MAX_REPORT_BYTES) throw new ReleaseReportError('E_RELEASE_TOO_LARGE')
  return { report, bytes, sha256: sha256Hex(bytes), tag: scan.tag, commitSha: commit, previousScanId: previous?.scan_id ?? null }
}
