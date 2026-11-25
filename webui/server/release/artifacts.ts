// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Fichiers d'une release (§ 7.3) : SARIF 2.1.0 fusionné (un « run » par
// outil) et SBOM CycloneDX de l'analyse. Produits une fois, à la création du
// rapport, en forme canonique, puis rangés sur disque (releasesDir/<scan>/) :
// leur empreinte, inscrite dans le rapport signé, reste vraie même si les
// résultats changent ensuite de statut. Jamais la valeur d'un secret (§ 6.3).

import { mkdir, readFile, rename, writeFile } from 'node:fs/promises'
import { join } from 'node:path'
import type { Queryable } from '../utils/db'
import { sbomDocument, scanSbom } from '../sbom/ingest'
import { canonicalBytes, sha256Hex, toSafeJson } from './canonical'

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/
export const ARTIFACT_NAMES = ['report.json', 'results.sarif', 'sbom.cdx.json', 'notes.md'] as const
export type ArtifactName = (typeof ARTIFACT_NAMES)[number]
export const MAX_SARIF_RESULTS = 20_000

/** Dossier des fichiers de releases de la console (surchargeable en test). */
export function releasesDir(): string {
  return process.env.NUXT_RELEASES_DIR || '/var/lib/scanoria/console/releases'
}

function scanDir(scanId: string, dir = releasesDir()): string {
  if (!UUID_RE.test(scanId)) throw new Error('invalid scan id')
  return join(dir, scanId)
}

/** Écrit atomiquement un fichier de la release (0640). */
export async function writeArtifact(scanId: string, name: ArtifactName, data: Buffer | string, dir = releasesDir()): Promise<void> {
  const d = scanDir(scanId, dir)
  await mkdir(d, { recursive: true, mode: 0o750 })
  const tmp = join(d, `.${name}.${process.pid}.tmp`)
  await writeFile(tmp, data, { mode: 0o640 })
  await rename(tmp, join(d, name))
}

export async function readArtifact(scanId: string, name: ArtifactName, dir = releasesDir()): Promise<Buffer | null> {
  try {
    return await readFile(join(scanDir(scanId, dir), name))
  }
  catch {
    return null
  }
}

const LEVEL: Record<string, 'error' | 'warning' | 'note'> = { critical: 'error', high: 'error', medium: 'warning', low: 'note', info: 'note' }

interface SarifRow {
  tool: string
  rule_id: string
  severity: string
  title: string
  message: string | null
  path: string | null
  start_line: number | null
  end_line: number | null
  fingerprint: string
  cwe: string[]
  vuln_ids: string[]
  status: string
  category: string
  secret_type: string | null
}

/** SARIF 2.1.0 fusionné de l'analyse ; les modules et versions viennent de scan_modules. */
export async function mergedSarif(db: Queryable, scanId: string): Promise<{ doc: Record<string, unknown>, truncated: boolean }> {
  const mods = await db.query<{ module_id: string, module_version: string }>(
    'SELECT module_id, module_version FROM scan_modules WHERE scan_id = $1', [scanId])
  const versions = new Map(mods.rows.map(m => [m.module_id, m.module_version]))
  const r = await db.query<SarifRow>(
    `SELECT f.tool, f.rule_id, f.severity, f.title, f.message, f.path, f.start_line, f.end_line, f.fingerprint,
            f.cwe, f.vuln_ids, f.status, f.category, f.secret_type
       FROM scan_findings sf JOIN findings f ON f.id = sf.finding_id
      WHERE sf.scan_id = $1
      ORDER BY f.tool, f.rule_id, f.path NULLS FIRST, f.start_line NULLS FIRST, f.fingerprint
      LIMIT $2`, [scanId, MAX_SARIF_RESULTS + 1])
  const truncated = r.rows.length > MAX_SARIF_RESULTS
  const byTool = new Map<string, SarifRow[]>()
  for (const f of r.rows.slice(0, MAX_SARIF_RESULTS)) {
    if (!byTool.has(f.tool)) byTool.set(f.tool, [])
    byTool.get(f.tool)!.push(f)
  }
  const runs = [...byTool].map(([tool, list]) => ({
    tool: {
      driver: {
        name: tool,
        ...(versions.get(tool) ? { version: versions.get(tool) } : {}),
        rules: [...new Set(list.map(f => f.rule_id))].map(id => ({ id })),
      },
    },
    results: list.map(f => ({
      ruleId: f.rule_id,
      level: LEVEL[f.severity] ?? 'note',
      // Titre et message seulement : un secret n'a jamais sa valeur en base.
      message: { text: f.message ? `${f.title}\n\n${f.message}` : f.title },
      ...(f.path
        ? { locations: [{ physicalLocation: { artifactLocation: { uri: f.path }, ...(f.start_line ? { region: { startLine: f.start_line, ...(f.end_line && f.end_line >= f.start_line ? { endLine: f.end_line } : {}) } } : {}) } }] }
        : {}),
      partialFingerprints: { 'scanoria/v1': f.fingerprint },
      properties: {
        'scanoria/severity': f.severity,
        'scanoria/status': f.status,
        'scanoria/category': f.category,
        ...(f.cwe.length ? { 'scanoria/cwe': f.cwe } : {}),
        ...(f.vuln_ids.length ? { 'scanoria/vulnerabilities': f.vuln_ids } : {}),
        ...(f.secret_type ? { 'scanoria/secret-type': f.secret_type } : {}),
      },
    })),
  }))
  return {
    doc: {
      $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
      version: '2.1.0',
      runs,
      ...(truncated ? { properties: { 'scanoria/truncated': true } } : {}),
    },
    truncated,
  }
}

export interface ReleaseArtifacts {
  sarif_sha256: string
  sarif_truncated: boolean
  sbom_sha256: string | null
  sbom_components: number
}

/** Produit et range le SARIF fusionné et le SBOM ; rend leurs empreintes pour le rapport. */
export async function writeReleaseArtifacts(db: Queryable, scan: { id: string, project_name: string, finished_at: string | null }, dir = releasesDir()): Promise<ReleaseArtifacts> {
  const sarif = await mergedSarif(db, scan.id)
  const sarifBytes = canonicalBytes(toSafeJson(sarif.doc))
  await writeArtifact(scan.id, 'results.sarif', sarifBytes, dir)
  const rows = await scanSbom(db, scan.id)
  let sbomSha: string | null = null
  if (rows.length) {
    const sbomBytes = canonicalBytes(toSafeJson(sbomDocument(rows, { scanId: scan.id, project: scan.project_name, createdAt: scan.finished_at })))
    await writeArtifact(scan.id, 'sbom.cdx.json', sbomBytes, dir)
    sbomSha = sha256Hex(sbomBytes)
  }
  return { sarif_sha256: sha256Hex(sarifBytes), sarif_truncated: sarif.truncated, sbom_sha256: sbomSha, sbom_components: rows.length }
}
