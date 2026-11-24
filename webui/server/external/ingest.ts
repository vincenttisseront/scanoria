// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// J6 (contrat 26 de la 0.6) : résultats produits ailleurs (outil interne,
// outil commercial lancé en CI), téléversés en SARIF 2.1.0 ou CycloneDX
// 1.5 / 1.6. Le document est lu en flux avec une taille bornée, détecté,
// validé en entier (G2) AVANT toute écriture : un document invalide est refusé
// avec la liste de ses défauts, jamais ingéré à moitié. Puis :
//   - une analyse trigger = 'external', external_source {tool, version, format,
//     uploaded_via}, module ext-<outil> (scan_modules), sans plan : elle ne se
//     rejoue pas (G11 : rien à relancer) ;
//   - les résultats passent par l'ingestion commune (contrat 5 : gravités G5,
//     défaut medium pour un outil inconnu, empreintes G19, recoupement F16,
//     tâches IA), avec origin = 'external' ;
//   - un SBOM CycloneDX remplit sbom_components (contrat 14), visible par F3 ;
//   - le quality gate est évalué comme pour toute analyse. Ce n'est pas un
//     verdict de release (seul le profil release en produit un) et aucun statut
//     de commit n'est publié ;
//   - jamais de cache V4 : l'analyse ne passe ni par le runner ni par le cache.

import { mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import type { Readable } from 'node:stream'
import type pg from 'pg'
import { CATEGORIES, COMMIT_RE, VerdictDetails, type Category } from '#shared/analysis'
import { parseCycloneDx, parseSarif, type ParseIssue } from '../findings/parse'
import { finalizeScanFindings, ingestModuleOutputs } from '../findings/ingest'
import { parseSbom, ingestSbom, SbomError } from '../sbom/ingest'
import { evaluateGate } from '../gates/evaluate'
import { gitRef } from '../scans/contract'

/** Taille maximale d'un document téléversé (lu en flux, refusé au-delà). */
export const EXTERNAL_MAX_BYTES = 32 * 1024 * 1024
export const EXTERNAL_FORMATS = ['sarif', 'cyclonedx'] as const
export type ExternalFormat = (typeof EXTERNAL_FORMATS)[number]
/** Priorité d'une analyse externe : elle n'occupe pas la file, l'ingestion est immédiate. */
export const EXTERNAL_PRIORITY = 50
const MODULE_PREFIX = 'ext-'
const MAX_ISSUES = 20
const CDX_VERSIONS = ['1.5', '1.6']

export type ExternalErrorCode
  = | 'E_EXTERNAL_TOO_LARGE' | 'E_EXTERNAL_JSON' | 'E_EXTERNAL_FORMAT' | 'E_EXTERNAL_INVALID'
    | 'E_EXTERNAL_TOO_MANY' | 'E_EXTERNAL_TOOL' | 'E_EXTERNAL_REF' | 'E_EXTERNAL_UPLOAD'

export interface DocumentIssue { path: string, code: string, detail?: string }

export class ExternalError extends Error {
  constructor(readonly code: ExternalErrorCode, readonly status: number, readonly issues: DocumentIssue[] = []) {
    super(code)
    this.name = 'ExternalError'
  }
}

/** Lit un corps en flux, refusé dès qu'il dépasse max (en-tête content-length compris). */
export async function readBoundedBody(body: Readable, declaredLength: number | null, max = EXTERNAL_MAX_BYTES): Promise<Buffer> {
  if (declaredLength !== null && declaredLength > max) throw new ExternalError('E_EXTERNAL_TOO_LARGE', 413)
  const chunks: Buffer[] = []
  let size = 0
  try {
    for await (const chunk of body) {
      const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk as string)
      size += buf.length
      if (size > max) {
        body.destroy()
        throw new ExternalError('E_EXTERNAL_TOO_LARGE', 413)
      }
      chunks.push(buf)
    }
  }
  catch (err) {
    if (err instanceof ExternalError) throw err
    throw new ExternalError('E_EXTERNAL_UPLOAD', 400)
  }
  return Buffer.concat(chunks, size)
}

export function parseJson(buf: Buffer): unknown {
  if (!buf.length) throw new ExternalError('E_EXTERNAL_JSON', 400, [{ path: '', code: 'empty' }])
  try {
    // BOM UTF-8 toléré (fichiers produits sous Windows).
    return JSON.parse(buf.toString('utf8').replace(/^\uFEFF/, ''))
  }
  catch (err) {
    throw new ExternalError('E_EXTERNAL_JSON', 400, [{ path: '', code: 'invalid-json', detail: String((err as Error).message).slice(0, 200) }])
  }
}

type Obj = Record<string, unknown>
const isObj = (v: unknown): v is Obj => !!v && typeof v === 'object' && !Array.isArray(v)
const str = (v: unknown): string | null => (typeof v === 'string' && v.trim() ? v.trim() : null)

export interface DetectedSource {
  format: ExternalFormat
  /** 2.1.0 (SARIF), 1.5 ou 1.6 (CycloneDX). */
  formatVersion: string
  tool: string
  version: string | null
}

/** Nom d'outil → identifiant de module ext-<slug> (MODULE_ID_RE), ou null. */
export function externalModuleId(tool: string): string | null {
  const slug = tool.normalize('NFKD').replace(/[̀-ͯ]/g, '').toLowerCase()
    .replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 36).replace(/-+$/, '')
  return slug.length >= 1 ? `${MODULE_PREFIX}${slug}` : null
}

function cdxTool(doc: Obj): { name: string | null, version: string | null } {
  const tools = isObj(doc.metadata) ? doc.metadata.tools : undefined
  // CycloneDX 1.5+ : {components: [...], services: [...]} ; forme héritée : tableau.
  const list = Array.isArray(tools) ? tools : isObj(tools) ? [...(Array.isArray(tools.components) ? tools.components : []), ...(Array.isArray(tools.services) ? tools.services : [])] : []
  const first = list.find(isObj)
  return { name: first ? str(first.name) : null, version: first ? str(first.version) : null }
}

/**
 * Format et outil du document, avec les défauts de structure qui le rendent
 * invalide (G2) : SARIF 2.1.0 (version, runs, tool.driver.name, results,
 * message de chaque résultat) ou CycloneDX 1.5 / 1.6 (bomFormat, specVersion,
 * components, vulnerabilities). Un seul outil par document.
 */
export function detectDocument(doc: unknown, override?: { tool?: string | null, version?: string | null }): { source: DetectedSource, issues: DocumentIssue[] } {
  if (!isObj(doc)) throw new ExternalError('E_EXTERNAL_FORMAT', 415, [{ path: '', code: 'not-an-object' }])
  const issues: DocumentIssue[] = []
  const push = (path: string, code: string, detail?: string) => {
    if (issues.length < MAX_ISSUES) issues.push(detail ? { path, code, detail } : { path, code })
  }
  if (doc.bomFormat === 'CycloneDX') {
    const spec = str(doc.specVersion) ?? ''
    if (!CDX_VERSIONS.includes(spec)) push('/specVersion', 'unsupported-version', spec || 'absent')
    if (doc.components !== undefined && !Array.isArray(doc.components)) push('/components', 'not-an-array')
    if (doc.vulnerabilities !== undefined) {
      if (!Array.isArray(doc.vulnerabilities)) push('/vulnerabilities', 'not-an-array')
      else {
        doc.vulnerabilities.forEach((v, i) => {
          if (!isObj(v) || !str(v.id)) push(`/vulnerabilities/${i}/id`, 'required')
        })
      }
    }
    const t = cdxTool(doc)
    const tool = str(override?.tool) ?? t.name ?? 'cyclonedx'
    return { source: { format: 'cyclonedx', formatVersion: spec, tool, version: str(override?.version) ?? t.version }, issues }
  }
  const looksSarif = doc.version !== undefined || doc.runs !== undefined || (typeof doc.$schema === 'string' && /sarif/i.test(doc.$schema))
  if (!looksSarif) throw new ExternalError('E_EXTERNAL_FORMAT', 415, [{ path: '', code: 'unknown-format' }])
  if (doc.version !== '2.1.0') push('/version', 'unsupported-version', str(doc.version) ?? 'absent')
  const names = new Set<string>()
  let version: string | null = null
  if (!Array.isArray(doc.runs) || !doc.runs.length) push('/runs', 'required')
  else {
    if (doc.runs.length > 32) push('/runs', 'too-many', String(doc.runs.length))
    doc.runs.slice(0, 32).forEach((run, i) => {
      const driver = isObj(run) && isObj(run.tool) && isObj(run.tool.driver) ? run.tool.driver : null
      const name = driver ? str(driver.name) : null
      if (!name) push(`/runs/${i}/tool/driver/name`, 'required')
      else {
        names.add(name.toLowerCase())
        version ??= str(driver!.semanticVersion) ?? str(driver!.version)
      }
      const results = isObj(run) ? run.results : undefined
      if (results !== undefined && results !== null && !Array.isArray(results)) push(`/runs/${i}/results`, 'not-an-array')
      if (Array.isArray(results)) {
        results.forEach((r, j) => {
          if (!isObj(r)) push(`/runs/${i}/results/${j}`, 'not-an-object')
          else if (!isObj(r.message) || (!str(r.message.text) && !str(r.message.id) && !str(r.message.markdown))) push(`/runs/${i}/results/${j}/message`, 'required')
        })
      }
    })
  }
  if (names.size > 1 && !override?.tool) push('/runs', 'mixed-tools', [...names].slice(0, 5).join(', '))
  const first = Array.isArray(doc.runs) && isObj(doc.runs[0]) && isObj(doc.runs[0].tool) && isObj(doc.runs[0].tool.driver) ? str(doc.runs[0].tool.driver.name) : null
  const tool = str(override?.tool) ?? first ?? 'sarif'
  return { source: { format: 'sarif', formatVersion: '2.1.0', tool, version: str(override?.version) ?? version }, issues }
}

const issueOf = (i: ParseIssue): DocumentIssue => ({ path: '', code: i.code, ...(i.detail ? { detail: i.detail } : {}) })

export interface ExternalInput {
  projectId: string
  doc: unknown
  /** Référence analysée (branche, tag) ; défaut : branche par défaut du projet, sinon « external ». */
  ref?: string | null
  commit?: string | null
  tool?: string | null
  version?: string | null
  /** Catégorie des résultats d'un SARIF sans indication (défaut sast) ; les étiquettes du document l'emportent. */
  category?: Category | null
  uploadedVia: 'api-token' | 'console'
  requestedBy?: number | null
  apiTokenId?: string | null
}

export interface ExternalOutcome {
  scanId: string
  number: number
  moduleId: string
  source: { tool: string, version: string | null, format: ExternalFormat, uploaded_via: 'api-token' | 'console' }
  count: number
  newCount: number
  components: number | null
  verdict: VerdictDetails['verdict']
}

/** Valide entièrement le document, puis l'ingère (voir l'en-tête). Lève ExternalError. */
export async function ingestExternal(db: pg.Pool, input: ExternalInput): Promise<ExternalOutcome> {
  if (input.commit != null && !COMMIT_RE.test(input.commit)) throw new ExternalError('E_EXTERNAL_REF', 400, [{ path: 'commit', code: 'invalid' }])
  const { source, issues } = detectDocument(input.doc, { tool: input.tool, version: input.version })
  const moduleId = externalModuleId(source.tool)
  if (!moduleId) throw new ExternalError('E_EXTERNAL_TOOL', 400, [{ path: '/tool', code: 'invalid', detail: source.tool.slice(0, 80) }])
  const categories = source.format === 'cyclonedx' ? ['sca', 'sbom'] : [input.category ?? 'sast']
  const ctx = { moduleId, moduleCategories: categories.filter(c => (CATEGORIES as readonly string[]).includes(c)) }
  // G2 : validation complète avant toute écriture.
  const parsed = source.format === 'sarif' ? parseSarif(input.doc, ctx) : parseCycloneDx(input.doc, ctx)
  if (parsed.issues.some(i => i.code === 'truncated')) throw new ExternalError('E_EXTERNAL_TOO_MANY', 413, parsed.issues.filter(i => i.code === 'truncated').map(issueOf))
  const all = [...issues, ...parsed.issues.map(issueOf)].slice(0, MAX_ISSUES)
  let components: number | null = null
  if (source.format === 'cyclonedx' && Array.isArray((input.doc as Obj).components)) {
    try {
      components = parseSbom(input.doc).components.length
    }
    catch (err) {
      if (err instanceof SbomError) {
        if (err.code === 'too-many-components') throw new ExternalError('E_EXTERNAL_TOO_MANY', 413, [{ path: '/components', code: err.code }])
        all.push({ path: '/components', code: err.code, detail: err.message.slice(0, 200) })
      }
      else throw err
    }
  }
  if (all.length) throw new ExternalError('E_EXTERNAL_INVALID', 422, all.slice(0, MAX_ISSUES))

  const ext = { tool: source.tool.slice(0, 120), version: source.version?.slice(0, 64) ?? null, format: source.format, uploaded_via: input.uploadedVia }
  const { scanId, number } = await createExternalScan(db, input, moduleId, ext)
  const dir = await mkdtemp(join(tmpdir(), 'scanoria-external-'))
  try {
    const file = source.format === 'sarif' ? 'result.sarif' : 'result.cdx.json'
    await writeFile(join(dir, file), JSON.stringify(input.doc), { mode: 0o600 })
    const out = await ingestModuleOutputs(db, { scanId, moduleId, resultDir: dir, outputs: source.format === 'sarif' ? { sarif: file } : { cyclonedx: file }, categories: ctx.moduleCategories })
    const { count, newCount } = out
    await db.query(
      `UPDATE findings f SET origin = 'external'
         FROM scan_findings sf WHERE sf.scan_id = $1 AND sf.finding_id = f.id AND f.tool = $2 AND f.origin <> 'external'`,
      [scanId, moduleId])
    if (components !== null) await ingestSbom(db, { scanId, projectId: input.projectId, doc: input.doc, moduleId })
    await db.query(
      `UPDATE scan_modules SET status = 'ok', results_count = $3, finished_at = now(),
              duration_ms = GREATEST(0, (extract(epoch FROM now() - started_at) * 1000)::int)
        WHERE scan_id = $1 AND module_id = $2`, [scanId, moduleId, count])
    await finalizeScanFindings(db, scanId, { complete: true })
    const details = VerdictDetails.parse(await evaluateGate(db, scanId))
    await db.query(
      `UPDATE scans SET status = 'done', verdict = $2, verdict_details = $3, finished_at = now()
        WHERE id = $1 AND status = 'ingesting'`, [scanId, details.verdict, JSON.stringify(details)])
    return { scanId, number, moduleId, source: ext, count, newCount, components, verdict: details.verdict }
  }
  catch (err) {
    // Échec après création : l'analyse est close en erreur, jamais laissée « en cours ».
    await db.query(
      `UPDATE scans SET status = 'error', error = $2, finished_at = now() WHERE id = $1 AND status = 'ingesting'`,
      [scanId, JSON.stringify({ code: 'E_EXTERNAL_INGEST', class: 'infra', message: 'external results could not be ingested' })]).catch(() => {})
    await db.query(`UPDATE scan_modules SET status = 'error', error_class = 'infra', finished_at = now() WHERE scan_id = $1`, [scanId]).catch(() => {})
    throw err
  }
  finally {
    await rm(dir, { recursive: true, force: true }).catch(() => {})
  }
}

async function createExternalScan(
  db: pg.Pool, input: ExternalInput, moduleId: string, ext: ExternalOutcome['source'],
): Promise<{ scanId: string, number: number }> {
  const client = await db.connect()
  try {
    await client.query('BEGIN')
    const p = await client.query<{ id: string, profile_id: string, gate_id: string, default_branch: string | null, archived: boolean, source_kind: string }>(
      `SELECT id, profile_id, gate_id, default_branch, archived_at IS NOT NULL AS archived, source_kind
         FROM projects WHERE id = $1 FOR UPDATE`, [input.projectId])
    const project = p.rows[0]
    if (!project) throw new ExternalError('E_EXTERNAL_REF', 404)
    const ref = input.ref ?? (project.source_kind === 'archive' ? 'archive' : project.default_branch) ?? 'external'
    if (!gitRef.safeParse(ref).success && ref !== 'archive') throw new ExternalError('E_EXTERNAL_REF', 400, [{ path: 'ref', code: 'invalid' }])
    const ins = await client.query<{ id: string, number: number }>(
      `INSERT INTO scans (project_id, number, trigger, priority, ref, commit_sha, profile_id, gate_id, plan, status,
                          requested_by, api_token_id, external_source, started_at)
       VALUES ($1, (SELECT COALESCE(max(number), 0) + 1 FROM scans WHERE project_id = $1), 'external', $2, $3, $4, $5, $6,
               NULL, 'ingesting', $7, $8, $9, now())
       RETURNING id, number`,
      [project.id, EXTERNAL_PRIORITY, ref, input.commit ?? null, project.profile_id, project.gate_id,
        input.requestedBy ?? null, input.apiTokenId ?? null, JSON.stringify(ext)])
    const scanId = ins.rows[0]!.id
    await client.query(
      `INSERT INTO scan_modules (scan_id, module_id, module_version, status, attempts, started_at)
       VALUES ($1, $2, $3, 'running', 1, now())`, [scanId, moduleId, ext.version ?? 'external'])
    await client.query('COMMIT')
    return { scanId, number: ins.rows[0]!.number }
  }
  catch (err) {
    await client.query('ROLLBACK').catch(() => {})
    throw err
  }
  finally {
    client.release()
  }
}
