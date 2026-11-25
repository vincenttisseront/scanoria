// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// H7, VEX (contrat 38) :
// - génération automatique : chaque exception APPROUVÉE, en vigueur, qui porte
//   un vex_status donne une déclaration par produit concerné (purl du
//   composant, tiré du SBOM du projet, sinon du paquet du résultat). La
//   justification vient du motif (marque « [justification] » en tête, posée
//   par l'import ou par I10), le texte du motif devient la déclaration
//   d'impact ou d'action. syncExceptionVex matérialise ces déclarations dans
//   vex_statements à l'approbation et les révoque (revoked_at) à la
//   révocation de l'exception ; une exception échue cesse d'elle-même d'en
//   produire ;
// - buildVex rend le document OpenVEX 0.2 canonique d'un projet ou d'une
//   analyse (vulnérabilités vues par l'analyse) : A le joint au rapport de
//   release et en cite l'empreinte ;
// - exportVex : OpenVEX ou CycloneDX 1.6, mêmes déclarations ;
// - importVex : document hostile lu strictement (format.ts), aperçu des
//   effets, puis chaque déclaration not_affected ou fixed devient une DEMANDE
//   d'exception (contrat 27, requested_via « tool-import »), jamais une
//   approbation ; les autres statuts sont gardés pour information
//   (vex_statements, source « import »). Aucune demande pour un avis MAL-
//   (H4) ni contre un verrou (G8) : requestException les refuse.

import { z } from 'zod'
import type { Queryable } from '../utils/db'
import { writeAudit } from '../utils/audit'
import { ExceptionError, isoDay, isValidDay, MAX_EXCEPTION_DAYS, requestException } from '../findings/exceptions'
import { parsePurl } from '../findings/normalize'
import { activeException, EXCEPTION_COLUMNS, ISO, statementsOfException, type ExceptionVexRow } from './sync'
import {
  canonicalJson, dedupeStatements, parseVexDocument, renderCycloneDxVex, renderOpenVex,
  sha256Hex, sortStatements, VEX_LIMITS, VexFormatError,
  type VexJustification, type VexStatement, type VexStatus,
} from './format'

/** Corps de POST /api/vex/projects/:id/import (repris par l'OpenAPI). */
export const vexImportSchema = z.strictObject({
  document: z.string().min(2).max(VEX_LIMITS.maxBytes),
  dry_run: z.boolean().default(true),
  expires_on: z.string().refine(isValidDay).optional(),
})

/** Durée par défaut d'une demande d'exception créée par un import. */
export const IMPORT_DEFAULT_DAYS = 90

interface StatementRow {
  vuln_id: string
  product: string
  status: VexStatus
  justification: VexJustification | null
  impact_statement: string | null
  action_statement: string | null
  created_at: Date
}

/** Déclarations en vigueur d'un projet, éventuellement limitées aux vulnérabilités vues par une analyse. */
export async function activeStatements(db: Queryable, projectId: string, scanId?: string | null): Promise<VexStatement[]> {
  // Déclarations enregistrées : importées, ou tirées d'une exception encore en vigueur.
  const rows = await db.query<StatementRow>(
    `SELECT v.vuln_id, v.product, v.status, v.justification, v.impact_statement, v.action_statement, v.created_at
       FROM vex_statements v LEFT JOIN exceptions e ON e.id = v.exception_id
      WHERE v.project_id = $1 AND v.revoked_at IS NULL
        AND (v.source = 'import' OR (${activeException('e')}))`,
    [projectId])
  const list: VexStatement[] = rows.rows.map(r => ({
    vuln_id: r.vuln_id, product: r.product, status: r.status, justification: r.justification,
    impact_statement: r.impact_statement, action_statement: r.action_statement, timestamp: ISO(r.created_at),
  }))
  // Exceptions approuvées avec vex_status pas encore matérialisées (approuvées avant la 0.8, par exemple).
  const pending = await db.query<ExceptionVexRow>(
    `SELECT ${EXCEPTION_COLUMNS} FROM exceptions x
      WHERE x.project_id = $1 AND ${activeException('x')}
        AND NOT EXISTS (SELECT 1 FROM vex_statements v WHERE v.exception_id = x.id AND v.revoked_at IS NULL)
      ORDER BY x.decided_at LIMIT 1000`, [projectId])
  for (const e of pending.rows) list.push(...await statementsOfException(db, e))
  let out = dedupeStatements(list)
  if (scanId) {
    const seen = await db.query<{ v: string }>(
      `SELECT DISTINCT upper(v) AS v FROM scan_findings sf JOIN findings f ON f.id = sf.finding_id, unnest(f.vuln_ids) v
        WHERE sf.scan_id = $1 AND f.project_id = $2`, [scanId, projectId])
    const ids = new Set(seen.rows.map(r => r.v))
    out = out.filter(s => ids.has(s.vuln_id.toUpperCase()))
  }
  return out
}

export class VexError extends Error {
  constructor(public code: 'E_NOT_FOUND' | 'E_VALIDATION', public detail: string | null = null) {
    super(code)
  }
}

async function documentTime(db: Queryable, projectId: string, scanId: string | null | undefined, statements: VexStatement[]): Promise<string> {
  if (scanId) {
    const s = await db.query<{ at: Date | null }>('SELECT coalesce(finished_at, queued_at) AS at FROM scans WHERE id = $1 AND project_id = $2', [scanId, projectId])
    if (!s.rows[0]) throw new VexError('E_NOT_FOUND', 'scan')
    if (s.rows[0].at) return ISO(s.rows[0].at)
  }
  const latest = statements.reduce<string>((m, s) => (s.timestamp > m ? s.timestamp : m), '')
  return latest || '1970-01-01T00:00:00Z'
}

export interface BuiltVex {
  /** Document OpenVEX 0.2. */
  document: Record<string, unknown>
  /** Forme canonique (octets dont sha256 est l'empreinte). */
  canonical: string
  sha256: string
  statements: VexStatement[]
}

async function checkProject(db: Queryable, projectId: string): Promise<void> {
  if (!(await db.query('SELECT 1 FROM projects WHERE id = $1', [projectId])).rowCount) throw new VexError('E_NOT_FOUND', 'project')
}

/**
 * Contrat 38 : document OpenVEX 0.2 canonique d'un projet (ou des
 * vulnérabilités vues par une analyse). Lecture seule. Un document sans
 * déclaration reste valide pour le rapport de release, qui cite son empreinte.
 */
export async function buildVex(db: Queryable, projectId: string, opts: { scanId?: string | null } = {}): Promise<BuiltVex> {
  await checkProject(db, projectId)
  const statements = await activeStatements(db, projectId, opts.scanId)
  const timestamp = await documentTime(db, projectId, opts.scanId, statements)
  const { document, canonical } = renderOpenVex({ statements, timestamp })
  // OpenVEX exige au moins une déclaration : un document vide n'en porte aucune et n'est pas exporté comme fichier.
  return { document, canonical, sha256: sha256Hex(canonical), statements }
}

export type VexExportFormat = 'openvex' | 'cyclonedx'

export interface VexExport {
  body: string
  sha256: string
  contentType: string
  filename: string
  count: number
}

/** Export par projet ou par analyse, en forme canonique. */
export async function exportVex(db: Queryable, projectId: string, opts: { scanId?: string | null, format: VexExportFormat }): Promise<VexExport> {
  const built = await buildVex(db, projectId, { scanId: opts.scanId })
  const slug = (await db.query<{ slug: string }>('SELECT slug FROM projects WHERE id = $1', [projectId])).rows[0]!.slug
  const timestamp = built.document.timestamp as string
  const body = opts.format === 'cyclonedx' ? renderCycloneDxVex({ statements: built.statements, timestamp }).canonical : built.canonical
  return {
    body,
    sha256: sha256Hex(body),
    contentType: opts.format === 'cyclonedx' ? 'application/vnd.cyclonedx+json' : 'application/json',
    filename: `${slug}${opts.scanId ? '-scan' : ''}.${opts.format === 'cyclonedx' ? 'cdx.vex' : 'openvex'}.json`,
    count: built.statements.length,
  }
}

// ---------------------------------------------------------------- import

export type ImportAction = 'request' | 'store' | 'duplicate' | 'refused'

export interface ImportEffect {
  vuln_id: string
  product: string
  status: VexStatus
  justification: VexJustification | null
  /** request : demande d'exception ; store : gardée pour information ; duplicate : déjà présente ; refused : H4, verrou, validation. */
  action: ImportAction
  reason?: string
  exception_id?: string
}

export interface ImportResult {
  format: 'openvex' | 'cyclonedx'
  dry_run: boolean
  effects: ImportEffect[]
  counts: Record<ImportAction, number>
}

export interface ImportActor {
  userId: number
  username: string
  ip?: string | null
}

const REQUEST_STATUSES: VexStatus[] = ['not_affected', 'fixed']

function importReason(s: VexStatement, format: string): string {
  const text = (s.status === 'affected' ? s.action_statement : s.impact_statement) ?? ''
  const head = s.justification ? `[${s.justification}] ` : ''
  const body = `VEX importé (${format}, ${s.status}) pour ${s.product}${text ? ` : ${text}` : '.'}`
  return `${head}${body}`.slice(0, 2000)
}

async function previewEffect(db: Queryable, projectId: string, s: VexStatement): Promise<ImportEffect> {
  const base = { vuln_id: s.vuln_id, product: s.product, status: s.status, justification: s.justification }
  if (/^MAL-/i.test(s.vuln_id)) return { ...base, action: 'refused', reason: 'malicious' }
  if (REQUEST_STATUSES.includes(s.status)) {
    const pkg = parsePurl(s.product)?.name ?? null
    const dup = await db.query(
      `SELECT 1 FROM exceptions
        WHERE project_id = $1 AND kind = 'vuln' AND upper(target->>'vuln_id') = upper($2)
          AND (target->>'package') IS NOT DISTINCT FROM $3
          AND status IN ('requested', 'approved') AND revoked_at IS NULL AND expires_on >= current_date LIMIT 1`,
      [projectId, s.vuln_id, pkg])
    return dup.rowCount ? { ...base, action: 'duplicate' } : { ...base, action: 'request' }
  }
  const dup = await db.query(
    `SELECT 1 FROM vex_statements WHERE project_id = $1 AND upper(vuln_id) = upper($2) AND product = $3 AND status = $4
        AND source = 'import' AND revoked_at IS NULL LIMIT 1`, [projectId, s.vuln_id, s.product, s.status])
  return dup.rowCount ? { ...base, action: 'duplicate' } : { ...base, action: 'store' }
}

/**
 * Import d'un document OpenVEX ou CycloneDX VEX. dry_run : aperçu seulement,
 * rien n'est écrit. Sinon, à appeler dans une transaction : une demande
 * refusée (H4, verrou G8) est notée dans les effets sans arrêter les autres.
 */
export async function importVex(db: Queryable, projectId: string, text: string, opts: { dryRun: boolean, actor: ImportActor, expiresOn?: string, today?: string }): Promise<ImportResult> {
  await checkProject(db, projectId)
  const parsed = parseVexDocument(text)
  const today = opts.today ?? isoDay()
  const expiresOn = opts.expiresOn ?? isoDay(IMPORT_DEFAULT_DAYS, new Date(`${today}T00:00:00Z`))
  if (expiresOn < today || expiresOn > isoDay(MAX_EXCEPTION_DAYS, new Date(`${today}T00:00:00Z`))) throw new VexError('E_VALIDATION', 'expires_on')
  const statements = dedupeStatements(parsed.statements)
  const effects: ImportEffect[] = []
  for (const s of statements) {
    const effect = await previewEffect(db, projectId, s)
    if (!opts.dryRun && effect.action === 'request') {
      const pkg = parsePurl(s.product)?.name
      try {
        const row = await requestException(db, {
          project_id: projectId, kind: 'vuln', target: pkg ? { vuln_id: s.vuln_id, package: pkg.slice(0, 255) } : { vuln_id: s.vuln_id },
          reason: importReason(s, parsed.format), expires_on: expiresOn, requested_via: 'tool-import',
          requester_label: opts.actor.username, requester_is_human: true, requester_user_id: opts.actor.userId,
          commit_authors: [], vex_status: s.status,
        }, today)
        effect.exception_id = row.id
      }
      catch (err) {
        if (!(err instanceof ExceptionError)) throw err
        effect.action = 'refused'
        effect.reason = err.code === 'E_MALICIOUS' ? 'malicious' : err.code === 'E_LOCKED' ? 'locked' : 'validation'
      }
    }
    else if (!opts.dryRun && effect.action === 'store') {
      await db.query(
        `INSERT INTO vex_statements (project_id, vuln_id, product, status, justification, impact_statement, action_statement, source, created_by)
         VALUES ($1, $2, $3, $4, $5, $6, $7, 'import', $8)`,
        [projectId, s.vuln_id, s.product, s.status, s.justification, s.impact_statement, s.action_statement, opts.actor.userId])
    }
    effects.push(effect)
  }
  const counts: Record<ImportAction, number> = { request: 0, store: 0, duplicate: 0, refused: 0 }
  for (const e of effects) counts[e.action]++
  if (!opts.dryRun) {
    await writeAudit(db, {
      actor: { type: 'user', userId: opts.actor.userId, username: opts.actor.username, ip: opts.actor.ip ?? null },
      action: 'vex.import', outcome: 'success', targetType: 'project', targetId: projectId,
      details: { format: parsed.format, counts, document_sha256: sha256Hex(text), expires_on: expiresOn },
    })
  }
  return { format: parsed.format, dry_run: opts.dryRun, effects: sortEffects(effects), counts }
}

function sortEffects(list: ImportEffect[]): ImportEffect[] {
  return [...list].sort((a, b) => canonicalJson([a.vuln_id, a.product]).localeCompare(canonicalJson([b.vuln_id, b.product])))
}

export { VexFormatError, sortStatements }
