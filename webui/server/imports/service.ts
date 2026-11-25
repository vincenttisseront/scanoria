// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Reprise de l'existant (J5) : aperçu puis application.
// 1. Aperçu : les fichiers repérés dans le dépôt (lecture bornée par l'API de
//    la forge) et, en option, une instance SonarQube, Dependency-Track ou
//    DefectDojo sont lus ; l'effet (demandes créées, doublons, entrées non
//    traduites) est affiché sans rien écrire. Le jeton de l'instance est
//    chiffré en base le temps de l'import.
// 2. Application : mêmes lectures, puis les demandes d'exception sont
//    déposées (requested_via « tool-import ») ; le jeton est effacé.
// Rien n'est approuvé : un administrateur humain décide ensuite (F5, J15).

import { z } from 'zod'
import type { Queryable } from '../utils/db'
import { decryptSecret, deleteSecret, encryptSecret } from '../utils/secrets'
import { isoDay } from '../findings/exceptions'
import type { ForgeClient } from '../forges'
import { effectiveProfile } from '../profiles/resolve'
import { DEFAULT_IMPORT_DAYS, fileRequests, type RequestOutcome } from '../profiles/requests'
import { IMPORT_FILES, IMPORT_FILE_MAX_BYTES, nosecRequests, parseImportFile, type ImportedRequest, type ParsedImport } from './repo-files'
import { globToRegExp } from '../gates/evaluate'
import { instanceSchema, readInstance, type InstanceRef } from './instances'

/** Fichiers Python lus au plus pour « # nosec » (lecture bornée par l'API de la forge). */
export const NOSEC_MAX_FILES = 40
/** Marque des jetons d'import (credentials.username) ; effacés après l'import, ou au bout d'une heure. */
export const IMPORT_TOKEN_USER = 'scanoria-import'
export const IMPORT_TOKEN_TTL_S = 3600

export const importPreviewSchema = z.strictObject({
  /** Lire les fichiers du dépôt (par défaut : oui). */
  repo: z.boolean().default(true),
  ref: z.string().min(1).max(255).regex(/^[A-Za-z0-9._/-]+$/).optional(),
  instance: instanceSchema.extend({ token: z.string().min(8).max(4096) }).optional(),
  /** Date de fin des demandes (90 jours par défaut, un an au plus). */
  expires_on: z.string().regex(/^\d{4}-\d{2}-\d{2}$/).optional(),
})
export const importApplySchema = z.strictObject({
  repo: z.boolean().default(true),
  ref: z.string().min(1).max(255).regex(/^[A-Za-z0-9._/-]+$/).optional(),
  instance: instanceSchema.optional(),
  /** Jeton d'instance chiffré à l'aperçu (credentials.id). */
  import_token: z.string().uuid().optional(),
  expires_on: z.string().regex(/^\d{4}-\d{2}-\d{2}$/).optional(),
})

export interface ImportSourceReport { source: string, requests: number, unsupported: number }

export interface ImportReport {
  outcome: RequestOutcome
  requests: (ImportedRequest & { status: 'new' | 'duplicate' | 'malicious' | 'invalid' | 'locked' })[]
  unsupported: ParsedImport['unsupported']
  sources: ImportSourceReport[]
  import_token: string | null
  expires_on: string
}

/** Jetons d'import oubliés (aperçu sans application) : effacés au bout d'une heure. */
export async function purgeImportTokens(db: Queryable): Promise<void> {
  await db.query(
    `DELETE FROM credentials c WHERE c.username = $1 AND c.kind = 'token' AND c.created_at < now() - make_interval(secs => $2)
        AND NOT EXISTS (SELECT 1 FROM forges f WHERE f.credential_id = c.id) AND NOT EXISTS (SELECT 1 FROM projects p WHERE p.credential_id = c.id)`,
    [IMPORT_TOKEN_USER, IMPORT_TOKEN_TTL_S])
}

export interface RepoAccess { client: ForgeClient, fullName: string, ref: string }

/** Lit les fichiers d'exceptions repérés à la racine du dépôt et les « # nosec » des fichiers Python. */
export async function readRepoImports(access: RepoAccess, until: string): Promise<ParsedImport & { sources: ImportSourceReport[] }> {
  const out: ParsedImport & { sources: ImportSourceReport[] } = { requests: [], unsupported: [], sources: [] }
  const tree = await access.client.listTree(access.fullName, access.ref, { maxEntries: 20_000 })
  const paths = new Set(tree.entries.filter(e => e.type === 'file').map(e => e.path))
  for (const file of IMPORT_FILES) {
    if (!paths.has(file)) continue
    const text = await access.client.readFile(access.fullName, access.ref, file, { maxBytes: IMPORT_FILE_MAX_BYTES })
    if (text === null) {
      out.unsupported.push({ source: file, entry: 'file too large' })
      continue
    }
    const p = parseImportFile(file, text, until)
    out.requests.push(...p.requests)
    out.unsupported.push(...p.unsupported)
    out.sources.push({ source: file, requests: p.requests.length, unsupported: p.unsupported.length })
  }
  // « # nosec » : fichiers Python lus en nombre borné, les plus petits d'abord (le plus de fichiers lus).
  const py = tree.entries.filter(e => e.type === 'file' && /\.py$/.test(e.path) && !/(^|\/)(\.venv|venv|site-packages|node_modules)\//.test(e.path))
    .sort((a, b) => (a.size ?? 0) - (b.size ?? 0)).slice(0, NOSEC_MAX_FILES)
  let nosec = 0
  for (const f of py) {
    const text = await access.client.readFile(access.fullName, access.ref, f.path, { maxBytes: IMPORT_FILE_MAX_BYTES }).catch(() => null)
    if (!text || !text.includes('nosec')) continue
    const p = nosecRequests(f.path, text, until)
    nosec += p.requests.length
    out.requests.push(...p.requests)
  }
  if (nosec) out.sources.push({ source: '# nosec', requests: nosec, unsupported: 0 })
  const totalPy = tree.entries.filter(e => e.type === 'file' && /\.py$/.test(e.path)).length
  if (totalPy > py.length) out.unsupported.push({ source: '# nosec', entry: `${totalPy - py.length} Python files not read` })
  if (tree.truncated) out.unsupported.push({ source: 'tree', entry: 'repository tree truncated' })
  return out
}

/** Modules exigés par les verrous des profils du projet. */
async function lockedModules(db: Queryable, projectId: string): Promise<string[]> {
  const r = await db.query<{ ids: string[] }>(
    `SELECT array_remove(ARRAY[profile_id, profile_pr_id, profile_nightly_id, profile_release_id], NULL)::text[] AS ids FROM projects WHERE id = $1`, [projectId])
  const out = new Set<string>()
  for (const id of new Set(r.rows[0]?.ids ?? [])) for (const m of (await effectiveProfile(db, id)).locks.required_modules) out.add(m)
  return [...out]
}

export class ImportRunError extends Error {
  constructor(readonly code: 'E_IMPORT_NO_SOURCE' | 'E_IMPORT_TOKEN' | 'E_IMPORT_DATE') {
    super(code)
  }
}

export interface RunImportInput {
  projectId: string
  repo: RepoAccess | null
  instance: (InstanceRef & { token?: string }) | null
  importToken?: string | null
  expiresOn?: string
  userId: number
  dryRun: boolean
}

/** Efface un jeton d'import, hors de toute transaction : effacé même si l'application échoue. */
export async function discardImportToken(db: Queryable, id: string | null | undefined): Promise<void> {
  if (!id) return
  await db.query('DELETE FROM credentials WHERE id = $1 AND username = $2', [id, IMPORT_TOKEN_USER]).catch(() => {})
}

/** Résultats examinés au plus pour traduire les entrées à portée combinée. */
const SCOPED_MAX_FINDINGS = 50_000

/**
 * Entrées à portée combinée (chemin ET règle, ou ligne) : une demande par
 * résultat existant qui y correspond exactement ; sans résultat, l'entrée est
 * listée comme non traduite. Jamais d'exception de chemin ou de règle entière.
 */
export async function resolveScoped(db: Queryable, projectId: string, parsed: ParsedImport): Promise<void> {
  const scoped = parsed.requests.filter(r => r.match)
  if (!scoped.length) return
  const tools = [...new Set(scoped.map(r => r.match!.tool))]
  const rows = (await db.query<{ id: string, tool: string, rule_id: string, path: string | null, start_line: number | null }>(
    `SELECT id::text, tool, rule_id, path, start_line FROM findings
      WHERE project_id = $1 AND tool = ANY($2::text[]) AND NOT malicious AND status <> 'fixed' LIMIT $3`,
    [projectId, tools, SCOPED_MAX_FINDINGS])).rows
  const out: ImportedRequest[] = []
  for (const r of parsed.requests) {
    const m = r.match
    if (!m) {
      out.push(r)
      continue
    }
    const re = globToRegExp(m.glob)
    const hits = rows.filter(f => f.tool === m.tool && f.path !== null && re.test(f.path)
      && (!m.rules?.length || m.rules.includes(f.rule_id)) && (m.line === undefined || f.start_line === m.line))
    if (!hits.length) {
      parsed.unsupported.push({ source: r.source, entry: `no matching finding: ${m.tool} ${(m.rules ?? []).join(',')} ${m.glob}${m.line ? `:${m.line}` : ''}`.slice(0, 160) })
      continue
    }
    for (const f of hits.slice(0, 200)) out.push({ kind: 'finding', target: { finding_id: f.id }, reason: r.reason, expires_on: r.expires_on, source: r.source })
  }
  parsed.requests = out
}

/** Aperçu (dryRun) ou application d'une reprise de l'existant. */
export async function runImport(db: Queryable, input: RunImportInput): Promise<ImportReport> {
  const today = isoDay()
  const until = input.expiresOn ?? isoDay(DEFAULT_IMPORT_DAYS)
  if (until < today || until > isoDay(366)) throw new ImportRunError('E_IMPORT_DATE')
  if (!input.repo && !input.instance) throw new ImportRunError('E_IMPORT_NO_SOURCE')
  await purgeImportTokens(db)
  const all: ParsedImport & { sources: ImportSourceReport[] } = { requests: [], unsupported: [], sources: [] }
  if (input.repo) {
    const r = await readRepoImports(input.repo, until)
    all.requests.push(...r.requests)
    all.unsupported.push(...r.unsupported)
    all.sources.push(...r.sources)
  }
  let importToken: string | null = null
  if (input.instance) {
    let token = input.instance.token ?? null
    if (!token) {
      if (!input.importToken) throw new ImportRunError('E_IMPORT_TOKEN')
      // Jeton lié à l'administrateur qui a fait l'aperçu.
      const r = await db.query('SELECT 1 FROM credentials WHERE id = $1 AND username = $2 AND kind = $3 AND created_by = $4',
        [input.importToken, IMPORT_TOKEN_USER, 'token', input.userId])
      if (!r.rowCount) throw new ImportRunError('E_IMPORT_TOKEN')
      token = (await decryptSecret(db, input.importToken)).value
    }
    try {
      const r = await readInstance(input.instance, token, db, input.projectId, until)
      all.requests.push(...r.requests)
      all.unsupported.push(...r.unsupported)
      all.sources.push({ source: input.instance.kind, requests: r.requests.length, unsupported: r.unsupported.length })
      if (input.dryRun && input.instance.token) {
        // Jeton chiffré le temps de l'import (aperçu → application, 1 h au plus), jamais renvoyé.
        importToken = await encryptSecret(db, { kind: 'token', value: input.instance.token, username: IMPORT_TOKEN_USER, createdBy: input.userId })
      }
    }
    finally {
      // Application : le jeton est effacé ; l'appelant l'efface aussi hors transaction (discardImportToken).
      if (!input.dryRun && input.importToken) await deleteSecret(db, input.importToken).catch(() => {})
    }
  }
  await resolveScoped(db, input.projectId, all)
  const outcome = await fileRequests(db, {
    projectId: input.projectId, via: 'tool-import', requesterLabel: `import ${all.sources.map(s => s.source).join(', ')}`.slice(0, 255),
    requests: all.requests, lockedModules: await lockedModules(db, input.projectId), dryRun: input.dryRun, today,
  })
  return {
    outcome,
    requests: all.requests.slice(0, 1000).map((r, i) => ({ ...r, status: outcome.statuses[i] ?? 'invalid' })),
    unsupported: all.unsupported.slice(0, 500),
    sources: all.sources,
    import_token: importToken,
    expires_on: until,
  }
}
