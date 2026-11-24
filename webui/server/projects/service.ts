// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Projets : lecture, création (dépôt d'une forge, URL Git libre, archive),
// modification, archivage, suppression, et détection F1 rattachée au projet.
// Requêtes SQL explicites ; aucun secret n'est renvoyé (seulement son indice).

import type { Queryable } from '../utils/db'
import { getConfig } from '../utils/config'
import { readCatalogIndex, readModulesState, latestModules } from '../utils/catalog'
import { deleteSecret } from '../utils/secrets'
import { ForgeError } from '../forges/http'
import { forgeClient, getForge, openForge, type ForgeClient } from '../forges'
import { detectRepository, suggestModules, DETECTION_VERSION, type CatalogModuleLite, type Detection, type InstalledLite } from './detect'
import { fullNameFromPath, parseGitUrl } from './git-url'

export interface ProjectRow {
  id: string
  slug: string
  name: string
  source_kind: 'git' | 'archive'
  forge_id: string | null
  forge_name: string | null
  forge_kind: string | null
  repo_full_name: string | null
  repo_url: string | null
  credential_id: string | null
  credential_hint: string | null
  credential_kind: string | null
  ssh_known_hosts: string | null
  upload_id: string | null
  default_branch: string | null
  tracked_branches: string[]
  schedule: 'none' | 'daily' | 'on-commit'
  profile_id: string
  profile_slug: string
  gate_id: string
  gate_slug: string
  spdx_license: string | null
  ai_opt_out: boolean
  detection: (Detection | DetectionError) | null
  last_commit: string | null
  last_polled_at: string | null
  created_by: string | null
  created_at: string
  archived_at: string | null
  last_scan: { id: string, number: number, status: string, verdict: string | null, queued_at: string } | null
}

export interface DetectionError {
  version: typeof DETECTION_VERSION
  analyzed_at: string
  error: string
}

const ts = (col: string, alias = col.split('.').pop()!) => `to_char(${col} AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS ${alias}`

const SELECT = `
  SELECT p.id::text, p.slug, p.name, p.source_kind, p.forge_id::text, f.name AS forge_name, f.kind AS forge_kind,
         p.repo_full_name, p.repo_url, p.credential_id::text, c.hint AS credential_hint, c.kind AS credential_kind,
         p.ssh_known_hosts, p.upload_id::text, p.default_branch, p.tracked_branches, p.schedule,
         p.profile_id::text, pr.slug AS profile_slug, p.gate_id::text, g.slug AS gate_slug,
         p.spdx_license, p.ai_opt_out, p.detection, p.last_commit, ${ts('p.last_polled_at')},
         p.created_by::text, ${ts('p.created_at')}, ${ts('p.archived_at')},
         (SELECT json_build_object('id', s.id, 'number', s.number, 'status', s.status, 'verdict', s.verdict,
                   'queued_at', to_char(s.queued_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'))
            FROM scans s WHERE s.project_id = p.id ORDER BY s.queued_at DESC LIMIT 1) AS last_scan
    FROM projects p
    JOIN profiles pr ON pr.id = p.profile_id
    JOIN gates g ON g.id = p.gate_id
    LEFT JOIN forges f ON f.id = p.forge_id
    LEFT JOIN credentials c ON c.id = p.credential_id`

export async function listProjects(db: Queryable, opts: { archived?: boolean, forgeId?: string } = {}): Promise<ProjectRow[]> {
  const where = [opts.archived ? 'p.archived_at IS NOT NULL' : 'p.archived_at IS NULL']
  const params: unknown[] = []
  if (opts.forgeId) {
    params.push(opts.forgeId)
    where.push(`p.forge_id = $${params.length}`)
  }
  const { rows } = await db.query<ProjectRow>(`${SELECT} WHERE ${where.join(' AND ')} ORDER BY p.name, p.slug LIMIT 5000`, params)
  return rows
}

export async function getProject(db: Queryable, id: string): Promise<ProjectRow | null> {
  const { rows } = await db.query<ProjectRow>(`${SELECT} WHERE p.id = $1`, [id])
  return rows[0] ?? null
}

/** Vue publique d'un projet : jamais l'identifiant du secret ni sa valeur. */
export function publicProject(p: ProjectRow) {
  const { credential_id: _credentialId, ...rest } = p
  return { ...rest, has_credential: !!p.credential_id }
}

export function slugify(name: string): string {
  const s = name
    .normalize('NFKD')
    .replace(/[̀-ͯ]/g, '')
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 50)
  return /^[a-z0-9]/.test(s) ? s : `projet-${s}`.replace(/-+$/, '').slice(0, 50) || 'projet'
}

export async function uniqueSlug(db: Queryable, name: string): Promise<string> {
  const base = slugify(name)
  const { rows } = await db.query<{ slug: string }>(`SELECT slug FROM projects WHERE slug = $1 OR slug LIKE $2`, [base, `${base}-%`])
  const taken = new Set(rows.map(r => r.slug))
  if (!taken.has(base)) return base
  for (let i = 2; i < 10_000; i++) {
    if (!taken.has(`${base}-${i}`)) return `${base}-${i}`
  }
  return `${base}-${Date.now().toString(36)}`
}

export async function builtinIds(db: Queryable): Promise<{ profileId: string, gateId: string }> {
  const { rows } = await db.query<{ profile_id: string, gate_id: string }>(
    `SELECT (SELECT id::text FROM profiles WHERE slug = 'complet') AS profile_id,
            (SELECT id::text FROM gates WHERE slug = 'defaut') AS gate_id`,
  )
  return { profileId: rows[0]!.profile_id, gateId: rows[0]!.gate_id }
}

export interface NewProject {
  name: string
  slug?: string
  sourceKind: 'git' | 'archive'
  forgeId?: string | null
  repoFullName?: string | null
  repoUrl?: string | null
  credentialId?: string | null
  sshKnownHosts?: string | null
  uploadId?: string | null
  defaultBranch?: string | null
  trackedBranches?: string[]
  schedule?: 'none' | 'daily' | 'on-commit'
  profileId?: string
  gateId?: string
  spdxLicense?: string | null
  aiOptOut?: boolean
  detection?: Detection | DetectionError | null
  createdBy?: number | null
  archived?: boolean
}

export class ProjectExistsError extends Error {
  constructor() {
    super('E_PROJECT_EXISTS')
  }
}

export async function createProject(db: Queryable, p: NewProject): Promise<ProjectRow> {
  const ids = (p.profileId && p.gateId) ? { profileId: p.profileId, gateId: p.gateId } : await builtinIds(db)
  const slug = p.slug ?? await uniqueSlug(db, p.name)
  try {
    const { rows } = await db.query<{ id: string }>(
      `INSERT INTO projects (slug, name, source_kind, forge_id, repo_full_name, repo_url, credential_id, ssh_known_hosts,
                             upload_id, default_branch, tracked_branches, schedule, profile_id, gate_id, spdx_license,
                             ai_opt_out, detection, created_by, archived_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, CASE WHEN $19 THEN now() END)
       RETURNING id::text`,
      [
        slug, p.name.slice(0, 200), p.sourceKind, p.forgeId ?? null, p.repoFullName ?? null, p.repoUrl ?? null,
        p.credentialId ?? null, p.sshKnownHosts ?? null, p.uploadId ?? null, p.defaultBranch ?? null,
        p.trackedBranches ?? (p.defaultBranch ? [p.defaultBranch] : []), p.schedule ?? 'on-commit',
        p.profileId ?? ids.profileId, p.gateId ?? ids.gateId, p.spdxLicense ?? null, p.aiOptOut ?? false,
        p.detection ? JSON.stringify(p.detection) : null, p.createdBy ?? null, p.archived ?? false,
      ],
    )
    return (await getProject(db, rows[0]!.id))!
  }
  catch (err) {
    if ((err as { code?: string }).code === '23505') throw new ProjectExistsError()
    throw err
  }
}

export interface ProjectPatch {
  name?: string
  tracked_branches?: string[]
  schedule?: 'none' | 'daily' | 'on-commit'
  profile_id?: string
  gate_id?: string
  ai_opt_out?: boolean
  credential_id?: string | null
  ssh_known_hosts?: string | null
  upload_id?: string | null
  default_branch?: string | null
  detection?: Detection | DetectionError | null
  spdx_license?: string | null
}

const PATCH_COLUMNS: Record<keyof ProjectPatch, string> = {
  name: 'name', tracked_branches: 'tracked_branches', schedule: 'schedule', profile_id: 'profile_id',
  gate_id: 'gate_id', ai_opt_out: 'ai_opt_out', credential_id: 'credential_id', ssh_known_hosts: 'ssh_known_hosts',
  upload_id: 'upload_id', default_branch: 'default_branch', detection: 'detection', spdx_license: 'spdx_license',
}

export async function updateProject(db: Queryable, id: string, patch: ProjectPatch): Promise<ProjectRow | null> {
  const sets: string[] = []
  const params: unknown[] = [id]
  for (const [key, col] of Object.entries(PATCH_COLUMNS) as [keyof ProjectPatch, string][]) {
    if (patch[key] === undefined) continue
    const v = patch[key]
    params.push(key === 'detection' && v !== null ? JSON.stringify(v) : v)
    sets.push(`${col} = $${params.length}`)
  }
  if (sets.length) await db.query(`UPDATE projects SET ${sets.join(', ')} WHERE id = $1`, params)
  return getProject(db, id)
}

export async function setArchived(db: Queryable, id: string, archived: boolean): Promise<ProjectRow | null> {
  await db.query(`UPDATE projects SET archived_at = CASE WHEN $2 THEN COALESCE(archived_at, now()) END WHERE id = $1`, [id, archived])
  return getProject(db, id)
}

/** Supprime un secret s'il n'est plus utilisé par aucune forge ni aucun projet. */
export async function dropUnusedCredential(db: Queryable, credentialId: string | null): Promise<void> {
  if (!credentialId) return
  const { rows } = await db.query<{ n: string }>(
    `SELECT (SELECT count(*) FROM forges WHERE credential_id = $1) + (SELECT count(*) FROM projects WHERE credential_id = $1) AS n`,
    [credentialId],
  )
  if (Number(rows[0]?.n ?? 0) === 0) await deleteSecret(db, credentialId)
}

/** Suppression définitive (analyses et résultats compris, par cascade). */
export async function deleteProject(db: Queryable, id: string): Promise<ProjectRow | null> {
  const project = await getProject(db, id)
  if (!project) return null
  await db.query(`DELETE FROM projects WHERE id = $1`, [id])
  await dropUnusedCredential(db, project.credential_id)
  return project
}

/**
 * Client de forge d'un projet : sa forge enregistrée, ou GitHub en accès
 * anonyme pour un dépôt public de github.com ajouté par URL. null sinon.
 */
export async function projectClient(db: Queryable, p: Pick<ProjectRow, 'forge_id' | 'repo_full_name' | 'repo_url' | 'source_kind'>): Promise<{ client: ForgeClient, fullName: string } | null> {
  if (p.source_kind !== 'git' || !p.repo_full_name) return null
  if (p.forge_id) {
    const forge = await getForge(db, p.forge_id)
    if (!forge) return null
    return { client: await openForge(db, forge), fullName: p.repo_full_name }
  }
  if (p.repo_url) {
    try {
      const u = parseGitUrl(p.repo_url)
      if (u.kind === 'https' && u.host === 'github.com') return { client: forgeClient({ kind: 'github', base_url: 'https://github.com' }), fullName: p.repo_full_name }
    }
    catch {
      return null
    }
  }
  return null
}

/** « propriétaire/dépôt » d'une URL de github.com, pour l'accès anonyme. */
export function githubFullName(repoUrl: string): string | null {
  try {
    const u = parseGitUrl(repoUrl)
    return u.kind === 'https' && u.host === 'github.com' ? fullNameFromPath(u.path) : null
  }
  catch {
    return null
  }
}

export async function loadCatalogLite(): Promise<{ catalog: CatalogModuleLite[], installed: InstalledLite[] }> {
  const cfg = getConfig()
  const [index, state] = await Promise.all([readCatalogIndex(cfg.catalogIndexFile), readModulesState(cfg.modulesStateFile)])
  return {
    catalog: [...latestModules(index).values()].map(m => ({
      id: m.id, name: m.name, type: m.type, categories: m.categories, license: { restrictions: m.license.restrictions },
    })),
    installed: state.modules.map(m => ({ id: m.id, enabled: m.enabled, status: m.status })),
  }
}

const TREE_LIMIT = 20_000
const FILE_LIMIT = 128 * 1024
const MAX_READS = 40

/** Détection F1 d'un dépôt par l'API de sa forge (lecture bornée, aucun clone). */
export async function detectWithClient(client: ForgeClient, fullName: string, ref: string, now = new Date()): Promise<Detection> {
  const [commit, tree] = await Promise.all([
    client.latestCommit(fullName, ref).catch(() => null),
    client.listTree(fullName, ref, { maxEntries: TREE_LIMIT }),
  ])
  let reads = 0
  const read = async (path: string) => {
    if (++reads > MAX_READS) return null
    return client.readFile(fullName, ref, path, { maxBytes: FILE_LIMIT })
  }
  const raw = await detectRepository({ tree, read, ref, commit, now })
  const { catalog, installed } = await loadCatalogLite()
  return suggestModules(raw, catalog, installed)
}

export function detectionError(err: unknown, now = new Date()): DetectionError {
  return {
    version: DETECTION_VERSION,
    analyzed_at: now.toISOString().replace(/\.\d{3}Z$/, 'Z'),
    error: err instanceof ForgeError ? err.code : 'E_DETECTION',
  }
}

/**
 * Relance la détection d'un projet et l'enregistre (avec la licence SPDX
 * trouvée). Une erreur est enregistrée telle quelle, sans lever.
 */
export async function refreshDetection(db: Queryable, project: ProjectRow, now = new Date()): Promise<ProjectRow> {
  let detection: Detection | DetectionError
  try {
    const access = await projectClient(db, project)
    if (!access) {
      detection = { version: DETECTION_VERSION, analyzed_at: now.toISOString().replace(/\.\d{3}Z$/, 'Z'), error: 'E_NO_FORGE_ACCESS' }
    }
    else {
      const ref = project.default_branch ?? (await access.client.repo(access.fullName)).default_branch
      if (!ref) throw new ForgeError('E_FORGE_NOT_FOUND')
      detection = await detectWithClient(access.client, access.fullName, ref, now)
    }
  }
  catch (err) {
    detection = detectionError(err, now)
  }
  const patch: ProjectPatch = { detection }
  if ('license' in detection && detection.license) patch.spdx_license = detection.license.spdx
  return (await updateProject(db, project.id, patch))!
}
