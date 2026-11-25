// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Lecture de .scanoria.yml (J8) à chaque analyse, avant son plan : le fichier
// est lu par l'API de la forge (lecture bornée, jamais de clone ni
// d'exécution), validé, puis rangé dans projects.config_state :
// - valide : il devient la configuration courante ; ses exceptions et chemins
//   ignorés deviennent des DEMANDES (requested_via « config ») ;
// - absent : plus de configuration en code ;
// - invalide ou illisible : signalé sur l'analyse, la configuration
//   précédente continue de s'appliquer.
// Le plan (worker) ne lit ensuite que la base, sous son verrou de dépôt.

import { createHash } from 'node:crypto'
import type pg from 'pg'
import type { Queryable } from '../utils/db'
import { writeAudit } from '../utils/audit'
import { getForge, openForge } from '../forges'
import { effectiveProfile } from '../profiles/resolve'
import { fileRequests } from '../profiles/requests'
import { REPO_CONFIG_FILE, REPO_CONFIG_MAX_BYTES, configRequests, parseRepoConfig, type ConfigIssue, type RepoConfig } from './repo-config'

export const CONFIG_STATE_VERSION = 1
/** Une ref sans commit (branche) est relue au plus toutes les 10 minutes. */
export const REF_REREAD_S = 600

export interface ConfigState {
  version: typeof CONFIG_STATE_VERSION
  status: 'ok' | 'absent' | 'invalid' | 'unavailable'
  read_at: string
  /** Commit lu, ou ref à défaut. */
  read_key: string
  sha256: string | null
  issues: ConfigIssue[]
  /** Dernière configuration valide (appliquée). */
  config: RepoConfig | null
  config_key: string | null
  /** Demandes déposées à la dernière lecture valide. */
  requests: { created: number, skipped: number } | null
}

export function parseConfigState(v: unknown): ConfigState | null {
  if (!v || typeof v !== 'object' || (v as { version?: unknown }).version !== CONFIG_STATE_VERSION) return null
  return v as ConfigState
}

export type ReadFn = (ref: string) => Promise<string | null>

/**
 * Lit et range la configuration d'un projet pour une ref (ou un commit).
 * read : contenu du fichier, null s'il est absent ; une exception = illisible.
 */
export async function refreshRepoConfig(db: Queryable, projectId: string, key: string, read: ReadFn, now = new Date(), opts: { scanId?: string } = {}): Promise<ConfigState> {
  const prev = parseConfigState((await db.query<{ config_state: unknown }>('SELECT config_state FROM projects WHERE id = $1', [projectId])).rows[0]?.config_state)
  const base = { version: CONFIG_STATE_VERSION, read_at: now.toISOString(), read_key: key } as const
  let state: ConfigState
  let text: string | null
  try {
    text = await read(key)
  }
  catch {
    state = { ...base, status: 'unavailable', sha256: null, issues: [{ path: '', message: 'forge unavailable' }], config: prev?.config ?? null, config_key: prev?.config_key ?? null, requests: prev?.requests ?? null }
    await save(db, projectId, state)
    return state
  }
  if (text === null) {
    state = { ...base, status: 'absent', sha256: null, issues: [], config: null, config_key: null, requests: null }
    await save(db, projectId, state)
    return state
  }
  const sha256 = createHash('sha256').update(text, 'utf8').digest('hex')
  const parsed = parseRepoConfig(text)
  if (!parsed.ok) {
    state = { ...base, status: 'invalid', sha256, issues: parsed.issues, config: prev?.config ?? null, config_key: prev?.config_key ?? null, requests: prev?.requests ?? null }
    await save(db, projectId, state)
    return state
  }
  const issues = await checkProfiles(db, parsed.config)
  // Exceptions et chemins ignorés : des demandes, jamais des exceptions approuvées.
  const { requests } = configRequests(parsed.config, now.toISOString().slice(0, 10))
  const locked = await lockedModules(db, projectId)
  const outcome = await fileRequests(db, {
    projectId, via: 'config', requesterLabel: `${REPO_CONFIG_FILE} @ ${key.slice(0, 40)}`, requests, lockedModules: locked, scanId: opts.scanId,
    today: now.toISOString().slice(0, 10),
  })
  if (outcome.created.length) {
    await writeAudit(db, {
      actor: { type: 'system' }, action: 'config.requests', outcome: 'success', targetType: 'project', targetId: projectId,
      details: { file: REPO_CONFIG_FILE, key, created: outcome.created.map(c => ({ id: c.id, kind: c.kind, target: c.target })), skipped: outcome.skipped.length },
    })
  }
  state = {
    ...base, status: 'ok', sha256, issues, config: parsed.config, config_key: key,
    requests: { created: outcome.created.length, skipped: outcome.skipped.length },
  }
  await save(db, projectId, state)
  return state
}

async function save(db: Queryable, projectId: string, state: ConfigState): Promise<void> {
  await db.query('UPDATE projects SET config_state = $2 WHERE id = $1', [projectId, JSON.stringify(state)])
}

/** Profils nommés par la configuration : inconnus ou archivés = signalés et ignorés. */
async function checkProfiles(db: Queryable, config: RepoConfig): Promise<ConfigIssue[]> {
  const issues: ConfigIssue[] = []
  for (const [slot, slug] of Object.entries(config.profiles ?? {})) {
    if (!slug) continue
    const r = await db.query('SELECT 1 FROM profiles WHERE slug = $1 AND archived_at IS NULL', [slug])
    if (!r.rowCount) issues.push({ path: `profiles.${slot}`, message: 'unknown profile' })
  }
  return issues
}

/** Modules exigés par les verrous des profils du projet (jamais exemptés). */
async function lockedModules(db: Queryable, projectId: string): Promise<string[]> {
  const r = await db.query<{ ids: string[] }>(
    `SELECT array_remove(ARRAY[profile_id, profile_pr_id, profile_nightly_id, profile_release_id], NULL)::text[] AS ids FROM projects WHERE id = $1`, [projectId])
  const out = new Set<string>()
  for (const id of new Set(r.rows[0]?.ids ?? [])) {
    try {
      for (const m of (await effectiveProfile(db, id)).locks.required_modules) out.add(m)
    }
    catch {
      // Chaîne illisible : rien à ajouter, la résolution du plan le signalera.
    }
  }
  return [...out]
}

/**
 * Passe du worker, avant les dépôts : lit la configuration des analyses en
 * file dont le commit (ou la ref, toutes les 10 minutes) n'a pas encore été lu.
 * Hors transaction de dépôt : la forge peut être lente.
 */
export async function prepareRepoConfigs(pool: Pick<pg.Pool, 'query'>, opts: { limit?: number, now?: Date, log?: (m: string) => void } = {}): Promise<number> {
  const rows = await pool.query<{ scan_id: string, project_id: string, key: string, forge_id: string, repo_full_name: string }>(
    `SELECT DISTINCT ON (s.project_id) s.id::text AS scan_id, s.project_id::text, COALESCE(s.commit_sha, s.ref) AS key, p.forge_id::text, p.repo_full_name
       FROM scans s JOIN projects p ON p.id = s.project_id
      WHERE s.status = 'queued' AND s.plan IS NULL AND s.trigger NOT IN ('replay', 'trial', 'recorrelate')
        AND p.source_kind = 'git' AND p.forge_id IS NOT NULL AND p.repo_full_name IS NOT NULL AND p.archived_at IS NULL
        AND NOT (p.config_state IS NOT NULL AND p.config_state->>'read_key' = COALESCE(s.commit_sha, s.ref)
                 AND (s.commit_sha IS NOT NULL OR (p.config_state->>'read_at')::timestamptz > $2::timestamptz - make_interval(secs => $3)))
      ORDER BY s.project_id, s.priority DESC, s.queued_at
      LIMIT $1`,
    [opts.limit ?? 5, (opts.now ?? new Date()).toISOString(), REF_REREAD_S])
  for (const row of rows.rows) {
    try {
      const forge = await getForge(pool, row.forge_id)
      if (!forge) throw new Error('forge not found')
      const client = await openForge(pool, forge)
      await refreshRepoConfig(pool, row.project_id, row.key, async (ref) => {
        // Lecture un peu au-delà de la borne : un fichier trop grand est signalé, pas pris pour absent.
        const text = await client.readFile(row.repo_full_name, ref, REPO_CONFIG_FILE, { maxBytes: REPO_CONFIG_MAX_BYTES * 4 })
        return text
      }, opts.now, { scanId: row.scan_id })
    }
    catch (e) {
      opts.log?.(`repo config of project ${row.project_id}: ${(e as Error).message}`)
      // Forge introuvable : lecture notée « illisible » pour ce commit (configuration précédente conservée), le plan n'attend pas indéfiniment.
      await refreshRepoConfig(pool, row.project_id, row.key, async () => {
        throw new Error('forge unavailable')
      }, opts.now, { scanId: row.scan_id }).catch(() => {})
    }
  }
  return rows.rows.length
}

export interface AppliedConfig {
  /** Profil demandé par le dépôt pour cet emplacement (slug), s'il existe. */
  profileSlug: string | null
  /** Note de couverture (G15) : état du fichier et chemins ignorés. */
  coverage: { status: ConfigState['status'], key: string | null, issues: ConfigIssue[], ignored: string[], profile: string | null } | null
}

/** Ce que le plan retient de la configuration courante d'un projet (base seule, sans réseau). */
export function appliedConfig(stateValue: unknown, slot: 'pr' | 'nightly' | 'release' | 'default'): AppliedConfig {
  const state = parseConfigState(stateValue)
  if (!state) return { profileSlug: null, coverage: null }
  const cfg = state.config
  const slug = cfg?.profiles?.[slot] ?? null
  const unknown = new Set(state.status === 'ok' ? state.issues.filter(i => i.path.startsWith('profiles.')).map(i => i.path.slice(9)) : [])
  const profileSlug = slug && !unknown.has(slot) ? slug : null
  return {
    profileSlug,
    coverage: {
      status: state.status,
      key: state.config_key,
      issues: state.issues.slice(0, 20),
      ignored: (cfg?.ignore ?? []).map(i => (typeof i === 'string' ? i : i.path)).slice(0, 100),
      profile: profileSlug,
    },
  }
}
