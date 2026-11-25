// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Export et import de toute la configuration de l'appliance en YAML versionné
// (J8) : projets, profils, gates, jeux de règles, tables de gravité et règles
// de tri. JAMAIS de secret : ni jeton, ni clé, ni secret chiffré, ni jeton
// d'API ; un projet importé reçoit ses secrets dans la console.
// À l'import : lecture sûre (config/yaml.ts), schéma strict, aperçu des écarts,
// puis application confirmée (empreinte de l'aperçu), en une transaction, tracée
// dans l'audit. Les règles de la console s'appliquent comme à la main :
// verrous de profil (G8), H4 et G13 jamais désactivés, dates de fin obligatoires.

import { createHash } from 'node:crypto'
import { stringify } from 'yaml'
import { z } from 'zod'
import { CATEGORIES, GateRules, ProfileLocks, SEVERITIES, SLUG_RE } from '#shared/analysis'
import { MODULE_ID_RE } from '#shared/schemas'
import type { Queryable } from '../utils/db'
import { isValidDay, isoDay } from '../findings/exceptions'
import { PROFILE_LEVELS, aiOptOutLocked, createProfile, getProfileBySlug, hasControlChars, syncAiOptOut, updateProfile } from '../profiles/service'
import { findLoosening, mergeAll, parseLocks } from '../profiles/locks'
import { builtinIds, createProject } from '../projects/service'
import { parseSafeYaml, type ConfigIssue } from './yaml'

/** Adresse de dépôt : https://…, ssh://utilisateur@hôte[:port]/chemin ou utilisateur@hôte:chemin (motifs sans retour arrière). */
function isRepoUrl(v: string): boolean {
  if (v.startsWith('https://')) return /^https:\/\/[^?#@\s]+$/.test(v)
  if (v.startsWith('ssh://')) return /^ssh:\/\/[\w.-]+@[A-Za-z0-9.-]+(?::\d{1,5})?\/[^?#\s]+$/.test(v)
  return /^[\w.-]+@[A-Za-z0-9.-]+:[^?#\s]+$/.test(v)
}

export const APPLIANCE_CONFIG_VERSION = 1
export const APPLIANCE_CONFIG_MAX_BYTES = 8 * 1024 * 1024

const slug = z.string().regex(SLUG_RE)
const moduleId = z.string().regex(MODULE_ID_RE)
const day = z.string().refine(isValidDay)
const text = (max: number) => z.string().max(max).refine(v => !hasControlChars(v), { message: 'control characters' })

const profileSchema = z.strictObject({
  slug,
  level: z.enum(PROFILE_LEVELS),
  parent: slug.nullable().default(null),
  categories: z.array(z.enum(CATEGORIES)).max(32).default([]),
  include_modules: z.array(moduleId).max(64).default([]),
  exclude_modules: z.array(moduleId).max(64).default([]),
  description: text(2000).nullable().default(null),
  locks: ProfileLocks.default(ProfileLocks.parse({})),
  rulesets: z.array(z.strictObject({ slug, version: z.number().int().min(1).nullable().default(null) })).max(32).default([]),
})

const gateSchema = z.strictObject({ slug, rules: GateRules })

const rulesetSchema = z.strictObject({
  slug,
  engine: z.string().regex(/^[a-z][a-z0-9-]{1,40}$/),
  name: text(200).pipe(z.string().min(1)),
  description: text(2000).nullable().default(null),
  /** Dernière version (contenu exporté) ; l'import ajoute une version si le contenu diffère. */
  content: z.string().min(1).max(1_048_576),
  sha256: z.string().regex(/^[0-9a-f]{64}$/).optional(),
})

const severitySchema = z.strictObject({ module: moduleId, native: z.string().min(1).max(64), severity: z.enum(SEVERITIES) })

const triageSchema = z.strictObject({
  project: slug.nullable().default(null),
  match: z.strictObject({
    path: z.string().min(1).max(512).optional(),
    tool: z.string().min(1).max(64).optional(),
    rule: z.string().min(1).max(255).optional(),
    severity: z.enum(SEVERITIES).optional(),
  }),
  action: z.enum(['false-positive', 'accepted', 'confirmed']),
  reason: z.string().trim().min(3).max(2000),
  expires_on: day,
})

const projectSchema = z.strictObject({
  slug,
  name: text(200).pipe(z.string().min(1)),
  source_kind: z.enum(['git', 'archive']),
  forge: z.string().min(1).max(100).nullable().default(null),
  repo_full_name: z.string().regex(/^[A-Za-z0-9._-]+(\/[A-Za-z0-9._-]+)+$/).nullable().default(null),
  /** URL sans identifiant (jamais user:motdepasse@) ; SSH « git@hôte:chemin » admis. */
  repo_url: z.string().max(512).refine(isRepoUrl).nullable().default(null),
  default_branch: z.string().min(1).max(255).nullable().default(null),
  tracked_branches: z.array(z.string().min(1).max(255)).max(50).default([]),
  schedule: z.enum(['none', 'daily', 'on-commit']).default('on-commit'),
  profiles: z.strictObject({ default: slug, pr: slug.nullable().default(null), nightly: slug.nullable().default(null), release: slug.nullable().default(null) }),
  gate: slug,
  ai_opt_out: z.boolean().default(false),
  spdx_license: z.string().min(1).max(128).nullable().default(null),
  archived: z.boolean().default(false),
})

export const applianceConfigSchema = z.strictObject({
  scanoria_config: z.literal(APPLIANCE_CONFIG_VERSION),
  exported_at: z.string().max(40).optional(),
  appliance_version: z.string().max(64).optional(),
  profiles: z.array(profileSchema).max(500).default([]),
  gates: z.array(gateSchema).max(200).default([]),
  rulesets: z.array(rulesetSchema).max(200).default([]),
  severity_maps: z.array(severitySchema).max(20_000).default([]),
  triage_rules: z.array(triageSchema).max(2000).default([]),
  projects: z.array(projectSchema).max(5000).default([]),
})
export type ApplianceConfig = z.infer<typeof applianceConfigSchema>

const sha = (s: string) => createHash('sha256').update(s, 'utf8').digest('hex')

// ------------------------------------------------------------------ export

/** Configuration courante de l'appliance, sans aucun secret. */
export async function exportConfig(db: Queryable, opts: { applianceVersion?: string, now?: Date } = {}): Promise<{ yaml: string, config: ApplianceConfig }> {
  const [profiles, gates, rulesets, severities, triage, projects] = await Promise.all([
    db.query<{ slug: string, level: string, parent: string | null, categories: string[], include_modules: string[], exclude_modules: string[], description: string | null, locks: unknown, rulesets: { slug: string, version: number | null }[] }>(
      `SELECT p.slug, p.level, pp.slug AS parent, p.categories, p.include_modules, p.exclude_modules, p.description, p.locks,
              COALESCE((SELECT json_agg(json_build_object('slug', r.slug, 'version', pr.pinned_version) ORDER BY r.slug)
                          FROM profile_rulesets pr JOIN rulesets r ON r.id = pr.ruleset_id WHERE pr.profile_id = p.id), '[]'::json) AS rulesets
         FROM profiles p LEFT JOIN profiles pp ON pp.id = p.parent_id
        WHERE p.archived_at IS NULL
        ORDER BY CASE p.level WHEN 'enterprise' THEN 0 WHEN 'team' THEN 1 ELSE 2 END, p.slug`),
    db.query<{ slug: string, rules: unknown }>('SELECT slug, rules FROM gates ORDER BY slug'),
    db.query<{ slug: string, engine: string, name: string, description: string | null, content: string, sha256: string }>(
      `SELECT r.slug, r.engine, r.name, r.description, v.content, v.sha256
         FROM rulesets r JOIN LATERAL (SELECT content, sha256 FROM ruleset_versions WHERE ruleset_id = r.id ORDER BY version DESC LIMIT 1) v ON true
        WHERE r.archived_at IS NULL ORDER BY r.slug`),
    db.query<{ module: string, native: string, severity: string }>(
      'SELECT module_id AS module, native, severity FROM severity_maps WHERE NOT builtin ORDER BY module_id, native'),
    db.query<{ project: string | null, match: unknown, action: string, reason: string, expires_on: string }>(
      `SELECT p.slug AS project, t.match, t.action, t.reason, to_char(t.expires_on, 'YYYY-MM-DD') AS expires_on
         FROM triage_rules t LEFT JOIN projects p ON p.id = t.project_id
        WHERE t.revoked_at IS NULL AND t.expires_on >= current_date ORDER BY t.created_at`),
    db.query<{ slug: string, name: string, source_kind: string, forge: string | null, repo_full_name: string | null, repo_url: string | null, default_branch: string | null, tracked_branches: string[], schedule: string, p_default: string, p_pr: string | null, p_nightly: string | null, p_release: string | null, gate: string, ai_opt_out: boolean, spdx_license: string | null, archived: boolean }>(
      `SELECT x.slug, x.name, x.source_kind, f.name AS forge, x.repo_full_name, x.repo_url, x.default_branch, x.tracked_branches, x.schedule,
              pd.slug AS p_default, pr.slug AS p_pr, pn.slug AS p_nightly, pl.slug AS p_release, g.slug AS gate,
              x.ai_opt_out, x.spdx_license, x.archived_at IS NOT NULL AS archived
         FROM projects x
         LEFT JOIN forges f ON f.id = x.forge_id
         JOIN profiles pd ON pd.id = x.profile_id
         LEFT JOIN profiles pr ON pr.id = x.profile_pr_id
         LEFT JOIN profiles pn ON pn.id = x.profile_nightly_id
         LEFT JOIN profiles pl ON pl.id = x.profile_release_id
         JOIN gates g ON g.id = x.gate_id
        ORDER BY x.slug`),
  ])
  const config: ApplianceConfig = {
    scanoria_config: APPLIANCE_CONFIG_VERSION,
    exported_at: (opts.now ?? new Date()).toISOString().replace(/\.\d{3}Z$/, 'Z'),
    ...(opts.applianceVersion ? { appliance_version: opts.applianceVersion } : {}),
    profiles: profiles.rows.map(p => ({
      slug: p.slug, level: p.level as ApplianceConfig['profiles'][number]['level'], parent: p.parent,
      categories: p.categories as ApplianceConfig['profiles'][number]['categories'], include_modules: p.include_modules, exclude_modules: p.exclude_modules,
      description: p.description, locks: parseLocks(p.locks), rulesets: p.rulesets,
    })),
    gates: gates.rows.map(g => ({ slug: g.slug, rules: GateRules.parse(g.rules) })),
    rulesets: rulesets.rows.map(r => ({ slug: r.slug, engine: r.engine, name: r.name, description: r.description, content: r.content, sha256: r.sha256 })),
    severity_maps: severities.rows as ApplianceConfig['severity_maps'],
    triage_rules: triage.rows.map(t => ({ project: t.project, match: t.match as ApplianceConfig['triage_rules'][number]['match'], action: t.action as 'accepted', reason: t.reason, expires_on: t.expires_on })),
    projects: projects.rows.map(p => ({
      slug: p.slug, name: p.name, source_kind: p.source_kind as 'git', forge: p.forge, repo_full_name: p.repo_full_name, repo_url: p.repo_url,
      default_branch: p.default_branch, tracked_branches: p.tracked_branches, schedule: p.schedule as 'daily',
      profiles: { default: p.p_default, pr: p.p_pr, nightly: p.p_nightly, release: p.p_release },
      gate: p.gate, ai_opt_out: p.ai_opt_out, spdx_license: p.spdx_license, archived: p.archived,
    })),
  }
  const header = '# Configuration Scanoria (J8). Aucun secret : jetons et clés se saisissent dans la console.\n'
  return { yaml: header + stringify(config, { lineWidth: 0, aliasDuplicateObjects: false }), config }
}

// ------------------------------------------------------------------ import

export type ImportAction = 'create' | 'update' | 'unchanged'
export interface ImportChange { section: string, key: string, action: ImportAction, fields: string[] }
export interface ImportPreview {
  digest: string
  changes: ImportChange[]
  issues: ConfigIssue[]
  /** Nombre d'objets par section et par action. */
  summary: Record<string, Record<ImportAction, number>>
}

export function parseApplianceConfig(text: string): { ok: true, config: ApplianceConfig } | { ok: false, issues: ConfigIssue[] } {
  const raw = parseSafeYaml(text, APPLIANCE_CONFIG_MAX_BYTES)
  if (!raw.ok) return raw
  const parsed = applianceConfigSchema.safeParse(raw.value)
  if (!parsed.success) return { ok: false, issues: parsed.error.issues.slice(0, 50).map(i => ({ path: i.path.join('.'), message: i.code })) }
  // Doublons de clés dans une même section.
  const issues: ConfigIssue[] = []
  const dup = (section: string, keys: string[]) => {
    const seen = new Set<string>()
    for (const k of keys) {
      if (seen.has(k)) issues.push({ path: section, message: `duplicate ${k}` })
      seen.add(k)
    }
  }
  dup('profiles', parsed.data.profiles.map(p => p.slug))
  dup('gates', parsed.data.gates.map(g => g.slug))
  dup('rulesets', parsed.data.rulesets.map(r => r.slug))
  dup('projects', parsed.data.projects.map(p => p.slug))
  dup('severity_maps', parsed.data.severity_maps.map(s => `${s.module}/${s.native}`))
  return issues.length ? { ok: false, issues } : { ok: true, config: parsed.data }
}

const same = (a: unknown, b: unknown) => JSON.stringify(a) === JSON.stringify(b)
const diffFields = (cur: Record<string, unknown>, next: Record<string, unknown>, keys: string[]) => keys.filter(k => !same(cur[k] ?? null, next[k] ?? null))

/** Écarts entre la configuration importée et l'appliance (rien n'est écrit). */
export async function planImport(db: Queryable, config: ApplianceConfig, text: string): Promise<ImportPreview> {
  const { config: current } = await exportConfig(db)
  const changes: ImportChange[] = []
  const issues: ConfigIssue[] = []
  const bySlug = <T extends { slug: string }>(xs: T[]) => new Map(xs.map(x => [x.slug, x]))

  const curProfiles = bySlug(current.profiles)
  const profileKeys = ['level', 'parent', 'categories', 'include_modules', 'exclude_modules', 'description', 'locks', 'rulesets']
  for (const p of config.profiles) {
    const cur = curProfiles.get(p.slug)
    if (!cur) {
      const archived = await db.query('SELECT 1 FROM profiles WHERE slug = $1', [p.slug])
      if (archived.rowCount) issues.push({ path: `profiles.${p.slug}`, message: 'archived profile' })
      else changes.push({ section: 'profiles', key: p.slug, action: 'create', fields: [] })
      continue
    }
    const f = diffFields(cur as never, p as never, profileKeys)
    changes.push({ section: 'profiles', key: p.slug, action: f.length ? 'update' : 'unchanged', fields: f })
  }
  const knownProfiles = new Set([...curProfiles.keys(), ...config.profiles.map(p => p.slug)])
  for (const p of config.profiles) if (p.parent && !knownProfiles.has(p.parent)) issues.push({ path: `profiles.${p.slug}.parent`, message: 'unknown profile' })
  issues.push(...hierarchyIssues(current.profiles, config.profiles))

  const curGates = bySlug(current.gates)
  for (const g of config.gates) {
    const cur = curGates.get(g.slug)
    changes.push({ section: 'gates', key: g.slug, action: !cur ? 'create' : same(cur.rules, g.rules) ? 'unchanged' : 'update', fields: cur && !same(cur.rules, g.rules) ? diffFields(cur.rules as never, g.rules as never, Object.keys(g.rules)) : [] })
  }
  const knownGates = new Set([...curGates.keys(), ...config.gates.map(g => g.slug)])

  const curRulesets = bySlug(current.rulesets)
  for (const r of config.rulesets) {
    const cur = curRulesets.get(r.slug)
    if (r.sha256 && r.sha256 !== sha(r.content)) issues.push({ path: `rulesets.${r.slug}.sha256`, message: 'content does not match sha256' })
    if (!cur) changes.push({ section: 'rulesets', key: r.slug, action: 'create', fields: [] })
    else {
      if (cur.engine !== r.engine) issues.push({ path: `rulesets.${r.slug}.engine`, message: 'engine cannot change' })
      const f = diffFields(cur as never, { ...r, sha256: sha(r.content) } as never, ['name', 'description', 'sha256'])
      changes.push({ section: 'rulesets', key: r.slug, action: f.length ? 'update' : 'unchanged', fields: f.map(x => (x === 'sha256' ? 'content' : x)) })
    }
  }
  const knownRulesets = new Set([...curRulesets.keys(), ...config.rulesets.map(r => r.slug)])
  for (const p of config.profiles) for (const r of p.rulesets) if (!knownRulesets.has(r.slug)) issues.push({ path: `profiles.${p.slug}.rulesets`, message: `unknown ruleset ${r.slug}` })

  const curSev = new Map(current.severity_maps.map(s => [`${s.module}/${s.native}`, s.severity]))
  for (const s of config.severity_maps) {
    const k = `${s.module}/${s.native}`
    const cur = curSev.get(k)
    changes.push({ section: 'severity_maps', key: k, action: cur === undefined ? 'create' : cur === s.severity ? 'unchanged' : 'update', fields: cur !== undefined && cur !== s.severity ? ['severity'] : [] })
  }

  const today = isoDay()
  const curTriage = new Set(current.triage_rules.map(t => JSON.stringify(t)))
  const knownProjects = new Set([...current.projects.map(p => p.slug), ...config.projects.map(p => p.slug)])
  for (const [i, t] of config.triage_rules.entries()) {
    if (t.expires_on < today) {
      issues.push({ path: `triage_rules.${i}.expires_on`, message: 'expired' })
      continue
    }
    if (t.project && !knownProjects.has(t.project)) issues.push({ path: `triage_rules.${i}.project`, message: 'unknown project' })
    changes.push({ section: 'triage_rules', key: `${t.project ?? '*'}:${i}`, action: curTriage.has(JSON.stringify(t)) ? 'unchanged' : 'create', fields: [] })
  }

  const curProjects = bySlug(current.projects)
  const projectKeys = ['name', 'tracked_branches', 'schedule', 'profiles', 'gate', 'ai_opt_out', 'archived']
  for (const p of config.projects) {
    for (const [slot, s] of Object.entries(p.profiles)) if (s && !knownProfiles.has(s)) issues.push({ path: `projects.${p.slug}.profiles.${slot}`, message: 'unknown profile' })
    if (!knownGates.has(p.gate)) issues.push({ path: `projects.${p.slug}.gate`, message: 'unknown gate' })
    const cur = curProjects.get(p.slug)
    if (!cur) {
      if (p.source_kind === 'archive') issues.push({ path: `projects.${p.slug}`, message: 'archive projects cannot be imported' })
      else if (!p.repo_url) issues.push({ path: `projects.${p.slug}.repo_url`, message: 'required' })
      else changes.push({ section: 'projects', key: p.slug, action: 'create', fields: [] })
      continue
    }
    if (cur.source_kind !== p.source_kind || (cur.repo_url ?? null) !== (p.repo_url ?? null)) issues.push({ path: `projects.${p.slug}`, message: 'source cannot change' })
    const f = diffFields(cur as never, p as never, projectKeys)
    changes.push({ section: 'projects', key: p.slug, action: f.length ? 'update' : 'unchanged', fields: f })
  }

  const summary: ImportPreview['summary'] = {}
  for (const c of changes) {
    summary[c.section] ??= { create: 0, update: 0, unchanged: 0 }
    summary[c.section]![c.action]++
  }
  return { digest: sha(text), changes, issues, summary }
}

/**
 * Hiérarchie importée (G8), avant toute écriture : parent de niveau supérieur,
 * aucun cycle, et aucun profil qui assouplit un verrou de ses ancêtres, y
 * compris un profil existant sous un parent importé plus strict. Les profils
 * importés remplacent les profils courants de même slug.
 */
function hierarchyIssues(current: ApplianceConfig['profiles'], imported: ApplianceConfig['profiles']): ConfigIssue[] {
  const all = new Map(current.map(p => [p.slug, p]))
  for (const p of imported) all.set(p.slug, p)
  const rank: Record<string, number> = { enterprise: 0, team: 1, project: 2 }
  const issues: ConfigIssue[] = []
  const touched = new Set(imported.map(p => p.slug))
  for (const p of all.values()) {
    const ancestors: ApplianceConfig['profiles'] = []
    let cur = p.parent ? all.get(p.parent) : undefined
    let child = p
    let broken = false
    while (cur) {
      if (cur.slug === p.slug || ancestors.length >= 3) {
        issues.push({ path: `profiles.${p.slug}.parent`, message: 'cycle' })
        broken = true
        break
      }
      if (rank[cur.level]! >= rank[child.level]!) {
        issues.push({ path: `profiles.${child.slug}.parent`, message: 'parent level must be higher' })
        broken = true
        break
      }
      ancestors.unshift(cur)
      child = cur
      cur = cur.parent ? all.get(cur.parent) : undefined
    }
    if (broken || !ancestors.length) continue
    if (!touched.has(p.slug) && !ancestors.some(a => touched.has(a.slug))) continue
    const inherited = mergeAll(ancestors.map(a => parseLocks(a.locks)))
    for (const v of findLoosening(inherited, { locks: parseLocks(p.locks), exclude_modules: p.exclude_modules })) {
      issues.push({ path: `profiles.${p.slug}.${v.field === 'exclude_modules' ? 'exclude_modules' : `locks.${v.field}`}`, message: 'loosens an inherited lock' })
    }
  }
  return issues
}

export class ImportError extends Error {
  constructor(readonly code: 'E_CONFIG_INVALID' | 'E_CONFIG_DIGEST' | 'E_CONFIG_APPLY', readonly issues: ConfigIssue[] = []) {
    super(code)
  }
}

/**
 * Applique une configuration déjà prévisualisée (même empreinte) dans la
 * transaction de l'appelant. Ordre : jeux de règles, gates, profils (racine
 * d'abord), tables de gravité, projets, règles de tri.
 */
export async function applyImport(db: Queryable, text: string, digest: string, userId: number): Promise<ImportPreview> {
  const parsed = parseApplianceConfig(text)
  if (!parsed.ok) throw new ImportError('E_CONFIG_INVALID', parsed.issues)
  const preview = await planImport(db, parsed.config, text)
  if (preview.digest !== digest) throw new ImportError('E_CONFIG_DIGEST')
  if (preview.issues.length) throw new ImportError('E_CONFIG_INVALID', preview.issues)
  const cfg = parsed.config
  const step = async (path: string, fn: () => Promise<unknown>) => {
    try {
      await fn()
    }
    catch (e) {
      const code = (e as { code?: string }).code ?? (e as Error).message
      throw new ImportError('E_CONFIG_APPLY', [{ path, message: String(code).slice(0, 200) }])
    }
  }
  const action = (section: string, key: string) => preview.changes.find(c => c.section === section && c.key === key)?.action

  for (const r of cfg.rulesets) {
    const a = action('rulesets', r.slug)
    if (a === 'unchanged') continue
    await step(`rulesets.${r.slug}`, async () => {
      let id = (await db.query<{ id: string }>('SELECT id::text FROM rulesets WHERE slug = $1', [r.slug])).rows[0]?.id
      if (!id) {
        id = (await db.query<{ id: string }>('INSERT INTO rulesets (slug, engine, name, description, created_by) VALUES ($1, $2, $3, $4, $5) RETURNING id::text',
          [r.slug, r.engine, r.name, r.description, userId])).rows[0]!.id
      }
      else await db.query('UPDATE rulesets SET name = $2, description = $3 WHERE id = $1', [id, r.name, r.description])
      const latest = await db.query<{ sha256: string }>('SELECT sha256 FROM ruleset_versions WHERE ruleset_id = $1 ORDER BY version DESC LIMIT 1', [id])
      if (latest.rows[0]?.sha256 !== sha(r.content)) {
        await db.query(
          `INSERT INTO ruleset_versions (ruleset_id, version, content, sha256, comment, origin, created_by)
           VALUES ($1, (SELECT COALESCE(max(version), 0) + 1 FROM ruleset_versions WHERE ruleset_id = $1), $2, $3, 'import', 'import', $4)`,
          [id, r.content, sha(r.content), userId])
      }
    })
  }
  for (const g of cfg.gates) {
    const a = action('gates', g.slug)
    if (a === 'unchanged') continue
    await step(`gates.${g.slug}`, () => db.query(
      `INSERT INTO gates (slug, builtin, rules, updated_by) VALUES ($1, false, $2, $3)
       ON CONFLICT (slug) DO UPDATE SET rules = EXCLUDED.rules, updated_at = now(), updated_by = EXCLUDED.updated_by`,
      [g.slug, JSON.stringify(g.rules), userId]))
  }
  const levelRank = { enterprise: 0, team: 1, project: 2 } as const
  const rulesetIds = async (refs: { slug: string, version: number | null }[]) => {
    const out: { ruleset_id: string, pinned_version: number | null }[] = []
    for (const r of refs) {
      const id = (await db.query<{ id: string }>('SELECT id::text FROM rulesets WHERE slug = $1', [r.slug])).rows[0]?.id
      if (id) out.push({ ruleset_id: id, pinned_version: r.version })
    }
    return out
  }
  for (const p of [...cfg.profiles].sort((a, b) => levelRank[a.level] - levelRank[b.level])) {
    const a = action('profiles', p.slug)
    if (a === 'unchanged') continue
    await step(`profiles.${p.slug}`, async () => {
      const parentId = p.parent ? (await getProfileBySlug(db, p.parent))?.id ?? null : null
      const body = {
        level: p.level, parent_id: parentId, categories: p.categories, include_modules: p.include_modules, exclude_modules: p.exclude_modules,
        description: p.description, locks: p.locks, rulesets: await rulesetIds(p.rulesets),
      }
      const cur = await getProfileBySlug(db, p.slug)
      if (!cur) await createProfile(db, { slug: p.slug, ...body }, userId)
      else await updateProfile(db, cur.id, cur.builtin ? { ...body, level: undefined, parent_id: undefined } : body, userId)
    })
  }
  for (const s of cfg.severity_maps) {
    if (action('severity_maps', `${s.module}/${s.native}`) === 'unchanged') continue
    await step(`severity_maps.${s.module}/${s.native}`, () => db.query(
      `INSERT INTO severity_maps (module_id, native, severity, builtin, updated_by) VALUES ($1, $2, $3, false, $4)
       ON CONFLICT (module_id, native) DO UPDATE SET severity = EXCLUDED.severity, builtin = false, updated_by = EXCLUDED.updated_by, updated_at = now()`,
      [s.module, s.native, s.severity, userId]))
  }
  const profileId = async (s: string | null) => (s ? (await getProfileBySlug(db, s))!.id : null)
  for (const p of cfg.projects) {
    const a = action('projects', p.slug)
    if (a === 'unchanged') continue
    await step(`projects.${p.slug}`, async () => {
      const gateId = (await db.query<{ id: string }>('SELECT id::text FROM gates WHERE slug = $1', [p.gate])).rows[0]!.id
      const ids = { d: (await profileId(p.profiles.default))!, pr: await profileId(p.profiles.pr), n: await profileId(p.profiles.nightly), r: await profileId(p.profiles.release) }
      let id = (await db.query<{ id: string }>('SELECT id::text FROM projects WHERE slug = $1', [p.slug])).rows[0]?.id
      if (!id) {
        const forgeId = p.forge ? (await db.query<{ id: string }>('SELECT id::text FROM forges WHERE name = $1', [p.forge])).rows[0]?.id ?? null : null
        const created = await createProject(db, {
          slug: p.slug, name: p.name, sourceKind: 'git', forgeId, repoFullName: forgeId ? p.repo_full_name : null, repoUrl: p.repo_url,
          defaultBranch: p.default_branch, trackedBranches: p.tracked_branches, schedule: p.schedule,
          profileId: ids.d ?? (await builtinIds(db)).profileId, gateId, spdxLicense: p.spdx_license, aiOptOut: p.ai_opt_out, createdBy: userId, archived: p.archived,
        })
        id = created.id
      }
      // « Aucun envoi à l'IA » imposé par un verrou ne se lève pas par un import.
      const aiOptOut = p.ai_opt_out || await aiOptOutLocked(db, id)
      await db.query(
        `UPDATE projects SET name = $2, tracked_branches = $3, schedule = $4, profile_id = $5, profile_pr_id = $6, profile_nightly_id = $7,
                profile_release_id = $8, gate_id = $9, ai_opt_out = $10,
                archived_at = CASE WHEN $11 THEN COALESCE(archived_at, now()) END
          WHERE id = $1`,
        [id, p.name, p.tracked_branches, p.schedule, ids.d, ids.pr, ids.n, ids.r, gateId, aiOptOut, p.archived])
      await syncAiOptOut(db, id)
    })
  }
  for (const [i, t] of cfg.triage_rules.entries()) {
    if (action('triage_rules', `${t.project ?? '*'}:${i}`) !== 'create') continue
    await step(`triage_rules.${i}`, async () => {
      const pid = t.project ? (await db.query<{ id: string }>('SELECT id::text FROM projects WHERE slug = $1', [t.project])).rows[0]?.id ?? null : null
      await db.query(
        'INSERT INTO triage_rules (project_id, match, action, reason, expires_on, created_by) VALUES ($1, $2, $3, $4, $5::date, $6)',
        [pid, JSON.stringify(t.match), t.action, t.reason, t.expires_on, userId])
    })
  }
  return preview
}
