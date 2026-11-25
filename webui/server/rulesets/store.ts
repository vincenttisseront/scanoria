// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Jeux de règles gérés dans la console (G4, 0.7 chantier A, contrat 34) :
// tables rulesets, ruleset_versions et profile_rulesets (migration 013).
// Une version n'est jamais modifiée : éditer, importer ou revenir en arrière
// crée une nouvelle version. Les contrôles ici sont statiques (taille,
// encodage, forme, aucune inclusion de fichier) ; la validation par le moteur
// se fait dans le conteneur confiné du module (demande validate-ruleset,
// engine.ts), jamais sur l'hôte.
//
// Contrat donné au chantier F (I12) : createRuleset, addRulesetVersion
// (origin manual | import | ai) et listRulesets. Le rôle administrateur est
// vérifié par la route API appelante ; la fonction écrit l'audit.

import { createHash } from 'node:crypto'
import { z } from 'zod'
import type { Queryable } from '../utils/db'
import { writeAudit, type AuditActor } from '../utils/audit'

export const RULESET_ENGINES = ['opengrep', 'semgrep', 'gitleaks', 'checkov', 'kics'] as const
export type RulesetEngine = (typeof RULESET_ENGINES)[number]
export const RULESET_ORIGINS = ['manual', 'import', 'ai'] as const
export type RulesetOrigin = (typeof RULESET_ORIGINS)[number]
export const RULESET_SLUG_RE = /^[a-z0-9][a-z0-9-]{0,62}$/
/** Slug des règles maison livrées avec l'appliance (montées par l'outil, jamais en base). */
export const RESERVED_SLUGS = ['scanoria-base'] as const
export const MAX_RULESET_BYTES = 1024 * 1024
/** Moteur à un seul fichier de configuration : un seul jeu rattaché par profil. */
export const SINGLE_RULESET_ENGINES: readonly RulesetEngine[] = ['gitleaks']
/** Fichier monté sous /rules/<slug>/ (KICS : requêtes dépliées par le runner). */
export const RULESET_FILE: Record<RulesetEngine, string> = {
  opengrep: 'rules.yaml', semgrep: 'rules.yaml', gitleaks: 'gitleaks.toml', checkov: 'policies.yaml', kics: 'queries.json',
}

export class RulesetError extends Error {
  constructor(readonly code: 'E_NOT_FOUND' | 'E_VALIDATION' | 'E_PRECONDITION' | 'E_CONFLICT', message: string, readonly issues: string[] = []) {
    super(message)
  }
}

export const sha256Hex = (text: string) => createHash('sha256').update(text, 'utf8').digest('hex')

const GITLEAKS_EXTEND_RE = /^\s*\[\s*extend\s*\]\s*$/m
const GITLEAKS_INCLUDE_RE = /^\s*(path|url)\s*=/m
const KICS_ID_RE = /^[A-Za-z0-9][A-Za-z0-9_-]{0,79}$/

/**
 * Contrôles statiques d'un contenu (mêmes règles que rulesets.py du runner,
 * qui les refait sans faire confiance à la console). Rend la liste des problèmes.
 */
export function staticIssues(engine: RulesetEngine, content: string): string[] {
  const issues: string[] = []
  const bytes = Buffer.byteLength(content, 'utf8')
  if (bytes === 0 || content.trim() === '') return ['empty']
  if (bytes > MAX_RULESET_BYTES) return ['too-large']
  if (content.includes('\u0000')) issues.push('nul-byte')
  if (content.includes('�')) issues.push('not-utf8')
  if (engine === 'opengrep' || engine === 'semgrep') {
    if (!/^rules\s*:/m.test(content)) issues.push('missing-rules-key')
  }
  else if (engine === 'checkov') {
    if (!/^\s*-?\s*metadata\s*:/m.test(content) || !/^\s*definition\s*:/m.test(content)) issues.push('missing-policy-keys')
  }
  else if (engine === 'gitleaks') {
    const m = GITLEAKS_EXTEND_RE.exec(content)
    if (m) {
      const rest = content.slice(m.index + m[0].length)
      const next = /^\s*\[/m.exec(rest)
      if (GITLEAKS_INCLUDE_RE.test(next ? rest.slice(0, next.index) : rest)) issues.push('gitleaks-extend-include')
    }
  }
  else if (engine === 'kics') {
    issues.push(...kicsIssues(content))
  }
  return issues
}

function kicsIssues(content: string): string[] {
  let doc: unknown
  try {
    doc = JSON.parse(content)
  }
  catch {
    return ['invalid-json']
  }
  const parsed = z.strictObject({
    queries: z.array(z.strictObject({
      id: z.string().regex(KICS_ID_RE),
      metadata: z.record(z.string(), z.unknown()),
      query: z.string().min(1),
    })).min(1).max(500),
  }).safeParse(doc)
  if (!parsed.success) return ['kics-structure']
  const ids = parsed.data.queries.map(q => q.id)
  return new Set(ids).size === ids.length ? [] : ['kics-duplicate-id']
}

export interface RulesetRow {
  id: string
  slug: string
  engine: RulesetEngine
  name: string
  description: string | null
  created_at: string
  archived_at: string | null
  latest_version: number | null
  latest_sha256: string | null
  latest_origin: RulesetOrigin | null
  latest_at: string | null
  profiles: number
}

export interface RulesetVersionRow {
  version: number
  sha256: string
  comment: string | null
  origin: RulesetOrigin
  created_by: number | null
  created_by_name: string | null
  created_at: string
  bytes: number
}

const LIST_SQL = `
  SELECT r.id, r.slug, r.engine, r.name, r.description, r.created_at, r.archived_at,
         v.version AS latest_version, v.sha256 AS latest_sha256, v.origin AS latest_origin, v.created_at AS latest_at,
         (SELECT count(*)::int FROM profile_rulesets pr WHERE pr.ruleset_id = r.id) AS profiles
    FROM rulesets r
    LEFT JOIN LATERAL (SELECT version, sha256, origin, created_at FROM ruleset_versions
                        WHERE ruleset_id = r.id ORDER BY version DESC LIMIT 1) v ON true`

export async function listRulesets(db: Queryable, opts: { engine?: RulesetEngine, includeArchived?: boolean } = {}): Promise<RulesetRow[]> {
  const where: string[] = []
  const params: unknown[] = []
  if (opts.engine) {
    params.push(opts.engine)
    where.push(`r.engine = $${params.length}`)
  }
  if (!opts.includeArchived) where.push('r.archived_at IS NULL')
  const r = await db.query<RulesetRow>(`${LIST_SQL} ${where.length ? `WHERE ${where.join(' AND ')}` : ''} ORDER BY r.engine, r.slug LIMIT 500`, params)
  return r.rows
}

export async function getRuleset(db: Queryable, id: string): Promise<RulesetRow | null> {
  if (!z.uuid().safeParse(id).success) return null
  const r = await db.query<RulesetRow>(`${LIST_SQL} WHERE r.id = $1`, [id])
  return r.rows[0] ?? null
}

export async function listVersions(db: Queryable, rulesetId: string): Promise<RulesetVersionRow[]> {
  const r = await db.query<RulesetVersionRow>(
    `SELECT v.version, v.sha256, v.comment, v.origin, v.created_by, u.username AS created_by_name, v.created_at,
            octet_length(v.content)::int AS bytes
       FROM ruleset_versions v LEFT JOIN users u ON u.id = v.created_by
      WHERE v.ruleset_id = $1 ORDER BY v.version DESC LIMIT 1000`, [rulesetId])
  return r.rows
}

export async function getVersionContent(db: Queryable, rulesetId: string, version: number): Promise<{ content: string, sha256: string } | null> {
  const r = await db.query<{ content: string, sha256: string }>(
    'SELECT content, sha256 FROM ruleset_versions WHERE ruleset_id = $1 AND version = $2', [rulesetId, version])
  return r.rows[0] ?? null
}

export interface Actor { userId: number, username?: string | null, ip?: string | null }
const auditActor = (a: Actor): AuditActor => ({ type: 'user', userId: a.userId, username: a.username ?? null, ip: a.ip ?? null })

export const createRulesetSchema = z.strictObject({
  slug: z.string().regex(RULESET_SLUG_RE).refine(s => !(RESERVED_SLUGS as readonly string[]).includes(s), 'reserved'),
  engine: z.enum(RULESET_ENGINES),
  name: z.string().trim().min(1).max(200),
  description: z.string().max(2000).nullable().optional(),
})

/** Crée un jeu de règles (sans version) ; slug unique. */
export async function createRuleset(db: Queryable, input: { slug: string, engine: RulesetEngine, name: string, description?: string | null, userId: number, username?: string | null, ip?: string | null }): Promise<{ id: string }> {
  const parsed = createRulesetSchema.safeParse({ slug: input.slug, engine: input.engine, name: input.name, description: input.description ?? null })
  if (!parsed.success) throw new RulesetError('E_VALIDATION', 'invalid ruleset', parsed.error.issues.map(i => i.path.join('.') || i.code))
  const exists = await db.query('SELECT 1 FROM rulesets WHERE slug = $1', [parsed.data.slug])
  if (exists.rowCount) throw new RulesetError('E_CONFLICT', 'slug already used')
  const r = await db.query<{ id: string }>(
    `INSERT INTO rulesets (slug, engine, name, description, created_by) VALUES ($1, $2, $3, $4, $5) RETURNING id`,
    [parsed.data.slug, parsed.data.engine, parsed.data.name, parsed.data.description ?? null, input.userId])
  const id = r.rows[0]!.id
  await writeAudit(db, {
    actor: auditActor(input), action: 'ruleset.create', outcome: 'success', targetType: 'ruleset', targetId: id,
    details: { slug: parsed.data.slug, engine: parsed.data.engine, name: parsed.data.name },
  })
  return { id }
}

/**
 * Nouvelle version d'un jeu de règles : contrôles statiques, refus d'un jeu
 * archivé, numéro suivant (verrou de ligne), audit « ruleset.version ».
 * origin « ai » : règle générée (I12) puis confirmée par un administrateur.
 */
export async function addRulesetVersion(db: Queryable, input: {
  rulesetId: string
  content: string
  comment?: string | null
  origin: RulesetOrigin
  userId: number
  username?: string | null
  ip?: string | null
  /** Version d'origine d'un retour arrière (tracé dans l'audit). */
  restoredFrom?: number
}): Promise<{ version: number, sha256: string }> {
  if (!(RULESET_ORIGINS as readonly string[]).includes(input.origin)) throw new RulesetError('E_VALIDATION', 'invalid origin')
  if (input.comment && input.comment.length > 2000) throw new RulesetError('E_VALIDATION', 'comment too long')
  if (!z.uuid().safeParse(input.rulesetId).success) throw new RulesetError('E_NOT_FOUND', 'ruleset not found')
  const rs = await db.query<{ engine: RulesetEngine, archived_at: string | null, slug: string }>(
    'SELECT engine, archived_at, slug FROM rulesets WHERE id = $1 FOR UPDATE', [input.rulesetId])
  const row = rs.rows[0]
  if (!row) throw new RulesetError('E_NOT_FOUND', 'ruleset not found')
  if (row.archived_at) throw new RulesetError('E_PRECONDITION', 'ruleset is archived')
  const issues = staticIssues(row.engine, input.content)
  if (issues.length) throw new RulesetError('E_VALIDATION', 'invalid content', issues)
  const sha256 = sha256Hex(input.content)
  const last = await db.query<{ version: number, sha256: string }>(
    'SELECT version, sha256 FROM ruleset_versions WHERE ruleset_id = $1 ORDER BY version DESC LIMIT 1', [input.rulesetId])
  if (last.rows[0]?.sha256 === sha256 && input.restoredFrom === undefined) {
    throw new RulesetError('E_CONFLICT', 'content identical to the latest version')
  }
  const version = (last.rows[0]?.version ?? 0) + 1
  await db.query(
    `INSERT INTO ruleset_versions (ruleset_id, version, content, sha256, comment, origin, created_by)
     VALUES ($1, $2, $3, $4, $5, $6, $7)`,
    [input.rulesetId, version, input.content, sha256, input.comment ?? null, input.origin, input.userId])
  await writeAudit(db, {
    actor: auditActor(input), action: input.restoredFrom === undefined ? 'ruleset.version' : 'ruleset.rollback',
    outcome: 'success', targetType: 'ruleset', targetId: input.rulesetId,
    details: { slug: row.slug, engine: row.engine, version, sha256, origin: input.origin, bytes: Buffer.byteLength(input.content, 'utf8'),
      ...(input.restoredFrom !== undefined ? { restored_from: input.restoredFrom } : {}) },
  })
  return { version, sha256 }
}

/** Retour à une version antérieure : crée une nouvelle version au même contenu. */
export async function rollbackRuleset(db: Queryable, input: { rulesetId: string, version: number, userId: number, username?: string | null, ip?: string | null }) {
  const old = await getVersionContent(db, input.rulesetId, input.version)
  if (!old) throw new RulesetError('E_NOT_FOUND', 'version not found')
  const o = await db.query<{ origin: RulesetOrigin }>('SELECT origin FROM ruleset_versions WHERE ruleset_id = $1 AND version = $2', [input.rulesetId, input.version])
  return addRulesetVersion(db, {
    rulesetId: input.rulesetId, content: old.content, origin: o.rows[0]!.origin,
    comment: `Retour à la version ${input.version}`, userId: input.userId, username: input.username, ip: input.ip, restoredFrom: input.version,
  })
}

/** Archive (ou désarchive) : un jeu archivé n'est plus monté dans aucune analyse. */
export async function setArchived(db: Queryable, input: { rulesetId: string, archived: boolean, userId: number, username?: string | null, ip?: string | null }) {
  const r = await db.query<{ slug: string }>(
    `UPDATE rulesets SET archived_at = CASE WHEN $2::boolean THEN COALESCE(archived_at, now()) ELSE NULL END
      WHERE id = $1 RETURNING slug`, [input.rulesetId, input.archived])
  if (!r.rowCount) throw new RulesetError('E_NOT_FOUND', 'ruleset not found')
  await writeAudit(db, {
    actor: auditActor(input), action: input.archived ? 'ruleset.archive' : 'ruleset.unarchive', outcome: 'success',
    targetType: 'ruleset', targetId: input.rulesetId, details: { slug: r.rows[0]!.slug },
  })
}

export async function updateRulesetMeta(db: Queryable, input: { rulesetId: string, name?: string, description?: string | null, userId: number, username?: string | null, ip?: string | null }) {
  const r = await db.query<{ slug: string }>(
    `UPDATE rulesets SET name = COALESCE($2, name), description = CASE WHEN $4::boolean THEN $3 ELSE description END
      WHERE id = $1 RETURNING slug`,
    [input.rulesetId, input.name ?? null, input.description ?? null, input.description !== undefined])
  if (!r.rowCount) throw new RulesetError('E_NOT_FOUND', 'ruleset not found')
  await writeAudit(db, {
    actor: auditActor(input), action: 'ruleset.update', outcome: 'success', targetType: 'ruleset', targetId: input.rulesetId,
    details: { slug: r.rows[0]!.slug, name: input.name ?? null, description_changed: input.description !== undefined },
  })
}

// ------------------------------------------------------------ rattachement aux profils

export interface ProfileAttachment { profile_id: string, profile_slug: string, pinned_version: number | null }

export async function listAttachments(db: Queryable, rulesetId: string): Promise<ProfileAttachment[]> {
  const r = await db.query<ProfileAttachment>(
    `SELECT pr.profile_id, p.slug AS profile_slug, pr.pinned_version
       FROM profile_rulesets pr JOIN profiles p ON p.id = pr.profile_id
      WHERE pr.ruleset_id = $1 ORDER BY p.slug`, [rulesetId])
  return r.rows
}

export const attachmentsSchema = z.strictObject({
  profiles: z.array(z.strictObject({
    profile_id: z.uuid(),
    pinned_version: z.number().int().min(1).nullable(),
  })).max(200).refine(l => new Set(l.map(x => x.profile_id)).size === l.length, 'duplicate'),
})

/**
 * Remplace les profils d'un jeu de règles (version épinglée ou dernière).
 * Refus : version inexistante, jeu archivé, second jeu d'un moteur à fichier unique.
 */
export async function setAttachments(db: Queryable, input: { rulesetId: string, profiles: { profile_id: string, pinned_version: number | null }[], userId: number, username?: string | null, ip?: string | null }) {
  const rs = await db.query<{ engine: RulesetEngine, archived_at: string | null, slug: string }>(
    'SELECT engine, archived_at, slug FROM rulesets WHERE id = $1 FOR UPDATE', [input.rulesetId])
  const row = rs.rows[0]
  if (!row) throw new RulesetError('E_NOT_FOUND', 'ruleset not found')
  if (row.archived_at && input.profiles.length) throw new RulesetError('E_PRECONDITION', 'ruleset is archived')
  const versions = new Set((await listVersions(db, input.rulesetId)).map(v => v.version))
  if (input.profiles.length && versions.size === 0) throw new RulesetError('E_PRECONDITION', 'ruleset has no version yet')
  for (const p of input.profiles) {
    if (p.pinned_version !== null && !versions.has(p.pinned_version)) throw new RulesetError('E_VALIDATION', 'unknown version', ['pinned_version'])
  }
  const ids = input.profiles.map(p => p.profile_id)
  if (ids.length) {
    const known = await db.query<{ id: string }>('SELECT id FROM profiles WHERE id = ANY($1::uuid[])', [ids])
    if (known.rowCount !== ids.length) throw new RulesetError('E_NOT_FOUND', 'profile not found')
    if (SINGLE_RULESET_ENGINES.includes(row.engine)) {
      const other = await db.query(
        `SELECT 1 FROM profile_rulesets pr JOIN rulesets r ON r.id = pr.ruleset_id
          WHERE pr.profile_id = ANY($1::uuid[]) AND r.engine = $2 AND r.id <> $3 LIMIT 1`, [ids, row.engine, input.rulesetId])
      if (other.rowCount) throw new RulesetError('E_CONFLICT', 'a profile already has a ruleset for this single-configuration engine')
    }
  }
  const before = await listAttachments(db, input.rulesetId)
  await db.query('DELETE FROM profile_rulesets WHERE ruleset_id = $1', [input.rulesetId])
  for (const p of input.profiles) {
    await db.query('INSERT INTO profile_rulesets (profile_id, ruleset_id, pinned_version) VALUES ($1, $2, $3)',
      [p.profile_id, input.rulesetId, p.pinned_version])
  }
  await writeAudit(db, {
    actor: auditActor(input), action: 'ruleset.attach', outcome: 'success', targetType: 'ruleset', targetId: input.rulesetId,
    details: { slug: row.slug, before: before.map(b => ({ profile_id: b.profile_id, pinned_version: b.pinned_version })), after: input.profiles },
  })
}

// ------------------------------------------------------------ plan (G11)

export interface PlannedRuleset { slug: string, engine: RulesetEngine, version: number, sha256: string }

/**
 * Versions retenues pour un profil, par moteur : version épinglée, sinon la
 * dernière ; jeux archivés ou sans version écartés. Contenus renvoyés pour
 * être rangés dans la file (files.ts) ; le plan ne garde que slug, version et sha256.
 */
export async function profileRulesets(db: Queryable, profileId: string): Promise<(PlannedRuleset & { content: string })[]> {
  const r = await db.query<PlannedRuleset & { content: string }>(
    `SELECT r.slug, r.engine, v.version, v.sha256, v.content
       FROM profile_rulesets pr
       JOIN rulesets r ON r.id = pr.ruleset_id AND r.archived_at IS NULL
       JOIN LATERAL (SELECT version, sha256, content FROM ruleset_versions
                      WHERE ruleset_id = r.id AND (pr.pinned_version IS NULL OR version = pr.pinned_version)
                      ORDER BY version DESC LIMIT 1) v ON true
      WHERE pr.profile_id = $1
      ORDER BY r.engine, r.slug LIMIT 64`, [profileId])
  return r.rows
}

/** Différence ligne à ligne (plus longue sous-suite commune), bornée ; pour l'historique. */
export function lineDiff(a: string, b: string, max = 4000): { op: ' ' | '+' | '-', text: string }[] | null {
  const x = a.split('\n')
  const y = b.split('\n')
  if (x.length > max || y.length > max) return null
  const n = x.length
  const m = y.length
  const dp: Uint32Array[] = Array.from({ length: n + 1 }, () => new Uint32Array(m + 1))
  for (let i = n - 1; i >= 0; i--) {
    for (let j = m - 1; j >= 0; j--) {
      dp[i]![j] = x[i] === y[j] ? dp[i + 1]![j + 1]! + 1 : Math.max(dp[i + 1]![j]!, dp[i]![j + 1]!)
    }
  }
  const out: { op: ' ' | '+' | '-', text: string }[] = []
  let i = 0
  let j = 0
  while (i < n && j < m) {
    if (x[i] === y[j]) {
      out.push({ op: ' ', text: x[i]! })
      i++
      j++
    }
    else if (dp[i + 1]![j]! >= dp[i]![j + 1]!) out.push({ op: '-', text: x[i++]! })
    else out.push({ op: '+', text: y[j++]! })
  }
  while (i < n) out.push({ op: '-', text: x[i++]! })
  while (j < m) out.push({ op: '+', text: y[j++]! })
  return out
}
