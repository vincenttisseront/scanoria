// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// J4 (0.8, chantier C) : émetteurs OIDC de confiance et liaisons (dépôt de la
// forge → projet), JWKS en cache, vérification complète d'un jeton de CI.
// - Un émetteur est déclaré automatiquement pour chaque forge connectée (J1),
//   avec l'émetteur Actions connu de la forge et l'audience « scanoria » ; un
//   administrateur en ajoute ou en désactive.
// - Une liaison est créée à l'enrôlement d'un dépôt (refs/heads/main et
//   refs/tags/* par défaut). Sans liaison, aucun accès.
// - JWKS lu en HTTPS (client de forge : aucune adresse locale, taille et délai
//   bornés), même origine que l'émetteur, gardé une heure, rafraîchi seulement
//   sur un `kid` inconnu, au plus une fois par minute et par émetteur.

import type { Queryable } from '../utils/db'
import { forgeGetJson, normalizeBaseUrl } from '../forges/http'
import { githubApiBase } from '../forges/github'
import {
  JwtError, candidateKeys, checkClaims, ciClaims, hasKid, parseJwt, refMatches, verifySignature,
  type CiClaims, type OidcKind,
} from './jwt'

export const DEFAULT_AUDIENCE = 'scanoria'
export const DEFAULT_REF_PATTERNS = ['refs/heads/main', 'refs/tags/*']

/**
 * Motifs d'une liaison créée à l'enrôlement : branche principale et tags,
 * plus les PR (GitHub et Forgejo : refs/pull/N/merge ou head ; GitLab : la
 * branche source d'une merge request, d'où refs/heads/*). Sans cela, l'étape
 * des modèles CI échouerait sur chaque PR en mode poussé.
 */
export function defaultRefPatterns(kind: string, defaultBranch?: string | null): string[] {
  const main = `refs/heads/${defaultBranch && /^[A-Za-z0-9._/-]{1,200}$/.test(defaultBranch) && !defaultBranch.includes('..') ? defaultBranch : 'main'}`
  return kind === 'gitlab' ? ['refs/heads/*', 'refs/tags/*'] : [main, 'refs/tags/*', 'refs/pull/*']
}
export const JWKS_TTL_MS = 60 * 60 * 1000
export const JWKS_REFRESH_MIN_MS = 60 * 1000
const MAX_JWKS_BYTES = 64 * 1024
const GITHUB_COM_ISSUER = 'https://token.actions.githubusercontent.com'

export interface OidcIssuerRow {
  id: string
  kind: OidcKind
  issuer: string
  audience: string
  forge_id: string | null
  enabled: boolean
  jwks_fetched_at: string | null
  created_at: string
  bindings: number
}

export interface OidcBindingRow {
  id: string
  issuer_id: string
  issuer: string
  kind: OidcKind
  project_id: string
  repository: string
  /** Identifiant immuable épinglé (migration 019), null tant qu'aucun jeton ni l'enrôlement ne l'a donné. */
  repository_id: string | null
  ref_patterns: string[]
  scopes: string[]
  created_at: string
}

const ts = (col: string, as = col.split('.').pop()) => `to_char(${col} AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS ${as}`

/** Émetteur Actions connu d'une forge (null : forge sans OIDC de CI connu). */
export function defaultIssuerFor(forge: { kind: string, base_url: string }): string | null {
  const base = normalizeBaseUrl(forge.base_url)
  switch (forge.kind) {
    case 'github': {
      const api = githubApiBase(base)
      // github.com : émetteur public ; GitHub Enterprise Server : <hôte>/_services/token.
      return api === 'https://api.github.com' ? GITHUB_COM_ISSUER : `${new URL(base).origin}/_services/token`
    }
    // GitLab : l'émetteur est l'adresse de l'instance (id_tokens).
    case 'gitlab': return base
    // Forgejo Actions : <instance>/api/actions.
    case 'forgejo': return `${base}/api/actions`
    default: return null
  }
}

export function normalizeIssuer(raw: string): string {
  const base = normalizeBaseUrl(raw)
  if (base.length > 255) throw new JwtError('E_OIDC_ISSUER')
  return base
}

export async function listIssuers(db: Queryable): Promise<OidcIssuerRow[]> {
  const { rows } = await db.query<OidcIssuerRow>(
    `SELECT i.id::text, i.kind, i.issuer, i.audience, i.forge_id::text, i.enabled, ${ts('i.jwks_fetched_at')}, ${ts('i.created_at')},
            (SELECT count(*)::int FROM oidc_bindings b WHERE b.issuer_id = i.id) AS bindings
       FROM oidc_issuers i ORDER BY i.created_at, i.issuer`)
  return rows
}

export async function getIssuer(db: Queryable, id: string): Promise<OidcIssuerRow | null> {
  return (await listIssuers(db)).find(i => i.id === id) ?? null
}

export async function createIssuer(db: Queryable, p: { kind: OidcKind, issuer: string, audience?: string, forgeId?: string | null, createdBy?: number | null }): Promise<{ id: string, created: boolean }> {
  const issuer = normalizeIssuer(p.issuer)
  const ins = await db.query<{ id: string }>(
    `INSERT INTO oidc_issuers (kind, issuer, audience, forge_id, created_by) VALUES ($1, $2, $3, $4, $5)
     ON CONFLICT (issuer) DO NOTHING RETURNING id::text`,
    [p.kind, issuer, p.audience ?? DEFAULT_AUDIENCE, p.forgeId ?? null, p.createdBy ?? null])
  if (ins.rows[0]) return { id: ins.rows[0].id, created: true }
  const { rows } = await db.query<{ id: string }>('SELECT id::text FROM oidc_issuers WHERE issuer = $1', [issuer])
  return { id: rows[0]!.id, created: false }
}

export async function setIssuerEnabled(db: Queryable, id: string, enabled: boolean): Promise<boolean> {
  const r = await db.query('UPDATE oidc_issuers SET enabled = $2 WHERE id = $1', [id, enabled])
  return !!r.rowCount
}

export async function listBindings(db: Queryable, projectId: string): Promise<OidcBindingRow[]> {
  const { rows } = await db.query<OidcBindingRow>(
    `SELECT b.id::text, b.issuer_id::text, i.issuer, i.kind, b.project_id::text, b.repository, b.repository_id, b.ref_patterns, b.scopes, ${ts('b.created_at')}
       FROM oidc_bindings b JOIN oidc_issuers i ON i.id = b.issuer_id
      WHERE b.project_id = $1 ORDER BY b.created_at`, [projectId])
  return rows
}

export async function createBinding(db: Queryable, p: { issuerId: string, projectId: string, repository: string, repositoryId?: string | null, refPatterns?: string[], scopes?: string[] }): Promise<string | null> {
  const { rows } = await db.query<{ id: string }>(
    `INSERT INTO oidc_bindings (issuer_id, project_id, repository, repository_id, ref_patterns, scopes)
     VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT (issuer_id, repository, project_id) DO NOTHING RETURNING id::text`,
    [p.issuerId, p.projectId, p.repository, p.repositoryId ?? null, p.refPatterns ?? DEFAULT_REF_PATTERNS, p.scopes ?? ['scan:create', 'scan:read']])
  return rows[0]?.id ?? null
}

/** Réinitialise l'épingle d'identifiant (dépôt légitimement recréé) : action d'administrateur, auditée par la route. */
export async function resetBindingPin(db: Queryable, projectId: string, id: string): Promise<boolean> {
  const r = await db.query('UPDATE oidc_bindings SET repository_id = NULL WHERE id = $2 AND project_id = $1', [projectId, id])
  return !!r.rowCount
}

export async function updateBinding(db: Queryable, projectId: string, id: string, p: { refPatterns: string[] }): Promise<boolean> {
  const r = await db.query('UPDATE oidc_bindings SET ref_patterns = $3 WHERE id = $2 AND project_id = $1', [projectId, id, p.refPatterns])
  return !!r.rowCount
}

export async function deleteBinding(db: Queryable, projectId: string, id: string): Promise<boolean> {
  const r = await db.query('DELETE FROM oidc_bindings WHERE id = $2 AND project_id = $1', [projectId, id])
  return !!r.rowCount
}

/**
 * Émetteur de la forge (créé s'il manque) ; à sa création, liaisons de tous
 * les projets déjà enrôlés depuis cette forge. Un émetteur désactivé par un
 * administrateur n'est jamais réactivé ici.
 */
export async function ensureForgeOidc(db: Queryable, forge: { id: string, kind: string, base_url: string }): Promise<{ issuerId: string | null, bound: number }> {
  let url: string | null
  try {
    url = defaultIssuerFor(forge)
  }
  catch {
    return { issuerId: null, bound: 0 }
  }
  if (!url) return { issuerId: null, bound: 0 }
  const { id, created } = await createIssuer(db, { kind: forge.kind as OidcKind, issuer: url, forgeId: forge.id })
  let bound = 0
  if (created) {
    const { rows } = await db.query<{ id: string, repo_full_name: string, default_branch: string | null }>(
      `SELECT id::text, repo_full_name, default_branch FROM projects WHERE forge_id = $1 AND repo_full_name IS NOT NULL AND archived_at IS NULL`, [forge.id])
    // Identifiant du dépôt inconnu ici : épinglé au premier jeton accepté.
    for (const p of rows) {
      if (await createBinding(db, { issuerId: id, projectId: p.id, repository: p.repo_full_name, refPatterns: defaultRefPatterns(forge.kind, p.default_branch) })) bound++
    }
  }
  return { issuerId: id, bound }
}

/** Liaison d'un projet tout juste enrôlé depuis une forge (J1 → J4). */
export async function bindEnrolledProject(db: Queryable, forge: { id: string, kind: string, base_url: string }, projectId: string, repository: string, repo: { id?: string | null, defaultBranch?: string | null } = {}): Promise<string | null> {
  const { issuerId } = await ensureForgeOidc(db, forge)
  if (!issuerId) return null
  // L'API de la forge donne l'identifiant immuable : épinglé dès l'enrôlement.
  const id = await createBinding(db, { issuerId, projectId, repository, repositoryId: repo.id ?? null, refPatterns: defaultRefPatterns(forge.kind, repo.defaultBranch) })
  if (!id && repo.id) {
    // Liaison déjà créée avec l'émetteur : épinglée si elle ne l'est pas encore.
    await db.query('UPDATE oidc_bindings SET repository_id = $3 WHERE issuer_id = $1 AND project_id = $2 AND repository_id IS NULL', [issuerId, projectId, repo.id])
  }
  return id
}

// --- JWKS -----------------------------------------------------------------------------------

interface IssuerKeys {
  id: string
  kind: OidcKind
  issuer: string
  audience: string
  enabled: boolean
  jwks: unknown
  fetched_at: Date | null
}

const lastRefresh = new Map<string, number>()

/** Tests : oublie les dates de rafraîchissement. */
export function resetJwksThrottle(): void {
  lastRefresh.clear()
}

/** Découverte OIDC puis JWKS, en HTTPS, même origine que l'émetteur. */
export async function fetchJwks(issuer: string): Promise<unknown> {
  const origin = new URL(issuer).origin
  const req = { authScheme: 'Bearer' as const, maxBytes: MAX_JWKS_BYTES, timeoutMs: 10_000 }
  let jwksUri: string
  try {
    const { data } = await forgeGetJson<{ issuer?: unknown, jwks_uri?: unknown }>(`${issuer}/.well-known/openid-configuration`, req)
    if (data?.issuer !== issuer || typeof data.jwks_uri !== 'string') throw new JwtError('E_OIDC_JWKS')
    const u = new URL(data.jwks_uri)
    if (u.protocol !== 'https:' || u.origin !== origin || u.username || u.password) throw new JwtError('E_OIDC_JWKS')
    jwksUri = u.toString()
  }
  catch (err) {
    if (err instanceof JwtError) throw err
    throw new JwtError('E_OIDC_JWKS')
  }
  try {
    const { data } = await forgeGetJson<{ keys?: unknown }>(jwksUri, req)
    if (!data || !Array.isArray(data.keys)) throw new JwtError('E_OIDC_JWKS')
    return { keys: data.keys.slice(0, 50) }
  }
  catch (err) {
    if (err instanceof JwtError) throw err
    throw new JwtError('E_OIDC_JWKS')
  }
}

async function refreshJwks(db: Queryable, row: IssuerKeys, now: number): Promise<unknown> {
  lastRefresh.set(row.id, now)
  const jwks = await fetchJwks(row.issuer)
  await db.query('UPDATE oidc_issuers SET jwks = $2, jwks_fetched_at = to_timestamp($3::double precision / 1000) WHERE id = $1', [row.id, JSON.stringify(jwks), now])
  return jwks
}

/** JWKS en cache ; rafraîchi s'il a plus d'une heure, ou sur `kid` inconnu (une fois par minute au plus). */
async function keysFor(db: Queryable, row: IssuerKeys, kid: string | null, now: number): Promise<unknown> {
  const age = row.fetched_at ? now - row.fetched_at.getTime() : Infinity
  const throttled = now - (lastRefresh.get(row.id) ?? 0) < JWKS_REFRESH_MIN_MS
  if (!row.jwks || age > JWKS_TTL_MS) {
    if (throttled && row.jwks) return row.jwks
    if (throttled) throw new JwtError('E_OIDC_JWKS')
    return refreshJwks(db, row, now)
  }
  if (!hasKid(row.jwks, kid) && !throttled) return refreshJwks(db, row, now)
  return row.jwks
}

// --- Vérification ---------------------------------------------------------------------------

export interface OidcMatch {
  bindingId: string
  projectId: string
  scopes: string[]
}

export interface OidcResult {
  issuerId: string
  kind: OidcKind
  issuer: string
  claims: CiClaims
  matches: OidcMatch[]
}

/** Partie de l'erreur utile à l'audit (jamais le jeton). */
export class OidcRefusal extends JwtError {
  constructor(code: JwtError['code'], public readonly context: { issuer?: string, repository?: string, ref?: string } = {}) {
    super(code)
  }
}

/**
 * Vérifie un jeton OIDC de CI : émetteur connu et actif, signature par son
 * JWKS, iss/aud/exp/nbf, revendications de dépôt et de ref comparées aux
 * liaisons. Rend les liaisons qui correspondent (au moins une), sinon lève.
 */
export async function verifyOidcToken(db: Queryable, raw: string, now = Date.now()): Promise<OidcResult> {
  const jwt = parseJwt(raw)
  const iss = jwt.claims.iss
  if (typeof iss !== 'string' || iss.length > 255) throw new OidcRefusal('E_OIDC_ISSUER')
  const { rows } = await db.query<IssuerKeys>(
    'SELECT id::text, kind, issuer, audience, enabled, jwks, jwks_fetched_at AS fetched_at FROM oidc_issuers WHERE issuer = $1', [iss])
  const row = rows[0]
  if (!row) throw new OidcRefusal('E_OIDC_ISSUER')
  const ctx = { issuer: row.issuer }
  if (!row.enabled) throw new OidcRefusal('E_OIDC_DISABLED', ctx)
  try {
    const jwks = await keysFor(db, row, jwt.header.kid, now)
    verifySignature(jwt, candidateKeys(jwks, jwt.header))
    checkClaims(jwt.claims, { issuer: row.issuer, audience: row.audience, nowS: Math.floor(now / 1000) })
  }
  catch (err) {
    if (err instanceof JwtError) throw new OidcRefusal(err.code, ctx)
    throw err
  }
  let claims: CiClaims
  try {
    claims = ciClaims(row.kind, jwt.claims)
  }
  catch {
    throw new OidcRefusal('E_OIDC_CLAIMS', ctx)
  }
  const b = await db.query<{ id: string, project_id: string, repository_id: string | null, ref_patterns: string[], scopes: string[] }>(
    `SELECT b.id::text, b.project_id::text, b.repository_id, b.ref_patterns, b.scopes FROM oidc_bindings b
       JOIN projects p ON p.id = b.project_id
      WHERE b.issuer_id = $1 AND lower(b.repository) = lower($2) AND p.archived_at IS NULL`, [row.id, claims.repository])
  const refCtx = { ...ctx, repository: claims.repository, ref: claims.ref }
  const byRef = b.rows.filter(r => r.ref_patterns.some(p => refMatches(p, claims.ref)))
  if (!byRef.length) throw new OidcRefusal('E_OIDC_BINDING', refCtx)
  // Épingle de l'identifiant immuable : un dépôt recréé sous le même nom
  // (autre identifiant) ne passe pas ; l'épingle n'est jamais écrasée ici.
  const pinned = byRef.filter(r => r.repository_id === null || r.repository_id === claims.repositoryId)
  if (!pinned.length) throw new OidcRefusal('E_OIDC_REPOSITORY_ID', refCtx)
  if (claims.repositoryId) {
    const toPin = pinned.filter(r => r.repository_id === null).map(r => r.id)
    if (toPin.length) await db.query('UPDATE oidc_bindings SET repository_id = $2 WHERE id = ANY($1::uuid[]) AND repository_id IS NULL', [toPin, claims.repositoryId])
  }
  const matches = pinned.map(r => ({ bindingId: r.id, projectId: r.project_id, scopes: r.scopes }))
  return { issuerId: row.id, kind: row.kind, issuer: row.issuer, claims, matches }
}
