// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// J1 — application de forge en un clic (docs/FORGES.md).
// - GitHub : flux du manifeste d'application. La console prépare le manifeste
//   (droits minimaux, webhook et redirection vers elle-même), l'administrateur
//   le confirme sur GitHub, qui rend un code ; la console l'échange contre
//   l'identifiant de l'application, sa clé privée et le secret du webhook,
//   chiffrés dans credentials. Aucun jeton à copier. Les jetons d'accès sont
//   ceux de l'installation (une heure), émis à la demande par la clé.
// - Forgejo et GitLab : aucun manifeste ; un compte de service à jeton de
//   portée réduite (forgejo-token, gitlab-token). La console crée elle-même le
//   secret du webhook et les webhooks des dépôts enrôlés.

import { createHmac, createPrivateKey, randomBytes, randomUUID, sign, timingSafeEqual } from 'node:crypto'
import type { Queryable } from '../utils/db'
import { writeAudit, type AuditActor } from '../utils/audit'
import { decryptSecret, encryptSecret, loadSecretKey, rotateSecret } from '../utils/secrets'
import { ForgeError, forgeSendJson, normalizeBaseUrl } from './http'
import { githubApiBase } from './github'

export type ForgeAppKind = 'github-app' | 'forgejo-oauth' | 'gitlab-oauth' | 'forgejo-token' | 'gitlab-token'

export interface ForgeAppRow {
  forge_id: string
  kind: ForgeAppKind
  app_id: string | null
  client_id: string | null
  slug: string | null
  key_credential_id: string | null
  webhook_credential_id: string | null
  installation_ids: string[]
  permissions: Record<string, unknown>
}

/** Droits demandés à GitHub : statuts, checks, contenus en lecture, PR en écriture (commentaires et revues). */
export const GITHUB_APP_PERMISSIONS = {
  metadata: 'read',
  contents: 'read',
  statuses: 'write',
  checks: 'write',
  pull_requests: 'write',
} as const
export const GITHUB_APP_EVENTS = ['push', 'pull_request', 'issue_comment', 'repository'] as const

/** Portées exactes du jeton de service, affichées dans la console (J1). */
export const SERVICE_TOKEN_SCOPES: Record<'forgejo' | 'gitlab', string[]> = {
  forgejo: ['read:user', 'read:organization', 'write:repository', 'write:issue'],
  gitlab: ['api', 'read_repository'],
}

export async function getForgeApp(db: Queryable, forgeId: string): Promise<ForgeAppRow | null> {
  const r = await db.query<ForgeAppRow>(
    `SELECT forge_id::text, kind, app_id, client_id, slug, key_credential_id::text, webhook_credential_id::text,
            installation_ids, permissions FROM forge_apps WHERE forge_id = $1`, [forgeId])
  return r.rows[0] ?? null
}

/** Secret du webhook d'une forge (null : aucun webhook configuré, mode tiré). */
export async function webhookSecret(db: Queryable, forgeId: string): Promise<string | null> {
  const app = await getForgeApp(db, forgeId)
  if (!app?.webhook_credential_id) return null
  return (await decryptSecret(db, app.webhook_credential_id)).value
}

/** Secret aléatoire de webhook : 32 octets, hexadécimal. */
export function newWebhookSecret(): string {
  return randomBytes(32).toString('hex')
}

/**
 * Forgejo et GitLab (J1) : forge enregistrée avec un jeton de service → une
 * ligne forge_apps et un secret de webhook, créés une fois. Sans jeton, rien
 * (lecture publique seulement, mode tiré).
 */
export async function ensureServiceApp(db: Queryable, forge: { id: string, kind: string, credential_id: string | null }, createdBy: number | null): Promise<ForgeAppRow | null> {
  if (forge.kind === 'github' || !forge.credential_id) return getForgeApp(db, forge.id)
  const existing = await getForgeApp(db, forge.id)
  if (existing) return existing
  const kind = forge.kind === 'gitlab' ? 'gitlab-token' : 'forgejo-token'
  const secretId = await encryptSecret(db, { kind: 'webhook-secret', value: newWebhookSecret(), createdBy })
  await db.query(
    `INSERT INTO forge_apps (forge_id, kind, webhook_credential_id, permissions, created_by)
     VALUES ($1, $2, $3, $4, $5) ON CONFLICT (forge_id) DO NOTHING`,
    [forge.id, kind, secretId, JSON.stringify({ scopes: SERVICE_TOKEN_SCOPES[forge.kind === 'gitlab' ? 'gitlab' : 'forgejo'] }), createdBy])
  return getForgeApp(db, forge.id)
}

// ------------------------------------------------------------------- GitHub

const STATE_TTL_MS = 30 * 60_000

interface ManifestState {
  /** Identifiant de la forge à créer (connu d'avance : il figure dans l'URL du webhook). */
  forge_id: string
  base_url: string
  org: string | null
  name: string
  user_id: number
  exp: number
}

function b64url(buf: Buffer | string): string {
  return Buffer.from(buf).toString('base64url')
}

async function stateKey(): Promise<Buffer> {
  return createHmac('sha256', await loadSecretKey()).update('scanoria:github-manifest-state').digest()
}

/** Jeton d'état du flux de manifeste : signé (HMAC), lié à l'administrateur, 30 minutes. */
export async function signManifestState(s: ManifestState): Promise<string> {
  const body = b64url(JSON.stringify(s))
  return `${body}.${b64url(createHmac('sha256', await stateKey()).update(body).digest())}`
}

export async function verifyManifestState(token: string, userId: number, now = Date.now()): Promise<ManifestState | null> {
  const m = /^([A-Za-z0-9_-]{10,2000})\.([A-Za-z0-9_-]{43})$/.exec(token)
  if (!m) return null
  const expected = createHmac('sha256', await stateKey()).update(m[1]!).digest()
  const got = Buffer.from(m[2]!, 'base64url')
  if (got.length !== expected.length || !timingSafeEqual(got, expected)) return null
  try {
    const s = JSON.parse(Buffer.from(m[1]!, 'base64url').toString('utf8')) as ManifestState
    if (s.user_id !== userId || typeof s.exp !== 'number' || s.exp < now) return null
    return s
  }
  catch {
    return null
  }
}

const ORG_RE = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$/

/** Adresse de création d'une application GitHub (organisation, sinon compte de l'administrateur). */
export function manifestTarget(baseUrl: string, org: string | null): string {
  const web = baseUrl.replace(/\/api\/v3$/, '')
  const root = new URL(web).hostname === 'api.github.com' ? 'https://github.com' : web
  return org ? `${root}/organizations/${org}/settings/apps/new` : `${root}/settings/apps/new`
}

/**
 * Prépare le flux du manifeste : manifeste à poster sur GitHub et jeton
 * d'état. consoleUrl : adresse de la console vue par GitHub (redirection,
 * webhook) ; en mode tiré l'appliance n'est pas joignable par la forge, le
 * webhook reste déclaré mais inactif et l'interrogation le remplace.
 */
export async function startGithubManifest(input: { base_url: string, org?: string | null, name: string, consoleUrl: string, userId: number, reachable: boolean }) {
  const baseUrl = normalizeBaseUrl(input.base_url)
  if (input.org && !ORG_RE.test(input.org)) throw new ForgeError('E_FORGE_INPUT')
  const forgeId = randomUUID()
  const state = await signManifestState({
    forge_id: forgeId, base_url: baseUrl, org: input.org ?? null, name: input.name.slice(0, 200), user_id: input.userId, exp: Date.now() + STATE_TTL_MS,
  })
  const host = new URL(input.consoleUrl).hostname
  const manifest = {
    name: `Scanoria ${host}`.slice(0, 34),
    url: input.consoleUrl,
    hook_attributes: { url: `${input.consoleUrl}/api/forges/${forgeId}/webhook`, active: input.reachable },
    redirect_url: `${input.consoleUrl}/api/forges/github/callback`,
    setup_url: `${input.consoleUrl}/api/forges/github/setup`,
    setup_on_update: true,
    public: false,
    default_permissions: GITHUB_APP_PERMISSIONS,
    default_events: GITHUB_APP_EVENTS,
  }
  return { forge_id: forgeId, action: `${manifestTarget(baseUrl, input.org ?? null)}?state=${encodeURIComponent(state)}`, manifest, state }
}

export interface ManifestConversion {
  id: number
  slug: string
  client_id: string
  client_secret: string
  webhook_secret: string
  pem: string
  owner: string | null
}

/** Échange le code rendu par GitHub (une heure de validité, usage unique). */
export async function convertManifest(baseUrl: string, code: string): Promise<ManifestConversion> {
  if (!/^[A-Za-z0-9_-]{8,128}$/.test(code)) throw new ForgeError('E_FORGE_INPUT')
  const { data } = await forgeSendJson<Record<string, unknown>>(`${githubApiBase(baseUrl)}/app-manifests/${code}/conversions`, {
    authScheme: 'Bearer', accept: 'application/vnd.github+json', headers: { 'x-github-api-version': '2022-11-28' },
  }, { method: 'POST' })
  const d = data ?? {}
  const pem = typeof d.pem === 'string' ? d.pem : ''
  if (typeof d.id !== 'number' || typeof d.slug !== 'string' || !/^[a-z0-9-]{1,100}$/.test(d.slug)
    || typeof d.client_id !== 'string' || typeof d.client_secret !== 'string' || typeof d.webhook_secret !== 'string'
    || !/^-----BEGIN (RSA )?PRIVATE KEY-----/.test(pem)) {
    throw new ForgeError('E_FORGE_RESPONSE')
  }
  try {
    createPrivateKey(pem)
  }
  catch {
    throw new ForgeError('E_FORGE_RESPONSE')
  }
  const owner = (d.owner as { login?: unknown } | null)?.login
  return {
    id: d.id, slug: d.slug, client_id: d.client_id.slice(0, 128), client_secret: d.client_secret, webhook_secret: d.webhook_secret, pem,
    owner: typeof owner === 'string' && ORG_RE.test(owner) ? owner : null,
  }
}

/** Enregistre la forge GitHub et son application ; la découverte attend l'installation. */
export async function saveGithubApp(db: Queryable, state: ManifestState, conv: ManifestConversion, actor: AuditActor): Promise<string> {
  const createdBy = actor.userId ?? null
  const keyId = await encryptSecret(db, { kind: 'app-key', value: conv.pem, createdBy })
  const hookId = await encryptSecret(db, { kind: 'webhook-secret', value: conv.webhook_secret, createdBy })
  const oauthId = await encryptSecret(db, { kind: 'oauth-secret', value: conv.client_secret, createdBy })
  let name = state.name
  const taken = await db.query('SELECT 1 FROM forges WHERE lower(name) = lower($1)', [name])
  if (taken.rowCount) name = `${name.slice(0, 180)} (${conv.slug})`.slice(0, 200)
  await db.query(
    `INSERT INTO forges (id, kind, name, base_url, credential_id, discovery, created_by) VALUES ($1, 'github', $2, $3, NULL, true, $4)`,
    [state.forge_id, name, state.base_url, createdBy])
  await db.query(
    `INSERT INTO forge_apps (forge_id, kind, app_id, client_id, slug, key_credential_id, webhook_credential_id, permissions, created_by)
     VALUES ($1, 'github-app', $2, $3, $4, $5, $6, $7, $8)`,
    [state.forge_id, String(conv.id), conv.client_id, conv.slug, keyId, hookId,
      JSON.stringify({ ...GITHUB_APP_PERMISSIONS, events: GITHUB_APP_EVENTS, oauth_credential_id: oauthId, owner: conv.owner }), createdBy])
  await writeAudit(db, {
    actor, action: 'forge.app-create', outcome: 'success', targetType: 'forge', targetId: state.forge_id,
    details: { kind: 'github-app', slug: conv.slug, app_id: conv.id, owner: conv.owner, permissions: GITHUB_APP_PERMISSIONS },
  })
  return state.forge_id
}

/** Adresse d'installation de l'application (dépôts de l'organisation). */
export function installUrl(baseUrl: string, slug: string): string {
  const root = manifestTarget(baseUrl, null).replace(/\/settings\/apps\/new$/, '')
  return `${root}/apps/${encodeURIComponent(slug)}/installations/new`
}

/** JWT de l'application (RS256, dix minutes au plus, horloge tolérée d'une minute). */
export function appJwt(appId: string, pem: string, now = Math.floor(Date.now() / 1000)): string {
  const head = b64url(JSON.stringify({ alg: 'RS256', typ: 'JWT' }))
  const body = b64url(JSON.stringify({ iat: now - 60, exp: now + 540, iss: appId }))
  const sig = sign('RSA-SHA256', Buffer.from(`${head}.${body}`), createPrivateKey(pem))
  return `${head}.${body}.${b64url(sig)}`
}

const tokenCache = new Map<string, { token: string, expires: number }>()

/** Vide le cache des jetons d'installation (tests). */
export function clearInstallationTokens(): void {
  tokenCache.clear()
}

/** Jeton d'installation (une heure), mis en cache jusqu'à cinq minutes de son échéance. */
export async function installationToken(db: Queryable, baseUrl: string, app: ForgeAppRow, now = Date.now()): Promise<string | null> {
  const installation = app.installation_ids[0]
  if (!app.app_id || !app.key_credential_id || !installation || !/^\d{1,20}$/.test(installation)) return null
  const key = `${app.forge_id}:${installation}`
  const cached = tokenCache.get(key)
  if (cached && cached.expires - 5 * 60_000 > now) return cached.token
  const pem = (await decryptSecret(db, app.key_credential_id)).value
  const { data } = await forgeSendJson<{ token?: unknown, expires_at?: unknown }>(
    `${githubApiBase(baseUrl)}/app/installations/${installation}/access_tokens`,
    { token: appJwt(app.app_id, pem, Math.floor(now / 1000)), authScheme: 'Bearer', accept: 'application/vnd.github+json', headers: { 'x-github-api-version': '2022-11-28' } },
    { method: 'POST' })
  if (typeof data?.token !== 'string' || data.token.length < 20 || data.token.length > 255) throw new ForgeError('E_FORGE_RESPONSE')
  const expires = typeof data.expires_at === 'string' ? Date.parse(data.expires_at) : now + 3600_000
  tokenCache.set(key, { token: data.token, expires: Number.isNaN(expires) ? now + 3600_000 : expires })
  return data.token
}

/** Installation reçue (webhook « installation » ou retour de setup_url) : retenue une fois. */
export async function addInstallation(db: Queryable, forgeId: string, installationId: string, actor: AuditActor): Promise<boolean> {
  if (!/^\d{1,20}$/.test(installationId)) return false
  const r = await db.query(
    `UPDATE forge_apps SET installation_ids = array_append(installation_ids, $2)
      WHERE forge_id = $1 AND kind = 'github-app' AND NOT ($2 = ANY(installation_ids)) AND cardinality(installation_ids) < 50`,
    [forgeId, installationId])
  if (!r.rowCount) return false
  await writeAudit(db, { actor, action: 'forge.app-install', outcome: 'success', targetType: 'forge', targetId: forgeId, details: { installation_id: installationId } })
  return true
}

/**
 * Jeton de clonage des projets d'une forge GitHub par application : le jeton
 * d'installation, recopié dans le secret de la forge (lu par le worker pour
 * le clonage) toutes les 30 minutes. Sans installation, rien.
 */
export async function refreshAppCredential(db: Queryable, forge: { id: string, base_url: string, credential_id: string | null }, now = Date.now()): Promise<boolean> {
  const app = await getForgeApp(db, forge.id)
  if (app?.kind !== 'github-app') return false
  if (forge.credential_id) {
    const r = await db.query<{ fresh: boolean }>(
      `SELECT COALESCE(rotated_at, created_at) > $2::timestamptz - interval '30 minutes' AS fresh FROM credentials WHERE id = $1`,
      [forge.credential_id, new Date(now).toISOString()])
    if (r.rows[0]?.fresh) return false
  }
  const token = await installationToken(db, forge.base_url, app, now)
  if (!token) return false
  if (forge.credential_id) {
    await rotateSecret(db, forge.credential_id, token, 'x-access-token')
  }
  else {
    const id = await encryptSecret(db, { kind: 'token', value: token, username: 'x-access-token' })
    await db.query('UPDATE forges SET credential_id = $2 WHERE id = $1', [forge.id, id])
    await db.query('UPDATE projects SET credential_id = $2 WHERE forge_id = $1 AND credential_id IS NULL', [forge.id, id])
  }
  return true
}
