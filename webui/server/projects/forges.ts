// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Forges enregistrées : ajout avec vérification immédiate, modification,
// retrait, lancement de la découverte. Le jeton est chiffré (contrat 2), son
// indice seul est montré ; l'audit ne reçoit jamais de valeur.

import type pg from 'pg'
import type { Queryable } from '../utils/db'
import { writeAudit, type AuditActor } from '../utils/audit'
import { encryptSecret, rotateSecret, secretInfo } from '../utils/secrets'
import { FORGE_COLUMNS, forgeClient, getForge, normalizeBaseUrl, type ForgeRow } from '../forges'
import { discoverForge } from './discover'
import { mapProjectError, projectError } from './errors'
import { dropUnusedCredential } from './service'
import { ensureServiceApp } from '../forges/apps'
import { forgeIntegration } from '../forges/status'

export async function forgeView(db: Queryable, f: ForgeRow) {
  const { rows } = await db.query<{ n: string }>(`SELECT count(*) AS n FROM projects WHERE forge_id = $1 AND archived_at IS NULL`, [f.id])
  const secret = await secretInfo(db, f.credential_id)
  return {
    id: f.id,
    kind: f.kind,
    name: f.name,
    base_url: f.base_url,
    discovery: f.discovery,
    has_token: !!f.credential_id,
    token_hint: secret?.hint ?? null,
    token_user: secret?.username ?? null,
    last_discovery_at: f.last_discovery_at,
    last_error: f.last_error,
    created_at: f.created_at,
    projects: Number(rows[0]?.n ?? 0),
    // 0.7 (D, J1) : application ou jeton de service, mode poussé ou tiré.
    integration: await forgeIntegration(db, f.id),
  }
}
export type ForgeView = Awaited<ReturnType<typeof forgeView>>

export async function listForges(db: Queryable): Promise<ForgeView[]> {
  const { rows } = await db.query<ForgeRow>(`SELECT ${FORGE_COLUMNS} FROM forges ORDER BY name`)
  return Promise.all(rows.map(f => forgeView(db, f)))
}

/** Utilisateur HTTPS du jeton pour le clone : GitHub impose x-access-token. */
function cloneUsername(kind: ForgeRow['kind'], login: string | null): string | null {
  if (kind === 'github') return 'x-access-token'
  return login && /^[^:\s]{1,255}$/.test(login) ? login : null
}

async function verify(kind: ForgeRow['kind'], baseUrl: string, token: string | null): Promise<string | null> {
  try {
    return (await forgeClient({ kind, base_url: baseUrl, token }).check()).login
  }
  catch (err) {
    mapProjectError(err)
  }
}

export async function createForge(
  db: Queryable,
  body: { kind: ForgeRow['kind'], name: string, base_url: string, token?: string, discovery: boolean },
  actor: AuditActor,
): Promise<{ forge: ForgeView, login: string | null }> {
  let baseUrl: string
  try {
    baseUrl = normalizeBaseUrl(body.base_url)
  }
  catch (err) {
    mapProjectError(err)
  }
  const taken = await db.query(`SELECT 1 FROM forges WHERE lower(name) = lower($1)`, [body.name])
  if (taken.rowCount) throw projectError(409, 'E_FORGE_NAME_TAKEN')
  const login = await verify(body.kind, baseUrl, body.token ?? null)
  const credentialId = body.token
    ? await encryptSecret(db, { kind: 'token', value: body.token, username: cloneUsername(body.kind, login), createdBy: actor.userId ?? null })
    : null
  let id: string
  try {
    const { rows } = await db.query<{ id: string }>(
      `INSERT INTO forges (kind, name, base_url, credential_id, discovery, created_by) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id::text`,
      [body.kind, body.name, baseUrl, credentialId, body.discovery, actor.userId ?? null],
    )
    id = rows[0]!.id
  }
  catch (err) {
    await dropUnusedCredential(db, credentialId)
    if ((err as { code?: string }).code === '23505') throw projectError(409, 'E_FORGE_NAME_TAKEN')
    throw err
  }
  await writeAudit(db, {
    actor, action: 'forge.create', outcome: 'success', targetType: 'forge', targetId: id,
    details: { name: body.name, kind: body.kind, base_url: baseUrl, with_token: !!body.token, discovery: body.discovery },
  })
  // J1 : jeton de service → secret de webhook ; les webhooks sont posés à la découverte.
  await ensureServiceApp(db, { id, kind: body.kind, credential_id: credentialId }, actor.userId ?? null)
  return { forge: await forgeView(db, (await getForge(db, id))!), login }
}

export async function updateForge(
  db: Queryable,
  forge: ForgeRow,
  body: { name?: string, token?: string | null, discovery?: boolean },
  actor: AuditActor,
): Promise<ForgeView> {
  if (body.name !== undefined && body.name.toLowerCase() !== forge.name.toLowerCase()) {
    const taken = await db.query(`SELECT 1 FROM forges WHERE lower(name) = lower($1) AND id <> $2`, [body.name, forge.id])
    if (taken.rowCount) throw projectError(409, 'E_FORGE_NAME_TAKEN')
  }
  let credentialId = forge.credential_id
  if (body.token) {
    const login = await verify(forge.kind, forge.base_url, body.token)
    if (credentialId) await rotateSecret(db, credentialId, body.token, cloneUsername(forge.kind, login))
    else credentialId = await encryptSecret(db, { kind: 'token', value: body.token, username: cloneUsername(forge.kind, login), createdBy: actor.userId ?? null })
  }
  else if (body.token === null) {
    credentialId = null
  }
  await db.query(
    `UPDATE forges SET name = COALESCE($2, name), discovery = COALESCE($3, discovery), credential_id = $4,
                       last_error = CASE WHEN $5 THEN NULL ELSE last_error END
      WHERE id = $1`,
    [forge.id, body.name ?? null, body.discovery ?? null, credentialId, body.token !== undefined],
  )
  if (body.token === null && forge.credential_id) {
    // Les projets de la forge qui partageaient ce jeton le perdent aussi.
    await db.query(`UPDATE projects SET credential_id = NULL WHERE forge_id = $1 AND credential_id = $2`, [forge.id, forge.credential_id])
    await dropUnusedCredential(db, forge.credential_id)
  }
  else if (credentialId && credentialId !== forge.credential_id) {
    await db.query(`UPDATE projects SET credential_id = $2 WHERE forge_id = $1 AND credential_id IS NULL`, [forge.id, credentialId])
  }
  await writeAudit(db, {
    actor, action: 'forge.update', outcome: 'success', targetType: 'forge', targetId: forge.id,
    details: { name: body.name, discovery: body.discovery, token: body.token === undefined ? 'unchanged' : body.token === null ? 'removed' : 'replaced' },
  })
  await ensureServiceApp(db, { id: forge.id, kind: forge.kind, credential_id: credentialId }, actor.userId ?? null)
  return forgeView(db, (await getForge(db, forge.id))!)
}

export async function deleteForge(db: Queryable, forge: ForgeRow, actor: AuditActor): Promise<void> {
  const { rows } = await db.query<{ n: string }>(`SELECT count(*) AS n FROM projects WHERE forge_id = $1`, [forge.id])
  const n = Number(rows[0]?.n ?? 0)
  if (n > 0) throw projectError(409, 'E_FORGE_IN_USE', { projects: n })
  await db.query(`DELETE FROM forges WHERE id = $1`, [forge.id])
  await dropUnusedCredential(db, forge.credential_id)
  await writeAudit(db, {
    actor, action: 'forge.delete', outcome: 'success', targetType: 'forge', targetId: forge.id,
    details: { name: forge.name, kind: forge.kind },
  })
}

/** Lance la découverte en arrière-plan (la réponse HTTP n'attend pas). */
export function startDiscovery(pool: pg.Pool, forgeId: string, actor: AuditActor): void {
  void (async () => {
    const forge = await getForge(pool, forgeId)
    if (forge) await discoverForge(pool, forge, { userId: actor.userId, username: actor.username })
  })().catch(err => console.error('[forges] discovery failed:', (err as Error)?.message))
}
