// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// POST /api/forges/:id/webhook (J1) : webhooks de Forgejo, GitHub et GitLab.
// 1. taille bornée (1 Mo) ; 2. signature vérifiée à temps constant avec le
// secret de la forge (forge_apps) ; 3. identifiant de livraison unique : un
// rejeu est refusé (webhook_deliveries) ; 4. évènements utiles seulement :
// push, PR ouverte ou mise à jour, commentaire de PR, installation et dépôt
// (GitHub). Un webhook non signé, de signature fausse, rejoué ou trop gros
// est rejeté et compté (webhook_deliveries, statut « rejected », sous un
// identifiant aléatoire : un faux ne peut pas « brûler » un vrai identifiant).
// Le contenu n'est jamais cru sur parole : la PR est relue dans la forge.

import { createHash, randomUUID } from 'node:crypto'
import type { IncomingMessage } from 'node:http'
import type pg from 'pg'
import type { Queryable } from '../utils/db'
import { getForge, isSafeRef } from './index'
import { webhookSecret, addInstallation, refreshAppCredential, removeInstallation } from './apps'
import { deliveryId, MAX_WEBHOOK_BYTES, verifyWebhookSignature, webhookEvent, type HeaderBag, type WebhookEvent } from './signature'
import { projectForge } from './context'
import { enqueuePullRequestScan, handlePrComment, projectForRepo } from './pr'
import { enqueueScan } from '../scans/enqueue'
import { loginOf } from './pr-types'

type Db = Queryable & Pick<pg.Pool, 'connect'>

export interface WebhookOutcome {
  status: number
  code: 'accepted' | 'ignored' | 'E_WEBHOOK_NOT_FOUND' | 'E_WEBHOOK_TOO_LARGE' | 'E_WEBHOOK_SIGNATURE' | 'E_WEBHOOK_NO_SECRET'
    | 'E_WEBHOOK_DELIVERY' | 'E_WEBHOOK_REPLAY' | 'E_WEBHOOK_PAYLOAD'
  /** Travail lancé après la réponse (la forge n'attend pas) ; attendu par les tests. */
  work?: Promise<string>
}

/** Corps lu au plus max octets ; 'too-large' au-delà ou si content-length est invalide. */
export async function readBounded(req: IncomingMessage, max: number): Promise<Buffer | 'too-large'> {
  const declared = req.headers['content-length']
  if (declared !== undefined && (!/^\d{1,12}$/.test(declared) || Number(declared) > max)) return 'too-large'
  const chunks: Buffer[] = []
  let size = 0
  for await (const chunk of req) {
    size += (chunk as Buffer).length
    if (size > max) {
      req.destroy()
      return 'too-large'
    }
    chunks.push(chunk as Buffer)
  }
  return Buffer.concat(chunks)
}

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
const SHA_RE = /^[0-9a-f]{40,64}$/
const ZERO_RE = /^0+$/

/** Rejets gardés en base par forge et par heure ; au-delà, seulement journalisés (flot non signé). */
export const MAX_REJECTS_PER_HOUR = 200

async function reject(db: Queryable, forgeId: string, event: string, detail: string): Promise<void> {
  await db.query(
    `INSERT INTO webhook_deliveries (forge_id, delivery_id, event, status, detail)
     SELECT $1, $2, $3, 'rejected', $4
      WHERE (SELECT count(*) FROM webhook_deliveries
              WHERE forge_id = $1 AND status = 'rejected' AND received_at > now() - interval '1 hour') < $5`,
    [forgeId, `x-${randomUUID()}`, (event || 'unknown').slice(0, 64), detail.slice(0, 500), MAX_REJECTS_PER_HOUR]).catch(() => {})
}

/** Reçoit un webhook ; ne lève jamais vers la forge (codes HTTP seulement). */
export async function receiveWebhook(db: Db, forgeId: string, headers: HeaderBag, body: Buffer | null, log: (m: string) => void = () => {}): Promise<WebhookOutcome> {
  if (!UUID_RE.test(forgeId)) return { status: 404, code: 'E_WEBHOOK_NOT_FOUND' }
  const forge = await getForge(db, forgeId)
  if (!forge) return { status: 404, code: 'E_WEBHOOK_NOT_FOUND' }
  const { raw, event } = webhookEvent(forge.kind, headers)
  if (!body || body.length > MAX_WEBHOOK_BYTES) {
    await reject(db, forge.id, raw, 'too-large')
    return { status: 413, code: 'E_WEBHOOK_TOO_LARGE' }
  }
  const secret = await webhookSecret(db, forge.id).catch(() => null)
  if (!secret) {
    await reject(db, forge.id, raw, 'no-secret')
    return { status: 403, code: 'E_WEBHOOK_NO_SECRET' }
  }
  if (!verifyWebhookSignature(forge.kind, headers, body, secret)) {
    await reject(db, forge.id, raw, 'signature')
    return { status: 401, code: 'E_WEBHOOK_SIGNATURE' }
  }
  const delivery = deliveryId(forge.kind, headers)
  if (!delivery) {
    await reject(db, forge.id, raw, 'delivery-id')
    return { status: 400, code: 'E_WEBHOOK_DELIVERY' }
  }
  let payload: unknown
  try {
    payload = JSON.parse(body.toString('utf8'))
  }
  catch {
    await reject(db, forge.id, raw, 'payload')
    return { status: 400, code: 'E_WEBHOOK_PAYLOAD' }
  }
  // L'identifiant de livraison n'est pas couvert par la signature : le corps
  // signé l'est, donc un même corps présenté sous un autre identifiant est
  // aussi un rejeu (empreinte du corps, ligne « body-seen »).
  const bodyKey = `body:${createHash('sha256').update(body).digest('hex')}`
  const ins = await db.query(
    `WITH seen AS (
       INSERT INTO webhook_deliveries (forge_id, delivery_id, event, status, detail) VALUES ($1, $5, 'body-seen', 'ignored', NULL)
       ON CONFLICT (forge_id, delivery_id) DO NOTHING RETURNING 1)
     INSERT INTO webhook_deliveries (forge_id, delivery_id, event, status, detail)
     SELECT $1, $2, $3, $4, NULL WHERE EXISTS (SELECT 1 FROM seen)
     ON CONFLICT (forge_id, delivery_id) DO NOTHING`,
    [forge.id, delivery, (raw || 'unknown').slice(0, 64), event ? 'accepted' : 'ignored', bodyKey])
  if (!ins.rowCount) {
    // L'empreinte a pu être inscrite seule (identifiant déjà vu) : on la laisse, le corps est connu.
    await reject(db, forge.id, raw, `replay ${delivery}`)
    return { status: 409, code: 'E_WEBHOOK_REPLAY' }
  }
  if (!event) return { status: 202, code: 'ignored' }
  const work = handleEvent(db, forge.id, event, payload)
    .then(async (what) => {
      if (what !== 'ok') await db.query('UPDATE webhook_deliveries SET detail = $3 WHERE forge_id = $1 AND delivery_id = $2', [forge.id, delivery, what.slice(0, 500)]).catch(() => {})
      return what
    })
    .catch(async (err: unknown) => {
      log(`webhook ${delivery}: ${(err as Error)?.message}`)
      // Échec de traitement (forge momentanément injoignable…) : la livraison
      // est oubliée, pour que la redélivrance de la forge soit acceptée.
      await db.query('DELETE FROM webhook_deliveries WHERE forge_id = $1 AND delivery_id = ANY($2::text[])', [forge.id, [delivery, bodyKey]]).catch(() => {})
      return 'error'
    })
  return { status: 202, code: 'accepted', work }
}

const str = (v: unknown): string | null => (typeof v === 'string' ? v : null)

/** Dépôt de l'évènement (nom complet), selon la forge. */
function repoOf(p: Record<string, unknown>): string | null {
  const repo = p.repository as { full_name?: unknown } | undefined
  const project = p.project as { path_with_namespace?: unknown } | undefined
  return str(repo?.full_name) ?? str(project?.path_with_namespace)
}

async function handleEvent(db: Db, forgeId: string, event: WebhookEvent, payload: unknown): Promise<string> {
  const p = (payload && typeof payload === 'object' ? payload : {}) as Record<string, unknown>
  const forge = (await getForge(db, forgeId))!
  if (event === 'ping') return 'ok'

  if (event === 'installation') {
    const inst = p.installation as { id?: unknown } | undefined
    const id = typeof inst?.id === 'number' ? String(inst.id) : null
    if (!id) return 'no-installation'
    if (p.action === 'deleted' || p.action === 'suspend') {
      await removeInstallation(db, forgeId, id, String(p.action), { type: 'system' })
      return `installation ${String(p.action).slice(0, 20)}`
    }
    await addInstallation(db, forgeId, id, { type: 'system' })
    await refreshAppCredential(db, forge)
    // Les dépôts de l'installation sont enrôlés à la prochaine découverte (immédiate).
    await db.query('UPDATE forges SET last_discovery_at = NULL WHERE id = $1', [forgeId])
    return 'ok'
  }

  const repo = repoOf(p)
  if (!repo) return 'no-repository'

  if (event === 'repository') {
    // Archivage ou désarchivage : repris par la découverte (suspension, J1).
    await db.query('UPDATE forges SET last_discovery_at = NULL WHERE id = $1', [forgeId])
    return 'ok'
  }

  const project = await projectForRepo(db, forgeId, repo)
  if (!project) return 'unknown-repository'
  const ctx = await projectForge(db, project.id)
  if (!ctx) return 'no-access'

  if (event === 'push') {
    const ref = str(p.ref) ?? ''
    const after = str(p.after) ?? str((p.checkout_sha as unknown)) ?? ''
    const branch = ref.startsWith('refs/heads/') ? ref.slice('refs/heads/'.length) : null
    if (!branch || !isSafeRef(branch) || !SHA_RE.test(after) || ZERO_RE.test(after)) return 'push-ignored'
    const tracked = await db.query<{ ok: boolean }>(
      `SELECT ($2 = default_branch OR $2 = ANY(tracked_branches)) AND schedule <> 'none' AS ok FROM projects WHERE id = $1`, [project.id, branch])
    if (!tracked.rows[0]?.ok) return 'branch-not-tracked'
    await enqueueScan(db, { projectId: project.id, ref: branch, commit: after, trigger: 'webhook' })
    return 'ok'
  }

  if (event === 'pull_request') {
    const number = prNumber(forge.kind, p)
    const action = forge.kind === 'gitlab' ? str((p.object_attributes as { action?: unknown } | undefined)?.action) : str(p.action)
    const wanted = forge.kind === 'gitlab' ? ['open', 'reopen', 'update'] : ['opened', 'reopened', 'synchronize', 'synchronized', 'ready_for_review', 'edited']
    if (!number || !action || !wanted.includes(action)) return 'pr-ignored'
    // La PR est relue dans la forge : têtes et base viennent de l'API, pas du webhook.
    const pr = await ctx.publisher.pullRequest(ctx.repo, number)
    await enqueuePullRequestScan(db, ctx, pr)
    return 'ok'
  }

  if (event === 'comment') {
    const c = commentOf(forge.kind, p)
    if (!c) return 'comment-ignored'
    return handlePrComment(db, ctx, c)
  }
  return 'ignored'
}

function prNumber(kind: string, p: Record<string, unknown>): number | null {
  const n = kind === 'gitlab'
    ? (p.object_attributes as { iid?: unknown } | undefined)?.iid
    : (p.pull_request as { number?: unknown } | undefined)?.number ?? p.number
  return typeof n === 'number' && Number.isInteger(n) && n > 0 ? n : null
}

/** Commentaire nouveau d'une PR, ou null (ticket, modification, suppression). */
function commentOf(kind: string, p: Record<string, unknown>) {
  if (kind === 'gitlab') {
    const a = p.object_attributes as { id?: unknown, note?: unknown, noteable_type?: unknown, action?: unknown } | undefined
    const mr = p.merge_request as { iid?: unknown } | undefined
    const user = p.user as { username?: unknown, bot?: unknown } | undefined
    if (a?.noteable_type !== 'MergeRequest' || typeof a.note !== 'string' || typeof mr?.iid !== 'number' || (a.action && a.action !== 'create')) return null
    return { number: mr.iid, comment: { id: String(a.id ?? ''), author: loginOf(user?.username), author_is_bot: user?.bot === true, body: a.note } }
  }
  if (p.action !== 'created') return null
  const issue = p.issue as { number?: unknown, pull_request?: unknown } | undefined
  const comment = p.comment as { id?: unknown, body?: unknown, user?: { login?: unknown, type?: unknown } } | undefined
  const isPr = !!issue?.pull_request || p.is_pull === true
  if (!isPr || typeof issue?.number !== 'number' || typeof comment?.body !== 'string') return null
  return {
    number: issue.number,
    comment: { id: String(comment.id ?? ''), author: loginOf(comment.user?.login), author_is_bot: comment.user?.type === 'Bot', body: comment.body },
  }
}
