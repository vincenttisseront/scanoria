// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Webhooks des forges : signature, identifiant de livraison et évènement.
// - Forgejo (et Gitea) : X-Forgejo-Signature (ou X-Gitea-Signature), HMAC-SHA256
//   hexadécimal du corps brut ;
// - GitHub : X-Hub-Signature-256 « sha256=<hex> », HMAC-SHA256 du corps brut ;
// - GitLab : X-Gitlab-Token, secret partagé envoyé tel quel.
// Toute comparaison est à temps constant. Aucune dépendance hors de node:crypto :
// le module est aussi chargé seul par tests/b34-forges.sh.

import { createHmac, timingSafeEqual } from 'node:crypto'

export type ForgeKind = 'forgejo' | 'github' | 'gitlab'

/** Corps d'un webhook accepté au plus (les forges envoient bien moins). */
export const MAX_WEBHOOK_BYTES = 1024 * 1024

export type HeaderBag = Record<string, string | string[] | undefined>

function header(h: HeaderBag, name: string): string | null {
  const v = h[name.toLowerCase()] ?? h[name]
  const s = Array.isArray(v) ? v[0] : v
  return typeof s === 'string' && s.length <= 512 ? s : null
}

function safeEqual(a: Buffer, b: Buffer): boolean {
  if (a.length !== b.length) {
    // Comparaison factice pour ne pas révéler la longueur attendue par le délai.
    timingSafeEqual(b, b)
    return false
  }
  return timingSafeEqual(a, b)
}

function hmacHex(secret: string, body: Buffer): Buffer {
  return Buffer.from(createHmac('sha256', secret).update(body).digest('hex'), 'utf8')
}

/** Vérifie la signature d'un webhook ; le secret vide est toujours refusé. */
export function verifyWebhookSignature(kind: ForgeKind, headers: HeaderBag, body: Buffer, secret: string): boolean {
  if (!secret || secret.length < 16) return false
  if (kind === 'gitlab') {
    const token = header(headers, 'x-gitlab-token')
    return !!token && safeEqual(Buffer.from(token, 'utf8'), Buffer.from(secret, 'utf8'))
  }
  if (kind === 'github') {
    const sig = header(headers, 'x-hub-signature-256')
    const m = sig ? /^sha256=([0-9a-f]{64})$/i.exec(sig) : null
    return !!m && safeEqual(Buffer.from(m[1]!.toLowerCase(), 'utf8'), hmacHex(secret, body))
  }
  const sig = header(headers, 'x-forgejo-signature') ?? header(headers, 'x-gitea-signature')
  return !!sig && /^[0-9a-f]{64}$/i.test(sig) && safeEqual(Buffer.from(sig.toLowerCase(), 'utf8'), hmacHex(secret, body))
}

/** Identifiant de livraison (rejeu refusé par webhook_deliveries) ; null s'il manque ou est invalide. */
export function deliveryId(kind: ForgeKind, headers: HeaderBag): string | null {
  const raw = kind === 'github'
    ? header(headers, 'x-github-delivery')
    : kind === 'gitlab'
      ? header(headers, 'x-gitlab-event-uuid') ?? header(headers, 'x-gitlab-webhook-uuid') ?? header(headers, 'idempotency-key')
      : header(headers, 'x-forgejo-delivery') ?? header(headers, 'x-gitea-delivery')
  return raw && /^[A-Za-z0-9._:-]{8,128}$/.test(raw) ? raw : null
}

/** Évènements utiles, normalisés ; tout le reste est ignoré. */
export type WebhookEvent = 'push' | 'pull_request' | 'comment' | 'installation' | 'repository' | 'ping'

export function webhookEvent(kind: ForgeKind, headers: HeaderBag): { raw: string, event: WebhookEvent | null } {
  const raw = (kind === 'github'
    ? header(headers, 'x-github-event')
    : kind === 'gitlab'
      ? header(headers, 'x-gitlab-event')
      : header(headers, 'x-forgejo-event') ?? header(headers, 'x-gitea-event')) ?? ''
  const name = raw.slice(0, 64)
  const map: Record<ForgeKind, Record<string, WebhookEvent>> = {
    github: {
      push: 'push', pull_request: 'pull_request', issue_comment: 'comment', ping: 'ping',
      installation: 'installation', installation_repositories: 'installation', repository: 'repository',
    },
    forgejo: {
      push: 'push', pull_request: 'pull_request', pull_request_sync: 'pull_request',
      issue_comment: 'comment', pull_request_comment: 'comment', repository: 'repository',
    },
    gitlab: { 'Push Hook': 'push', 'Merge Request Hook': 'pull_request', 'Note Hook': 'comment' },
  }
  return { raw: name, event: Object.hasOwn(map[kind], name) ? map[kind][name]! : null }
}
