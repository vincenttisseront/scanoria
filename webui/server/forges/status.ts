// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// État d'intégration d'une forge (J1), montré dans la console : application
// ou jeton de service (portées exactes), mode poussé (webhooks reçus) ou tiré
// (interrogation), webhooks rejetés. Le choix du mode est automatique
// (principe 8) : sans livraison acceptée depuis PUSH_WINDOW, l'appliance
// interroge la forge.

import type { Queryable } from '../utils/db'
import { getForgeApp, GITHUB_APP_PERMISSIONS, SERVICE_TOKEN_SCOPES } from './apps'

/** Une livraison acceptée dans cette fenêtre : la forge joint l'appliance, inutile d'interroger. */
export const PUSH_WINDOW_MINUTES = 30

export type ForgeMode = 'push' | 'pull'

/** Mode courant d'une forge : poussé si un webhook signé a été accepté récemment. */
export async function forgeMode(db: Queryable, forgeId: string): Promise<ForgeMode> {
  const r = await db.query(
    `SELECT 1 FROM webhook_deliveries WHERE forge_id = $1 AND status IN ('accepted', 'ignored') AND event NOT IN ('comment-seen', 'body-seen', 'poll')
        AND received_at > now() - make_interval(mins => $2) LIMIT 1`, [forgeId, PUSH_WINDOW_MINUTES])
  return r.rowCount ? 'push' : 'pull'
}

export async function forgeIntegration(db: Queryable, forgeId: string) {
  const app = await getForgeApp(db, forgeId)
  const d = await db.query<{ accepted_at: Date | null, rejected: string }>(
    `SELECT max(received_at) FILTER (WHERE status IN ('accepted', 'ignored') AND event NOT IN ('comment-seen', 'body-seen', 'poll')) AS accepted_at,
            count(*) FILTER (WHERE status = 'rejected' AND received_at > now() - interval '30 days') AS rejected
       FROM webhook_deliveries WHERE forge_id = $1`, [forgeId])
  const kind = app?.kind ?? null
  return {
    app: kind,
    // Portées exactes affichées (jeton de service à droits réduits, révocable dans la forge).
    scopes: kind === 'github-app'
      ? Object.entries(GITHUB_APP_PERMISSIONS).map(([k, v]) => `${k}:${v}`)
      : kind === 'forgejo-token' ? SERVICE_TOKEN_SCOPES.forgejo : kind === 'gitlab-token' ? SERVICE_TOKEN_SCOPES.gitlab : [],
    slug: app?.slug ?? null,
    installations: app?.installation_ids.length ?? 0,
    webhook: !!app?.webhook_credential_id,
    mode: await forgeMode(db, forgeId),
    last_webhook_at: d.rows[0]?.accepted_at ?? null,
    rejected_webhooks_30d: Number(d.rows[0]?.rejected ?? 0),
  }
}
