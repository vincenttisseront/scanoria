// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// GET /api/system/offline (opérateur) : clé de l'appliance, clés de confiance,
// lots exportés et importés, miroir déclaré ou publié (F17), export
// périodique et sources de Dependency-Track (0.6, chantier A, § 9).

import { defineEventHandler } from 'h3'
import { getConfig } from '../../../utils/config'
import { getPool } from '../../../utils/db'
import { requireRole } from '../../../utils/http'
import { readPublishedState } from '../../../utils/appliance'
import { listBundles, listTrustedKeys, readOfflineStatus } from '../../../offline/status'

export default defineEventHandler(async (event) => {
  requireRole(event, 'operator')
  const cfg = getConfig()
  const pool = getPool()
  const [status, published, keys, history] = await Promise.all([
    readOfflineStatus(cfg.offlineStatusFile ?? '/var/lib/scanoria/offline/status.json'),
    readPublishedState(cfg.stateFile),
    listTrustedKeys(pool),
    listBundles(pool),
  ])
  // Clé de l'appliance : état hors ligne, sinon photographie d'état (créée au premier passage du helper).
  const stateKey = (published.state as { appliance_key?: unknown } | undefined)?.appliance_key
  const applianceKey = status?.appliance_key ?? (stateKey && typeof stateKey === 'object' ? stateKey : null)
  const inStore = new Set(status?.trusted_keys ?? [])
  return {
    available: status !== null,
    appliance_key: applianceKey,
    trusted_keys: keys.map(k => ({ ...k, in_store: inStore.has(k.fingerprint) })),
    exports: status?.bundles ?? [],
    history,
    last_import: status?.last_import ?? null,
    mirror: status?.mirror ?? null,
    publication: status?.publication ?? null,
    schedule: status?.schedule ?? { enabled: false, every_days: 7, keep: 2, modules: [], last_run_at: null },
    dtrack: status?.dtrack ?? null,
  }
})
