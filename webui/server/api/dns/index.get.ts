// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// GET /api/dns (lecteur) : dernier contrôle DNS publié par le helper et liste
// des enregistrements à créer : le nom de l'appliance et le générique
// *.<nom> (§ 3.4), qui couvre toutes les applications des modules.

import { defineEventHandler } from 'h3'
import { requireAuth } from '../../utils/http'
import { getConfig } from '../../utils/config'
import { readDnsStatus } from '../../utils/catalog'
import { readPublishedState } from '../../utils/appliance'

export default defineEventHandler(async (event) => {
  requireAuth(event)
  const cfg = getConfig()
  const [status, published] = await Promise.all([readDnsStatus(cfg.dnsStatusFile), readPublishedState(cfg.stateFile)])
  const fqdn = status?.fqdn ?? (published.state?.appliance as { fqdn?: string | null } | undefined)?.fqdn ?? null
  const expected = new Map<string, string>()
  for (const r of status?.records ?? []) if (!expected.has(r.type)) expected.set(r.type, r.expected)
  const required = fqdn
    ? [...expected.entries()].flatMap(([type, address]) => [
        { name: fqdn, type, value: address },
        { name: `*.${fqdn}`, type, value: address },
      ])
    : []
  return { fqdn, status, required }
})
