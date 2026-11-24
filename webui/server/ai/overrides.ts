// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Délais forcés par module (appliance_settings « scan.timeout_overrides ») :
// seul réglage de ressources qu'un diagnostic IA (I15) peut proposer, appliqué
// par le clic d'une personne. Relus par la file d'analyses à la construction
// du plan ; ils ne font qu'allonger le délai déclaré par le manifeste.

import { z } from 'zod'
import type { Queryable } from '../utils/db'

export const TimeoutOverrides = z.record(z.string().regex(/^[a-z0-9][a-z0-9-]{1,40}$/), z.int().min(60).max(86_400))

/** Délais forcés ; {} si absents ou non conformes (jamais d'erreur). */
export async function loadTimeoutOverrides(db: Queryable): Promise<Record<string, number>> {
  try {
    const { rows } = await db.query<{ value: unknown }>(`SELECT value FROM appliance_settings WHERE key = 'scan.timeout_overrides'`)
    const parsed = TimeoutOverrides.safeParse(rows[0]?.value ?? {})
    return parsed.success ? parsed.data : {}
  }
  catch {
    return {}
  }
}
