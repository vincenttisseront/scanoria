// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// J9, J11–J13, J16 (0.8, chantier D) : passe périodique du déploiement, dans
// la console (seule à déposer les demandes au helper et à lire leurs
// résultats). Contrat 40 : l'écouteur onReleaseVerdict (listen.ts) lance une
// passe immédiate pour l'analyse ; la passe périodique rattrape tout le reste
// (redémarrage, écouteur non branché, suivi des CD). Une seule passe à la
// fois sur l'appliance (verrou consultatif PostgreSQL).

import type pg from 'pg'
import { createDeployments } from './runs'
import { advanceScan } from './steps'
import { autonomousPass } from './autonomous'
import { collectSignatures } from '../attest'

export const DEPLOY_LOCK = 0x5ca4_0d40

export interface PassResult {
  created: number
  advanced: number
  autoMerge: number
}

/** Une passe complète ; ne lève jamais (erreurs journalisées). */
export async function deployPass(pool: pg.Pool, opts: { scanId?: string, log?: (m: string) => void } = {}): Promise<PassResult | null> {
  const log = opts.log ?? (m => console.error(`[deploy] ${m}`))
  const client = await pool.connect()
  try {
    const lock = await client.query<{ ok: boolean }>('SELECT pg_try_advisory_lock($1) AS ok', [DEPLOY_LOCK])
    if (!lock.rows[0]?.ok) return null
    try {
      const created = await createDeployments(client, opts.scanId)
      await collectSignatures(client)
      const active = await client.query<{ scan_id: string }>(
        `SELECT DISTINCT d.scan_id::text FROM deployments d WHERE d.status IN ('pending', 'running')
            AND ($1::uuid IS NULL OR d.scan_id = $1::uuid) LIMIT 50`, [opts.scanId ?? null])
      for (const x of active.rows) {
        try {
          await advanceScan(client, x.scan_id)
        }
        catch (err) {
          log(`scan ${x.scan_id}: ${(err as Error).message}`)
        }
      }
      const autoMerge = opts.scanId ? 0 : await autonomousPass(client)
      return { created: created.length, advanced: active.rowCount ?? 0, autoMerge }
    }
    finally {
      await client.query('SELECT pg_advisory_unlock($1)', [DEPLOY_LOCK])
    }
  }
  catch (err) {
    log(`pass failed: ${(err as Error).message}`)
    return null
  }
  finally {
    client.release()
  }
}
