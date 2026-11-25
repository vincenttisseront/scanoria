// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Accès PostgreSQL : un pool unique, requêtes SQL explicites et paramétrées.

import pg from 'pg'
import { getConfig } from './config'

export type Queryable = Pick<pg.Pool, 'query'> | Pick<pg.PoolClient, 'query'>

let pool: pg.Pool | undefined

// pg-pool : pool.end() se résout dès que client.end() est *appelé* sur chaque
// client, sans attendre la fermeture de la connexion. Une commande qui suit
// aussitôt (DROP DATABASE … WITH (FORCE) des tests, arrêt du serveur PostgreSQL)
// peut alors tuer un backend encore ouvert : le client reçoit 57P01, l'émet en
// 'error', et le pool le relaie, en erreur non gérée s'il n'a pas d'écouteur.
// trackClients suit les connexions ouvertes ; endPool attend leur fermeture.
const liveClients = new WeakMap<pg.Pool, Set<pg.PoolClient>>()

/** Suit les connexions ouvertes du pool, pour que endPool attende leur fermeture réelle. */
export function trackClients(p: pg.Pool): pg.Pool {
  const live = new Set<pg.PoolClient>()
  liveClients.set(p, live)
  p.on('connect', (client) => {
    live.add(client)
    client.once('end', () => live.delete(client))
  })
  return p
}

/** Ferme le pool et attend que chaque connexion soit réellement terminée. */
export async function endPool(p: pg.Pool): Promise<void> {
  await p.end()
  const live = liveClients.get(p)
  if (live?.size) await Promise.all([...live].map(c => new Promise<void>(resolve => c.once('end', () => resolve()))))
}

export function getPool(): pg.Pool {
  if (!pool) {
    pool = trackClients(new pg.Pool({
      connectionString: getConfig().databaseUrl,
      max: 10,
      idleTimeoutMillis: 30_000,
      connectionTimeoutMillis: 5_000,
      application_name: 'scanoria-console',
    }))
    pool.on('error', (err) => {
      console.error('[db] idle client error:', err.message)
    })
  }
  return pool
}

export async function closePool(): Promise<void> {
  const p = pool
  pool = undefined
  if (p) await endPool(p)
}

/** Exécute fn dans une transaction (BEGIN/COMMIT, ROLLBACK sur erreur). */
export async function withTransaction<T>(p: pg.Pool, fn: (client: pg.PoolClient) => Promise<T>): Promise<T> {
  const client = await p.connect()
  try {
    await client.query('BEGIN')
    const result = await fn(client)
    await client.query('COMMIT')
    return result
  }
  catch (err) {
    await client.query('ROLLBACK').catch(() => {})
    throw err
  }
  finally {
    client.release()
  }
}
