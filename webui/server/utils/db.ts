// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Accès PostgreSQL : un pool unique, requêtes SQL explicites et paramétrées.

import pg from 'pg'
import { getConfig } from './config'

export type Queryable = Pick<pg.Pool, 'query'> | Pick<pg.PoolClient, 'query'>

let pool: pg.Pool | undefined

export function getPool(): pg.Pool {
  if (!pool) {
    pool = new pg.Pool({
      connectionString: getConfig().databaseUrl,
      max: 10,
      idleTimeoutMillis: 30_000,
      connectionTimeoutMillis: 5_000,
      application_name: 'scanoria-console',
    })
    pool.on('error', (err) => {
      console.error('[db] idle client error:', err.message)
    })
  }
  return pool
}

export async function closePool(): Promise<void> {
  const p = pool
  pool = undefined
  if (p) await p.end()
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
