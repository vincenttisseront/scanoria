// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Bases PostgreSQL jetables pour les tests d'intégration. DATABASE_URL désigne
// une base d'administration (droit CREATE DATABASE) ; chaque appel crée une
// base scanoria_test_<aléa>, supprimée à la fin.

import { randomBytes } from 'node:crypto'
import { fileURLToPath } from 'node:url'
import pg from 'pg'
import { applyMigrations, loadMigrationsFromDir } from '../../migrate.mjs'
import { endPool, trackClients } from '../../server/utils/db'

export const DATABASE_URL = process.env.DATABASE_URL ?? ''
export const MIGRATIONS_DIR = fileURLToPath(new URL('../../server/db/migrations', import.meta.url))

export function withDatabase(url: string, database: string): string {
  const u = new URL(url)
  u.pathname = `/${database}`
  return u.toString()
}

export interface TestDatabase {
  name: string
  url: string
  pool: pg.Pool
  drop: () => Promise<void>
}

export async function createTestDatabase(opts: { migrate?: boolean } = {}): Promise<TestDatabase> {
  const name = `scanoria_test_${randomBytes(6).toString('hex')}`
  const admin = new pg.Client({ connectionString: DATABASE_URL })
  await admin.connect()
  try {
    await admin.query(`CREATE DATABASE ${name} TEMPLATE template0 ENCODING 'UTF8'`)
  }
  finally {
    await admin.end()
  }
  const url = withDatabase(DATABASE_URL, name)
  const pool = trackClients(new pg.Pool({ connectionString: url, max: 5 }))
  if (opts.migrate !== false) {
    const client = await pool.connect()
    try {
      await applyMigrations(client, loadMigrationsFromDir(MIGRATIONS_DIR))
    }
    finally {
      client.release()
    }
  }
  return {
    name,
    url,
    pool,
    drop: async () => {
      // Connexions réellement fermées avant le DROP … WITH (FORCE) : sinon un
      // backend encore ouvert est tué (57P01) et l'erreur remonte, non gérée,
      // par ce pool sans écouteur 'error' (server/utils/db.ts, endPool).
      await endPool(pool)
      const c = new pg.Client({ connectionString: DATABASE_URL })
      await c.connect()
      try {
        await c.query(`DROP DATABASE IF EXISTS ${name} WITH (FORCE)`)
      }
      finally {
        await c.end()
      }
    },
  }
}
