#!/usr/bin/env node
// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Lanceur autonome des migrations de la base de la console
// (docs/ARCHITECTURE.md § 9.1), appelé par ExecStartPre de scanoria-console :
//   node /opt/scanoria/current/webui/migrate.mjs
// - verrou consultatif PostgreSQL (une seule exécution à la fois) ;
// - chaque fichier NNN_nom.sql dans sa propre transaction ;
// - enregistrement dans schema_migrations (version, nom, SHA-256 du fichier) ;
// - empreinte ou nom différents d'une migration appliquée = échec ;
// - base plus récente que le code (migration inconnue) = échec.
// Code de sortie : 0 si la base est à jour, 1 sinon.
// Base : NUXT_DATABASE_URL (ou DATABASE_URL). Fichiers : NUXT_MIGRATIONS_DIR,
// sinon ./migrations (lot de mise à jour) puis ./server/db/migrations (dépôt).

import { createHash } from 'node:crypto'
import { existsSync, readFileSync, readdirSync } from 'node:fs'
import { createRequire } from 'node:module'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'

export const MIGRATION_NAME_RE = /^([0-9]{3})_[a-z0-9_]+\.sql$/
const LOCK_SQL = `SELECT pg_advisory_lock(hashtext('scanoria.migrations'))`
const UNLOCK_SQL = `SELECT pg_advisory_unlock(hashtext('scanoria.migrations'))`
const TABLE_SQL = `CREATE TABLE IF NOT EXISTS schema_migrations (
    version     integer     PRIMARY KEY CHECK (version > 0),
    name        text        NOT NULL CHECK (name ~ '^[0-9]{3}_[a-z0-9_]+\\.sql$'),
    checksum    text        NOT NULL CHECK (checksum ~ '^[0-9a-f]{64}$'),
    applied_at  timestamptz NOT NULL DEFAULT now()
)`

/** SHA-256 hexadécimal du contenu exact du fichier. */
export function checksumOf(content) {
  return createHash('sha256').update(content).digest('hex')
}

/**
 * Prépare la liste ordonnée des migrations à partir de couples {name, content}.
 * Numérotation continue à partir de 001 exigée.
 */
export function prepareMigrations(files) {
  const list = files.map(({ name, content }) => {
    const m = MIGRATION_NAME_RE.exec(name)
    if (!m) throw new Error(`invalid migration file name: ${name}`)
    return { version: Number(m[1]), name, sql: String(content), checksum: checksumOf(content) }
  })
  list.sort((a, b) => a.version - b.version)
  list.forEach((mig, i) => {
    if (mig.version !== i + 1) throw new Error(`migration numbering is not continuous at ${mig.name}`)
  })
  return list
}

export function loadMigrationsFromDir(dir) {
  const names = readdirSync(dir).filter(n => n.endsWith('.sql'))
  return prepareMigrations(names.map(name => ({ name, content: readFileSync(join(dir, name)) })))
}

/**
 * Applique les migrations manquantes. client : objet pg connecté (Client ou
 * PoolClient). Renvoie la liste des noms appliqués pendant cet appel.
 */
export async function applyMigrations(client, migrations, log = () => {}) {
  await client.query(LOCK_SQL)
  try {
    await client.query(TABLE_SQL)
    const { rows } = await client.query('SELECT version, name, checksum FROM schema_migrations ORDER BY version')
    const shipped = new Map(migrations.map(m => [m.version, m]))
    for (const row of rows) {
      const mig = shipped.get(row.version)
      if (!mig) throw new Error(`database has migration ${row.version} (${row.name}) unknown to this version`)
      if (mig.name !== row.name) throw new Error(`migration ${row.version} name mismatch: ${row.name} != ${mig.name}`)
      if (mig.checksum !== row.checksum) throw new Error(`migration ${mig.name} checksum mismatch (file modified after release)`)
    }
    const done = new Set(rows.map(r => r.version))
    const applied = []
    for (const mig of migrations) {
      if (done.has(mig.version)) continue
      log(`applying ${mig.name}`)
      await client.query('BEGIN')
      try {
        await client.query(mig.sql)
        await client.query(
          'INSERT INTO schema_migrations (version, name, checksum) VALUES ($1, $2, $3)',
          [mig.version, mig.name, mig.checksum],
        )
        await client.query('COMMIT')
      }
      catch (err) {
        await client.query('ROLLBACK').catch(() => {})
        throw new Error(`migration ${mig.name} failed: ${err.message}`, { cause: err })
      }
      applied.push(mig.name)
    }
    return applied
  }
  finally {
    await client.query(UNLOCK_SQL).catch(() => {})
  }
}

/** Charge le pilote pg : dépendances du dépôt, sinon celles embarquées par Nitro (lot). */
async function loadPg(here) {
  try {
    return (await import('pg')).default
  }
  catch {
    const candidates = [join(here, 'server', 'index.mjs'), join(here, '.output', 'server', 'index.mjs')]
    for (const anchor of candidates) {
      if (!existsSync(anchor)) continue
      try {
        const require = createRequire(anchor)
        return require('pg')
      }
      catch {
        // essai suivant
      }
    }
    throw new Error('cannot load the pg driver')
  }
}

function migrationsDir(here) {
  if (process.env.NUXT_MIGRATIONS_DIR) return resolve(process.env.NUXT_MIGRATIONS_DIR)
  for (const dir of [join(here, 'migrations'), join(here, 'server', 'db', 'migrations')]) {
    if (existsSync(dir)) return dir
  }
  throw new Error('migrations directory not found')
}

async function main() {
  const here = dirname(fileURLToPath(import.meta.url))
  const url = process.env.NUXT_DATABASE_URL || process.env.DATABASE_URL
    || 'postgresql:///scanoria?host=/var/run/postgresql'
  const pg = await loadPg(here)
  const migrations = loadMigrationsFromDir(migrationsDir(here))
  const client = new pg.Client({ connectionString: url, application_name: 'scanoria-migrate' })
  await client.connect()
  try {
    const applied = await applyMigrations(client, migrations, msg => console.log(`[migrate] ${msg}`))
    console.log(`[migrate] database up to date (${migrations.length} migrations, ${applied.length} applied now)`)
  }
  finally {
    await client.end()
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  main().catch((err) => {
    console.error(`[migrate] error: ${err.message}`)
    process.exit(1)
  })
}
