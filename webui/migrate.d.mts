// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Types de migrate.mjs (lanceur autonome des migrations).

export interface Migration {
  version: number
  name: string
  sql: string
  checksum: string
}

export interface MigrationClient {
  query: (sql: string, params?: unknown[]) => Promise<{ rows: unknown[] }>
}

export const MIGRATION_NAME_RE: RegExp
export function checksumOf(content: string | Uint8Array): string
export function prepareMigrations(files: { name: string, content: string | Uint8Array }[]): Migration[]
export function loadMigrationsFromDir(dir: string): Migration[]
export function applyMigrations(
  client: MigrationClient,
  migrations: Migration[],
  log?: (msg: string) => void,
): Promise<string[]>
