// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Premier administrateur (docs/ARCHITECTURE.md § 9.3) : le premier démarrage
// dépose bootstrap/admin.json = {"username", "password_hash" (PHC)} ; la console
// crée ce compte s'il n'existe aucun administrateur actif, audite
// system.bootstrap-admin, puis supprime le fichier dans tous les cas traités.

import { lstat, readFile, unlink } from 'node:fs/promises'
import { join } from 'node:path'
import type pg from 'pg'
import { z } from 'zod'
import { withTransaction } from './db'
import { writeAudit } from './audit'
import { isValidPhc } from './password'
import { USERNAME_RE } from '#shared/schemas'

const bootstrapSchema = z.strictObject({
  username: z.string().regex(USERNAME_RE),
  password_hash: z.string().refine(isValidPhc, { message: 'invalid PHC hash' }),
})

export type BootstrapOutcome = 'absent' | 'created' | 'admin-exists' | 'invalid' | 'username-taken'

export async function consumeBootstrapAdmin(pool: pg.Pool, bootstrapDir: string): Promise<BootstrapOutcome> {
  const path = join(bootstrapDir, 'admin.json')
  let st
  try {
    st = await lstat(path)
  }
  catch {
    return 'absent'
  }
  const discard = async () => {
    await unlink(path).catch(err => console.error('[bootstrap] cannot remove admin.json:', (err as Error).message))
  }
  if (!st.isFile() || st.size > 4096) {
    console.error('[bootstrap] admin.json is not a small regular file: ignored')
    await discard()
    return 'invalid'
  }
  let data: z.infer<typeof bootstrapSchema>
  try {
    const parsed = bootstrapSchema.safeParse(JSON.parse(await readFile(path, 'utf8')))
    if (!parsed.success) throw new Error('schema')
    data = parsed.data
  }
  catch {
    console.error('[bootstrap] admin.json is invalid: ignored')
    await withTransaction(pool, c => writeAudit(c, {
      actor: { type: 'system' }, action: 'system.bootstrap-admin', outcome: 'failure', details: { reason: 'invalid file' },
    }))
    await discard()
    return 'invalid'
  }
  const outcome = await withTransaction(pool, async (client) => {
    await client.query('LOCK TABLE users IN SHARE ROW EXCLUSIVE MODE')
    const admins = await client.query(`SELECT 1 FROM users WHERE role = 'admin' AND is_active LIMIT 1`)
    if (admins.rowCount) return 'admin-exists' as const
    const taken = await client.query('SELECT 1 FROM users WHERE username = $1', [data.username])
    if (taken.rowCount) {
      await writeAudit(client, {
        actor: { type: 'system' }, action: 'system.bootstrap-admin', outcome: 'failure',
        targetType: 'user', targetId: data.username, details: { reason: 'username already exists' },
      })
      return 'username-taken' as const
    }
    const { rows } = await client.query<{ id: string }>(
      `INSERT INTO users (username, role, password_hash, must_change_password, password_changed_at)
       VALUES ($1, 'admin', $2, false, now()) RETURNING id::text`,
      [data.username, data.password_hash],
    )
    await writeAudit(client, {
      actor: { type: 'system' }, action: 'system.bootstrap-admin', outcome: 'success',
      targetType: 'user', targetId: rows[0]!.id, details: { username: data.username },
    })
    return 'created' as const
  })
  await discard()
  return outcome
}
