// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Chantier B de la 0.4 : mot de passe administrateur de SonarQube rendu une
// seule fois (revealAdminPassword), contre un vrai PostgreSQL 16 : demande
// reset-service-admin réussie, demandeur seul, seconde lecture refusée même
// en concurrence, fichier purgé, contenu invalide. Mot de passe généré à
// l'exécution.

import { randomBytes, randomUUID } from 'node:crypto'
import { mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { createTestDatabase, DATABASE_URL, type TestDatabase } from '../helpers/db'
import { createUser } from '../../server/utils/users'
import { managesAdmin, revealAdminPassword } from '../../server/services/admin-access'

describe.skipIf(!DATABASE_URL)('accès administrateur SonarQube (PostgreSQL réel)', () => {
  let db: TestDatabase
  let dir: string
  let adminId: string
  let otherId: string

  beforeAll(async () => {
    db = await createTestDatabase()
    dir = await mkdtemp(join(tmpdir(), 'sonar-oneshot-'))
    const pw = randomBytes(12).toString('hex')
    adminId = String((await createUser(db.pool, { username: 'admin1', role: 'admin', password: pw })).id)
    otherId = String((await createUser(db.pool, { username: 'admin2', role: 'admin', password: pw })).id)
  })
  afterAll(async () => {
    if (dir) await rm(dir, { recursive: true, force: true })
    await db?.drop()
  })

  async function request(opts: { status?: string, user?: string, module?: string, type?: string, password?: unknown, file?: boolean } = {}) {
    const id = randomUUID()
    await db.pool.query(
      `INSERT INTO helper_requests (id, type, file_name, requested_by, params, status, code, output)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
      [id, opts.type ?? 'reset-service-admin', `${id}.json`, opts.user ?? adminId, { id: opts.module ?? 'sonarqube' },
        opts.status ?? 'ok', (opts.status ?? 'ok') === 'ok' ? 'OK' : 'E_SONAR_ADMIN', { id: 'sonarqube', login: 'admin', oneshot: true }])
    const password = opts.password === undefined ? `Sq#${randomBytes(16).toString('hex')}9a` : opts.password
    if (opts.file !== false) await writeFile(join(dir, `${id}.json`), JSON.stringify({ password }))
    return { id, password }
  }
  const reveal = (requestId: string, userId = adminId, moduleId = 'sonarqube') =>
    revealAdminPassword(db.pool, { requestId, moduleId, userId, dir })

  it('seul SonarQube a un compte administrateur géré', () => {
    expect(managesAdmin('sonarqube')).toBe(true)
    expect(managesAdmin('dtrack')).toBe(false)
  })

  it('rend le mot de passe une seule fois, au seul demandeur', async () => {
    const r = await request()
    expect(await reveal(r.id, otherId)).toEqual({ ok: false, code: 'E_FORBIDDEN' })
    expect(await reveal(r.id)).toEqual({ ok: true, login: 'admin', password: r.password })
    expect(await reveal(r.id)).toEqual({ ok: false, code: 'E_GONE' })
    const { rows } = await db.pool.query(`SELECT output FROM helper_requests WHERE id = $1`, [r.id])
    expect(rows[0].output.revealed).toBe(true)
    expect(JSON.stringify(rows[0].output)).not.toContain(r.password)
  })

  it('deux lectures simultanées : une seule réussit', async () => {
    const r = await request()
    const out = await Promise.all([reveal(r.id), reveal(r.id), reveal(r.id)])
    expect(out.filter(o => o.ok)).toHaveLength(1)
    expect(out.filter(o => !o.ok).map(o => !o.ok && o.code)).toEqual(['E_GONE', 'E_GONE'])
  })

  it('demande inconnue, d’un autre type ou d’un autre module', async () => {
    expect(await reveal('pas-un-uuid')).toEqual({ ok: false, code: 'E_NOT_FOUND' })
    expect(await reveal(randomUUID())).toEqual({ ok: false, code: 'E_NOT_FOUND' })
    const r = await request()
    expect(await reveal(r.id, adminId, 'dtrack')).toEqual({ ok: false, code: 'E_NOT_FOUND' })
    const other = await request({ type: 'run-selftest' })
    expect(await reveal(other.id)).toEqual({ ok: false, code: 'E_NOT_FOUND' })
  })

  it('demande en échec : rien à lire', async () => {
    const r = await request({ status: 'error' })
    expect(await reveal(r.id)).toEqual({ ok: false, code: 'E_PRECONDITION' })
  })

  it('fichier purgé ou invalide : E_GONE, et la demande est quand même consommée', async () => {
    const purged = await request({ file: false })
    expect(await reveal(purged.id)).toEqual({ ok: false, code: 'E_GONE' })
    const bad = await request({ password: '<script>' })
    expect(await reveal(bad.id)).toEqual({ ok: false, code: 'E_GONE' })
    const notString = await request({ password: 42 })
    expect(await reveal(notString.id)).toEqual({ ok: false, code: 'E_GONE' })
    await writeFile(join(dir, `${notString.id}.json`), JSON.stringify({ password: `Sq#${randomBytes(16).toString('hex')}9a` }))
    expect(await reveal(notString.id)).toEqual({ ok: false, code: 'E_GONE' })
  })
})
