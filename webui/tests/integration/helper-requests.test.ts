// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Dépôt des demandes et ingestion des résultats contre un vrai PostgreSQL 16.

import { mkdir, mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { DATABASE_URL, createTestDatabase, type TestDatabase } from '../helpers/db'
import { submitRequest, getHelperRequest, RequestValidationError } from '../../server/utils/requests'
import { IngestMemory, ingestResults, markRunning } from '../../server/utils/ingest'
import { createUser } from '../../server/utils/users'
import { listAudit } from '../../server/utils/audit'

describe.skipIf(!DATABASE_URL)('demandes au service root (PostgreSQL réel)', () => {
  let db: TestDatabase
  let dir: string
  let userId: number
  const requester = () => ({ userId, username: 'admin', address: '192.0.2.10' })

  beforeAll(async () => {
    db = await createTestDatabase()
    dir = await mkdtemp(join(tmpdir(), 'scanoria-queue-'))
    for (const sub of ['tmp', 'incoming', 'done', 'failed']) await mkdir(join(dir, sub), { mode: 0o700 })
    userId = Number((await createUser(db.pool, { username: 'admin', role: 'admin', password: 'admin-long-password' })).id)
  })
  afterAll(async () => {
    await db?.drop()
    await rm(dir, { recursive: true, force: true })
  })

  function resultFor(id: string, type: string, patch: Record<string, unknown> = {}) {
    return {
      version: 1, id, type, origin: 'console', status: 'ok', code: 'OK', message: 'done',
      received_at: '2026-11-23T08:00:01Z', started_at: '2026-11-23T08:00:01Z', finished_at: '2026-11-23T08:00:05Z',
      output: {}, ...patch,
    }
  }

  it('dépose la demande (ligne pending + fichier) sans la clé privée en base', async () => {
    const key = '-----BEGIN PRIVATE KEY-----\nTOPSECRETKEYMATERIAL\n-----END PRIVATE KEY-----\n'
    const sub = await submitRequest(db.pool, dir, 'import-certificate', {
      cert_pem: '-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n', key_pem: key,
    }, requester())
    const content = JSON.parse(await readFile(join(dir, 'incoming', sub.fileName), 'utf8'))
    expect(content).toMatchObject({ version: 1, id: sub.id, type: 'import-certificate', requested_by: { user_id: userId, username: 'admin', address: '192.0.2.10' } })
    expect(content.params.key_pem).toBe(key)
    const row = await getHelperRequest(db.pool, sub.id)
    expect(row).toMatchObject({ status: 'pending', origin: 'console', type: 'import-certificate' })
    expect(JSON.stringify(row)).not.toContain('TOPSECRET')
    expect(await readdir(join(dir, 'tmp'))).toEqual([])
  })

  it('refuse des paramètres invalides sans rien écrire', async () => {
    const before = await readdir(join(dir, 'incoming'))
    await expect(submitRequest(db.pool, dir, 'set-hostname', { fqdn: 'bad name' }, requester())).rejects.toBeInstanceOf(RequestValidationError)
    expect(await readdir(join(dir, 'incoming'))).toEqual(before)
  })

  it('marque la ligne en erreur si le fichier ne peut être écrit', async () => {
    const broken = join(dir, 'missing-dir')
    await expect(submitRequest(db.pool, broken, 'run-selftest', {}, requester())).rejects.toThrow()
    const { rows } = await db.pool.query(`SELECT status, code FROM helper_requests WHERE type = 'run-selftest'`)
    expect(rows).toEqual([{ status: 'error', code: 'E_INTERNAL' }])
  })

  it('ingère un résultat de la console, met à jour la ligne et audite une seule fois', async () => {
    const sub = await submitRequest(db.pool, dir, 'set-hostname', { fqdn: 'analyse.exemple.test' }, requester())
    await markRunning(db.pool, sub.id)
    expect((await getHelperRequest(db.pool, sub.id))?.status).toBe('running')
    await rm(join(dir, 'incoming', sub.fileName))
    await writeFile(join(dir, 'done', sub.fileName), JSON.stringify(resultFor(sub.id, 'set-hostname', { output: { fqdn: 'analyse.exemple.test' } })))
    const memory = new IngestMemory()
    const stats = await ingestResults(db.pool, dir, memory)
    expect(stats.ingested).toBe(1)
    expect(await getHelperRequest(db.pool, sub.id)).toMatchObject({ status: 'ok', code: 'OK', output: { fqdn: 'analyse.exemple.test' } })
    expect((await ingestResults(db.pool, dir, memory)).ingested).toBe(0)
    expect((await ingestResults(db.pool, dir, new IngestMemory())).ingested).toBe(0)
    const audit = await listAudit(db.pool, { limit: 10, offset: 0, action: 'system.set-hostname.result' })
    expect(audit.items).toHaveLength(1)
    expect(audit.items[0]).toMatchObject({ actor_username: 'admin', outcome: 'success', request_id: sub.id })
  })

  it('ingère un échec et une action lancée par un timer (ligne créée)', async () => {
    const sub = await submitRequest(db.pool, dir, 'set-admin-networks', { networks: ['198.51.100.0/24'] }, requester())
    await writeFile(join(dir, 'failed', sub.fileName), JSON.stringify(resultFor(sub.id, 'set-admin-networks', { status: 'error', code: 'E_LOCKOUT', message: 'lockout' })))
    const timerId = 'a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d'
    const timerName = `20261123T070000Z-${timerId}.json`
    await writeFile(join(dir, 'done', timerName), JSON.stringify(resultFor(timerId, 'check-update', { origin: 'timer', output: { latest_version: '0.2.0' } })))
    await ingestResults(db.pool, dir, new IngestMemory())
    expect(await getHelperRequest(db.pool, sub.id)).toMatchObject({ status: 'error', code: 'E_LOCKOUT' })
    expect(await getHelperRequest(db.pool, timerId)).toMatchObject({ status: 'ok', origin: 'timer', requested_by: null })
    const audit = await listAudit(db.pool, { limit: 10, offset: 0, action: 'system.check-update.result' })
    expect(audit.items[0]).toMatchObject({ actor_type: 'system', actor_username: 'system' })
  })

  it('enregistre l’historique des mises à jour (succès et retour automatique)', async () => {
    const ok = await submitRequest(db.pool, dir, 'apply-update', { source: 'github', version: '0.2.0' }, requester(), new Date(), { installed_version_hint: '0.1.0' })
    await writeFile(join(dir, 'done', ok.fileName), JSON.stringify(resultFor(ok.id, 'apply-update', { output: { channel: 'stable' } })))
    const ko = await submitRequest(db.pool, dir, 'apply-update', { source: 'github', version: '0.3.0' }, requester(), new Date(Date.now() + 1000), { installed_version_hint: '0.2.0' })
    await writeFile(join(dir, 'failed', ko.fileName), JSON.stringify(resultFor(ko.id, 'apply-update', { status: 'error', code: 'E_HEALTH_ROLLED_BACK' })))
    const rb = await submitRequest(db.pool, dir, 'rollback-update', { expected_current: '0.2.0', expected_target: '0.1.0' }, requester(), new Date(Date.now() + 2000))
    await writeFile(join(dir, 'done', rb.fileName), JSON.stringify(resultFor(rb.id, 'rollback-update')))
    await ingestResults(db.pool, dir, new IngestMemory())
    const { rows } = await db.pool.query(
      `SELECT action, from_version, to_version, status, code, source, channel FROM update_history ORDER BY to_version`,
    )
    expect(rows).toEqual([
      { action: 'rollback', from_version: '0.2.0', to_version: '0.1.0', status: 'success', code: 'OK', source: null, channel: null },
      { action: 'apply', from_version: '0.1.0', to_version: '0.2.0', status: 'success', code: 'OK', source: 'github', channel: 'stable' },
      { action: 'auto-rollback', from_version: '0.2.0', to_version: '0.3.0', status: 'rolled-back', code: 'E_HEALTH_ROLLED_BACK', source: 'github', channel: null },
    ])
  })

  it('ignore les fichiers hostiles et audite une seule fois un rejet sans identifiant', async () => {
    await writeFile(join(dir, 'failed', 'invalid-20261123T080000Z-x1.json'), JSON.stringify({
      ...resultFor('', 'set-hostname'), id: null, type: null, status: 'rejected', code: 'E_INVALID_NAME',
    }))
    await writeFile(join(dir, 'done', '20261123T080000Z-b1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d.json'), '{not json')
    const mismatch = 'c1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d'
    await writeFile(join(dir, 'done', `20261123T080000Z-${mismatch}.json`), JSON.stringify(resultFor('d1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d', 'run-selftest')))
    await writeFile(join(dir, 'done', 'escape.json'), JSON.stringify(resultFor(mismatch, 'run-selftest')))
    await ingestResults(db.pool, dir, new IngestMemory())
    await ingestResults(db.pool, dir, new IngestMemory())
    const audit = await listAudit(db.pool, { limit: 10, offset: 0, action: 'system.helper.rejected-file' })
    expect(audit.items).toHaveLength(1)
    expect(await getHelperRequest(db.pool, 'd1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d')).toBeNull()
    expect(await getHelperRequest(db.pool, mismatch)).toBeNull()
  })

  it('passe en « lost » une demande sans résultat après 1 h', async () => {
    const sub = await submitRequest(db.pool, dir, 'check-update', {}, requester())
    await db.pool.query(`UPDATE helper_requests SET created_at = now() - interval '2 hours' WHERE id = $1`, [sub.id])
    const stats = await ingestResults(db.pool, dir, new IngestMemory())
    expect(stats.lost).toBeGreaterThanOrEqual(1)
    expect((await getHelperRequest(db.pool, sub.id))?.status).toBe('lost')
  })
})
