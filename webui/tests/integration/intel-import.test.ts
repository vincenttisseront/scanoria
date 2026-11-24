// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// H3 (0.5, chantier C) contre un vrai PostgreSQL 16 : import des exports EPSS
// et KEV du helper (contrat 17) dans vuln_intel, idempotent ; retrait du KEV
// et de l'EPSS absents du nouvel export ; feed désinstallé ; lignes invalides
// ignorées ; fichier piégé refusé ; alias GHSA → CVE par findings.vuln_ids ;
// colonnes, filtres et tri des Résultats ; quality gate KEV sous le seuil de
// gravité et EPSS avec une vraie base ; état de l'import.

import { mkdtemp, rm, symlink, utimes, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { gzipSync } from 'node:zlib'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { DATABASE_URL, createTestDatabase, type TestDatabase } from '../helpers/db'
import { applyIntel, intelStatus, readExport, syncIntel, IntelImportError } from '../../server/intel/import'
import { listFindings } from '../../server/findings/triage'
import { evaluateGate } from '../../server/gates/evaluate'

const lines = (rows: unknown[]) => gzipSync(rows.map(r => (typeof r === 'string' ? r : JSON.stringify(r))).join('\n') + '\n')

describe.skipIf(!DATABASE_URL)('EPSS et KEV (PostgreSQL réel)', () => {
  let db: TestDatabase
  let dir: string
  let stateFile: string
  let projectId: string
  let scanId: string
  const ids: Record<string, string> = {}
  let tick = 0

  async function state(feeds: string[]) {
    await writeFile(stateFile, JSON.stringify({
      modules: [], operations: [],
      feeds: feeds.map(id => ({ id, updated_at: '2026-11-24T06:00:00Z', checked_at: '2026-11-24T06:00:00Z', size_mb: 1, status: 'ok', error: null })),
    }))
  }
  /** Écrit un export ; la date de modification avance à chaque écriture (comme un rename du helper). */
  async function exportFile(feed: string, rows: unknown[]) {
    const file = join(dir, `${feed}.jsonl.gz`)
    await writeFile(file, lines(rows))
    tick += 10
    const t = new Date(Date.UTC(2026, 10, 24, 6, 0, tick))
    await utimes(file, t, t)
  }
  const sync = () => syncIntel(db.pool, { modulesStateFile: stateFile, exportDir: dir, now: new Date('2026-11-24T07:00:00Z') })
  const intel = async (id: string) => (await db.pool.query('SELECT vuln_id, epss, epss_percentile, kev, to_char(kev_added, \'YYYY-MM-DD\') AS kev_added FROM vuln_intel WHERE vuln_id = $1', [id])).rows[0]

  async function finding(values: Record<string, unknown>): Promise<string> {
    const row: Record<string, unknown> = { tool: 'osv-scanner', rule_id: 'r', category: 'sca', severity: 'low', title: 't', ...values }
    const cols = Object.keys(row)
    const r = await db.pool.query<{ id: string }>(
      `INSERT INTO findings (project_id, fingerprint, last_scan_id, ${cols.join(', ')})
       VALUES ($1, encode(sha256(gen_random_uuid()::text::bytea), 'hex'), $2, ${cols.map((_, i) => `$${i + 3}`).join(', ')}) RETURNING id`,
      [projectId, scanId, ...cols.map(c => row[c])],
    )
    await db.pool.query('INSERT INTO scan_findings (scan_id, finding_id, is_new) VALUES ($1, $2, true)', [scanId, r.rows[0]!.id])
    return r.rows[0]!.id
  }

  beforeAll(async () => {
    db = await createTestDatabase()
    dir = await mkdtemp(join(tmpdir(), 'scanoria-intel-'))
    stateFile = join(dir, 'state.json')
    projectId = (await db.pool.query<{ id: string }>(
      `INSERT INTO projects (slug, name, source_kind, profile_id, gate_id)
       VALUES ('intel', 'Intel', 'archive', (SELECT id FROM profiles WHERE slug = 'rapide'), (SELECT id FROM gates WHERE slug = 'defaut')) RETURNING id`,
    )).rows[0]!.id
    scanId = (await db.pool.query<{ id: string }>(
      `INSERT INTO scans (project_id, number, trigger, priority, ref, profile_id, gate_id, status, job_id, started_at, plan)
       VALUES ($1, 1, 'manual', 50, 'main', (SELECT id FROM profiles WHERE slug = 'rapide'), (SELECT id FROM gates WHERE slug = 'defaut'), 'ingesting', gen_random_uuid(), now(),
               '{"modules": [{"id": "osv-scanner"}]}') RETURNING id`, [projectId],
    )).rows[0]!.id
    await db.pool.query(`INSERT INTO scan_modules (scan_id, module_id, module_version, status) VALUES ($1, 'osv-scanner', '1.0.0', 'ok')`, [scanId])
    const pkg = (name: string) => JSON.stringify({ ecosystem: 'npm', name, version: '1.0.0', fixed: [] })
    ids.kev = await finding({ vuln_ids: ['GHSA-aaaa-bbbb-cccc', 'CVE-2026-0001'], package: pkg('kev-lib'), severity: 'low' })
    ids.epss = await finding({ vuln_ids: ['CVE-2026-0002'], package: pkg('epss-lib'), severity: 'medium' })
    ids.calm = await finding({ vuln_ids: ['CVE-2026-0003'], package: pkg('calm-lib'), severity: 'medium' })
    ids.sast = await finding({ category: 'sast', tool: 'semgrep', severity: 'critical', path: 'a.py' })
  })

  afterAll(async () => {
    await db?.drop()
    if (dir) await rm(dir, { recursive: true, force: true })
  })

  it('sans export ni base : rien à importer, aucune valeur', async () => {
    await state([])
    expect(await sync()).toEqual([{ feed: 'epss', action: 'absent' }, { feed: 'kev', action: 'absent' }])
    expect(await intelStatus(db.pool)).toEqual([
      { id: 'epss', rows: null, imported_at: null, source_updated_at: null },
      { id: 'kev', rows: null, imported_at: null, source_updated_at: null },
    ])
  })

  it('import EPSS et KEV, lignes invalides ignorées', async () => {
    await state(['epss', 'kev'])
    await exportFile('epss', [
      { vuln_id: 'CVE-2026-0001', epss: 0.02, epss_percentile: 0.5 },
      { vuln_id: 'CVE-2026-0002', epss: 0.42, epss_percentile: 0.97 },
      { vuln_id: 'CVE-2026-0003', epss: 0.001, epss_percentile: 0.1 },
      { vuln_id: 'CVE-2026-0009', epss: 2, epss_percentile: 0.1 },
      { vuln_id: '../etc', epss: 0.1, epss_percentile: 0.1 },
      'pas du json',
      { vuln_id: 'CVE-2026-0010', epss: 0.1, epss_percentile: 0.1, extra: true },
    ])
    await exportFile('kev', [{ vuln_id: 'CVE-2026-0001', kev: true, kev_added: '2026-11-20' }, { vuln_id: 'CVE-2026-0004', kev: true, kev_added: '2026-02-30' }])
    const out = await sync()
    expect(out[0]).toMatchObject({ feed: 'epss', action: 'imported', rows: 3, skipped: 4, changed: 3, cleared: 0 })
    expect(out[1]).toMatchObject({ feed: 'kev', action: 'imported', rows: 1, skipped: 1, changed: 1 })
    expect(await intel('CVE-2026-0001')).toMatchObject({ kev: true, kev_added: '2026-11-20' })
    expect((await intel('CVE-2026-0002')).epss).toBeCloseTo(0.42, 5)
    expect(await intel('CVE-2026-0009')).toBeUndefined()
    const st = await intelStatus(db.pool)
    expect(st[0]).toMatchObject({ id: 'epss', rows: 3, imported_at: '2026-11-24T07:00:00.000Z', source_updated_at: '2026-11-24T06:00:00Z' })
  })

  it('idempotent : même fichier → rien relu ; même contenu réécrit → aucun changement', async () => {
    expect((await sync()).map(r => r.action)).toEqual(['unchanged', 'unchanged'])
    const before = (await db.pool.query('SELECT vuln_id, updated_at FROM vuln_intel ORDER BY vuln_id')).rows
    await exportFile('epss', [
      { vuln_id: 'CVE-2026-0001', epss: 0.02, epss_percentile: 0.5 },
      { vuln_id: 'CVE-2026-0002', epss: 0.42, epss_percentile: 0.97 },
      { vuln_id: 'CVE-2026-0003', epss: 0.001, epss_percentile: 0.1 },
      { vuln_id: 'CVE-2026-0009', epss: 2, epss_percentile: 0.1 },
      { vuln_id: '../etc', epss: 0.1, epss_percentile: 0.1 },
      'pas du json',
      { vuln_id: 'CVE-2026-0010', epss: 0.1, epss_percentile: 0.1, extra: true },
    ])
    expect((await sync())[0]).toEqual({ feed: 'epss', action: 'unchanged' })
    const r = await applyIntel(db.pool, 'epss', (await readExport('epss', join(dir, 'epss.jsonl.gz'))).rows)
    expect(r).toEqual({ changed: 0, cleared: 0 })
    expect((await db.pool.query('SELECT vuln_id, updated_at FROM vuln_intel ORDER BY vuln_id')).rows).toEqual(before)
  })

  it('alias : le GHSA prend l’EPSS et le KEV de son CVE ; colonnes, filtres et tri des Résultats', async () => {
    const all = await listFindings(db.pool, { limit: 50, offset: 0, category: 'sca' })
    expect(all.items.map(i => i.id)).toEqual([ids.kev, ids.epss, ids.calm])
    expect(all.items[0]).toMatchObject({ kev: true, kev_added: '2026-11-20' })
    expect(all.items[0]!.epss).toBeCloseTo(0.02, 5)
    expect(all.items[1]!.epss_percentile).toBeCloseTo(0.97, 5)
    const everything = await listFindings(db.pool, { limit: 50, offset: 0 })
    // Tri par ligne : KEV en tête ; une vulnérabilité à EPSS élevé passe devant un SAST
    // critique, une vulnérabilité à EPSS faible reste rangée par sa gravité.
    expect(everything.items.map(i => i.id)).toEqual([ids.kev, ids.epss, ids.sast, ids.calm])
    expect(everything.items.find(i => i.id === ids.sast)).toMatchObject({ epss: null, kev: false })
    expect((await listFindings(db.pool, { limit: 50, offset: 0, kev: true })).items.map(i => i.id)).toEqual([ids.kev])
    expect((await listFindings(db.pool, { limit: 50, offset: 0, kev: false })).total).toBe(3)
    const hi = await listFindings(db.pool, { limit: 50, offset: 0, epss_min: 0.1 })
    expect(hi.items.map(i => i.id)).toEqual([ids.epss])
    expect(hi.total).toBe(1)
  })

  it('quality gate : KEV bloquant sous le seuil de gravité, EPSS au-dessus du seuil bloquant', async () => {
    const v = await evaluateGate(db.pool, scanId)
    expect(v.verdict).toBe('failed')
    expect(v.reasons.slice(0, 3).map(r => [r.code, r.finding_ids])).toEqual([
      ['kev', [ids.kev]], ['epss', [ids.epss]], ['sast', [ids.sast]],
    ])
    // G11 : un plan d'avant la 0.5 rejoué garde le verdict de l'époque (KEV et EPSS ignorés).
    await db.pool.query(`UPDATE scans SET plan = jsonb_set(plan, '{gate}', '{"rules": {"sast_block_from": null}}') WHERE id = $1`, [scanId])
    const old = await evaluateGate(db.pool, scanId)
    expect(old.reasons.some(r => r.code === 'kev' || r.code === 'epss')).toBe(false)
    expect(old.verdict).toBe('passed')
    await db.pool.query(`UPDATE scans SET plan = plan - 'gate' WHERE id = $1`, [scanId])
  })

  it('nouvel export : une CVE retirée du KEV repasse non KEV, un score absent est effacé', async () => {
    await exportFile('kev', [{ vuln_id: 'CVE-2026-0005', kev: true, kev_added: '2026-11-23' }])
    await exportFile('epss', [{ vuln_id: 'CVE-2026-0001', epss: 0.03, epss_percentile: 0.6 }])
    const out = await sync()
    expect(out[0]).toMatchObject({ feed: 'epss', action: 'imported', changed: 1, cleared: 2 })
    expect(out[1]).toMatchObject({ feed: 'kev', action: 'imported', changed: 1, cleared: 1 })
    expect(await intel('CVE-2026-0001')).toMatchObject({ kev: false, kev_added: null })
    expect(await intel('CVE-2026-0002')).toBeUndefined()
    expect(await intel('CVE-2026-0005')).toMatchObject({ kev: true, epss: null })
    const v = await evaluateGate(db.pool, scanId)
    expect(v.reasons.some(r => r.code === 'kev' || r.code === 'epss')).toBe(false)
  })

  it('fichier piégé (lien symbolique, trop gros) refusé sans toucher aux valeurs', async () => {
    await rm(join(dir, 'kev.jsonl.gz'))
    await writeFile(join(dir, 'ailleurs.gz'), lines([{ vuln_id: 'CVE-2026-0099', kev: true, kev_added: '2026-11-01' }]))
    await symlink(join(dir, 'ailleurs.gz'), join(dir, 'kev.jsonl.gz'))
    const out = await sync()
    expect(out[1]).toEqual({ feed: 'kev', action: 'error', error: 'not-regular' })
    expect(await intel('CVE-2026-0099')).toBeUndefined()
    expect(await intel('CVE-2026-0005')).toMatchObject({ kev: true })
    await rm(join(dir, 'kev.jsonl.gz'))
    await writeFile(join(dir, 'kev.jsonl.gz'), Buffer.from('pas du gzip'))
    expect((await sync())[1]).toEqual({ feed: 'kev', action: 'error', error: 'unreadable' })
    // Échec mémorisé : le même fichier n'est pas relu, l'erreur reste signalée, l'état publié est intact.
    expect((await sync())[1]).toEqual({ feed: 'kev', action: 'error', error: 'unreadable' })
    const st = (await db.pool.query(`SELECT value FROM appliance_settings WHERE key = 'intel.import_kev'`)).rows[0]!.value
    expect(st.failed).toMatchObject({ error: 'unreadable' })
    expect(st.imported_at).not.toBe('')
    await expect(readExport('kev', join(dir, 'absent.gz'))).rejects.toThrow()
    expect(new IntelImportError('too-large').code).toBe('too-large')
  })

  it('feed désinstallé (absent de l’état et sans export) : valeurs effacées', async () => {
    await rm(join(dir, 'kev.jsonl.gz'))
    await state(['epss'])
    const out = await sync()
    expect(out[1]).toMatchObject({ feed: 'kev', action: 'cleared', cleared: 1 })
    expect(await intel('CVE-2026-0005')).toBeUndefined()
    expect((await intelStatus(db.pool))[1]).toMatchObject({ id: 'kev', imported_at: null })
    expect((await sync())[1]).toEqual({ feed: 'kev', action: 'absent' })
    // Base EPSS toujours là.
    expect((await intel('CVE-2026-0001')).epss).toBeCloseTo(0.03, 5)
  })
})
