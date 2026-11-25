// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// K7, K5, K6 (0.7) contre un vrai PostgreSQL 16 : les SARIF enregistrés des
// modules agentic-radar, mcp-scanner et skill-scanner sont ingérés comme
// résultats normaux ; l'inventaire d'agentic-radar est enregistré pour
// l'analyse (agent_inventories), une seule fois même en cas de relance, et
// jamais pris d'un autre module ni d'un SARIF externe.

import { randomBytes } from 'node:crypto'
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { DATABASE_URL, createTestDatabase, type TestDatabase } from '../helpers/db'
import { loadConfig, setConfig } from '../../server/utils/config'
import { ingestModuleOutputs } from '../../server/findings/ingest'
import { readAgentInventory } from '../../server/ai/agent-inventory'

const MODULES = fileURLToPath(new URL('../../../modules/', import.meta.url))
const IDS = ['agentic-radar', 'mcp-scanner', 'skill-scanner']

describe.skipIf(!DATABASE_URL)('modules d’analyse du code IA K5–K7 (PostgreSQL réel)', () => {
  let db: TestDatabase
  let root: string
  let projectId: string
  let n = 0

  async function newScan(): Promise<{ id: string, dir: string }> {
    const job = crypto.randomUUID()
    const r = await db.pool.query<{ id: string }>(
      `INSERT INTO scans (project_id, number, trigger, priority, ref, commit_sha, profile_id, gate_id, status, job_id, started_at)
       VALUES ($1, $2, 'manual', 50, 'main', $3, (SELECT id FROM profiles WHERE slug = 'rapide'), (SELECT id FROM gates WHERE slug = 'defaut'), 'ingesting', $4, now())
       RETURNING id`,
      [projectId, ++n, randomBytes(20).toString('hex'), job],
    )
    const id = r.rows[0]!.id
    for (const m of IDS) await db.pool.query(`INSERT INTO scan_modules (scan_id, module_id, module_version, status) VALUES ($1, $2, '0.14.2', 'ok')`, [id, m])
    return { id, dir: join(root, 'scans', 'results', job) }
  }

  async function ingest(scan: { id: string, dir: string }, moduleId: string, doc: unknown, external = false) {
    await mkdir(join(scan.dir, moduleId), { recursive: true })
    await writeFile(join(scan.dir, moduleId, 'result.sarif'), JSON.stringify(doc))
    return ingestModuleOutputs(db.pool, { scanId: scan.id, moduleId, resultDir: scan.dir, outputs: { sarif: `${moduleId}/result.sarif` }, ...(external ? { external: true } : {}) })
  }
  const recorded = async (id: string) => JSON.parse(await readFile(`${MODULES}${id}/tests/recorded.sarif`, 'utf8')) as Record<string, unknown>

  beforeAll(async () => {
    db = await createTestDatabase()
    root = await mkdtemp(join(tmpdir(), 'scanoria-kmod-'))
    process.env.SCANORIA_SCANS_DIR = join(root, 'scans')
    await writeFile(join(root, 'catalog-index.json'), JSON.stringify({
      schema: 1, version: 1,
      modules: IDS.map(id => ({ id, version: '0.14.2', categories: ['ai'] })),
    }))
    setConfig(loadConfig({ NUXT_DATABASE_URL: db.url, NUXT_CATALOG_INDEX_FILE: join(root, 'catalog-index.json') }))
    projectId = (await db.pool.query<{ id: string }>(
      `INSERT INTO projects (slug, name, source_kind, profile_id, gate_id)
       VALUES ('agents', 'Agents', 'archive', (SELECT id FROM profiles WHERE slug = 'rapide'), (SELECT id FROM gates WHERE slug = 'defaut')) RETURNING id`,
    )).rows[0]!.id
  })

  afterAll(async () => {
    delete process.env.SCANORIA_SCANS_DIR
    await db?.drop()
    if (root) await rm(root, { recursive: true, force: true })
  })

  it('résultats des trois modules ingérés avec emplacement', async () => {
    const s = await newScan()
    for (const id of IDS) {
      const r = await ingest(s, id, await recorded(id))
      expect(r.errors).toEqual([])
      expect(r.count).toBeGreaterThan(0)
    }
    const { rows } = await db.pool.query<{ tool: string, rule_id: string, path: string | null }>('SELECT tool, rule_id, path FROM findings ORDER BY rule_id')
    expect(rows.map(r => r.rule_id)).toContain('agentic-radar/arbitrary-code-execution-ace')
    expect(rows.some(r => r.rule_id.startsWith('mcp-scanner/'))).toBe(true)
    expect(rows.some(r => r.rule_id.startsWith('skill-scanner/'))).toBe(true)
    // Aucun chemin absolu ni remontée hors du dépôt.
    expect(rows.every(r => !r.path || (!r.path.startsWith('/') && !r.path.includes('..')))).toBe(true)
  })

  it('inventaire enregistré une fois pour l’analyse, relu par la route', async () => {
    const s = await newScan()
    await ingest(s, 'agentic-radar', await recorded('agentic-radar'))
    await ingest(s, 'agentic-radar', await recorded('agentic-radar'))
    const inv = await readAgentInventory(db.pool, s.id)
    expect(inv!.module_version).toBe('0.14.2')
    expect(inv!.frameworks).toEqual(['langgraph'])
    expect(inv!.inventory.workflows[0]!.tools.length).toBeGreaterThan(0)
    expect(Number((await db.pool.query<{ n: string }>('SELECT count(*) AS n FROM agent_inventories WHERE scan_id = $1', [s.id])).rows[0]!.n)).toBe(1)
  })

  it('jamais pris d’un autre module, d’un SARIF externe, ni d’un inventaire invalide', async () => {
    const s = await newScan()
    const doc = await recorded('agentic-radar')
    await ingest(s, 'mcp-scanner', doc)
    await ingest(s, 'agentic-radar', doc, true)
    expect(await readAgentInventory(db.pool, s.id)).toBeNull()
    const bad = structuredClone(doc) as { runs: { properties: Record<string, unknown> }[] }
    bad.runs[0]!.properties['scanoria/agent-inventory'] = { version: 1, frameworks: [], workflows: [{ framework: 'DROP TABLE' }] }
    await ingest(s, 'agentic-radar', bad)
    expect(await readAgentInventory(db.pool, s.id)).toBeNull()
  })
})
