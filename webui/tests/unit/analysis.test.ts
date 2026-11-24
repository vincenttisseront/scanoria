// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Les contrats des analyses (webui/shared/analysis.ts) doivent correspondre à
// la migration 003_analyses.sql, au schéma des modules et aux schémas
// scan-job / scan-result du runner (docs/ARCHITECTURE.md § 12).

import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import Ajv2020 from 'ajv/dist/2020.js'
import { describe, expect, it } from 'vitest'
import {
  CATEGORIES, ERROR_CLASSES, EXCEPTION_KINDS, FINDING_STATUSES, FORGE_KINDS, GateRules, SCAN_MODULE_STATUSES,
  SCAN_PRIORITY, SCAN_STATUSES, SCAN_TRIGGERS, SCHEDULES, SECRET_STATES, SEVERITIES, VERDICTS, VerdictDetails,
} from '#shared/analysis'

const root = (rel: string) => fileURLToPath(new URL(`../../../${rel}`, import.meta.url))
const SQL = readFileSync(root('webui/server/db/migrations/003_analyses.sql'), 'utf8')
const schema = (name: string) => JSON.parse(readFileSync(root(`src/rootfs/usr/share/scanoria/schemas/${name}.schema.json`), 'utf8'))
const quoted = (values: readonly string[]) => values.map(v => `'${v}'`).join(', ')

describe('contrats des analyses', () => {
  it.each([
    ['severity', SEVERITIES], ['status', SCAN_STATUSES], ['trigger', SCAN_TRIGGERS],
    ['verdict', VERDICTS], ['finding status', FINDING_STATUSES], ['secret_state', SECRET_STATES],
    ['exception kind', EXCEPTION_KINDS], ['forge kind', FORGE_KINDS], ['schedule', SCHEDULES],
    ['module status', SCAN_MODULE_STATUSES], ['error_class', ERROR_CLASSES],
  ] as const)('énumération %s identique dans 003_analyses.sql', (_name, values) => {
    expect(SQL.replace(/\s+/g, ' ').replace(/\( /g, '(')).toContain(`IN (${quoted(values)})`)
  })

  it('catégories identiques au schéma des modules', () => {
    const mod = JSON.parse(readFileSync(root('catalog/schema/module.schema.json'), 'utf8'))
    expect([...CATEGORIES]).toEqual(mod.properties.categories.items.enum)
  })

  it('priorités : release > webhook/api > manuel > planifié', () => {
    expect(SCAN_PRIORITY.release).toBeGreaterThan(SCAN_PRIORITY.api)
    expect(SCAN_PRIORITY.api).toBeGreaterThan(SCAN_PRIORITY.manual)
    expect(SCAN_PRIORITY.manual).toBeGreaterThan(SCAN_PRIORITY.schedule)
  })

  it('règles du gate « defaut » valides, H4 et G13 non désactivables', () => {
    const seeded = JSON.parse(/'(\{[^']*"inconclusive_blocks"[^']*\})'::jsonb/.exec(SQL)![1]!)
    expect(GateRules.parse(seeded)).toEqual(seeded)
    expect(GateRules.safeParse({ ...seeded, block_malicious: false }).success).toBe(false)
    expect(GateRules.safeParse({ ...seeded, inconclusive_blocks: false }).success).toBe(false)
    expect(GateRules.safeParse({ ...seeded, extra: 1 }).success).toBe(false)
  })

  it('VerdictDetails : exemple valide, raison inconnue refusée', () => {
    const v = {
      verdict: 'inconclusive', gate_id: '3f1c2b9a-1d2e-4f3a-8b4c-5d6e7f8a9b0c', rules: GateRules.parse({}),
      evaluated_at: '2026-11-24T08:00:00Z', new_code_only: true,
      counts: { critical: 0, high: 1, medium: 0, low: 0, info: 0 },
      reasons: [{ code: 'module-error', blocking: true, count: 1, severity: null, module: 'trivy', finding_ids: [], actions: ['rerun'] }],
      exceptions_applied: [],
    }
    expect(VerdictDetails.safeParse(v).success).toBe(true)
    expect(VerdictDetails.safeParse({ ...v, reasons: [{ ...v.reasons[0], code: 'ai-says-no' }] }).success).toBe(false)
  })

  const ajv = new Ajv2020({ strict: false, allErrors: true })
  const job = ajv.compile(schema('scan-job'))
  const result = ajv.compile(schema('scan-result'))
  const id = '3f1c2b9a-1d2e-4f3a-8b4c-5d6e7f8a9b0c'
  const baseJob = {
    schema: 1, id, scan_id: id, created_at: '2026-11-24T08:00:00Z',
    source: { kind: 'git', url: 'https://forge.exemple.test/equipe/depot.git', ref: 'refs/heads/main', history: 'shallow', credential: null },
    modules: [{ id: 'gitleaks', version: '8.30.1' }],
  }

  it('scan-job : tâche valide, sources hostiles refusées', () => {
    expect(job(baseJob)).toBe(true)
    for (const bad of [
      { ...baseJob.source, url: 'https://user:pass@forge.exemple.test/x.git' },
      { ...baseJob.source, url: 'file:///etc/shadow' },
      { ...baseJob.source, url: '--upload-pack=touch /tmp/x' },
      { ...baseJob.source, ref: '--output=/etc/passwd' },
      { ...baseJob.source, ref: 'refs/heads/../../x' },
      { ...baseJob.source, history: 'all' },
    ]) expect(job({ ...baseJob, source: bad })).toBe(false)
    expect(job({ ...baseJob, modules: [{ id: '../trivy', version: '1' }] })).toBe(false)
    expect(job({ ...baseJob, modules: [{ id: 'trivy', version: '1', image: 'docker.io/x:latest' }] })).toBe(false)
  })

  it('scan-result : chemins de sortie relatifs seulement', () => {
    const ok = {
      schema: 1, id, scan_id: id, status: 'ok', error: null,
      started_at: '2026-11-24T08:00:00Z', finished_at: '2026-11-24T08:01:00Z',
      source: { kind: 'git', commit: 'a'.repeat(40), history: 'shallow', files: 10, bytes: 1000, skipped: [] },
      modules: [{
        id: 'gitleaks', version: '8.30.1', status: 'ok', error: null, image_digest: `sha256:${'b'.repeat(64)}`,
        feeds: [], outputs: { sarif: 'gitleaks/result.sarif' }, log: 'gitleaks/log.txt',
      }],
    }
    expect(result(ok)).toBe(true)
    for (const p of ['../x.sarif', '/etc/passwd', 'a/../../b', 'a/./b'])
      expect(result({ ...ok, modules: [{ ...ok.modules[0], outputs: { sarif: p } }] })).toBe(false)
  })
})
