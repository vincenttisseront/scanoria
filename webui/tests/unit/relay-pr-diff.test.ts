// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// 0.7 (K2, K4) : commit de base d'une PR (prBase) et champ pr_base du contrat de tâche.

import { describe, expect, it } from 'vitest'
import { prBase } from '../../server/scans/plan'
import { scanJobSchema } from '../../server/scans/contract'

const job = (extra: Record<string, unknown>) => ({
  schema: 1, id: '11111111-1111-4111-8111-111111111111', scan_id: '22222222-2222-4222-8222-222222222222',
  created_at: '2026-11-25T10:00:00Z', source: { kind: 'archive', upload_id: '33333333-3333-4333-8333-333333333333' },
  modules: [{ id: 'pr-agent', version: '0.50.0' }], ...extra,
})

describe('commit de base des PR (K2, K4)', () => {
  it('prBase : SHA-1 ou SHA-256 seulement', () => {
    expect(prBase({ pull_request: { base_sha: 'a'.repeat(40) } })).toBe('a'.repeat(40))
    expect(prBase({ pull_request: { base_sha: 'f'.repeat(64) } })).toBe('f'.repeat(64))
    for (const bad of ['A'.repeat(40), 'a'.repeat(39), '-x', 42, null, undefined]) {
      expect(prBase({ pull_request: { base_sha: bad } })).toBeUndefined()
    }
    expect(prBase({ pull_request: null })).toBeUndefined()
    expect(prBase({})).toBeUndefined()
  })

  it('contrat de tâche : pr_base validé', () => {
    expect(scanJobSchema.safeParse(job({ pr_base: 'a'.repeat(40) })).success).toBe(true)
    expect(scanJobSchema.safeParse(job({})).success).toBe(true)
    expect(scanJobSchema.safeParse(job({ pr_base: '--output=/etc/x' })).success).toBe(false)
  })
})
