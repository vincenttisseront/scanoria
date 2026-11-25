// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Chantier B (0.7) : I10, rédaction des exceptions (draft-exception), sans
// base. Enregistrement et banc d'essai I23 (cas d'injection compris), aucune
// rédaction pour un paquet malveillant (H4), durée ramenée dans [7, 366],
// sortie échappée, consigne qui rappelle que l'IA ne décide rien.

import { describe, expect, it } from 'vitest'
import { draftException, DRAFT_MAX_DAYS, DRAFT_MIN_DAYS, DraftExceptionOutput } from '../../server/ai/tasks/exception'
import { COMPLETION_KINDS, TASK_KINDS, TASKS } from '../../server/ai/tasks'
import { SUITES } from '../../server/ai/testbed'
import type { Queryable } from '../../server/utils/db'

const PID = '00000000-0000-4000-8000-000000000001'
const FID = '00000000-0000-4000-8000-000000000002'

function fakeDb(row: Record<string, unknown> | null): Queryable {
  return { query: async () => ({ rows: row ? [row] : [], rowCount: row ? 1 : 0 }) } as unknown as Queryable
}
const row = (over: Record<string, unknown> = {}) => ({
  tool: 'osv-scanner', rule_id: 'GHSA-0000-0000-0001', category: 'sca', severity: 'high', native_severity: 'HIGH', title: 't', message: 'm',
  path: 'package-lock.json', start_line: null, end_line: null, cwe: [], vuln_ids: ['GHSA-0000-0000-0001'], package: null,
  malicious: false, secret_type: null, snippet: null, ...over,
})
const ctx = { projectId: PID, subjectId: FID, subjectType: 'finding', locale: 'fr' } as never

describe('I10 : rédaction des exceptions', () => {
  it('tâche enregistrée, de complétion, avec banc d\'essai et cas d\'injection', () => {
    expect(TASK_KINDS).toContain('draft-exception')
    expect(COMPLETION_KINDS).toContain('draft-exception')
    expect(TASKS['draft-exception']).toBe(draftException)
    const suite = SUITES['draft-exception']!
    expect(suite.cases.length).toBeGreaterThanOrEqual(3)
    expect(suite.cases.some(c => c.expect.must_not_contain.length > 0)).toBe(true)
    expect(draftException.instruction('fr')).not.toBe(draftException.instruction('en'))
    expect(draftException.instruction('fr')).toMatch(/ne décides rien/)
    expect(draftException.instruction('en')).toMatch(/decide nothing/)
  })

  it('contexte : rien pour un malveillant (H4), un résultat absent ou un identifiant invalide', async () => {
    expect(await draftException.load(fakeDb(row({ malicious: true })), ctx)).toBeNull()
    expect(await draftException.load(fakeDb(null), ctx)).toBeNull()
    expect(await draftException.load(fakeDb(row()), { ...(ctx as object), subjectId: 'x' } as never)).toBeNull()
    const input = await draftException.load(fakeDb(row({ path: 'tests/fixtures/a.json' })), ctx)
    expect(input).toMatchObject({ max_days: DRAFT_MAX_DAYS, path_hints: { test: true } })
  })

  it('secret : ni valeur, ni message, ni extrait envoyés', async () => {
    const input = await draftException.load(fakeDb(row({ category: 'secrets', secret_type: 'generic-api-key', message: 'valeur visible', snippet: 'key = abc' })), ctx)
    const sent = JSON.stringify(input)
    expect(sent).not.toContain('valeur visible')
    expect(sent).not.toContain('key = abc')
  })

  it('sortie : schéma strict, durée ramenée dans [7, 366], texte échappé', () => {
    expect(DraftExceptionOutput.safeParse({ reason: 'r', expires_in_days: 900, duration_rationale: 'd', to_check: [] }).success).toBe(false)
    expect(DraftExceptionOutput.safeParse({ reason: 'r', expires_in_days: 30, duration_rationale: 'd', to_check: [], extra: 1 }).success).toBe(false)
    const input = { finding: {} as never, path_hints: { test: false, vendored: false, example: false, generated: false }, max_days: DRAFT_MAX_DAYS }
    const short = draftException.finalize!({ reason: 'Motif.', expires_in_days: 1, duration_rationale: 'Court.', to_check: ['a'] }, input)
    expect(short.expires_in_days).toBe(DRAFT_MIN_DAYS)
    const out = draftException.finalize!({ reason: '<img src=x onerror=alert(1)> voir @equipe', expires_in_days: 90, duration_rationale: '<b>x</b>', to_check: ['<script>y</script>'] }, input)
    expect(out.expires_in_days).toBe(90)
    expect(JSON.stringify(out)).not.toMatch(/<img|<script|<b>/i)
  })
})
