// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Chantier B (0.8) : I10 étendu à H7, statut VEX proposé avec une demande
// d'exception. Seulement pour une vulnérabilité de dépendance ; « none » et
// une justification hors not_affected donnent null ; l'avis I11 est lu dans
// le projet de la tâche et réduit à son verdict et à son résumé.

import { describe, expect, it } from 'vitest'
import { draftException, DraftExceptionOutput } from '../../server/ai/tasks/exception'
import type { Queryable } from '../../server/utils/db'

const PID = '00000000-0000-4000-8000-000000000001'
const FID = '00000000-0000-4000-8000-000000000002'
const finding = {
  tool: 'osv-scanner', rule_id: 'CVE-2026-0001', category: 'sca', severity: 'high', native_severity: 'HIGH', title: 't', message: 'm',
  path: 'package-lock.json', start_line: null, end_line: null, cwe: [], vuln_ids: ['CVE-2026-0001'], package: null,
  malicious: false, secret_type: null, snippet: null,
}
const base = { reason: 'Motif.', expires_in_days: 60, duration_rationale: 'Court.', to_check: [] }
const hints = { test: false, vendored: false, example: false, generated: false }

function db(reach: unknown): Queryable {
  return { query: async (q: string, params: unknown[]) => {
    if (q.includes('assess-reachability')) {
      expect(params).toEqual([FID, PID])
      return { rows: reach ? [{ output: reach }] : [] }
    }
    return { rows: [finding] }
  } } as unknown as Queryable
}

describe('I10 : statut VEX proposé (H7)', () => {
  it('contexte : vulnérabilité de dépendance, avis I11 réduit au verdict et au résumé', async () => {
    const reach = { reachability: 'improbable', summary: 'Aucun appel.', reasons: [], cited: [{ ref: 0, kind: 'call', path: 'src/a.js', line: 3, symbol: 'f' }] }
    const input = await draftException.load(db(reach), { projectId: PID, subjectId: FID })
    expect(input).toMatchObject({ vex_applicable: true, reachability: { reachability: 'improbable', summary: 'Aucun appel.' } })
    expect(JSON.stringify(input)).not.toContain('src/a.js')
    expect((await draftException.load(db({ reachability: 'peut-être' }), { projectId: PID, subjectId: FID }))!.reachability).toBeNull()
  })

  it('sortie : statut et justification gardés pour une vulnérabilité, null sinon', () => {
    const input = { finding: finding as never, path_hints: hints, max_days: 366, vex_applicable: true, reachability: null }
    expect(draftException.finalize({ ...base, vex_status: 'not_affected', vex_justification: 'vulnerable_code_not_in_execute_path' }, input))
      .toMatchObject({ vex_status: 'not_affected', vex_justification: 'vulnerable_code_not_in_execute_path' })
    expect(draftException.finalize({ ...base, vex_status: 'affected', vex_justification: 'component_not_present' }, input))
      .toMatchObject({ vex_status: 'affected', vex_justification: null })
    expect(draftException.finalize({ ...base, vex_status: 'none', vex_justification: 'none' }, input)).toMatchObject({ vex_status: null, vex_justification: null })
    expect(draftException.finalize({ ...base, vex_status: 'fixed', vex_justification: 'none' }, { ...input, vex_applicable: false }))
      .toMatchObject({ vex_status: null, vex_justification: null })
    expect(DraftExceptionOutput.safeParse({ ...base, vex_status: 'peut-être' }).success).toBe(false)
    // Sorties d'avant la 0.8 (sans champ VEX) toujours valides.
    expect(DraftExceptionOutput.safeParse(base).success).toBe(true)
  })

  it('résultat SAST : pas de statut VEX ni d\'avis I11 lu', async () => {
    let reads = 0
    const sast = { query: async (q: string) => {
      if (q.includes('assess-reachability')) reads++
      return { rows: [{ ...finding, category: 'sast', vuln_ids: [] }] }
    } } as unknown as Queryable
    expect(await draftException.load(sast, { projectId: PID, subjectId: FID })).toMatchObject({ vex_applicable: false, reachability: null })
    expect(reads).toBe(0)
  })
})
