// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// 0.6 (V6, contrat 23, chantier D) : un module « not-applicable » n'est jamais
// compté comme absent ni en échec (G13) ; un module sans applies_to tourne
// toujours (décidé par le runner : b28) ; libellés et couleurs présents.

import { randomUUID } from 'node:crypto'
import { describe, expect, it } from 'vitest'
import { applicableModules, computeVerdict, type GateInput } from '../../server/gates/evaluate'
import { orchestrationGaps, detectionOf } from '../../server/scans/orchestration'
import { scanResultSchema } from '../../server/scans/contract'
import { GateRules, SCAN_MODULE_STATUSES, VerdictDetails } from '#shared/analysis'
import fr from '../../i18n/locales/fr'
import en from '../../i18n/locales/en'

function run(p: Partial<GateInput>) {
  const out = computeVerdict({
    gateId: randomUUID(), rules: GateRules.parse({}), modules: [], findings: [], exceptions: [],
    coverage: null, today: '2026-11-24', evaluatedAt: '2026-11-24T10:00:00Z', ...p,
  })
  expect(VerdictDetails.safeParse(out).success).toBe(true)
  return out
}

describe('not-applicable (V6)', () => {
  it('jamais compté comme absent : verdict favorable, aucune raison de module', () => {
    const v = run({ modules: [{ module_id: 'trivy', status: 'ok' }, { module_id: 'hadolint', status: 'not-applicable' }], planModules: ['trivy', 'hadolint'] })
    expect(v.verdict).toBe('passed')
    expect(v.reasons.filter(r => r.module === 'hadolint')).toEqual([])
  })

  it('un vrai absent du plan reste bloquant à côté d’un not-applicable (G13)', () => {
    const v = run({ modules: [{ module_id: 'hadolint', status: 'not-applicable' }], planModules: ['hadolint', 'trivy'] })
    expect(v.verdict).toBe('inconclusive')
    expect(v.reasons).toContainEqual(expect.objectContaining({ code: 'module-missing', module: 'trivy', blocking: true }))
  })

  it('applicableModules écarte seulement not-applicable', () => {
    const all = SCAN_MODULE_STATUSES.map(status => ({ module_id: status, status }))
    expect(applicableModules(all).map(m => m.status)).toEqual(SCAN_MODULE_STATUSES.filter(s => s !== 'not-applicable'))
  })

  it('couverture : entrée not-applicable (contrat 23) et repli SBOM (V3)', () => {
    const base = { version: '1', error: null, image_digest: null, feeds: [], outputs: {}, log: null }
    const result = scanResultSchema.parse({
      schema: 1, id: randomUUID(), scan_id: randomUUID(), status: 'ok', started_at: '2026-11-24T10:00:00Z', finished_at: '2026-11-24T10:00:00Z',
      source: { kind: 'git', commit: null, history: 'shallow', files: 0, bytes: 0, skipped: [], tree: 'a'.repeat(64), detection: {} },
      modules: [
        { ...base, id: 'hadolint', status: 'not-applicable' },
        { ...base, id: 'grype', status: 'ok', input: 'src', sbom_fallback: true },
        { ...base, id: 'trivy', status: 'ok', input: 'src' },
      ],
    })
    expect(orchestrationGaps(result)).toEqual([
      { kind: 'not-applicable', code: 'not-applicable', module: 'hadolint', reason: 'no-matching-files' },
      { kind: 'sbom-fallback', module: 'grype' },
    ])
  })

  it('détection : clés bornées et valeurs entières seulement', () => {
    expect(detectionOf({ 'python': 2, 'Bad Key': 1, 'go': -1, 'java': 1.5, 'shell': 0 })).toEqual({ python: 2, shell: 0 })
    expect(detectionOf(undefined)).toEqual({})
    expect(Object.keys(detectionOf(Object.fromEntries(Array.from({ length: 100 }, (_, i) => [`k${i}`, 1]))))).toHaveLength(64)
  })

  it('libellés fr et en du statut et de la couverture', () => {
    for (const l of [fr, en] as unknown as { scans: Record<string, Record<string, string>> }[]) {
      expect(l.scans.moduleStatus!['not-applicable']).toBeTruthy()
      expect(l.scans.gapKind!['not-applicable']).toBeTruthy()
      expect(l.scans.gapKind!['sbom-fallback']).toBeTruthy()
      expect(l.scans.gaps!.notApplicable).toContain('{module}')
      expect(l.scans.reusedFrom as unknown as string).toContain('{number}')
    }
  })
})
