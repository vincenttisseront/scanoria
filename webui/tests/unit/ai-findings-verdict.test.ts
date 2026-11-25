// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// 0.7 (contrat 32) : un résultat d'un module d'analyse par IA (origin = 'ai')
// n'entre pas dans le verdict tant qu'une personne ne l'a pas confirmé, même
// s'il cite un avis MAL- ou un secret ; confirmé, il compte comme un autre.

import { randomUUID } from 'node:crypto'
import { describe, expect, it } from 'vitest'
import { computeVerdict, type GateFinding, type GateInput } from '../../server/gates/evaluate'
import { excludeUnconfirmedAi, isUnconfirmedAi } from '../../server/findings/ai-findings'
import { modelLabel, parseModelLabel } from '../../server/ai/models'
import { GateRules } from '#shared/analysis'

function finding(p: Partial<GateFinding> = {}): GateFinding {
  return {
    id: randomUUID(), tool: 'fraim', rule_id: 'R1', category: 'sast', severity: 'critical', path: 'src/app.py',
    vuln_ids: [], package_name: null, malicious: false, secret_type: null, status: 'new', status_until: null, is_new: true,
    ...p,
  }
}

function run(p: Partial<GateInput> = {}) {
  return computeVerdict({
    gateId: randomUUID(), rules: GateRules.parse({}), modules: [{ module_id: 'fraim', status: 'ok' }], findings: [], exceptions: [],
    coverage: null, today: '2026-11-25', evaluatedAt: '2026-11-25T10:00:00Z', ...p,
  })
}

describe('résultats IA et verdict', () => {
  it('isUnconfirmedAi / excludeUnconfirmedAi', () => {
    expect(isUnconfirmedAi({ origin: 'ai' })).toBe(true)
    expect(isUnconfirmedAi({ origin: 'ai', ai_confirmed_at: '2026-11-25T09:00:00Z' })).toBe(false)
    expect(isUnconfirmedAi({ origin: 'module' })).toBe(false)
    expect(isUnconfirmedAi({})).toBe(false)
    const out = excludeUnconfirmedAi([{ origin: 'ai' }, { origin: 'module' }, { origin: 'ai', ai_confirmed_at: new Date() }])
    expect(out.excluded).toBe(1)
    expect(out.kept).toHaveLength(2)
  })

  it('non confirmé : hors verdict, même critique, secret ou MAL-', () => {
    const v = run({
      findings: [
        finding({ origin: 'ai' }),
        finding({ origin: 'ai', category: 'secrets', secret_type: 'generic' }),
        finding({ origin: 'ai', category: 'sca', malicious: true, vuln_ids: ['MAL-2026-9'] }),
      ],
    })
    expect(v.verdict).toBe('passed')
    expect(v.reasons).toEqual([])
    expect(v.counts.critical).toBe(0)
  })

  it('confirmé par une personne : compte comme un résultat normal', () => {
    const v = run({ findings: [finding({ origin: 'ai', ai_confirmed_at: '2026-11-25T09:00:00Z' })] })
    expect(v.verdict).toBe('failed')
    expect(v.counts.critical).toBe(1)
  })

  it('les résultats des autres modules ne changent pas', () => {
    expect(run({ findings: [finding({ origin: 'module' })] }).verdict).toBe('failed')
    expect(run({ findings: [finding()] }).verdict).toBe('failed')
  })

  it('libellé du modèle : nom et début de l’empreinte', () => {
    const label = modelLabel({ model: 'qwen:7b', digest: 'a'.repeat(64) })
    expect(label).toBe(`qwen:7b@${'a'.repeat(12)}`)
    expect(parseModelLabel(label)).toEqual({ model: 'qwen:7b', digest: 'a'.repeat(12) })
    expect(parseModelLabel(null)).toBeNull()
  })
})
