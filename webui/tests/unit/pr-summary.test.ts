// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Retour dans la PR : statut de commit, commentaire de synthèse (verdict,
// raisons, résultats, H6, I25 marqué IA, J15) et annotations bornées (J7).
import { randomUUID } from 'node:crypto'
import { describe, expect, it } from 'vitest'
import type { VerdictDetails } from '#shared/analysis'
import { buildAnnotations, buildSummary, shortId, statusFor, type SummaryFinding, type SummaryInput } from '../../server/forges/summary'
import { sanitizeForForge } from '../../server/forges/sanitize'

function details(verdict: VerdictDetails['verdict'], reasons: Partial<VerdictDetails['reasons'][number]>[] = []): VerdictDetails {
  return {
    verdict, gate_id: randomUUID(), rules: {} as VerdictDetails['rules'], evaluated_at: new Date().toISOString(), new_code_only: true,
    counts: { critical: 0, high: 1, medium: 0, low: 0, info: 0 },
    reasons: reasons.map(r => ({ code: 'secret', blocking: true, count: 1, severity: 'high', module: null, finding_ids: [], actions: ['fix'], ...r })),
    exceptions_applied: [],
  } as VerdictDetails
}

function finding(p: Partial<SummaryFinding> = {}): SummaryFinding {
  return {
    id: randomUUID(), tool: 'gitleaks', rule_id: 'generic-api-key', title: 'Secret probable', severity: 'high', path: 'src/config.ts', start_line: 12,
    category: 'secrets', malicious: false, secret_type: 'generic', ai_summary: null, ai_model: null, ...p,
  }
}

function input(p: Partial<SummaryInput> = {}): SummaryInput {
  return {
    locale: 'fr', phase: 'final', scanUrl: 'https://analyse.exemple.test/scans/1', exceptionUrl: id => `https://analyse.exemple.test/projects/p/exceptions/new?finding=${id}`,
    scanNumber: 7, profile: 'rapide', verdict: 'failed', details: details('failed', [{}]), earlyReasons: [], newFindings: [finding()], totalNew: 1,
    dependencies: null, quarantineDays: 7, aiVerdict: null, ...p,
  }
}

describe('statut de commit', () => {
  it('en cours, anticipé, favorable, défavorable, non concluant (G13 : échec)', () => {
    expect(statusFor('pending', null, null, [], 'fr').state).toBe('pending')
    const early = statusFor('early', null, null, ['secret', 'malicious-package'], 'fr')
    expect(early.state).toBe('failure')
    expect(early.description).toMatch(/secret/i)
    expect(statusFor('final', 'passed', details('passed'), [], 'en').state).toBe('success')
    expect(statusFor('final', 'failed', details('failed', [{ code: 'vuln', count: 3 }]), [], 'en').description).toMatch(/3/)
    expect(statusFor('final', 'inconclusive', details('inconclusive'), [], 'fr').state).toBe('failure')
  })
})

describe('commentaire de synthèse', () => {
  it('verdict, raisons, résultats avec identifiant court et lien d’exception', () => {
    const f = finding()
    const md = buildSummary(input({ newFindings: [f] }))
    expect(md).toContain(shortId(f.id))
    expect(md).toContain(`finding=${f.id}`)
    expect(md).toContain('/scanoria accept')
    expect(md).toMatch(/```\n\/scanoria accept/)
  })

  it('paquet malveillant : jamais de lien d’exception', () => {
    const f = finding({ malicious: true, tool: 'osv-scanner', rule_id: 'MAL-2026-1', category: 'sca' })
    const md = buildSummary(input({ newFindings: [f] }))
    expect(md).not.toContain(`finding=${f.id}`)
    expect(md).not.toContain('/scanoria accept')
  })

  it('I25 et I9 : explication de l’IA marquée « proposé par IA »', () => {
    const md = buildSummary(input({
      newFindings: [finding({ ai_summary: 'Clé codée en dur dans la configuration.', ai_model: 'modele-test:7b' })],
      aiVerdict: { text: 'Le gate bloque à cause d’un secret.', model: 'modele-test:7b' },
    }))
    expect(md.match(/proposé par IA/g)?.length).toBeGreaterThanOrEqual(2)
    expect(md).toMatch(/modele\\?-test/)
  })

  it('H6 : dépendances ajoutées, licence interdite, version récente, script d’installation', () => {
    const md = buildSummary(input({
      dependencies: {
        added: [
          { purl: 'pkg:npm/gauche@1.0.0', name: 'gauche', version: '1.0.0', licenses: ['AGPL-3.0-only'], decision: 'denied', age_days: 2, install_script: true },
          { purl: 'pkg:npm/sage@2.0.0', name: 'sage', version: '2.0.0', licenses: [], decision: 'allowed', age_days: 400, install_script: false },
        ],
        removed: 1,
        baseKnown: true,
      },
    }))
    expect(md).toContain('gauche')
    expect(md).toContain('❌')
    expect(md).toMatch(/⚠️/)
  })

  it('texte hostile d’un résultat : rien d’actif après nettoyage', () => {
    const f = finding({
      title: '<img src=x onerror=1> @admin ![p](https://piege.exemple.test/p.png)',
      rule_id: '[x](https://piege.exemple.test)',
      path: 'a|b`c.ts',
      ai_summary: 'Voir https://piege.exemple.test et #1',
    })
    const out = sanitizeForForge(buildSummary(input({ newFindings: [f] })), { consoleUrl: 'https://analyse.exemple.test' })
    expect(out).not.toMatch(/<img|!\[|https:\/\/piege|(^|[^\\])@admin|\s#1\b/)
    expect(out).not.toContain('a|b')
  })

  it('anglais et phase « en cours »', () => {
    const md = buildSummary(input({ locale: 'en', phase: 'pending', verdict: null, details: null, newFindings: [], totalNew: 0 }))
    expect(md).not.toContain('/scanoria accept')
    expect(md).toMatch(/Scanoria/)
  })
})

describe('annotations (J7)', () => {
  it('fichiers modifiés seulement, plus graves d’abord, bornées', () => {
    const list = [
      finding({ severity: 'low', path: 'a.ts', start_line: 1 }),
      finding({ severity: 'critical', path: 'b.ts', start_line: 9 }),
      finding({ severity: 'high', path: 'hors-pr.ts', start_line: 3 }),
      finding({ severity: 'medium', path: null, start_line: null }),
    ]
    const out = buildAnnotations(list, new Set(['a.ts', 'b.ts']), 'fr', 30)
    expect(out.map(a => a.path)).toEqual(['b.ts', 'a.ts'])
    expect(out[0]!.level).toBe('failure')
    expect(buildAnnotations(Array.from({ length: 80 }, (_, i) => finding({ start_line: i + 1 })), null, 'fr', 30)).toHaveLength(30)
  })
})
