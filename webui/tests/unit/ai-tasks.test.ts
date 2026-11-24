// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Tâches IA de la 0.4 (I3, I5, I14, I15, I17), sans base : garde-fous de
// finalize (citations vérifiées, liens reconstruits, réglage calculé sans le
// modèle), contexte de journal masqué et borné, clés de règle, données
// locales jamais envoyées.

import { randomBytes } from 'node:crypto'
import { describe, expect, it } from 'vitest'
import { triageFinding, type TriageInput } from '../../server/ai/tasks/triage'
import { summarizeScan, type SummaryInput } from '../../server/ai/tasks/summary'
import { classifySecret, isGenericSecret } from '../../server/ai/tasks/secret'
import { diagnoseScan, proposeTimeout, MAX_PROPOSED_TIMEOUT_S, type DiagnoseInput } from '../../server/ai/tasks/diagnose'
import { ruleKey, RULE_KEY_RE, translateRule } from '../../server/ai/tasks/translate'
import { aiLogContext, MAX_CONTEXT_BYTES, sanitizeContext, tailBytes } from '../../server/ai/context'
import { pathHints, quoteFound } from '../../server/ai/task-kit'
import { buildMessages, promptView } from '../../server/ai/prompt'
import { TASK_KINDS, TASKS } from '../../server/ai/tasks'
import { SUITES } from '../../server/ai/testbed'

const fakeToken = () => ['gh', 'p_'].join('') + randomBytes(27).toString('base64url').replace(/[^A-Za-z0-9]/g, 'q').slice(0, 36)

function triageInput(over: Partial<TriageInput['finding']> = {}): TriageInput {
  return {
    finding: {
      tool: 'semgrep', rule_id: 'r', category: 'sast', severity: 'high', native_severity: null, title: 'Use of eval',
      message: 'eval with input', path: 'tests/unit/test_eval.py', start_line: 3, end_line: 3, cwe: [], vuln_ids: [],
      package: null, malicious: false, secret_type: null, snippet: 'eval(fixture_input)  # test only', ...over,
    },
    path_hints: pathHints(over.path ?? 'tests/unit/test_eval.py'),
    examples: [],
  }
}

describe('tâches de la 0.4 : enregistrement', () => {
  it('chaque tâche a son banc d\'essai I23, son schéma et une invite dans les deux langues', () => {
    for (const kind of ['triage-finding', 'summarize-scan', 'classify-secret', 'diagnose-scan', 'translate-rule']) {
      expect(TASK_KINDS).toContain(kind)
      expect(SUITES[kind], kind).toBeDefined()
      expect(SUITES[kind]!.cases.length).toBeGreaterThanOrEqual(3)
      // Chaque banc d'essai contient au moins un cas d'injection.
      expect(SUITES[kind]!.cases.some(c => c.expect.must_not_contain.length > 0), kind).toBe(true)
      const def = TASKS[kind]!
      expect(def.instruction('fr')).not.toBe(def.instruction('en'))
      expect(def.jsonSchema).toMatchObject({ type: 'object', additionalProperties: false })
    }
  })
})

describe('I3 pré-tri : citation vérifiée, jamais de décision', () => {
  it('garde une citation présente dans les données', () => {
    const input = triageInput()
    const out = triageFinding.finalize({
      suggestion: 'likely-false-positive', summary: 'Test code.',
      reasons: [{ kind: 'test-code', quote: 'tests/unit/test_eval.py', explanation: 'Under tests/.' }],
    }, input)
    expect(out).toMatchObject({ suggestion: 'likely-false-positive', downgraded: false })
    expect(out.reasons[0]).toMatchObject({ cited: true, quote: 'tests/unit/test_eval.py' })
  })

  it('une citation inventée est retirée, et un indice tranché sans citation redevient « à confirmer »', () => {
    const out = triageFinding.finalize({
      suggestion: 'likely-true-positive', summary: 'Real.',
      reasons: [{ kind: 'real-risk', quote: 'os.system(user_input)', explanation: 'Command injection.' }],
    }, triageInput())
    expect(out.suggestion).toBe('to-confirm')
    expect(out.downgraded).toBe(true)
    expect(out.reasons[0]).toMatchObject({ cited: false, quote: '' })
  })

  it('« à confirmer » sans citation reste tel quel ; la sortie est échappée', () => {
    const out = triageFinding.finalize({
      suggestion: 'to-confirm', summary: '<img src=x onerror=alert(1)>Unsure @admin',
      reasons: [{ kind: 'other', quote: '', explanation: 'See https://evil.exemple.test/x' }],
    }, triageInput())
    expect(out).toMatchObject({ suggestion: 'to-confirm', downgraded: false })
    expect(out.summary).not.toMatch(/<|evil/)
    expect(out.reasons[0]!.explanation).toContain('[link removed]')
  })

  it('citation : insensible à la casse et aux espaces, trois caractères au moins', () => {
    expect(quoteFound('EVAL(fixture_input)', ['x', 'eval(fixture_input)  # test'])).toBe(true)
    expect(quoteFound('ab', ['ab'])).toBe(false)
    expect(quoteFound('absent', [null, undefined, 'present'])).toBe(false)
  })

  it('indices de chemin', () => {
    expect(pathHints('src/__tests__/a.ts').test).toBe(true)
    expect(pathHints('pkg/a_test.go').test).toBe(true)
    expect(pathHints('vendor/lib/a.go').vendored).toBe(true)
    expect(pathHints('docs/examples/conf.yaml').example).toBe(true)
    expect(pathHints('dist/app.min.js').generated).toBe(true)
    expect(pathHints(null)).toEqual({ test: false, vendored: false, example: false, generated: false })
    expect(pathHints('src/contest.py').test).toBe(false)
  })
})

describe('I5 résumé : priorités reconstruites depuis les candidats', () => {
  const ids = ['11111111-1111-4111-8111-111111111111', '22222222-2222-4222-8222-222222222222']
  const input: SummaryInput = {
    scan_number: 3, ref: 'main', status: 'done', verdict: 'failed', blocking_reasons: [], new_by_severity: { high: 2 },
    fixed_count: 0, open_count: 2, not_covered: [], failed_modules: [],
    candidates: [
      { ref: 1, tool: 'gitleaks', rule_id: 'g', severity: 'high', title: 'Key', path: 'a', line: 1, malicious: false, secret: true },
      { ref: 2, tool: 'trivy', rule_id: 't', severity: 'high', title: 'CVE', path: 'b', line: null, malicious: false, secret: false },
    ],
    _ids: ids,
    _scan_id: '33333333-3333-4333-8333-333333333333',
  }

  it('numéros hors liste ou répétés ignorés ; lien vers la console construit localement', () => {
    const out = summarizeScan.finalize({
      headline: 'H', changes: 'C', blocking: 'B', not_covered: 'N',
      priorities: [{ ref: 2, why: 'first' }, { ref: 2, why: 'dup' }, { ref: 9, why: 'out' }],
    }, input)
    expect(out.priorities).toEqual([{
      ref: 2, why: 'first', severity: 'high', finding_id: ids[1],
      link: `/findings?scan=${input._scan_id}&ids=${ids[1]}`,
    }])
  })

  it('les clés locales (« _… ») ne partent jamais au modèle', () => {
    expect(promptView(input)).not.toHaveProperty('_ids')
    const msg = buildMessages('fr', 'x', input).at(-1)!.content
    expect(msg).not.toContain(ids[0])
    expect(msg).not.toContain('_scan_id')
    expect(promptView([1, 2])).toEqual([1, 2])
  })
})

describe('I14 secrets génériques', () => {
  it('seuls les secrets sans type significatif sont classés', () => {
    expect(isGenericSecret({ category: 'secrets', secret_type: 'generic-api-key', rule_id: 'generic-api-key' })).toBe(true)
    expect(isGenericSecret({ category: 'secrets', secret_type: null, rule_id: 'x' })).toBe(true)
    expect(isGenericSecret({ category: 'secrets', secret_type: 'high-entropy', rule_id: 'x' })).toBe(true)
    expect(isGenericSecret({ category: 'secrets', secret_type: 'aws-access-key', rule_id: 'aws-access-token' })).toBe(false)
    expect(isGenericSecret({ category: 'sast', secret_type: null, rule_id: 'generic' })).toBe(false)
  })

  it('sortie échappée', () => {
    const out = classifySecret.finalize({ class: 'password', confidence: 'high', summary: '<b>pw</b>', reasons: ['@ops look'] }, {} as never)
    expect(out.summary).toBe('pw')
    expect(out.reasons[0]).toBe('@​ops look')
  })
})

describe('I15 diagnostic : réglage proposé sans le modèle', () => {
  const base: DiagnoseInput = {
    scan_number: 1, scan_status: 'done', scan_error: null, logs: [],
    modules: [{ module: 'semgrep', version: '1', status: 'timeout', error_class: 'infra', attempts: 1, duration_ms: 900_000, timeout_s: 900, peak_memory_mb: null }],
  }

  it('délai doublé (au moins +10 min), plafonné ; rien pour un autre statut', () => {
    expect(proposeTimeout({ module: 'm', status: 'timeout', timeout_s: 900 })).toEqual({ kind: 'timeout', module: 'm', current_s: 900, proposed_s: 1800 })
    expect(proposeTimeout({ module: 'm', status: 'timeout', timeout_s: 120 })!.proposed_s).toBe(720)
    expect(proposeTimeout({ module: 'm', status: 'timeout', timeout_s: 9000 })!.proposed_s).toBe(MAX_PROPOSED_TIMEOUT_S)
    expect(proposeTimeout({ module: 'm', status: 'timeout', timeout_s: MAX_PROPOSED_TIMEOUT_S })).toBeNull()
    expect(proposeTimeout({ module: 'm', status: 'oom', timeout_s: 900 })).toBeNull()
    expect(proposeTimeout({ module: 'm', status: 'timeout', timeout_s: null })).toBeNull()
  })

  it('un module inventé par le modèle est retiré ; la proposition vient des faits', () => {
    const out = diagnoseScan.finalize({ cause: 'memory', module: 'rm-rf', summary: 'S', fix: 'F', steps: [] }, base)
    expect(out.module).toBeNull()
    expect(out.proposal).toEqual({ kind: 'timeout', module: 'semgrep', current_s: 900, proposed_s: 1800 })
  })
})

describe('I15 contexte de journal joint', () => {
  it('masqué, réduit à la fin, borné pour l\'ensemble', () => {
    const token = fakeToken()
    const log = `${'line of output\n'.repeat(5000)}fatal: auth failed with ${token}\n`
    const ctx = aiLogContext([{ module: 'trivy', log }, { module: 'gitleaks', log: 'ok\n' }, { module: '../etc', log: 'x' }])
    expect(ctx.logs.map(l => l.module)).toEqual(['trivy', 'gitleaks'])
    expect(JSON.stringify(ctx)).not.toContain(token)
    expect(ctx.logs[0]!.excerpt).toContain('fatal: auth failed')
    expect(ctx.logs[0]!.excerpt.startsWith('…\n')).toBe(true)
    expect(Buffer.byteLength(JSON.stringify(ctx))).toBeLessThan(MAX_CONTEXT_BYTES + 2048)
  })

  it('revalidé par enqueueAiTask : autre tâche, autre forme ou valeur en clair refusées ou remasquées', () => {
    const token = fakeToken()
    expect(sanitizeContext('triage-finding', { logs: [] })).toBeNull()
    expect(sanitizeContext('diagnose-scan', { logs: [{ module: 'x', excerpt: 'a', extra: 1 }] })).toBeNull()
    expect(sanitizeContext('diagnose-scan', 'free text')).toBeNull()
    expect(sanitizeContext('diagnose-scan', null)).toBeNull()
    const ok = sanitizeContext('diagnose-scan', { logs: [{ module: 'trivy', excerpt: `token ${token}` }] })
    expect(JSON.stringify(ok)).not.toContain(token)
  })

  it('fin de texte en octets, sur une frontière de ligne', () => {
    expect(tailBytes('abc', 10)).toBe('abc')
    expect(tailBytes('first\nsecond\nthird', 12)).toBe('…\nthird')
    expect(Buffer.byteLength(tailBytes('é'.repeat(100), 21))).toBeLessThanOrEqual(25)
  })
})

describe('I17 traduction des règles', () => {
  it('clé outil:version:règle', () => {
    expect(ruleKey('semgrep', '1.2.3', 'python.lang.sqli')).toBe('semgrep:1.2.3:python.lang.sqli')
    expect(ruleKey('trivy', null, 'CVE-2026-0001')).toBe('trivy:unknown:CVE-2026-0001')
    expect(ruleKey('trivy', 'v1:2', 'a b')).toBe('trivy:v1-2:a_b')
    expect(ruleKey('Bad Tool', '1', 'r')).toBeNull()
    expect(RULE_KEY_RE.test('semgrep:1:r')).toBe(true)
  })

  it('sujet transverse sans projet, sortie échappée', () => {
    expect(translateRule.projectScoped).toBe(false)
    expect(translateRule.finalize({ translation: '<i>Requête</i> SQL' }, { tool: 't', rule_id: 'r', text: 'x' })).toEqual({ translation: 'Requête SQL' })
  })
})
