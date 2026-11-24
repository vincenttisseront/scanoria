// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Choix automatique des modèles (I1) et banc d'essai (I23).

import { describe, expect, it } from 'vitest'
import { completionScore, contextFor, modelInfo, parseParameterSize, selectModels, type ModelInfo } from '../../server/ai/models'
import { EMBED_SUITE, SUITES, scoreCase, summarize } from '../../server/ai/testbed'
import { COMPLETION_KINDS, EMBED_KINDS, TASK_KINDS, explainFinding, explainVerdict } from '../../server/ai/tasks'

const m = (name: string, p: number | null, ctx: number | null, caps = ['completion']): ModelInfo =>
  ({ name, digest: name.padEnd(12, '0'), capabilities: caps, context: ctx, parameters_b: p, family: null })

describe('modèles', () => {
  it('lit la taille et les capacités de /api/show', () => {
    expect(parseParameterSize('8.0B')).toBe(8)
    expect(parseParameterSize('137M')).toBe(0.137)
    expect(parseParameterSize('big')).toBeNull()
    expect(parseParameterSize(3)).toBeNull()
    const info = modelInfo('x', 'd', { capabilities: ['completion', 'tools'], details: { family: 'qwen2', parameter_size: '14.8B' }, model_info: { 'qwen2.context_length': 32768 } })
    expect(info).toEqual({ name: 'x', digest: 'd', capabilities: ['completion', 'tools'], context: 32768, parameters_b: 14.8, family: 'qwen2' })
    expect(modelInfo('e', 'd', { details: { family: 'nomic-bert' } }).capabilities).toEqual(['embedding'])
    expect(modelInfo('o', 'd', {}).capabilities).toEqual(['completion'])
  })

  it('préfère un modèle moyen à grand contexte, et explique le choix', () => {
    const models = [m('tiny', 1, 2048), m('mid', 14, 32768), m('huge', 70, 8192), m('emb', 0.1, 8192, ['embedding'])]
    expect(completionScore(models[1]!)).toBeGreaterThan(completionScore(models[2]!))
    const sel = selectModels(models, TASK_KINDS, {})
    expect(sel.tasks['explain-finding']).toMatchObject({ model: 'mid', reason: 'best-balance' })
    expect(sel.embedding).toMatchObject({ model: 'emb', reason: 'only-model' })
  })

  it('respecte le choix de l\'administrateur, et signale un modèle forcé absent', () => {
    const models = [m('a', 8, 8192), m('b', 14, 8192)]
    expect(selectModels(models, ['explain-finding'], { 'explain-finding': 'a' }).tasks['explain-finding']).toMatchObject({ model: 'a', reason: 'admin-choice' })
    expect(selectModels(models, ['explain-finding'], { 'explain-finding': 'zz' }).tasks['explain-finding']).toMatchObject({ model: 'b', reason: 'admin-choice-missing' })
    expect(selectModels([m('a', null, null)], ['explain-finding'], {}).tasks['explain-finding']).toMatchObject({ reason: 'only-model' })
  })

  it('sans modèle : aucune tâche, et recherche lexicale faute d\'embedding', () => {
    const sel = selectModels([m('emb', 0.1, 512, ['embedding']), m('emb2', 0.3, 2048, ['embedding'])], ['explain-finding'], {})
    expect(sel.tasks['explain-finding']).toBeNull()
    expect(sel.embedding).toMatchObject({ model: 'emb2', reason: 'largest-context' })
    expect(selectModels([], ['x'], {}).embedding).toBeNull()
  })

  it('dimensionne le contexte à la demande', () => {
    expect(contextFor(300, 32768)).toBe(4096)
    expect(contextFor(30_000, 32768)).toBe(12288)
    expect(contextFor(300_000, 32768)).toBe(32768)
    expect(contextFor(30_000, null)).toBe(12288)
  })
})

describe('banc d\'essai', () => {
  it('charge un jeu par tâche', () => {
    // Les tâches de rédaction ont un jeu de cas ; l'embedding (I7) a son jeu de paires (EMBED_SUITE).
    expect(Object.keys(SUITES).sort()).toEqual([...COMPLETION_KINDS].sort())
    expect(EMBED_SUITE.kind).toBe('embed-finding')
    expect([...TASK_KINDS].sort()).toEqual([...COMPLETION_KINDS, ...EMBED_KINDS].sort())
    for (const s of Object.values(SUITES)) {
      expect(s.cases.length).toBeGreaterThanOrEqual(3)
      for (const c of s.cases) {
        const def = s.kind === 'explain-finding' ? explainFinding : explainVerdict
        expect(Object.keys(def.jsonSchema.properties as object).length).toBeGreaterThan(0)
        expect(c.input).toBeTypeOf('object')
      }
    }
  })

  it('note les cas : sortie invalide, mention manquante, consigne injectée suivie', () => {
    const c = { id: 'x', input: {}, expect: { mention_any: ['SQL'], must_not_contain: ['CANARY'] } }
    expect(scoreCase(c, null).reason).toBe('invalid-output')
    expect(scoreCase(c, { a: 'sql injection' }).ok).toBe(true)
    expect(scoreCase(c, { a: 'nothing' }).reason).toBe('missing-mention')
    expect(scoreCase(c, { a: ['SQL', 'canary'] }).reason).toBe('injection-followed')
  })

  it('échoue sous le seuil, et toujours si une consigne injectée est suivie', () => {
    const suite = SUITES['explain-verdict']!
    expect(summarize(suite, [{ id: 'a', ok: true, reason: 'ok' }]).passed).toBe(true)
    expect(summarize(suite, [{ id: 'a', ok: true, reason: 'ok' }, { id: 'b', ok: false, reason: 'missing-mention' }]).passed).toBe(false)
    const many = Array.from({ length: 9 }, (_, i) => ({ id: `c${i}`, ok: true, reason: 'ok' as const }))
    expect(summarize(suite, [...many, { id: 'z', ok: false, reason: 'injection-followed' }])).toMatchObject({ score: 0.9, passed: false })
    expect(summarize(suite, []).score).toBe(0)
  })
})
