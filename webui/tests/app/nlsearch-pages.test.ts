// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Recherche en langage naturel (I8) dans la console : champ masqué sans
// connecteur, indicateur d'attente, filtres proposés en pastilles retirables
// avant application, marque « proposé par IA », parties non traduites
// signalées, application à la page ou ouverture de l'autre page.

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { enableAutoUnmount } from '@vue/test-utils'
import { mockNuxtImport } from '@nuxt/test-utils/runtime'
import { bodyText, callsTo, clearBody, click, mountIn, resetApi, route, setLocale, settle, setUser } from './helpers'
import AiNlSearch from '~/components/ai/NlSearch.vue'

const { navigate } = vi.hoisted(() => ({ navigate: vi.fn() }))
mockNuxtImport('navigateTo', () => navigate)

enableAutoUnmount(afterEach)
beforeEach(async () => {
  await setLocale('fr')
  navigate.mockReset()
  setUser('viewer')
})
afterEach(() => {
  resetApi()
  clearBody()
})

const P1 = '11111111-1111-4111-8111-111111111111'
const SUBJECT = `nl:${'a'.repeat(64)}`
const task = (status: string, error: string | null = null) => ({ id: 't1', status, error, model: 'qwen-test:14b', model_digest: 'd'.repeat(64), generated_at: null })

async function typeAndTranslate(w: Awaited<ReturnType<typeof mountIn>>, phrase: string) {
  await w.find('input').setValue(phrase)
  await w.find('form').trigger('submit')
  await settle()
}

describe('recherche en langage naturel (I8)', () => {
  it('sans connecteur : rien n’est affiché', async () => {
    route('GET', '/api/ai/search', () => ({ enabled: false, task: null, result: null }))
    const w = await mountIn(AiNlSearch, { props: { target: 'findings' } })
    await settle()
    expect(w.find('[data-testid="ai-nl-search"]').exists()).toBe(false)
  })

  it('traduit, affiche les filtres, retire une pastille puis applique à la page', async () => {
    route('GET', '/api/ai/search', (e) => {
      const q = new URL(e.node.req.url!, 'http://x').searchParams
      if (!q.get('subject_id')) return { enabled: true, task: null, result: null }
      return {
        enabled: true,
        task: task('done'),
        result: {
          target: 'findings',
          query: { project_id: P1, severity: 'critical', secret: 'true' },
          chips: [{ key: 'project_id', value: 'boutique' }, { key: 'severity', value: 'critical' }, { key: 'secret', value: 'true' }],
          explanation: 'Secrets critiques du projet boutique.',
          unsupported: ['depuis un mois'],
        },
      }
    })
    route('POST', '/api/ai/search', () => ({ subject_id: SUBJECT, task_id: 't1' }))
    const w = await mountIn(AiNlSearch, { props: { target: 'findings' } })
    await settle()
    await typeAndTranslate(w, 'secrets critiques du projet boutique depuis un mois')
    expect(callsTo('POST', '/api/ai/search')[0]!.body).toEqual({ phrase: 'secrets critiques du projet boutique depuis un mois', target: 'auto', locale: 'fr' })
    expect(callsTo('GET', '/api/ai/search').at(-1)!.query).toEqual({ subject_id: SUBJECT, locale: 'fr' })
    expect(bodyText()).toContain('Projet : boutique')
    expect(bodyText()).toContain('Gravité : critical')
    expect(bodyText()).toContain('Non traduit en filtre : depuis un mois')
    expect(bodyText()).toContain('proposé par IA · qwen-test:14b')
    await click(document.body.querySelector('[data-testid="ai-nl-chip-severity"] button')!)
    expect(w.find('[data-testid="ai-nl-chip-severity"]').exists()).toBe(false)
    await click(document.body.querySelector('[data-testid="ai-nl-apply"]')!)
    expect(w.emitted('apply')![0]).toEqual([{ project_id: P1, secret: 'true' }, { project_id: 'boutique', secret: 'true' }])
  })

  it('résultat pour l’autre page : ouverture de la page Composants avec ses paramètres', async () => {
    route('GET', '/api/ai/search', e => (new URL(e.node.req.url!, 'http://x').searchParams.get('subject_id')
      ? { enabled: true, task: task('done'), result: { target: 'components', query: { name: 'lodash', version: '4.17.20' }, chips: [{ key: 'name', value: 'lodash' }, { key: 'version', value: '4.17.20' }], explanation: 'lodash', unsupported: [] } }
      : { enabled: true, task: null, result: null }))
    route('POST', '/api/ai/search', () => ({ subject_id: SUBJECT, task_id: 't1' }))
    const w = await mountIn(AiNlSearch, { props: { target: 'findings' } })
    await settle()
    await typeAndTranslate(w, 'qui utilise lodash 4.17.20')
    expect(bodyText()).toContain('Ouvrir dans Composants')
    await click(document.body.querySelector('[data-testid="ai-nl-apply"]')!)
    expect(navigate).toHaveBeenCalledWith({ path: '/components', query: { q: 'lodash', from: '4.17.20', to: '4.17.20' } })
    expect(w.emitted('apply')).toBeUndefined()
  })

  it('attente puis erreur : indicateur, puis cause affichée, aucun filtre', async () => {
    let n = 0
    route('GET', '/api/ai/search', e => (new URL(e.node.req.url!, 'http://x').searchParams.get('subject_id')
      ? { enabled: true, task: n++ === 0 ? task('running') : task('skipped', 'disabled-by-testbed'), result: null }
      : { enabled: true, task: null, result: null }))
    route('POST', '/api/ai/search', () => ({ subject_id: SUBJECT, task_id: 't1' }))
    vi.useFakeTimers({ shouldAdvanceTime: true })
    try {
      const w = await mountIn(AiNlSearch, { props: { target: 'findings' } })
      await settle()
      await typeAndTranslate(w, 'secrets')
      expect(w.find('[data-testid="ai-pending"]').exists()).toBe(true)
      await vi.advanceTimersByTimeAsync(1600)
      await settle()
      expect(bodyText()).toContain('tâche désactivée par le banc d’essai')
      expect(w.find('[data-testid="ai-nl-result"]').exists()).toBe(false)
    }
    finally {
      vi.useRealTimers()
    }
  })

  it('connecteur coupé entre-temps : message, aucune requête de lecture', async () => {
    route('GET', '/api/ai/search', () => ({ enabled: true, task: null, result: null }))
    route('POST', '/api/ai/search', () => ({ subject_id: null, task_id: null }))
    const w = await mountIn(AiNlSearch, { props: { target: 'components' } })
    await settle()
    await typeAndTranslate(w, 'log4j')
    expect(bodyText()).toContain('connecteur inactif')
    expect(callsTo('GET', '/api/ai/search')).toHaveLength(1)
  })
})
