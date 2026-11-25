// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// 0.7 (contrat 32) dans la console : badge « IA » d'un résultat d'un module
// d'analyse par IA, panneau du détail (informatif, modèle et empreinte),
// confirmation par une modale de la console réservée à operator, erreur de
// l'API affichée ; rien pour un résultat d'un autre module.

import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { enableAutoUnmount } from '@vue/test-utils'
import { apiFail, bodyText, button, callsTo, clearBody, click, mountIn, resetApi, route, setLocale, setUser, settle } from './helpers'
import AiOriginBadge from '~/components/findings/AiOriginBadge.vue'
import AiFindingPanel from '~/components/findings/AiFindingPanel.vue'

const ID = '0b7d3c1e-8f7a-4d2b-9c3e-1a2b3c4d5e6f'
const PENDING = { confirmed: false, confirmed_at: null, confirmed_by: null, model: 'qwen-test:7b', digest: 'abcdef012345' }

enableAutoUnmount(afterEach)
beforeEach(async () => {
  await setLocale('fr')
})
afterEach(() => {
  resetApi()
  clearBody()
})

describe('badge IA', () => {
  it('résultat IA : badge, confirmé ou non', async () => {
    let w = await mountIn(AiOriginBadge, { props: { origin: 'ai' } })
    expect(w.text()).toBe('IA')
    w = await mountIn(AiOriginBadge, { props: { origin: 'ai', confirmed: true } })
    expect(w.text()).toBe('IA confirmé')
  })

  it('autre origine : rien', async () => {
    const w = await mountIn(AiOriginBadge, { props: { origin: 'module' } })
    expect(w.text()).toBe('')
  })
})

describe('panneau d’un résultat IA', () => {
  it('autre origine : aucun appel, rien affiché', async () => {
    const w = await mountIn(AiFindingPanel, { props: { findingId: ID, origin: 'external' } })
    await settle()
    expect(w.text()).toBe('')
    expect(callsTo('GET', `/api/findings/${ID}/ai`)).toHaveLength(0)
  })

  it('viewer : informatif, modèle et empreinte, aucun bouton de confirmation', async () => {
    setUser('viewer')
    route('GET', `/api/findings/${ID}/ai`, () => PENDING)
    await mountIn(AiFindingPanel, { props: { findingId: ID, origin: 'ai' } })
    await settle()
    expect(bodyText()).toContain('n’entre pas dans le verdict')
    expect(bodyText()).toContain('qwen-test:7b (abcdef012345)')
    expect(document.querySelector('[data-testid="ai-finding-confirm"]')).toBeNull()
  })

  it('operator : confirmation par une modale, puis état confirmé et événement', async () => {
    setUser('operator')
    route('GET', `/api/findings/${ID}/ai`, () => PENDING)
    route('POST', `/api/findings/${ID}/ai-confirm`, () => ({ ...PENDING, confirmed: true, confirmed_by: 'operator', confirmed_at: '2026-11-25T09:00:00Z' }))
    const w = await mountIn(AiFindingPanel, { props: { findingId: ID, origin: 'ai' } })
    await settle()
    await click(document.querySelector('[data-testid="ai-finding-confirm"]')!)
    expect(bodyText()).toContain('Confirmer ce résultat proposé par IA ?')
    expect(callsTo('POST', `/api/findings/${ID}/ai-confirm`)).toHaveLength(0)
    await click(document.querySelector('[data-testid="ai-finding-confirm-send"]')!)
    expect(callsTo('POST', `/api/findings/${ID}/ai-confirm`)).toHaveLength(1)
    expect(bodyText()).toContain('Confirmé par operator')
    expect(w.emitted('confirmed')).toHaveLength(1)
  })

  it('refus de l’API (compte non humain) : message d’erreur, rien de confirmé', async () => {
    setUser('operator')
    route('GET', `/api/findings/${ID}/ai`, () => PENDING)
    route('POST', `/api/findings/${ID}/ai-confirm`, () => apiFail(403, 'E_FORBIDDEN'))
    const w = await mountIn(AiFindingPanel, { props: { findingId: ID, origin: 'ai' } })
    await settle()
    await click(document.querySelector('[data-testid="ai-finding-confirm"]')!)
    await click(document.querySelector('[data-testid="ai-finding-confirm-send"]')!)
    expect(w.emitted('confirmed')).toBeUndefined()
    expect(bodyText()).not.toContain('Confirmé par')
    await click(button('Annuler'))
  })

  it('anglais', async () => {
    await setLocale('en')
    setUser('viewer')
    route('GET', `/api/findings/${ID}/ai`, () => ({ ...PENDING, confirmed: true, confirmed_by: 'admin', confirmed_at: '2026-11-25T09:00:00Z' }))
    await mountIn(AiFindingPanel, { props: { findingId: ID, origin: 'ai' } })
    await settle()
    expect(bodyText().toLowerCase()).toContain('confirmed by admin')
  })
})
