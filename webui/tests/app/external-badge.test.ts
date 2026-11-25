// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// J6 (0.6) dans la console : badge « externe » d'un résultat ou d'une analyse
// reçus d'un outil tiers, avec sa source ; rien pour un résultat de module.

import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { enableAutoUnmount } from '@vue/test-utils'
import { clearBody, mountIn, resetApi, setLocale, settle } from './helpers'
import ExternalBadge from '~/components/findings/ExternalBadge.vue'

enableAutoUnmount(afterEach)
beforeEach(async () => {
  await setLocale('fr')
})
afterEach(() => {
  resetApi()
  clearBody()
})

describe('badge externe (J6)', () => {
  it('résultat externe : badge et source', async () => {
    const w = await mountIn(ExternalBadge, { props: { origin: 'external', source: { tool: 'Acme SAST', version: '4.2.0', format: 'sarif', uploaded_via: 'api-token' } } })
    await settle()
    expect(w.text()).toContain('externe')
    expect(w.html()).toContain('Acme SAST')
  })

  it('résultat de module : rien', async () => {
    const w = await mountIn(ExternalBadge, { props: { origin: 'module', source: null } })
    await settle()
    expect(w.text()).toBe('')
  })

  it('anglais', async () => {
    await setLocale('en')
    const w = await mountIn(ExternalBadge, { props: { origin: 'external', source: { tool: 'X', version: null, format: 'cyclonedx', uploaded_via: 'console' } } })
    await settle()
    expect(w.text().toLowerCase()).toContain('external')
  })
})
