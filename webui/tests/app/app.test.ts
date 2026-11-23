// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Racine de l'application : langue du document et titre « page · Scanoria »
// suivent la langue de la console.

import { afterEach, describe, expect, it } from 'vitest'
import { enableAutoUnmount } from '@vue/test-utils'
import { resetApi, route, setLocale, settle, mountIn, clearBody } from './helpers'
import App from '~/app.vue'

enableAutoUnmount(afterEach)

afterEach(async () => {
  resetApi()
  clearBody()
  await setLocale('fr')
})

describe('application', () => {
  it('attribut lang et gabarit de titre selon la langue', async () => {
    await setLocale('fr')
    route('GET', '/api/auth/session', () => ({ authenticated: false }))
    route('GET', '/api/about', () => ({
      product: 'Scanoria', version: '0.1.0', license: 'AGPL-3.0-or-later', copyright: 'Copyright (C) 2026 Vincent Tisseront',
      license_url: 'https://www.gnu.org/licenses/agpl-3.0.html', source_url: null, repository_url: null,
    }))
    await mountIn(App, { route: '/system/about' })
    await settle()
    expect(document.documentElement.lang).toBe('fr')
    expect(document.title).toBe('À propos et licence · Scanoria')
    await setLocale('en')
    await settle()
    expect(document.documentElement.lang).toBe('en')
    expect(document.title).toBe('About and license · Scanoria')
  })
})
