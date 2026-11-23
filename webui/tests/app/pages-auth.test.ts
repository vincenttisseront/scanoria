// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Pages de connexion, de compte et « À propos » (licence AGPL, lien vers le
// code source de la version installée).

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { enableAutoUnmount } from '@vue/test-utils'
import { mockNuxtImport } from '@nuxt/test-utils/runtime'
import { apiFail, button, callsTo, clearBody, mountIn, resetApi, route, setLocale, settle, setUser } from './helpers'
import LoginPage from '~/pages/login.vue'
import AccountPage from '~/pages/account.vue'
import AboutPage from '~/pages/system/about.vue'

const { navigateToMock, toastAdd } = vi.hoisted(() => ({ navigateToMock: vi.fn(), toastAdd: vi.fn() }))
mockNuxtImport('navigateTo', () => navigateToMock)
mockNuxtImport('useToast', () => () => ({ add: toastAdd }))

enableAutoUnmount(afterEach)

const ABOUT = {
  product: 'Scanoria',
  version: '0.1.0',
  license: 'AGPL-3.0-or-later',
  copyright: 'Copyright (C) 2026 Vincent Tisseront',
  license_url: 'https://www.gnu.org/licenses/agpl-3.0.html',
  source_url: 'https://github.com/exemple/scanoria/tree/v0.1.0',
  repository_url: 'https://github.com/exemple/scanoria',
}

beforeEach(async () => {
  await setLocale('fr')
  navigateToMock.mockReset()
  toastAdd.mockReset()
  setUser(null)
})
afterEach(() => {
  resetApi()
  clearBody()
})

async function fill(wrapper: Awaited<ReturnType<typeof mountIn>>, type: string, values: string[]) {
  const inputs = wrapper.findAll(`input[type="${type}"]`)
  for (const [i, v] of values.entries()) await inputs[i]!.setValue(v)
}

describe('connexion', () => {
  it('connecte, recharge la session et suit « next » interne', async () => {
    route('GET', '/api/about', () => ABOUT)
    route('POST', '/api/auth/login', () => ({ ok: true, csrf: 'c' }))
    route('GET', '/api/auth/session', () => ({ authenticated: true, csrf: 'c', address: null, user: { id: 1, username: 'alice', display_name: null, role: 'admin', locale: 'fr', must_change_password: false } }))
    const w = await mountIn(LoginPage, { route: '/login?next=/updates' })
    expect(w.text()).toContain('Connexion')
    expect(w.text()).toContain('Scanoria 0.1.0 · AGPL-3.0-or-later')
    expect(w.find('a[href="https://github.com/exemple/scanoria/tree/v0.1.0"]').exists()).toBe(true)
    await w.find('input[type="text"]').setValue('alice')
    await fill(w, 'password', ['un-mot-de-passe-long'])
    await w.find('form').trigger('submit')
    await settle()
    await vi.waitFor(() => expect(navigateToMock).toHaveBeenCalledWith('/updates'))
    expect(callsTo('POST', '/api/auth/login')[0]!.body).toEqual({ username: 'alice', password: 'un-mot-de-passe-long' })
    expect(useSession().state.value.user?.username).toBe('alice')
  })

  it('« next » externe ignoré ; échec affiché et mot de passe effacé ; anglais', async () => {
    await setLocale('en')
    route('GET', '/api/about', () => ({ ...ABOUT, source_url: null }))
    route('POST', '/api/auth/login', () => apiFail(401, 'E_INVALID_CREDENTIALS'))
    const w = await mountIn(LoginPage, { route: '/login?next=//exemple.test' })
    expect(w.text()).toContain('Sign in')
    expect(w.find('a[href="/system/about"]').exists()).toBe(true)
    await w.find('input[type="text"]').setValue('alice')
    await fill(w, 'password', ['mauvais-mot-de-passe'])
    await w.find('form').trigger('submit')
    await vi.waitFor(() => expect(w.text()).toContain('Wrong username or password'))
    expect((w.find('input[type="password"]').element as HTMLInputElement).value).toBe('')
    expect(navigateToMock).not.toHaveBeenCalled()
  })
})

describe('mon compte', () => {
  it('changement imposé : alerte, bouton inactif tant que la saisie est invalide, puis retour à l’accueil', async () => {
    setUser('viewer', { must_change_password: true })
    route('POST', '/api/auth/password', () => ({ ok: true }))
    route('GET', '/api/auth/session', () => ({ authenticated: true, csrf: 'c2', address: null, user: { id: 1, username: 'alice', display_name: null, role: 'viewer', locale: 'fr', must_change_password: false } }))
    const w = await mountIn(AccountPage)
    expect(w.text()).toContain('Pour continuer, choisissez un nouveau mot de passe.')
    expect(w.text()).toContain('alice · Lecteur')
    const save = () => button('Enregistrer')
    expect(save().disabled).toBe(true)
    await fill(w, 'password', ['ancien-mot-de-passe', 'nouveau-mot-de-passe', 'autre-chose-encore'])
    expect(w.text()).toContain('Les deux mots de passe diffèrent.')
    expect(save().disabled).toBe(true)
    await fill(w, 'password', ['ancien-mot-de-passe', 'nouveau-mot-de-passe', 'nouveau-mot-de-passe'])
    expect(save().disabled).toBe(false)
    await w.find('form').trigger('submit')
    await settle()
    expect(callsTo('POST', '/api/auth/password')[0]!.body).toEqual({ current_password: 'ancien-mot-de-passe', new_password: 'nouveau-mot-de-passe' })
    expect(toastAdd).toHaveBeenCalledWith(expect.objectContaining({ color: 'success' }))
    expect(navigateToMock).toHaveBeenCalledWith('/')
    expect((w.find('input[type="password"]').element as HTMLInputElement).value).toBe('')
  })

  it('mot de passe actuel incorrect : message traduit, pas de redirection', async () => {
    setUser('admin')
    route('POST', '/api/auth/password', () => apiFail(400, 'E_CURRENT_PASSWORD'))
    const w = await mountIn(AccountPage)
    expect(w.text()).not.toContain('Pour continuer')
    await fill(w, 'password', ['faux-mot-de-passe', 'nouveau-mot-de-passe', 'nouveau-mot-de-passe'])
    await w.find('form').trigger('submit')
    await settle()
    expect(toastAdd).toHaveBeenCalledWith(expect.objectContaining({ title: 'Le mot de passe actuel est incorrect.', color: 'error' }))
    expect(navigateToMock).not.toHaveBeenCalled()
  })
})

describe('à propos', () => {
  it('licence, copyright et lien vers le code source de la version installée', async () => {
    route('GET', '/api/about', () => ABOUT)
    const w = await mountIn(AboutPage)
    await settle()
    expect(w.text()).toContain('AGPL-3.0-or-later')
    expect(w.text()).toContain('Copyright (C) 2026 Vincent Tisseront')
    expect(w.text()).toContain('Code source de la version 0.1.0')
    expect(w.find(`a[href="${ABOUT.source_url}"]`).exists()).toBe(true)
    expect(w.find(`a[href="${ABOUT.license_url}"]`).exists()).toBe(true)
  })

  it('dépôt d’origine inconnu : avertissement (anglais)', async () => {
    await setLocale('en')
    route('GET', '/api/about', () => ({ ...ABOUT, source_url: null }))
    const w = await mountIn(AboutPage)
    await settle()
    expect(w.text()).toContain('About and license')
    expect(w.text()).toContain('update-source.json')
  })
})
