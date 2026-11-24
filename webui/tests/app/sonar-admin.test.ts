// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Chantier B de la 0.4 : accès administrateur de SonarQube dans le détail du
// module (lien, décisions automatiques, réinitialisation du mot de passe
// admin confirmée par une modale, mot de passe affiché une seule fois).
// Le mot de passe de test est généré à l'exécution.

import { randomBytes } from 'node:crypto'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { enableAutoUnmount } from '@vue/test-utils'
import { mockNuxtImport } from '@nuxt/test-utils/runtime'
import { apiFail, bodyText, button, buttons, callsTo, clearBody, click, mountIn, resetApi, route, setLocale, settle, setUser } from './helpers'
import ServiceAdminAccess from '~/components/ServiceAdminAccess.vue'
import ModulePage from '~/pages/catalog/[id].vue'

const { toastAdd } = vi.hoisted(() => ({ toastAdd: vi.fn() }))
mockNuxtImport('useToast', () => () => ({ add: toastAdd }))

enableAutoUnmount(afterEach)

beforeEach(async () => {
  await setLocale('fr')
  toastAdd.mockReset()
})
afterEach(() => {
  vi.useRealTimers()
  resetApi()
  clearBody()
})

const PW = `Sq#${randomBytes(16).toString('hex')}9a`
const PROPS = { moduleId: 'sonarqube', name: 'SonarQube Community Build', appUrl: 'https://sonarqube.analyse.exemple.test', isAdmin: true }

function fakeClock(): void {
  vi.useFakeTimers({ toFake: ['setTimeout', 'setInterval', 'clearTimeout', 'clearInterval'] })
}
async function drive(rounds = 3): Promise<void> {
  for (let i = 0; i < rounds; i++) await vi.advanceTimersByTimeAsync(2100)
  await settle()
}
function helper(final: Record<string, unknown> = { status: 'ok', code: 'OK' }) {
  route('POST', '/api/catalog/modules/sonarqube/admin-password', () => ({ request_id: 'r1' }))
  route('GET', '/api/requests/r1', () => ({ id: 'r1', type: 'reset-service-admin', step: null, message: null, output: null, ...final }))
}

describe('accès administrateur SonarQube', () => {
  it('affiche le lien, les décisions automatiques et l’identifiant', async () => {
    setUser('admin')
    const w = await mountIn(ServiceAdminAccess, { props: PROPS })
    expect(w.text()).toContain('Accès administrateur')
    expect(w.text()).toContain('mot de passe « admin » remplacé')
    expect(w.text()).toContain('Identifiant : admin')
    expect(w.find('a[href="https://sonarqube.analyse.exemple.test"]').exists()).toBe(true)
  })

  it('sans rôle admin : aucun bouton de réinitialisation', async () => {
    setUser('viewer')
    const w = await mountIn(ServiceAdminAccess, { props: { ...PROPS, isAdmin: false, appUrl: null } })
    expect(w.find('[data-testid="service-admin-reset"]').exists()).toBe(false)
  })

  it('réinitialise après confirmation, puis montre le mot de passe une seule fois', async () => {
    setUser('admin')
    helper()
    route('POST', '/api/catalog/modules/sonarqube/admin-password/reveal', () => ({ login: 'admin', password: PW }))
    await mountIn(ServiceAdminAccess, { props: PROPS })
    fakeClock()
    await click(button('Réinitialiser le mot de passe admin'))
    expect(bodyText()).toContain('Réinitialiser le mot de passe administrateur ?')
    expect(callsTo('POST', '/api/catalog/modules/sonarqube/admin-password')).toHaveLength(0)
    buttons('Réinitialiser').pop()!.dispatchEvent(new MouseEvent('click', { bubbles: true }))
    await drive()
    expect(callsTo('POST', '/api/catalog/modules/sonarqube/admin-password')).toHaveLength(1)
    expect(callsTo('POST', '/api/catalog/modules/sonarqube/admin-password/reveal')[0]!.body).toEqual({ request_id: 'r1' })
    expect(document.body.querySelector('[data-testid="service-admin-password"]')!.textContent).toBe(PW)
    expect(bodyText()).toContain('Affiché une seule fois')
    const writeText = vi.fn(async () => {})
    Object.defineProperty(navigator, 'clipboard', { value: { writeText }, configurable: true })
    await click(button('Copier'))
    expect(writeText).toHaveBeenCalledWith(PW)
    expect(bodyText()).toContain('Copié')
    await click(button('J’ai noté le mot de passe'))
    await settle()
    expect(bodyText()).not.toContain(PW)
  })

  it('demande en échec : aucun appel de lecture', async () => {
    setUser('admin')
    helper({ status: 'error', code: 'E_SONAR_ADMIN' })
    await mountIn(ServiceAdminAccess, { props: PROPS })
    fakeClock()
    await click(button('Réinitialiser le mot de passe admin'))
    buttons('Réinitialiser').pop()!.dispatchEvent(new MouseEvent('click', { bubbles: true }))
    await drive()
    expect(callsTo('POST', '/api/catalog/modules/sonarqube/admin-password/reveal')).toHaveLength(0)
    expect(toastAdd).toHaveBeenCalledWith(expect.objectContaining({ color: 'error' }))
  })

  it('mot de passe déjà affiché : message d’erreur, rien n’est montré', async () => {
    setUser('admin')
    helper()
    route('POST', '/api/catalog/modules/sonarqube/admin-password/reveal', () => apiFail(410, 'E_GONE'))
    await mountIn(ServiceAdminAccess, { props: PROPS })
    fakeClock()
    await click(button('Réinitialiser le mot de passe admin'))
    buttons('Réinitialiser').pop()!.dispatchEvent(new MouseEvent('click', { bubbles: true }))
    await drive()
    expect(document.body.querySelector('[data-testid="service-admin-password"]')).toBeNull()
    expect(toastAdd).toHaveBeenCalledWith(expect.objectContaining({ title: expect.stringContaining('déjà été affiché') }))
  })

  it('branché dans le détail du module sonarqube installé et actif seulement', async () => {
    setUser('admin')
    const LICENSE = { spdx: 'LGPL-3.0-only', restrictions: 'none' as const }
    const detail = (status: string) => ({
      module: {
        id: 'sonarqube', name: 'SonarQube Community Build', type: 'service', version: '26.11.0.134175', description: 'Qualité',
        categories: ['quality', 'sast'], license: LICENSE, upstream: { homepage: 'https://exemple.test/h', source: 'https://exemple.test/s' },
        resources: { min_ram_mb: 4096, min_cpu: 2, disk_mb: 10240 }, hostname: 'sonarqube',
        requires: { modules: [], feeds: [], appliance: '>=0.4.0' }, conflicts: [], sysctl: {}, postgres: true,
      },
      options_schema: null, options_i18n: null, versions: ['26.11.0.134175'], update_available: null, update_license: null,
      plan: null, dependents: [], operations: [],
      installed: { id: 'sonarqube', version: '26.11.0.134175', type: 'service', status, enabled: true, options: {}, route: { hostname: 'sonarqube', url: 'https://sonarqube.analyse.exemple.test' } },
      dns: null,
    })
    route('GET', '/api/catalog', () => ({ modules: [], packs: [], recommended: null, operations: [], dns: null }))
    route('GET', '/api/catalog/modules/sonarqube', () => detail('healthy'))
    const w = await mountIn(ModulePage, { route: '/catalog/sonarqube' })
    await settle()
    expect(w.find('[data-testid="service-admin"]').exists()).toBe(true)
  })
})
