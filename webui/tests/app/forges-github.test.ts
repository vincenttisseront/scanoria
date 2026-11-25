// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Chantier D (0.7, J1) : page de retour de GitHub (conversion du manifeste,
// installation, retour incomplet, erreur) et, sur la page Forges, l'état de
// l'intégration (application ou jeton de compte de service et ses droits
// exacts, mode tiré ou poussé, webhooks rejetés) et le départ « en un clic ».
// API simulée.

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { enableAutoUnmount } from '@vue/test-utils'
import { mockNuxtImport } from '@nuxt/test-utils/runtime'
import { apiFail, bodyText, callsTo, clearBody, mountIn, resetApi, route, setLocale, settle, setUser } from './helpers'
import GithubPage from '~/pages/forges/github.vue'
import ForgesPage from '~/pages/projects/forges.vue'
import type { Forge } from '~/composables/useProjects'

const { toastAdd } = vi.hoisted(() => ({ toastAdd: vi.fn() }))
mockNuxtImport('useToast', () => () => ({ add: toastAdd }))

const FORGE_ID = '33333333-3333-4333-8333-333333333333'

enableAutoUnmount(afterEach)
beforeEach(async () => {
  await setLocale('fr')
  setUser('admin')
  sessionStorage.clear()
})
afterEach(() => {
  resetApi()
  clearBody()
})

function forge(patch: Partial<Forge> = {}): Forge {
  return {
    id: FORGE_ID, kind: 'forgejo', name: 'Forge', base_url: 'https://forge.exemple.test', discovery: true, has_token: true,
    token_hint: '…ab12', token_user: 'scanoria-bot', last_discovery_at: '2026-11-25T09:30:00Z', last_error: null, created_at: '2026-11-25T09:00:00Z',
    projects: 1, ...patch,
  }
}

describe('retour de GitHub (/forges/github)', () => {
  it('conversion du manifeste, puis installation retrouvée par la session', async () => {
    route('POST', '/api/forges/github/convert', () => ({ forge_id: FORGE_ID, slug: 'scanoria-equipe', install_url: 'https://github.com/apps/scanoria-equipe/installations/new' }))
    await mountIn(GithubPage, { route: '/forges/github?code=code-0001&state=etat-0001' })
    await settle()
    expect(callsTo('POST', '/api/forges/github/convert')[0]!.body).toEqual({ code: 'code-0001', state: 'etat-0001' })
    expect(bodyText()).toContain('Application scanoria-equipe créée. Installez-la sur vos dépôts.')
    expect(bodyText()).toContain('Installer sur GitHub')
    clearBody()

    route('POST', '/api/forges/github/install', () => ({ ok: true }))
    await mountIn(GithubPage, { route: '/forges/github?installation_id=42&setup_action=install' })
    await settle()
    expect(callsTo('POST', '/api/forges/github/install')[0]!.body).toEqual({ forge_id: FORGE_ID, installation_id: '42' })
    expect(bodyText()).toContain('Installation enregistrée, découverte des dépôts en cours.')
  })

  it('retour incomplet ; erreur de l’API affichée', async () => {
    await mountIn(GithubPage, { route: '/forges/github' })
    await settle()
    expect(bodyText()).toContain('Retour de GitHub incomplet.')
    clearBody()

    route('POST', '/api/forges/github/convert', () => apiFail(400, 'E_FORGEAPP_STATE'))
    await mountIn(GithubPage, { route: '/forges/github?code=code-0002&state=perime' })
    await settle()
    expect(callsTo('POST', '/api/forges/github/convert')).toHaveLength(1)
    expect(bodyText()).not.toContain('Installer sur GitHub')
    expect(bodyText()).not.toContain('Retour de GitHub incomplet.')
  })
})

describe('page Forges : intégration (J1)', () => {
  it('jeton de compte de service à droits réduits, mode tiré ; application GitHub en mode poussé, rejets comptés', async () => {
    route('GET', '/api/forges', () => ({
      items: [
        forge({ integration: { app: 'forgejo-token', scopes: ['read:user', 'write:repository', 'write:issue'], slug: null, installations: 0, webhook: true, mode: 'pull', last_webhook_at: null, rejected_webhooks_30d: 0 } }),
        forge({
          id: '44444444-4444-4444-8444-444444444444', kind: 'github', name: 'GitHub', base_url: 'https://github.com', has_token: false, token_hint: null, token_user: null,
          integration: { app: 'github-app', scopes: ['checks:write', 'statuses:write'], slug: 'scanoria-equipe', installations: 2, webhook: true, mode: 'push', last_webhook_at: '2026-11-25T09:40:00Z', rejected_webhooks_30d: 3 },
        }),
      ],
    }))
    await mountIn(ForgesPage)
    await settle()
    const text = bodyText()
    expect(text).toContain('Compte de service Forgejo')
    expect(text).toContain('Jeton d’un compte de service à droits réduits, révocable à tout moment dans la forge. Portées exactes :')
    expect(text).toContain('read:user, write:repository, write:issue')
    expect(text).toContain('Mode tiré : l’appliance interroge la forge toutes les 5 minutes')
    expect(text).toContain('Application GitHub scanoria-equipe')
    expect(text).toContain('2 installation(s)')
    expect(text).toContain('Droits demandés à GitHub :')
    expect(text).toContain('checks:write, statuses:write')
    expect(text).toContain('Mode poussé : webhooks signés reçus')
    expect(text).toContain('dernier webhook :')
    expect(text).toContain('3 webhook(s) rejeté(s) sur 30 jours')
  })

  it('GitHub en un clic : manifeste demandé puis formulaire posté vers GitHub ; erreur affichée', async () => {
    route('GET', '/api/forges', () => ({ items: [] }))
    const submit = vi.spyOn(HTMLFormElement.prototype, 'submit').mockImplementation(() => {})
    let fail = false
    route('POST', '/api/forges/github/manifest', () => (fail
      ? apiFail(400, 'E_FORGEAPP_CONSOLE_URL')
      : { action: 'https://github.com/organizations/equipe/settings/apps/new?state=etat', manifest: '{"name":"Scanoria"}' }))
    const w = await mountIn(ForgesPage)
    await settle()
    expect(bodyText()).toContain('Connecter GitHub en un clic')
    const vm = w.vm as unknown as { gh: { name: string, org: string, reachable: boolean }, startGithub: () => Promise<void> }
    vm.gh.org = 'equipe'
    await vm.startGithub()
    await settle()
    expect(callsTo('POST', '/api/forges/github/manifest')[0]!.body).toEqual({ name: 'GitHub', org: 'equipe', reachable: false })
    expect(submit).toHaveBeenCalledTimes(1)
    const form = document.querySelector<HTMLFormElement>('form[action^="https://github.com/organizations/equipe/settings/apps/new"]')!
    expect(form.method).toBe('post')
    expect(form.querySelector<HTMLInputElement>('input[name="manifest"]')!.value).toBe('{"name":"Scanoria"}')
    form.remove()

    fail = true
    vm.gh.org = ''
    await vm.startGithub()
    await settle()
    expect(callsTo('POST', '/api/forges/github/manifest')[1]!.body).toEqual({ name: 'GitHub', org: null, reachable: false })
    expect(submit).toHaveBeenCalledTimes(1)
    submit.mockRestore()
  })
})
