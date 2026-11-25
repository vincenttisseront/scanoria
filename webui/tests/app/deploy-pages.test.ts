// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Carte « Déploiement après verdict favorable » (0.8, chantier D) : chaîne
// (PR, releases, attestations, déploiements et refus), cible proposée
// confirmée, cible déclarée par une modale de la console, fusion automatique
// confirmée avec accusé, retrait confirmé, lecteur sans action, anglais.

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { enableAutoUnmount } from '@vue/test-utils'
import { apiFail, bodyText, button, buttons, callsTo, clearBody, click, mountIn, resetApi, route, setLocale, settle, setUser } from './helpers'
import ProjectChain from '~/components/deploy/ProjectChain.vue'

enableAutoUnmount(afterEach)

beforeEach(async () => {
  await setLocale('fr')
  setUser('admin')
})
afterEach(() => {
  vi.useRealTimers()
  resetApi()
  clearBody()
})

const base = '/api/deploy/projects/p1'
const DIGEST = `sha256:${'a'.repeat(64)}`
const dialog = () => document.body.querySelector('[role="dialog"]')!

const target = (over: Record<string, unknown> = {}) => ({
  id: 't1', kind: 'gitops-pr', environment: 'production', on_trigger: 'release', config: {}, credential_hint: null, auto_merge: false, enabled: true, ...over,
})
function chain(over: Record<string, unknown> = {}) {
  return {
    autonomous: true,
    pull_requests: [{ scan_id: 's-pr', number: 12, verdict: 'passed', auto_merge: 'enabled' }],
    releases: [
      {
        scan_id: 's1', tag: 'v1.2.0', commit_sha: 'b'.repeat(40), verdict: 'passed', report_status: 'signed', reasons: [],
        attestations: [{ id: 'a1', subject_name: 'registre.exemple.test/valide/app', subject_digest: DIGEST, status: 'pushed', pushed_to: 'x', error: null }],
        deployments: [
          { id: 'd1', kind: 'registry-promotion', environment: 'production', status: 'succeeded', refused_reason: null, external_url: null, error: null },
          { id: 'd2', kind: 'cd-trigger', environment: 'production', status: 'running', refused_reason: null, external_url: 'https://forge.exemple.test/equipe/app/actions/runs/42', error: null },
        ],
      },
      {
        scan_id: 's0', tag: 'v1.1.0', commit_sha: 'c'.repeat(40), verdict: 'failed', report_status: null, reasons: [{}, {}],
        attestations: [],
        deployments: [{ id: 'd0', kind: 'cd-trigger', environment: 'production', status: 'refused', refused_reason: 'verdict-not-passed', external_url: null, error: null }],
      },
    ],
    ...over,
  }
}

describe('déploiement après verdict favorable', () => {
  it('chaîne : PR, release, attestation téléchargeable, déploiement suivi, refus expliqué', async () => {
    route('GET', `${base}/chain`, () => chain())
    route('GET', `${base}/targets`, () => ({ items: [target()] }))
    route('GET', `${base}/proposals`, () => ({ items: [] }))
    await mountIn(ProjectChain, { props: { projectId: 'p1', isAdmin: true } })
    await settle()
    const text = bodyText()
    expect(text).toContain('Chaîne autonome activée')
    expect(text).toContain('PR 12')
    expect(text).toContain('Fusion automatique activée')
    expect(text).toContain('v1.2.0')
    expect(text).toContain('Refusé : verdict non favorable')
    expect(document.body.querySelector('a[href="/api/deploy/attestations/a1"]')).not.toBeNull()
    expect(document.body.querySelector('a[href="https://forge.exemple.test/equipe/app/actions/runs/42"]')?.getAttribute('rel')).toContain('noopener')
    expect(document.body.querySelector('[data-testid="deploy-chain"] .animate-spin')).not.toBeNull()
  })

  it('proposition confirmée, cible activée puis désactivée, fusion automatique avec accusé, retrait', async () => {
    let items = [target()]
    route('GET', `${base}/chain`, () => chain({ autonomous: false, pull_requests: [], releases: [] }))
    route('GET', `${base}/targets`, () => ({ items }))
    route('GET', `${base}/proposals`, () => ({ items: [{ kind: 'cd-trigger', environment: 'production', config: { provider: 'forge', workflow: 'deploy.yml', inputs: ['scanoria_report'] }, reason: { workflow: 'deploy.yml', path: '.forgejo/workflows/deploy.yml', inputs: ['scanoria_report'] } }] }))
    route('POST', `${base}/targets`, () => ({ target: target({ id: 't2', kind: 'cd-trigger' }) }))
    route('PATCH', '/api/deploy/targets/t1', (_e, body) => {
      items = [target({ ...(body as object) })]
      return { target: items[0] }
    })
    route('DELETE', '/api/deploy/targets/t1', () => {
      items = []
      return null
    })
    await mountIn(ProjectChain, { props: { projectId: 'p1', isAdmin: true } })
    await settle()
    expect(bodyText()).toContain('.forgejo/workflows/deploy.yml')
    expect(bodyText()).toContain('Aucune release analysée')

    await click(button('Confirmer'))
    expect(callsTo('POST', `${base}/targets`)[0]!.body).toMatchObject({ kind: 'cd-trigger', environment: 'production', config: { workflow: 'deploy.yml' } })

    await click(button('Désactiver'))
    expect(callsTo('PATCH', '/api/deploy/targets/t1')[0]!.body).toEqual({ enabled: false })
    expect(bodyText()).toContain('Désactivée')
    await click(button('Activer'))

    await click(button('Autoriser la fusion automatique'))
    expect(bodyText()).toContain('Scanoria ne fusionne jamais lui-même')
    const confirm = [...dialog().querySelectorAll('button')].find(b => b.textContent?.trim() === 'Confirmer')!
    expect(confirm.disabled).toBe(true)
    await click(dialog().querySelector('[role="checkbox"]')!)
    await click(confirm)
    expect(callsTo('PATCH', '/api/deploy/targets/t1').at(-1)!.body).toEqual({ auto_merge: true })
    expect(bodyText()).toContain('Fusion automatique de la forge')

    await click(button('Retirer'))
    expect(bodyText()).toContain('irréversible')
    const remove = [...dialog().querySelectorAll('button')].filter(b => b.textContent?.trim() === 'Retirer')
    await click(remove.at(-1)!)
    expect(callsTo('DELETE', '/api/deploy/targets/t1')).toHaveLength(1)
    expect(bodyText()).toContain('Aucune cible')
  })

  it('cible déclarée par la modale (registre, jeton), refus du serveur traduit', async () => {
    let fail = true
    route('GET', `${base}/chain`, () => chain({ autonomous: false, pull_requests: [], releases: [] }))
    route('GET', `${base}/targets`, () => ({ items: [] }))
    route('GET', `${base}/proposals`, () => ({ items: [] }))
    route('POST', `${base}/targets`, () => {
      if (fail) apiFail(409, 'E_PRECONDITION')
      return { target: target({ kind: 'registry-promotion' }) }
    })
    const w = await mountIn(ProjectChain, { props: { projectId: 'p1', isAdmin: true } })
    await settle()
    await click(document.body.querySelector('[data-testid="deploy-add"]')!)
    const vm = w.vm as unknown as { draft: Record<string, string> }
    vm.draft.kind = 'registry-promotion'
    vm.draft.source = ' registre.exemple.test/candidat/app '
    vm.draft.destination = 'registre.exemple.test/valide/app'
    vm.draft.username = 'robot'
    vm.draft.token = 'jeton-de-test'
    await settle()
    expect(dialog().querySelector('input[type="password"]')).not.toBeNull()
    const add = () => [...dialog().querySelectorAll('button')].find(b => b.textContent?.trim() === 'Ajouter une cible')!
    await click(add())
    expect(document.body.querySelector('[role="dialog"]')).not.toBeNull()
    fail = false
    await click(add())
    const body = callsTo('POST', `${base}/targets`).at(-1)!.body
    expect(body).toEqual({
      kind: 'registry-promotion', environment: 'production', on_trigger: 'release',
      config: { source: 'registre.exemple.test/candidat/app', destination: 'registre.exemple.test/valide/app' },
      credential: { value: 'jeton-de-test', username: 'robot' },
    })
    expect(vm.draft.token).toBe('')

    // Les autres types : configuration envoyée selon le formulaire.
    await click(document.body.querySelector('[data-testid="deploy-add"]')!)
    vm.draft.kind = 'gitops-pr'
    vm.draft.on_trigger = 'branch'
    vm.draft.branch = 'main'
    vm.draft.repo = 'equipe/deploiement'
    vm.draft.path = 'apps/app.yaml'
    vm.draft.image = 'registre.exemple.test/valide/app'
    await settle()
    await click(add())
    expect(callsTo('POST', `${base}/targets`).at(-1)!.body).toMatchObject({ on_trigger: 'branch', config: { repo: 'equipe/deploiement', base: 'main', branch: 'main', files: [{ path: 'apps/app.yaml', image: 'registre.exemple.test/valide/app' }] } })
    await click(document.body.querySelector('[data-testid="deploy-add"]')!)
    vm.draft.kind = 'cd-trigger'
    vm.draft.on_trigger = 'release'
    vm.draft.provider = 'jenkins'
    vm.draft.url = 'https://jenkins.exemple.test'
    vm.draft.job = 'livraison/app'
    await settle()
    await click(add())
    expect(callsTo('POST', `${base}/targets`).at(-1)!.body).toMatchObject({ config: { provider: 'jenkins', url: 'https://jenkins.exemple.test', job: 'livraison/app' } })
  })

  it('lecteur : aucune action ni proposition ; rafraîchi tant qu\'un déploiement est en cours ; anglais', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true })
    setUser('viewer')
    await setLocale('en')
    route('GET', `${base}/chain`, () => chain())
    route('GET', `${base}/targets`, () => ({ items: [target()] }))
    await mountIn(ProjectChain, { props: { projectId: 'p1', isAdmin: false } })
    await settle()
    expect(buttons('Remove')).toHaveLength(0)
    expect(document.body.querySelector('[data-testid="deploy-add"]')).toBeNull()
    expect(callsTo('GET', `${base}/proposals`)).toHaveLength(0)
    expect(bodyText()).toContain('Deployment after a passed verdict')
    const before = callsTo('GET', `${base}/chain`).length
    await vi.advanceTimersByTimeAsync(15_100)
    await settle()
    expect(callsTo('GET', `${base}/chain`).length).toBeGreaterThan(before)
  })

  it('lecture en échec : message traduit, pas de plantage', async () => {
    route('GET', `${base}/chain`, () => apiFail(500, 'E_INTERNAL'))
    route('GET', `${base}/targets`, () => ({ items: [] }))
    await mountIn(ProjectChain, { props: { projectId: 'p1', isAdmin: false } })
    await settle()
    expect(bodyText()).toContain('Chargement')
  })
})
