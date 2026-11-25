// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Intégration CI d'un projet (J2, J3, J4, J16) et page Système > Émetteurs
// OIDC : PR d'intégration, protection appliquée seulement après la modale de
// confirmation, chaîne autonome, liaisons OIDC épinglées, refus comptés.

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { enableAutoUnmount } from '@vue/test-utils'
import { mockNuxtImport } from '@nuxt/test-utils/runtime'
import { apiFail, bodyText, button, buttons, callsTo, clearBody, click, mountIn, resetApi, route, setLocale, settle, setUser } from './helpers'
import ProjectIntegration from '~/components/ci/ProjectIntegration.vue'
import OidcPage from '~/pages/system/oidc.vue'

const { toastAdd } = vi.hoisted(() => ({ toastAdd: vi.fn() }))
mockNuxtImport('useToast', () => () => ({ add: toastAdd }))

enableAutoUnmount(afterEach)

beforeEach(async () => {
  await setLocale('fr')
  toastAdd.mockReset()
})
afterEach(() => {
  resetApi()
  clearBody()
})

const P = 'p1'
const base = `/api/projects/${P}/ci`

function ciState(patch: Record<string, unknown> = {}) {
  return {
    release_mode: 'pull',
    autonomous_chain: false,
    forge: { id: 'f1', kind: 'forgejo', name: 'Forge' },
    repository: 'equipe/app',
    default_branch: 'main',
    detected_ci: [{ kind: 'forgejo', path: '.forgejo/workflows/ci.yml' }],
    template: 'forgejo',
    contexts: { pr: 'scanoria/pr', release_gate: 'scanoria/release-gate' },
    requests: [],
    bindings: [],
    issuers: [{ id: 'i1', kind: 'forgejo', issuer: 'https://forge.exemple.test/api/actions', enabled: true }],
    console_url: 'https://analyse.exemple.test',
    client_sha256: 'a'.repeat(64),
    ...patch,
  }
}

function input(el: HTMLInputElement, value: string) {
  el.value = value
  el.dispatchEvent(new Event('input'))
}

describe('intégration CI du projet', () => {
  it('sans forge : modèles téléchargeables et empreinte du client', async () => {
    setUser('viewer')
    route('GET', base, () => ciState({ forge: null }))
    await mountIn(ProjectIntegration, { props: { projectId: P } })
    await settle()
    const text = bodyText()
    expect(text).toContain('Projet sans forge')
    expect(text).toContain('a'.repeat(64))
    const links = Array.from(document.body.querySelectorAll<HTMLAnchorElement>('a[href^="/api/ci/templates"]')).map(a => a.getAttribute('href'))
    expect(links).toContain(`/api/ci/templates?file=github%2Fscanoria.yml&project=${P}`)
    expect(links).toContain('/api/ci/templates?file=gitlab%2Fscanoria.yml')
    expect(buttons('Appliquer la protection')).toHaveLength(0)
  })

  it('erreur de chargement affichée', async () => {
    setUser('viewer')
    route('GET', base, () => apiFail(404, 'E_NOT_FOUND'))
    await mountIn(ProjectIntegration, { props: { projectId: P } })
    await settle()
    expect(document.body.querySelector('[data-testid="ci-integration"]')).toBeNull()
  })

  it('opérateur : ouvre la PR d’intégration puis rafraîchit', async () => {
    setUser('operator')
    let opened = false
    route('GET', base, () => ciState(opened
      ? { requests: [{ id: 'r1', kind: 'ci-pr', state: 'open', external_id: '7', detail: { url: 'https://forge.exemple.test/equipe/app/pulls/7' }, decided_by_username: null, updated_at: '2026-11-25T08:00:00Z' }] }
      : {}))
    route('POST', `${base}/pr`, () => {
      opened = true
      return { outcome: 'opened' }
    })
    await mountIn(ProjectIntegration, { props: { projectId: P } })
    await settle()
    expect(bodyText()).toContain('Modèle retenu : forgejo, mode tiré.')
    await click(document.body.querySelector('[data-testid="ci-pr-open"]')!)
    await settle()
    expect(callsTo('POST', `${base}/pr`)).toHaveLength(1)
    expect(toastAdd).toHaveBeenCalledWith(expect.objectContaining({ title: 'PR d’intégration ouverte.' }))
    expect(bodyText()).toContain('PR n° 7')
    expect(document.body.querySelector('[data-testid="ci-pr-open"]')).toBeNull()
  })

  it('PR en erreur : droit manquant, ligne manuelle et nouvelle proposition refusée', async () => {
    setUser('operator')
    route('GET', base, () => ciState({
      requests: [{ id: 'r1', kind: 'ci-pr', state: 'error', external_id: null, detail: { error: 'E_FORGE_PERMISSION', missing_permission: 'contents:write', manual: 'scanoria-ci.sh --wait' }, decided_by_username: null, updated_at: '2026-11-25T08:00:00Z' }],
    }))
    route('POST', `${base}/pr`, () => apiFail(409, 'E_INTEGRATION_STATE'))
    await mountIn(ProjectIntegration, { props: { projectId: P } })
    await settle()
    const text = bodyText()
    expect(text).toContain('Ouverture de la PR impossible (E_FORGE_PERMISSION).')
    expect(text).toContain('Droit manquant sur la forge : contents:write.')
    expect(text).toContain('scanoria-ci.sh --wait')
    await click(button('Proposer à nouveau'))
    expect(toastAdd).toHaveBeenCalledWith(expect.objectContaining({ color: 'error' }))
  })

  it('administrateur : protection appliquée après la modale, avec le gate de release', async () => {
    setUser('admin')
    route('GET', base, () => ciState({
      requests: [{ id: 'pr1', kind: 'branch-protection', state: 'proposed', external_id: null, detail: { contexts: ['scanoria/pr'] }, decided_by_username: null, updated_at: '2026-11-25T08:00:00Z' }],
    }))
    route('POST', `${base}/protection`, () => ({ id: 'pr1', kind: 'branch-protection', state: 'applied', external_id: null, detail: {}, decided_by_username: 'alice', updated_at: '2026-11-25T08:01:00Z' }))
    await mountIn(ProjectIntegration, { props: { projectId: P } })
    await settle()
    await click(document.body.querySelector('[data-testid="ci-protection-apply"]')!)
    expect(callsTo('POST', `${base}/protection`)).toHaveLength(0)
    expect(bodyText()).toContain('La branche main du dépôt equipe/app exigera')
    const box = document.body.querySelector<HTMLButtonElement>('button[role="checkbox"]')!
    await click(box)
    expect(bodyText()).toContain('scanoria/release-gate')
    await click(button('Appliquer la protection'))
    const [call] = callsTo('POST', `${base}/protection`)
    expect(call?.body).toEqual({ request_id: 'pr1', action: 'apply', include_release_gate: true, confirm: true })
    expect(toastAdd).toHaveBeenCalledWith(expect.objectContaining({ title: 'Protection appliquée.' }))
  })

  it('protection refusée par la forge, puis refus de la proposition', async () => {
    setUser('admin')
    route('GET', base, () => ciState({
      requests: [{ id: 'pr1', kind: 'branch-protection', state: 'proposed', external_id: null, detail: { error: 'E_FORGE', missing_permission: 'administration:write' }, decided_by_username: null, updated_at: '2026-11-25T08:00:00Z' }],
    }))
    route('POST', `${base}/protection`, (_e, body) => (body as { action: string }).action === 'apply'
      ? { id: 'pr1', kind: 'branch-protection', state: 'proposed', external_id: null, detail: { error: 'E_FORGE' }, decided_by_username: null, updated_at: '2026-11-25T08:01:00Z' }
      : { id: 'pr1', kind: 'branch-protection', state: 'declined', external_id: null, detail: {}, decided_by_username: 'alice', updated_at: '2026-11-25T08:01:00Z' })
    await mountIn(ProjectIntegration, { props: { projectId: P } })
    await settle()
    expect(bodyText()).toContain('Droit manquant sur la forge : administration:write.')
    await click(document.body.querySelector('[data-testid="ci-protection-apply"]')!)
    await click(button('Appliquer la protection'))
    expect(toastAdd).toHaveBeenCalledWith(expect.objectContaining({ title: 'La forge a refusé la protection.', color: 'error' }))
    await click(buttons('Refuser')[0]!)
    await click(button('Refuser'))
    expect(callsTo('POST', `${base}/protection`).at(-1)?.body).toMatchObject({ action: 'decline' })
    expect(toastAdd).toHaveBeenCalledWith(expect.objectContaining({ title: 'Protection refusée.' }))
  })

  it('GitLab : la modale montre le réglage de projet, pas une règle par branche', async () => {
    setUser('admin')
    route('GET', base, () => ciState({
      forge: { id: 'f2', kind: 'gitlab', name: 'GitLab' },
      requests: [{ id: 'pr1', kind: 'branch-protection', state: 'proposed', external_id: null, detail: {}, decided_by_username: null, updated_at: '2026-11-25T08:00:00Z' }],
    }))
    await mountIn(ProjectIntegration, { props: { projectId: P } })
    await settle()
    await click(document.body.querySelector('[data-testid="ci-protection-apply"]')!)
    expect(document.body.querySelector('[data-testid="ci-protection-gitlab"]')).not.toBeNull()
  })

  it('protection décidée puis proposée à nouveau, chaîne autonome activée', async () => {
    setUser('admin')
    route('GET', base, () => ciState({
      requests: [{ id: 'pr1', kind: 'branch-protection', state: 'declined', external_id: null, detail: { contexts: ['scanoria/pr'] }, decided_by_username: 'bob', updated_at: '2026-11-25T08:00:00Z' }],
    }))
    route('POST', `${base}/protection-request`, () => ({ ok: true }))
    route('PATCH', `${base}/settings`, () => ({ ok: true }))
    await mountIn(ProjectIntegration, { props: { projectId: P } })
    await settle()
    expect(bodyText()).toContain('décidée par bob')
    await click(button('Proposer la protection'))
    expect(callsTo('POST', `${base}/protection-request`)).toHaveLength(1)
    await click(document.body.querySelector('[data-testid="ci-chain"] button[role="switch"], button[data-testid="ci-chain"]')!)
    expect(callsTo('PATCH', `${base}/settings`)[0]?.body).toEqual({ autonomous_chain: true })
    expect(toastAdd).toHaveBeenCalledWith(expect.objectContaining({ title: 'Chaîne autonome activée.' }))
  })

  it('liaisons OIDC : ajout, réinitialisation de l’épingle et retrait confirmés', async () => {
    setUser('admin')
    const binding = { id: 'b1', issuer_id: 'i1', issuer: 'https://forge.exemple.test/api/actions', kind: 'forgejo', repository: 'equipe/app', repository_id: '42', ref_patterns: ['refs/heads/main', 'refs/tags/*'] }
    route('GET', base, () => ciState({ bindings: [binding, { ...binding, id: 'b2', repository: 'equipe/lib', repository_id: null }] }))
    route('POST', `${base}/bindings`, () => ({ id: 'b3' }))
    route('PATCH', `${base}/bindings/b1`, () => ({ ok: true }))
    route('DELETE', `${base}/bindings/b2`, () => null)
    await mountIn(ProjectIntegration, { props: { projectId: P } })
    await settle()
    const text = bodyText()
    expect(text).toContain('dépôt n° 42 épinglé')
    expect(text).toContain('identifiant épinglé au premier jeton')

    await click(button('Ajouter une liaison'))
    const inputs = Array.from(document.body.querySelectorAll<HTMLInputElement>('[role="dialog"] input'))
    input(inputs.at(-1)!, 'refs/heads/main, refs/pull/*')
    await settle()
    await click(button('Enregistrer'))
    expect(callsTo('POST', `${base}/bindings`)[0]?.body).toEqual({ issuer_id: 'i1', repository: 'equipe/app', ref_patterns: ['refs/heads/main', 'refs/pull/*'] })

    await click(buttons('Réinitialiser l’épingle')[0]!)
    expect(bodyText()).toContain('à la place de 42')
    await click(button('Réinitialiser l’épingle'))
    expect(callsTo('PATCH', `${base}/bindings/b1`)[0]?.body).toEqual({ reset_repository_id: true })

    await click(buttons('Retirer')[1]!)
    await click(button('Retirer'))
    expect(callsTo('DELETE', `${base}/bindings/b2`)).toHaveLength(1)
  })

  it('liaisons OIDC : erreurs de la console montrées en toast', async () => {
    setUser('admin')
    const binding = { id: 'b1', issuer_id: 'i1', issuer: 'https://forge.exemple.test/api/actions', kind: 'forgejo', repository: 'equipe/app', repository_id: '42', ref_patterns: ['refs/heads/main'] }
    route('GET', base, () => ciState({ bindings: [binding] }))
    route('POST', `${base}/bindings`, () => apiFail(409, 'E_EXISTS'))
    route('PATCH', `${base}/bindings/b1`, () => apiFail(404, 'E_NOT_FOUND'))
    route('DELETE', `${base}/bindings/b1`, () => apiFail(404, 'E_NOT_FOUND'))
    route('PATCH', `${base}/settings`, () => apiFail(403, 'E_FORBIDDEN'))
    await mountIn(ProjectIntegration, { props: { projectId: P } })
    await settle()
    await click(button('Ajouter une liaison'))
    await click(button('Enregistrer'))
    await click(buttons('Réinitialiser l’épingle')[0]!)
    await click(button('Réinitialiser l’épingle'))
    await click(buttons('Retirer')[0]!)
    await click(button('Retirer'))
    await click(document.body.querySelector('[data-testid="ci-chain"] button[role="switch"], button[data-testid="ci-chain"]')!)
    expect(toastAdd.mock.calls.filter(([a]) => a.color === 'error')).toHaveLength(4)
  })
})

describe('émetteurs OIDC', () => {
  it('lecteur : réservé aux administrateurs, aucun appel', async () => {
    setUser('viewer')
    await mountIn(OidcPage)
    await settle()
    expect(callsTo('GET', '/api/ci/issuers')).toHaveLength(0)
  })

  it('administrateur : liste, refus comptés, ajout et désactivation confirmée', async () => {
    setUser('admin')
    let enabled = true
    route('GET', '/api/ci/issuers', () => ({
      issuers: [
        { id: 'i1', kind: 'forgejo', issuer: 'https://forge.exemple.test/api/actions', audience: 'scanoria', enabled, bindings: 2, jwks_fetched_at: '2026-11-25T08:00:00Z' },
        { id: 'i2', kind: 'github', issuer: 'https://jetons.exemple.test', audience: 'scanoria', enabled: false, bindings: 0, jwks_fetched_at: null },
      ],
      refusals: { E_OIDC_SIGNATURE: 3, E_OIDC_BINDING: 0 },
    }))
    route('POST', '/api/ci/issuers', () => ({ id: 'i3' }))
    route('PATCH', '/api/ci/issuers/i1', () => {
      enabled = false
      return { ok: true }
    })
    await mountIn(OidcPage)
    await settle()
    const text = bodyText()
    expect(text).toContain('forgejo, audience scanoria, 2 liaison(s)')
    expect(text).toContain('clés pas encore lues')
    expect(text).toContain('E_OIDC_SIGNATURE : 3')
    expect(text).not.toContain('E_OIDC_BINDING')

    await click(document.body.querySelector('[data-testid="oidc-issuer-add"]')!)
    expect(button('Enregistrer').disabled).toBe(true)
    const inputs = Array.from(document.body.querySelectorAll<HTMLInputElement>('[role="dialog"] input'))
    input(inputs.find(i => i.placeholder.startsWith('https://'))!, ' https://forge2.exemple.test/api/actions ')
    await settle()
    await click(button('Enregistrer'))
    expect(callsTo('POST', '/api/ci/issuers')[0]?.body).toEqual({ kind: 'forgejo', issuer: 'https://forge2.exemple.test/api/actions', audience: 'scanoria' })

    await click(buttons('Désactiver')[0]!)
    expect(bodyText()).toContain('seront refusés')
    await click(button('Désactiver'))
    expect(callsTo('PATCH', '/api/ci/issuers/i1')[0]?.body).toEqual({ enabled: false })
  })

  it('erreurs : chargement, ajout et bascule en toast', async () => {
    setUser('admin')
    route('GET', '/api/ci/issuers', () => ({ issuers: [{ id: 'i1', kind: 'gitlab', issuer: 'https://gitlab.exemple.test', audience: 'scanoria', enabled: false, bindings: 0, jwks_fetched_at: null }], refusals: {} }))
    route('POST', '/api/ci/issuers', () => apiFail(409, 'E_EXISTS'))
    route('PATCH', '/api/ci/issuers/i1', () => apiFail(404, 'E_NOT_FOUND'))
    await mountIn(OidcPage)
    await settle()
    expect(bodyText()).toContain('Aucun refus.')
    await click(document.body.querySelector('[data-testid="oidc-issuer-add"]')!)
    const inputs = Array.from(document.body.querySelectorAll<HTMLInputElement>('[role="dialog"] input'))
    input(inputs.find(i => i.placeholder.startsWith('https://'))!, 'https://gitlab.exemple.test')
    await settle()
    await click(button('Enregistrer'))
    await click(button('Annuler'))
    await click(buttons('Activer')[0]!)
    await click(button('Activer'))
    expect(toastAdd.mock.calls.filter(([a]) => a.color === 'error')).toHaveLength(2)
  })

  it('aucun émetteur, chargement en échec', async () => {
    setUser('admin')
    route('GET', '/api/ci/issuers', () => apiFail(500, 'E_INTERNAL'))
    await mountIn(OidcPage)
    await settle()
    expect(bodyText()).toContain('Aucun émetteur déclaré.')
    expect(toastAdd).toHaveBeenCalledWith(expect.objectContaining({ color: 'error' }))
  })
})
