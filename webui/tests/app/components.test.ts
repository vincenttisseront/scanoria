// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Composants, mise en page et garde de navigation : modale de confirmation
// (jamais confirm()), indicateur d'attente, alertes d'état, langue, menu
// selon le rôle, déconnexion, redirections de la garde.

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { enableAutoUnmount } from '@vue/test-utils'
import { mockNuxtImport, mountSuspended } from '@nuxt/test-utils/runtime'
import { h } from 'vue'
import { apiFail, bodyText, button, callsTo, clearBody, click, mountIn, resetApi, route, sampleState, setLocale, settle, setUser } from './helpers'
import ConfirmModal from '~/components/ConfirmModal.vue'
import RequestProgress from '~/components/RequestProgress.vue'
import StateAlert from '~/components/StateAlert.vue'
import LocaleSwitch from '~/components/LocaleSwitch.vue'
import PageShell from '~/components/PageShell.vue'
import DefaultLayout from '~/layouts/default.vue'
import AuthLayout from '~/layouts/auth.vue'
import authMiddleware from '~/middleware/auth.global'

const { navigateToMock, toastAdd } = vi.hoisted(() => ({ navigateToMock: vi.fn((to: unknown) => ({ redirectedTo: to })), toastAdd: vi.fn() }))
mockNuxtImport('navigateTo', () => navigateToMock)
mockNuxtImport('useToast', () => () => ({ add: toastAdd }))

enableAutoUnmount(afterEach)

beforeEach(async () => {
  await setLocale('fr')
  navigateToMock.mockClear()
  toastAdd.mockReset()
  setUser(null)
})
afterEach(async () => {
  resetApi()
  clearBody()
  await setLocale('fr')
})

describe('ConfirmModal', () => {
  it('affiche titre et texte, émet confirm, et Annuler ferme la modale', async () => {
    const w = await mountSuspended(ConfirmModal, { props: { title: 'Supprimer bob ?', body: 'Définitif.', open: true, confirmLabel: 'Supprimer' } })
    await settle()
    expect(bodyText()).toContain('Supprimer bob ?')
    expect(bodyText()).toContain('Définitif.')
    expect(document.body.querySelector('[role="dialog"]')).not.toBeNull()
    await click(button('Supprimer'))
    expect(w.emitted('confirm')).toHaveLength(1)
    await click(button('Annuler'))
    expect(w.emitted('update:open')?.at(-1)).toEqual([false])
  })

  it('avec « ack », le bouton reste désactivé tant que la case n’est pas cochée', async () => {
    const w = await mountSuspended(ConfirmModal, { props: { title: 'Revenir ?', open: true, ack: 'Je comprends' } })
    await settle()
    const confirm = button('Confirmer')
    expect(confirm.disabled).toBe(true)
    await click(confirm)
    expect(w.emitted('confirm')).toBeUndefined()
    await click(document.body.querySelector('[role="checkbox"]')!)
    expect(button('Confirmer').disabled).toBe(false)
    await click(button('Confirmer'))
    expect(w.emitted('confirm')).toHaveLength(1)
  })

  it('pendant le chargement, Annuler est désactivé ; libellés en anglais', async () => {
    await setLocale('en')
    await mountSuspended(ConfirmModal, { props: { title: 'Apply?', open: true, loading: true } })
    await settle()
    expect(button('Cancel').disabled).toBe(true)
    expect(bodyText()).toContain('Confirm')
  })
})

describe('RequestProgress', () => {
  it('indicateur d’attente annoncé (role=status) seulement quand actif', async () => {
    const off = await mountSuspended(RequestProgress, { props: { active: false, label: 'x' } })
    expect(off.find('[role="status"]').exists()).toBe(false)
    const on = await mountSuspended(RequestProgress, { props: { active: true, label: 'Étape : extraction' } })
    expect(on.find('[role="status"]').text()).toBe('Étape : extraction')
    expect(on.find('.animate-spin').exists()).toBe(true)
  })
})

describe('StateAlert', () => {
  it('rien quand l’état est disponible et sans alerte', async () => {
    const w = await mountSuspended(StateAlert, { props: { data: sampleState() } })
    expect(w.text()).toBe('')
  })

  it.each([
    ['stale', 'date de plus de 3 minutes (240 s)'],
    ['invalid', 'L’état publié est illisible.'],
    ['missing', 'n’a pas encore publié son état'],
  ])('état indisponible (%s)', async (reason, text) => {
    const w = await mountSuspended(StateAlert, { props: { data: { available: false, reason: reason as 'stale', age_seconds: 240, state: null, console_version: '0.1.0' } } })
    expect(w.text()).toContain('État de l’appliance indisponible')
    expect(w.text()).toContain(text)
  })

  it('alerte permanente après l’échec d’un retour arrière', async () => {
    const data = sampleState({ update: { alert: { code: 'E_ROLLBACK_FAILED', message: 'journal', at: '2026-11-20T10:00:00Z', version: '0.2.0' } } })
    const w = await mountSuspended(StateAlert, { props: { data } })
    expect(w.text()).toContain('Échec du retour arrière d’une mise à jour')
    expect(w.text()).toContain('version 0.2.0')
    expect(w.text()).toContain('journal : journal')
  })
})

describe('LocaleSwitch et PageShell', () => {
  it('le cadre de page affiche titre, actions et contenu ; la langue change', async () => {
    const w = await mountSuspended(PageShell, {
      props: { title: 'Titre de page' },
      slots: { default: () => h('p', 'contenu'), actions: () => h('button', 'action') },
    })
    expect(w.text()).toContain('Titre de page')
    expect(w.text()).toContain('contenu')
    expect(w.text()).toContain('action')
    const sw = await mountSuspended(LocaleSwitch)
    expect(sw.text()).toContain('Français')
    const select = sw.findComponent({ name: 'USelect' })
    select.vm.$emit('update:modelValue', 'en')
    await settle()
    expect(useNuxtApp().$i18n.locale.value).toBe('en')
  })

  it('mise en page d’authentification : contenu centré', async () => {
    const w = await mountSuspended(AuthLayout, { slots: { default: () => h('form', 'connexion') } })
    expect(w.text()).toBe('connexion')
  })
})

describe('mise en page principale', () => {
  it('menu selon le rôle : lecteur sans utilisateurs ni audit', async () => {
    setUser('viewer')
    const w = await mountSuspended(DefaultLayout, { slots: { default: () => h('main', 'page') } })
    expect(w.text()).toContain('Tableau de bord')
    expect(w.text()).toContain('À propos')
    expect(w.text()).not.toContain('Utilisateurs')
    expect(w.text()).not.toContain('Journal d’audit')
    expect(w.text()).toContain('Alice')
  })

  it('opérateur : audit ; administrateur : utilisateurs et audit', async () => {
    setUser('operator')
    const op = await mountSuspended(DefaultLayout)
    expect(op.text()).toContain('Journal d’audit')
    expect(op.text()).not.toContain('Utilisateurs')
    setUser('admin', { display_name: null })
    const ad = await mountSuspended(DefaultLayout)
    expect(ad.text()).toContain('Utilisateurs')
    expect(ad.text()).toContain('alice')
  })

  it('menu en sections : titres, ordre des entrées et applications des modules « service » sains', async () => {
    setUser('admin')
    const svc = (id: string, name: string, extra: Record<string, unknown> = {}) => ({
      id,
      name,
      installed: { id, type: 'service', status: 'healthy', enabled: true, route: { hostname: id, url: `https://${id}.analyse.exemple.test/` }, ...extra },
    })
    route('GET', '/api/catalog', () => ({
      modules: [
        svc('sonarqube', 'SonarQube'),
        svc('dtrack', 'Dependency-Track'),
        svc('defectdojo', 'DefectDojo', { enabled: false }),
        svc('broken', 'Cassé', { status: 'failed' }),
        svc('ailleurs', 'Ailleurs', { route: { hostname: 'ailleurs', url: 'https://exemple.test/' } }),
        svc('clair', 'En clair', { route: { hostname: 'clair', url: 'http://clair.analyse.exemple.test/' } }),
        { id: 'trivy', name: 'Trivy', installed: { id: 'trivy', type: 'scanner', status: 'healthy', enabled: true } },
      ],
    }))
    const w = await mountSuspended(DefaultLayout)
    await settle()
    const nav = w.findComponent({ name: 'UNavigationMenu' })
    const lists = nav.props('items') as { label: string, type?: string, to?: string, target?: string }[][]
    expect(lists.map(l => l.map(i => i.label))).toEqual([
      ['Tableau de bord'],
      ['Analyse', 'Projets', 'Analyses', 'Résultats', 'Composants', 'Quality gates', 'Jeux de règles', 'Licences', 'Santé'],
      ['Modules', 'Catalogue', 'Dependency-Track', 'SonarQube'],
      ['Administration', 'Système', 'Certificats TLS', 'Utilisateurs', 'IA', 'Hors ligne', 'Journal d’audit', 'Mises à jour', 'À propos'],
    ])
    expect(lists.slice(1).every(l => l[0]!.type === 'label')).toBe(true)
    const sonar = lists[2]!.find(i => i.label === 'SonarQube')!
    expect(sonar).toMatchObject({ to: 'https://sonarqube.analyse.exemple.test/', target: '_blank' })
    expect(nav.props('tooltip')).toBe(true)
    expect(w.find('nav[aria-label="Menu principal"]').exists()).toBe(true)
  })

  it('entrée active selon la page, sous-pages comprises', async () => {
    setUser('admin')
    const active = async (path: string) => {
      const w = await mountSuspended(DefaultLayout, { route: path })
      const lists = w.findComponent({ name: 'UNavigationMenu' }).props('items') as { label: string, active?: boolean }[][]
      return lists.flat().filter(i => i.active).map(i => i.label)
    }
    expect(await active('/')).toEqual(['Tableau de bord'])
    expect(await active('/scans/42')).toEqual(['Analyses'])
    expect(await active('/scans/health')).toEqual(['Santé'])
    expect(await active('/system/severities')).toEqual(['Système'])
    expect(await active('/system/tls')).toEqual(['Certificats TLS'])
    expect(await active('/catalog/trivy')).toEqual(['Catalogue'])
  })

  it('applique la langue du compte puis enregistre un changement de langue', async () => {
    setUser('viewer', { locale: 'en' })
    route('PATCH', '/api/account', () => ({ ok: true }))
    const w = await mountSuspended(DefaultLayout)
    await settle()
    expect(useNuxtApp().$i18n.locale.value).toBe('en')
    expect(w.text()).toContain('Dashboard')
    await setLocale('fr')
    await settle()
    expect(callsTo('PATCH', '/api/account').map(c => c.body)).toEqual([{ locale: 'fr' }])
    expect(useSession().state.value.user?.locale).toBe('fr')
  })

  it('déconnexion depuis le menu : session effacée, retour à la connexion, erreur signalée', async () => {
    setUser('admin')
    route('POST', '/api/auth/logout', () => apiFail(500, 'E_INTERNAL'))
    const w = await mountIn(DefaultLayout)
    const menu = w.findComponent({ name: 'UDropdownMenu' })
    const items = menu.props('items') as { label: string, to?: string, onSelect?: () => void }[][]
    expect(items.flat().map(i => i.label)).toEqual(['Mon compte', 'Se déconnecter'])
    expect(items[0]![0]!.to).toBe('/account')
    items[1]![0]!.onSelect!()
    await settle()
    expect(callsTo('POST', '/api/auth/logout')).toHaveLength(1)
    expect(toastAdd).toHaveBeenCalledWith(expect.objectContaining({ title: 'Erreur interne de la console.' }))
    expect(useSession().state.value.user).toBeNull()
    expect(navigateToMock).toHaveBeenCalledWith('/login')
  })
})

describe('garde de navigation', () => {
  const to = (path: string, meta: Record<string, unknown> = {}, fullPath = path) => ({ path, fullPath, meta }) as never
  const guard = authMiddleware as unknown as (to: never, from: never) => Promise<unknown>

  it('charge la session si besoin et renvoie vers la connexion avec « next »', async () => {
    useState('session').value = { loaded: false, user: null, csrf: null, address: null }
    route('GET', '/api/auth/session', () => ({ authenticated: false }))
    await guard(to('/updates'), to('/'))
    expect(callsTo('GET', '/api/auth/session')).toHaveLength(1)
    expect(navigateToMock).toHaveBeenLastCalledWith({ path: '/login', query: { next: '/updates' } })
    await guard(to('/'), to('/'))
    expect(navigateToMock).toHaveBeenLastCalledWith({ path: '/login', query: {} })
  })

  it('pages publiques : libres, sauf la connexion déjà authentifié', async () => {
    expect(await guard(to('/system/about', { public: true }), to('/'))).toBeUndefined()
    expect(navigateToMock).not.toHaveBeenCalled()
    setUser('viewer')
    await guard(to('/login', { public: true }), to('/'))
    expect(navigateToMock).toHaveBeenLastCalledWith('/')
  })

  it('mot de passe à changer, puis rôle insuffisant', async () => {
    setUser('viewer', { must_change_password: true })
    await guard(to('/updates'), to('/'))
    expect(navigateToMock).toHaveBeenLastCalledWith('/account')
    navigateToMock.mockClear()
    expect(await guard(to('/account'), to('/'))).toBeUndefined()
    setUser('operator')
    await guard(to('/system/users', { role: 'admin' }), to('/'))
    expect(navigateToMock).toHaveBeenLastCalledWith('/')
    navigateToMock.mockClear()
    expect(await guard(to('/system/audit', { role: 'operator' }), to('/'))).toBeUndefined()
    expect(navigateToMock).not.toHaveBeenCalled()
  })
})
