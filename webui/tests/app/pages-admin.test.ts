// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Journal d'audit (filtres, pagination, panneau latéral de détail) et
// gestion des utilisateurs (création, modification, mot de passe,
// suppression confirmée par une modale de la console).

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { enableAutoUnmount } from '@vue/test-utils'
import { mockNuxtImport } from '@nuxt/test-utils/runtime'
import { apiFail, bodyText, button, callsTo, clearBody, click, mountIn, resetApi, route, setLocale, settle, setUser } from './helpers'
import AuditPage from '~/pages/system/audit.vue'
import UsersPage from '~/pages/system/users.vue'

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

const AUDIT_ROWS = [
  {
    id: '42', occurred_at: '2026-11-23T08:00:00Z', actor_user_id: '1', actor_username: 'alice', actor_type: 'user',
    actor_ip: '192.0.2.10', action: 'user.create', target_type: 'user', target_id: '7', outcome: 'success',
    request_id: '0f8fad5b-d9cb-469f-a165-70867728950e', details: { username: 'bob', role: 'viewer' },
  },
  {
    id: '41', occurred_at: '2026-11-23T07:00:00Z', actor_user_id: null, actor_username: null, actor_type: 'anonymous',
    actor_ip: null, action: 'auth.login', target_type: null, target_id: null, outcome: 'failure', request_id: null, details: {},
  },
  {
    id: '40', occurred_at: '2026-11-23T06:00:00Z', actor_user_id: null, actor_username: null, actor_type: 'system',
    actor_ip: null, action: 'update.apply', target_type: 'update', target_id: null, outcome: 'denied', request_id: null, details: {},
  },
]

describe('journal d’audit', () => {
  it('liste, libellés d’acteur et de résultat, panneau latéral au clic', async () => {
    setUser('operator')
    route('GET', '/api/audit', () => ({ items: AUDIT_ROWS, total: 3 }))
    const w = await mountIn(AuditPage)
    await settle()
    expect(w.text()).toContain('3 entrée(s)')
    expect(w.text()).toContain('anonyme')
    expect(w.text()).toContain('système')
    expect(w.text()).toContain('user:7')
    expect(w.text()).toContain('refusé')
    expect(callsTo('GET', '/api/audit')[0]!.query).toMatchObject({ limit: '50', offset: '0' })
    const rows = w.findAll('tbody tr')
    expect(rows).toHaveLength(3)
    await rows[0]!.trigger('click')
    await settle()
    const panel = bodyText()
    expect(panel).toContain('Entrée n° 42')
    expect(panel).toContain('192.0.2.10')
    expect(panel).toContain('0f8fad5b-d9cb-469f-a165-70867728950e')
    expect(panel).toContain('"username": "bob"')
  })

  it('filtres (après délai) normalisés, valeurs invalides ignorées, pagination', async () => {
    setUser('admin')
    route('GET', '/api/audit', () => ({ items: AUDIT_ROWS, total: 120 }))
    const w = await mountIn(AuditPage)
    await settle()
    const [action, actor] = w.findAll('input')
    await action!.setValue('  AUTH. ')
    await actor!.setValue('x y')
    await vi.waitFor(() => expect(callsTo('GET', '/api/audit').length).toBe(2), { timeout: 2000 })
    const q = callsTo('GET', '/api/audit')[1]!.query
    expect(q.action).toBe('auth.')
    expect(q.actor).toBeUndefined()
    const outcome = w.findAllComponents({ name: 'USelect' }).find(c => JSON.stringify(c.props('items')).includes('failure'))!
    outcome.vm.$emit('update:modelValue', 'failure')
    await vi.waitFor(() => expect(callsTo('GET', '/api/audit').length).toBe(3), { timeout: 2000 })
    expect(callsTo('GET', '/api/audit')[2]!.query.outcome).toBe('failure')
    w.findComponent({ name: 'UPagination' }).vm.$emit('update:page', 2)
    await vi.waitFor(() => expect(callsTo('GET', '/api/audit').length).toBe(4))
    expect(callsTo('GET', '/api/audit')[3]!.query.offset).toBe('50')
    // un filtre ramène à la première page
    await actor!.setValue('bob')
    await vi.waitFor(() => expect(callsTo('GET', '/api/audit').at(-1)!.query).toMatchObject({ offset: '0', actor: 'bob' }), { timeout: 2000 })
  })

  it('erreur de chargement signalée ; actualisation (anglais)', async () => {
    await setLocale('en')
    setUser('operator')
    route('GET', '/api/audit', () => apiFail(403, 'E_FORBIDDEN'))
    await mountIn(AuditPage)
    await settle()
    expect(bodyText()).toContain('Your role does not allow this action.')
    await click(button('Refresh'))
    expect(callsTo('GET', '/api/audit')).toHaveLength(2)
  })
})

const USERS = [
  { id: '1', username: 'alice', display_name: 'Alice', email: null, role: 'admin', locale: 'fr', is_active: true, must_change_password: false, locked_until: null, last_login_at: '2026-11-23T08:00:00Z' },
  { id: '2', username: 'bob', display_name: null, email: 'bob@exemple.test', role: 'viewer', locale: 'en', is_active: false, must_change_password: true, locked_until: '2099-01-01T00:00:00Z', last_login_at: null },
]

describe('utilisateurs', () => {
  beforeEach(() => setUser('admin'))

  it('liste avec badges (inactif, verrouillé, mot de passe à changer)', async () => {
    route('GET', '/api/users', () => ({ items: USERS }))
    const w = await mountIn(UsersPage)
    await settle()
    const text = w.text()
    expect(text).toContain('alice')
    expect(text).toContain('Administrateur')
    expect(text).toContain('Lecteur')
    expect(text).toContain('Verrouillé jusqu’au')
    expect(text).toContain('Mot de passe à changer')
    expect(text).toContain('Non')
  })

  it('création : bouton actif seulement avec une saisie valide, puis rechargement', async () => {
    let list: Record<string, unknown>[] = [USERS[0]!]
    route('GET', '/api/users', () => ({ items: list }))
    route('POST', '/api/users', (_e, body) => {
      list = [...list, { ...USERS[1]!, ...(body as Record<string, unknown>) }]
      return { id: '3' }
    })
    await mountIn(UsersPage)
    await settle()
    await click(button('Nouvel utilisateur'))
    expect(bodyText()).toContain('Créer un utilisateur')
    expect(button('Créer').disabled).toBe(true)
    const inputs = Array.from(document.body.querySelectorAll<HTMLInputElement>('[role="dialog"] input'))
    const set = async (el: HTMLInputElement, v: string) => {
      el.value = v
      el.dispatchEvent(new Event('input', { bubbles: true }))
      await settle()
    }
    await set(inputs[0]!, ' carol ')
    await set(inputs.find(i => i.type === 'password')!, 'mot-de-passe-initial')
    expect(button('Créer').disabled).toBe(false)
    await click(button('Créer'))
    expect(callsTo('POST', '/api/users')[0]!.body).toEqual({
      username: 'carol', display_name: null, email: null, role: 'viewer', locale: 'fr', password: 'mot-de-passe-initial',
    })
    expect(toastAdd).toHaveBeenCalledWith(expect.objectContaining({ title: 'Utilisateur créé.' }))
    expect(callsTo('GET', '/api/users')).toHaveLength(2)
  })

  it('création refusée : identifiant déjà pris', async () => {
    route('GET', '/api/users', () => ({ items: USERS }))
    route('POST', '/api/users', () => apiFail(409, 'E_USERNAME_TAKEN'))
    const w = await mountIn(UsersPage)
    await settle()
    await click(button('Nouvel utilisateur'))
    const vm = w.vm as unknown as { createForm: Record<string, string>, create: () => Promise<void> }
    Object.assign(vm.createForm, { username: 'bob', password: 'mot-de-passe-initial' })
    await settle()
    await click(button('Créer'))
    expect(toastAdd).toHaveBeenCalledWith(expect.objectContaining({ title: 'Cet identifiant existe déjà.', color: 'error' }))
  })

  it('menu d’actions : modifier, réinitialiser le mot de passe, supprimer (sauf soi-même)', async () => {
    route('GET', '/api/users', () => ({ items: USERS }))
    route('PATCH', '/api/users/2', () => ({ ok: true }))
    route('POST', '/api/users/2/password', () => ({ ok: true }))
    route('DELETE', '/api/users/2', () => ({ ok: true }))
    const w = await mountIn(UsersPage)
    await settle()
    const menus = w.findAllComponents({ name: 'UDropdownMenu' })
    expect(menus).toHaveLength(2)
    type Item = { label: string, disabled?: boolean, onSelect: () => void }
    const itemsOf = (i: number) => (menus[i]!.props('items') as Item[][]).flat()
    expect(itemsOf(0).find(i => i.label === 'Supprimer')!.disabled).toBe(true)
    expect(itemsOf(1).find(i => i.label === 'Supprimer')!.disabled).toBe(false)

    itemsOf(1).find(i => i.label === 'Modifier')!.onSelect()
    await settle()
    expect(bodyText()).toContain('Modifier bob')
    await click(button('Enregistrer'))
    expect(callsTo('PATCH', '/api/users/2')[0]!.body).toEqual({ display_name: null, email: 'bob@exemple.test', role: 'viewer', locale: 'en', is_active: false })
    expect(toastAdd).toHaveBeenLastCalledWith(expect.objectContaining({ title: 'Utilisateur modifié.' }))

    itemsOf(1).find(i => i.label === 'Réinitialiser le mot de passe')!.onSelect()
    await settle()
    expect(bodyText()).toContain('Nouveau mot de passe pour bob')
    expect(button('Enregistrer').disabled).toBe(true)
    const pwd = document.body.querySelector<HTMLInputElement>('[role="dialog"] input[type="password"]')!
    pwd.value = 'mot-de-passe-temporaire'
    pwd.dispatchEvent(new Event('input', { bubbles: true }))
    await settle()
    await click(button('Enregistrer'))
    expect(callsTo('POST', '/api/users/2/password')[0]!.body).toEqual({ password: 'mot-de-passe-temporaire', must_change_password: true })

    itemsOf(1).find(i => i.label === 'Supprimer')!.onSelect()
    await settle()
    expect(bodyText()).toContain('Supprimer bob ?')
    expect(callsTo('DELETE', '/api/users/2')).toHaveLength(0)
    await click(button('Supprimer'))
    expect(callsTo('DELETE', '/api/users/2')).toHaveLength(1)
    expect(toastAdd).toHaveBeenLastCalledWith(expect.objectContaining({ title: 'Utilisateur supprimé.' }))
  })

  it('erreurs : liste, modification, mot de passe et suppression (dernier administrateur)', async () => {
    route('GET', '/api/users', () => ({ items: USERS }))
    route('PATCH', '/api/users/1', () => apiFail(409, 'E_LAST_ADMIN'))
    route('POST', '/api/users/1/password', () => apiFail(400, 'E_VALIDATION'))
    route('DELETE', '/api/users/2', () => apiFail(404, 'E_NOT_FOUND'))
    const w = await mountIn(UsersPage)
    await settle()
    type Item = { label: string, onSelect: () => void }
    const itemsOf = (i: number) => (w.findAllComponents({ name: 'UDropdownMenu' })[i]!.props('items') as Item[][]).flat()
    itemsOf(0).find(i => i.label === 'Modifier')!.onSelect()
    await settle()
    await click(button('Enregistrer'))
    expect(toastAdd).toHaveBeenLastCalledWith(expect.objectContaining({ title: 'Impossible : c’est le dernier administrateur actif.' }))
    await click(button('Annuler'))
    itemsOf(0).find(i => i.label === 'Réinitialiser le mot de passe')!.onSelect()
    await settle()
    const vm = w.vm as unknown as { resetForm: { password: string } }
    vm.resetForm.password = 'mot-de-passe-temporaire'
    await settle()
    await click(button('Enregistrer'))
    expect(toastAdd).toHaveBeenLastCalledWith(expect.objectContaining({ title: 'Certaines valeurs sont invalides.' }))
    await click(button('Annuler'))
    itemsOf(1).find(i => i.label === 'Supprimer')!.onSelect()
    await settle()
    await click(button('Supprimer'))
    expect(toastAdd).toHaveBeenLastCalledWith(expect.objectContaining({ title: 'Élément introuvable.' }))
    resetApi()
    route('GET', '/api/users', () => apiFail(500, 'E_INTERNAL'))
    await mountIn(UsersPage)
    await settle()
    expect(bodyText()).toContain('Erreur interne de la console.')
  })
})
