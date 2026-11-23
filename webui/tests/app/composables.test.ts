// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Composables de la console : session et rôles, appels API (CSRF, 401,
// changement de mot de passe imposé, messages traduits), formats fr/en,
// suivi d'une demande au service root, état publié.

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { mockNuxtImport, mountSuspended } from '@nuxt/test-utils/runtime'
import { apiFail, callsTo, resetApi, route, setLocale, settle, setupComponent, setUser, sampleState } from './helpers'
import { errorCode, errorStatus } from '~/composables/useApi'

const { navigateToMock, toastAdd } = vi.hoisted(() => ({ navigateToMock: vi.fn(), toastAdd: vi.fn() }))
mockNuxtImport('navigateTo', () => navigateToMock)
mockNuxtImport('useToast', () => () => ({ add: toastAdd }))

async function use<T>(fn: () => T): Promise<T> {
  const holder: { value?: T } = {}
  await mountSuspended(setupComponent(fn, holder))
  return holder.value!
}

beforeEach(async () => {
  await setLocale('fr')
  navigateToMock.mockReset()
  toastAdd.mockReset()
  setUser(null)
})
afterEach(async () => {
  resetApi()
  vi.useRealTimers()
  await setLocale('fr')
})

describe('useSession', () => {
  it('charge la session authentifiée puis applique la hiérarchie des rôles', async () => {
    route('GET', '/api/auth/session', () => ({
      authenticated: true, csrf: 'jeton', address: '192.0.2.7',
      user: { id: 3, username: 'bob', display_name: null, role: 'operator', locale: 'en', must_change_password: false },
    }))
    const s = await use(() => useSession())
    await s.refresh()
    expect(s.state.value).toMatchObject({ loaded: true, csrf: 'jeton', address: '192.0.2.7' })
    expect(s.can('viewer')).toBe(true)
    expect(s.can('operator')).toBe(true)
    expect(s.can('admin')).toBe(false)
    s.clear()
    expect(s.state.value.user).toBeNull()
    expect(s.can('viewer')).toBe(false)
  })

  it('sans session ou en erreur réseau : utilisateur absent, état chargé', async () => {
    route('GET', '/api/auth/session', () => ({ authenticated: false }))
    const s = await use(() => useSession())
    await s.refresh()
    expect(s.state.value).toEqual({ loaded: true, user: null, csrf: null, address: null })
    resetApi()
    route('GET', '/api/auth/session', () => apiFail(500, 'E_INTERNAL'))
    setUser('admin')
    await s.refresh()
    expect(s.state.value.user).toBeNull()
  })
})

describe('useApi', () => {
  it('envoie le jeton CSRF sur les requêtes qui modifient, pas sur GET', async () => {
    setUser('admin')
    route('GET', '/api/x', () => ({ ok: 1 }))
    route('POST', '/api/x', (_e, body) => ({ echo: body }))
    const { api } = await use(() => useApi())
    expect(await api('/api/x')).toEqual({ ok: 1 })
    expect(await api('/api/x', { method: 'POST', body: { a: 1 } })).toEqual({ echo: { a: 1 } })
    expect(callsTo('GET', '/api/x')[0]!.csrf).toBeUndefined()
    expect(callsTo('POST', '/api/x')[0]!.csrf).toBe('csrf-test')
  })

  it('401 : session effacée et retour à la connexion', async () => {
    setUser('viewer')
    route('GET', '/api/y', () => apiFail(401, 'E_UNAUTHENTICATED'))
    const { api } = await use(() => useApi())
    await expect(api('/api/y')).rejects.toBeTruthy()
    expect(useSession().state.value.user).toBeNull()
    expect(navigateToMock).toHaveBeenCalledWith('/login')
  })

  it('401 sur la connexion elle-même : pas de redirection', async () => {
    route('POST', '/api/auth/login', () => apiFail(401, 'E_INVALID_CREDENTIALS'))
    const { api } = await use(() => useApi())
    await expect(api('/api/auth/login', { method: 'POST', body: {} })).rejects.toBeTruthy()
    expect(navigateToMock).not.toHaveBeenCalled()
  })

  it('changement de mot de passe imposé : redirection vers le compte', async () => {
    setUser('viewer')
    route('GET', '/api/z', () => apiFail(403, 'E_PASSWORD_CHANGE_REQUIRED'))
    const { api } = await use(() => useApi())
    await expect(api('/api/z')).rejects.toBeTruthy()
    expect(navigateToMock).toHaveBeenCalledWith('/account')
  })

  it('traduit les codes d’erreur en français et en anglais', async () => {
    route('GET', '/api/e', () => apiFail(409, 'E_USERNAME_TAKEN'))
    route('GET', '/api/u', () => apiFail(500, 'E_SOMETHING_UNKNOWN'))
    const { api, errorMessage } = await use(() => useApi())
    const taken = await api('/api/e').catch(e => e)
    const unknown = await api('/api/u').catch(e => e)
    expect(errorCode(taken)).toBe('E_USERNAME_TAKEN')
    expect(errorStatus(taken)).toBe(409)
    expect(errorMessage(taken)).toBe('Cet identifiant existe déjà.')
    expect(errorMessage(unknown)).toBe('Une erreur est survenue. Réessayez.')
    expect(errorMessage(new TypeError('fetch failed'))).toBe('La console ne répond pas. Vérifiez la connexion.')
    await setLocale('en')
    expect(errorMessage(taken)).toBe('This username already exists.')
  })
})

describe('useFormat', () => {
  it('formate dates, tailles et empreintes selon la langue', async () => {
    const f = await use(() => useFormat())
    expect(f.date(null)).toBe('jamais')
    expect(f.date('pas-une-date')).toBe('pas-une-date')
    expect(f.date('2026-11-23T08:00:00Z')).toMatch(/2026/)
    expect(f.gb(1536)).toBe('1,5')
    expect(f.gb(undefined)).toBe('?')
    expect(f.fingerprint('aabbcc')).toBe('AA:BB:CC')
    expect(f.fingerprint(null)).toBe('—')
    await setLocale('en')
    expect(f.gb(1536)).toBe('1.5')
    expect(f.date(undefined)).toBe('never')
  })
})

describe('useHelperRequest', () => {
  it('dépose la demande, suit les étapes puis annonce le succès traduit', async () => {
    setUser('admin')
    const statuses = [
      { status: 'running', step: 'download', code: null },
      { status: 'ok', step: null, code: 'OK' },
    ]
    route('POST', '/api/system/selftest', () => ({ request_id: 'r1' }))
    route('GET', '/api/requests/r1', () => ({ id: 'r1', type: 'run-selftest', message: null, output: null, ...statuses.shift() }))
    const req = await use(() => useHelperRequest())
    expect(req.label.value).toBe('')
    const p = req.run('/api/system/selftest', { quick: true }, { pollMs: 1 })
    expect(req.running.value).toBe(true)
    const final = await p
    expect(final).toMatchObject({ status: 'ok', code: 'OK' })
    expect(req.running.value).toBe(false)
    expect(callsTo('POST', '/api/system/selftest')[0]!.body).toEqual({ quick: true })
    expect(toastAdd).toHaveBeenCalledWith(expect.objectContaining({ title: 'Demande transmise au service système.' }))
    expect(toastAdd).toHaveBeenLastCalledWith(expect.objectContaining({ title: 'Terminé avec succès.', color: 'success' }))
  })

  it('libellé : étape traduite, état, redémarrage de la console', async () => {
    const req = await use(() => useHelperRequest())
    req.status.value = 'pending'
    expect(req.label.value).toBe('En file d’attente…')
    req.step.value = 'verify'
    expect(req.label.value).toBe('Étape : vérification de la signature')
    req.step.value = 'inconnue'
    expect(req.label.value).toBe('Étape : inconnue')
    req.restarting.value = true
    expect(req.label.value).toBe('La console redémarre, reconnexion en cours…')
    expect(req.codeMessage('E_SIGNATURE')).toBe('Signature invalide : la mise à jour est rejetée.')
    expect(req.codeMessage(null)).toBe('Une erreur est survenue. Réessayez.')
  })

  it('échec du service root : message du code de résultat', async () => {
    setUser('admin')
    route('POST', '/api/system/hostname', () => ({ request_id: 'r2' }))
    route('GET', '/api/requests/r2', () => ({ id: 'r2', type: 'set-hostname', status: 'rejected', step: null, code: 'E_INVALID_PARAM', message: 'x', output: null }))
    const req = await use(() => useHelperRequest())
    const final = await req.run('/api/system/hostname', { fqdn: 'a.exemple.test' }, { pollMs: 1 })
    expect(final?.status).toBe('rejected')
    expect(toastAdd).toHaveBeenLastCalledWith(expect.objectContaining({
      title: 'Refusé', description: 'Demande refusée : paramètre invalide.', color: 'error',
    }))
  })

  it('demande perdue : pas de description ; erreurs réseau pendant un redémarrage tolérées', async () => {
    setUser('admin')
    let n = 0
    route('POST', '/api/system/updates/apply', () => ({ request_id: 'r3' }))
    route('GET', '/api/requests/r3', () => {
      n += 1
      if (n === 1) apiFail(502, 'E_UNAVAILABLE')
      return { id: 'r3', type: 'apply-update', status: 'lost', step: null, code: null, message: null, output: null }
    })
    const req = await use(() => useHelperRequest())
    const final = await req.run('/api/system/updates/apply', { source: 'github', version: '0.2.0' }, { pollMs: 1 })
    expect(n).toBe(2)
    expect(final?.status).toBe('lost')
    expect(toastAdd).toHaveBeenLastCalledWith(expect.objectContaining({ title: 'Sans réponse du service système', description: undefined }))
  })

  it('refus d’autorisation pendant le suivi : arrêt et message d’erreur', async () => {
    setUser('admin')
    route('POST', '/api/system/selftest', () => ({ request_id: 'r4' }))
    route('GET', '/api/requests/r4', () => apiFail(403, 'E_FORBIDDEN'))
    const req = await use(() => useHelperRequest())
    expect(await req.run('/api/system/selftest', {}, { pollMs: 1 })).toBeNull()
    expect(toastAdd).toHaveBeenLastCalledWith(expect.objectContaining({ title: 'Votre rôle ne permet pas cette action.', color: 'error' }))
  })

  it('dépôt refusé (service occupé) : aucun suivi', async () => {
    setUser('admin')
    route('POST', '/api/system/selftest', () => apiFail(409, 'E_HELPER_BUSY'))
    const req = await use(() => useHelperRequest())
    expect(await req.run('/api/system/selftest', {}, { pollMs: 1 })).toBeNull()
    expect(toastAdd).toHaveBeenCalledTimes(1)
    expect(toastAdd).toHaveBeenCalledWith(expect.objectContaining({ title: 'Le service système est occupé.' }))
  })

  it('délai dépassé sans résultat : avertissement', async () => {
    setUser('admin')
    route('POST', '/api/system/selftest', () => ({ request_id: 'r5' }))
    route('GET', '/api/requests/r5', () => ({ id: 'r5', type: 'run-selftest', status: 'running', step: 'run', code: null, message: null, output: null }))
    const req = await use(() => useHelperRequest())
    expect(await req.run('/api/system/selftest', {}, { pollMs: 1, timeoutMs: 30 })).toBeNull()
    expect(toastAdd).toHaveBeenLastCalledWith(expect.objectContaining({ title: 'Sans réponse du service système', color: 'warning' }))
  })
})

describe('useApplianceState', () => {
  it('lit l’état au montage, le rafraîchit périodiquement et ignore les erreurs', async () => {
    setUser('viewer')
    let n = 0
    route('GET', '/api/state', () => {
      n += 1
      if (n === 2) apiFail(500, 'E_INTERNAL')
      return sampleState()
    })
    const holder: { value?: ReturnType<typeof useApplianceState> } = {}
    const wrapper = await mountSuspended(setupComponent(() => useApplianceState(20), holder))
    const s = holder.value!
    await settle()
    expect(s.state.value?.appliance.fqdn).toBe('analyse.exemple.test')
    await vi.waitFor(() => expect(n).toBeGreaterThanOrEqual(3))
    expect(s.data.value?.available).toBe(true)
    wrapper.unmount()
    const after = n
    await new Promise(resolve => setTimeout(resolve, 80))
    expect(n).toBeLessThanOrEqual(after + 1)
  })
})
