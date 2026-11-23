// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Tableau de bord, Système (nom, réseaux d'administration) et TLS : actions
// réservées aux administrateurs, modales de confirmation de la console,
// indicateurs d'attente pendant les demandes au service root.

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { enableAutoUnmount } from '@vue/test-utils'
import { mockNuxtImport } from '@nuxt/test-utils/runtime'
import {
  bodyText, button, buttons, callsTo, clearBody, click, mountIn, resetApi, route, sampleState, setLocale, settle, setUser,
} from './helpers'
import DashboardPage from '~/pages/index.vue'
import SystemPage from '~/pages/system/index.vue'
import TlsPage from '~/pages/system/tls.vue'

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

/** Demande au service root : dépôt puis résultat final au premier suivi. */
function helperRoute(path: string, id: string, final: Record<string, unknown> = { status: 'ok', code: 'OK' }) {
  route('POST', path, () => ({ request_id: id }))
  route('GET', `/api/requests/${id}`, () => ({ id, type: 'x', step: null, message: null, output: null, ...final }))
}

/** Fait avancer le suivi (sondage toutes les 2 s) de quelques tours. */
async function drive(rounds = 3): Promise<void> {
  for (let i = 0; i < rounds; i++) await vi.advanceTimersByTimeAsync(2100)
  await settle()
}

describe('tableau de bord', () => {
  it('santé : services, disques, TLS, pare-feu, mise à jour, sans action pour un lecteur', async () => {
    setUser('viewer')
    route('GET', '/api/state', () => sampleState({
      update: { available: true, latest_version: '0.2.0', last_check_at: '2026-11-23T07:00:00Z' },
      helper: { busy: true, current: { id: 'r', type: 'apply-update', step: 'download', started_at: '2026-11-23T08:00:00Z' } },
    }))
    const w = await mountIn(DashboardPage)
    await settle()
    const text = w.text()
    expect(text).toContain('analyse.exemple.test')
    expect(text).toContain('4 vCPU, 8192 Mo')
    expect(text).toContain('actif')
    expect(text).toContain('en échec')
    expect(text).toContain('démarrage')
    expect(text).toContain('2 Go libres sur 40 Go')
    expect(text).toContain('Règles chargées')
    expect(text).toContain('Version 0.2.0 disponible')
    expect(text).toContain('Service système occupé : apply-update')
    expect(text).toContain('téléchargement')
    expect(text).toContain('Jamais lancés')
    expect(buttons('Lancer les tests')).toHaveLength(0)
  })

  it('administrateur : tests de fumée avec indicateur d’attente puis état rafraîchi', async () => {
    vi.useFakeTimers({ toFake: ['setTimeout', 'setInterval', 'clearTimeout', 'clearInterval'] })
    setUser('admin')
    let n = 0
    route('GET', '/api/state', () => {
      n += 1
      return sampleState({ tls: { not_after: new Date(Date.now() + 5 * 86_400_000).toISOString() } })
    })
    helperRoute('/api/system/selftest', 'st1')
    const w = await mountIn(DashboardPage)
    await settle()
    expect(w.text()).toContain('À jour')
    await click(button('Lancer les tests'))
    expect(w.find('[role="status"]').exists()).toBe(true)
    await drive()
    expect(callsTo('POST', '/api/system/selftest')[0]!.body).toEqual({ quick: true })
    expect(w.find('[role="status"]').exists()).toBe(false)
    expect(n).toBeGreaterThanOrEqual(2)
    expect(toastAdd).toHaveBeenLastCalledWith(expect.objectContaining({ title: 'Terminé avec succès.' }))
  })

  it('anglais, état indisponible : alerte et aucun détail', async () => {
    await setLocale('en')
    setUser('viewer')
    route('GET', '/api/state', () => ({ available: false, reason: 'missing', state: null, console_version: '0.1.0' }))
    const w = await mountIn(DashboardPage)
    await settle()
    expect(w.text()).toContain('Dashboard')
    expect(w.text()).not.toContain('Services')
    await click(button('Refresh'))
    expect(callsTo('GET', '/api/state').length).toBeGreaterThanOrEqual(2)
  })

  it('selftest passé, certificat expiré', async () => {
    setUser('viewer')
    const st = sampleState({ tls: { not_after: '2020-01-01T00:00:00Z' } })
    st.state!.selftest = { status: 'warn', finished_at: '2026-11-23T08:00:00Z' }
    route('GET', '/api/state', () => st)
    const w = await mountIn(DashboardPage)
    await settle()
    expect(w.text()).toContain('avertissement')
    expect(w.text()).toContain('Dernier passage le')
  })
})

describe('système', () => {
  it('lecteur : champs désactivés, actions masquées, mention « réservé aux administrateurs »', async () => {
    setUser('viewer')
    route('GET', '/api/state', () => sampleState())
    const w = await mountIn(SystemPage)
    await settle()
    expect(w.text()).toContain('Nom actuel : analyse.exemple.test')
    expect(w.text()).toContain('Réservé aux administrateurs.')
    expect(buttons('Changer le nom')).toHaveLength(0)
    expect(buttons('Appliquer')).toHaveLength(0)
    expect((w.find('input').element as HTMLInputElement).disabled).toBe(true)
    expect((w.find('input').element as HTMLInputElement).value).toBe('analyse.exemple.test')
  })

  it('changement de nom : validation, conseil DNS, modale avec case à cocher, demande', async () => {
    vi.useFakeTimers({ toFake: ['setTimeout', 'setInterval', 'clearTimeout', 'clearInterval'] })
    setUser('admin')
    route('GET', '/api/state', () => sampleState())
    helperRoute('/api/system/hostname', 'h1')
    const w = await mountIn(SystemPage)
    await settle()
    expect(button('Changer le nom').disabled).toBe(true)
    await w.find('input').setValue('pas un nom')
    expect(w.text()).toContain('Certaines valeurs sont invalides.')
    await w.find('input').setValue('Console.Exemple.Test')
    expect(w.text()).toContain('console.exemple.test et *.console.exemple.test')
    expect(button('Changer le nom').disabled).toBe(false)
    await click(button('Changer le nom'))
    expect(bodyText()).toContain('Changer le nom de l’appliance ?')
    expect(button('Confirmer').disabled).toBe(true)
    await click(document.body.querySelector('[role="dialog"] [role="checkbox"]')!)
    const confirm = button('Confirmer')
    expect(confirm.disabled).toBe(false)
    confirm.dispatchEvent(new MouseEvent('click', { bubbles: true }))
    await drive()
    expect(callsTo('POST', '/api/system/hostname')[0]!.body).toEqual({ fqdn: 'console.exemple.test' })
    expect(document.body.querySelector('[role="dialog"]')).toBeNull()
  })

  it('réseaux : réseau invalide signalé, liste confirmée, perte d’accès autorisée explicitement', async () => {
    vi.useFakeTimers({ toFake: ['setTimeout', 'setInterval', 'clearTimeout', 'clearInterval'] })
    setUser('admin')
    route('GET', '/api/state', () => sampleState())
    helperRoute('/api/system/admin-networks', 'n1', { status: 'error', code: 'E_LOCKOUT' })
    const w = await mountIn(SystemPage)
    await settle()
    expect(w.text()).toContain('Votre adresse vue par la console : 192.0.2.10')
    const area = w.find('textarea')
    expect((area.element as HTMLTextAreaElement).value).toBe('192.0.2.0/24')
    await area.setValue('192.0.2.0/24\n300.1.1.1/8')
    expect(w.text()).toContain('Réseau invalide : 300.1.1.1/8')
    expect(button('Appliquer').disabled).toBe(true)
    await area.setValue('192.0.2.0/24, 198.51.100.0/24')
    await click(w.findAll('[role="checkbox"]').at(-1)!.element)
    expect(button('Appliquer').disabled).toBe(false)
    await click(button('Appliquer'))
    expect(bodyText()).toContain('198.51.100.0/24')
    expect(bodyText()).toContain('vous avez autorisé la perte de votre propre accès')
    button('Confirmer').dispatchEvent(new MouseEvent('click', { bubbles: true }))
    await drive()
    expect(callsTo('POST', '/api/system/admin-networks')[0]!.body).toEqual({
      networks: ['192.0.2.0/24', '198.51.100.0/24'], allow_self_lockout: true,
    })
    expect(toastAdd).toHaveBeenLastCalledWith(expect.objectContaining({
      title: 'Échec', description: 'Refusé : votre propre adresse ne serait plus autorisée (risque de perte d’accès).',
    }))
  })
})

describe('TLS', () => {
  const CERT = '-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----'
  const KEY = '-----BEGIN PRIVATE KEY-----\nMIIE\n-----END PRIVATE KEY-----'

  it('lecteur : certificat affiché, téléchargement de l’AC, ni renouvellement ni import', async () => {
    setUser('viewer')
    route('GET', '/api/state', () => sampleState())
    const w = await mountIn(TlsPage)
    await settle()
    expect(w.text()).toContain('AC interne')
    expect(w.text()).toContain('analyse.exemple.test, *.analyse.exemple.test')
    expect(w.text()).toContain('AA:BB:CC:DD')
    expect(w.text()).toContain('00:11')
    expect(w.find('a[href="/api/system/tls/ca"]').exists()).toBe(true)
    expect(buttons('Renouveler le certificat interne')).toHaveLength(0)
    expect(w.text()).not.toContain('Importer un certificat')
  })

  it('renouvellement confirmé par une modale', async () => {
    vi.useFakeTimers({ toFake: ['setTimeout', 'setInterval', 'clearTimeout', 'clearInterval'] })
    setUser('admin')
    route('GET', '/api/state', () => sampleState())
    helperRoute('/api/system/tls/issue', 't1')
    await mountIn(TlsPage)
    await settle()
    await click(button('Renouveler le certificat interne'))
    expect(bodyText()).toContain('Émettre un nouveau certificat interne ?')
    button('Confirmer').dispatchEvent(new MouseEvent('click', { bubbles: true }))
    await drive()
    expect(callsTo('POST', '/api/system/tls/issue')[0]!.body).toEqual({ force: true })
  })

  it('import : PEM validés, chargement d’un fichier, clé effacée après la demande', async () => {
    vi.useFakeTimers({ toFake: ['setTimeout', 'setInterval', 'clearTimeout', 'clearInterval'] })
    setUser('admin')
    route('GET', '/api/state', () => sampleState({ tls: { mode: 'imported' } }))
    helperRoute('/api/system/tls/import', 't2')
    const w = await mountIn(TlsPage)
    await settle()
    expect(w.text()).toContain('Certificat importé')
    const areas = w.findAll('textarea')
    expect(button('Importer').disabled).toBe(true)
    await areas[0]!.setValue(CERT)
    // la clé est chargée depuis un fichier
    const file = new File([KEY], 'cle.key', { type: 'text/plain' })
    const input = w.findAll('input[type="file"]')[1]!
    Object.defineProperty(input.element, 'files', { value: [file], configurable: true })
    await input.trigger('change')
    await settle()
    expect((areas[1]!.element as HTMLTextAreaElement).value).toBe(KEY)
    await areas[2]!.setValue(CERT)
    expect(button('Importer').disabled).toBe(false)
    await click(button('Importer'))
    button('Confirmer').dispatchEvent(new MouseEvent('click', { bubbles: true }))
    await drive()
    expect(callsTo('POST', '/api/system/tls/import')[0]!.body).toEqual({ cert_pem: `${CERT}\n`, key_pem: `${KEY}\n`, chain_pem: `${CERT}\n` })
    for (const a of areas) expect((a.element as HTMLTextAreaElement).value).toBe('')
  })

  it('import refusé : la clé est effacée, le certificat conservé', async () => {
    vi.useFakeTimers({ toFake: ['setTimeout', 'setInterval', 'clearTimeout', 'clearInterval'] })
    setUser('admin')
    route('GET', '/api/state', () => sampleState())
    helperRoute('/api/system/tls/import', 't3', { status: 'error', code: 'E_CERT_NAMES' })
    const w = await mountIn(TlsPage)
    await settle()
    const areas = w.findAll('textarea')
    await areas[0]!.setValue(CERT)
    await areas[1]!.setValue(KEY)
    await click(button('Importer'))
    button('Confirmer').dispatchEvent(new MouseEvent('click', { bubbles: true }))
    await drive()
    expect(callsTo('POST', '/api/system/tls/import')[0]!.body).toEqual({ cert_pem: `${CERT}\n`, key_pem: `${KEY}\n` })
    expect((areas[0]!.element as HTMLTextAreaElement).value).toBe(CERT)
    expect((areas[1]!.element as HTMLTextAreaElement).value).toBe('')
    expect(toastAdd).toHaveBeenLastCalledWith(expect.objectContaining({ description: 'Le certificat doit couvrir le nom de l’appliance et *.nom.' }))
  })
})
