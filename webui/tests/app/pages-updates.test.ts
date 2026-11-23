// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Page des mises à jour : versions, notes, recherche, installation confirmée,
// politique (fenêtre de maintenance), retour à N-1 avec case à cocher,
// import hors ligne (téléversement des quatre fichiers), historique.

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { enableAutoUnmount } from '@vue/test-utils'
import { mockNuxtImport } from '@nuxt/test-utils/runtime'
import {
  apiFail, bodyText, button, buttons, callsTo, clearBody, click, mountIn, resetApi, route, sampleState, setLocale, settle, setUser,
} from './helpers'
import UpdatesPage from '~/pages/updates.vue'

const { toastAdd } = vi.hoisted(() => ({ toastAdd: vi.fn() }))
mockNuxtImport('useToast', () => () => ({ add: toastAdd }))

enableAutoUnmount(afterEach)

const UPLOAD_ID = '0f8fad5b-d9cb-469f-a165-70867728950e'
const HISTORY = [
  { id: '2', action: 'auto-rollback', from_version: '0.1.0', to_version: '0.2.0', status: 'rolled-back', code: 'E_HEALTH_ROLLED_BACK', initiated_by: null, started_at: '2026-11-22T03:00:00Z' },
  { id: '1', action: 'apply', from_version: '0.0.9', to_version: '0.1.0', status: 'success', code: 'OK', initiated_by: 'alice', started_at: '2026-11-20T03:00:00Z' },
]

let reload: ReturnType<typeof vi.fn<() => void>>

beforeEach(async () => {
  await setLocale('fr')
  toastAdd.mockReset()
  reload = vi.fn<() => void>()
  vi.spyOn(window.location, 'reload').mockImplementation(reload)
})
afterEach(() => {
  vi.useRealTimers()
  vi.restoreAllMocks()
  resetApi()
  clearBody()
})

function helperRoute(path: string, id: string, final: Record<string, unknown> = { status: 'ok', code: 'OK' }) {
  route('POST', path, () => ({ request_id: id }))
  route('GET', `/api/requests/${id}`, () => ({ id, type: 'x', step: null, message: null, output: null, ...final }))
}

/** Horloge simulée, posée après le montage (le montage de cette page attend de vrais délais). */
function fakeClock(): void {
  vi.useFakeTimers({ toFake: ['setTimeout', 'setInterval', 'clearTimeout', 'clearInterval'] })
}

async function drive(rounds = 3): Promise<void> {
  for (let i = 0; i < rounds; i++) await vi.advanceTimersByTimeAsync(2100)
  await settle()
}

const AVAILABLE = {
  appliance: { previous_version: '0.0.9' },
  update: {
    available: true, latest_version: '0.2.0', last_check_at: '2026-11-23T07:00:00Z', last_check_code: 'E_NETWORK',
    notes_md: '## 0.2.0\n- moteur de modules', published_at: '2026-11-22T12:00:00Z', skipped_version: '0.1.5',
  },
}

describe('mises à jour', () => {
  it('lecteur : versions, notes, historique, aucune action', async () => {
    setUser('viewer')
    route('GET', '/api/state', () => sampleState(AVAILABLE))
    route('GET', '/api/system/updates/history', () => ({ items: HISTORY }))
    const w = await mountIn(UpdatesPage)
    await settle()
    const text = w.text()
    expect(text).toContain('0.2.0')
    expect(text).toContain('Version précédente (N-1) : 0.0.9')
    expect(text).toContain('Résultat : Erreur réseau')
    expect(text).toContain('Version 0.1.5 abandonnée')
    expect(text).toContain('Publiée le')
    expect(text).toContain('moteur de modules')
    expect(text).toContain('Retour automatique')
    expect(text).toContain('annulé (E_HEALTH_ROLLED_BACK)')
    expect(text).toContain('system')
    expect(text).toContain('0.0.9 → 0.1.0')
    expect(buttons('Rechercher maintenant')).toHaveLength(0)
    expect(text).not.toContain('Politique de mise à jour')
    expect(text).not.toContain('Importer une mise à jour')
  })

  it('anglais, à jour, historique indisponible', async () => {
    await setLocale('en')
    setUser('admin')
    route('GET', '/api/state', () => sampleState())
    route('GET', '/api/system/updates/history', () => apiFail(500, 'E_INTERNAL'))
    const w = await mountIn(UpdatesPage)
    await settle()
    expect(w.text()).toContain('No newer version')
    expect(w.text()).toContain('No previous version kept.')
    expect(buttons('Install now')).toHaveLength(0)
  })

  it('recherche puis installation confirmée ; la console est rechargée après succès', async () => {
    setUser('admin')
    route('GET', '/api/state', () => sampleState(AVAILABLE))
    route('GET', '/api/system/updates/history', () => ({ items: [] }))
    helperRoute('/api/system/updates/check', 'c1')
    helperRoute('/api/system/updates/apply', 'a1')
    await mountIn(UpdatesPage)
    await settle()
    fakeClock()
    await click(button('Rechercher maintenant'))
    expect(button('Installer maintenant').disabled).toBe(true)
    await drive()
    expect(callsTo('POST', '/api/system/updates/check')[0]!.body).toEqual({})
    expect(button('Installer maintenant').disabled).toBe(false)
    await click(button('Installer maintenant'))
    expect(bodyText()).toContain('Installer la version 0.2.0 ?')
    button('Confirmer').dispatchEvent(new MouseEvent('click', { bubbles: true }))
    await drive()
    expect(callsTo('POST', '/api/system/updates/apply')[0]!.body).toEqual({ source: 'github', version: '0.2.0' })
    expect(callsTo('GET', '/api/system/updates/history').length).toBeGreaterThanOrEqual(2)
    await vi.advanceTimersByTimeAsync(1600)
    expect(reload).toHaveBeenCalled()
  })

  it('retour à N-1 : case à cocher obligatoire, versions attendues envoyées, pas de rechargement en échec', async () => {
    setUser('admin')
    route('GET', '/api/state', () => sampleState(AVAILABLE))
    route('GET', '/api/system/updates/history', () => ({ items: [] }))
    helperRoute('/api/system/updates/rollback', 'rb1', { status: 'error', code: 'E_PRECONDITION' })
    await mountIn(UpdatesPage)
    await settle()
    fakeClock()
    await click(button('Revenir à 0.0.9'))
    expect(bodyText()).toContain('Revenir à la version 0.0.9 ?')
    expect(button('Confirmer').disabled).toBe(true)
    await click(document.body.querySelector('[role="dialog"] [role="checkbox"]')!)
    button('Confirmer').dispatchEvent(new MouseEvent('click', { bubbles: true }))
    await drive()
    expect(callsTo('POST', '/api/system/updates/rollback')[0]!.body).toEqual({ expected_current: '0.1.0', expected_target: '0.0.9' })
    await vi.advanceTimersByTimeAsync(1600)
    expect(reload).not.toHaveBeenCalled()
  })

  it('politique : fenêtre reprise de l’état, installation automatique exige des jours', async () => {
    setUser('admin')
    route('GET', '/api/state', () => sampleState({
      update: { channel: 'prerelease', auto_apply: false, maintenance_window: { days: ['sat', 'mon'], start: '02:30', duration_minutes: 60 } },
    }))
    route('GET', '/api/system/updates/history', () => ({ items: [] }))
    helperRoute('/api/system/updates/policy', 'p1')
    const w = await mountIn(UpdatesPage)
    await settle()
    fakeClock()
    expect(w.text()).toContain('Jours')
    expect((w.find('input[type="time"]').element as HTMLInputElement).value).toBe('02:30')
    const vm = w.vm as unknown as { policy: { auto_apply: boolean, days: string[] } }
    vm.policy.auto_apply = true
    vm.policy.days = []
    await settle()
    expect(w.text()).toContain('L’installation automatique exige une fenêtre de maintenance.')
    expect(button('Enregistrer la politique').disabled).toBe(true)
    vm.policy.days = ['sun', 'mon']
    await settle()
    await click(button('Enregistrer la politique'))
    await drive()
    expect(callsTo('POST', '/api/system/updates/policy')[0]!.body).toEqual({
      channel: 'prerelease', auto_check: true, auto_apply: true,
      maintenance_window: { days: ['mon', 'sun'], start: '02:30', duration_minutes: 60 },
    })
  })

  it('politique sans fenêtre : maintenance_window nulle', async () => {
    setUser('admin')
    route('GET', '/api/state', () => sampleState())
    route('GET', '/api/system/updates/history', () => ({ items: [] }))
    helperRoute('/api/system/updates/policy', 'p2')
    const w = await mountIn(UpdatesPage)
    await settle()
    fakeClock()
    expect(w.text()).not.toContain('Jours')
    await click(button('Enregistrer la politique'))
    await drive()
    expect(callsTo('POST', '/api/system/updates/policy')[0]!.body).toEqual({
      channel: 'stable', auto_check: true, auto_apply: false, maintenance_window: null,
    })
  })

  it('import hors ligne : fichiers manquants signalés, téléversement des quatre fichiers puis installation', async () => {
    setUser('admin')
    route('GET', '/api/state', () => sampleState())
    route('GET', '/api/system/updates/history', () => ({ items: [] }))
    route('POST', '/api/system/updates/uploads', () => ({ upload_id: UPLOAD_ID }))
    const names = ['release.json', 'SHA256SUMS', 'SHA256SUMS.sig', 'scanoria-0.2.0.tar.zst']
    for (const n of names) route('PUT', `/api/system/updates/uploads/${UPLOAD_ID}/${n}`, () => ({ upload_id: UPLOAD_ID, name: n }))
    helperRoute('/api/system/updates/apply', 'u1')
    const w = await mountIn(UpdatesPage)
    await settle()
    fakeClock()
    const input = w.find('#update-upload-files')
    const choose = async (files: string[]) => {
      Object.defineProperty(input.element, 'files', { value: files.map(f => new File(['x'], f)), configurable: true })
      await input.trigger('change')
      await settle()
    }
    await choose(['release.json'])
    expect(w.text()).toContain('Fichiers manquants : scanoria-X.Y.Z.tar.zst, SHA256SUMS, SHA256SUMS.sig')
    expect(button('Téléverser et installer').disabled).toBe(true)
    await choose(names)
    expect(w.text()).not.toContain('Fichiers manquants')
    await click(button('Téléverser et installer'))
    expect(bodyText()).toContain('Installer la version 0.2.0 ?')
    button('Confirmer').dispatchEvent(new MouseEvent('click', { bubbles: true }))
    await drive()
    for (const n of names) {
      const put = callsTo('PUT', `/api/system/updates/uploads/${UPLOAD_ID}/${n}`)
      expect(put).toHaveLength(1)
      expect(put[0]!.csrf).toBe('csrf-test')
    }
    expect(callsTo('POST', '/api/system/updates/apply')[0]!.body).toEqual({ source: 'upload', upload_id: UPLOAD_ID })
  })

  it('import hors ligne : échec du téléversement signalé', async () => {
    setUser('admin')
    route('GET', '/api/state', () => sampleState())
    route('GET', '/api/system/updates/history', () => ({ items: [] }))
    route('POST', '/api/system/updates/uploads', () => apiFail(413, 'E_TOO_LARGE'))
    const w = await mountIn(UpdatesPage)
    await settle()
    fakeClock()
    const input = w.find('#update-upload-files')
    Object.defineProperty(input.element, 'files', {
      value: ['release.json', 'SHA256SUMS', 'SHA256SUMS.sig', 'scanoria-0.2.0.tar.zst'].map(f => new File(['x'], f)),
    })
    await input.trigger('change')
    await settle()
    await click(button('Téléverser et installer'))
    button('Confirmer').dispatchEvent(new MouseEvent('click', { bubbles: true }))
    await drive(1)
    expect(toastAdd).toHaveBeenLastCalledWith(expect.objectContaining({ title: 'Fichier ou demande trop volumineux.', color: 'error' }))
    expect(document.body.querySelector('[role="dialog"]')).toBeNull()
  })
})
