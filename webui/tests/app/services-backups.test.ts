// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Sauvegardes d'un module permanent (0.4, chantier A) : liste, « Sauvegarder
// maintenant » avec indicateur d'attente, restauration derrière une modale de
// confirmation irréversible, sauvegarde d'une autre version non restaurable,
// lecteur sans action, textes en anglais.

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { enableAutoUnmount } from '@vue/test-utils'
import { mockNuxtImport } from '@nuxt/test-utils/runtime'
import { bodyText, button, buttons, callsTo, clearBody, click, mountIn, resetApi, route, setLocale, settle, setUser } from './helpers'
import ModuleBackups from '~/components/ModuleBackups.vue'
import type { InstalledModule, ModuleBackup } from '~/composables/useCatalog'

const { toastAdd } = vi.hoisted(() => ({ toastAdd: vi.fn() }))
mockNuxtImport('useToast', () => () => ({ add: toastAdd }))

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

const BACKUP: ModuleBackup = {
  id: '20261123T020000Z', created_at: '2026-11-23T02:00:00Z', module_version: '1.2.0', reason: 'manual',
  size_bytes: 1_572_864, database: true, volumes: ['data', 'logs'],
}

function svc(patch: Partial<InstalledModule> = {}): InstalledModule {
  return {
    id: 'svc', version: '1.2.0', type: 'service', status: 'healthy', enabled: true, installed_at: '2026-11-20T10:00:00Z',
    options: {}, testbed: null, route: null, last_error: null,
    backups: [
      BACKUP,
      { ...BACKUP, id: '20261120T020000Z', module_version: '1.1.0', reason: 'update', size_bytes: 512, database: false, volumes: [] },
    ],
    ...patch,
  } as InstalledModule
}

function helperRoute(path: string, id: string) {
  route('POST', path, () => ({ request_id: id }))
  route('GET', `/api/requests/${id}`, () => ({ id, type: 'x', status: 'ok', code: 'OK', step: null, message: null, output: null }))
}

async function drive(): Promise<void> {
  for (let i = 0; i < 3; i++) await vi.advanceTimersByTimeAsync(2100)
  await settle()
}

describe('ModuleBackups', () => {
  it('liste les sauvegardes, avec taille, contenu et motif', async () => {
    await mountIn(ModuleBackups, { props: { module: svc(), name: 'Service', admin: true } })
    const text = bodyText()
    expect(text).toContain('Sauvegardes')
    expect(text).toContain('1,5 Mo')
    expect(text).toContain('base de données · volumes : data, logs')
    expect(text).toContain('avant mise à jour')
    expect(text).toContain('configuration seule')
    expect(document.body.querySelectorAll('[data-backup]').length).toBe(2)
    const restores = buttons('Restaurer')
    expect(restores.map(b => b.disabled)).toEqual([false, true])
    expect(restores[1]!.title).toContain('1.1.0')
  })

  it('sauvegarde à la demande : indicateur d’attente puis rafraîchissement', async () => {
    vi.useFakeTimers({ toFake: ['setTimeout', 'setInterval', 'clearTimeout', 'clearInterval'] })
    helperRoute('/api/catalog/modules/svc/backup', 'req-b')
    const w = await mountIn(ModuleBackups, { props: { module: svc(), name: 'Service', admin: true } })
    await click(document.body.querySelector('[data-backup-now]')!)
    expect(callsTo('POST', '/api/catalog/modules/svc/backup')[0]?.body).toEqual({})
    await drive()
    expect(w.emitted('done')).toHaveLength(1)
  })

  it('restauration seulement après la confirmation explicite', async () => {
    vi.useFakeTimers({ toFake: ['setTimeout', 'setInterval', 'clearTimeout', 'clearInterval'] })
    helperRoute('/api/catalog/modules/svc/restore', 'req-r')
    const w = await mountIn(ModuleBackups, { props: { module: svc(), name: 'Service', admin: true } })
    await click(buttons('Restaurer')[0]!)
    expect(bodyText()).toContain('Restaurer Service')
    expect(bodyText()).toContain('définitivement remplacées')
    const confirm = button('Restaurer')
    expect(confirm.disabled).toBe(true)
    await click(document.body.querySelector('[role="dialog"] [role="checkbox"]')!)
    await click(button('Restaurer'))
    expect(callsTo('POST', '/api/catalog/modules/svc/restore')[0]?.body).toEqual({ backup: '20261123T020000Z' })
    await drive()
    expect(w.emitted('done')).toHaveLength(1)
  })

  it('lecteur : aucune action ; module occupé : boutons désactivés ; aucune sauvegarde', async () => {
    await mountIn(ModuleBackups, { props: { module: svc(), name: 'Service', admin: false } })
    expect(buttons('Restaurer')).toHaveLength(0)
    expect(document.body.querySelector('[data-backup-now]')).toBeNull()
    clearBody()
    await mountIn(ModuleBackups, { props: { module: svc({ status: 'testing' }), name: 'Service', admin: true } })
    expect((document.body.querySelector('[data-backup-now]') as HTMLButtonElement).disabled).toBe(true)
    clearBody()
    await setLocale('en')
    await mountIn(ModuleBackups, { props: { module: svc({ backups: undefined }), name: 'Service', admin: true, busy: true } })
    expect(bodyText()).toContain('Backups')
    expect((document.body.querySelector('[data-backup-now]') as HTMLButtonElement).disabled).toBe(true)
  })
})
