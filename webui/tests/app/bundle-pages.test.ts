// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Page Système > Hors ligne (0.6, chantier A) : actions réservées aux
// administrateurs, modales de la console (jamais alert/confirm), indicateur
// d'attente pendant les demandes au service root, état relu sans recharger,
// français et anglais.

import { createHash, randomBytes } from 'node:crypto'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { enableAutoUnmount, type VueWrapper } from '@vue/test-utils'
import { mockNuxtImport } from '@nuxt/test-utils/runtime'
import { button, buttons, callsTo, clearBody, click, mountIn, resetApi, route, setLocale, settle, setUser } from './helpers'
import OfflinePage from '~/pages/system/offline.vue'

const { toastAdd } = vi.hoisted(() => ({ toastAdd: vi.fn() }))
mockNuxtImport('useToast', () => () => ({ add: toastAdd }))

enableAutoUnmount(afterEach)

// Clé et empreintes produites à l'exécution : aucune valeur fixe dans le dépôt.
const PUB = randomBytes(32).toString('base64')
const FPR = createHash('sha256').update(Buffer.from(PUB, 'base64')).digest('hex')
const OWN = createHash('sha256').update(randomBytes(32)).digest('hex')
const BUNDLE = 'scanoria-bundle-20261124T020000Z.tar'

function view(patch: Record<string, unknown> = {}) {
  return {
    available: true,
    appliance_key: { public_key: randomBytes(32).toString('base64'), fingerprint: OWN },
    trusted_keys: [{ id: 'k1', label: 'Appliance du siège', public_key: PUB, fingerprint: FPR, added_at: '2026-11-20T08:00:00Z', added_by_username: 'admin', revoked_at: null, in_store: true }],
    exports: [{ name: BUNDLE, created_at: '2026-11-24T02:00:00Z', size_bytes: 3 * 1024 ** 3, sha256: FPR, signer_fingerprint: OWN, modules: ['gitleaks'], scheduled: true }],
    history: [{ id: 'h1', direction: 'import', status: 'error', contents: {}, size_bytes: null, signer_fingerprint: null, error: { code: 'E_BUNDLE_SIGNATURE' }, requested_by_username: 'admin', created_at: '2026-11-24T03:00:00Z', finished_at: '2026-11-24T03:01:00Z' }],
    last_import: null,
    mirror: null,
    publication: null,
    schedule: { enabled: false, every_days: 7, keep: 2, modules: [], last_run_at: null },
    dtrack: {
      configured_at: '2026-11-24T02:00:00Z', configure_error: null,
      sources: [{ id: 'osv', available: true, ecosystems: ['npm', 'PyPI'], updated_at: '2026-11-24T01:00:00Z', reason: null }, { id: 'epss', available: false, ecosystems: [], updated_at: null, reason: 'feed-missing' }],
      gaps: [{ id: 'nvd', reason: 'no-feed' }, { id: 'ghsa', reason: 'token-required' }],
    },
    ...patch,
  }
}

let state = view()
let loads = 0
function routes() {
  route('GET', '/api/system/offline', () => {
    loads += 1
    return state
  })
  route('GET', '/api/catalog', () => ({ modules: [
    { id: 'gitleaks', name: 'gitleaks', type: 'scanner', installed: { version: '1' } },
    { id: 'osv-db', name: 'OSV', type: 'feed', installed: { version: '1' } },
    { id: 'trivy', name: 'Trivy', type: 'scanner', installed: null },
  ] }))
}

/** Demande au service root : dépôt puis résultat final au premier suivi. */
function helperRoute(path: string, id: string, final: Record<string, unknown> = { status: 'ok', code: 'OK' }) {
  route('POST', path, () => ({ request_id: id }))
  route('GET', `/api/requests/${id}`, () => ({ id, type: 'x', step: null, message: null, output: null, ...final }))
}
async function drive(rounds = 3): Promise<void> {
  for (let i = 0; i < rounds; i++) await vi.advanceTimersByTimeAsync(2100)
  await settle()
}
function dialog(): Element {
  const d = document.body.querySelector('[role="dialog"]')
  expect(d).not.toBeNull()
  return d!
}
async function input(selector: string, value: string): Promise<void> {
  const el = document.body.querySelector(`${selector} input, input${selector}`) as HTMLInputElement
  el.value = value
  el.dispatchEvent(new Event('input', { bubbles: true }))
  await settle()
}
function pick(w: VueWrapper, name: 'USelectMenu' | 'USelect', index: number, value: unknown) {
  const menu = w.findAllComponents({ name }).at(index)
  expect(menu).toBeDefined()
  menu!.vm.$emit('update:modelValue', value)
}
const fakeTimers = () => vi.useFakeTimers({ toFake: ['setTimeout', 'setInterval', 'clearTimeout', 'clearInterval'] })

beforeEach(async () => {
  await setLocale('fr')
  toastAdd.mockReset()
  state = view()
  loads = 0
})
afterEach(() => {
  vi.useRealTimers()
  vi.unstubAllGlobals()
  resetApi()
  clearBody()
})

describe('bundle : page Hors ligne', () => {
  it('opérateur : état complet en lecture, aucune action d’administrateur', async () => {
    setUser('operator')
    routes()
    const w = await mountIn(OfflinePage)
    await settle()
    const text = w.text()
    expect(text).toContain('Clé de cette appliance')
    expect(text).toContain('Appliance du siège')
    expect(text).toContain('Sources de Dependency-Track')
    expect(w.find('[data-testid="dtrack-gaps"]').exists()).toBe(true)
    expect(text).toContain('Historique des lots')
    expect(buttons('Ajouter une clé')).toHaveLength(0)
    expect(buttons('Exporter')).toHaveLength(0)
    expect(buttons('Importer')).toHaveLength(0)
    expect(buttons('Retirer')).toHaveLength(0)
  })

  it('état indisponible : avertissement, sans planter', async () => {
    setUser('admin')
    state = view({ available: false, appliance_key: null, trusted_keys: [], exports: [], history: [], dtrack: null })
    routes()
    const w = await mountIn(OfflinePage)
    await settle()
    expect(w.find('[data-testid="offline-dtrack"]').exists()).toBe(false)
    expect(w.text()).toContain('Aucune clé de confiance')
  })

  it('ajout d’une clé : empreinte calculée, case à cocher obligatoire, demande puis état relu', async () => {
    setUser('admin')
    routes()
    const w = await mountIn(OfflinePage)
    await settle()
    fakeTimers()
    helperRoute('/api/system/offline/keys', 'k2')
    await click(button('Ajouter une clé'))
    expect(dialog().textContent).toContain('Ajouter une clé de confiance')
    await input('[data-testid="trusted-key"]', 'pas une clé')
    expect(document.body.querySelector('[data-testid="trusted-fingerprint"]')).toBeNull()
    const other = randomBytes(32).toString('base64')
    const otherFpr = createHash('sha256').update(Buffer.from(other, 'base64')).digest('hex')
    await input('[data-testid="trusted-label"]', 'Appliance de recette')
    await input('[data-testid="trusted-key"]', other)
    await vi.waitFor(() => expect(document.body.querySelector('[data-testid="trusted-fingerprint"]')).not.toBeNull())
    const shown = document.body.querySelector('[data-testid="trusted-fingerprint"]')!.textContent!.replace(/[^0-9a-f]/gi, '').toLowerCase()
    expect(shown).toBe(otherFpr)
    const confirm = document.body.querySelector('[data-testid="trusted-confirm"]') as HTMLButtonElement
    expect(confirm.disabled).toBe(true)
    await click(document.body.querySelector('[role="dialog"] [role="checkbox"]')!)
    expect(confirm.disabled).toBe(false)
    confirm.dispatchEvent(new MouseEvent('click', { bubbles: true }))
    await settle()
    expect(w.find('[data-testid="offline-running"]').exists()).toBe(true)
    await drive()
    expect(callsTo('POST', '/api/system/offline/keys')[0]!.body).toEqual({ label: 'Appliance de recette', public_key: other, fingerprint: otherFpr })
    expect(w.find('[data-testid="offline-running"]').exists()).toBe(false)
    expect(loads).toBeGreaterThanOrEqual(2)
  })

  it('retrait d’une clé : modale avec case à cocher, couleur d’erreur', async () => {
    setUser('admin')
    routes()
    const w = await mountIn(OfflinePage)
    await settle()
    fakeTimers()
    helperRoute('/api/system/offline/keys/remove', 'k3')
    await click(button('Retirer'))
    expect(dialog().textContent).toContain('Retirer cette clé de confiance ?')
    expect(dialog().textContent).toContain('Appliance du siège')
    const confirm = Array.from(dialog().querySelectorAll('button')).find(b => b.textContent?.trim() === 'Retirer')!
    expect(confirm.disabled).toBe(true)
    await click(dialog().querySelector('[role="checkbox"]')!)
    confirm.dispatchEvent(new MouseEvent('click', { bubbles: true }))
    await drive()
    expect(callsTo('POST', '/api/system/offline/keys/remove')[0]!.body).toEqual({ fingerprint: FPR })
    expect(w.text()).toContain('Clés de confiance')
  })

  it('export : estimation, modale de confirmation, indicateur, échec traduit', async () => {
    setUser('admin')
    routes()
    const w = await mountIn(OfflinePage)
    await settle()
    fakeTimers()
    helperRoute('/api/system/offline/export', 'e1', { status: 'ok', code: 'OK', output: { estimated_bytes: 50 * 1024 ** 2, modules: ['gitleaks'], feeds: [], images: ['gitleaks'] } })
    pick(w, 'USelectMenu', 0, ['gitleaks'])
    await settle()
    await click(button('Estimer la taille'))
    await drive()
    expect(callsTo('POST', '/api/system/offline/export')[0]!.body).toEqual({ modules: ['gitleaks'], dry_run: true })
    expect(w.find('[data-testid="export-estimate"]').text()).toContain('50')
    resetApi()
    routes()
    helperRoute('/api/system/offline/export', 'e2', { status: 'error', code: 'E_BUNDLE_IMAGE' })
    await click(w.find('[data-testid="export-run"]').element)
    expect(dialog().textContent).toContain('Exporter un lot hors ligne ?')
    Array.from(dialog().querySelectorAll('button')).find(b => b.textContent?.trim() === 'Exporter')!
      .dispatchEvent(new MouseEvent('click', { bubbles: true }))
    await settle()
    expect(w.find('[data-testid="offline-running"]').exists()).toBe(true)
    await drive()
    expect(callsTo('POST', '/api/system/offline/export')[0]!.body).toEqual({ modules: ['gitleaks'] })
    expect(toastAdd).toHaveBeenLastCalledWith(expect.objectContaining({ title: 'Échec' }))
    expect(JSON.stringify(toastAdd.mock.calls.at(-1))).not.toContain('E_BUNDLE_IMAGE')
  })

  it('lot exporté : lien de téléchargement par son nom', async () => {
    setUser('admin')
    routes()
    const w = await mountIn(OfflinePage)
    await settle()
    expect(w.find(`a[href="/api/system/offline/bundles/${BUNDLE}"]`).exists()).toBe(true)
  })

  it('import : modale, téléversement avec avancement, puis demande au service root', async () => {
    setUser('admin')
    routes()
    route('POST', '/api/system/offline/uploads', () => ({ upload_id: '3f1c2a9e-7b4d-4e2a-9c1f-0a1b2c3d4e5f' }))
    const sent: { url?: string, csrf?: string } = {}
    class FakeXhr {
      status = 201
      upload: { onprogress?: (e: { lengthComputable: boolean, loaded: number, total: number }) => void } = {}
      onload?: () => void
      onerror?: () => void
      private headers: Record<string, string> = {}
      open(_m: string, url: string) {
        sent.url = url
      }

      setRequestHeader(k: string, v: string) {
        this.headers[k] = v
      }

      send() {
        sent.csrf = this.headers['x-csrf-token']
        this.upload.onprogress?.({ lengthComputable: true, loaded: 5, total: 10 })
        setTimeout(() => this.onload?.(), 0)
      }
    }
    vi.stubGlobal('XMLHttpRequest', FakeXhr)
    const w = await mountIn(OfflinePage)
    await settle()
    helperRoute('/api/system/offline/import', 'i1')
    const file = new File([new Uint8Array(10)], 'lot.tar')
    const el = w.find('[data-testid="import-file"] input, input[data-testid="import-file"]')
    Object.defineProperty(el.element, 'files', { value: [file] })
    await el.trigger('change')
    await click(w.find('[data-testid="import-run"]').element)
    expect(dialog().textContent).toContain('Importer ce lot ?')
    expect(dialog().textContent).toContain('lot.tar')
    fakeTimers()
    Array.from(dialog().querySelectorAll('button')).find(b => b.textContent?.trim() === 'Importer')!
      .dispatchEvent(new MouseEvent('click', { bubbles: true }))
    await drive(4)
    expect(sent.url).toBe('/api/system/offline/uploads/3f1c2a9e-7b4d-4e2a-9c1f-0a1b2c3d4e5f')
    expect(sent.csrf).toBeTruthy()
    expect(callsTo('POST', '/api/system/offline/import')[0]!.body).toEqual({ upload_id: '3f1c2a9e-7b4d-4e2a-9c1f-0a1b2c3d4e5f' })
  })

  it('miroir : adresse https et clé exigées, sortie confirmée par case à cocher', async () => {
    setUser('admin')
    routes()
    const w = await mountIn(OfflinePage)
    await settle()
    fakeTimers()
    helperRoute('/api/system/offline/mirror', 'm1')
    const setBtn = () => w.find('[data-testid="mirror-set"]').element as HTMLButtonElement
    expect(setBtn().disabled).toBe(true)
    await input('[data-testid="mirror-url"]', 'http://mirror.analyse.exemple.test')
    pick(w, 'USelect', -1, FPR)
    await settle()
    expect(setBtn().disabled).toBe(true)
    await input('[data-testid="mirror-url"]', 'https://mirror.analyse.exemple.test')
    expect(setBtn().disabled).toBe(false)
    await click(setBtn())
    expect(dialog().textContent).toContain('Utiliser cette appliance miroir ?')
    const confirm = Array.from(dialog().querySelectorAll('button')).find(b => b.textContent?.trim() === 'Utiliser ce miroir')!
    expect(confirm.disabled).toBe(true)
    await click(dialog().querySelector('[role="checkbox"]')!)
    confirm.dispatchEvent(new MouseEvent('click', { bubbles: true }))
    await drive()
    expect(callsTo('POST', '/api/system/offline/mirror')[0]!.body).toEqual({ enabled: true, url: 'https://mirror.analyse.exemple.test', fingerprint: FPR })
  })

  it('anglais : libellés traduits', async () => {
    await setLocale('en')
    setUser('admin')
    routes()
    const w = await mountIn(OfflinePage)
    await settle()
    expect(w.text()).toContain('Offline')
    expect(w.text()).toContain('Trusted keys')
    expect(w.text()).not.toContain('Clés de confiance')
  })
})
