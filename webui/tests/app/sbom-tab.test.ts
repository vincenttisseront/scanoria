// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Onglet « SBOM » d'une analyse (0.5, contrat 14) : composants, filtres et tri
// envoyés au serveur, pagination, export CycloneDX, lien Dependency-Track,
// couverture (composants ignorés), indicateur d'attente, anglais.

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { enableAutoUnmount } from '@vue/test-utils'
import { apiFail, bodyText, callsTo, clearBody, click, mountIn, resetApi, route, setLocale, settle, setUser } from './helpers'
import SbomComponents from '~/components/sbom/Components.vue'

enableAutoUnmount(afterEach)

beforeEach(async () => {
  await setLocale('fr')
  setUser('viewer')
})
afterEach(() => {
  vi.useRealTimers()
  resetApi()
  clearBody()
})

const ID = '3f1c2a9e-7b4d-4e2a-9c1f-0a1b2c3d4e5f'
const DTRACK = '6c1f2e3d-0a9b-4c8d-b7e6-f5a4b3c2d1e0'
const PATH = `/api/scans/${ID}/sbom`

function page(patch: Record<string, unknown> = {}) {
  return {
    scan_id: ID, project_id: 'p1', total: 3, matched: 3, page: 1, per_page: 50,
    components: [
      { purl: 'pkg:npm/minimist@1.2.8', ecosystem: 'npm', name: 'minimist', version: '1.2.8', licenses: ['MIT'], direct: true, paths: ['package-lock.json'], published_at: null },
      { purl: 'pkg:pypi/six@1.17.0', ecosystem: 'pypi', name: 'six', version: '1.17.0', licenses: [], direct: null, paths: ['requirements.txt'], published_at: null },
      { purl: 'pkg:golang/github.com/google/uuid@v1.6.0', ecosystem: 'golang', name: 'github.com/google/uuid', version: 'v1.6.0', licenses: [], direct: false, paths: [], published_at: null },
    ],
    ecosystems: [{ ecosystem: 'golang', count: 1 }, { ecosystem: 'npm', count: 1 }, { ecosystem: 'pypi', count: 1 }],
    licenses: [{ license: 'MIT', count: 1 }],
    coverage: { components: 3, ignored_no_purl: 2, ignored_invalid_purl: 1, direct_known: true, module: 'syft' },
    dtrack: { project: DTRACK, url: `https://dtrack.analyse.exemple.test/projects/${DTRACK}` },
    ...patch,
  }
}

describe('onglet SBOM', () => {
  it('composants, licences, dépendances, couverture, export et lien Dependency-Track', async () => {
    route('GET', PATH, () => page())
    route('GET', `/api/licenses/scans/${ID}`, () => ({ counts: { allowed: 1, review: 0, denied: 0 }, items: [{ purl: 'pkg:npm/minimist@1.2.8', name: 'minimist', version: '1.2.8', licenses: ['MIT'], decision: 'allowed', source: 'default' }] }))
    await mountIn(SbomComponents, { props: { scanId: ID } })
    await settle()
    const text = bodyText()
    expect(text).toContain('3 composant(s), 3 écosystème(s).')
    expect(text).toContain('3 composant(s) sans purl utilisable ignoré(s)')
    expect(text).toContain('minimist')
    expect(text).toContain('pkg:npm/minimist@1.2.8')
    expect(text).toContain('MIT')
    expect(text).toContain('non déclarée')
    expect(text).toContain('directe')
    expect(text).toContain('transitive')
    expect(text).toContain('inconnu')
    expect(document.body.querySelector(`a[href="${PATH}/export"]`)).not.toBeNull()
    const link = document.body.querySelector<HTMLAnchorElement>('[data-testid="sbom-dtrack"]')!
    expect(link.getAttribute('href')).toBe(`https://dtrack.analyse.exemple.test/projects/${DTRACK}`)
    expect(link.getAttribute('rel')).toContain('noopener')
    // Décision de licence (F8) pour le composant connu de la politique, licences brutes pour les autres.
    expect(document.body.querySelectorAll('[data-testid="license-allowed"]')).toHaveLength(1)
    expect(text).toContain('Autorisée')
    expect(callsTo('GET', PATH)[0]!.query).toMatchObject({ page: '1', per_page: '50', sort: 'name', order: 'asc' })
  })

  it('filtres et ordre envoyés au serveur, après une courte attente', async () => {
    route('GET', PATH, () => page())
    await mountIn(SbomComponents, { props: { scanId: ID } })
    await settle()
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] })
    const input = document.body.querySelector<HTMLInputElement>('input[data-testid="sbom-search"], [data-testid="sbom-search"] input')!
    input.value = 'mini'
    input.dispatchEvent(new Event('input', { bubbles: true }))
    await click(document.body.querySelector('[data-testid="sbom-order"]')!)
    await vi.advanceTimersByTimeAsync(300)
    vi.useRealTimers()
    await settle()
    const last = callsTo('GET', PATH).at(-1)!
    expect(last.query).toMatchObject({ q: 'mini', order: 'desc', page: '1' })
  })

  it('pagination au-delà de 50 composants', async () => {
    route('GET', PATH, event => page({ matched: 120, total: 120, page: Number((event as unknown as { node: { req: { url: string } } }).node.req.url.match(/page=(\d+)/)?.[1] ?? 1) }))
    await mountIn(SbomComponents, { props: { scanId: ID } })
    await settle()
    const next = [...document.body.querySelectorAll('button')].find(b => b.textContent?.trim() === '2')
    expect(next).toBeTruthy()
    await click(next!)
    await settle()
    expect(callsTo('GET', PATH).at(-1)!.query).toMatchObject({ page: '2' })
  })

  it('sans SBOM : message, ni export ni lien ; Dependency-Track sans interface accessible', async () => {
    route('GET', PATH, () => page({ total: 0, matched: 0, components: [], ecosystems: [], licenses: [], coverage: null, dtrack: null }))
    await mountIn(SbomComponents, { props: { scanId: ID } })
    await settle()
    expect(bodyText()).toContain('Aucun SBOM dans cette analyse')
    expect(document.body.querySelector('[data-testid="sbom-export"]')).toBeNull()
    expect(document.body.querySelector('[data-testid="sbom-dtrack"]')).toBeNull()
    resetApi()
    clearBody()
    route('GET', PATH, () => page({ dtrack: { project: DTRACK, url: null }, coverage: { direct_known: false } }))
    await mountIn(SbomComponents, { props: { scanId: ID } })
    await settle()
    expect(bodyText()).toContain('dont l’interface n’est pas accessible')
    expect(bodyText()).toContain('ne dit pas quelles dépendances sont directes')
    expect(document.body.querySelector('[data-testid="sbom-dtrack"]')).toBeNull()
  })

  it('indicateur d’attente, erreur de l’API, anglais', async () => {
    let release: () => void = () => {}
    route('GET', PATH, () => new Promise((resolve) => {
      release = () => resolve(page())
    }))
    await mountIn(SbomComponents, { props: { scanId: ID } })
    await settle()
    expect(document.body.querySelector('[data-testid="sbom-loading"]')).not.toBeNull()
    release()
    await settle()
    await setLocale('en')
    await settle()
    expect(bodyText()).toContain('3 component(s), 3 ecosystem(s).')
    expect(bodyText()).toContain('Open in Dependency-Track')
    resetApi()
    clearBody()
    route('GET', PATH, () => apiFail(404, 'E_SCAN_NOT_FOUND'))
    await mountIn(SbomComponents, { props: { scanId: ID } })
    await settle()
    expect(document.body.querySelector('[data-testid="sbom-empty"]')).toBeNull()
    expect(document.body.querySelector('[role="alert"], .text-error, [data-slot="title"]')).not.toBeNull()
  })
})
