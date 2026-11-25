// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Détail d'une analyse (0.6, chantier C) : miroir Git local (V2), sources en
// mémoire (V9) et exclusions communes (G15) affichés avec la couverture.

import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { enableAutoUnmount } from '@vue/test-utils'
import { bodyText, clearBody, mountIn, resetApi, route, setLocale, settle, setUser } from './helpers'
import ScanPage from '~/pages/scans/[id].vue'
import type { ScanDetail } from '~/composables/useScans'

enableAutoUnmount(afterEach)
beforeEach(async () => {
  await setLocale('fr')
})
afterEach(() => {
  resetApi()
  clearBody()
})

const ID = '3f1c2a9e-7b4d-4e2a-9c1f-0a1b2c3d4e5f'

function detail(coverage: ScanDetail['coverage']): ScanDetail {
  return {
    id: ID, project_id: 'p1', project_name: 'Boutique', project_slug: 'boutique', number: 7, trigger: 'schedule',
    priority: 10, effective_priority: 10, ref: 'main', commit_sha: 'c'.repeat(40), profile: 'rapide', status: 'done', verdict: 'passed',
    attempt: 1, error: null, replay_of: null, queued_at: '2026-11-24T08:00:00Z', started_at: '2026-11-24T08:01:00Z', finished_at: '2026-11-24T08:02:00Z',
    gate: 'defaut', plan: null, coverage, verdict_details: null, requested_by_username: null, by_api_token: false, queue_position: null, modules: [],
  } as ScanDetail
}

describe('délais d’exécution dans le détail d’une analyse', () => {
  it('miroir, mémoire et exclusions, en français puis en anglais', async () => {
    setUser('viewer')
    route('GET', `/api/scans/${ID}`, () => detail({
      gaps: [],
      source: { files: 42, bytes: 1000, skipped: [], workdir: 'tmpfs', mirror: 'fetched' },
      excluded: [{ pattern: '**/node_modules/**', count: 120 }, { pattern: '**/*.png', count: 3 }],
    }))
    await mountIn(ScanPage, { route: `/scans/${ID}` })
    await settle()
    const notes = document.body.querySelector('[data-testid="exec-notes"]')!.textContent!
    expect(notes).toContain('seuls les nouveaux objets ont été récupérés')
    expect(notes).toContain('Sources extraites en mémoire.')
    const ex = document.body.querySelector('[data-testid="exec-excluded"]')!.textContent!
    expect(ex).toContain('Exclusions communes, non analysées')
    expect(ex).toContain('**/node_modules/** : 120 fichier(s)')
    expect(ex).toContain('**/*.png : 3 fichier(s)')
    await setLocale('en')
    await settle()
    expect(bodyText()).toContain('Sources extracted in memory.')
  })

  it('analyse antérieure à la 0.6 : rien de plus', async () => {
    setUser('viewer')
    route('GET', `/api/scans/${ID}`, () => detail({ gaps: [], source: { files: 1, bytes: 1, skipped: [] } }))
    await mountIn(ScanPage, { route: `/scans/${ID}` })
    await settle()
    expect(document.body.querySelector('[data-testid="exec-notes"]')).toBeNull()
    expect(document.body.querySelector('[data-testid="exec-excluded"]')).toBeNull()
  })

  it('commit déjà présent dans le miroir, sources sur disque', async () => {
    setUser('viewer')
    route('GET', `/api/scans/${ID}`, () => detail({ gaps: [], source: { files: 1, bytes: 1, skipped: [], workdir: 'disk', mirror: 'hit' } }))
    await mountIn(ScanPage, { route: `/scans/${ID}` })
    await settle()
    const notes = document.body.querySelector('[data-testid="exec-notes"]')!.textContent!
    expect(notes).toContain('la forge n’a pas été contactée')
    expect(notes).toContain('Sources extraites sur disque.')
  })
})
