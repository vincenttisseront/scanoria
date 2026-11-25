// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// G6 et F13 (0.6, chantier B), sans base : versions figées appliquées au plan
// (contrat 24), disponibilité des versions retenues, avertissements, plan
// d'essai (contrat 25), lecture sans confiance de l'état publié par le helper.

import { mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { applyPins, pinWarnings, retainedAvailable } from '../../server/vigilance/pins'
import { trialPlan } from '../../server/vigilance/trials'
import { replayAvailability, type PlannedModule, type ScanPlan } from '../../server/scans/plan'
import { readVigilanceState } from '../../server/vigilance/state'
import { purlOf, updateFor } from '../../server/vigilance/selfvulns'
import type { CatalogIndex, InstalledModule } from '../../server/utils/catalog'

const D1 = `sha256:${'1'.repeat(64)}`
const D2 = `sha256:${'2'.repeat(64)}`
const D3 = `sha256:${'3'.repeat(64)}`

const mod = (over: Partial<PlannedModule> = {}): PlannedModule => ({
  id: 'gitleaks', version: '8.30.1', image: `ghcr.io/exemple/gitleaks@${D2}`, image_digest: D2, categories: ['secrets'],
  options: {}, feeds: [], timeout_s: 300, history: 'full', outputs: ['sarif'], reason: 'category', ...over,
})
const inst = (version: string, over: Record<string, unknown> = {}) =>
  ({ id: 'gitleaks', version, type: 'scanner', status: 'healthy', enabled: true, installed_at: '2026-11-24T00:00:00Z', options: {}, ...over }) as unknown as InstalledModule
const index = (versions: string[]) => ({ schema: 1, version: 1, modules: versions.map(v => ({ id: 'gitleaks', version: v })) }) as unknown as CatalogIndex
const plan = (modules: PlannedModule[]): ScanPlan => ({
  schema: 1, created_at: '2026-11-24T00:00:00Z', source: { kind: 'git', ref: 'main', commit: null, history: 'full' },
  profile: { id: '00000000-0000-4000-8000-000000000000', slug: 'rapide' }, gate: { id: '00000000-0000-4000-8000-000000000001', slug: 'defaut', rules: {} },
  modules, gaps: [], timeout_s: 300,
} as unknown as ScanPlan)

describe('pin-apply : versions figées dans le plan (contrat 24)', () => {
  it('remplace version, empreinte et image ; marque « pin »', () => {
    const [m] = applyPins([mod()], new Map([['gitleaks', { version: '8.30.0', image_digest: D1 }]]))
    expect(m).toMatchObject({ version: '8.30.0', image_digest: D1, image: `ghcr.io/exemple/gitleaks@${D1}`, alternate: 'pin' })
  })
  it('empreinte égale à celle du catalogue : rien ne change', () => {
    const [m] = applyPins([mod()], new Map([['gitleaks', { version: '8.30.1', image_digest: D2 }]]))
    expect(m!.alternate).toBeUndefined()
  })
  it('empreinte invalide ou module non figé : ignorés', () => {
    expect(applyPins([mod()], new Map([['gitleaks', { version: '8.30.0', image_digest: 'sha256:court' }]]))[0]!.alternate).toBeUndefined()
    expect(applyPins([mod()], new Map([['trivy', { version: '1', image_digest: D1 }]]))[0]!.alternate).toBeUndefined()
  })
  it('module sans image : version figée, image null', () => {
    expect(applyPins([mod({ image: null })], new Map([['gitleaks', { version: '8.30.0', image_digest: D1 }]]))[0]!.image).toBeNull()
  })
})

describe('pin-retained : disponibilité des versions retenues', () => {
  const retained = [{ module: 'gitleaks', version: '8.30.0', image_digest: D1, kind: 'pin' as const }]
  it('retenue si module, version et empreinte concordent', () => {
    expect(retainedAvailable({ id: 'gitleaks', version: '8.30.0', image_digest: D1 }, retained)).toBe(true)
    expect(retainedAvailable({ id: 'gitleaks', version: '8.30.0', image_digest: D3 }, retained)).toBe(false)
    expect(retainedAvailable({ id: 'trivy', version: '8.30.0', image_digest: D1 }, retained)).toBe(false)
  })
  it('état illisible : le runner tranche (disponible ici)', () => {
    expect(retainedAvailable({ id: 'gitleaks', version: '9', image_digest: D3 }, null)).toBe(true)
    expect(retainedAvailable({ id: 'gitleaks', version: '9', image_digest: D3 }, undefined)).toBe(true)
  })
  it('replayAvailability : version figée retenue disponible, absente « missing »', () => {
    const p = plan([mod({ version: '8.30.0', image_digest: D1, alternate: 'pin' })])
    expect(replayAvailability(p, [inst('8.30.1')], retained).available).toHaveLength(1)
    expect(replayAvailability(p, [inst('8.30.1')], []).missing).toHaveLength(1)
    expect(replayAvailability(p, [inst('8.30.1', { enabled: false })], retained).missing).toHaveLength(1)
    // Sans alternative, une autre version que l'installée reste indisponible (G11).
    expect(replayAvailability(plan([mod({ version: '8.30.0', image_digest: D1 })]), [inst('8.30.1')], retained).missing).toHaveLength(1)
  })
})

describe('pin-warnings : avertissements d’une version figée', () => {
  const pin = { module_id: 'gitleaks', version: '8.30.0', image_digest: D1 }
  it('retirée du catalogue, vulnérable, absente', () => {
    expect(pinWarnings(pin, { index: index(['8.30.1']), installed: [inst('8.30.1')], retained: [], vulnerable: new Set(['gitleaks']) }))
      .toEqual(['retired', 'vulnerable', 'missing'])
  })
  it('version installée : aucun avertissement', () => {
    expect(pinWarnings(pin, { index: index(['8.30.0', '8.30.1']), installed: [inst('8.30.0')], retained: [], vulnerable: new Set() })).toEqual([])
  })
  it('module désinstallé : absente ; index illisible : pas « retirée »', () => {
    expect(pinWarnings(pin, { index: null, installed: [], retained: null, vulnerable: new Set() })).toEqual(['missing'])
  })
})

describe('trial-plan : plan d’essai (contrat 25)', () => {
  it('réduit au module, candidate par empreinte, sans trou de couverture', () => {
    const orig = plan([mod({ version: '8.30.0', image_digest: D1, image: `ghcr.io/exemple/gitleaks@${D1}` }), mod({ id: 'trivy' })])
    const t = trialPlan({ ...orig, gaps: [{ kind: 'profile-category', category: 'sast', module: null, reason: 'no-module' }] } as unknown as ScanPlan, 'gitleaks', '8.30.1', D2)!
    expect(t.modules).toEqual([expect.objectContaining({ id: 'gitleaks', version: '8.30.1', image_digest: D2, image: `ghcr.io/exemple/gitleaks@${D2}`, alternate: 'trial' })])
    expect(t.gaps).toEqual([])
    expect(t.timeout_s).toBe(300)
  })
  it('module absent du plan d’origine : null', () => {
    expect(trialPlan(plan([mod({ id: 'trivy' })]), 'gitleaks', '8.30.1', D2)).toBeNull()
  })
})

describe('selfvuln-state : état publié par le helper, lu sans confiance', () => {
  let dir: string
  beforeAll(async () => {
    dir = await mkdtemp(join(tmpdir(), 'scanoria-vig-'))
  })
  afterAll(async () => {
    await rm(dir, { recursive: true, force: true })
  })
  it('absent ou illisible : indisponible', async () => {
    expect((await readVigilanceState(join(dir, 'absent.json'))).available).toBe(false)
    await writeFile(join(dir, 'bad.json'), '{')
    expect(await readVigilanceState(join(dir, 'bad.json'))).toEqual({ available: false, updated_at: null, retained: [], self_sbom: null })
  })
  it('entrées hostiles écartées une à une', async () => {
    await writeFile(join(dir, 's.json'), JSON.stringify({ version: 1, updated_at: '2026-11-24T00:00:00Z', retained: [
      { module: 'gitleaks', version: '8.30.0', image_digest: D1, kind: 'pin' },
      { module: '../x', version: '1', image_digest: D1, kind: 'pin' },
      { module: 'gitleaks', version: '8.30.1', image_digest: 'sha256:x', kind: 'trial' },
      { module: 'gitleaks', version: '8.30.2', image_digest: D3, kind: 'autre' },
    ], self_sbom: { version: 1, at: 'hier', subjects: [], gaps: [] } }))
    const st = await readVigilanceState(join(dir, 's.json'))
    expect(st.available).toBe(true)
    expect(st.retained.map(r => r.version)).toEqual(['8.30.0'])
    expect(st.self_sbom).toBeNull()
  })
  it('purl et version corrective', () => {
    expect(purlOf({ ecosystem: 'npm', name: 'minimist', version: '1.2.5' })).toBe('pkg:npm/minimist@1.2.5')
    expect(purlOf({ ecosystem: null, name: 'libssl', version: null })).toBe('pkg:generic/libssl')
    expect(purlOf({ ecosystem: 'npm', name: ' ', version: '1' })).toBeNull()
    expect(purlOf({ ecosystem: 'Go Modules!', name: 'x', version: '1 0' })).toBe('pkg:gomodules/x@10')
    const ctx = { installed: [inst('8.30.0')], index: index(['8.29.0', '8.30.0', '8.30.1', '8.31.0']), consoleUpdate: null }
    expect(updateFor('module:gitleaks', ctx)).toBe('8.31.0')
    expect(updateFor('module:trivy', ctx)).toBeNull()
    expect(updateFor('console', { ...ctx, consoleUpdate: '0.6.1' })).toBe('0.6.1')
  })
})
