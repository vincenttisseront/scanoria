// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Profils (0.7, chantier C) : liste hiérarchique et création, détail avec
// verrous et refus explicites, aperçu (G10) avec indicateur d'attente,
// profils par déclencheur d'un projet (G9) et « aucun envoi à l'IA » imposé,
// reprise de l'existant (J5), export et import de la configuration (J8).

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { enableAutoUnmount } from '@vue/test-utils'
import { mockNuxtImport } from '@nuxt/test-utils/runtime'
import { createError } from 'h3'
import {
  apiFail, bodyText, button, callsTo, clearBody, click, mountIn, resetApi, route, setLocale, settle, setUser,
} from './helpers'
import ProfilesPage from '~/pages/profiles/index.vue'
import ProfilePage from '~/pages/profiles/[id].vue'
import ConfigPage from '~/pages/system/config.vue'
import ProjectProfiles from '~/components/profiles/ProjectProfiles.vue'
import ImportExisting from '~/components/profiles/ImportExisting.vue'
import LocksEditor from '~/components/profiles/LocksEditor.vue'
import ScanConfigNote from '~/components/profiles/ScanConfigNote.vue'
import { cloneLocks, emptyLocks, lockFieldLabel, lockValueLabel, profileErrorDetails } from '~/utils/profiles'

const { toastAdd, navigateToMock } = vi.hoisted(() => ({ toastAdd: vi.fn(), navigateToMock: vi.fn() }))
mockNuxtImport('useToast', () => () => ({ add: toastAdd }))
mockNuxtImport('navigateTo', () => navigateToMock)

enableAutoUnmount(afterEach)

async function mount(...args: Parameters<typeof mountIn>) {
  const w = await mountIn(...args)
  await settle()
  return w
}

beforeEach(async () => {
  await setLocale('fr')
  toastAdd.mockReset()
  navigateToMock.mockReset()
})
afterEach(() => {
  resetApi()
  clearBody()
})

const ENT = '11111111-1111-4111-8111-111111111111'
const TEAM = '22222222-2222-4222-8222-222222222222'
const RAPIDE = '33333333-3333-4333-8333-333333333333'
const PROJECT = '44444444-4444-4444-8444-444444444444'
const IMPORT_TOKEN = '55555555-5555-4555-8555-555555555555'

const row = (patch: Record<string, unknown> = {}) => ({
  id: ENT, slug: 'entreprise', builtin: false, level: 'enterprise', parent_id: null, parent_slug: null,
  categories: ['secrets'], include_modules: [], exclude_modules: [], description: null,
  locks: { required_categories: ['secrets'], required_modules: [], gate_floor: { max_secrets: 0 }, ai_opt_out: false },
  rulesets: [], archived_at: null, updated_at: '2026-11-25T08:00:00Z', updated_by_username: 'alice', projects: 1, children: 1, ...patch,
})
const team = row({ id: TEAM, slug: 'equipe-web', level: 'team', parent_id: ENT, parent_slug: 'entreprise', locks: emptyLocks(), projects: 0, children: 0 })
const rapide = row({ id: RAPIDE, slug: 'rapide', builtin: true, locks: emptyLocks(), children: 0 })

function input(testid: string): HTMLInputElement {
  return document.body.querySelector<HTMLInputElement>(`[data-testid="${testid}"] input, input[data-testid="${testid}"]`)!
}
async function type(testid: string, value: string) {
  const el = input(testid)
  el.value = value
  el.dispatchEvent(new Event('input'))
  await settle()
}

describe('liste des profils', () => {
  it('hiérarchie, badges, création d’un profil racine (admin)', async () => {
    setUser('admin')
    route('GET', '/api/profiles', () => ({ items: [team, rapide, row()] }))
    route('POST', '/api/profiles', () => row({ id: TEAM, slug: 'nouveau' }))
    await mount(ProfilesPage)
    const text = bodyText()
    expect(text).toContain('entreprise')
    expect(text).toContain('equipe-web')
    expect(text).toContain('intégré')
    expect(text).toContain('par alice')
    // L'enfant suit son parent.
    expect(text.indexOf('entreprise')).toBeLessThan(text.indexOf('equipe-web'))
    await click(button('Nouveau profil'))
    await type('profile-slug', 'nouveau')
    await click(button('Créer'))
    expect(callsTo('POST', '/api/profiles')[0]!.body).toEqual({ slug: 'nouveau', level: 'enterprise', parent_id: null })
    expect(navigateToMock).toHaveBeenCalledWith(`/profiles/${TEAM}`)
  })

  it('erreur de création traduite ; lecteur sans bouton ; archivés sur demande', async () => {
    setUser('admin')
    route('GET', '/api/profiles', () => ({ items: [row()] }))
    route('POST', '/api/profiles', () => apiFail(409, 'E_PROFILE_SLUG_TAKEN'))
    await mount(ProfilesPage)
    await click(button('Nouveau profil'))
    await type('profile-slug', 'entreprise')
    await click(button('Créer'))
    expect(toastAdd).toHaveBeenCalledWith(expect.objectContaining({ title: 'Cet identifiant est déjà utilisé.', color: 'error' }))
    resetApi()
    clearBody()

    setUser('viewer')
    route('GET', '/api/profiles', () => ({ items: [row({ archived_at: '2026-11-20T00:00:00Z' })] }))
    await mount(ProfilesPage)
    expect(document.body.querySelector('[data-testid="profile-create"]')).toBeNull()
    expect(bodyText()).toContain('archivé')
  })
})

describe('détail d’un profil', () => {
  const detail = (patch: Record<string, unknown> = {}) => ({
    profile: team,
    inherited_locks: row().locks,
    effective: { chain: [{ id: ENT, slug: 'entreprise', level: 'enterprise' }, { id: TEAM, slug: 'equipe-web', level: 'team' }], categories: ['secrets'], include_modules: [], exclude_modules: [], locks: row().locks },
    projects: [{ id: PROJECT, slug: 'web', name: 'Web', slots: ['default', 'pr'] }],
    ...patch,
  })

  it('héritage, verrous hérités, projets ; refus d’un verrou assoupli expliqué', async () => {
    setUser('admin')
    route('GET', `/api/profiles/${TEAM}`, () => detail())
    route('PATCH', `/api/profiles/${TEAM}`, () => {
      throw createError({ statusCode: 409, statusMessage: 'E_PROFILE_LOCKED', data: { code: 'E_PROFILE_LOCKED', violations: [{ field: 'gate_floor.max_secrets', locked: 0, requested: 3 }] } })
    })
    await mount(ProfilePage, { route: `/profiles/${TEAM}` })
    const text = bodyText()
    expect(text).toContain('Équipe')
    expect(text).toContain('Web')
    expect(text).toContain('Pull requests')
    expect(text).toContain('hérité : 0')
    // Changer la description rend la page modifiée.
    const ta = document.body.querySelector<HTMLTextAreaElement>('textarea')!
    ta.value = 'Équipe web'
    ta.dispatchEvent(new Event('input'))
    await settle()
    await click(document.body.querySelector<HTMLButtonElement>('[data-testid="profile-save"]')!)
    expect(callsTo('PATCH', `/api/profiles/${TEAM}`)[0]!.body).toMatchObject({ description: 'Équipe web' })
    expect(bodyText()).toContain('verrouillé à 0, demandé 3')
    expect(toastAdd).toHaveBeenCalledWith(expect.objectContaining({ title: 'Un verrou hérité ne peut pas être assoupli.' }))
  })

  it('aperçu : indicateur d’attente, modules, manquants avec lien vers le catalogue', async () => {
    setUser('operator')
    route('GET', `/api/profiles/${TEAM}`, () => detail())
    route('GET', '/api/projects', () => ({ items: [{ id: PROJECT, name: 'Web', slug: 'web', source_kind: 'git' }] }))
    let release: () => void = () => {}
    route('POST', '/api/profiles/preview', () => new Promise((resolve) => {
      release = () => resolve({
        effective: { chain: ['entreprise', 'equipe-web'], categories: ['secrets', 'sast'], include_modules: [], exclude_modules: [], locks: row().locks },
        modules: [{ id: 'gitleaks', version: '8.0.0', categories: ['secrets'], reason: 'category', expected_ms: 4200, measured: 'appliance', ram_mb: 256, cpu: 1 }],
        missing: [{ category: 'sast', module: null, reason: 'no-module', install: [{ id: 'opengrep', name: 'Opengrep' }] }],
        estimate: { duration_ms: 4200, unmeasured: [], peak_ram_mb: 256, peak_cpu: 1 },
        coverage: null,
        violations: [],
      })
    }))
    await mount(ProfilePage, { route: `/profiles/${TEAM}` })
    // Lecture seule pour un opérateur : pas de bouton Enregistrer.
    expect(document.body.querySelector('[data-testid="profile-save"]')).toBeNull()
    await click(document.body.querySelector<HTMLButtonElement>('[data-testid="profile-preview"]')!)
    expect(bodyText()).toContain('Calcul de l’aperçu…')
    release()
    await settle()
    await settle()
    const text = bodyText()
    expect(text).toContain('gitleaks')
    expect(text).toContain('mesuré sur l’appliance')
    expect(text).toContain('256 Mo')
    expect(document.body.querySelector('a[href="/catalog/opengrep"]')).not.toBeNull()
    expect(callsTo('POST', '/api/profiles/preview')[0]!.body).toMatchObject({ profile_id: TEAM, parent_id: ENT })
  })

  it('archivage confirmé dans une modale', async () => {
    setUser('admin')
    const solo = row({ id: TEAM, slug: 'solo', projects: 0, children: 0 })
    route('GET', `/api/profiles/${TEAM}`, () => detail({ profile: solo, projects: [], inherited_locks: emptyLocks() }))
    route('POST', `/api/profiles/${TEAM}/archive`, () => ({ ...solo, archived_at: '2026-11-25T09:00:00Z' }))
    await mount(ProfilePage, { route: `/profiles/${TEAM}` })
    await click(document.body.querySelector<HTMLButtonElement>('[data-testid="profile-archive"]')!)
    expect(bodyText()).toContain('Archiver le profil solo ?')
    const buttons = Array.from(document.body.querySelectorAll<HTMLButtonElement>('button')).filter(b => b.textContent?.trim() === 'Archiver')
    await click(buttons[buttons.length - 1]!)
    expect(callsTo('POST', `/api/profiles/${TEAM}/archive`)[0]!.body).toEqual({ archived: true })
  })
})

describe('éditeur de verrous', () => {
  it('signale une règle plus souple que le verrou hérité ; IA imposée par le parent', async () => {
    setUser('admin')
    const w = await mount(LocksEditor, {
      props: {
        modelValue: { required_categories: [], required_modules: [], gate_floor: { max_secrets: 5 }, ai_opt_out: false },
        inherited: { required_categories: ['secrets'], required_modules: ['gitleaks'], gate_floor: { max_secrets: 0 }, ai_opt_out: true },
      },
    })
    const text = bodyText()
    expect(text).toContain('plus souple que le verrou hérité')
    expect(text).toContain('Imposé par un profil parent.')
    expect(text).toContain('Hérité : gitleaks')
    w.unmount()
  })

  it('cocher, régler et décocher une règle du plancher ; chaque sens de comparaison', async () => {
    setUser('admin')
    const inherited = { required_categories: [], required_modules: [], gate_floor: { kev_blocks: true, vuln_block_from: 'high', quarantine_days: 7, new_code_only: false, epss_block_from: 0.1 }, ai_opt_out: false }
    const w = await mount(LocksEditor, { props: { modelValue: emptyLocks(), inherited } })
    type S = { toggle: (k: string, on: boolean) => void, setValue: (k: string, v: unknown) => void, looser: (k: string) => boolean, severityValue: (k: string) => string }
    const st = (w.vm as unknown as { $: { setupState: S } }).$.setupState
    const last = () => (w.emitted('update:modelValue')!.at(-1)![0] as { gate_floor: Record<string, unknown> })
    st.toggle('kev_blocks', true)
    expect(last().gate_floor.kev_blocks).toBe(true) // valeur héritée reprise
    st.toggle('max_secrets', true)
    expect(last().gate_floor.max_secrets).toBe(0) // défaut du gate
    const cases: [string, unknown, boolean][] = [
      ['kev_blocks', false, true], ['kev_blocks', true, false],
      ['vuln_block_from', 'critical', true], ['vuln_block_from', null, true], ['vuln_block_from', 'low', false],
      ['quarantine_days', 3, true], ['quarantine_days', 14, false],
      ['new_code_only', true, true], ['new_code_only', false, false],
      ['epss_block_from', 0.5, true], ['epss_block_from', null, true], ['epss_block_from', 0.05, false],
    ]
    for (const [k, v, expected] of cases) {
      await w.setProps({ modelValue: { ...emptyLocks(), gate_floor: { [k]: v } } })
      expect(st.looser(k), `${k}=${String(v)}`).toBe(expected)
    }
    await w.setProps({ modelValue: { ...emptyLocks(), gate_floor: { vuln_block_from: null } } })
    expect(st.severityValue('vuln_block_from')).toBe('__none__')
    st.setValue('vuln_block_from', 'medium')
    expect(last().gate_floor.vuln_block_from).toBe('medium')
    st.toggle('vuln_block_from', false)
    expect(last().gate_floor).not.toHaveProperty('vuln_block_from')
    expect(st.looser('sast_block_from')).toBe(false)
  })

  it('aides pures', () => {
    const t = (k: string) => ({ 'gates.fields.max_secrets': 'Secrets', 'profiles.lockFields.exclude_modules': 'Module exigé retiré', 'gates.none': 'jamais', 'common.yes': 'Oui', 'common.no': 'Non', 'gates.severities.high': 'élevée' } as Record<string, string>)[k] ?? k
    const te = (k: string) => t(k) !== k
    expect(lockFieldLabel('gate_floor.max_secrets', t, te)).toBe('Secrets')
    expect(lockFieldLabel('gate_floor.inconnu', t, te)).toBe('inconnu')
    expect(lockFieldLabel('exclude_modules', t, te)).toBe('Module exigé retiré')
    expect(lockValueLabel(null, t, te)).toBe('jamais')
    expect(lockValueLabel(true, t, te)).toBe('Oui')
    expect(lockValueLabel('high', t, te)).toBe('élevée')
    expect(lockValueLabel(3, t, te)).toBe('3')
    expect(cloneLocks(null)).toEqual(emptyLocks())
    expect(profileErrorDetails({ data: { data: { code: 'E_X', violations: [{ field: 'f', locked: 1, requested: 2 }] } } })).toEqual({ code: 'E_X', violations: [{ field: 'f', locked: 1, requested: 2 }], profile: undefined })
  })
})

describe('profils d’un projet', () => {
  const slot = (slug: string, profileId: string | null) => ({ profile_id: profileId, effective_id: RAPIDE, slug, chain: ['entreprise', slug], locks: row().locks, from_config: null })
  const view = (patch: Record<string, unknown> = {}) => ({
    slots: { default: slot('complet', ENT), pr: { ...slot('rapide', RAPIDE), from_config: 'rapide' }, nightly: slot('complet', null), release: slot('release', null) },
    ai_opt_out: true, ai_opt_out_locked: true,
    config_state: { status: 'invalid', read_at: '2026-11-25T08:00:00Z', read_key: 'a'.repeat(40), sha256: null, issues: [{ path: 'ignore.0', message: 'whole repository' }], config_key: 'b'.repeat(40), requests: { created: 2, skipped: 1 } },
    ...patch,
  })

  it('affiche l’effectif, la configuration en code et le verrou IA ; enregistre', async () => {
    setUser('operator')
    route('GET', `/api/projects/${PROJECT}/profiles`, () => view())
    route('GET', '/api/profiles', () => ({ items: [row(), rapide] }))
    route('PUT', `/api/projects/${PROJECT}/profiles`, () => apiFail(403, 'E_PROFILE_LOOSER'))
    const w = await mount(ProjectProfiles, { props: { projectId: PROJECT, canEdit: true } })
    const text = bodyText()
    expect(text).toContain('.scanoria.yml : rapide')
    expect(text).toContain('invalide')
    expect(text).toContain('whole repository')
    expect(text).toContain('2 déposées, 1 écartées.')
    expect(document.body.querySelector('[data-testid="ai-locked"]')).not.toBeNull()
    expect(w.emitted('update:aiLocked')?.[0]).toEqual([true])
    expect(document.body.querySelector('a[href*="/findings/exceptions?project_id="]')).not.toBeNull()
  })
})

describe('reprise de l’existant', () => {
  it('aperçu puis application, jeton jamais renvoyé à l’application', async () => {
    setUser('admin')
    const report = {
      outcome: { created: [], skipped: [] },
      requests: [
        { kind: 'path', target: { glob: 'tests/**', tool: 'gitleaks' }, reason: 'importé', expires_on: '2027-02-23', source: '.gitleaks.toml', status: 'new' },
        { kind: 'vuln', target: { vuln_id: 'MAL-2026-1' }, reason: 'importé', expires_on: '2027-02-23', source: 'dependency-track', status: 'malicious' },
      ],
      unsupported: [{ source: '.gitleaks.toml', entry: 'regexes: x' }],
      sources: [{ source: '.gitleaks.toml', requests: 1, unsupported: 1 }],
      import_token: IMPORT_TOKEN,
      expires_on: '2027-02-23',
    }
    route('POST', `/api/projects/${PROJECT}/imports/preview`, () => report)
    route('POST', `/api/projects/${PROJECT}/imports/apply`, () => ({ ...report, outcome: { created: [{}], skipped: [] } }))
    const w = await mount(ImportExisting, { props: { projectId: PROJECT, isGit: true, open: true } })
    await click(document.body.querySelector<HTMLButtonElement>('[data-testid="import-preview"]')!)
    const text = bodyText()
    expect(text).toContain('1 demandes nouvelles sur 2')
    expect(text).toContain('paquet malveillant, refusée')
    expect(text).toContain('1 entrées non reprises')
    expect(callsTo('POST', `/api/projects/${PROJECT}/imports/preview`)[0]!.body).toEqual({ repo: true })
    await click(document.body.querySelector<HTMLButtonElement>('[data-testid="import-apply"]')!)
    expect(callsTo('POST', `/api/projects/${PROJECT}/imports/apply`)[0]!.body).toEqual({ repo: true, import_token: IMPORT_TOKEN, expires_on: '2027-02-23' })
    expect(toastAdd).toHaveBeenCalledWith(expect.objectContaining({ title: '1 demandes déposées.' }))
    expect(w.emitted('applied')).toBeTruthy()
  })
})

describe('configuration de l’appliance', () => {
  it('réservé à l’administrateur', async () => {
    setUser('operator')
    await mount(ConfigPage)
    expect(bodyText()).toContain('Réservé aux administrateurs.')
    expect(document.body.querySelector('[data-testid="config-export"]')).toBeNull()
  })

  it('export téléchargé ; écarts puis application confirmée', async () => {
    setUser('admin')
    route('GET', '/api/config/export', () => ({ yaml: 'scanoria_config: 1\n', filename: 'scanoria-config-2026-11-25.yml' }))
    const preview = {
      digest: 'd'.repeat(64),
      changes: [{ section: 'profiles', key: 'importe', action: 'create', fields: [] }, { section: 'gates', key: 'defaut', action: 'unchanged', fields: [] }],
      issues: [],
      summary: { profiles: { create: 1, update: 0, unchanged: 0 }, gates: { create: 0, update: 0, unchanged: 1 } },
    }
    route('POST', '/api/config/import/preview', () => preview)
    route('POST', '/api/config/import/apply', () => preview)
    const orig = { create: URL.createObjectURL, revoke: URL.revokeObjectURL }
    const createUrl = vi.fn(() => 'blob:x')
    const revoke = vi.fn()
    const anchorClick = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {})
    URL.createObjectURL = createUrl
    URL.revokeObjectURL = revoke
    const w = await mount(ConfigPage)
    try {
      await click(document.body.querySelector<HTMLButtonElement>('[data-testid="config-export"]')!)
      expect(createUrl).toHaveBeenCalled()
      expect(anchorClick).toHaveBeenCalled()
      expect(revoke).toHaveBeenCalledWith('blob:x')
    }
    finally {
      URL.createObjectURL = orig.create
      URL.revokeObjectURL = orig.revoke
      anchorClick.mockRestore()
    }

    // Fichier choisi : texte lu, puis aperçu.
    const vm = w.vm as unknown as { $: { setupState: { text: string, fileName: string } } }
    vm.$.setupState.text = 'scanoria_config: 1\n'
    vm.$.setupState.fileName = 'config.yml'
    await settle()
    await click(document.body.querySelector<HTMLButtonElement>('[data-testid="config-preview"]')!)
    const text = bodyText()
    expect(text).toContain('Profils : 1 créés, 0 modifiés, 0 inchangés')
    expect(text).toContain('importe')
    expect(text).not.toContain('defaut')
    await click(document.body.querySelector<HTMLButtonElement>('[data-testid="config-apply"]')!)
    expect(bodyText()).toContain('Appliquer la configuration ?')
    const ack = document.body.querySelector<HTMLButtonElement>('[role="checkbox"]')!
    await click(ack)
    const confirm = Array.from(document.body.querySelectorAll<HTMLButtonElement>('button')).filter(b => b.textContent?.trim() === 'Appliquer')
    await click(confirm[confirm.length - 1]!)
    expect(callsTo('POST', '/api/config/import/apply')[0]!.body).toEqual({ yaml: 'scanoria_config: 1\n', digest: 'd'.repeat(64) })
  })

  it('fichier refusé : problèmes listés ; empreinte changée signalée', async () => {
    setUser('admin')
    route('POST', '/api/config/import/preview', () => {
      throw createError({ statusCode: 422, statusMessage: 'E_CONFIG_INVALID', data: { code: 'E_CONFIG_INVALID', issues: [{ path: 'profiles.0', message: 'anchors and aliases are not allowed' }] } })
    })
    const w = await mount(ConfigPage)
    const vm = w.vm as unknown as { $: { setupState: { text: string } } }
    vm.$.setupState.text = 'a: &x 1'
    await settle()
    await click(document.body.querySelector<HTMLButtonElement>('[data-testid="config-preview"]')!)
    expect(bodyText()).toContain('Fichier refusé.')
    expect(bodyText()).toContain('anchors and aliases are not allowed')
  })
})

describe('note de configuration d’une analyse', () => {
  it('profil figé, fichier invalide signalé, chemins ignorés', async () => {
    setUser('viewer')
    await mount(ScanConfigNote, {
      props: {
        profile: { slug: 'projet-web', chain: ['entreprise', 'equipe-web', 'projet-web'], slot: 'pr', source: 'config' },
        repoConfig: { status: 'invalid', key: 'a'.repeat(40), issues: [{ path: 'ignore.0', message: 'whole repository' }], ignored: ['docs/**'], profile: null },
      },
    })
    const text = bodyText()
    expect(text).toContain('entreprise › equipe-web › projet-web')
    expect(text).toContain('Pull requests')
    expect(text).toContain('demandé par .scanoria.yml')
    expect(text).toContain('.scanoria.yml invalide')
    expect(text).toContain('docs/**')
  })

  it('rien à dire : rien affiché', async () => {
    setUser('viewer')
    await mount(ScanConfigNote, { props: { profile: null, repoConfig: { status: 'absent', key: null, issues: [], ignored: [], profile: null } } })
    expect(document.body.querySelector('[data-testid="scan-config-note"]')).toBeNull()
  })
})
