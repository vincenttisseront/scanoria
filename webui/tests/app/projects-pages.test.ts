// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Pages Projets et Forges (chantier A) : liste, assistant d'ajout (forge avec
// aperçu F1, URL Git avec clés d'hôte confirmées, archive), détail (réglages,
// archivage, suppression confirmée par le slug), forges (ajout vérifié,
// découverte, jeton, retrait). API simulée.

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { enableAutoUnmount } from '@vue/test-utils'
import { mockNuxtImport } from '@nuxt/test-utils/runtime'
import { apiFail, bodyText, button, callsTo, clearBody, click, mountIn, resetApi, route, setLocale, settle, setUser } from './helpers'
import ProjectsPage from '~/pages/projects/index.vue'
import NewProjectPage from '~/pages/projects/new.vue'
import ProjectPage from '~/pages/projects/[id].vue'
import ForgesPage from '~/pages/projects/forges.vue'
import type { Forge, Project, ProjectDetection } from '~/composables/useProjects'

const { toastAdd, navigate } = vi.hoisted(() => ({ toastAdd: vi.fn(), navigate: vi.fn() }))
mockNuxtImport('useToast', () => () => ({ add: toastAdd }))
mockNuxtImport('navigateTo', () => navigate)

enableAutoUnmount(afterEach)
beforeEach(async () => {
  await setLocale('fr')
  toastAdd.mockReset()
  navigate.mockReset()
})
afterEach(() => {
  resetApi()
  clearBody()
})

const ID = '11111111-1111-4111-8111-111111111111'
const FORGE_ID = '22222222-2222-4222-8222-222222222222'

const DETECTION: ProjectDetection = {
  version: 1, analyzed_at: '2026-11-24T10:00:00Z', ref: 'main', commit: 'a'.repeat(40), truncated: true, files: 12,
  languages: ['typescript', 'python'], language_files: { typescript: 8, python: 2 },
  package_managers: [{ name: 'npm', manifest: 'package.json', lockfile: 'package-lock.json' }, { name: 'pip', manifest: 'requirements.txt', lockfile: null }],
  missing_lockfiles: ['requirements.txt'], containers: ['Dockerfile'], iac: { terraform: true, kubernetes: false, helm: false, ansible: false },
  ci: [{ kind: 'forgejo-actions', path: '.forgejo/workflows/ci.yml' }], shell_scripts: 0, license: { spdx: 'MIT', source: 'LICENSE' },
  categories: ['secrets', 'sca', 'iac'], profile: 'complet', pr_profile: 'rapide',
  modules: [
    { id: 'gitleaks', name: 'gitleaks', categories: ['secrets'], installed: true, enabled: true, reason: 'always' },
    { id: 'trivy', name: 'Trivy', categories: ['sca'], installed: true, enabled: false, reason: 'category' },
    { id: 'checkov', name: 'Checkov', categories: ['iac'], installed: false, enabled: false, reason: 'iac' },
    { id: 'osv-scanner', name: 'OSV-Scanner', categories: ['sca'], installed: false, enabled: false, reason: 'lockfiles' },
  ],
  coverage_gaps: ['licenses'],
}

function project(patch: Partial<Project> = {}): Project {
  return {
    id: ID, slug: 'equipe-app', name: 'equipe/app', source_kind: 'git', forge_id: FORGE_ID, forge_name: 'Forge', forge_kind: 'forgejo',
    repo_full_name: 'equipe/app', repo_url: 'https://forge.exemple.test/equipe/app.git', has_credential: true, credential_hint: '…ab12',
    credential_kind: 'token', ssh_known_hosts: null, upload_id: null, default_branch: 'main', tracked_branches: ['main'],
    schedule: 'on-commit', profile_id: 'p1', profile_slug: 'complet', gate_id: 'g1', gate_slug: 'defaut', spdx_license: 'MIT',
    ai_opt_out: false, detection: DETECTION, last_commit: 'b'.repeat(40), last_polled_at: '2026-11-24T10:00:00Z',
    created_at: '2026-11-24T09:00:00Z', archived_at: null, last_scan: { id: 's1', number: 3, status: 'done', verdict: 'passed', queued_at: '2026-11-24T10:01:00Z' },
    ...patch,
  }
}

function forge(patch: Partial<Forge> = {}): Forge {
  return {
    id: FORGE_ID, kind: 'forgejo', name: 'Forge', base_url: 'https://forge.exemple.test', discovery: true, has_token: true,
    token_hint: '…ab12', token_user: 'robot', last_discovery_at: '2026-11-24T09:30:00Z', last_error: null, created_at: '2026-11-24T09:00:00Z',
    projects: 3, ...patch,
  }
}

describe('liste des projets', () => {
  it('affiche, filtre, bascule vers les archivés ; erreur de chargement', async () => {
    setUser('operator')
    route('GET', '/api/projects', event => ({
      items: new URL(event.path, 'http://x').searchParams.get('archived')
        ? []
        : [project(), project({ id: 'x2', name: 'Livraison', slug: 'livraison', source_kind: 'archive', forge_name: null, repo_url: null, repo_full_name: null, ai_opt_out: true, last_scan: null, detection: null, schedule: 'daily' })],
    }))
    const w = await mountIn(ProjectsPage)
    await settle()
    expect(w.findAll('tbody tr')).toHaveLength(2)
    expect(bodyText()).toContain('Forge · equipe/app')
    expect(bodyText()).toContain('typescript, python')
    expect(bodyText()).toContain('#3 · passed')
    expect(bodyText()).toContain('Archive téléversée')
    expect(bodyText()).toContain('aucun envoi à l’IA')
    expect(bodyText()).toContain('pas encore analysé')
    expect(bodyText()).toContain('Ajouter un projet')
    const vm = w.vm as unknown as { filter: string, archived: boolean }
    vm.filter = 'livr'
    await settle()
    expect(w.findAll('tbody tr')).toHaveLength(1)
    vm.archived = true
    await settle()
    expect(bodyText()).toContain('Aucun projet archivé.')
    expect(callsTo('GET', '/api/projects').at(-1)!.query).toEqual({ archived: '1' })
  })

  it('lecteur : pas de bouton d’ajout ; liste vide ; erreur', async () => {
    setUser('viewer')
    route('GET', '/api/projects', () => ({ items: [] }))
    await mountIn(ProjectsPage)
    await settle()
    expect(bodyText()).not.toContain('Ajouter un projet')
    expect(bodyText()).toContain('Aucun projet pour l’instant')
    resetApi()
    route('GET', '/api/projects', () => apiFail(500, 'E_INTERNAL'))
    clearBody()
    await mountIn(ProjectsPage)
    await settle()
    expect(bodyText()).toMatch(/erreur|Erreur/)
  })
})

describe('assistant d’ajout', () => {
  it('depuis une forge : dépôts, aperçu de la détection, ajout puis redirection', async () => {
    setUser('admin')
    route('GET', '/api/forges', () => ({ items: [forge(), forge({ id: 'gl', kind: 'gitlab', name: 'GL' })] }))
    route('GET', `/api/forges/${FORGE_ID}/repos`, () => ({
      items: [
        { full_name: 'equipe/app', description: null, private: true, archived: false, empty: false, default_branch: 'main', project_id: null },
        { full_name: 'equipe/deja', description: null, private: false, archived: false, empty: false, default_branch: 'main', project_id: 'p9' },
      ],
    }))
    route('POST', '/api/projects/preview', () => ({ repo: {}, branches: ['main'], detection: DETECTION }))
    route('POST', '/api/projects', () => ({ project: project() }))
    const w = await mountIn(NewProjectPage)
    await settle()
    expect(bodyText()).toContain('equipe/app')
    expect(bodyText()).toContain('déjà un projet')
    expect(bodyText()).toContain('privé')
    await click(button('Choisir'))
    expect(callsTo('POST', '/api/projects/preview')[0]!.body).toEqual({ forge_id: FORGE_ID, repo: 'equipe/app' })
    const text = bodyText()
    expect(text).toContain('Aperçu de equipe/app')
    expect(text).toContain('typescript (8), python (2)')
    expect(text).toContain('pas de fichier de verrouillage')
    expect(text).toContain('MIT (LICENSE)')
    expect(text).toContain('dépôt très grand : détection partielle')
    expect(text).toContain('Aucun module du catalogue ne couvre')
    expect(text).toContain('« complet » pour les analyses planifiées')
    expect(text).toContain('fichiers d’infrastructure présents · non installé')
    expect(text).toContain('Installer les 2 modules manquants')
    const vm = w.vm as unknown as { repoFilter: string }
    vm.repoFilter = 'zzz'
    await settle()
    expect(bodyText()).toContain('Aucun dépôt.')
    await click(button('Ajouter le projet'))
    expect(callsTo('POST', '/api/projects')[0]!.body).toEqual({ source: 'forge', forge_id: FORGE_ID, repo: 'equipe/app' })
    expect(navigate).toHaveBeenCalledWith(`/projects/${ID}`)
  })

  it('URL SSH : clés d’hôte relevées, confirmation exigée ; erreur traduite', async () => {
    setUser('operator')
    route('GET', '/api/forges', () => ({ items: [] }))
    route('POST', '/api/projects/ssh-hostkeys', () => ({
      host: 'git.exemple.test', keys: [{ type: 'ssh-ed25519', fingerprint: 'SHA256:abc', line: 'x' }], known_hosts: 'git.exemple.test ssh-ed25519 QUJD',
    }))
    route('POST', '/api/projects', () => apiFail(409, 'E_PROJECT_EXISTS'))
    const w = await mountIn(NewProjectPage)
    await settle()
    const vm = w.vm as unknown as { mode: string, git: { url: string, privateKey: string, auth: string }, keysConfirmed: boolean, canAddGit: boolean }
    expect(vm.mode).toBe('git')
    await click(button('Depuis une forge'))
    expect(bodyText()).toContain('Aucune forge connectée')
    await click(button('Par une URL Git'))
    vm.git.url = 'git@git.exemple.test:equipe/depot.git'
    await settle()
    expect(vm.git.auth).toBe('ssh-key')
    vm.git.privateKey = 'cle-de-test\r\n'
    await settle()
    expect(vm.canAddGit).toBe(false)
    await click(button('Relever les clés d’hôte'))
    expect(bodyText()).toContain('ssh-ed25519 SHA256:abc')
    vm.keysConfirmed = true
    await settle()
    expect(vm.canAddGit).toBe(true)
    await click(button('Ajouter le projet'))
    expect(callsTo('POST', '/api/projects')[0]!.body).toEqual({
      source: 'git', url: 'git@git.exemple.test:equipe/depot.git',
      auth: { kind: 'ssh-key', private_key: 'cle-de-test\n', known_hosts: 'git.exemple.test ssh-ed25519 QUJD' },
    })
    expect(bodyText()).toContain('Ce dépôt est déjà un projet.')
    vm.git.url = 'https://git.exemple.test/a/b.git'
    await settle()
    expect(vm.git.auth).toBe('none')
  })

  it('URL HTTPS avec jeton, puis archive téléversée', async () => {
    setUser('operator')
    route('GET', '/api/forges', () => ({ items: [] }))
    route('POST', '/api/projects', () => ({ project: project() }))
    route('PUT', '/api/projects/uploads', () => ({ upload_id: '33333333-3333-4333-8333-333333333333', format: 'zip', size: 4 }))
    const w = await mountIn(NewProjectPage)
    await settle()
    const vm = w.vm as unknown as {
      setMode: (m: string) => void
      git: { url: string, auth: string, token: string, username: string, branch: string }
      onFile: (e: Event) => void
      archiveName: string
      addArchive: () => Promise<void>
    }
    Object.assign(vm.git, { url: 'https://git.exemple.test/a/b.git', auth: 'token', token: 'jeton-de-test', username: 'robot', branch: 'develop' })
    await settle()
    await click(button('Ajouter le projet'))
    expect(callsTo('POST', '/api/projects')[0]!.body).toEqual({
      source: 'git', url: 'https://git.exemple.test/a/b.git', auth: { kind: 'token', token: 'jeton-de-test', username: 'robot' }, default_branch: 'develop',
    })
    vm.setMode('archive')
    await settle()
    const file = new File([new Uint8Array([0x50, 0x4b, 3, 4])], 'livraison.zip')
    vm.onFile({ target: { files: [file] } } as unknown as Event)
    await settle()
    expect(vm.archiveName).toBe('livraison')
    await vm.addArchive()
    await settle()
    expect(callsTo('PUT', '/api/projects/uploads')).toHaveLength(1)
    expect(callsTo('POST', '/api/projects')[1]!.body).toEqual({ source: 'archive', upload_id: '33333333-3333-4333-8333-333333333333', name: 'livraison' })
  })
})

describe('détail d’un projet', () => {
  function detail(p: Project = project()) {
    return {
      project: p,
      choices: { profiles: [{ id: 'p1', slug: 'complet' }, { id: 'p2', slug: 'rapide' }], gates: [{ id: 'g1', slug: 'defaut' }] },
      schedule: { daily_time_utc: '03:17', last_daily_slot: '2026-11-24T03:17:00Z', poll_interval_s: 300 },
    }
  }

  it('affiche ce qui a été décidé et pourquoi ; enregistre ; relance la détection ; archive', async () => {
    setUser('operator')
    route('GET', `/api/projects/${ID}`, () => detail())
    route('PATCH', `/api/projects/${ID}`, () => ({ project: project({ schedule: 'daily', tracked_branches: ['main', 'dev'] }) }))
    route('POST', `/api/projects/${ID}/detect`, () => ({ project: project({ detection: { version: 1, analyzed_at: '2026-11-24T10:00:00Z', error: 'E_FORGE_AUTH' } }) }))
    route('POST', `/api/projects/${ID}/archive`, () => ({ project: project({ archived_at: '2026-11-24T11:00:00Z' }) }))
    const w = await mountIn(ProjectPage, { route: `/projects/${ID}` })
    await settle()
    expect(bodyText()).toContain('La forge est interrogée toutes les 5 minutes')
    expect(bodyText()).toContain('Jeton …ab12')
    expect(bodyText()).toContain('bbbbbbbbbbbb')
    const vm = w.vm as unknown as { form: { branches: string, schedule: string, ai_opt_out: boolean } }
    vm.form.branches = 'main, dev'
    vm.form.schedule = 'daily'
    vm.form.ai_opt_out = true
    await click(button('Enregistrer'))
    expect(callsTo('PATCH', `/api/projects/${ID}`)[0]!.body).toMatchObject({ schedule: 'daily', tracked_branches: ['main', 'dev'], ai_opt_out: true })
    expect(bodyText()).toContain('Une analyse par jour et par branche suivie, vers 03:17 UTC')
    await click(button('Relancer la détection'))
    expect(bodyText()).toContain('La forge refuse l’accès')
    await click(button('Archiver'))
    expect(callsTo('POST', `/api/projects/${ID}/archive`)[0]!.body).toEqual({ archived: true })
    expect(bodyText()).toContain('Projet archivé le')
    expect(bodyText()).toContain('Réactiver')
  })

  it('suppression : modale de la console, slug à saisir, redirection ; archive et SSH affichés', async () => {
    setUser('admin')
    route('GET', `/api/projects/${ID}`, () => detail(project({
      schedule: 'none', source_kind: 'git', forge_id: null, forge_name: null, repo_full_name: null, repo_url: 'ssh://git@git.exemple.test/a/b.git',
      credential_kind: 'ssh-key', ssh_known_hosts: 'git.exemple.test ssh-ed25519 QUJD', last_scan: null,
    })))
    route('DELETE', `/api/projects/${ID}`, () => ({ deleted: true }))
    const w = await mountIn(ProjectPage, { route: `/projects/${ID}` })
    await settle()
    expect(bodyText()).toContain('Aucune analyse automatique')
    expect(bodyText()).toContain('git.exemple.test ssh-ed25519 QUJD')
    await click(button('Supprimer définitivement'))
    expect(bodyText()).toContain('Saisissez equipe-app pour confirmer')
    const vm = w.vm as unknown as { deleteConfirm: string, remove: () => Promise<void> }
    vm.deleteConfirm = 'autre'
    await vm.remove()
    expect(callsTo('DELETE', `/api/projects/${ID}`)).toHaveLength(0)
    vm.deleteConfirm = 'equipe-app'
    await vm.remove()
    await settle()
    expect(calls()).toBeTruthy()
    expect(navigate).toHaveBeenCalledWith('/projects')
  })

  it('projet archive ; erreur de chargement', async () => {
    setUser('viewer')
    route('GET', `/api/projects/${ID}`, () => detail(project({ source_kind: 'archive', forge_name: null, repo_url: null, detection: null, schedule: 'daily', has_credential: false })))
    await mountIn(ProjectPage, { route: `/projects/${ID}` })
    await settle()
    expect(bodyText()).toContain('Une archive est analysée telle quelle')
    expect(bodyText()).toContain('aucun (dépôt public)')
    expect(bodyText()).not.toContain('Archiver')
    resetApi()
    clearBody()
    route('GET', `/api/projects/${ID}`, () => apiFail(404, 'E_NOT_FOUND'))
    await mountIn(ProjectPage, { route: `/projects/${ID}` })
    await settle()
    expect(bodyText()).not.toContain('Réglages')
  })
})

describe('forges', () => {
  it('ajout vérifié, découverte, modification du jeton, retrait confirmé', async () => {
    setUser('admin')
    let items = [forge({ last_error: 'E_FORGE_RATE_LIMITED' })]
    route('GET', '/api/forges', () => ({ items }))
    route('POST', '/api/forges', (_e, body) => {
      items = [...items, forge({ id: 'f2', name: (body as { name: string }).name, kind: 'github' })]
      return { forge: items[1], login: 'robot', discovery_started: true }
    })
    route('POST', `/api/forges/${FORGE_ID}/discover`, () => ({ repos: 4, created: ['a'], error: null }))
    route('PATCH', `/api/forges/${FORGE_ID}`, () => ({ forge: forge() }))
    route('DELETE', `/api/forges/${FORGE_ID}`, () => apiFail(409, 'E_FORGE_IN_USE'))
    const w = await mountIn(ForgesPage)
    await settle()
    expect(bodyText()).toContain('Jeton enregistré …ab12, compte robot')
    expect(bodyText()).toContain('La forge limite le nombre de requêtes')
    expect(bodyText()).toContain('3 projet(s)')

    const vm = w.vm as unknown as { form: { kind: string, name: string, base_url: string, token: string } }
    vm.form.kind = 'github'
    await settle()
    expect(vm.form.base_url).toBe('https://github.com')
    vm.form.name = 'GitHub'
    vm.form.token = 'jeton-de-test'
    await settle()
    await click(button('Vérifier et connecter'))
    expect(callsTo('POST', '/api/forges')[0]!.body).toEqual({ kind: 'github', name: 'GitHub', base_url: 'https://github.com', discovery: true, token: 'jeton-de-test' })
    expect(toastAdd).toHaveBeenCalledWith(expect.objectContaining({ title: 'Forge GitHub connectée.', description: 'Découverte des dépôts en cours.' }))
    expect(vm.form.token).toBe('')

    await (w.vm as unknown as { discover: (f: Forge) => Promise<void> }).discover(forge())
    await settle()
    expect(toastAdd).toHaveBeenCalledWith(expect.objectContaining({ title: '4 dépôts lus, 1 nouveaux projets.' }))

    const edit = w.vm as unknown as { openEdit: (f: Forge) => void, editRemove: boolean, saveEdit: () => Promise<void> }
    edit.openEdit(forge())
    await settle()
    edit.editRemove = true
    await edit.saveEdit()
    await settle()
    expect(callsTo('PATCH', `/api/forges/${FORGE_ID}`)[0]!.body).toEqual({ discovery: true, token: null })

    const del = w.vm as unknown as { askRemove: (f: Forge) => void, confirmRemove: () => Promise<void> }
    del.askRemove(forge())
    await settle()
    expect(bodyText()).toContain('Retirer la forge Forge ?')
    await del.confirmRemove()
    await settle()
    expect(toastAdd).toHaveBeenCalledWith(expect.objectContaining({ title: 'Des projets utilisent encore cette forge : archivez-les ou supprimez-les d’abord.' }))
  })

  it('lecteur : pas de formulaire ; liste vide ; ajout refusé affiché', async () => {
    setUser('viewer')
    route('GET', '/api/forges', () => ({ items: [] }))
    await mountIn(ForgesPage)
    await settle()
    expect(bodyText()).toContain('Aucune forge connectée.')
    expect(bodyText()).not.toContain('Connecter une forge')
    resetApi()
    clearBody()
    setUser('admin')
    route('GET', '/api/forges', () => ({ items: [] }))
    route('POST', '/api/forges', () => apiFail(422, 'E_FORGE_AUTH'))
    const w = await mountIn(ForgesPage)
    await settle()
    const vm = w.vm as unknown as { form: { name: string, base_url: string }, add: () => Promise<void> }
    vm.form.name = 'F'
    vm.form.base_url = 'https://forge.exemple.test'
    await vm.add()
    await settle()
    expect(bodyText()).toContain('La forge refuse l’accès')
  })
})

function calls() {
  return callsTo('DELETE', `/api/projects/${ID}`)
}
