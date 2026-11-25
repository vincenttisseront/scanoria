// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// J11–J13 (0.8, chantier D) : configurations de cibles hostiles, gabarits
// d'étiquette, détection d'un workflow de déploiement, refus et états de run.

import { describe, expect, it } from 'vitest'
import { fillTemplate, parseConfig, targetCreateSchema } from '../../server/deploy/config'
import { dispatchInputs } from '../../server/deploy/targets'
import { refusalOf, safeUrl } from '../../server/deploy/runs'
import { gitlabStateOf, runStateOf } from '../../server/forges/deploy'
import { authorRequestedAutoMerge } from '../../server/deploy/autonomous'

describe('deploy-config', () => {
  it('CD : workflow de forge ou Jenkins en HTTPS, rien d\'autre', () => {
    expect(parseConfig('cd-trigger', { provider: 'forge', workflow: 'deploy.yml' })).toMatchObject({ inputs: ['scanoria_report', 'scanoria_commit', 'scanoria_tag'] })
    expect(parseConfig('cd-trigger', { provider: 'jenkins', url: 'https://jenkins.exemple.test', job: 'equipe/deploy' })).not.toBeNull()
    for (const bad of [
      { provider: 'forge', workflow: '../deploy.yml' },
      { provider: 'forge', workflow: 'deploy.sh' },
      { provider: 'forge', workflow: 'deploy.yml', ref: '--upload-pack=x' },
      { provider: 'forge', workflow: 'deploy.yml', repo: '../x' },
      { provider: 'forge', workflow: 'deploy.yml', extra: 1 },
      { provider: 'forge', workflow: 'deploy.yml', inputs: ['secret'] },
      { provider: 'jenkins', url: 'http://jenkins.exemple.test', job: 'x' },
      { provider: 'jenkins', url: 'https://localhost', job: 'x' },
      { provider: 'jenkins', url: 'https://127.0.0.1', job: 'x' },
      { provider: 'jenkins', url: 'https://192.0.2.10', job: 'x' },
      { provider: 'jenkins', url: 'https://[2001:db8::1]', job: 'x' },
      { provider: 'jenkins', url: 'https://u:p@jenkins.exemple.test', job: 'x' },
      { provider: 'jenkins', url: 'https://jenkins.exemple.test', job: '../x' },
      { provider: 'ssh', host: 'prod' },
    ]) expect(parseConfig('cd-trigger', bad), JSON.stringify(bad)).toBeNull()
  })

  it('GitOps : chemins relatifs sûrs et images sans étiquette', () => {
    expect(parseConfig('gitops-pr', { repo: 'equipe/deploiement', files: [{ path: 'apps/app/kustomization.yaml', image: 'registre.exemple.test/valide/app' }] })).toMatchObject({ base: 'main' })
    for (const path of ['/etc/passwd', '../x.yaml', 'a/../../x', 'a//b', 'a\\b', 'a/\u0001', '']) {
      expect(parseConfig('gitops-pr', { repo: 'equipe/deploiement', files: [{ path, image: 'registre.exemple.test/valide/app' }] }), path).toBeNull()
    }
    for (const image of ['registre.exemple.test/app:v1', 'registre.exemple.test/app@sha256:aa', 'app', 'HTTPS://x/y']) {
      expect(parseConfig('gitops-pr', { repo: 'equipe/deploiement', files: [{ path: 'a.yaml', image }] }), image).toBeNull()
    }
    expect(parseConfig('gitops-pr', { repo: 'equipe/deploiement', files: [] })).toBeNull()
  })

  it('registre : source et destination distinctes, gabarits limités', () => {
    expect(parseConfig('registry-promotion', { source: 'registre.exemple.test/candidat/app', destination: 'registre.exemple.test/valide/app' })).toMatchObject({ source_tag: '{tag}', destination_tag: '{tag}' })
    expect(parseConfig('registry-promotion', { source: 'registre.exemple.test/a/app', destination: 'registre.exemple.test/a/app' })).toBeNull()
    expect(parseConfig('registry-promotion', { source: 'registre.exemple.test/a/app', destination: 'registre.exemple.test/b/app', source_tag: '{env}' })).toBeNull()
    expect(parseConfig('registry-promotion', { source: 'registre.exemple.test/a/app', destination: 'registre.exemple.test/b/app', source_tag: '$(id)' })).toBeNull()
    // Adresse littérale refusée : le transport ne contrôle les adresses qu'après résolution d'un nom.
    expect(parseConfig('registry-promotion', { source: '192.0.2.10/a/app', destination: 'registre.exemple.test/b/app' })).toBeNull()
    expect(parseConfig('registry-promotion', { source: 'registre.exemple.test/a/app', destination: '192.0.2.10:5000/b/app' })).toBeNull()
  })

  it('gabarit d\'étiquette rempli et revalidé', () => {
    expect(fillTemplate('{tag}', { tag: 'v1.2.0', commit: 'c'.repeat(40) })).toBe('v1.2.0')
    expect(fillTemplate('sha-{short_commit}', { tag: null, commit: 'c'.repeat(40) })).toBe(`sha-${'c'.repeat(12)}`)
    expect(fillTemplate('{tag}', { tag: null, commit: 'c'.repeat(40) })).toBeNull()
    expect(fillTemplate('{tag}', { tag: 'refs/tags/v1', commit: 'c'.repeat(40) })).toBeNull()
  })

  it('schéma de création : environnement et déclencheur bornés', () => {
    expect(targetCreateSchema.safeParse({ kind: 'cd-trigger', environment: 'production', config: {} }).success).toBe(true)
    expect(targetCreateSchema.safeParse({ kind: 'cd-trigger', environment: 'Prod!', config: {} }).success).toBe(false)
    expect(targetCreateSchema.safeParse({ kind: 'ssh', environment: 'production', config: {} }).success).toBe(false)
  })

  it('workflow de déploiement détecté sans rien exécuter', () => {
    const wf = 'on:\n  workflow_dispatch:\n    inputs:\n      scanoria_report:\n        required: true\n      scanoria_commit:\n        type: string\n'
    expect(dispatchInputs(wf)).toEqual(['scanoria_report', 'scanoria_commit'])
    expect(dispatchInputs('on:\n  push:\n    branches: [main]\n')).toBeNull()
    expect(dispatchInputs('on:\n  workflow_dispatch:\n    inputs:\n      version:\n        type: string\n')).toBeNull()
    expect(dispatchInputs(`on:\n  workflow_dispatch:\n${' '.repeat(300 * 1024)}`)).toBeNull()
  })

  it('refus : cible désactivée, projet suspendu, verdict non favorable', () => {
    expect(refusalOf({ verdict: 'passed', enabled: true, suspended: false })).toBeNull()
    expect(refusalOf({ verdict: 'failed', enabled: true, suspended: false })).toBe('verdict-not-passed')
    expect(refusalOf({ verdict: 'inconclusive', enabled: true, suspended: false })).toBe('verdict-not-passed')
    expect(refusalOf({ verdict: null, enabled: true, suspended: false })).toBe('verdict-not-passed')
    expect(refusalOf({ verdict: 'passed', enabled: false, suspended: false })).toBe('target-disabled')
    expect(refusalOf({ verdict: 'passed', enabled: true, suspended: true })).toBe('project-suspended')
  })

  it('états des runs de forge et des pipelines', () => {
    expect(runStateOf('completed', 'success')).toBe('succeeded')
    expect(runStateOf('completed', 'failure')).toBe('failed')
    expect(runStateOf('in_progress', null)).toBe('running')
    expect(runStateOf('success', undefined)).toBe('succeeded')
    expect(runStateOf('cancelled', undefined)).toBe('failed')
    expect(runStateOf('waiting', undefined)).toBe('running')
    expect(gitlabStateOf('success')).toBe('succeeded')
    expect(gitlabStateOf('failed')).toBe('failed')
    expect(gitlabStateOf('running')).toBe('running')
    expect(safeUrl('http://x')).toBeNull()
    expect(safeUrl('https://forge.exemple.test/a')).toBe('https://forge.exemple.test/a')
  })

  it('J16 : demande de l\'auteur, sur une ligne à elle seule', () => {
    expect(authorRequestedAutoMerge('Correctif.\n\n/scanoria auto-merge\n')).toBe(true)
    expect(authorRequestedAutoMerge('Ne pas faire /scanoria auto-merge ici')).toBe(false)
    expect(authorRequestedAutoMerge('')).toBe(false)
  })
})
