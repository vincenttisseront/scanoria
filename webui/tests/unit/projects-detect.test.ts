// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Assistant d'ajout F1 sur des arbres simulés : langages, gestionnaires et
// verrouillages, conteneurs, IaC, CI, licence, catégories et modules proposés.

import { describe, expect, it } from 'vitest'
import { detectRepository, licenseFromText, moduleRelevance, suggestModules, type CatalogModuleLite } from '../../server/projects/detect'

function input(files: Record<string, string>, opts: { truncated?: boolean } = {}) {
  const reads: string[] = []
  return {
    reads,
    value: {
      tree: {
        entries: Object.entries(files).map(([path, c]) => ({ path, type: 'file' as const, size: c.length })),
        truncated: opts.truncated ?? false,
      },
      read: async (p: string) => {
        reads.push(p)
        return files[p] ?? null
      },
      ref: 'main',
      commit: 'a'.repeat(40),
      now: new Date('2026-11-24T10:00:00Z'),
    },
  }
}

const MIT = 'MIT License\n\nPermission is hereby granted, free of charge, to any person obtaining a copy of this software'

const CATALOG: CatalogModuleLite[] = [
  { id: 'gitleaks', name: 'gitleaks', type: 'scanner', categories: ['secrets'] },
  { id: 'osv-scanner', name: 'OSV-Scanner', type: 'scanner', categories: ['sca'] },
  { id: 'trivy', name: 'Trivy', type: 'scanner', categories: ['sca', 'iac', 'container', 'sbom', 'secrets'] },
  { id: 'shellcheck', name: 'ShellCheck', type: 'scanner', categories: ['lint'] },
  { id: 'actionlint', name: 'actionlint', type: 'scanner', categories: ['lint', 'ci'] },
  { id: 'hadolint', name: 'hadolint', type: 'scanner', categories: ['lint'] },
  { id: 'checkov', name: 'Checkov', type: 'scanner', categories: ['iac'] },
  { id: 'bandit', name: 'Bandit', type: 'scanner', categories: ['sast'] },
  { id: 'zap', name: 'ZAP', type: 'scanner', categories: ['dast'] },
  { id: 'codeql', name: 'CodeQL', type: 'scanner', categories: ['sast'], license: { restrictions: 'private-code-forbidden' } },
  { id: 'osv-db', name: 'OSV DB', type: 'feed', categories: ['sca'] },
  { id: 'sonarqube', name: 'SonarQube', type: 'service', categories: ['quality', 'sast'] },
]

describe('détection F1', () => {
  it('dépôt Node + Python + Docker + Terraform + workflows', async () => {
    const t = input({
      'package.json': '{"license":"Apache-2.0"}',
      'package-lock.json': '{}',
      'src/app.ts': '', 'src/util.ts': '', 'src/legacy.js': '',
      'tools/requirements.txt': 'requests==2.0.0\nflask==3.0.0\n',
      'tools/run.py': '',
      'scripts/deploy.sh': '',
      'Dockerfile': 'FROM scratch',
      'infra/main.tf': '',
      '.github/workflows/ci.yml': 'on: push',
      'node_modules/x/index.js': '',
      'LICENSE': MIT,
    })
    const d = await detectRepository(t.value)
    expect(d.languages).toEqual(['typescript', 'javascript', 'python', 'shell'])
    expect(d.language_files.hcl).toBe(1)
    expect(d.package_managers).toEqual([
      { name: 'npm', manifest: 'package.json', lockfile: 'package-lock.json' },
      { name: 'pip', manifest: 'tools/requirements.txt', lockfile: 'tools/requirements.txt' },
    ])
    expect(d.missing_lockfiles).toEqual([])
    expect(d.containers).toEqual(['Dockerfile'])
    expect(d.iac).toEqual({ terraform: true, kubernetes: false, helm: false, ansible: false })
    expect(d.ci).toEqual([{ kind: 'github-actions', path: '.github/workflows/ci.yml' }])
    expect(d.shell_scripts).toBe(1)
    expect(d.license).toEqual({ spdx: 'MIT', source: 'LICENSE' })
    expect(d.categories).toEqual(['ci', 'container', 'iac', 'licenses', 'lint', 'quality', 'sast', 'sbom', 'sca', 'secrets'])
    expect(d.profile).toBe('complet')
    expect(d.pr_profile).toBe('rapide')
    expect(d.files).toBe(12)
    expect(d.commit).toBe('a'.repeat(40))
    expect(d.analyzed_at).toBe('2026-11-24T10:00:00Z')
  })

  it('verrouillages absents, yarn, poetry, go, cargo, maven, gradle, composer, bundler, nuget', async () => {
    const d = await detectRepository(input({
      'web/package.json': '{}', 'web/yarn.lock': '',
      'api/package.json': '{}',
      'py/pyproject.toml': '', 'py/poetry.lock': '', 'py/requirements.txt': 'x',
      'loose/requirements.txt': 'requests>=2\n',
      'go.mod': '', 'go.sum': '',
      'rs/Cargo.toml': '',
      'java/pom.xml': '',
      'kt/build.gradle.kts': '',
      'php/composer.json': '', 'php/composer.lock': '',
      'rb/Gemfile': '', 'rb/Gemfile.lock': '',
      'net/App.csproj': '',
    }).value)
    const pm = Object.fromEntries(d.package_managers.map(p => [p.manifest, [p.name, p.lockfile]]))
    expect(pm).toEqual({
      'web/package.json': ['yarn', 'web/yarn.lock'],
      'api/package.json': ['npm', null],
      'py/pyproject.toml': ['poetry', 'py/poetry.lock'],
      'loose/requirements.txt': ['pip', null],
      'go.mod': ['go', 'go.sum'],
      'rs/Cargo.toml': ['cargo', null],
      'java/pom.xml': ['maven', null],
      'kt/build.gradle.kts': ['gradle', null],
      'php/composer.json': ['composer', 'php/composer.lock'],
      'rb/Gemfile': ['bundler', 'rb/Gemfile.lock'],
      'net/App.csproj': ['nuget', null],
    })
    expect(d.missing_lockfiles.sort()).toEqual(['api/package.json', 'java/pom.xml', 'kt/build.gradle.kts', 'loose/requirements.txt', 'net/App.csproj', 'rs/Cargo.toml'])
  })

  it('Kubernetes lu dans les YAML (lecture bornée), Helm, Ansible, autres CI', async () => {
    const files: Record<string, string> = {
      'k8s/deploy.yaml': 'apiVersion: apps/v1\nkind: Deployment\n',
      '.forgejo/workflows/build.yml': '', '.gitlab-ci.yml': '', 'Jenkinsfile': '',
      'roles/web/tasks/main.yml': '- name: x',
    }
    for (let i = 0; i < 30; i++) files[`conf/c${i}.yaml`] = 'a: 1'
    const t = input(files)
    const d = await detectRepository(t.value)
    expect(d.iac.kubernetes).toBe(true)
    expect(d.iac.ansible).toBe(true)
    expect(d.ci.map(c => c.kind).sort()).toEqual(['forgejo-actions', 'gitlab-ci', 'jenkins'])
    expect(t.reads.length).toBeLessThanOrEqual(12)
    expect(t.reads[0]).toBe('k8s/deploy.yaml')

    const helm = await detectRepository(input({ 'chart/Chart.yaml': 'name: x' }).value)
    expect(helm.iac).toMatchObject({ helm: true, kubernetes: true })
    const none = await detectRepository(input({ 'a.yaml': 'a: 1' }).value)
    expect(none.iac.kubernetes).toBe(false)
    expect(none.categories).toEqual(['secrets'])
  })

  it('licence : texte, en-tête SPDX, package.json, inconnue ; arbre tronqué signalé', async () => {
    expect(licenseFromText('GNU AFFERO GENERAL PUBLIC LICENSE\n Version 3, 19 November 2007')).toBe('AGPL-3.0')
    expect(licenseFromText('Apache License\nVersion 2.0, January 2004')).toBe('Apache-2.0')
    expect(licenseFromText('SPDX-License-Identifier: BSD-3-Clause')).toBe('BSD-3-Clause')
    expect(licenseFromText('Tous droits réservés')).toBeNull()
    const pkg = await detectRepository(input({ 'package.json': '{"license":"ISC"}', 'LICENSE': 'maison' }, { truncated: true }).value)
    expect(pkg.license).toEqual({ spdx: 'ISC', source: 'package.json' })
    expect(pkg.truncated).toBe(true)
    const broken = await detectRepository(input({ 'package.json': '{' }).value)
    expect(broken.license).toBeNull()
  })

  it('modules pertinents : installés d’abord, rien de DAST ni de licence restreinte, trous de couverture', async () => {
    const raw = await detectRepository(input({
      'package.json': '{}', 'package-lock.json': '{}', 'a.ts': '', 'run.py': '', 'x.sh': '',
      'Dockerfile': '', '.github/workflows/ci.yml': '', 'main.tf': '',
    }).value)
    const d = suggestModules(raw, CATALOG, [
      { id: 'gitleaks', enabled: true, status: 'healthy' },
      { id: 'trivy', enabled: false, status: 'disabled' },
    ])
    expect(d.modules.map(m => [m.id, m.installed, m.enabled, m.reason])).toEqual([
      ['gitleaks', true, true, 'always'],
      ['trivy', true, false, 'category'],
      ['actionlint', false, false, 'workflows'],
      ['bandit', false, false, 'python'],
      ['checkov', false, false, 'iac'],
      ['hadolint', false, false, 'containers'],
      ['osv-scanner', false, false, 'lockfiles'],
      ['shellcheck', false, false, 'shell'],
    ])
    expect(d.coverage_gaps).toEqual(['licenses'])
    expect(moduleRelevance(CATALOG.find(m => m.id === 'zap')!, raw)).toBeNull()
    expect(moduleRelevance(CATALOG.find(m => m.id === 'codeql')!, raw)).toBeNull()
    expect(moduleRelevance(CATALOG.find(m => m.id === 'osv-db')!, raw)).toBeNull()

    const bare = suggestModules(await detectRepository(input({ 'README.md': '' }).value), CATALOG, [])
    expect(bare.modules.map(m => m.id)).toEqual(['gitleaks', 'trivy'])
    expect(bare.coverage_gaps).toEqual([])
  })
})
