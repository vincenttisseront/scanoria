// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Reprise de l'existant (J5) : chaque format de configuration de dépôt traduit
// en demandes d'exception exactes, jamais élargies ; ce qui n'est pas
// représentable est signalé.

import { describe, expect, it } from 'vitest'
import { IMPORT_FILE_MAX_BYTES, nosecRequests, parseImportFile, regexToGlob, safeGlob } from '../../server/imports/repo-files'

const UNTIL = '2027-02-23'
const targets = (r: { requests: { kind: string, target: Record<string, unknown> }[] }) => r.requests.map(x => [x.kind, x.target])

describe('import-files : globs', () => {
  it.each([
    ['tests/', 'tests/**'],
    ['./docs/*.md', 'docs/*.md'],
    ['/vendor/**', 'vendor/**'],
    ['../etc/passwd', null],
    ['a/../../b', null],
    ['**', null],
    ['*/*', null],
    ['', null],
    ['a b', null],
    ['a\u0000b', null],
  ])('safeGlob(%j) = %j', (raw, want) => {
    expect(safeGlob(raw)).toBe(want)
  })

  it.each([
    ['^tests/fixtures/.*$', 'tests/fixtures/**'],
    ['testdata', '**testdata**'],
    ['\\.env\\.example$', '**.env.example'],
    ['^docs/', 'docs/**'],
    ['(.*?)fixtures(.*?)', '**fixtures**'],
    ['^vendor/(.*)', 'vendor/**'],
    ['[a-z]+\\.go', null],
    ['a|b', null],
    ['a.b', null],
    ['\\d+', null],
    ['.*', null],
    ['^$', null],
  ])('regexToGlob(%j) = %j', (re, want) => {
    expect(regexToGlob(re)).toBe(want)
  })
})

describe('import-files : formats', () => {
  it('.gitleaks.toml : chemins exacts, règles ciblées, le reste signalé', () => {
    const r = parseImportFile('.gitleaks.toml', `
title = "x"
[allowlist]
description = "Jeux d'essai"
paths = ['''^tests/fixtures/.*$''', '''[a-z]+\\.key''']
regexes = ['''AKIA.*''']
commits = ["abc123"]

[[allowlists]]
targetRules = ["generic-api-key"]
paths = ['''^docs/''']
`, UNTIL)
    expect(targets(r)).toEqual([
      ['path', { glob: 'tests/fixtures/**', tool: 'gitleaks' }],
      ['path', { glob: 'docs/**', tool: 'gitleaks' }],
    ])
    expect(r.requests[0]!.reason).toBe('importé (.gitleaks.toml) : Jeux d\'essai')
    expect(r.requests[1]!.reason).toContain('generic-api-key')
    expect(r.requests.every(x => x.expires_on === UNTIL)).toBe(true)
    expect(r.unsupported.map(u => u.entry.split(':')[0])).toEqual(['paths', 'regexes', 'commits'])
    expect(parseImportFile('.gitleaks.toml', '[[[', UNTIL).unsupported[0]!.entry).toBe('unreadable TOML')
  })

  it('.gitleaksignore : empreintes avec ou sans commit', () => {
    const r = parseImportFile('.gitleaksignore', '# commentaire\nabc123:src/app.ts:generic-api-key:12\nconfig/dev.env:private-key:3\nn\'importe quoi\n../x:r:1\n', UNTIL)
    expect(targets(r)).toEqual([
      ['path', { glob: 'src/app.ts', tool: 'gitleaks' }],
      ['path', { glob: 'config/dev.env', tool: 'gitleaks' }],
    ])
    expect(r.requests[0]!.source).toBe('.gitleaksignore:2')
    expect(r.unsupported).toHaveLength(2)
  })

  it('.trivyignore : CVE, règles, commentaire et échéance reprise si plus proche', () => {
    const r = parseImportFile('.trivyignore', '# Pas exposé\nCVE-2026-12345 exp:2026-12-31\n\nAVD-DS-0002\nCVE-2025-1 exp:2030-01-01\n%%%\n', UNTIL)
    expect(targets(r)).toEqual([
      ['vuln', { vuln_id: 'CVE-2026-12345' }],
      ['rule', { rule_id: 'AVD-DS-0002', tool: 'trivy' }],
      ['vuln', { vuln_id: 'CVE-2025-1' }],
    ])
    expect(r.requests[0]!.expires_on).toBe('2026-12-31')
    expect(r.requests[2]!.expires_on).toBe(UNTIL)
    expect(r.requests[0]!.reason).toBe('importé (.trivyignore) : Pas exposé')
    expect(r.unsupported.map(u => u.source)).toEqual(['.trivyignore:6'])
  })

  it('.trivyignore.yaml : chemins pour Trivy seul, licences signalées', () => {
    const r = parseImportFile('.trivyignore.yaml', `
vulnerabilities:
  - id: CVE-2026-0001
    statement: Non atteignable
    expired_at: 2026-12-01
  - id: CVE-2026-0002
    paths: ["vendor/lib/", "../x"]
misconfigurations:
  - id: AVD-KSV-0001
licenses:
  - id: GPL-3.0
secrets:
  - {}
`, UNTIL)
    expect(targets(r)).toEqual([
      ['vuln', { vuln_id: 'CVE-2026-0001' }],
      ['path', { glob: 'vendor/lib/**', tool: 'trivy' }],
      ['rule', { rule_id: 'AVD-KSV-0001', tool: 'trivy' }],
    ])
    expect(r.requests[0]!.expires_on).toBe('2026-12-01')
    expect(r.unsupported).toHaveLength(3)
    expect(parseImportFile('.trivyignore.yaml', 'a: &x 1\nb: *x', UNTIL).unsupported[0]!.entry).toBe('unreadable YAML')
  })

  it('osv-scanner.toml : IgnoredVulns avec motif et échéance', () => {
    const r = parseImportFile('osv-scanner.toml', `
[[IgnoredVulns]]
id = "GHSA-xxxx-xxxx-xxxx"
ignoreUntil = 2026-12-15T00:00:00Z
reason = "Correctif en cours"

[[IgnoredVulns]]
id = "pas-un-id"

[[PackageOverrides]]
name = "lodash"
ignore = true
`, UNTIL)
    expect(targets(r)).toEqual([['vuln', { vuln_id: 'GHSA-xxxx-xxxx-xxxx' }]])
    expect(r.requests[0]!.expires_on).toBe('2026-12-15')
    expect(r.requests[0]!.reason).toContain('Correctif en cours')
    expect(r.unsupported).toHaveLength(2)
  })

  it('.semgrepignore : syntaxe gitignore, une demande par moteur, négation signalée', () => {
    const r = parseImportFile('.semgrepignore', 'node_modules\n/build/\ntests/*.py\n!keep.py\n:include .gitignore\n', UNTIL, { semgrepTools: ['opengrep'] })
    expect(targets(r)).toEqual([
      ['path', { glob: '**/node_modules/**', tool: 'opengrep' }],
      ['path', { glob: 'build/**', tool: 'opengrep' }],
      ['path', { glob: 'tests/*.py', tool: 'opengrep' }],
    ])
    expect(r.unsupported).toHaveLength(2)
    expect(parseImportFile('.semgrepignore', 'dist\n', UNTIL).requests.map(x => x.target.tool)).toEqual(['opengrep', 'semgrep'])
  })

  it('sonar-project.properties : exclusions et règles globales', () => {
    const r = parseImportFile('sonar-project.properties', [
      'sonar.projectKey=exemple',
      'sonar.exclusions=**/generated/**, \\',
      '  docs/**',
      'sonar.coverage.exclusions=tests/**',
      'sonar.issue.ignore.multicriteria=e1,e2,e3',
      'sonar.issue.ignore.multicriteria.e1.ruleKey=typescript:S1234',
      'sonar.issue.ignore.multicriteria.e1.resourceKey=**/*',
      'sonar.issue.ignore.multicriteria.e2.ruleKey=java:S100',
      'sonar.issue.ignore.multicriteria.e2.resourceKey=src/legacy/**',
      'sonar.issue.ignore.multicriteria.e3.ruleKey=*',
    ].join('\n'), UNTIL)
    expect(targets(r)).toEqual([
      ['path', { glob: '**/generated/**', tool: 'sonar-scanner' }],
      ['path', { glob: 'docs/**', tool: 'sonar-scanner' }],
      ['rule', { rule_id: 'typescript:S1234', tool: 'sonar-scanner' }],
    ])
    expect(r.unsupported.map(u => u.entry)).toEqual(['multicriteria e2: java:S100 on src/legacy/**', 'multicriteria e3'])
  })

  it.each([
    ['.checkov.yaml', 'skip-check:\n  - CKV_AWS_20\n  - CKV_*', 'checkov', ['CKV_AWS_20']],
    ['.checkov.yml', 'skip_check: CKV_K8S_1,CKV_K8S_2', 'checkov', ['CKV_K8S_1', 'CKV_K8S_2']],
    ['.hadolint.yaml', 'ignored: [DL3008, DL3018]', 'hadolint', ['DL3008', 'DL3018']],
    ['.hadolint.yml', 'ignored: []', 'hadolint', []],
    ['.bandit', '[bandit]\nskips = B101,B602, X1\n', 'bandit', ['B101', 'B602']],
    ['.bandit', 'skips: [B104]\n', 'bandit', ['B104']],
  ] as const)('%s', (file, text, tool, rules) => {
    const r = parseImportFile(file, text, UNTIL)
    expect(r.requests.map(x => x.target)).toEqual(rules.map(rule_id => ({ rule_id, tool })))
  })

  it('# nosec : exception de chemin Bandit pour le fichier, règles citées', () => {
    const r = nosecRequests('app/db.py', 'x = 1\nq = f"SELECT {a}"  # nosec B608\nsubprocess.call(c, shell=True)  # nosec\n', UNTIL)
    expect(targets(r)).toEqual([['path', { glob: 'app/db.py', tool: 'bandit' }]])
    expect(r.requests[0]!.reason).toBe('importé (# nosec) : app/db.py (B608)')
    expect(nosecRequests('app/ok.py', 'print(1)\n', UNTIL).requests).toEqual([])
    expect(nosecRequests('../x.py', '# nosec\n', UNTIL).requests).toEqual([])
    expect(parseImportFile('nosec', '# nosec', UNTIL).requests).toEqual([])
  })

  it('fichier trop gros : signalé, rien importé', () => {
    const r = parseImportFile('.trivyignore', `CVE-2026-1\n${'#'.repeat(IMPORT_FILE_MAX_BYTES)}`, UNTIL)
    expect(r.requests).toEqual([])
    expect(r.unsupported[0]!.entry).toBe('file too large')
  })
})
