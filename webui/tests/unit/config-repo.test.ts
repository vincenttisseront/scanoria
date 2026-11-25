// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// J8 : lecture de .scanoria.yml comme donnée hostile.
import { readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'
import { REPO_CONFIG_MAX_BYTES, configRequests, parseRepoConfig, repoConfigJsonSchema } from '../../server/config/repo-config'

const VALID = `version: 1
profiles:
  pr: rapide
  release: release
ignore:
  - docs/**
  - path: vendor/**
    reason: code tiers relu
    until: 2027-01-10
exceptions:
  - kind: vuln
    vuln: CVE-2026-1234
    package: lodash
    reason: fonction vulnérable jamais appelée
    until: 2027-01-10
  - kind: rule
    rule: B602
    tool: bandit
    reason: commande fixe
    until: 2026-12-31
`

describe('config : .scanoria.yml', () => {
  it('fichier valide : profils, exceptions, chemins ignorés', () => {
    const r = parseRepoConfig(VALID)
    expect(r.ok).toBe(true)
    if (!r.ok) return
    expect(r.config.profiles).toEqual({ pr: 'rapide', release: 'release' })
    const req = configRequests(r.config, '2026-11-25')
    expect(req.ignored).toEqual([{ path: 'docs/**', until: '2027-02-23' }, { path: 'vendor/**', until: '2027-01-10' }])
    expect(req.requests).toHaveLength(4)
    expect(req.requests[0]).toEqual({ kind: 'vuln', target: { vuln_id: 'CVE-2026-1234', package: 'lodash' }, reason: 'fonction vulnérable jamais appelée', expires_on: '2027-01-10' })
    expect(req.requests[1]!.target).toEqual({ rule_id: 'B602', tool: 'bandit' })
    expect(req.requests[2]).toMatchObject({ kind: 'path', target: { glob: 'docs/**' }, expires_on: '2027-02-23' })
    expect(req.requests[3]).toMatchObject({ kind: 'path', target: { glob: 'vendor/**' }, reason: 'code tiers relu' })
  })

  it('date de fin ramenée à un an au plus', () => {
    const r = parseRepoConfig('version: 1\nexceptions:\n  - kind: module\n    module: trivy\n    reason: en panne\n    until: 2030-01-01\n')
    expect(r.ok).toBe(true)
    if (r.ok) expect(configRequests(r.config, '2026-11-25').requests[0]!.expires_on).toBe('2027-11-26')
  })

  it.each([
    ['ancre et alias', 'version: 1\nignore: &x [a]\nexceptions: *x\n', /anchors/],
    ['bombe d\'alias', 'a: &a [x, x]\nb: &b [*a, *a]\nc: [*b, *b]\n', /anchors/],
    ['fusion <<', 'base: &b {version: 1}\n<<: *b\n', /anchors|unreadable|MERGE|DUPLICATE/i],
    ['étiquette python', 'version: 1\nprofiles: !!python/object/apply:os.system ["id"]\n', /tags|TAG/i],
    ['étiquette locale', 'version: !inc 1\n', /tags|TAG/i],
    ['clé en double', 'version: 1\nversion: 1\n', /DUPLICATE_KEY/],
    ['plusieurs documents', 'version: 1\n---\nversion: 1\n', /several/],
    ['vide', '', /empty/],
    ['binaire', 'version: 1\0\n', /binary/],
    ['YAML cassé', 'version: [1\n', /./],
  ])('refuse : %s', (_label, text, issue) => {
    const r = parseRepoConfig(text)
    expect(r.ok).toBe(false)
    if (!r.ok) expect(r.issues.map(i => i.message).join(' ')).toMatch(issue)
  })

  it.each([
    ['version texte', 'version: "1"\n'],
    ['version inconnue', 'version: 2\n'],
    ['clé inconnue', 'version: 1\nrun: rm -rf /\n'],
    ['profil invalide', 'version: 1\nprofiles:\n  pr: ../x\n'],
    ['déclencheur inconnu', 'version: 1\nprofiles:\n  push: rapide\n'],
    ['date impossible', 'version: 1\nexceptions:\n  - {kind: vuln, vuln: CVE-1-2, reason: abc, until: 2027-02-30}\n'],
    ['motif absent', 'version: 1\nexceptions:\n  - {kind: vuln, vuln: CVE-1-2, until: 2027-02-01}\n'],
    ['date absente', 'version: 1\nexceptions:\n  - {kind: rule, rule: x, reason: abc}\n'],
    ['type inattendu', 'version: 1\nexceptions: {kind: vuln}\n'],
    ['chemin remontant', 'version: 1\nignore: ["../etc/**"]\n'],
    ['chemin absolu', 'version: 1\nignore: ["/etc/**"]\n'],
    ['type de résultat', 'version: 1\nexceptions:\n  - {kind: finding, finding: x, reason: abc, until: 2027-01-01}\n'],
    ['trop d\'entrées', `version: 1\nignore: [${Array.from({ length: 101 }, (_, i) => `p${i}`).join(', ')}]\n`],
  ])('schéma strict : %s', (_label, text) => {
    expect(parseRepoConfig(text).ok).toBe(false)
  })

  it('taille bornée', () => {
    const r = parseRepoConfig(`version: 1\n# ${'x'.repeat(REPO_CONFIG_MAX_BYTES)}\n`)
    expect(r.ok).toBe(false)
    if (!r.ok) expect(r.issues[0]!.message).toBe('file too large')
  })

  it('schéma JSON publié', () => {
    const s = repoConfigJsonSchema()
    expect(s.title).toBe('.scanoria.yml')
    expect(JSON.stringify(s)).toContain('"exceptions"')
    expect((s as { additionalProperties?: unknown }).additionalProperties).toBe(false)
  })

  it('docs/scanoria-config.schema.json est à jour', () => {
    const published = JSON.parse(readFileSync(new URL('../../../docs/scanoria-config.schema.json', import.meta.url), 'utf8'))
    expect(published).toEqual(repoConfigJsonSchema())
  })
})
