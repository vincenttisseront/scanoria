// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Contrat 14 (0.5) : lecture d'un SBOM CycloneDX sans base (purl normalisé,
// licences, dépendances directes, fichiers, bornes et refus).

import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'
import { MAX_COMPONENTS, SbomError, displayName, dtrackProjectOf, normalizePurl, parseSbom, sbomDocument } from '../../server/sbom/ingest'

const MODULES = fileURLToPath(new URL('../../../modules/', import.meta.url))
const recorded = (id: string) => JSON.parse(readFileSync(`${MODULES}${id}/tests/recorded.cdx.json`, 'utf8')) as Record<string, unknown>
const bom = (components: unknown[], extra: Record<string, unknown> = {}) => ({ bomFormat: 'CycloneDX', specVersion: '1.6', version: 1, components, ...extra })

describe('purl', () => {
  it('normalise le schéma, le type, PyPI et les qualificatifs', () => {
    expect(normalizePurl('PKG:NPM/minimist@1.2.8')?.purl).toBe('pkg:npm/minimist@1.2.8')
    expect(normalizePurl('pkg:pypi/Django_REST.framework@3.15.0')?.purl).toBe('pkg:pypi/django-rest-framework@3.15.0')
    expect(normalizePurl('pkg:deb/debian/curl@8.5.0?distro=debian-12&arch=amd64')?.purl)
      .toBe('pkg:deb/debian/curl@8.5.0?arch=amd64&distro=debian-12')
    expect(normalizePurl('pkg:npm/%40angular/core@17.0.0')).toMatchObject({ type: 'npm', namespace: ['@angular'], name: 'core', purl: 'pkg:npm/%40angular/core@17.0.0' })
    expect(normalizePurl('pkg:golang/github.com/google/uuid@v1.6.0')?.purl).toBe('pkg:golang/github.com/google/uuid@v1.6.0')
    expect(normalizePurl('pkg:github/Owner/Repo@v1')?.purl).toBe('pkg:github/owner/repo@v1')
    expect(normalizePurl('pkg:npm/sans-version')).toMatchObject({ version: null, purl: 'pkg:npm/sans-version' })
    expect(normalizePurl('pkg:maven/org.example/lib@1.0#src/../main')?.purl).toBe('pkg:maven/org.example/lib@1.0#src/main')
  })

  it('refuse un purl illisible', () => {
    for (const bad of [null, 42, '', 'npm/x@1', 'pkg:', 'pkg:npm', 'pkg:1bad/x@1', 'pkg:npm/x y@1', 'pkg:npm/%E0%A4%A@1',
      'pkg:npm/x@%E0%A4%A', 'pkg:npm/x@1?Bad Key=1', `pkg:npm/${'a'.repeat(1100)}@1`]) {
      expect(normalizePurl(bad), String(bad)).toBeNull()
    }
  })

  it('nom affiché avec son espace de noms', () => {
    expect(displayName(normalizePurl('pkg:golang/github.com/google/uuid@v1.6.0')!)).toBe('github.com/google/uuid')
    expect(displayName(normalizePurl('pkg:maven/org.apache.commons/commons-lang3@3.14.0')!)).toBe('org.apache.commons:commons-lang3')
    expect(displayName(normalizePurl('pkg:npm/%40scope/pkg@1')!)).toBe('@scope/pkg')
  })
})

describe('parseSbom', () => {
  it('lit la sortie enregistrée de Syft : un composant par écosystème, licences et fichiers', () => {
    const { components, coverage } = parseSbom(recorded('syft'))
    expect(components.map(c => [c.ecosystem, c.name, c.version])).toEqual([
      ['golang', 'github.com/google/uuid', 'v1.6.0'], ['npm', 'minimist', '1.2.8'], ['pypi', 'six', '1.17.0']])
    expect(components.find(c => c.name === 'minimist')).toMatchObject({ licenses: ['MIT'], paths: ['package-lock.json'], direct: null })
    expect(coverage).toMatchObject({ components: 3, ignored_no_purl: 0, ignored_invalid_purl: 0, direct_known: false, spec_version: '1.6' })
  })

  it('dépendances directes d’après le graphe, doublons fusionnés, imbrication, composants sans purl comptés', () => {
    const doc = bom([
      { 'bom-ref': 'a', 'name': 'a', 'purl': 'pkg:npm/a@1', 'licenses': [{ expression: 'MIT OR Apache-2.0' }],
        'properties': [{ name: 'syft:location:0:path', value: '/package-lock.json' }] },
      { 'bom-ref': 'a2', 'name': 'a', 'purl': 'pkg:NPM/a@1', 'licenses': [{ license: { name: 'Licence maison' } }],
        'evidence': { occurrences: [{ location: 'sub/package-lock.json' }] } },
      { 'bom-ref': 'b', 'name': 'b', 'purl': 'pkg:npm/b@2', 'components': [{ 'bom-ref': 'c', 'name': 'c', 'purl': 'pkg:npm/c@3' }] },
      { name: 'fichier', type: 'file' },
      { name: 'mauvais', purl: 'pkg:npm/x y' },
    ], { metadata: { component: { 'bom-ref': 'root', 'name': 'app' } }, dependencies: [{ ref: 'root', dependsOn: ['a2', 'b'] }, { ref: 'b', dependsOn: ['c'] }] })
    const { components, coverage } = parseSbom(doc)
    expect(components.map(c => [c.purl, c.direct])).toEqual([['pkg:npm/a@1', true], ['pkg:npm/b@2', true], ['pkg:npm/c@3', false]])
    expect(components[0]).toMatchObject({ licenses: ['MIT OR Apache-2.0', 'Licence maison'], paths: ['package-lock.json', 'sub/package-lock.json'] })
    expect(coverage).toMatchObject({ components: 3, ignored_no_purl: 1, ignored_invalid_purl: 1, direct_known: true })
  })

  it('refuse un document invalide ou trop grand, sans résultat partiel', () => {
    const cases: [unknown, string][] = [
      [null, 'not-cyclonedx'], [[], 'not-cyclonedx'], [{ bomFormat: 'SPDX' }, 'not-cyclonedx'],
      [{ bomFormat: 'CycloneDX', specVersion: '2.0' }, 'unsupported-version'],
      [{ bomFormat: 'CycloneDX', specVersion: '1.6', components: {} }, 'malformed'],
      [bom(['x']), 'malformed'], [bom([{ name: 'x', components: 'y' }]), 'malformed'],
    ]
    for (const [doc, code] of cases) {
      expect(() => parseSbom(doc)).toThrow(SbomError)
      try {
        parseSbom(doc)
      }
      catch (e) {
        expect((e as SbomError).code).toBe(code)
      }
    }
    let deep: Record<string, unknown> = { name: 'z', purl: 'pkg:npm/z@1' }
    for (let i = 0; i < 20; i++) deep = { name: `n${i}`, components: [deep] }
    expect(() => parseSbom(bom([deep]))).toThrow(/nested too deeply/)
    const many = Array.from({ length: MAX_COMPONENTS + 1 }, (_, i) => ({ name: `p${i}`, purl: `pkg:npm/p${i}@1` }))
    expect(() => parseSbom(bom(many))).toThrow(/more than 50000/)
    expect(parseSbom(bom(many.slice(0, MAX_COMPONENTS))).components).toHaveLength(MAX_COMPONENTS)
  })

  it('reconnaît la sortie de dtrack-upload (identifiant du projet Dependency-Track)', () => {
    expect(dtrackProjectOf(recorded('dtrack-upload'))).toBe('3d7c8f2a-5b1e-4c9d-a6f0-2e8b7d4c1a90')
    expect(dtrackProjectOf(recorded('syft'))).toBeNull()
    expect(dtrackProjectOf({ metadata: { properties: [{ name: 'scanoria:dtrack:project', value: 'pas-un-uuid' }] } })).toBeNull()
    expect(dtrackProjectOf(null)).toBeNull()
  })

  it('régénère un CycloneDX 1.6 relisible à l’identique', () => {
    const { components } = parseSbom(recorded('syft'))
    const withDirect = components.map((c, i) => ({ ...c, direct: i === 0, licenses: i === 2 ? ['MIT', 'Licence maison'] : c.licenses }))
    const doc = sbomDocument(withDirect, { scanId: '6f1b9f0e-2b8a-4c55-9d3e-1a2b3c4d5e6f', project: 'Démo', createdAt: '2026-11-24T12:00:00Z' })
    expect(doc).toMatchObject({ bomFormat: 'CycloneDX', specVersion: '1.6', serialNumber: 'urn:uuid:6f1b9f0e-2b8a-4c55-9d3e-1a2b3c4d5e6f' })
    const again = parseSbom(doc)
    expect(again.components.map(c => [c.purl, c.direct, c.licenses, c.paths])).toEqual(withDirect.map(c => [c.purl, c.direct, c.licenses, c.paths]))
    expect(sbomDocument([], { scanId: 'x', project: 'p' })).not.toHaveProperty('dependencies')
  })
})
