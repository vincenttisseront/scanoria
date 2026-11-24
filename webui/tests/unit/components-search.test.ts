// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// F3 : comparaison de versions par écosystème, intervalles, curseur et CSV.

import { describe, expect, it } from 'vitest'
import { compareVersions, inRange } from '../../server/sbom/versions'
import { componentQuerySchema, csvCell, decodeCursor, encodeCursor } from '../../server/sbom/search'

describe('versions', () => {
  it.each([
    ['1.2.5', '1.2.6', -1], ['1.10.0', '1.9.9', 1], ['1.0', '1.0.0', 0], ['1.0', '1.0.0.1', -1],
    ['v1.2.3', '1.2.3', 0], ['1.0.0-rc.1', '1.0.0', -1], ['1.0.0-alpha', '1.0.0-beta', -1],
    ['1.0.0-beta.2', '1.0.0-beta.11', -1], ['2.0.0.dev1', '2.0.0a1', -1], ['2.0.0rc1', '2.0.0', -1],
    ['2.0.0.post1', '2.0.0', 1], ['1.0.0+build.5', '1.0.0', 0], ['1.0-SNAPSHOT', '1.0', -1], ['3.0.Final', '3.0', 0],
  ])('%s ? %s → %i', (a, b, r) => {
    expect(compareVersions(a, b)).toBe(r)
    expect(compareVersions(b, a)).toBe(r === 0 ? 0 : -r)
  })

  it('intervalle inclusif selon l’écosystème, égalité seule sinon', () => {
    expect(inRange('npm', '1.2.5', '1.0.0', '1.2.5')).toBe(true)
    expect(inRange('npm', '1.2.6', '1.0.0', '1.2.5')).toBe(false)
    expect(inRange('pypi', '2.31.0', '2.0', undefined)).toBe(true)
    expect(inRange('npm', null, '1.0.0', undefined)).toBe(false)
    expect(inRange('npm', null, undefined, undefined)).toBe(true)
    expect(inRange('deb', '5.2-1', '5.0', '6.0')).toBe(false)
    expect(inRange('deb', '5.2-1', '5.2-1', undefined)).toBe(true)
  })
})

describe('recherche : paramètres, curseur, CSV', () => {
  it('au moins un critère ; purl, avis et limite validés', () => {
    expect(componentQuerySchema.safeParse({}).success).toBe(false)
    expect(componentQuerySchema.safeParse({ ecosystem: 'npm' }).success).toBe(false)
    expect(componentQuerySchema.safeParse({ name: 'minimist' }).success).toBe(true)
    expect(componentQuerySchema.safeParse({ purl: 'npm/minimist' }).success).toBe(false)
    expect(componentQuerySchema.safeParse({ vuln: 'CVE-1\'; DROP' }).success).toBe(false)
    expect(componentQuerySchema.safeParse({ vuln: 'GHSA-xvch-5gv4-984h' }).success).toBe(true)
    expect(componentQuerySchema.safeParse({ name: 'x', limit: '500' }).success).toBe(false)
    expect(componentQuerySchema.safeParse({ name: 'x', other: '1' }).success).toBe(false)
  })

  it('curseur opaque, aller-retour ; curseur forgé ignoré', () => {
    expect(decodeCursor(encodeCursor('alpha'))).toBe('alpha')
    expect(decodeCursor('pas-du-base64-json')).toBeNull()
    expect(decodeCursor(Buffer.from(JSON.stringify({ s: 'x'.repeat(100) })).toString('base64url'))).toBeNull()
    expect(decodeCursor(undefined)).toBeNull()
  })

  it('cellules CSV : guillemets, séparateurs, formules neutralisées', () => {
    expect(csvCell('minimist')).toBe('minimist')
    expect(csvCell('a,b')).toBe('"a,b"')
    expect(csvCell('dit "oui"')).toBe('"dit ""oui"""')
    expect(csvCell('=HYPERLINK("x")')).toBe('"\'=HYPERLINK(""x"")"')
    expect(csvCell('+1')).toBe('\'+1')
    expect(csvCell('@SUM(A1)')).toBe('\'@SUM(A1)')
    expect(csvCell(['MIT', 'Apache-2.0'])).toBe('MIT Apache-2.0')
    expect(csvCell(null)).toBe('')
    expect(csvCell('ligne\nsuivante')).toBe('ligne suivante')
  })
})
