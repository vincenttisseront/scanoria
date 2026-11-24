// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// F8 : expressions SPDX (analyse, bornes, évaluation OR/AND/WITH) et
// politique de licences (défauts, globale, surcharge par projet).

import { describe, expect, it } from 'vitest'
import { evaluateSpdx, licenseIds, parseSpdx, SpdxParseError } from '../../server/licenses/spdx'
import { decideComponent, decideExpression, decideLicense, DEFAULT_ALLOWED, type EffectivePolicy } from '../../server/licenses/policy'

const empty = (): EffectivePolicy => ({ project: new Map(), global: new Map() })

describe('expressions SPDX', () => {
  it('identifiant simple, « + » et LicenseRef', () => {
    expect(parseSpdx('MIT')).toEqual({ type: 'license', id: 'MIT', orLater: false })
    expect(parseSpdx('GPL-2.0+')).toEqual({ type: 'license', id: 'GPL-2.0', orLater: true })
    expect(parseSpdx('LicenseRef-Interne')).toEqual({ type: 'license', id: 'LicenseRef-Interne', orLater: false })
    expect(parseSpdx('DocumentRef-ext:LicenseRef-x').type).toBe('license')
  })

  it('AND lie plus fort que OR, parenthèses, opérateurs insensibles à la casse', () => {
    expect(parseSpdx('MIT or Apache-2.0 and BSD-3-Clause')).toEqual({
      type: 'or',
      items: [{ type: 'license', id: 'MIT', orLater: false }, { type: 'and', items: [
        { type: 'license', id: 'Apache-2.0', orLater: false }, { type: 'license', id: 'BSD-3-Clause', orLater: false }] }],
    })
    expect(parseSpdx('(MIT OR Apache-2.0) AND BSD-3-Clause').type).toBe('and')
    expect(licenseIds(parseSpdx('(MIT OR GPL-2.0-only WITH Classpath-exception-2.0) AND MIT'))).toEqual(['MIT', 'GPL-2.0-only'])
  })

  it('WITH : exception rattachée à la licence de base', () => {
    expect(parseSpdx('GPL-2.0-only WITH Classpath-exception-2.0')).toEqual({
      type: 'with', license: { type: 'license', id: 'GPL-2.0-only', orLater: false }, exception: 'Classpath-exception-2.0',
    })
  })

  it.each([
    [''], ['   '], ['MIT AND'], ['OR MIT'], ['(MIT'], ['MIT)'], ['MIT Apache-2.0'], ['MIT WITH'], ['MIT WITH (x)'],
    ['M!T'], ['()'], ['AND'], ['MIT; rm -rf /'],
  ])('expression mal formée refusée : %j', (expr) => {
    expect(() => parseSpdx(expr)).toThrow(SpdxParseError)
  })

  it('bornes : longueur, nombre de jetons, profondeur', () => {
    expect(() => parseSpdx('M'.repeat(1025))).toThrow(SpdxParseError)
    expect(() => parseSpdx(Array.from({ length: 200 }, () => 'A').join(' OR '))).toThrow(/too many tokens/)
    expect(() => parseSpdx(`${'('.repeat(40)}MIT${')'.repeat(40)}`)).toThrow(/too deep/)
    expect(parseSpdx(`${'('.repeat(20)}MIT${')'.repeat(20)}`)).toEqual({ type: 'license', id: 'MIT', orLater: false })
  })

  it('évaluation : OR = meilleure option, AND = pire, WITH = base', () => {
    const d = (id: string): 'allowed' | 'review' | 'denied' => (id === 'MIT' ? 'allowed' : id === 'GPL-3.0-only' ? 'denied' : 'review')
    expect(evaluateSpdx(parseSpdx('MIT OR GPL-3.0-only'), d)).toBe('allowed')
    expect(evaluateSpdx(parseSpdx('MIT AND GPL-3.0-only'), d)).toBe('denied')
    expect(evaluateSpdx(parseSpdx('LGPL-2.1-only AND MIT'), d)).toBe('review')
    expect(evaluateSpdx(parseSpdx('GPL-3.0-only WITH GCC-exception-3.1'), d)).toBe('denied')
    expect(evaluateSpdx(parseSpdx('(GPL-3.0-only OR LGPL-2.1-only) AND MIT'), d)).toBe('review')
  })
})

describe('politique de licences', () => {
  it('défauts : permissives autorisées, copyleft et inconnues à revoir, rien d’interdit', () => {
    const p = empty()
    for (const l of ['MIT', 'Apache-2.0', 'BSD-3-Clause', 'ISC', '0BSD', 'Zlib', 'mit']) expect(decideLicense(p, l).decision, l).toBe('allowed')
    for (const l of ['GPL-3.0-only', 'AGPL-3.0-or-later', 'LGPL-2.1-only', 'MPL-2.0', 'LicenseRef-x', 'Inconnue']) expect(decideLicense(p, l).decision, l).toBe('review')
    expect(DEFAULT_ALLOWED).not.toContain('GPL-3.0-only')
  })

  it('surcharge du projet > globale > défaut ; formes équivalentes -only / -or-later / +', () => {
    const p: EffectivePolicy = {
      global: new Map([['gpl-2.0-only', 'denied'], ['mit', 'review']]),
      project: new Map([['mit', 'allowed'], ['gpl-3.0-or-later', 'allowed']]),
    }
    expect(decideLicense(p, 'MIT')).toEqual({ decision: 'allowed', source: 'project' })
    expect(decideLicense(p, 'GPL-2.0')).toEqual({ decision: 'denied', source: 'global' })
    expect(decideLicense(p, 'GPL-3.0', true)).toEqual({ decision: 'allowed', source: 'project' })
    expect(decideExpression(p, 'GPL-3.0+').decision).toBe('allowed')
    expect(decideLicense({ ...p, project: new Map() }, 'MIT')).toEqual({ decision: 'review', source: 'global' })
  })

  it('composant : la pire de ses entrées ; aucune licence ou illisible = à revoir', () => {
    const p: EffectivePolicy = { global: new Map([['gpl-3.0-only', 'denied']]), project: new Map() }
    expect(decideComponent(p, ['MIT', 'Apache-2.0']).decision).toBe('allowed')
    expect(decideComponent(p, ['MIT', 'GPL-3.0-only'])).toEqual({ decision: 'denied', source: 'global' })
    expect(decideComponent(p, ['MIT OR GPL-3.0-only']).decision).toBe('allowed')
    expect(decideComponent(p, [])).toEqual({ decision: 'review', source: 'unknown' })
    expect(decideComponent(p, ['', '  '])).toEqual({ decision: 'review', source: 'unknown' })
    expect(decideComponent(p, ['MIT AND ('])).toEqual({ decision: 'review', source: 'unknown' })
  })
})
