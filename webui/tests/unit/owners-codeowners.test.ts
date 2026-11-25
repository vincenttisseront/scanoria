// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Chantier B (0.7) : lecture de CODEOWNERS (F6) sans rien exécuter. Syntaxe
// GitHub, GitLab (sections, défauts) et Forgejo ; motifs piégés (retour
// arrière, « .. », classes, NUL), tailles et nombres bornés.

import { describe, expect, it } from 'vitest'
import {
  compilePattern, MAX_CODEOWNERS_BYTES, MAX_OWNERS, MAX_RULES, ownersFor, parseCodeowners, segmentMatch,
} from '../../server/findings/codeowners'

describe('CODEOWNERS : motifs', () => {
  it('jokers d\'un segment', () => {
    expect(segmentMatch('*.js', 'a.js')).toBe(true)
    expect(segmentMatch('*.js', 'a.ts')).toBe(false)
    expect(segmentMatch('a?c', 'abc')).toBe(true)
    expect(segmentMatch('a?c', 'ac')).toBe(false)
    expect(segmentMatch('*', '')).toBe(true)
    expect(segmentMatch('a*b*c', 'aXXbYYc')).toBe(true)
    expect(segmentMatch('a*b*c', 'aXXbYY')).toBe(false)
  })

  it('ancrage, dossiers, « ** »', () => {
    const m = (p: string, path: string) => compilePattern(p)!(path)
    expect(m('*.js', 'src/deep/a.js')).toBe(true)
    expect(m('/build/', 'build/x/y')).toBe(true)
    expect(m('/build/', 'src/build/x')).toBe(false)
    expect(m('build/', 'build')).toBe(false)
    expect(m('docs/*', 'docs/a.md')).toBe(true)
    expect(m('docs/*', 'docs/a/b.md')).toBe(true)
    expect(m('apps/**/test', 'apps/a/b/test/x.js')).toBe(true)
    expect(m('apps/**/test', 'src/apps/a/test/x.js')).toBe(false)
    expect(m('README.md', 'sub/README.md')).toBe(true)
    expect(m('/README.md', 'sub/README.md')).toBe(false)
    expect(m('/', 'any/thing')).toBe(true)
  })

  it('motifs refusés : classes, « .. », « . », NUL, trop de jokers ou de « ** », trop long', () => {
    expect(compilePattern('[ab].js')).toBeNull()
    expect(compilePattern('a/../b')).toBeNull()
    expect(compilePattern('./a')).toBeNull()
    expect(compilePattern('a\u0000b')).toBeNull()
    expect(compilePattern('*'.repeat(17))).toBeNull()
    expect(compilePattern('**/a/**/b/**/c/**/d')).toBeNull()
    expect(compilePattern(`a${'b'.repeat(600)}`)).toBeNull()
    expect(compilePattern('')).toBeNull()
  })

  it('motifs pathologiques : temps borné', () => {
    const evil = ['*a*a*a*a*a*a*a*a*a*a*a*a*a*a*b', '**/**/**/x', '?'.repeat(16)]
    const path = `${'a'.repeat(200)}/${'a/'.repeat(100)}${'a'.repeat(300)}`
    const t0 = Date.now()
    for (const e of evil) {
      const m = compilePattern(e)
      expect(m).not.toBeNull()
      m!(path)
    }
    expect(Date.now() - t0).toBeLessThan(500)
  })
})

describe('CODEOWNERS : fichier', () => {
  it('GitHub : dernier motif qui correspond, ligne sans responsable, commentaires, échappements', () => {
    const p = parseCodeowners([
      '﻿# responsables',
      '*       @org/tous',
      '*.js    @front dev@exemple.test # commentaire',
      '/docs/  @doc',
      '/docs/generated/',
      'my\\ file.txt @espace',
    ].join('\r\n'))
    expect(p.issues).toEqual([])
    expect(ownersFor(p, 'src/a.js')).toEqual(['@front', 'dev@exemple.test'])
    expect(ownersFor(p, 'docs/guide.md')).toEqual(['@doc'])
    expect(ownersFor(p, 'docs/generated/x.md')).toEqual([])
    expect(ownersFor(p, 'my file.txt')).toEqual(['@espace'])
    expect(ownersFor(p, 'Makefile')).toEqual(['@org/tous'])
    expect(ownersFor(p, null)).toEqual([])
    expect(ownersFor(p, './src/a.js')).toEqual(['@front', 'dev@exemple.test'])
    expect(ownersFor(p, '../etc/passwd')).toEqual([])
  })

  it('GitLab : sections réunies, responsables par défaut, section optionnelle et nombre d\'approbations', () => {
    const p = parseCodeowners([
      '* @base',
      '[Sécurité] @secu',
      '*.tf',
      '^[Docs][2] @doc',
      '*.md',
      'README.md @redac',
    ].join('\n'))
    expect(ownersFor(p, 'main.tf').sort()).toEqual(['@base', '@secu'])
    expect(ownersFor(p, 'README.md').sort()).toEqual(['@base', '@redac'])
    expect(ownersFor(p, 'a.md').sort()).toEqual(['@base', '@doc'])
  })

  it('lignes non prises en charge ou hostiles signalées, jamais exécutées', () => {
    const p = parseCodeowners([
      '!negation @x',
      '../hors/** @x',
      'a/../b @x',
      '[abc].js @x',
      '*.py @ok $(id) `uname` ;rm',
    ].join('\n'))
    expect(p.issues.map(i => i.code)).toEqual(['unsupported', 'parent-segment', 'parent-segment', 'bad-pattern', 'bad-owner'])
    expect(ownersFor(p, 'a.py')).toEqual(['@ok'])
  })

  it('bornes : taille, nombre de règles, nombre de responsables', () => {
    expect(parseCodeowners('a'.repeat(MAX_CODEOWNERS_BYTES + 1)).rules).toEqual([])
    const many = Array.from({ length: MAX_RULES + 5 }, (_, i) => `f${i} @o`).join('\n')
    const p = parseCodeowners(many)
    expect(p.rules).toHaveLength(MAX_RULES)
    expect(p.issues.at(-1)!.code).toBe('too-many-rules')
    const wide = parseCodeowners(`* ${Array.from({ length: 40 }, (_, i) => `@o${i}`).join(' ')}`)
    expect(ownersFor(wide, 'x').length).toBeLessThanOrEqual(MAX_OWNERS)
    const sections = parseCodeowners(Array.from({ length: 30 }, (_, i) => `[S${i}]\n* @s${i}`).join('\n'))
    expect(ownersFor(sections, 'x')).toHaveLength(MAX_OWNERS)
  })
})
