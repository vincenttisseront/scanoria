// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Contrat 30 : sanitizeForForge contre une liste d'attaques (texte publié
// dans une forge : commentaires, statuts, annotations).
import { describe, expect, it } from 'vitest'
import { MAX_FORGE_TEXT, allowedLink, codeBlock, escapeInline, sanitizeForForge } from '../../server/forges/sanitize'

const CONSOLE = 'https://analyse.exemple.test'
const ZW = '​'
const clean = (s: string) => sanitizeForForge(s, { consoleUrl: CONSOLE })

describe('sanitizeForForge (contrat 30)', () => {
  it('HTML et entités : jamais interprétés', () => {
    expect(clean('<script>alert(1)</script>')).toBe('&lt;script&gt;alert(1)&lt;/script&gt;')
    expect(clean('<img src=x onerror=alert(1)>')).not.toMatch(/<img/)
    expect(clean('<!-- caché -->')).not.toContain('<!--')
    expect(clean('<details><summary>x</summary>')).not.toMatch(/<details|<summary/)
    expect(clean('&#64;admin')).toBe(`&amp;#${ZW}64;admin`)
  })

  it('images : le « ! » est échappé, aucune requête vers un tiers', () => {
    const out = clean('![pixel](https://traqueur.exemple.test/p.png)')
    expect(out).not.toMatch(/!\[/)
    expect(out).not.toContain('https://traqueur')
  })

  it('mentions, références et références croisées neutralisées', () => {
    expect(clean('@admin')).toBe(`@${ZW}admin`)
    expect(clean('ferme #12')).toBe(`ferme #${ZW}12`)
    expect(clean('équipe/dépôt#3 et groupe/projet!7')).not.toMatch(/[#!]\d/)
    expect(clean('@everyone ~jalon $snippet %etiquette')).not.toMatch(/(^|\s)[@~$%]\w/)
  })

  it('liens : console et références CWE, CVE, OSV seulement', () => {
    expect(clean(`[analyse](${CONSOLE}/scans/1)`)).toBe(`[analyse](${CONSOLE}/scans/1)`)
    expect(clean('[CWE-79](https://cwe.mitre.org/data/definitions/79.html)')).toContain('](https://cwe.mitre.org/')
    expect(clean('[OSV](https://osv.dev/vulnerability/GHSA-xxxx-xxxx-xxxx)')).toContain('](https://osv.dev/')
    for (const bad of [
      '[ici](https://hameçon.exemple.test/login)',
      '[ici](https://analyse.exemple.test.piege.exemple.test/)',
      '[ici](https://analyse.exemple.test@piege.exemple.test/)',
      '[ici](javascript:alert(1))',
      '[ici](data:text/html;base64,PHNjcmlwdD4=)',
      '[ici](vbscript:msgbox)',
      `[ici](${CONSOLE.replace('https', 'http')}/x)`,
    ]) {
      const out = clean(bad)
      expect(out, bad).not.toMatch(/\]\((?!\\)/)
      expect(out, bad).not.toMatch(/(https?|javascript|data|vbscript):(?!\[)/i)
    }
  })

  it('URL nues, définitions de liens de référence et autoliens : inertes', () => {
    expect(clean('voir https://piege.exemple.test/p')).toBe('voir hxxps://piege[.]exemple[.]test/p')
    expect(clean('(https://piege.exemple.test)')).not.toContain('https://')
    expect(clean('[ref]: https://piege.exemple.test')).toMatch(/^\\\[ref\]/)
    expect(clean('<https://piege.exemple.test>')).not.toContain('<https')
    expect(clean('www.piege.exemple.test')).toBe(`www${ZW}.piege.exemple.test`)
  })

  it('libellé d’un lien permis : mentions neutralisées aussi', () => {
    expect(clean(`[@admin](${CONSOLE}/x)`)).toBe(`[@${ZW}admin](${CONSOLE}/x)`)
  })

  it('caractères de contrôle, bidirectionnels et invisibles retirés', () => {
    expect(clean('a‮b\u0000c⁦d﻿e‏f')).toBe('abcdef')
  })

  it('blocs de code : contenu gardé, info limitée, bloc ouvert refermé', () => {
    expect(clean('```ts\n@x <b>\n```')).toBe('```ts\n@x <b>\n```')
    expect(clean('``` onclick=1\nx\n```')).toBe('```\nx\n```')
    expect(clean('```\nouvert')).toBe('```\nouvert\n```')
    expect(codeBlock('a ``` b')).not.toMatch(/^```\n.*```.*\n```$/s)
  })

  it('longueur bornée, bloc de code coupé refermé', () => {
    const out = sanitizeForForge(`\`\`\`\n${'x'.repeat(MAX_FORGE_TEXT * 2)}`)
    expect(out.length).toBeLessThanOrEqual(MAX_FORGE_TEXT + 4)
    expect(out).toMatch(/```\n\n… \(texte tronqué/)
    expect(sanitizeForForge('y'.repeat(500), { maxLength: 100 }).length).toBeLessThanOrEqual(100)
  })

  it('entrée non textuelle : chaîne vide', () => {
    expect(sanitizeForForge(undefined as unknown as string)).toBe('')
  })

  it('escapeInline : une ligne, bornée, sans HTML', () => {
    const out = escapeInline('a\nb <i>c</i> @d', 10)
    expect(out).not.toContain('\n')
    expect(out).not.toMatch(/(?<!\\)</)
    expect(out.endsWith('…')).toBe(true)
    expect(escapeInline('@admin')).toBe('\\@admin')
  })

  it('allowedLink', () => {
    expect(allowedLink(`${CONSOLE}/a`, CONSOLE)).toBe(true)
    expect(allowedLink(`${CONSOLE}/a`, null)).toBe(false)
    expect(allowedLink('https://nvd.nist.gov/vuln/detail/CVE-2024-0001', null)).toBe(true)
    expect(allowedLink('https://www.cve.org/CVERecord?id=CVE-2024-0001', null)).toBe(true)
    expect(allowedLink('https://piege.exemple.test', CONSOLE)).toBe(false)
  })
})
