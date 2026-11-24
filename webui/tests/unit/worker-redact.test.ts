// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Masquage du secret de la source dans ce que renvoie le runner.

import { describe, expect, it } from 'vitest'
import { REDACTED, makeRedactor } from '../../server/scans/redact'

describe('makeRedactor', () => {
  const token = `scn_${'k'.repeat(20)}+/=${'z'.repeat(17)}`

  it('valeur exacte, encodée pour une URL, et formes usuelles', () => {
    const r = makeRedactor([token, null, 'abc'])
    const out = r([
      `token ${token}`,
      `https://${encodeURIComponent(token)}@forge.exemple.test/a.git`,
      'https://ci:motdepasse@forge.exemple.test/a.git',
      'Authorization: Basic Y2k6eHl6',
      'PRIVATE-TOKEN: abcdef',
      'abc reste visible',
    ].join('\n'))
    expect(out).not.toContain(token)
    expect(out).not.toContain(encodeURIComponent(token))
    expect(out).not.toContain('motdepasse')
    expect(out).not.toContain('Y2k6eHl6')
    expect(out).not.toContain('abcdef')
    expect(out).toContain('abc reste visible')
    expect(out).toContain(REDACTED)
  })

  it('clé privée sur plusieurs lignes : bloc et lignes isolées masqués', () => {
    const body = ['MIIEowIBAAKCAQEAexempleexempleexemple', 'ZXhlbXBsZWV4ZW1wbGVleGVtcGxlZXhlbXBs']
    const key = ['-----BEGIN OPENSSH ' + 'PRIVATE KEY-----', ...body, '-----END OPENSSH ' + 'PRIVATE KEY-----'].join('\n')
    const r = makeRedactor([key])
    expect(r(`debug: ${body[1]}`)).toBe(`debug: ${REDACTED}`)
    const other = makeRedactor([])
    expect(other(`x\n${key}\ny`)).toBe(`x\n${REDACTED}\ny`)
  })
})
