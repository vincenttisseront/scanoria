// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// J15 côté forge : analyse de « /scanoria accept » (commande hostile ou
// malformée → aide, jamais d'exception).
import { describe, expect, it } from 'vitest'
import { MAX_COMMAND_CHARS, isRealDay, parseScanoriaCommand, tokenize } from '../../server/forges/command'

const ID = '1a2b3c4d'

describe('/scanoria accept (J15)', () => {
  it('forme complète, en français et en anglais', () => {
    expect(parseScanoriaCommand(`/scanoria accept ${ID} --until 2027-01-31 --reason "faux positif de test"`))
      .toEqual({ kind: 'accept', finding: ID, until: '2027-01-31', reason: 'faux positif de test' })
    expect(parseScanoriaCommand(`Merci !\n/scanoria accepter ${ID} --jusqu-au=2027-01-31 --motif «valeur factice»`))
      .toEqual({ kind: 'accept', finding: ID, until: '2027-01-31', reason: 'valeur factice' })
    expect(parseScanoriaCommand(`/scanoria accept 0f1e2d3c-4b5a-6978-8a9b-0c1d2e3f4a5b --reason=“code de test” --until=2027-03-01`))
      .toMatchObject({ kind: 'accept', finding: '0f1e2d3c-4b5a-6978-8a9b-0c1d2e3f4a5b', until: '2027-03-01' })
  })

  it('aide et erreurs précises', () => {
    expect(parseScanoriaCommand('/scanoria aide')).toEqual({ kind: 'help', error: null })
    expect(parseScanoriaCommand('/scanoria help')).toEqual({ kind: 'help', error: null })
    expect(parseScanoriaCommand('/scanoria accept')).toEqual({ kind: 'help', error: 'E_CMD_FINDING' })
    expect(parseScanoriaCommand('/scanoria accept zz --until 2027-01-01 --reason "abc"')).toEqual({ kind: 'help', error: 'E_CMD_FINDING' })
    expect(parseScanoriaCommand(`/scanoria accept ${ID} --until 2027-02-30 --reason "abc"`)).toEqual({ kind: 'help', error: 'E_CMD_UNTIL' })
    expect(parseScanoriaCommand(`/scanoria accept ${ID} --until demain --reason "abc"`)).toEqual({ kind: 'help', error: 'E_CMD_UNTIL' })
    expect(parseScanoriaCommand(`/scanoria accept ${ID} --until 2027-01-01 --reason "ab"`)).toEqual({ kind: 'help', error: 'E_CMD_REASON' })
    expect(parseScanoriaCommand(`/scanoria accept ${ID} --until 2027-01-01`)).toEqual({ kind: 'help', error: 'E_CMD_REASON' })
    expect(parseScanoriaCommand('/scanoria supprimer tout')).toEqual({ kind: 'help', error: 'E_CMD_UNKNOWN' })
    expect(parseScanoriaCommand(`/scanoria accept ${ID} --until 2027-01-01 --reason "${'x'.repeat(MAX_COMMAND_CHARS)}"`))
      .toMatchObject({ kind: 'help' })
  })

  it('pas une commande : texte ordinaire, citation, bloc de code (notre propre commentaire)', () => {
    expect(parseScanoriaCommand('rien à voir')).toBeNull()
    expect(parseScanoriaCommand('on parle de /scanoria plus tard')).toBeNull()
    expect(parseScanoriaCommand(`\`\`\`\n/scanoria accept ${ID} --until 2027-01-31 --reason "x y z"\n\`\`\``)).toBeNull()
    expect(parseScanoriaCommand(`~~~\n/scanoria accept ${ID} --until 2027-01-31 --reason "x y z"\n~~~`)).toBeNull()
  })

  it('options inconnues, répétées ou injectées : refusées', () => {
    expect(parseScanoriaCommand(`/scanoria accept ${ID} --until 2027-01-31 --reason "abc" --approve`)).toMatchObject({ kind: 'help' })
    expect(parseScanoriaCommand(`/scanoria accept ${ID} ${ID} --until 2027-01-31 --reason "abc"`)).toMatchObject({ kind: 'help' })
    expect(parseScanoriaCommand(`/scanoria accept ${ID} --until 2027-01-31 --reason "non fermé`)).toMatchObject({ kind: 'help' })
  })

  it('isRealDay et tokenize', () => {
    expect(isRealDay('2028-02-29')).toBe(true)
    expect(isRealDay('2027-02-29')).toBe(false)
    expect(isRealDay('2027-13-01')).toBe(false)
    expect(tokenize('a "b c" «d e»')).toEqual(['a', 'b c', 'd e'])
    expect(tokenize('a "b')).toBeNull()
  })
})
