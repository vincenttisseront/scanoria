// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Chantier B (0.8) : formats VEX (H7) sans base. Rendu OpenVEX 0.2.0 et
// CycloneDX 1.6 canonique et stable, règles OpenVEX (not_affected justifié,
// affected avec action), lecture stricte et refus des documents hostiles
// (la validation contre les schémas officiels est dans tests/b38-vex.sh).

import { describe, expect, it } from 'vitest'
import {
  canonicalJson, dedupeStatements, documentId, justificationFromReason, parseVexDocument, renderCycloneDxVex, renderOpenVex,
  sha256Hex, validPurl, VEX_LIMITS, VexFormatError, type VexStatement,
} from '../../server/vex/format'

const T = '2026-11-25T10:00:00Z'
const s = (over: Partial<VexStatement> = {}): VexStatement => ({
  vuln_id: 'CVE-2026-0001', product: 'pkg:npm/lib@1.0.0', status: 'fixed', justification: null,
  impact_statement: null, action_statement: null, timestamp: T, ...over,
})
const code = (text: string) => {
  try {
    parseVexDocument(text)
    return 'accepted'
  }
  catch (e) {
    return e instanceof VexFormatError ? e.code : 'crash'
  }
}
const ov = (statements: unknown[]) => JSON.stringify({ '@context': 'https://openvex.dev/ns/v0.2.0', 'statements': statements })

describe('formats VEX (H7)', () => {
  it('JSON canonique : clés triées, sans espace, undefined omis', () => {
    expect(canonicalJson({ b: 1, a: [{ d: undefined, c: 'x' }] })).toBe('{"a":[{"c":"x"}],"b":1}')
    expect(sha256Hex('')).toBe('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')
  })

  it('OpenVEX : groupement par texte, règles not_affected et affected, stable', () => {
    const list = [
      s({ status: 'not_affected', justification: 'component_not_present' }),
      s({ product: 'pkg:npm/autre@2.0.0', status: 'not_affected', justification: 'component_not_present' }),
      s({ vuln_id: 'CVE-2026-0002', status: 'not_affected' }),
      s({ vuln_id: 'CVE-2026-0003', status: 'affected' }),
      s({ vuln_id: 'CVE-2026-0004', status: 'under_investigation', impact_statement: 'En cours.' }),
    ]
    const { document, canonical } = renderOpenVex({ statements: list, timestamp: T, tooling: 'Scanoria 0.8.0' })
    const st = document.statements as Record<string, unknown>[]
    expect(st).toHaveLength(4)
    expect((st[0]!.products as unknown[]).length).toBe(2)
    expect(st[1]).toMatchObject({ status: 'not_affected', impact_statement: 'Not affected.' })
    expect(st[2]).toMatchObject({ status: 'affected', action_statement: 'Remediation pending.' })
    expect(st[3]).toMatchObject({ status_notes: 'En cours.' })
    expect(document['@id']).toBe(documentId(list))
    expect(document.tooling).toBe('Scanoria 0.8.0')
    expect(renderOpenVex({ statements: [...list].reverse(), timestamp: T, tooling: 'Scanoria 0.8.0' }).canonical).toBe(canonical)
  })

  it('CycloneDX : composants par purl, états et justifications traduits, numéro de série stable', () => {
    const list = [s({ status: 'not_affected', justification: 'vulnerable_code_cannot_be_controlled_by_adversary', impact_statement: 'Réseau isolé.' }), s({ vuln_id: 'CVE-2026-0002', status: 'affected', action_statement: 'Mise à jour.' })]
    const a = renderCycloneDxVex({ statements: list, timestamp: T })
    expect(a.document).toMatchObject({ bomFormat: 'CycloneDX', specVersion: '1.6', components: [{ 'bom-ref': 'pkg:npm/lib@1.0.0', 'name': 'lib' }] })
    const v = a.document.vulnerabilities as { analysis: Record<string, unknown> }[]
    expect(v[0]!.analysis).toMatchObject({ state: 'not_affected', justification: 'requires_environment', detail: 'Réseau isolé.' })
    expect(v[1]!.analysis).toMatchObject({ state: 'exploitable', detail: 'Mise à jour.' })
    expect(String(a.document.serialNumber)).toMatch(/^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/)
    expect(renderCycloneDxVex({ statements: [...list].reverse(), timestamp: T }).canonical).toBe(a.canonical)
    expect(parseVexDocument(a.canonical).statements).toMatchObject([
      { vuln_id: 'CVE-2026-0001', status: 'not_affected', justification: 'vulnerable_code_cannot_be_controlled_by_adversary' },
      { vuln_id: 'CVE-2026-0002', status: 'affected', action_statement: 'Mise à jour.' },
    ])
  })

  it('dédoublonnage : la déclaration la plus récente d\'un couple l\'emporte', () => {
    const out = dedupeStatements([s({ status: 'affected', timestamp: '2026-11-01T00:00:00Z' }), s({ status: 'fixed', timestamp: '2026-11-02T00:00:00Z' }), s({ vuln_id: 'cve-2026-0001', status: 'affected', timestamp: '2026-10-01T00:00:00Z' })])
    expect(out).toHaveLength(1)
    expect(out[0]!.status).toBe('fixed')
  })

  it('justification en tête du motif', () => {
    expect(justificationFromReason('[inline_mitigations_already_exist] Pare-feu applicatif.')).toEqual({ justification: 'inline_mitigations_already_exist', text: 'Pare-feu applicatif.' })
    expect(justificationFromReason('[inventee_pour_voir] x')).toEqual({ justification: null, text: '[inventee_pour_voir] x' })
    expect(justificationFromReason('Sans marque.').justification).toBeNull()
  })

  it('purl : forme stricte', () => {
    expect(validPurl('pkg:deb/debian/openssl@3.0.11?arch=amd64')).toBe(true)
    for (const p of ['pkg:npm/a b', 'pkg:npm/', 'http://x', 'pkg:NPM/x', 'pkg:npm/x\n', 42]) expect(validPurl(p)).toBe(false)
  })

  it('documents hostiles refusés avec un code stable', () => {
    const st = (over: Record<string, unknown> = {}) => ({ vulnerability: { name: 'CVE-2026-0001' }, products: [{ '@id': 'pkg:npm/lib@1' }], status: 'fixed', ...over })
    expect(code('x'.repeat(VEX_LIMITS.maxBytes + 1))).toBe('E_VEX_TOO_LARGE')
    expect(code('nope')).toBe('E_VEX_JSON')
    expect(code('null')).toBe('E_VEX_FORMAT')
    expect(code('{}')).toBe('E_VEX_FORMAT')
    expect(code(ov([st({ status: 'exploitable' })]))).toBe('E_VEX_STATUS')
    expect(code(ov([st({ vulnerability: { name: '`id`' } })]))).toBe('E_VEX_VULN_ID')
    expect(code(ov([st({ products: [] })]))).toBe('E_VEX_PRODUCT')
    expect(code(ov([st({ products: ['pkg:npm/x'] })]))).toBe('E_VEX_PRODUCT')
    expect(code(ov(['x']))).toBe('E_VEX_FORMAT')
    expect(code(ov([st({ status: 'not_affected', justification: 'x' })]))).toBe('E_VEX_JUSTIFICATION')
    expect(code(ov([st({ action_statement: 'a'.repeat(VEX_LIMITS.maxText + 1) })]))).toBe('E_VEX_FIELD')
    expect(code(ov(Array.from({ length: VEX_LIMITS.maxStatements + 1 }, () => st())))).toBe('E_VEX_TOO_MANY')
    const cdx = (v: unknown) => JSON.stringify({ bomFormat: 'CycloneDX', specVersion: '1.5', vulnerabilities: [v] })
    expect(code(cdx('x'))).toBe('E_VEX_FORMAT')
    expect(code(cdx({ id: 'CVE-2026-0001', analysis: { state: 'not_affected' }, affects: [{ ref: 'pkg:npm/x@1' }] }))).toBe('E_VEX_JUSTIFICATION')
    expect(code(cdx({ id: 'CVE-2026-0001', analysis: { state: 'resolved' }, affects: [] }))).toBe('E_VEX_PRODUCT')
    expect(code(JSON.stringify({ bomFormat: 'CycloneDX', specVersion: '1.6', vulnerabilities: [] }))).toBe('E_VEX_FORMAT')
    // Horodatages illisibles : celui du document, sinon l'instant de lecture.
    const r = parseVexDocument(ov([st({ timestamp: 'hier' })]), new Date('2026-11-25T12:00:00.123Z'))
    expect(r.statements[0]!.timestamp).toBe('2026-11-25T12:00:00Z')
  })
})
