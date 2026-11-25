// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// J9 (0.8, chantier D) : déclaration in-toto canonique, PAE DSSE et
// vérification d'une enveloppe (signature, sujet, prédicat, verdict).

import { generateKeyPairSync, sign } from 'node:crypto'
import { describe, expect, it } from 'vitest'
import {
  PAYLOAD_TYPE, PREDICATE_TYPE, buildStatement, canonicalJson, envelopeOf, pae, sha256Hex, verifyEnvelope,
  type VerdictPredicate,
} from '../../server/attest/dsse'
import { statementBytes } from '../../server/attest'

const DIGEST = `sha256:${'ab'.repeat(32)}`
const predicate: VerdictPredicate = {
  scan_id: '0b7c2f0e-9a4d-4c1e-8f3a-2d5b6c7d8e9f', project_id: '1b7c2f0e-9a4d-4c1e-8f3a-2d5b6c7d8e9f', verdict: 'passed',
  commit_sha: 'c'.repeat(40), ref: 'v1.2.0', tag: 'v1.2.0', report_sha256: 'd'.repeat(64),
  report_url: 'https://analyse.exemple.test/scans/0b7c2f0e-9a4d-4c1e-8f3a-2d5b6c7d8e9f', evaluated_at: '2026-11-25T10:00:00Z',
}

function keyPair() {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519')
  const raw = publicKey.export({ format: 'der', type: 'spki' }).subarray(12)
  return { raw, privateKey }
}

function signed(bytes: Buffer, privateKey: ReturnType<typeof keyPair>['privateKey']) {
  return envelopeOf(bytes, sign(null, pae(PAYLOAD_TYPE, bytes), privateKey).toString('base64'), 'e'.repeat(64))
}

describe('attest-dsse', () => {
  it('JSON canonique : clés triées, sans espace, nombres entiers seulement', () => {
    expect(canonicalJson({ b: 1, a: [true, null, 'x'], c: { z: 'é', y: undefined } })).toBe('{"a":[true,null,"x"],"b":1,"c":{"z":"é"}}')
    expect(() => canonicalJson({ a: 1.5 })).toThrow()
    expect(() => canonicalJson({ a: () => 1 })).toThrow()
  })

  it('PAE de DSSE v1', () => {
    expect(pae('t', Buffer.from('ab')).toString()).toBe('DSSEv1 1 t 2 ab')
  })

  it('déclaration in-toto v1 : un sujet par empreinte, refuse les formes douteuses', () => {
    const st = buildStatement('registre.exemple.test/valide/app', DIGEST, predicate)
    expect(st).toMatchObject({ _type: 'https://in-toto.io/Statement/v1', predicateType: PREDICATE_TYPE, subject: [{ digest: { sha256: 'ab'.repeat(32) } }] })
    expect(() => buildStatement('registre.exemple.test/valide/app', 'sha256:xyz', predicate)).toThrow()
    expect(() => buildStatement('../etc/passwd', DIGEST, predicate)).toThrow()
    expect(() => buildStatement('registre.exemple.test/app:v1', DIGEST, predicate)).toThrow()
    const bytes = statementBytes('registre.exemple.test/valide/app', DIGEST, predicate)
    expect(bytes.toString()).toBe(canonicalJson(JSON.parse(bytes.toString())))
    expect(sha256Hex(bytes)).toMatch(/^[0-9a-f]{64}$/)
  })

  it('enveloppe vérifiée : bonne clé, bon sujet, verdict favorable', () => {
    const k = keyPair()
    const bytes = statementBytes('registre.exemple.test/valide/app', DIGEST, predicate)
    const env = signed(bytes, k.privateKey)
    expect(verifyEnvelope(env, k.raw, DIGEST)?.statement.predicate.commit_sha).toBe('c'.repeat(40))
    expect(verifyEnvelope(env, k.raw)?.digest).toBe(DIGEST)
  })

  it('enveloppe refusée : autre clé, autre sujet, charge modifiée, type ou verdict faux', () => {
    const k = keyPair()
    const other = keyPair()
    const bytes = statementBytes('registre.exemple.test/valide/app', DIGEST, predicate)
    const env = signed(bytes, k.privateKey)
    expect(verifyEnvelope(env, other.raw, DIGEST)).toBeNull()
    expect(verifyEnvelope(env, k.raw, `sha256:${'00'.repeat(32)}`)).toBeNull()
    const tampered = { ...env, payload: Buffer.from(bytes.toString().replace('passed', 'failed')).toString('base64') }
    expect(verifyEnvelope(tampered, k.raw)).toBeNull()
    expect(verifyEnvelope({ ...env, payloadType: 'text/plain' }, k.raw)).toBeNull()
    expect(verifyEnvelope({ ...env, payload: `${env.payload}=` }, k.raw)).toBeNull()
    expect(verifyEnvelope(null, k.raw)).toBeNull()
    const failed = Buffer.from(canonicalJson({ ...buildStatement('registre.exemple.test/valide/app', DIGEST, predicate), predicate: { ...predicate, verdict: 'failed' } }))
    expect(verifyEnvelope(signed(failed, k.privateKey), k.raw)).toBeNull()
    const notJson = Buffer.from('pas du json')
    expect(verifyEnvelope(signed(notJson, k.privateKey), k.raw)).toBeNull()
    expect(() => verifyEnvelope(env, Buffer.alloc(3))).toThrow()
  })
})
