// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// J9 (0.8, chantier D) : déclaration in-toto (Statement v1) et enveloppe DSSE.
// Les octets signés par le helper (attest.py) sont la PAE de la déclaration
// canonique (clés triées, aucun espace) ; la même PAE est recalculée ici pour
// vérifier une enveloppe, comme scanoria-verify et cosign le font.

import { createHash, createPublicKey, verify as cryptoVerify } from 'node:crypto'

export const PAYLOAD_TYPE = 'application/vnd.in-toto+json'
export const STATEMENT_TYPE = 'https://in-toto.io/Statement/v1'
/** Type de prédicat Scanoria (attendu par la politique d'admission d'exemple). */
export const PREDICATE_TYPE = 'https://github.com/vincenttisseront/scanoria/attestation/release-verdict/v1'
export const DSSE_MEDIA_TYPE = 'application/vnd.dsse.envelope.v1+json'

export interface VerdictPredicate {
  scan_id: string
  project_id: string
  verdict: 'passed'
  commit_sha: string
  ref: string
  tag?: string
  report_sha256?: string
  report_url?: string
  evaluated_at: string
}

export interface Statement {
  _type: typeof STATEMENT_TYPE
  subject: [{ name: string, digest: { sha256: string } }]
  predicateType: typeof PREDICATE_TYPE
  predicate: VerdictPredicate
}

export interface DsseEnvelope {
  payloadType: string
  payload: string
  signatures: { keyid: string, sig: string }[]
}

/** JSON canonique : clés triées, sans espace ; refuse les nombres non entiers. */
export function canonicalJson(value: unknown): string {
  if (value === null || typeof value === 'boolean' || typeof value === 'string') return JSON.stringify(value)
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value)) throw new Error('canonical JSON: non-integer number')
    return String(value)
  }
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`
  if (typeof value === 'object') {
    const entries = Object.entries(value as Record<string, unknown>).filter(([, v]) => v !== undefined)
    entries.sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
    return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${canonicalJson(v)}`).join(',')}}`
  }
  throw new Error('canonical JSON: unsupported value')
}

export function sha256Hex(data: Buffer | string): string {
  return createHash('sha256').update(data).digest('hex')
}

/** Pre-Authentication Encoding de DSSE v1. */
export function pae(payloadType: string, payload: Buffer): Buffer {
  const t = Buffer.from(payloadType, 'utf8')
  return Buffer.concat([Buffer.from(`DSSEv1 ${t.length} `), t, Buffer.from(` ${payload.length} `), payload])
}

/** Nom de sujet : dépôt d'image sans étiquette ni empreinte (registre/chemin). */
const SUBJECT_NAME_RE = /^[a-z0-9][a-z0-9.-]{0,252}(:\d{1,5})?(\/[a-z0-9]+([._-][a-z0-9]+)*)+$/

export function buildStatement(subjectName: string, digest: string, predicate: VerdictPredicate): Statement {
  if (!SUBJECT_NAME_RE.test(subjectName) || subjectName.length > 500) throw new Error('invalid subject name')
  const m = /^sha256:([0-9a-f]{64})$/.exec(digest)
  if (!m) throw new Error('invalid subject digest')
  return { _type: STATEMENT_TYPE, subject: [{ name: subjectName, digest: { sha256: m[1]! } }], predicateType: PREDICATE_TYPE, predicate }
}

export function envelopeOf(statementBytes: Buffer, signature: string, keyFingerprint: string): DsseEnvelope {
  return { payloadType: PAYLOAD_TYPE, payload: statementBytes.toString('base64'), signatures: [{ keyid: keyFingerprint, sig: signature }] }
}

/** Clé publique Ed25519 brute (32 octets) → objet clé de node. */
export function ed25519PublicKey(raw: Buffer) {
  if (raw.length !== 32) throw new Error('invalid Ed25519 public key')
  return createPublicKey({ key: Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), raw]), format: 'der', type: 'spki' })
}

export interface VerifiedAttestation {
  statement: Statement
  digest: string
}

/**
 * Vérifie une enveloppe : une signature valide de la PAE par la clé donnée,
 * déclaration in-toto Scanoria, sujet égal à l'empreinte attendue, verdict
 * favorable. Rend null au moindre écart.
 */
export function verifyEnvelope(envelope: unknown, rawPublicKey: Buffer, expectedDigest?: string): VerifiedAttestation | null {
  const e = envelope as Partial<DsseEnvelope> | null
  if (!e || e.payloadType !== PAYLOAD_TYPE || typeof e.payload !== 'string' || !Array.isArray(e.signatures)) return null
  const payload = Buffer.from(e.payload, 'base64')
  if (payload.toString('base64') !== e.payload) return null
  const key = ed25519PublicKey(rawPublicKey)
  const msg = pae(PAYLOAD_TYPE, payload)
  const signed = e.signatures.some(s => typeof s?.sig === 'string' && cryptoVerify(null, msg, key, Buffer.from(s.sig, 'base64')))
  if (!signed) return null
  let st: Statement
  try {
    st = JSON.parse(payload.toString('utf8')) as Statement
  }
  catch {
    return null
  }
  if (st?._type !== STATEMENT_TYPE || st.predicateType !== PREDICATE_TYPE || st.predicate?.verdict !== 'passed') return null
  const sha = st.subject?.[0]?.digest?.sha256
  if (!Array.isArray(st.subject) || st.subject.length !== 1 || typeof sha !== 'string') return null
  const digest = `sha256:${sha}`
  if (expectedDigest && expectedDigest !== digest) return null
  return { statement: st, digest }
}
