// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Contrat 37 : signature du rapport de release par le helper root, avec la
// clé de l'appliance (la console ne la voit jamais). La console :
// 1. range le rapport en « pending » (release_reports), puis dépose la
//    demande sign-release-report qui porte les octets canoniques eux-mêmes
//    (base64) avec leur empreinte ; helper_requests n'en garde que la taille ;
// 2. au retour, revérifie tout avant d'écrire « signed » : demande et rapport
//    de la même analyse, même empreinte, signature Ed25519 valide sur ces
//    octets avec la clé publique publiée par le helper (même empreinte de clé).
// Une erreur passagère (helper arrêté, clé pas encore créée) est retentée,
// MAX_SIGN_ATTEMPTS fois au plus ; ensuite le rapport passe en « error ».

import { createPublicKey, verify } from 'node:crypto'
import type { Queryable } from '../utils/db'
import { getConfig } from '../utils/config'
import { readPublishedState } from '../utils/appliance'
import { readOfflineStatus } from '../offline/status'
import { submitRequest } from '../utils/requests'
import { SYSTEM_REQUESTER } from '../sbom/dates'
import { canonicalBytes, sha256Hex } from './canonical'

export const MAX_SIGN_ATTEMPTS = 3
const RETRY_CODES = new Set(['E_SIGN_KEY', 'E_INTERNAL', 'E_TIMEOUT'])
const PUB_RE = /^[A-Za-z0-9+/]{43}=$/
const FP_RE = /^[0-9a-f]{64}$/
const SIG_RE = /^[A-Za-z0-9+/]{86}==$/
// En-tête DER (SubjectPublicKeyInfo) d'une clé publique Ed25519.
const SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex')

export interface ApplianceKey { public_key: string, fingerprint: string, pem: string }

/** Clé publique Ed25519 brute (base64) → PEM SubjectPublicKeyInfo, ou null. */
export function publicKeyPem(publicKey: string): string | null {
  if (!PUB_RE.test(publicKey)) return null
  const raw = Buffer.from(publicKey, 'base64')
  if (raw.length !== 32) return null
  const b64 = Buffer.concat([SPKI_PREFIX, raw]).toString('base64')
  return `-----BEGIN PUBLIC KEY-----\n${b64}\n-----END PUBLIC KEY-----\n`
}

/** Clé publique de l'appliance publiée par le helper (état hors ligne, sinon photographie d'état), ou null. */
export async function applianceKey(): Promise<ApplianceKey | null> {
  const cfg = getConfig()
  const status = await readOfflineStatus(cfg.offlineStatusFile ?? '/var/lib/scanoria/offline/status.json').catch(() => null)
  let key: unknown = status?.appliance_key ?? null
  if (!key) {
    const st = await readPublishedState(cfg.stateFile).catch(() => null)
    key = (st?.state as { appliance_key?: unknown } | null | undefined)?.appliance_key ?? null
  }
  const k = key as { public_key?: unknown, fingerprint?: unknown } | null
  if (!k || typeof k.public_key !== 'string' || typeof k.fingerprint !== 'string') return null
  const pem = publicKeyPem(k.public_key)
  // L'empreinte annoncée doit être celle de la clé : SHA-256 des 32 octets bruts.
  if (!pem || !FP_RE.test(k.fingerprint) || sha256Hex(Buffer.from(k.public_key, 'base64')) !== k.fingerprint) return null
  return { public_key: k.public_key, fingerprint: k.fingerprint, pem }
}

/** Vrai si signature (base64) est une signature Ed25519 valide de data par la clé publique brute donnée. */
export function verifySignature(publicKey: string, data: Buffer, signature: string): boolean {
  const pem = publicKeyPem(publicKey)
  if (!pem || !SIG_RE.test(signature)) return false
  try {
    return verify(null, data, createPublicKey(pem), Buffer.from(signature, 'base64'))
  }
  catch {
    return false
  }
}

/** Dépose la demande de signature d'un rapport déjà rangé en « pending ». */
export async function requestReportSignature(db: Queryable, scanId: string, bytes: Buffer, sha256: string, attempt = 1, requestsDir = getConfig().requestsDir): Promise<string> {
  const req = await submitRequest(db, requestsDir, 'sign-release-report', {
    scan_id: scanId, sha256, kind: 'release-report', content_b64: bytes.toString('base64'),
  }, SYSTEM_REQUESTER, new Date(), { scan_id: scanId, attempt })
  return req.id
}

interface SignResultRow {
  id: string
  scan_id: string | null
  status: string
  code: string | null
  output: { signature?: unknown, key_fingerprint?: unknown, sha256?: unknown, scan_id?: unknown } | null
  attempt: unknown
}

export interface AppliedSignature { scanId: string, outcome: 'signed' | 'error' | 'retry' }

async function markApplied(db: Queryable, id: string): Promise<void> {
  await db.query(`UPDATE helper_requests SET params = params || '{"applied": true}'::jsonb WHERE id = $1`, [id])
}

async function failReport(db: Queryable, scanId: string, error: string): Promise<void> {
  await db.query(`UPDATE release_reports SET status = 'error', error = $2 WHERE scan_id = $1 AND status = 'pending'`, [scanId, error.slice(0, 1000)])
}

function signatureProblem(x: { bytes: Buffer, expected: string, output: Record<string, unknown>, scanId: string, key: ApplianceKey | null, fp: string, sig: string }): string | null {
  if (sha256Hex(x.bytes) !== x.expected) return 'E_SIGN_DIGEST'
  if (x.output.sha256 !== x.expected || x.output.scan_id !== x.scanId) return 'E_SIGN_SCAN'
  if (!x.key || x.fp !== x.key.fingerprint) return 'E_SIGN_KEY'
  if (!verifySignature(x.key.public_key, x.bytes, x.sig)) return 'E_SIGNATURE'
  return null
}

/**
 * Recopie les signatures revenues du helper (demandes terminées pas encore
 * appliquées). Rend l'issue par analyse ; ne lève pas pour une demande isolée.
 */
export async function applySignatureResults(db: Queryable, key: ApplianceKey | null, requestsDir = getConfig().requestsDir): Promise<AppliedSignature[]> {
  const r = await db.query<SignResultRow>(
    `SELECT id::text, params ->> 'scan_id' AS scan_id, status, code, output, params -> 'attempt' AS attempt FROM helper_requests
      WHERE type = 'sign-release-report' AND status IN ('ok', 'error', 'rejected', 'lost') AND NOT (params ? 'applied')
      ORDER BY created_at LIMIT 20`)
  const out: AppliedSignature[] = []
  for (const req of r.rows) {
    await markApplied(db, req.id)
    if (!req.scan_id) continue
    const row = (await db.query<{ report: unknown, report_sha256: string, status: string }>(
      'SELECT report, report_sha256, status FROM release_reports WHERE scan_id = $1', [req.scan_id])).rows[0]
    if (!row || row.status !== 'pending') continue
    if (req.status !== 'ok') {
      const attempt = typeof req.attempt === 'number' ? req.attempt : 1
      if ((req.status === 'lost' || RETRY_CODES.has(req.code ?? '')) && attempt < MAX_SIGN_ATTEMPTS) {
        await requestReportSignature(db, req.scan_id, canonicalBytes(row.report), row.report_sha256, attempt + 1, requestsDir)
        out.push({ scanId: req.scan_id, outcome: 'retry' })
      }
      else {
        await failReport(db, req.scan_id, req.code ?? 'E_SIGN_FAILED')
        out.push({ scanId: req.scan_id, outcome: 'error' })
      }
      continue
    }
    const o = req.output ?? {}
    const bytes = canonicalBytes(row.report)
    const sig = typeof o.signature === 'string' ? o.signature : ''
    const fp = typeof o.key_fingerprint === 'string' ? o.key_fingerprint : ''
    // Rien n'est cru sur parole : empreinte du rapport en base, analyse, clé publiée et signature.
    const problem = signatureProblem({ bytes, expected: row.report_sha256, output: o, scanId: req.scan_id, key, fp, sig })
    if (problem === 'E_SIGN_KEY' && !key) {
      // Clé pas encore publiée par le helper : on retentera au prochain passage.
      await db.query(`UPDATE helper_requests SET params = params - 'applied' WHERE id = $1`, [req.id])
      continue
    }
    if (problem) {
      await failReport(db, req.scan_id, problem)
      out.push({ scanId: req.scan_id, outcome: 'error' })
      continue
    }
    await db.query(
      `UPDATE release_reports SET status = 'signed', signature = $2, key_fingerprint = $3, signed_at = now(), error = NULL
        WHERE scan_id = $1 AND status = 'pending'`, [req.scan_id, sig, fp])
    out.push({ scanId: req.scan_id, outcome: 'signed' })
  }
  return out
}

export const SIGNED_REPORT_SCHEMA = 'scanoria-signed-release-report/1'
export const REPORT_PAYLOAD_TYPE = 'application/vnd.scanoria.release-report+json'

/**
 * Fichier téléchargeable « rapport.json » (vérifié par scanoria-verify) :
 * enveloppe canonique sur une ligne, qui porte les octets signés en base64
 * (payload), leur empreinte, la signature et l'empreinte de la clé.
 */
export function signedEnvelope(row: { report: unknown, report_sha256: string, signature: string, key_fingerprint: string, signed_at: Date | string }): Buffer {
  const bytes = canonicalBytes(row.report)
  if (sha256Hex(bytes) !== row.report_sha256) throw new Error('E_SIGN_DIGEST')
  const env = {
    schema: SIGNED_REPORT_SCHEMA,
    payload_type: REPORT_PAYLOAD_TYPE,
    payload: bytes.toString('base64'),
    payload_sha256: row.report_sha256,
    signature: row.signature,
    key_fingerprint: row.key_fingerprint,
    signed_at: new Date(row.signed_at).toISOString().replace(/\.\d{3}Z$/, 'Z'),
  }
  return Buffer.from(`${JSON.stringify(Object.fromEntries(Object.entries(env).sort(([a], [b]) => (a < b ? -1 : 1))))}\n`, 'utf8')
}
