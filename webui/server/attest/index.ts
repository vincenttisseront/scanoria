// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// J9 (0.8, chantier D) : attestations d'un verdict favorable. Une ligne
// `attestations` par sujet (image par empreinte) et par analyse ; la
// signature est demandée au helper root (sign-attestation, contrat 37), qui
// relit la déclaration elle-même : la console ne voit jamais la clé privée.
// Le suivi est fait par passes (aucune attente bloquante) : la demande porte
// l'identifiant de l'attestation dans son contexte en base.

import type { Queryable } from '../utils/db'
import { getConfig } from '../utils/config'
import { submitRequest, type Requester } from '../utils/requests'
import { buildStatement, canonicalJson, envelopeOf, PREDICATE_TYPE, sha256Hex, type DsseEnvelope, type VerdictPredicate } from './dsse'

export const SYSTEM_REQUESTER: Requester = { userId: 0, username: 'system' }

export interface AttestationRow {
  id: string
  scan_id: string
  subject_name: string
  subject_digest: string
  predicate_type: string
  envelope: DsseEnvelope | null
  status: 'pending' | 'signed' | 'pushed' | 'error'
  pushed_to: string | null
  error: string | null
  created_at: string
}

const COLUMNS = `id::text, scan_id::text, subject_name, subject_digest, predicate_type, envelope, status, pushed_to, error,
  to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS created_at`

export async function listAttestations(db: Queryable, scanId: string): Promise<AttestationRow[]> {
  const r = await db.query<AttestationRow>(`SELECT ${COLUMNS} FROM attestations WHERE scan_id = $1 ORDER BY created_at, subject_name`, [scanId])
  return r.rows
}

export async function getAttestation(db: Queryable, id: string): Promise<AttestationRow | null> {
  const r = await db.query<AttestationRow>(`SELECT ${COLUMNS} FROM attestations WHERE id = $1`, [id])
  return r.rows[0] ?? null
}

/** Déclaration canonique (octets signés) d'une attestation. */
export function statementBytes(subjectName: string, digest: string, predicate: VerdictPredicate): Buffer {
  return Buffer.from(canonicalJson(buildStatement(subjectName, digest, predicate)), 'utf8')
}

/**
 * Crée l'attestation d'un sujet si elle n'existe pas, puis dépose la demande
 * de signature. Idempotent : une seule ligne et une seule demande par sujet.
 */
export async function requestAttestation(db: Queryable, input: { scanId: string, subjectName: string, digest: string, predicate: VerdictPredicate }, now = new Date()): Promise<AttestationRow> {
  if (input.predicate.verdict !== 'passed' || input.predicate.scan_id !== input.scanId) throw new Error('attestation refused: verdict not passed')
  const bytes = statementBytes(input.subjectName, input.digest, input.predicate)
  await db.query(
    `INSERT INTO attestations (scan_id, subject_name, subject_digest, predicate_type, status)
     VALUES ($1, $2, $3, $4, 'pending') ON CONFLICT (scan_id, subject_digest, predicate_type) DO NOTHING`,
    [input.scanId, input.subjectName, input.digest, PREDICATE_TYPE])
  const row = (await db.query<AttestationRow>(
    `SELECT ${COLUMNS} FROM attestations WHERE scan_id = $1 AND subject_digest = $2 AND predicate_type = $3`,
    [input.scanId, input.digest, PREDICATE_TYPE])).rows[0]!
  if (row.status !== 'pending') return row
  const asked = await db.query(
    `SELECT 1 FROM helper_requests WHERE type = 'sign-attestation' AND params ->> 'attestation_id' = $1 AND status IN ('pending', 'running', 'ok')`, [row.id])
  if (asked.rowCount) return row
  await submitRequest(db, getConfig().requestsDir, 'sign-attestation', {
    scan_id: input.scanId,
    kind: 'attestation',
    sha256: sha256Hex(bytes),
    content_b64: bytes.toString('base64'),
  }, SYSTEM_REQUESTER, now, { attestation_id: row.id })
  return row
}

const SIG_RE = /^[A-Za-z0-9+/]{86}==$/
const FP_RE = /^[0-9a-f]{64}$/

/**
 * Recueille les signatures rendues par le helper : enveloppe DSSE enregistrée
 * (statut « signed »), ou erreur. Rend le nombre d'attestations terminées.
 */
export async function collectSignatures(db: Queryable): Promise<number> {
  const r = await db.query<{ id: string, status: string, code: string | null, output: Record<string, unknown> | null, content: string | null, sha256: string | null }>(
    `SELECT a.id::text, h.status, h.code, h.output, h.params ->> 'content_b64' AS content, h.params ->> 'sha256' AS sha256
       FROM attestations a
       JOIN helper_requests h ON h.type = 'sign-attestation' AND h.params ->> 'attestation_id' = a.id::text
      WHERE a.status = 'pending' AND h.status IN ('ok', 'error', 'rejected', 'lost')
      LIMIT 100`)
  let done = 0
  for (const x of r.rows) {
    const out = x.output ?? {}
    const sig = typeof out.signature === 'string' ? out.signature : ''
    const fp = typeof out.key_fingerprint === 'string' ? out.key_fingerprint : ''
    if (x.status === 'ok' && SIG_RE.test(sig) && FP_RE.test(fp) && x.content && out.sha256 === x.sha256) {
      const envelope = envelopeOf(Buffer.from(x.content, 'base64'), sig, fp)
      await db.query(`UPDATE attestations SET envelope = $2, status = 'signed', error = NULL WHERE id = $1 AND status = 'pending'`, [x.id, JSON.stringify(envelope)])
    }
    else {
      await db.query(`UPDATE attestations SET status = 'error', error = $2 WHERE id = $1 AND status = 'pending'`, [x.id, (x.code ?? 'E_INTERNAL').slice(0, 100)])
    }
    done++
  }
  return done
}
