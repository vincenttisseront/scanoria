// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Reflet en base des demandes hors ligne (0.6, chantier A), appelé par
// l'ingestion des résultats du helper dans la même transaction :
// - trust-key : trusted_keys (ajout, ou revoked_at au retrait) ;
// - export-bundle et import-bundle : offline_bundles (ligne créée au dépôt
//   par la console, ou à la lecture du résultat pour l'export périodique).
// Le magasin du helper (/etc/scanoria/trusted-keys) reste seul consulté à
// l'import : ces tables ne servent qu'à l'affichage et à l'audit.

import type { Queryable } from '../utils/db'
import type { HelperResult } from '#shared/schemas'
import { KEY_FINGERPRINT_RE, PUBLIC_KEY_B64_RE } from '#shared/schemas'

interface RequestRow {
  requested_by: string | null
  params: unknown
}

const str = (v: unknown, re?: RegExp): string | null => (typeof v === 'string' && (!re || re.test(v)) ? v : null)
const int = (v: unknown): number | null => (typeof v === 'number' && Number.isSafeInteger(v) && v >= 0 ? v : null)

export async function recordOffline(db: Queryable, result: HelperResult, row: RequestRow): Promise<void> {
  const params = (row.params && typeof row.params === 'object' ? row.params : {}) as Record<string, unknown>
  const out = result.output ?? {}
  if (result.type === 'trust-key') {
    if (result.status !== 'ok') return
    if (out.action === 'add') {
      const fingerprint = str(out.fingerprint, KEY_FINGERPRINT_RE)
      const publicKey = str(out.public_key, PUBLIC_KEY_B64_RE)
      if (!fingerprint || !publicKey) return
      const label = (str(params.label) ?? fingerprint.slice(0, 16)).slice(0, 100) || fingerprint.slice(0, 16)
      await db.query(
        `INSERT INTO trusted_keys (label, purpose, public_key, fingerprint, added_by)
         VALUES ($1, 'bundle', $2, $3, $4)
         ON CONFLICT (fingerprint) DO UPDATE
           SET label = EXCLUDED.label, public_key = EXCLUDED.public_key, added_by = EXCLUDED.added_by,
               added_at = now(), revoked_at = NULL`,
        [label, publicKey, fingerprint, row.requested_by])
    }
    else if (out.action === 'remove') {
      const fingerprint = str(out.fingerprint, KEY_FINGERPRINT_RE)
      if (fingerprint) await db.query('UPDATE trusted_keys SET revoked_at = now() WHERE fingerprint = $1 AND revoked_at IS NULL', [fingerprint])
    }
    return
  }
  if (result.type !== 'export-bundle' && result.type !== 'import-bundle') return
  const direction = result.type === 'export-bundle' ? 'export' : 'import'
  // Estimation (dry_run), réglage de l'export périodique, export périodique sauté : rien à tracer.
  if (direction === 'export' && result.status === 'ok' && (out.dry_run === true || 'schedule' in out || 'skipped' in out)) return
  if (direction === 'export' && (params.dry_run === true || 'schedule' in params)) return
  const ok = result.status === 'ok'
  const contents: Record<string, unknown> = {}
  for (const k of ['name', 'created_at', 'modules', 'feeds', 'images', 'testbeds', 'catalog', 'catalog_version', 'removed']) {
    if (k in out) contents[k] = out[k]
  }
  const values = [
    ok ? 'done' : 'error',
    JSON.stringify(contents),
    ok ? int(out.size_bytes) : null,
    ok ? str(out.sha256, KEY_FINGERPRINT_RE) : null,
    ok ? str(out.signer_fingerprint, KEY_FINGERPRINT_RE) : null,
    ok ? null : JSON.stringify({ code: result.code, message: result.message.slice(0, 2000) }),
    result.finished_at,
    result.id,
  ]
  const updated = await db.query(
    `UPDATE offline_bundles SET status = $1, contents = $2::jsonb, size_bytes = $3, sha256 = $4,
            signer_fingerprint = $5, error = $6::jsonb, finished_at = $7
      WHERE request_id = $8`, values)
  if (updated.rowCount) return
  await db.query(
    `INSERT INTO offline_bundles (direction, status, contents, size_bytes, sha256, signer_fingerprint, error, finished_at, request_id, requested_by)
     VALUES ($9, $1, $2::jsonb, $3, $4, $5, $6::jsonb, $7, $8, $10)`,
    [...values, direction, row.requested_by])
}
