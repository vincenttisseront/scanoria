// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Dépôt des demandes pour scanoria-helper (docs/ARCHITECTURE.md § 5.2, § 5.3) :
// ligne helper_requests « pending » (paramètres sans secret), création exclusive
// de tmp/<nom>.part (0600), écriture, fsync, renommage dans incoming/<nom>.
// La console ne fait jamais d'action privilégiée elle-même.

import { randomUUID } from 'node:crypto'
import { open, rename, unlink } from 'node:fs/promises'
import { join } from 'node:path'
import type { Queryable } from './db'
import {
  REQUEST_FILE_RE,
  envelopeSchema,
  requestParamSchemas,
  type RequestParams,
  type RequestType,
} from '#shared/schemas'

export const MAX_REQUEST_BYTES = 128 * 1024
/** 0.8 (contrat 37) : seuls les types de signature portent un contenu de 4 Mio (base64 compris). */
export const LARGE_REQUEST_BYTES: Partial<Record<RequestType, number>> = { 'sign-release-report': 6 * 1024 * 1024 }

export function maxRequestBytes(type: RequestType | null | undefined): number {
  return (type && LARGE_REQUEST_BYTES[type]) || MAX_REQUEST_BYTES
}

export interface Requester {
  userId: number
  username: string
  address?: string
}

export class RequestValidationError extends Error {
  constructor(public readonly issues: { path: string, code: string }[]) {
    super('invalid request parameters')
  }
}

export class RequestTooLargeError extends Error {
  constructor() {
    super('request exceeds 128 KiB')
  }
}

/** Horodatage UTC à la seconde, au format RFC 3339 « Z ». */
export function isoSeconds(date: Date): string {
  return `${date.toISOString().slice(0, 19)}Z`
}

/** Nom de fichier : AAAAMMJJTHHMMSSZ-<uuid>.json (ordre lexical = ordre FIFO). */
export function requestFileName(createdAt: string, id: string): string {
  const stamp = createdAt.slice(0, 19).replace(/[-:]/g, '')
  const name = `${stamp}Z-${id}.json`
  if (!REQUEST_FILE_RE.test(name)) throw new Error('invalid request file name')
  return name
}

/** Paramètres enregistrés en base : jamais de clé privée ni de contenu PEM. */
export function sanitizeParams(type: RequestType, params: Record<string, unknown>): Record<string, unknown> {
  if (type === 'import-certificate') {
    return {
      cert_pem_bytes: typeof params.cert_pem === 'string' ? params.cert_pem.length : 0,
      chain_provided: typeof params.chain_pem === 'string',
    }
  }
  if (type === 'sign-release-report') {
    // Jamais le contenu en base : il est déjà dans release_reports (empreinte et taille seulement).
    const { content_b64, ...rest } = params
    return { ...rest, content_bytes: typeof content_b64 === 'string' ? Math.floor(content_b64.length * 3 / 4) : 0 }
  }
  return { ...params }
}

export function buildEnvelope<T extends RequestType>(
  type: T,
  params: RequestParams<T>,
  requester: Requester,
  now: Date = new Date(),
  id: string = randomUUID(),
) {
  const envelope = {
    version: 1 as const,
    id,
    type,
    created_at: isoSeconds(now),
    requested_by: {
      user_id: requester.userId,
      username: requester.username,
      ...(requester.address ? { address: requester.address } : {}),
    },
    params,
  }
  const parsed = envelopeSchema(type).safeParse(envelope)
  if (!parsed.success) {
    throw new RequestValidationError(parsed.error.issues.map(i => ({ path: i.path.join('.'), code: i.code })))
  }
  return envelope
}

/** Valide les paramètres d'un type ; lève RequestValidationError. */
export function validateParams<T extends RequestType>(type: T, params: unknown): RequestParams<T> {
  const parsed = requestParamSchemas[type].safeParse(params)
  if (!parsed.success) {
    throw new RequestValidationError(parsed.error.issues.map(i => ({ path: i.path.join('.'), code: i.code })))
  }
  return parsed.data as RequestParams<T>
}

/** Écrit atomiquement le fichier de demande : tmp/<nom>.part puis incoming/<nom>. */
export async function writeRequestFile(requestsDir: string, fileName: string, content: string, maxBytes = MAX_REQUEST_BYTES): Promise<void> {
  if (!REQUEST_FILE_RE.test(fileName)) throw new Error('invalid request file name')
  if (Buffer.byteLength(content, 'utf8') > maxBytes) throw new RequestTooLargeError()
  const partPath = join(requestsDir, 'tmp', `${fileName}.part`)
  const finalPath = join(requestsDir, 'incoming', fileName)
  const handle = await open(partPath, 'wx', 0o600)
  try {
    await handle.writeFile(content, 'utf8')
    await handle.sync()
  }
  catch (err) {
    await handle.close().catch(() => {})
    await unlink(partPath).catch(() => {})
    throw err
  }
  await handle.close()
  try {
    await rename(partPath, finalPath)
  }
  catch (err) {
    await unlink(partPath).catch(() => {})
    throw err
  }
}

export interface SubmittedRequest {
  id: string
  type: RequestType
  fileName: string
  createdAt: string
}

/**
 * Dépose une demande : validation zod, ligne helper_requests, fichier atomique.
 * En cas d'échec d'écriture, la ligne passe en « error » / E_INTERNAL.
 */
export async function submitRequest<T extends RequestType>(
  db: Queryable,
  requestsDir: string,
  type: T,
  rawParams: unknown,
  requester: Requester,
  now: Date = new Date(),
  /** Contexte propre à la console, ajouté à la ligne en base (jamais au fichier). */
  dbContext: Record<string, unknown> = {},
): Promise<SubmittedRequest> {
  const params = validateParams(type, rawParams)
  const envelope = buildEnvelope(type, params, requester, now)
  const content = `${JSON.stringify(envelope)}\n`
  if (Buffer.byteLength(content, 'utf8') > maxRequestBytes(type)) throw new RequestTooLargeError()
  const fileName = requestFileName(envelope.created_at, envelope.id)
  await db.query(
    `INSERT INTO helper_requests (id, type, origin, file_name, requested_by, params, status, created_at)
     VALUES ($1, $2, 'console', $3, $4, $5, 'pending', $6)`,
    [
      envelope.id,
      type,
      fileName,
      requester.userId > 0 ? requester.userId : null,
      JSON.stringify({ ...sanitizeParams(type, params as Record<string, unknown>), ...dbContext }),
      envelope.created_at,
    ],
  )
  try {
    await writeRequestFile(requestsDir, fileName, content, maxRequestBytes(type))
  }
  catch (err) {
    await db.query(
      `UPDATE helper_requests SET status = 'error', code = 'E_INTERNAL',
              message = 'console could not write the request file', finished_at = now()
        WHERE id = $1`,
      [envelope.id],
    )
    throw err
  }
  return { id: envelope.id, type, fileName, createdAt: envelope.created_at }
}

export interface HelperRequestRow {
  id: string
  type: RequestType
  origin: string
  status: 'pending' | 'running' | 'ok' | 'error' | 'rejected' | 'lost'
  code: string | null
  message: string | null
  output: Record<string, unknown> | null
  params: Record<string, unknown>
  requested_by: string | null
  requested_by_username: string | null
  created_at: string
  finished_at: string | null
}

const ROW_COLUMNS = `r.id::text, r.type, r.origin, r.status, r.code, r.message, r.output, r.params,
  r.requested_by::text, u.username AS requested_by_username,
  to_char(r.created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS created_at,
  to_char(r.finished_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS finished_at`

export async function getHelperRequest(db: Queryable, id: string): Promise<HelperRequestRow | null> {
  const { rows } = await db.query<HelperRequestRow>(
    `SELECT ${ROW_COLUMNS} FROM helper_requests r LEFT JOIN users u ON u.id = r.requested_by WHERE r.id = $1`,
    [id],
  )
  return rows[0] ?? null
}

export async function listHelperRequests(db: Queryable, limit = 50): Promise<HelperRequestRow[]> {
  const { rows } = await db.query<HelperRequestRow>(
    `SELECT ${ROW_COLUMNS} FROM helper_requests r LEFT JOIN users u ON u.id = r.requested_by
      ORDER BY r.created_at DESC LIMIT $1`,
    [limit],
  )
  return rows
}
