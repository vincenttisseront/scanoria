// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Forme canonique du rapport de release (contrat 36) : JSON sans espaces,
// clés triées, nombres entiers seulement. La même forme est recalculée par le
// helper root (scanoria/release.py, canonical_bytes) avant de signer : un
// octet de différence et il refuse. Restrictions qui garantissent l'accord
// entre JavaScript et Python :
// - clés en ASCII imprimable (même ordre de tri dans les deux langages) ;
// - nombres entiers sûrs (|n| ≤ 2^53 - 1) : un décimal est d'abord converti
//   en chaîne par le constructeur du rapport (toSafeJson) ;
// - chaînes bien formées (aucune moitié de paire de substitution isolée).

import { createHash } from 'node:crypto'

export class CanonicalError extends Error {
  constructor(public readonly path: string, reason: string) {
    super(`${reason} at ${path || '$'}`)
  }
}

const KEY_RE = /^[\x20-\x7E]{1,128}$/
const MAX_DEPTH = 30

function encode(v: unknown, path: string, depth: number): string {
  if (depth > MAX_DEPTH) throw new CanonicalError(path, 'too deep')
  if (v === null) return 'null'
  if (typeof v === 'boolean') return v ? 'true' : 'false'
  if (typeof v === 'number') {
    if (!Number.isSafeInteger(v)) throw new CanonicalError(path, 'non-integer number')
    return Object.is(v, -0) ? '0' : String(v)
  }
  if (typeof v === 'string') {
    if (!v.isWellFormed()) throw new CanonicalError(path, 'lone surrogate')
    return JSON.stringify(v)
  }
  if (Array.isArray(v)) return `[${v.map((x, i) => encode(x, `${path}[${i}]`, depth + 1)).join(',')}]`
  if (typeof v === 'object') {
    // Ordre des unités de code UTF-16 (comme le helper Python), jamais localeCompare.
    const keys = Object.keys(v as object).sort((a, b) => (a < b ? -1 : 1))
    const parts: string[] = []
    for (const k of keys) {
      const x = (v as Record<string, unknown>)[k]
      if (x === undefined) continue
      if (!KEY_RE.test(k)) throw new CanonicalError(path, 'invalid key')
      parts.push(`${JSON.stringify(k)}:${encode(x, `${path}.${k}`, depth + 1)}`)
    }
    return `{${parts.join(',')}}`
  }
  throw new CanonicalError(path, `unsupported ${typeof v}`)
}

/** Texte canonique d'une valeur JSON ; lève CanonicalError hors des restrictions. */
export function canonicalJson(v: unknown): string {
  return encode(v, '', 0)
}

/** Octets canoniques (UTF-8). */
export function canonicalBytes(v: unknown): Buffer {
  return Buffer.from(canonicalJson(v), 'utf8')
}

export function sha256Hex(data: Buffer | string): string {
  return createHash('sha256').update(data).digest('hex')
}

/**
 * Copie sûre pour la forme canonique : un nombre non entier devient sa
 * chaîne décimale, une date sa forme ISO, une chaîne mal formée est
 * corrigée (U+FFFD), undefined disparaît. Les clés non ASCII lèvent quand
 * même (elles ne viennent jamais de données externes dans le rapport).
 */
export function toSafeJson(v: unknown): unknown {
  if (v === null || v === undefined) return v === null ? null : undefined
  if (v instanceof Date) return Number.isFinite(v.getTime()) ? v.toISOString() : null
  if (typeof v === 'number') return Number.isSafeInteger(v) ? v : Number.isFinite(v) ? String(v) : null
  if (typeof v === 'bigint') return v.toString()
  if (typeof v === 'string') return v.toWellFormed().replaceAll(String.fromCharCode(0), '')
  if (typeof v === 'boolean') return v
  if (Array.isArray(v)) return v.map(x => toSafeJson(x) ?? null)
  if (typeof v === 'object') {
    const out: Record<string, unknown> = {}
    for (const [k, x] of Object.entries(v as Record<string, unknown>)) {
      const y = toSafeJson(x)
      if (y !== undefined) out[k] = y
    }
    return out
  }
  return null
}
