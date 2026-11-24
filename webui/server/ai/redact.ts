// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Masquage avant tout envoi à l'IA (CLAUDE.md § 3.5, « rien de secret ne
// sort ») : chaque valeur qui est ou ressemble à un secret est remplacée par
// sa forme (type, longueur, jeu de caractères), jamais par un extrait. Même
// moteur que les résultats (server/findings/redact.ts), toujours en mode
// agressif : mieux vaut masquer un identifiant inoffensif que laisser passer
// un jeton.

import { entropy, looksRandom as engineLooksRandom, maskSecrets, URL_SECRET_TYPE } from '../findings/redact'

export interface Redaction {
  text: string
  count: number
}

/** Noms des types tels que l'IA les reçoit depuis la 0.3. */
const AI_TYPES: Record<string, string> = { [URL_SECRET_TYPE]: 'url-credentials', 'api-key': 'stripe-key' }

/** Jeu de caractères d'une valeur, sans rien en révéler d'autre. */
export function charset(value: string): string {
  const parts: string[] = []
  if (/[a-z]/.test(value)) parts.push('a-z')
  if (/[A-Z]/.test(value)) parts.push('A-Z')
  if (/[0-9]/.test(value)) parts.push('0-9')
  if (/[^A-Za-z0-9]/.test(value)) parts.push('symbols')
  return parts.join(',') || 'empty'
}

/** Forme d'un secret : type, longueur, jeu de caractères. */
export function shape(type: string, value: string): string {
  return `[REDACTED type=${type} len=${value.length} charset=${charset(value)}]`
}

export const shannon = entropy

/** Valeur à forte entropie : jeton probable (critère commun du moteur). */
export function looksRandom(value: string): boolean {
  return engineLooksRandom(value)
}

/** Masque tout ce qui est ou ressemble à un secret dans un texte. */
export function redactText(input: string): Redaction {
  const r = maskSecrets(input, {
    aggressive: true,
    maxLength: null,
    format: (type, value) => shape(AI_TYPES[type] ?? type, value),
  })
  return { text: r.text, count: r.found.length }
}

/** Masque récursivement toutes les chaînes d'une valeur JSON. */
export function redactValue<T>(value: T): { value: T, count: number } {
  let count = 0
  const walk = (v: unknown): unknown => {
    if (typeof v === 'string') {
      const r = redactText(v)
      count += r.count
      return r.text
    }
    if (Array.isArray(v)) return v.map(walk)
    if (v && typeof v === 'object') {
      return Object.fromEntries(Object.entries(v as Record<string, unknown>).map(([k, x]) => [k, walk(x)]))
    }
    return v
  }
  const out = walk(value) as T
  return { value: out, count }
}
