// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Masquage avant tout envoi à l'IA (CLAUDE.md § 3.5, « rien de secret ne
// sort ») : chaque valeur qui est ou ressemble à un secret est remplacée par
// sa forme (type, longueur, jeu de caractères), jamais par un extrait. Le
// masquage est volontairement large : mieux vaut masquer un identifiant
// inoffensif que laisser passer un jeton.

export interface Redaction {
  text: string
  count: number
}

interface Rule {
  type: string
  re: RegExp
  /**
   * 0 : toute la correspondance est le secret. 2 : le groupe 1 est le préfixe
   * (conservé tel quel) et le groupe 2 la valeur, remplacée par position.
   */
  group: 0 | 2
}

// Toutes les expressions sont linéaires (aucune répétition imbriquée).
const RULES: Rule[] = [
  { type: 'private-key', re: /-----BEGIN [A-Z0-9 ]{0,40}PRIVATE KEY( BLOCK)?-----[\s\S]{0,20000}?(-----END [A-Z0-9 ]{0,40}PRIVATE KEY( BLOCK)?-----|$)/g, group: 0 },
  { type: 'aws-access-key', re: /\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA)[0-9A-Z]{16}\b/g, group: 0 },
  { type: 'github-token', re: /\b(?:gh[pousr]_[A-Za-z0-9]{30,255}|github_pat_[A-Za-z0-9_]{40,255})\b/g, group: 0 },
  { type: 'gitlab-token', re: /\bglpat-[A-Za-z0-9_-]{20,255}\b/g, group: 0 },
  { type: 'slack-token', re: /\bxox[abprs]-[A-Za-z0-9-]{10,255}\b/g, group: 0 },
  { type: 'google-api-key', re: /\bAIza[0-9A-Za-z_-]{35}\b/g, group: 0 },
  { type: 'stripe-key', re: /\b[rs]k_(?:live|test)_[0-9A-Za-z]{16,255}\b/g, group: 0 },
  { type: 'scanoria-token', re: /\bscn_[A-Za-z0-9]{8,255}\b/g, group: 0 },
  { type: 'jwt', re: /\beyJ[A-Za-z0-9_-]{8,4096}\.eyJ[A-Za-z0-9_-]{8,8192}\.[A-Za-z0-9_-]{8,4096}\b/g, group: 0 },
  { type: 'url-credentials', re: /\b([a-z][a-z0-9+.-]{1,20}:\/\/[^\s:/@"'<>]{1,256}:)([^\s@/"'<>]{1,256})@/gi, group: 2 },
  { type: 'authorization', re: /\b((?:Bearer|Basic|Token)\s+)([A-Za-z0-9._~+/=-]{8,4096})/g, group: 2 },
  {
    type: 'assignment',
    re: /\b([A-Za-z0-9_]{0,40}(?:password|passwd|pwd|secret|token|api[_-]?key|apikey|access[_-]?key|private[_-]?key|client[_-]?secret|credentials?|auth)["']?\s{0,5}(?::=|=>|[:=])\s{0,5}["'`]?)([^\s"'`,;)}\]]{3,4096})/gi,
    group: 2,
  },
]

const ENTROPY_TOKEN_RE = /[A-Za-z0-9+/_=-]{20,4096}/g
const MASK_RE = /^\[REDACTED [^\]]{1,80}\]$/

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

export function shannon(value: string): number {
  const counts = new Map<string, number>()
  for (const ch of value) counts.set(ch, (counts.get(ch) ?? 0) + 1)
  let h = 0
  for (const n of counts.values()) {
    const p = n / value.length
    h -= p * Math.log2(p)
  }
  return h
}

/** Valeur à forte entropie avec lettres et chiffres : jeton probable. */
export function looksRandom(value: string): boolean {
  return value.length >= 20 && /[A-Za-z]/.test(value) && /[0-9]/.test(value) && shannon(value) >= 3.3
}

function replaceGroup(text: string, rule: Rule, counter: { n: number }): string {
  return text.replace(rule.re, (...args: unknown[]) => {
    const match = args[0] as string
    const prefix = rule.group === 0 ? '' : (args[1] as string)
    const value = rule.group === 0 ? match : (args[2] as string | undefined)
    if (!value || MASK_RE.test(value) || value.startsWith('[REDACTED')) return match
    counter.n += 1
    // Remplacement par position : la valeur peut aussi figurer dans le préfixe (« app:app@ »).
    return `${prefix}${shape(rule.type, value)}${match.slice(prefix.length + value.length)}`
  })
}

/** Masque tout ce qui est ou ressemble à un secret dans un texte. */
export function redactText(input: string): Redaction {
  const counter = { n: 0 }
  let text = input
  for (const rule of RULES) text = replaceGroup(text, rule, counter)
  text = text.replace(ENTROPY_TOKEN_RE, (token) => {
    if (!looksRandom(token)) return token
    counter.n += 1
    return shape('high-entropy', token)
  })
  return { text, count: counter.n }
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
