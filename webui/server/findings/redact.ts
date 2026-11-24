// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Masquage des secrets (CLAUDE.md § 6.3, F7, ARCHITECTURE § 12.6) : la valeur
// d'un secret n'est jamais stockée ni envoyée à l'IA. Chaque motif trouvé est
// remplacé par sa forme « [secret masqué : type, longueur N] ». Réutilisé par
// l'IA (§ 3.5) avant tout envoi.

export interface SecretShape {
  type: string
  length: number
  /** Jeu de caractères : hex, digits, base64, base64url, alnum, printable. */
  charset: string
}

/** Forme d'une valeur, sans rien en garder. */
export function secretShape(value: string, type = 'generic'): SecretShape {
  let charset = 'printable'
  if (/^[0-9]+$/.test(value)) charset = 'digits'
  else if (/^[0-9a-f]+$/i.test(value)) charset = 'hex'
  else if (/^[A-Za-z0-9]+$/.test(value)) charset = 'alnum'
  else if (/^[A-Za-z0-9_-]+$/.test(value)) charset = 'base64url'
  else if (/^[A-Za-z0-9+/]+=*$/.test(value)) charset = 'base64'
  return { type, length: value.length, charset }
}

export function maskToken(type: string, length: number): string {
  return `[secret masqué : ${type}, longueur ${length}]`
}

const MASK_RE = /\[secret masqué : [a-z0-9-]+, longueur [0-9]+\]/g

// Motifs construits par morceaux : aucun ne doit ressembler lui-même à un secret.
const PEM_BEGIN = '-----BEGIN'
const KEY_MARK = 'PRIVATE KEY-----'
const PATTERNS: { type: string, re: RegExp, group?: number }[] = [
  { type: 'private-key', re: new RegExp(`${PEM_BEGIN}[ A-Z0-9]*${KEY_MARK}[\\s\\S]*?(?:-----END[ A-Z0-9]*${KEY_MARK}|$)`, 'g') },
  { type: 'jwt', re: /eyJ[A-Za-z0-9_-]{5,}\.eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}/g },
  { type: 'aws-access-key', re: /\b(?:AKIA|ASIA|AGPA|AIDA|AROA)[A-Z0-9]{16}\b/g },
  { type: 'github-token', re: /\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,})\b/g },
  { type: 'gitlab-token', re: /\bglpat-[A-Za-z0-9_-]{20,}\b/g },
  { type: 'slack-token', re: /\bxox[abposr]-[A-Za-z0-9-]{10,}\b/g },
  { type: 'scanoria-token', re: /\bscn_[A-Za-z0-9]{40}\b/g },
  { type: 'api-key', re: /\b(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b/g },
  // Identifiants dans une URL : seul le mot de passe est masqué.
  // eslint-disable-next-line no-control-regex
  { type: 'url-password', re: /(?<=[a-z][a-z0-9+.-]*:\/\/[^\s:/@]{1,256}:)[^\s@/\u0000]{1,256}(?=@)/gi },
  // Affectation « clé = valeur » dont le nom évoque un secret.
  {
    type: 'assignment',
    // eslint-disable-next-line no-control-regex
    re: /(?<=\b[A-Za-z0-9_.-]*(?:pass(?:word|wd)?|pwd|secret|token|api[_-]?key|apikey|access[_-]?key|private[_-]?key|credential)s?[A-Za-z0-9_.-]*["']?\s*(?::=|=>|[:=])\s*["'`]?)[^\s"'`,;<>\u0000]{4,}/gi,
  },
  { type: 'bearer', re: /(?<=\bBearer\s+)[A-Za-z0-9._~+/-]{8,}=*/g },
]

/** Entropie de Shannon par caractère. */
export function entropy(value: string): number {
  const counts = new Map<string, number>()
  for (const c of value) counts.set(c, (counts.get(c) ?? 0) + 1)
  let h = 0
  for (const n of counts.values()) {
    const p = n / value.length
    h -= p * Math.log2(p)
  }
  return h
}

const CANDIDATE_RE = /[A-Za-z0-9+/_=-]{20,}/g

function looksRandom(value: string): boolean {
  if (/^[a-z]+$|^[A-Z]+$|^[0-9]+$/.test(value)) return false
  if (/^[a-z_-]+$/i.test(value)) return false // identifiant ou mot composé
  const classes = [/[a-z]/, /[A-Z]/, /[0-9]/].filter(re => re.test(value)).length
  return classes >= 2 && entropy(value) >= 3.5
}

export interface RedactOptions {
  /** Masque aussi toute chaîne longue et aléatoire (résultats de la catégorie secrets, envoi à l'IA). */
  aggressive?: boolean
}

export interface RedactResult {
  text: string
  found: SecretShape[]
}

/** Masque tout motif de secret connu (et, en mode agressif, toute chaîne aléatoire). */
export function redactText(input: string, opts: RedactOptions = {}): RedactResult {
  const found: SecretShape[] = []
  // Les masques déjà posés sont protégés (idempotence).
  const kept: string[] = []
  // eslint-disable-next-line no-control-regex
  let text = input.replace(/\u0000/g, '').replace(MASK_RE, (m) => {
    kept.push(m)
    return `\u0000${kept.length - 1}\u0000`
  })
  // Chaque masque posé est mis à l'abri : un motif suivant ne le retouche pas.
  const hide = (type: string, m: string) => {
    found.push(secretShape(m, type))
    kept.push(maskToken(type, m.length))
    return `\u0000${kept.length - 1}\u0000`
  }
  for (const p of PATTERNS) text = text.replace(p.re, m => hide(p.type, m))
  if (opts.aggressive) text = text.replace(CANDIDATE_RE, m => (looksRandom(m) ? hide('high-entropy', m) : m))
  // eslint-disable-next-line no-control-regex
  text = text.replace(/\u0000([0-9]+)\u0000/g, (_m, i: string) => kept[Number(i)] ?? '')
  return { text, found }
}

/** Raccourci : texte masqué seulement. */
export function redact(input: string, opts: RedactOptions = {}): string {
  return redactText(input, opts).text
}
