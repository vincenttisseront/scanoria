// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Masquage des secrets, module unique (CLAUDE.md § 3.5 et § 6.3, F7,
// ARCHITECTURE § 12.6) : la valeur d'un secret n'est jamais stockée ni
// envoyée à l'IA. Un seul moteur (motifs, entropie, idempotence), deux
// présentations :
// - résultats et journaux : « [secret masqué : type, longueur N] » (ce fichier) ;
// - IA : « [REDACTED type=… len=… charset=…] » (server/ai/redact.ts, toujours
//   agressif).
// Les motifs sont l'union des deux jeux de la 0.3 : la règle la plus large.

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

/** Longueur maximale traitée ; au-delà, le texte est tronqué. */
export const MAX_REDACT = 8000

/** Masques déjà posés, dans les deux présentations : jamais remasqués (idempotence). */
const MASK_RE = /\[secret masqué : [a-z0-9-]+, longueur [0-9]+\]|\[REDACTED [^\]\n]{1,80}\]/g

// Motifs construits par morceaux : aucun ne doit ressembler lui-même à un secret.
const PEM_BEGIN = '-----BEGIN'
const KEY_MARK = 'PRIVATE KEY( BLOCK)?-----'

interface Pattern {
  type: string
  re: RegExp
  /** 1 : le groupe 1 est un préfixe conservé, le groupe 2 la valeur masquée. */
  group?: 1
}

// Toutes les expressions sont linéaires (aucune répétition imbriquée, espaces bornés).
const PATTERNS: Pattern[] = [
  { type: 'private-key', re: new RegExp(`${PEM_BEGIN}[ A-Z0-9]{0,40}${KEY_MARK}[\\s\\S]*?(?:-----END[ A-Z0-9]{0,40}${KEY_MARK}|$)`, 'g') },
  { type: 'jwt', re: /eyJ[A-Za-z0-9_-]{5,8192}\.eyJ[A-Za-z0-9_-]{5,8192}\.[A-Za-z0-9_-]{5,8192}/g },
  { type: 'aws-access-key', re: /\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA)[A-Z0-9]{16}\b/g },
  { type: 'github-token', re: /\b(?:gh[pousr]_[A-Za-z0-9]{30,255}|github_pat_[A-Za-z0-9_]{30,255})\b/g },
  { type: 'gitlab-token', re: /\bglpat-[A-Za-z0-9_-]{20,255}\b/g },
  { type: 'slack-token', re: /\bxox[abposr]-[A-Za-z0-9-]{10,255}\b/g },
  { type: 'google-api-key', re: /\bAIza[0-9A-Za-z_-]{35}\b/g },
  { type: 'scanoria-token', re: /\bscn_[A-Za-z0-9]{8,255}\b/g },
  { type: 'api-key', re: /\b(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{16,255}\b/g },
  // Identifiants dans une URL : seul le mot de passe est masqué.
  // eslint-disable-next-line no-control-regex
  { type: 'url-password', re: /(\b[a-z][a-z0-9+.-]{0,31}:\/\/[^\s:/@"'<>]{1,256}:)([^\s@/"'<>\u0000]{1,256})(?=@)/gi, group: 1 },
  // Affectation « clé = valeur » dont le nom évoque un secret (suffixe permis : password_hash = …).
  {
    type: 'assignment',
    // eslint-disable-next-line no-control-regex
    re: /(\b[A-Za-z0-9_.-]{0,64}?(?:pass(?:word|wd)?|pwd|secret|token|api[_-]?key|apikey|access[_-]?key|private[_-]?key|credential)s?[A-Za-z0-9_.-]{0,64}["']?[ \t]{0,8}(?::=|=>|[:=])[ \t]{0,8}["'`]?)([^\s"'`,;<>\u0000]{4,4096})/gi,
    group: 1,
  },
  // Même chose sans suffixe, valeurs courtes et noms « auth », « client_secret » (jeu IA de la 0.3).
  {
    type: 'assignment',
    // eslint-disable-next-line no-control-regex
    re: /(\b[A-Za-z0-9_]{0,40}(?:password|passwd|pwd|secret|token|api[_-]?key|apikey|access[_-]?key|private[_-]?key|client[_-]?secret|credentials?|auth)["']?\s{0,5}(?::=|=>|[:=])\s{0,5}["'`]?)([^\s"'`,;)}\]<>\u0000]{3,4096})/gi,
    group: 1,
  },
  { type: 'authorization', re: /(\b(?:Bearer|Basic|Token)[ \t]{1,8})([A-Za-z0-9._~+/-]{8,4096}=*)/g, group: 1 },
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

const CANDIDATE_RE = /[A-Za-z0-9+/_=-]{20,4096}/g

/**
 * Chaîne aléatoire probable (union des deux critères de la 0.3) : au moins
 * deux classes et entropie ≥ 3,5, ou lettres et chiffres et entropie ≥ 3,3.
 * Jamais un mot ou un identifiant sans chiffre.
 */
export function looksRandom(value: string): boolean {
  if (value.length < 20) return false
  if (/^[a-z]+$|^[A-Z]+$|^[0-9]+$/.test(value)) return false
  if (/^[a-z_-]+$/i.test(value)) return false
  const h = entropy(value)
  const classes = [/[a-z]/, /[A-Z]/, /[0-9]/].filter(re => re.test(value)).length
  if (classes >= 2 && h >= 3.5) return true
  return /[A-Za-z]/.test(value) && /[0-9]/.test(value) && h >= 3.3
}

export interface EngineOptions {
  /** Masque aussi toute chaîne longue et aléatoire. */
  aggressive?: boolean
  /** Présentation d'un secret trouvé. */
  format?: (type: string, value: string) => string
  /** Taille maximale traitée (null : aucune troncature). */
  maxLength?: number | null
}

export interface RedactResult {
  text: string
  found: SecretShape[]
}

/** Moteur commun : remplace chaque secret par sa forme, selon la présentation demandée. */
export function maskSecrets(raw: string, opts: EngineOptions = {}): RedactResult {
  const format = opts.format ?? ((type: string, value: string) => maskToken(type, value.length))
  const max = opts.maxLength === undefined ? MAX_REDACT : opts.maxLength
  const found: SecretShape[] = []
  // Taille bornée avant masquage : coût linéaire garanti.
  const input = max !== null && raw.length > max ? `${raw.slice(0, max)}…` : raw
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
    kept.push(format(type, m))
    return `\u0000${kept.length - 1}\u0000`
  }
  for (const p of PATTERNS) {
    text = p.group
      ? text.replace(p.re, (_m, prefix: string, value: string) => `${prefix}${hide(p.type, value)}`)
      : text.replace(p.re, m => hide(p.type, m))
  }
  if (opts.aggressive) text = text.replace(CANDIDATE_RE, m => (looksRandom(m) ? hide('high-entropy', m) : m))
  // eslint-disable-next-line no-control-regex
  text = text.replace(/\u0000([0-9]+)\u0000/g, (_m, i: string) => kept[Number(i)] ?? '')
  return { text, found }
}

export interface RedactOptions {
  /** Masque aussi toute chaîne longue et aléatoire (résultats de la catégorie secrets, envoi à l'IA). */
  aggressive?: boolean
}

/** Noms des types tels que les résultats les affichent depuis la 0.3. */
const FINDING_TYPES: Record<string, string> = { authorization: 'bearer' }

/** Masque tout motif de secret connu (et, en mode agressif, toute chaîne aléatoire). */
export function redactText(raw: string, opts: RedactOptions = {}): RedactResult {
  const r = maskSecrets(raw, {
    aggressive: opts.aggressive,
    format: (type, value) => maskToken(FINDING_TYPES[type] ?? type, value.length),
  })
  return { text: r.text, found: r.found.map(f => ({ ...f, type: FINDING_TYPES[f.type] ?? f.type })) }
}

/** Raccourci : texte masqué seulement. */
export function redact(input: string, opts: RedactOptions = {}): string {
  return redactText(input, opts).text
}
