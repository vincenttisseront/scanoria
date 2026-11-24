// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Masquage de la 0.3 (version 1), FIGÉ : il ne sert plus qu'à calculer
// l'entrée de l'empreinte d'un résultat (G19). Le masquage élargi de la 0.4
// (redact.ts) sert à l'affichage, à l'extrait stocké et à l'IA ; s'il
// entrait dans l'empreinte, des résultats déjà triés reviendraient en
// « nouveau » et perdraient leur tri ou leur exception.
//
// NE PAS MODIFIER : toute différence de sortie change des empreintes. Les
// répétitions ouvertes de la 0.3 sont bornées à MAX_REDACT, longueur maximale
// de l'entrée : la sortie est identique.

import { MAX_REDACT, maskToken } from './redact'

const MASK_RE = /\[secret masqué : [a-z0-9-]+, longueur [0-9]+\]/g
const PEM_BEGIN = '-----BEGIN'
const KEY_MARK = 'PRIVATE KEY-----'
const PATTERNS: { type: string, re: RegExp, group?: number }[] = [
  { type: 'private-key', re: new RegExp(`${PEM_BEGIN}[ A-Z0-9]{0,8000}${KEY_MARK}[\\s\\S]*?(?:-----END[ A-Z0-9]{0,8000}${KEY_MARK}|$)`, 'g') },
  { type: 'jwt', re: /eyJ[A-Za-z0-9_-]{5,8000}\.eyJ[A-Za-z0-9_-]{5,8000}\.[A-Za-z0-9_-]{5,8000}/g },
  { type: 'aws-access-key', re: /\b(?:AKIA|ASIA|AGPA|AIDA|AROA)[A-Z0-9]{16}\b/g },
  { type: 'github-token', re: /\b(?:gh[pousr]_[A-Za-z0-9]{30,8000}|github_pat_[A-Za-z0-9_]{30,8000})\b/g },
  { type: 'gitlab-token', re: /\bglpat-[A-Za-z0-9_-]{20,8000}\b/g },
  { type: 'slack-token', re: /\bxox[abposr]-[A-Za-z0-9-]{10,8000}\b/g },
  { type: 'scanoria-token', re: /\bscn_[A-Za-z0-9]{40}\b/g },
  { type: 'api-key', re: /\b(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{16,8000}\b/g },
  // eslint-disable-next-line no-control-regex
  { type: 'url-' + 'password', re: /(\b[a-z][a-z0-9+.-]{0,31}:\/\/[^\s:/@]{1,256}:)([^\s@/\u0000]{1,256})(?=@)/gi, group: 1 },
  {
    type: 'assignment',
    // eslint-disable-next-line no-control-regex
    re: /(\b[A-Za-z0-9_.-]{0,64}?(?:pass(?:word|wd)?|pwd|secret|token|api[_-]?key|apikey|access[_-]?key|private[_-]?key|credential)s?[A-Za-z0-9_.-]{0,64}["']?[ \t]{0,8}(?::=|=>|[:=])[ \t]{0,8}["'`]?)([^\s"'`,;<>\u0000]{4,8000})/gi,
    group: 1,
  },
  { type: 'bearer', re: /(\bBearer[ \t]{1,8})([A-Za-z0-9._~+/-]{8,8000}=*)/g, group: 1 },
]

/** Masquage de la 0.3, non agressif : entrée de l'empreinte seulement. */
export function redactForFingerprint(raw: string): string {
  const input = raw.length > MAX_REDACT ? `${raw.slice(0, MAX_REDACT)}…` : raw
  const kept: string[] = []
  // eslint-disable-next-line no-control-regex
  let text = input.replace(/\u0000/g, '').replace(MASK_RE, (m) => {
    kept.push(m)
    return `\u0000${kept.length - 1}\u0000`
  })
  const hide = (type: string, m: string) => {
    kept.push(maskToken(type, m.length))
    return `\u0000${kept.length - 1}\u0000`
  }
  for (const p of PATTERNS) {
    text = p.group
      ? text.replace(p.re, (_m, prefix: string, value: string) => `${prefix}${hide(p.type, value)}`)
      : text.replace(p.re, m => hide(p.type, m))
  }
  // eslint-disable-next-line no-control-regex
  return text.replace(/\u0000([0-9]+)\u0000/g, (_m, i: string) => kept[Number(i)] ?? '')
}
