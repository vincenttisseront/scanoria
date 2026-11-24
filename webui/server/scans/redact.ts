// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Masquage des secrets de la source dans ce que le runner renvoie (messages
// d'erreur, journaux des modules) avant tout stockage ou affichage : la
// valeur exacte du jeton ou de la clé du projet, puis les formes usuelles
// d'un secret dans une sortie git ou HTTP (identifiants dans une URL,
// en-tête Authorization, bloc de clé privée).

export const REDACTED = '[masqué]'

const escape = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')

const PATTERNS: [RegExp, string][] = [
  [/-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z0-9 ]*PRIVATE KEY-----|$)/g, REDACTED],
  [/(\b[a-z][a-z0-9+.-]*:\/\/)[^/\s:@]*:[^/\s@]*@/gi, `$1${REDACTED}@`],
  [/(\b[a-z][a-z0-9+.-]*:\/\/)[^/\s:@]{16,}@/gi, `$1${REDACTED}@`],
  [/\b(authorization|proxy-authorization)(\s*[:=]\s*)(?:(basic|bearer|token)\s+)?\S+/gi, `$1$2$3 ${REDACTED}`],
  [/\b(private-token|x-api-key|x-auth-token)(\s*[:=]\s*)\S+/gi, `$1$2${REDACTED}`],
]

/**
 * Fonction de masquage pour un ensemble de valeurs secrètes. Une clé sur
 * plusieurs lignes est masquée en entier et ligne par ligne.
 */
export function makeRedactor(secrets: (string | null | undefined)[]): (text: string) => string {
  const values = new Set<string>()
  for (const s of secrets) {
    if (!s) continue
    if (s.length >= 6) {
      values.add(s)
      values.add(encodeURIComponent(s))
    }
    for (const line of s.split(/\r?\n/)) {
      const l = line.trim()
      if (l.length >= 12 && !/^-----(BEGIN|END) /.test(l)) values.add(l)
    }
  }
  const exact = [...values].sort((a, b) => b.length - a.length).map(v => new RegExp(escape(v), 'g'))
  return (text: string) => {
    let out = text
    for (const re of exact) out = out.replace(re, REDACTED)
    for (const [re, rep] of PATTERNS) out = out.replace(re, rep)
    return out
  }
}
