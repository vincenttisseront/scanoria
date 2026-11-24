// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Échappement de toute sortie IA (CLAUDE.md § 3.5) : texte brut seulement,
// aucun HTML, aucune image, liens limités à la console et aux références
// connues (CWE, CVE, OSV), mentions (@…, #…) neutralisées pour qu'un texte
// publié plus tard vers une forge ne notifie personne.

const ALLOWED_HOSTS = new Set(['cwe.mitre.org', 'www.cve.org', 'cve.org', 'nvd.nist.gov', 'osv.dev'])
const ZWSP = '\u200B'

// Caractères de contrôle (hors saut de ligne et tabulation), directionnels
// et invisibles susceptibles de tromper un lecteur.
// eslint-disable-next-line no-control-regex
const CONTROL_RE = /[\u0000-\u0008\u000B-\u001F\u007F-\u009F\u200B-\u200F\u202A-\u202E\u2066-\u2069\uFEFF]/g
const TAG_RE = /<\/?[A-Za-z!?][^<>]{0,2000}>/g
const MD_IMAGE_RE = /!\[[^\]]{0,500}\]\([^)]{0,2000}\)/g
const MD_LINK_RE = /\[([^\]]{0,500})\]\(([^)\s]{0,2000})\)/g
const URL_RE = /\b(?:https?|ftp|file|javascript|data|vbscript):[^\s<>()"'`]{0,2000}/gi
const MENTION_RE = /(^|[^\w`])([@#])(?=[\w-])/g

/** Lien permis : chemin de la console, ou https vers une référence connue. */
export function allowedLink(url: string): boolean {
  if (/^\/(?!\/)[A-Za-z0-9/_.?=&%-]{0,500}$/.test(url)) return true
  let u: URL
  try {
    u = new URL(url)
  }
  catch {
    return false
  }
  return u.protocol === 'https:' && ALLOWED_HOSTS.has(u.hostname) && !u.username && !u.password && !u.port
}

/** Texte brut sûr : à afficher tel quel (interpolation Vue) ou à publier. */
export function sanitizeText(input: unknown, maxLength: number): string {
  if (typeof input !== 'string') return ''
  let s = input.normalize('NFC').replace(/\r\n?/g, '\n').replace(CONTROL_RE, '')
  s = s.replace(MD_IMAGE_RE, '')
  s = s.replace(MD_LINK_RE, (_m, label: string, url: string) => (allowedLink(url) ? `${label} (${url})` : label))
  s = s.replace(TAG_RE, '')
  s = s.replace(/[<>]/g, ch => (ch === '<' ? '‹' : '›'))
  s = s.replace(URL_RE, url => (allowedLink(url) ? url : '[link removed]'))
  s = s.replace(MENTION_RE, (_m, pre: string, sigil: string) => `${pre}${sigil}${ZWSP}`)
  s = s.replace(/\n{3,}/g, '\n\n').trim()
  if (s.length > maxLength) s = `${s.slice(0, Math.max(0, maxLength - 1)).trimEnd()}…`
  return s
}

/** Applique sanitizeText à chaque chaîne d'une sortie déjà validée. */
export function sanitizeDeep<T>(value: T, maxLength = 4000): T {
  const walk = (v: unknown): unknown => {
    if (typeof v === 'string') return sanitizeText(v, maxLength)
    if (Array.isArray(v)) return v.map(walk)
    if (v && typeof v === 'object') {
      return Object.fromEntries(Object.entries(v as Record<string, unknown>).map(([k, x]) => [k, walk(x)]))
    }
    return v
  }
  return walk(value) as T
}

/** Références fiables construites depuis les identifiants du résultat, pas depuis l'IA. */
export function referenceLinks(cwe: readonly string[], vulnIds: readonly string[]): { label: string, url: string }[] {
  const out: { label: string, url: string }[] = []
  for (const c of cwe) {
    const m = /^CWE-([0-9]{1,6})$/i.exec(c.trim())
    if (m) out.push({ label: `CWE-${m[1]}`, url: `https://cwe.mitre.org/data/definitions/${m[1]}.html` })
  }
  for (const v of vulnIds) {
    const id = v.trim()
    if (/^CVE-[0-9]{4}-[0-9]{4,9}$/.test(id)) out.push({ label: id, url: `https://www.cve.org/CVERecord?id=${id}` })
    else if (/^(GHSA(-[23456789cfghjmpqrvwx]{4}){3}|MAL-[0-9]{4}-[0-9]{1,9}|[A-Z]{2,10}-[0-9]{4}-[0-9A-Za-z-]{1,40})$/.test(id)) {
      out.push({ label: id, url: `https://osv.dev/vulnerability/${encodeURIComponent(id)}` })
    }
  }
  return out.slice(0, 12)
}
