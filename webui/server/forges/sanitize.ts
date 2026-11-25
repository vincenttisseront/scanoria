// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Contrat 30 : tout texte publié vers une forge passe par sanitizeForForge
// (CLAUDE.md § 3.5). Le texte vient en partie du code analysé ou de l'IA :
// c'est une donnée hostile. Ce module neutralise :
// - les mentions « @… » et les références « #… », « !… » (GitLab), « ~… » ;
// - les images (aucune requête vers un tiers à l'ouverture de la PR) ;
// - le HTML (balises, commentaires, entités) ;
// - les liens, sauf vers la console et vers les références CWE, CVE et OSV ;
// - les URL nues hors de cette liste (rendues inertes : « hxxps:// ») ;
// - le Markdown qui casse la mise en page (bloc de code non fermé, titres et
//   définitions de liens) et les caractères de contrôle.
// Aucune dépendance : le module est aussi chargé seul par tests/b34-forges.sh.

export interface SanitizeOptions {
  /** Origine de la console (https://analyse.exemple.test) : seuls liens libres. */
  consoleUrl?: string | null
  /** Longueur maximale du texte produit (GitHub refuse au-delà de 65 536). */
  maxLength?: number
}

export const MAX_FORGE_TEXT = 60_000
const ZWSP = '​'

/** Références connues acceptées comme liens (§ 3.5) : CWE, CVE, OSV. */
const REFERENCE_LINK_RES: RegExp[] = [
  /^https:\/\/cwe\.mitre\.org\/data\/definitions\/\d{1,6}\.html$/,
  /^https:\/\/www\.cve\.org\/CVERecord\?id=CVE-\d{4}-\d{4,7}$/,
  /^https:\/\/nvd\.nist\.gov\/vuln\/detail\/CVE-\d{4}-\d{4,7}$/,
  /^https:\/\/osv\.dev\/vulnerability\/[A-Za-z0-9][A-Za-z0-9._:-]{1,120}$/,
]

function consoleOrigin(url: string | null | undefined): string | null {
  if (!url) return null
  try {
    const u = new URL(url)
    return u.protocol === 'https:' && !u.username && !u.password ? u.origin : null
  }
  catch {
    return null
  }
}

/** Lien permis : console (même origine, HTTPS) ou référence connue. */
export function allowedLink(url: string, consoleUrl?: string | null): boolean {
  if (REFERENCE_LINK_RES.some(re => re.test(url))) return true
  const origin = consoleOrigin(consoleUrl)
  if (!origin) return false
  try {
    const u = new URL(url)
    return u.origin === origin && !u.username && !u.password && (url === origin || url.startsWith(`${origin}/`))
  }
  catch {
    return false
  }
}

/** Caractères de contrôle (hors \n et \t), bidirectionnels et de largeur nulle hostiles. */
// eslint-disable-next-line no-control-regex
const CONTROL_RE = /[\u0000-\u0008\u000B-\u001F\u007F-\u009F\u061C\u200C-\u200F\u202A-\u202E\u2066-\u2069\uFEFF]/g

function stripControls(s: string): string {
  return s.replace(/\r\n?/g, '\n').replace(CONTROL_RE, '')
}

/**
 * Texte libre inséré dans une ligne de Markdown (message d'un outil, chemin,
 * titre de règle) : une seule ligne, caractères spéciaux échappés, borné.
 */
export function escapeInline(text: unknown, max = 300): string {
  let s = stripControls(typeof text === 'string' ? text : String(text ?? '')).replace(/\s+/g, ' ').trim()
  if (s.length > max) s = `${s.slice(0, max - 1)}…`
  return s.replace(/[\\`*_{}[\]()<>#+\-!|~@&:]/g, c => `\\${c}`)
}

/** Bloc de code sûr : la clôture est plus longue que toute suite de « ` » du texte. */
export function codeBlock(text: string, lang = ''): string {
  const body = stripControls(text)
  const longest = Math.max(2, ...[...body.matchAll(/`+/g)].map(m => m[0].length))
  const fence = '`'.repeat(longest + 1)
  return `${fence}${/^[a-z0-9-]{0,20}$/.test(lang) ? lang : ''}\n${body}\n${fence}`
}

const FENCE_RE = /^ {0,3}(`{3,}|~{3,})/

/** Une ligne hors bloc de code. */
function sanitizeLine(line: string, consoleUrl: string | null | undefined): string {
  let s = line
  // HTML : aucune balise ni entité ne survit (« <!-- », « <img », « &#64; »).
  s = s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
  // Titres de premier niveau et définitions de liens de référence : neutralisés.
  s = s.replace(/^( {0,3})(\[[^\]]*\]:)/, '$1\\$2')
  // Images : le « ! » devant « [ » est échappé (le texte reste, aucune requête).
  s = s.replace(/!(?=\[)/g, '\\!')
  // Liens Markdown [texte](url) : gardés seulement vers une adresse permise.
  s = s.replace(/\[([^\]\n]{0,500})\]\(\s*([^()\s]{1,2000})(?:\s+"[^"]*")?\s*\)/g, (_m, label: string, url: string) =>
    allowedLink(url, consoleUrl) ? `[${label}](${url})` : `${label} (${defang(url)})`)
  // URL nues hors liste : rendues inertes (aucun lien automatique).
  s = s.replace(/(?<![(\w])(https?|ftp|ftps|file|javascript|data|mailto):(\/\/)?([^\s<>()]*)/gi, (m: string) => {
    if (allowedLink(m, consoleUrl)) return m
    return defang(m)
  })
  s = s.replace(/\bwww\.(?=[A-Za-z0-9-]+\.)/gi, `www${ZWSP}.`)
  // Mentions et références de la forge : rendues inertes par une espace de largeur nulle.
  s = s.replace(/(^|[^\w`])([@#!~$%])(?=[\w.-])/g, (_m, pre: string, sym: string) => `${pre}${sym}${ZWSP}`)
  s = s.replace(/&(?=\d)/g, `&${ZWSP}`)
  // Références croisées « dépôt#12 » et « dépôt!3 ».
  s = s.replace(/([\w.-])([#!])(?=\d)/g, `$1$2${ZWSP}`)
  return s
}

/** Neutralise une URL : schéma altéré, jamais cliquable. */
function defang(url: string): string {
  return url
    .replace(/^https?:/i, m => (m.toLowerCase() === 'https:' ? 'hxxps:' : 'hxxp:'))
    .replace(/^(ftp|ftps|file|javascript|data|mailto):/i, (_m, p: string) => `${p.toLowerCase()}[:]`)
    .replace(/\./g, '[.]')
}

/**
 * Contrat 30 : texte Markdown prêt à publier dans une forge. Les blocs de code
 * gardent leur contenu (déjà inerte), sauf les caractères de contrôle, et un
 * bloc resté ouvert est refermé ; le texte est borné.
 */
export function sanitizeForForge(markdown: string, opts: SanitizeOptions = {}): string {
  const max = Math.min(opts.maxLength ?? MAX_FORGE_TEXT, MAX_FORGE_TEXT)
  const lines = stripControls(typeof markdown === 'string' ? markdown : '').split('\n')
  const out: string[] = []
  let fence: string | null = null
  for (const line of lines) {
    const f = FENCE_RE.exec(line)
    if (fence) {
      out.push(line)
      if (f && f[1]![0] === fence[0] && f[1]!.length >= fence.length && line.trim() === f[1]) fence = null
      continue
    }
    if (f) {
      fence = f[1]!
      // Info du bloc limitée à un nom de langage.
      out.push(`${line.slice(0, line.indexOf(fence) + fence.length)}${/^[a-z0-9-]{0,20}$/.test(line.slice(line.indexOf(fence) + fence.length).trim()) ? line.slice(line.indexOf(fence) + fence.length).trim() : ''}`)
      continue
    }
    out.push(sanitizeLine(line, opts.consoleUrl))
  }
  if (fence) out.push(fence)
  let text = out.join('\n')
  if (text.length > max) {
    const note = '\n\n… (texte tronqué / text truncated)'
    text = text.slice(0, max - note.length)
    // Un bloc de code coupé est refermé.
    const opened = text.split('\n').filter(l => FENCE_RE.test(l)).length % 2 === 1
    text = `${text}${opened ? '\n```' : ''}${note}`
  }
  return text
}
