// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Normalisation des résultats (ARCHITECTURE § 12.6) : chemins relatifs à la
// racine du dépôt, CWE, identifiants d'avis, paquets, catégorie et empreinte
// stable (G19). Fonctions pures, sans accès à la base.

import { createHash } from 'node:crypto'
import type { Category } from '#shared/analysis'

/** Racines possibles de la source dans le conteneur du scanner (§ 6.4). */
const SOURCE_ROOTS = ['/src/', '/github/workspace/']

/**
 * Chemin relatif à la racine du dépôt, ou null s'il sort du dépôt (« .. »,
 * absolu hors de /src, caractères de contrôle). Un chemin vide donne ''.
 */
export function normalizePath(uri: string | undefined | null, baseUri?: string | null): string | null {
  if (uri === undefined || uri === null) return ''
  let p = String(uri)
  if (p.length > 2048) return null
  if (baseUri && !/^[a-z][a-z0-9+.-]*:/i.test(p) && !p.startsWith('/')) p = `${baseUri.replace(/\/?$/, '/')}${p}`
  if (/^file:/i.test(p)) p = p.replace(/^file:(\/\/[^/]*)?/i, '')
  else if (/^[a-z][a-z0-9+.-]*:/i.test(p)) return null // autre schéma : jamais un fichier du dépôt
  try {
    p = decodeURIComponent(p)
  }
  catch {
    return null
  }
  // eslint-disable-next-line no-control-regex
  if (/[\u0000-\u001f\u007f]/.test(p)) return null
  p = p.replace(/\\/g, '/')
  if (p.startsWith('/')) {
    const root = SOURCE_ROOTS.find(r => p.startsWith(r) || `${p}/` === r)
    if (!root) return null
    p = p.slice(root.length)
  }
  const parts: string[] = []
  for (const seg of p.split('/')) {
    if (seg === '' || seg === '.') continue
    if (seg === '..') return null
    parts.push(seg)
  }
  const out = parts.join('/')
  return out.length > 1024 ? null : out
}

/** Texte affichable : sans caractère de contrôle (hors saut de ligne), borné. */
export function cleanText(value: unknown, max: number): string {
  if (typeof value !== 'string') return ''
  // eslint-disable-next-line no-control-regex
  const s = value.replace(/\r\n?/g, '\n').replace(/[\u0000-\u0008\u000b-\u001f\u007f]/g, '').trim()
  return s.length > max ? `${s.slice(0, max - 1)}…` : s
}

/** Espaces repliés : base du contexte de l'empreinte (insensible à l'indentation). */
export function collapseWhitespace(value: string): string {
  return value.replace(/\s+/g, ' ').trim()
}

const CWE_RE = /\bcwe[-_/:]?\s*([0-9]{1,5})\b/gi

/** « CWE-79 » depuis des étiquettes (« external/cwe/cwe-79 », « CWE-79: … »). */
export function extractCwe(values: unknown[]): string[] {
  const out = new Set<string>()
  const visit = (v: unknown, depth: number) => {
    if (depth > 3 || out.size >= 20) return
    if (typeof v === 'string') {
      for (const m of v.matchAll(CWE_RE)) out.add(`CWE-${Number(m[1])}`)
    }
    else if (typeof v === 'number' && Number.isInteger(v) && v > 0 && v < 100000) {
      out.add(`CWE-${v}`)
    }
    else if (Array.isArray(v)) {
      for (const x of v.slice(0, 50)) visit(x, depth + 1)
    }
  }
  for (const v of values) visit(v, 0)
  return [...out].slice(0, 20)
}

/** Identifiants d'avis reconnus (CVE, GHSA, OSV, MAL-, écosystèmes). */
export const VULN_ID_RE = /\b(?:CVE-[0-9]{4}-[0-9]{4,7}|GHSA(?:-[23456789cfghjmpqrvwx]{4}){3}|MAL-[0-9]{4}-[0-9]{1,7}|OSV-[0-9]{4}-[0-9]{1,7}|PYSEC-[0-9]{4}-[0-9]{1,7}|RUSTSEC-[0-9]{4}-[0-9]{4}|GO-[0-9]{4}-[0-9]{4,7}|GSD-[0-9]{4}-[0-9]{1,7})\b/g

export function isVulnId(value: string): boolean {
  VULN_ID_RE.lastIndex = 0
  const m = VULN_ID_RE.exec(value)
  VULN_ID_RE.lastIndex = 0
  return !!m && m[0] === value
}

export function extractVulnIds(values: unknown[]): string[] {
  const out = new Set<string>()
  const visit = (v: unknown, depth: number) => {
    if (depth > 3 || out.size >= 30) return
    if (typeof v === 'string') {
      for (const m of v.matchAll(VULN_ID_RE)) out.add(m[0])
    }
    else if (Array.isArray(v)) {
      for (const x of v.slice(0, 50)) visit(x, depth + 1)
    }
  }
  for (const v of values) visit(v, 0)
  return [...out].slice(0, 30)
}

/** Avis principal d'un résultat de dépendance : CVE, puis GHSA, puis le premier. */
export function primaryVulnId(ids: string[]): string | null {
  return ids.find(i => i.startsWith('MAL-')) ?? ids.find(i => i.startsWith('CVE-')) ?? ids.find(i => i.startsWith('GHSA-')) ?? ids[0] ?? null
}

export interface PackageRef {
  ecosystem: string | null
  name: string
  version: string | null
  fixed: string[]
}

const LOCKFILES: [RegExp, string][] = [
  [/(^|\/)(package-lock\.json|npm-shrinkwrap\.json|yarn\.lock|pnpm-lock\.yaml|package\.json)$/, 'npm'],
  [/(^|\/)(requirements[^/]*\.txt|poetry\.lock|Pipfile\.lock|uv\.lock|pyproject\.toml)$/, 'PyPI'],
  [/(^|\/)(go\.mod|go\.sum)$/, 'Go'],
  [/(^|\/)(Cargo\.lock|Cargo\.toml)$/, 'crates.io'],
  [/(^|\/)(pom\.xml|gradle\.lockfile|build\.gradle(\.kts)?)$/, 'Maven'],
  [/(^|\/)(Gemfile\.lock|Gemfile)$/, 'RubyGems'],
  [/(^|\/)(composer\.lock|composer\.json)$/, 'Packagist'],
  [/(^|\/)(packages\.lock\.json|[^/]+\.csproj)$/, 'NuGet'],
]

export function ecosystemFromPath(path: string | null): string | null {
  if (!path) return null
  return LOCKFILES.find(([re]) => re.test(path))?.[1] ?? null
}

const PURL_TYPES: Record<string, string> = {
  npm: 'npm', pypi: 'PyPI', golang: 'Go', cargo: 'crates.io', maven: 'Maven', gem: 'RubyGems',
  composer: 'Packagist', nuget: 'NuGet', deb: 'Debian', apk: 'Alpine', rpm: 'RPM', hex: 'Hex', pub: 'Pub',
}

/** « pkg:npm/%40scope/nom@1.2.3?… » → paquet. */
export function parsePurl(purl: unknown): PackageRef | null {
  if (typeof purl !== 'string' || purl.length > 1024) return null
  const m = /^pkg:([a-z0-9.+-]+)\/([^@?#]+)(?:@([^?#]+))?/i.exec(purl)
  if (!m) return null
  let name: string
  let version: string | null
  try {
    name = decodeURIComponent(m[2]!)
    version = m[3] ? decodeURIComponent(m[3]) : null
  }
  catch {
    return null
  }
  const type = m[1]!.toLowerCase()
  return { ecosystem: PURL_TYPES[type] ?? type, name: cleanText(name, 255), version: version ? cleanText(version, 128) : null, fixed: [] }
}

export function splitVersions(value: string | undefined | null): string[] {
  if (!value) return []
  return value.split(/[,;|]\s*|\s+/).map(v => v.trim()).filter(v => /^[0-9A-Za-z][0-9A-Za-z.+:~_-]{0,63}$/.test(v)).slice(0, 10)
}

/** Paquet décrit dans un message de scanner (Trivy, OSV-Scanner, Grype). */
export function packageFromMessage(text: string): PackageRef | null {
  const trivy = /Package:\s*([^\s]+)\s*\n\s*Installed Version:\s*([^\s]+)/i.exec(text)
  if (trivy) {
    const fixed = /Fixed Version:\s*([^\n]*)/i.exec(text)
    return { ecosystem: null, name: cleanText(trivy[1], 255), version: cleanText(trivy[2], 128), fixed: splitVersions(fixed?.[1]) }
  }
  const osv = /Package '((?:@[^/'\s]+\/)?[^@'\s]+)@([^'\s]+)'/.exec(text)
  if (osv) return { ecosystem: null, name: cleanText(osv[1], 255), version: cleanText(osv[2], 128), fixed: [] }
  return null
}

/** Versions corrigées dans le tableau « Fixed Versions » de l'aide d'OSV-Scanner. */
export function fixedFromHelp(markdown: string, name: string): string[] {
  const out = new Set<string>()
  for (const line of markdown.split('\n')) {
    const cells = line.split('|').map(c => c.trim())
    if (cells.length >= 5 && cells[2] === name && isVulnId(cells[1] ?? '')) {
      for (const v of splitVersions(cells[3])) out.add(v)
    }
  }
  return [...out]
}

/** Identifiants codés en dur : mot de passe (259), identifiants (798), clé (321). */
const SECRET_CWES = new Set(['CWE-259', 'CWE-321', 'CWE-798'])

/**
 * Catégorie d'un résultat (findings.category) : déduite des étiquettes, des
 * identifiants d'avis et des catégories déclarées par le module.
 */
export function inferCategory(opts: {
  moduleCategories: string[]
  tags: string[]
  hasVuln: boolean
  hasPackage: boolean
  cwe?: string[]
}): Category | 'quality' {
  const tags = opts.tags.map(t => t.toLowerCase())
  const mod = opts.moduleCategories
  if (opts.cwe?.some(c => SECRET_CWES.has(c))) return 'secrets'
  if (tags.some(t => t === 'secret' || t === 'secrets') || (mod.length && mod.every(c => c === 'secrets'))) return 'secrets'
  if (opts.hasVuln || opts.hasPackage || tags.includes('vulnerability')) return mod.includes('container') && !mod.includes('sca') ? 'container' : 'sca'
  if (tags.some(t => t === 'misconfiguration' || t === 'iac')) return 'iac'
  if (tags.some(t => t === 'license' || t === 'licenses')) return 'licenses'
  const order: Category[] = ['sast', 'iac', 'ci', 'quality', 'lint', 'container', 'dast', 'licenses', 'secrets', 'sca']
  return order.find(c => mod.includes(c)) ?? 'quality'
}

export function sha256(value: string): string {
  return createHash('sha256').update(value, 'utf8').digest('hex')
}

/**
 * Empreinte stable (G19), sans numéro de ligne :
 * - dépendance : outil | écosystème | nom | version | avis ;
 * - partialFingerprints SARIF quand l'outil en fournit (valeurs non vides) ;
 * - sinon outil | règle | chemin | contexte (texte normalisé autour du résultat).
 */
export function fingerprintOf(f: {
  tool: string
  ruleId: string
  path: string | null
  context: string
  pkg: PackageRef | null
  vulnId: string | null
  partial: Record<string, unknown> | null
}): string {
  if (f.pkg && f.vulnId) {
    return sha256(['dep', f.tool, f.pkg.ecosystem ?? '', f.pkg.name, f.pkg.version ?? '', f.vulnId].join('\u001f'))
  }
  const partial = Object.entries(f.partial ?? {})
    .filter(([, v]) => typeof v === 'string' && v !== '')
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
    .map(([k, v]) => `${k}=${String(v)}`)
  if (partial.length) return sha256(['pf', f.tool, f.ruleId, f.path ?? '', ...partial].join('\u001f'))
  return sha256(['ctx', f.tool, f.ruleId, f.path ?? '', collapseWhitespace(f.context)].join('\u001f'))
}
