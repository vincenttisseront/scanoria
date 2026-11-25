// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Affectation par CODEOWNERS (F6). Le fichier est copié, sans rien exécuter,
// par scanoria-runner depuis l'arbre récupéré dans le conteneur de
// récupération (emplacements standard de GitHub, GitLab et Forgejo), dans
// results/<tâche>/codeowners.txt ; la console le lit ici, borné, et remplit
// findings.owners à l'ingestion.
//
// Syntaxe retenue (commune aux trois forges) :
// - une ligne = un motif puis des responsables (« @login », « @org/equipe »,
//   adresse) ; « # » commente ; « \# » et « \  » échappent ;
// - motifs de type gitignore : « / » initial ou intérieur ancre à la racine,
//   « / » final = contenu d'un dossier, « * » et « ? » dans un segment,
//   « ** » traverse les dossiers ; le DERNIER motif qui correspond l'emporte ;
// - sections GitLab « [Nom] » ou « ^[Nom][n] » suivies de responsables par
//   défaut : chaque section décide de son côté, les responsables s'ajoutent ;
// - non pris en charge et ignorés (signalés) : négation « ! », classes
//   « [ ] », segments « .. », motifs trop longs ou trop riches en jokers.

/** Taille maximale lue : au-delà, le fichier est ignoré (et signalé). */
export const MAX_CODEOWNERS_BYTES = 128 * 1024
export const MAX_RULES = 2000
export const MAX_OWNERS_PER_LINE = 20
/** findings.owners : au plus 20 éléments (contrainte de la migration 013). */
export const MAX_OWNERS = 20
const MAX_PATTERN = 512
const MAX_WILDCARDS = 16
/** « ** » : au plus 3 par motif, pour borner le retour arrière. */
const MAX_GLOBSTARS = 3

/** Emplacements lus par le runner, dans cet ordre (le premier présent gagne). */
export const CODEOWNERS_LOCATIONS = [
  '.github/CODEOWNERS', 'CODEOWNERS', 'docs/CODEOWNERS', '.gitlab/CODEOWNERS', '.forgejo/CODEOWNERS', '.gitea/CODEOWNERS',
] as const

const OWNER_RE = /^(?:@[A-Za-z0-9](?:[A-Za-z0-9._-]{0,99})(?:\/[A-Za-z0-9._-]{1,100})?|[^@\s/]{1,64}@[^@\s/]{1,190})$/

export interface CodeownersRule {
  section: string
  pattern: string
  owners: string[]
  match: (path: string) => boolean
}

export interface ParsedCodeowners {
  rules: CodeownersRule[]
  issues: { line: number, code: 'unsupported' | 'bad-pattern' | 'bad-owner' | 'too-many-rules' | 'parent-segment' }[]
}

/** Un segment de chemin contre un segment de motif (« * » et « ? »), sans expression régulière : O(n·m). */
export function segmentMatch(pattern: string, text: string): boolean {
  let p = 0
  let t = 0
  let star = -1
  let mark = 0
  while (t < text.length) {
    if (p < pattern.length && (pattern[p] === '?' || pattern[p] === text[t])) {
      p++
      t++
    }
    else if (p < pattern.length && pattern[p] === '*') {
      star = p++
      mark = t
    }
    else if (star >= 0) {
      p = star + 1
      t = ++mark
    }
    else {
      return false
    }
  }
  while (p < pattern.length && pattern[p] === '*') p++
  return p === pattern.length
}

/** « ** » seul = zéro ou plusieurs segments ; programmation dynamique bornée par (motif × chemin). */
function segmentsMatch(pat: string[], path: string[]): boolean {
  const memo = new Map<number, boolean>()
  const go = (i: number, j: number): boolean => {
    const key = i * (path.length + 1) + j
    const known = memo.get(key)
    if (known !== undefined) return known
    let r: boolean
    if (i === pat.length) r = j === path.length
    else if (pat[i] === '**') r = go(i + 1, j) || (j < path.length && go(i, j + 1))
    else r = j < path.length && segmentMatch(pat[i]!, path[j]!) && go(i + 1, j + 1)
    memo.set(key, r)
    return r
  }
  return go(0, 0)
}

/**
 * Motif CODEOWNERS → fonction de correspondance sur le chemin relatif. null =
 * refusé. Motif ET chemins viennent du dépôt analysé (données hostiles) :
 * aucune expression régulière n'est construite, la correspondance est en
 * temps polynomial borné, quel que soit le motif.
 */
export function compilePattern(raw: string): ((path: string) => boolean) | null {
  let p = raw
  if (!p || p.length > MAX_PATTERN || p.includes('\0')) return null
  if ((p.match(/[*?]/g) ?? []).length > MAX_WILDCARDS) return null
  if ((p.match(/\*\*/g) ?? []).length > MAX_GLOBSTARS) return null
  if (/[[\]]/.test(p)) return null
  const dirOnly = p.endsWith('/')
  while (p.endsWith('/')) p = p.slice(0, -1)
  const anchored = p.startsWith('/') || p.includes('/')
  while (p.startsWith('/')) p = p.slice(1)
  if (!p) return () => true // « / » ou « * » à la racine : tout le dépôt
  const segs = p.split('/').filter(Boolean).map(s => (s === '**' ? s : s.replace(/\*\*+/g, '*')))
  if (segs.some(s => s === '..' || s === '.')) return null
  const full = [...(anchored ? [] : ['**']), ...segs, ...(dirOnly ? ['*', '**'] : ['**'])]
  return (path: string) => segmentsMatch(full, path.split('/'))
}

/** Découpe une ligne en jetons (espaces), « \ » échappant le caractère suivant. */
function tokens(line: string): string[] {
  const out: string[] = []
  let cur = ''
  for (let i = 0; i < line.length; i++) {
    const c = line[i]!
    if (c === '\\' && i + 1 < line.length) {
      cur += line[++i]
      continue
    }
    if (c === '#') break
    if (c === ' ' || c === '\t') {
      if (cur) out.push(cur)
      cur = ''
      continue
    }
    cur += c
  }
  if (cur) out.push(cur)
  return out
}

const SECTION_RE = /^\^?\[([^\]]{1,100})\](?:\[\d{1,3}\])?$/

export function parseCodeowners(text: string): ParsedCodeowners {
  const parsed: ParsedCodeowners = { rules: [], issues: [] }
  if (text.length > MAX_CODEOWNERS_BYTES) return parsed
  let section = ''
  let defaults: string[] = []
  const lines = text.replace(/^\uFEFF/, '').split(/\r?\n/)
  for (let n = 0; n < lines.length; n++) {
    const line = lines[n]!.trim()
    if (!line || line.startsWith('#')) continue
    const toks = tokens(line)
    if (!toks.length) continue
    // Section GitLab : « [Nom] @defaut » ou « ^[Nom][2] @defaut ».
    const header = toks[0]!.match(SECTION_RE)
    if (header && line.startsWith(toks[0]![0] === '^' ? '^[' : '[')) {
      section = header[1]!.trim().toLowerCase()
      defaults = toks.slice(1).filter(o => OWNER_RE.test(o)).slice(0, MAX_OWNERS_PER_LINE)
      continue
    }
    if (parsed.rules.length >= MAX_RULES) {
      parsed.issues.push({ line: n + 1, code: 'too-many-rules' })
      break
    }
    const [pattern, ...rest] = toks
    if (pattern!.startsWith('!')) {
      parsed.issues.push({ line: n + 1, code: 'unsupported' })
      continue
    }
    if (pattern!.split('/').some(s => s === '..')) {
      parsed.issues.push({ line: n + 1, code: 'parent-segment' })
      continue
    }
    const match = compilePattern(pattern!)
    if (!match) {
      parsed.issues.push({ line: n + 1, code: 'bad-pattern' })
      continue
    }
    const owners = rest.slice(0, MAX_OWNERS_PER_LINE)
    if (owners.some(o => !OWNER_RE.test(o))) parsed.issues.push({ line: n + 1, code: 'bad-owner' })
    const valid = owners.filter(o => OWNER_RE.test(o))
    // Une ligne sans responsable retire la propriété (GitHub), sauf défaut de section (GitLab).
    parsed.rules.push({ section, pattern: pattern!, owners: valid.length || owners.length ? valid : defaults, match })
  }
  return parsed
}

function normalizePath(p: string): string {
  return p.replace(/\\/g, '/').replace(/^\.\//, '').replace(/^\/+/, '')
}

/** Responsables d'un chemin : dernier motif qui correspond dans chaque section, réunis. */
export function ownersFor(parsed: ParsedCodeowners, path: string | null): string[] {
  if (!path || !parsed.rules.length) return []
  const p = normalizePath(path).slice(0, 1024)
  if (!p || p.split('/').includes('..')) return []
  const bySection = new Map<string, string[]>()
  for (const r of parsed.rules) {
    if (r.match(p)) bySection.set(r.section, r.owners)
  }
  const out = new Set<string>()
  for (const owners of bySection.values()) {
    for (const o of owners) {
      out.add(o)
      if (out.size >= MAX_OWNERS) return [...out]
    }
  }
  return [...out]
}
