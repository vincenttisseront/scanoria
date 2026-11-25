// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Reprise de l'existant (J5) : les configurations d'exceptions déjà présentes
// dans un dépôt deviennent des DEMANDES d'exception (requested_via
// « tool-import »), motif « importé », date de fin par défaut. Chaque lecteur
// est pur, borné et ne lève jamais : une entrée qu'il ne sait pas traduire
// fidèlement est écartée et signalée, jamais élargie.
// Formats : .gitleaks.toml (allowlist), .gitleaksignore, .trivyignore et
// .trivyignore.yaml, osv-scanner.toml, .semgrepignore, « # nosec » (Bandit),
// sonar-project.properties (exclusions, règles ignorées), .checkov.yaml,
// .hadolint.yaml, .bandit.

import { parse as parseToml } from 'smol-toml'
import { isValidDay } from '../findings/exceptions'
import type { ExceptionRequestInput } from '../profiles/requests'
import { parseSafeYaml } from '../config/yaml'

export const IMPORT_FILES = [
  '.gitleaks.toml', '.gitleaksignore', '.trivyignore', '.trivyignore.yaml', 'osv-scanner.toml', '.semgrepignore',
  'sonar-project.properties', '.checkov.yaml', '.checkov.yml', '.hadolint.yaml', '.hadolint.yml', '.bandit',
] as const
export type ImportFile = (typeof IMPORT_FILES)[number] | 'nosec'

/** Taille maximale lue par fichier. */
export const IMPORT_FILE_MAX_BYTES = 256 * 1024
const MAX_LINES = 2000

export interface ImportedRequest extends ExceptionRequestInput {
  /** Fichier d'origine et ligne (affichés dans l'aperçu). */
  source: string
}

export interface ParsedImport {
  requests: ImportedRequest[]
  /** Entrées non traduites (motif exact non représentable, format inconnu). */
  unsupported: { source: string, entry: string }[]
}

const VULN_RE = /^(CVE-\d{4}-\d{4,}|GHSA(-[23456789cfghjmpqrvwx]{4}){3}|PYSEC-\d{4}-\d+|GO-\d{4}-\d+|RUSTSEC-\d{4}-\d+|OSV-\d{4}-\d+|[A-Z]{2,10}-\d{4}-[A-Za-z0-9.-]+)$/
const RULE_RE = /^[A-Za-z0-9._:/-]{1,255}$/
const GLOB_RE = /^[A-Za-z0-9._@+*?/-]{1,512}$/

const reasonOf = (file: string, extra?: string | null) => {
  const r = `importé (${file})${extra ? ` : ${extra.trim().replace(/\s+/g, ' ')}` : ''}`
  return r.slice(0, 2000)
}

const clampUntil = (until: string | null | undefined, fallback: string): string =>
  until && isValidDay(until) && until < fallback ? until : fallback

/** Glob sûr d'un chemin : relatif, sans « .. », sans caractère exotique. */
export function safeGlob(raw: string): string | null {
  let g = raw.trim().replace(/^\.\//, '')
  if (g.startsWith('/')) g = g.slice(1)
  if (g.endsWith('/')) g = `${g}**`
  if (!g || !GLOB_RE.test(g) || g.split('/').includes('..')) return null
  // « * » ou « ** » seuls : tout le dépôt, jamais importé.
  if (/^\*+(\/\*+)*$/.test(g)) return null
  return g
}

/**
 * Traduit une expression régulière de chemin de gitleaks en glob, seulement
 * quand la traduction est exacte : littéraux, « \\. », « .* » (→ « ** »,
 * qui traverse les dossiers), ancres ^ et $. Une expression non ancrée
 * cherche n'importe où : « ** » est ajouté du côté libre. Tout le reste
 * (classes, groupes, alternatives, « . » seul) donne null : l'entrée est
 * signalée, jamais élargie.
 */
export function regexToGlob(re: string): string | null {
  let s = re.trim()
  const anchoredStart = s.startsWith('^')
  if (anchoredStart) s = s.slice(1)
  const anchoredEnd = s.endsWith('$') && !s.endsWith('\\$')
  if (anchoredEnd) s = s.slice(0, -1)
  let out = ''
  for (let i = 0; i < s.length;) {
    const wild = ['(.*?)', '(.*)', '.*?', '.*'].find(w => s.startsWith(w, i))
    if (wild) {
      out += '**'
      i += wild.length
      continue
    }
    const c = s[i]!
    if (c === '\\') {
      const n = s[i + 1]
      if (n && /[./_@+-]/.test(n)) {
        out += n
        i += 2
        continue
      }
      return null
    }
    if (/[A-Za-z0-9_/@+-]/.test(c)) {
      out += c
      i++
      continue
    }
    return null
  }
  if (!out) return null
  const glob = `${anchoredStart || out.startsWith('**') ? '' : '**'}${out}${anchoredEnd || out.endsWith('**') ? '' : '**'}`.replace(/\*{3,}/g, '**')
  return safeGlob(glob)
}

const lines = (text: string) => text.split(/\r?\n/).slice(0, MAX_LINES)

const pathReq = (glob: string, tool: string | undefined, file: string, until: string, extra?: string | null, line?: number): ImportedRequest => ({
  kind: 'path', target: { glob, ...(tool ? { tool } : {}) }, reason: reasonOf(file, extra), expires_on: until, source: line ? `${file}:${line}` : file,
})
const ruleReq = (rule: string, tool: string, file: string, until: string, extra?: string | null, line?: number): ImportedRequest => ({
  kind: 'rule', target: { rule_id: rule, tool }, reason: reasonOf(file, extra), expires_on: until, source: line ? `${file}:${line}` : file,
})
const vulnReq = (vuln: string, file: string, until: string, extra?: string | null, line?: number, pkg?: string): ImportedRequest => ({
  kind: 'vuln', target: { vuln_id: vuln, ...(pkg ? { package: pkg } : {}) }, reason: reasonOf(file, extra), expires_on: until, source: line ? `${file}:${line}` : file,
})

function safeToml(text: string): Record<string, unknown> | null {
  try {
    const v = parseToml(text, { maxDepth: 16 })
    return v && typeof v === 'object' ? v as Record<string, unknown> : null
  }
  catch {
    return null
  }
}

const strings = (v: unknown, max = 500): string[] => (Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string').slice(0, max) : [])

function gitleaksToml(text: string, until: string): ParsedImport {
  const out: ParsedImport = { requests: [], unsupported: [] }
  const doc = safeToml(text)
  if (!doc) return { requests: [], unsupported: [{ source: '.gitleaks.toml', entry: 'unreadable TOML' }] }
  const lists = [doc.allowlist, ...(Array.isArray(doc.allowlists) ? doc.allowlists : [])].filter((x): x is Record<string, unknown> => !!x && typeof x === 'object')
  for (const l of lists.slice(0, 50)) {
    const desc = typeof l.description === 'string' ? l.description.slice(0, 200) : null
    const rules = strings(l.targetRules ?? l.rules)
    for (const p of strings(l.paths)) {
      const glob = regexToGlob(p)
      if (!glob) {
        out.unsupported.push({ source: '.gitleaks.toml', entry: `paths: ${p.slice(0, 120)}` })
        continue
      }
      if (rules.length) for (const r of rules) out.requests.push({ ...pathReq(glob, 'gitleaks', '.gitleaks.toml', until, desc ? `${desc} (${r})` : r) })
      else out.requests.push(pathReq(glob, 'gitleaks', '.gitleaks.toml', until, desc))
    }
    for (const r of strings(l.regexes)) out.unsupported.push({ source: '.gitleaks.toml', entry: `regexes: ${r.slice(0, 120)}` })
    for (const c of strings(l.commits)) out.unsupported.push({ source: '.gitleaks.toml', entry: `commits: ${c.slice(0, 64)}` })
    for (const s of strings(l.stopwords)) out.unsupported.push({ source: '.gitleaks.toml', entry: `stopwords: ${s.slice(0, 64)}` })
  }
  return out
}

function gitleaksIgnore(text: string, until: string): ParsedImport {
  const out: ParsedImport = { requests: [], unsupported: [] }
  for (const [i, raw] of lines(text).entries()) {
    const l = raw.trim()
    if (!l || l.startsWith('#')) continue
    // Empreinte gitleaks : [commit:]fichier:règle:ligne.
    const parts = l.split(':')
    const file = parts.length >= 4 ? parts.slice(1, -2).join(':') : parts.length === 3 ? parts[0]! : null
    const rule = parts.length >= 3 ? parts[parts.length - 2]! : null
    const glob = file ? safeGlob(file) : null
    if (!glob || !rule || !RULE_RE.test(rule)) {
      out.unsupported.push({ source: `.gitleaksignore:${i + 1}`, entry: l.slice(0, 120) })
      continue
    }
    out.requests.push(pathReq(glob, 'gitleaks', '.gitleaksignore', until, rule, i + 1))
  }
  return out
}

function trivyIgnore(text: string, until: string): ParsedImport {
  const out: ParsedImport = { requests: [], unsupported: [] }
  let comment: string | null = null
  for (const [i, raw] of lines(text).entries()) {
    const l = raw.trim()
    if (!l) {
      comment = null
      continue
    }
    if (l.startsWith('#')) {
      comment = l.replace(/^#+\s*/, '').slice(0, 300) || null
      continue
    }
    const [id, ...rest] = l.split(/\s+/)
    const exp = rest.map(r => /^exp:(\d{4}-\d{2}-\d{2})$/.exec(r)?.[1]).find(Boolean) ?? null
    const end = clampUntil(exp, until)
    if (id && VULN_RE.test(id)) out.requests.push(vulnReq(id, '.trivyignore', end, comment, i + 1))
    else if (id && /^(AVD-[A-Z0-9]+-\d+|[A-Z]{2,6}-\d{3,5}|[a-z0-9-]{3,64})$/.test(id)) out.requests.push(ruleReq(id, 'trivy', '.trivyignore', end, comment, i + 1))
    else out.unsupported.push({ source: `.trivyignore:${i + 1}`, entry: l.slice(0, 120) })
    comment = null
  }
  return out
}

function trivyIgnoreYaml(text: string, until: string): ParsedImport {
  const out: ParsedImport = { requests: [], unsupported: [] }
  const doc = parseSafeYaml(text, IMPORT_FILE_MAX_BYTES)
  if (!doc.ok || !doc.value || typeof doc.value !== 'object') return { requests: [], unsupported: [{ source: '.trivyignore.yaml', entry: 'unreadable YAML' }] }
  const v = doc.value as Record<string, unknown>
  for (const section of ['vulnerabilities', 'misconfigurations', 'secrets', 'licenses'] as const) {
    const list = Array.isArray(v[section]) ? (v[section] as unknown[]).slice(0, 500) : []
    for (const e of list) {
      const o = (e && typeof e === 'object' ? e : {}) as Record<string, unknown>
      const id = typeof o.id === 'string' ? o.id : null
      const end = clampUntil(typeof o.expired_at === 'string' ? o.expired_at.slice(0, 10) : null, until)
      const why = typeof o.statement === 'string' ? o.statement.slice(0, 300) : null
      const paths = strings(o.paths, 50)
      if (!id) {
        out.unsupported.push({ source: `.trivyignore.yaml:${section}`, entry: JSON.stringify(o).slice(0, 120) })
        continue
      }
      if (section === 'licenses') {
        out.unsupported.push({ source: '.trivyignore.yaml:licenses', entry: id.slice(0, 120) })
        continue
      }
      if (paths.length) {
        // Exception par chemin pour Trivy seulement (l'avis précis reste visible pour les autres outils).
        for (const p of paths) {
          const glob = safeGlob(p)
          if (glob) out.requests.push(pathReq(glob, 'trivy', '.trivyignore.yaml', end, why ? `${id} : ${why}` : id))
          else out.unsupported.push({ source: '.trivyignore.yaml', entry: `${id} ${p}`.slice(0, 120) })
        }
      }
      else if (section === 'vulnerabilities' && VULN_RE.test(id)) out.requests.push(vulnReq(id, '.trivyignore.yaml', end, why))
      else if (RULE_RE.test(id)) out.requests.push(ruleReq(id, 'trivy', '.trivyignore.yaml', end, why))
    }
  }
  return out
}

function osvToml(text: string, until: string): ParsedImport {
  const out: ParsedImport = { requests: [], unsupported: [] }
  const doc = safeToml(text)
  if (!doc) return { requests: [], unsupported: [{ source: 'osv-scanner.toml', entry: 'unreadable TOML' }] }
  for (const e of (Array.isArray(doc.IgnoredVulns) ? doc.IgnoredVulns : []).slice(0, 500)) {
    const o = (e && typeof e === 'object' ? e : {}) as Record<string, unknown>
    const id = typeof o.id === 'string' ? o.id : null
    const rawUntil = o.ignoreUntil instanceof Date ? o.ignoreUntil.toISOString().slice(0, 10) : typeof o.ignoreUntil === 'string' ? o.ignoreUntil.slice(0, 10) : null
    if (!id || !VULN_RE.test(id)) {
      out.unsupported.push({ source: 'osv-scanner.toml', entry: String(id ?? JSON.stringify(o)).slice(0, 120) })
      continue
    }
    out.requests.push(vulnReq(id, 'osv-scanner.toml', clampUntil(rawUntil, until), typeof o.reason === 'string' ? o.reason.slice(0, 300) : null))
  }
  for (const e of (Array.isArray(doc.PackageOverrides) ? doc.PackageOverrides : []).slice(0, 100)) {
    out.unsupported.push({ source: 'osv-scanner.toml', entry: `PackageOverrides ${JSON.stringify(e).slice(0, 100)}` })
  }
  return out
}

/** .semgrepignore : syntaxe de .gitignore ; une négation (« ! ») n'est pas représentable. */
function semgrepIgnore(text: string, until: string, tools: string[]): ParsedImport {
  const out: ParsedImport = { requests: [], unsupported: [] }
  for (const [i, raw] of lines(text).entries()) {
    const l = raw.trim()
    if (!l || l.startsWith('#')) continue
    if (l.startsWith('!') || l.startsWith(':include')) {
      out.unsupported.push({ source: `.semgrepignore:${i + 1}`, entry: l.slice(0, 120) })
      continue
    }
    const anchored = l.startsWith('/') || l.slice(0, -1).includes('/')
    const g = safeGlob(anchored ? l : `**/${l}${l.endsWith('/') || l.includes('*') ? '' : '/**'}`)
    if (!g) {
      out.unsupported.push({ source: `.semgrepignore:${i + 1}`, entry: l.slice(0, 120) })
      continue
    }
    for (const tool of tools) out.requests.push(pathReq(g, tool, '.semgrepignore', until, null, i + 1))
  }
  return out
}

/** sonar-project.properties : sonar.exclusions et sonar.issue.ignore.multicriteria. */
function sonarProperties(text: string, until: string): ParsedImport {
  const out: ParsedImport = { requests: [], unsupported: [] }
  const props = new Map<string, string>()
  let cont = ''
  for (const raw of lines(text)) {
    const l = cont + raw.trim()
    if (l.endsWith('\\')) {
      cont = l.slice(0, -1)
      continue
    }
    cont = ''
    if (!l || l.startsWith('#') || l.startsWith('!')) continue
    const m = /^([^=:\s]+)\s*[=:]\s*(.*)$/.exec(l)
    if (m) props.set(m[1]!, m[2]!)
  }
  // sonar.coverage.exclusions ne touche que la couverture de tests : sans effet sur les résultats, non repris.
  const key = 'sonar.exclusions'
  for (const p of (props.get(key) ?? '').split(',').map(s => s.trim()).filter(Boolean).slice(0, 200)) {
    const g = safeGlob(p)
    if (g) out.requests.push(pathReq(g, 'sonar-scanner', 'sonar-project.properties', until, key))
    else out.unsupported.push({ source: 'sonar-project.properties', entry: `${key}=${p}`.slice(0, 120) })
  }
  for (const id of (props.get('sonar.issue.ignore.multicriteria') ?? '').split(',').map(s => s.trim()).filter(Boolean).slice(0, 100)) {
    const rule = props.get(`sonar.issue.ignore.multicriteria.${id}.ruleKey`)?.trim()
    const res = props.get(`sonar.issue.ignore.multicriteria.${id}.resourceKey`)?.trim()
    if (!rule || !RULE_RE.test(rule) || rule.includes('*')) {
      out.unsupported.push({ source: 'sonar-project.properties', entry: `multicriteria ${id}` })
      continue
    }
    const glob = res && res !== '**/*' && res !== '**' ? safeGlob(res) : null
    if (res && res !== '**/*' && res !== '**' && !glob) {
      out.unsupported.push({ source: 'sonar-project.properties', entry: `multicriteria ${id}: ${res}`.slice(0, 120) })
      continue
    }
    // Règle limitée à des fichiers : non représentable exactement (règle OU chemin) ; seule la règle globale est importée.
    if (glob) out.unsupported.push({ source: 'sonar-project.properties', entry: `multicriteria ${id}: ${rule} on ${res}`.slice(0, 120) })
    else out.requests.push(ruleReq(rule, 'sonar-scanner', 'sonar-project.properties', until, `multicriteria ${id}`))
  }
  return out
}

function yamlList(file: string, text: string, key: string | string[], tool: string, until: string): ParsedImport {
  const out: ParsedImport = { requests: [], unsupported: [] }
  const doc = parseSafeYaml(text, IMPORT_FILE_MAX_BYTES)
  if (!doc.ok || !doc.value || typeof doc.value !== 'object') return { requests: [], unsupported: [{ source: file, entry: 'unreadable YAML' }] }
  const v = doc.value as Record<string, unknown>
  for (const k of Array.isArray(key) ? key : [key]) {
    const raw = v[k]
    const list = typeof raw === 'string' ? raw.split(',') : strings(raw)
    for (const r of list.map(s => s.trim()).filter(Boolean)) {
      if (RULE_RE.test(r) && !r.includes('*')) out.requests.push(ruleReq(r, tool, file, until, k))
      else out.unsupported.push({ source: file, entry: `${k}: ${r}`.slice(0, 120) })
    }
  }
  return out
}

/** .bandit : INI (« [bandit] skips = B101,B602 ») ou YAML (« skips: [B101] »). */
function banditConfig(text: string, until: string): ParsedImport {
  const ini = /^\s*skips\s*[=:]\s*(.+)$/m.exec(text)
  if (ini && !/^\s*\[/.test(ini[1]!)) {
    const out: ParsedImport = { requests: [], unsupported: [] }
    for (const r of ini[1]!.split(',').map(s => s.trim()).filter(Boolean).slice(0, 200)) {
      if (/^B\d{3}$/.test(r)) out.requests.push(ruleReq(r, 'bandit', '.bandit', until, 'skips'))
      else out.unsupported.push({ source: '.bandit', entry: r.slice(0, 64) })
    }
    return out
  }
  return yamlList('.bandit', text, 'skips', 'bandit', until)
}

/**
 * « # nosec » (Bandit) dans un fichier Python : la ligne n'est pas
 * représentable (exception par règle ou par chemin) ; on demande une exception
 * de chemin Bandit pour le fichier, limitée aux règles citées quand il y en a.
 */
export function nosecRequests(path: string, text: string, until: string): ParsedImport {
  const out: ParsedImport = { requests: [], unsupported: [] }
  const glob = safeGlob(path)
  if (!glob) return out
  const rules = new Set<string>()
  let bare = 0
  for (const raw of lines(text)) {
    const m = /#\s*nosec\b[:\s]*([A-Z0-9, ]*)/.exec(raw)
    if (!m) continue
    const ids = (m[1] ?? '').split(/[,\s]+/).filter(x => /^B\d{3}$/.test(x))
    if (ids.length) for (const id of ids) rules.add(id)
    else bare++
  }
  if (!rules.size && !bare) return out
  out.requests.push(pathReq(glob, 'bandit', '# nosec', until, `${path}${rules.size ? ` (${[...rules].sort().join(', ')})` : ''}`))
  return out
}

/** Lecture d'un fichier repéré du dépôt. */
export function parseImportFile(file: ImportFile, text: string, until: string, opts: { semgrepTools?: string[] } = {}): ParsedImport {
  if (Buffer.byteLength(text, 'utf8') > IMPORT_FILE_MAX_BYTES) return { requests: [], unsupported: [{ source: file, entry: 'file too large' }] }
  switch (file) {
    case '.gitleaks.toml': return gitleaksToml(text, until)
    case '.gitleaksignore': return gitleaksIgnore(text, until)
    case '.trivyignore': return trivyIgnore(text, until)
    case '.trivyignore.yaml': return trivyIgnoreYaml(text, until)
    case 'osv-scanner.toml': return osvToml(text, until)
    case '.semgrepignore': return semgrepIgnore(text, until, opts.semgrepTools ?? ['opengrep', 'semgrep'])
    case 'sonar-project.properties': return sonarProperties(text, until)
    case '.checkov.yaml':
    case '.checkov.yml': return yamlList(file, text, ['skip-check', 'skip_check'], 'checkov', until)
    case '.hadolint.yaml':
    case '.hadolint.yml': return yamlList(file, text, 'ignored', 'hadolint', until)
    case '.bandit': return banditConfig(text, until)
    case 'nosec': return { requests: [], unsupported: [] }
  }
}
