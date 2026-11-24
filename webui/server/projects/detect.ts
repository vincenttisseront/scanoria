// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Assistant d'ajout de dépôt (F1) : détection sans clone, à partir de l'arbre
// et de quelques fichiers lus par l'API de la forge (lecture bornée). Le
// résultat va dans projects.detection et explique chaque décision : langages,
// gestionnaires de paquets et verrouillages, conteneurs, IaC, CI, licence,
// catégories à couvrir, profil, modules pertinents installés ou à installer.
// Rien n'est installé ici : la console propose, une personne confirme.

import type { Category } from '#shared/analysis'
import type { ForgeTree, TreeEntry } from '../forges/types'

export const DETECTION_VERSION = 1

export interface PackageManager {
  name: string
  manifest: string
  lockfile: string | null
}

export interface CiWorkflow {
  kind: 'github-actions' | 'forgejo-actions' | 'gitlab-ci' | 'jenkins'
  path: string
}

export type ModuleReason
  = | 'always' | 'languages' | 'lockfiles' | 'containers' | 'iac' | 'workflows' | 'shell' | 'python' | 'category'

export interface SuggestedModule {
  id: string
  name: string
  categories: string[]
  installed: boolean
  enabled: boolean
  reason: ModuleReason
}

export interface Detection {
  version: typeof DETECTION_VERSION
  analyzed_at: string
  ref: string | null
  commit: string | null
  /** Arbre trop grand ou tronqué par la forge : détection partielle. */
  truncated: boolean
  files: number
  languages: string[]
  language_files: Record<string, number>
  package_managers: PackageManager[]
  /** Manifestes sans fichier de verrouillage (couverture SCA incomplète, G15). */
  missing_lockfiles: string[]
  containers: string[]
  iac: { terraform: boolean, kubernetes: boolean, helm: boolean, ansible: boolean }
  ci: CiWorkflow[]
  shell_scripts: number
  license: { spdx: string, source: string } | null
  categories: Category[]
  /** Profil du projet (analyses planifiées et manuelles) et profil des PR (G9, 0.7). */
  profile: 'complet'
  pr_profile: 'rapide'
  modules: SuggestedModule[]
  /** Catégories utiles au dépôt pour lesquelles le catalogue n'a aucun module. */
  coverage_gaps: Category[]
}

const IGNORED_DIR_RE = /(^|\/)(node_modules|vendor|third_party|\.git|dist|build|target|\.venv|venv|__pycache__|bower_components)\//

const LANGUAGE_EXT: Record<string, string> = {
  js: 'javascript', mjs: 'javascript', cjs: 'javascript', jsx: 'javascript', vue: 'javascript', svelte: 'javascript',
  ts: 'typescript', tsx: 'typescript', mts: 'typescript', cts: 'typescript',
  py: 'python', pyi: 'python',
  go: 'go',
  java: 'java',
  kt: 'kotlin', kts: 'kotlin',
  scala: 'scala',
  groovy: 'groovy',
  rb: 'ruby',
  php: 'php',
  cs: 'csharp',
  fs: 'fsharp',
  vb: 'vbnet',
  rs: 'rust',
  c: 'c', h: 'c',
  cc: 'cpp', cpp: 'cpp', cxx: 'cpp', hpp: 'cpp', hh: 'cpp',
  swift: 'swift',
  m: 'objective-c',
  dart: 'dart',
  ex: 'elixir', exs: 'elixir',
  erl: 'erlang',
  lua: 'lua',
  pl: 'perl', pm: 'perl',
  r: 'r',
  sh: 'shell', bash: 'shell', zsh: 'shell', ksh: 'shell',
  ps1: 'powershell', psm1: 'powershell',
  sql: 'sql',
  tf: 'hcl', hcl: 'hcl',
}

/** Manifeste → fichiers de verrouillage possibles (le premier trouvé gagne). */
const MANIFESTS: { file: RegExp, locks: { file: string, name: string }[], name: string }[] = [
  { file: /^package\.json$/, name: 'npm', locks: [
    { file: 'package-lock.json', name: 'npm' }, { file: 'npm-shrinkwrap.json', name: 'npm' },
    { file: 'yarn.lock', name: 'yarn' }, { file: 'pnpm-lock.yaml', name: 'pnpm' }, { file: 'bun.lock', name: 'npm' },
  ] },
  { file: /^pyproject\.toml$/, name: 'pip', locks: [
    { file: 'poetry.lock', name: 'poetry' }, { file: 'uv.lock', name: 'uv' }, { file: 'pdm.lock', name: 'pip' },
  ] },
  { file: /^requirements(-[a-z0-9_-]+)?\.txt$/, name: 'pip', locks: [] },
  { file: /^Pipfile$/, name: 'pipenv', locks: [{ file: 'Pipfile.lock', name: 'pipenv' }] },
  { file: /^go\.mod$/, name: 'go', locks: [{ file: 'go.sum', name: 'go' }] },
  { file: /^pom\.xml$/, name: 'maven', locks: [] },
  { file: /^build\.gradle(\.kts)?$/, name: 'gradle', locks: [{ file: 'gradle.lockfile', name: 'gradle' }] },
  { file: /^Cargo\.toml$/, name: 'cargo', locks: [{ file: 'Cargo.lock', name: 'cargo' }] },
  { file: /^composer\.json$/, name: 'composer', locks: [{ file: 'composer.lock', name: 'composer' }] },
  { file: /^Gemfile$/, name: 'bundler', locks: [{ file: 'Gemfile.lock', name: 'bundler' }] },
  { file: /^.+\.csproj$/, name: 'nuget', locks: [{ file: 'packages.lock.json', name: 'nuget' }] },
]

/**
 * requirements.txt épinglé (« == » partout) compte comme verrouillé : OSV et
 * Trivy y lisent des versions exactes.
 */
function requirementsPinned(text: string | null): boolean {
  if (!text) return false
  const lines = text.split(/\r?\n/).map(l => l.replace(/#.*/, '').trim()).filter(l => l && !l.startsWith('-'))
  return lines.length > 0 && lines.every(l => /==/.test(l))
}

const LICENSE_FILE_RE = /^(LICEN[CS]E|COPYING)(\.(md|txt|rst))?$/i

/** Reconnaissance de licence par des phrases caractéristiques (texte normalisé). */
const LICENSE_PATTERNS: [string, RegExp][] = [
  ['AGPL-3.0', /gnu affero general public license\s+version 3/],
  ['LGPL-3.0', /gnu lesser general public license\s+version 3/],
  ['LGPL-2.1', /gnu lesser general public license\s+version 2\.1/],
  ['GPL-3.0', /gnu general public license\s+version 3/],
  ['GPL-2.0', /gnu general public license\s+version 2/],
  ['Apache-2.0', /apache license,?\s+version 2\.0/],
  ['MPL-2.0', /mozilla public license,?\s+(version|v\.?)\s*2\.0/],
  ['BSD-3-Clause', /neither the name of .{1,200}? nor the names of its\s+contributors/],
  ['BSD-2-Clause', /redistributions in binary form must reproduce the above copyright notice/],
  ['MIT', /permission is hereby granted, free of charge, to any person obtaining a copy/],
  ['ISC', /permission to use, copy, modify, and\/or distribute this software for any/],
  ['Unlicense', /this is free and unencumbered software released into the public domain/],
  ['EUPL-1.2', /european union public licen[cs]e\s+v\.?\s*1\.2/],
]
const SPDX_ID_RE = /^[A-Za-z0-9.+-]{2,64}$/

export function licenseFromText(text: string): string | null {
  const norm = text.toLowerCase().replace(/\s+/g, ' ').slice(0, 20_000)
  const spdx = /spdx-license-identifier:\s*([a-z0-9.+-]+)/i.exec(text)
  if (spdx && SPDX_ID_RE.test(spdx[1]!)) return spdx[1]!
  for (const [id, re] of LICENSE_PATTERNS) {
    if (re.test(norm)) return id
  }
  return null
}

const KUBERNETES_DIR_RE = /(^|\/)(k8s|kubernetes|manifests|deploy|deployment|kustomize|overlays|base)\//i
const MAX_YAML_READS = 12

export type FileReader = (path: string) => Promise<string | null>

export interface DetectInput {
  tree: ForgeTree
  read: FileReader
  ref?: string | null
  commit?: string | null
  now?: Date
}

function base(path: string): string {
  return path.slice(path.lastIndexOf('/') + 1)
}
function dir(path: string): string {
  const i = path.lastIndexOf('/')
  return i < 0 ? '' : path.slice(0, i + 1)
}

/** Détection brute (sans catalogue) : ce que contient le dépôt. */
export async function detectRepository(input: DetectInput): Promise<Omit<Detection, 'modules' | 'coverage_gaps'>> {
  const files = input.tree.entries.filter((e: TreeEntry) => e.type === 'file' && !IGNORED_DIR_RE.test(e.path))
  const paths = new Set(files.map(f => f.path))

  const languageFiles: Record<string, number> = {}
  let shellScripts = 0
  for (const f of files) {
    const ext = /\.([A-Za-z0-9]+)$/.exec(base(f.path))?.[1]?.toLowerCase()
    const lang = ext ? LANGUAGE_EXT[ext] : undefined
    if (!lang) continue
    languageFiles[lang] = (languageFiles[lang] ?? 0) + 1
    if (lang === 'shell') shellScripts++
  }
  // hcl est rapporté comme IaC (Terraform), pas comme langage à analyser en SAST.
  const languages = Object.keys(languageFiles).filter(l => l !== 'hcl').sort((a, b) => languageFiles[b]! - languageFiles[a]! || a.localeCompare(b))

  const packageManagers: PackageManager[] = []
  const missingLockfiles: string[] = []
  for (const f of files) {
    const name = base(f.path)
    const m = MANIFESTS.find(x => x.file.test(name))
    if (!m) continue
    // Un requirements.txt à côté d'un pyproject.toml n'est pas un second projet.
    if (m.name === 'pip' && name !== 'pyproject.toml' && paths.has(`${dir(f.path)}pyproject.toml`)) continue
    const lock = m.locks.find(l => paths.has(`${dir(f.path)}${l.file}`))
    let lockfile = lock ? `${dir(f.path)}${lock.file}` : null
    if (!lock && m.name === 'pip' && name.startsWith('requirements') && packageManagers.length < 50) {
      if (requirementsPinned(await input.read(f.path))) lockfile = f.path
    }
    packageManagers.push({ name: lock?.name ?? m.name, manifest: f.path, lockfile })
    if (!lockfile) missingLockfiles.push(f.path)
    if (packageManagers.length >= 200) break
  }

  const containers = files
    .filter(f => /^(Dockerfile|Containerfile)(\..+)?$/.test(base(f.path)) || /\.(dockerfile|containerfile)$/i.test(f.path))
    .map(f => f.path)
    .slice(0, 100)

  const terraform = files.some(f => /\.tf$/.test(f.path))
  const helm = files.some(f => base(f.path) === 'Chart.yaml')
  const ansible = files.some(f => base(f.path) === 'ansible.cfg' || /(^|\/)roles\/[^/]+\/tasks\/main\.ya?ml$/.test(f.path)
    || /(^|\/)(playbooks?\/.+|site|playbook)\.ya?ml$/.test(f.path))

  const ci: CiWorkflow[] = []
  for (const f of files) {
    if (/^\.github\/workflows\/[^/]+\.ya?ml$/.test(f.path)) ci.push({ kind: 'github-actions', path: f.path })
    else if (/^\.(forgejo|gitea)\/workflows\/[^/]+\.ya?ml$/.test(f.path)) ci.push({ kind: 'forgejo-actions', path: f.path })
    else if (f.path === '.gitlab-ci.yml') ci.push({ kind: 'gitlab-ci', path: f.path })
    else if (base(f.path) === 'Jenkinsfile') ci.push({ kind: 'jenkins', path: f.path })
  }
  const ciPaths = new Set(ci.map(c => c.path))

  // Kubernetes : manifestes YAML avec apiVersion et kind, lus en nombre borné,
  // d'abord dans les répertoires usuels.
  let kubernetes = helm
  if (!kubernetes) {
    const yaml = files.filter(f => /\.ya?ml$/.test(f.path) && !ciPaths.has(f.path) && !f.path.startsWith('.'))
    const candidates = [...yaml.filter(f => KUBERNETES_DIR_RE.test(f.path)), ...yaml.filter(f => !KUBERNETES_DIR_RE.test(f.path))]
    for (const f of candidates.slice(0, MAX_YAML_READS)) {
      const text = await input.read(f.path)
      if (text && /^apiVersion:\s*\S+/m.test(text) && /^kind:\s*[A-Z][A-Za-z]+/m.test(text)) {
        kubernetes = true
        break
      }
    }
  }

  let license: Detection['license'] = null
  const licenseFile = files.find(f => !f.path.includes('/') && LICENSE_FILE_RE.test(f.path))
  if (licenseFile) {
    const text = await input.read(licenseFile.path)
    const spdx = text ? licenseFromText(text) : null
    if (spdx) license = { spdx, source: licenseFile.path }
  }
  if (!license && paths.has('package.json')) {
    try {
      const pkg = JSON.parse((await input.read('package.json')) ?? '{}') as { license?: unknown }
      if (typeof pkg.license === 'string' && SPDX_ID_RE.test(pkg.license)) license = { spdx: pkg.license, source: 'package.json' }
    }
    catch {
      // package.json illisible : licence inconnue
    }
  }

  const categories = new Set<Category>(['secrets'])
  if (languages.some(l => l !== 'shell' && l !== 'sql')) {
    categories.add('sast')
    categories.add('quality')
  }
  if (packageManagers.length) {
    categories.add('sca')
    categories.add('sbom')
    categories.add('licenses')
  }
  if (containers.length) {
    categories.add('container')
    categories.add('sbom')
  }
  if (terraform || kubernetes || helm || ansible || containers.length) categories.add('iac')
  if (shellScripts || containers.length || ci.length) categories.add('lint')
  if (ci.length) categories.add('ci')

  return {
    version: DETECTION_VERSION,
    analyzed_at: (input.now ?? new Date()).toISOString().replace(/\.\d{3}Z$/, 'Z'),
    ref: input.ref ?? null,
    commit: input.commit ?? null,
    truncated: input.tree.truncated,
    files: files.length,
    languages,
    language_files: languageFiles,
    package_managers: packageManagers,
    missing_lockfiles: missingLockfiles,
    containers,
    iac: { terraform, kubernetes, helm, ansible },
    ci,
    shell_scripts: shellScripts,
    license,
    categories: [...categories].sort((a, b) => a.localeCompare(b)),
    profile: 'complet',
    pr_profile: 'rapide',
  }
}

export interface CatalogModuleLite {
  id: string
  name: string
  type: string
  categories: string[]
  license?: { restrictions?: string }
}
export interface InstalledLite {
  id: string
  enabled: boolean
  status: string
}

type Raw = Omit<Detection, 'modules' | 'coverage_gaps'>

/** Raison pour laquelle un module est pertinent, ou null s'il ne l'est pas. */
export function moduleRelevance(m: CatalogModuleLite, d: Raw): ModuleReason | null {
  if (m.type !== 'scanner') return null
  // Licence interdite sur du code privé (CodeQL) : jamais proposée d'office.
  if (m.license?.restrictions === 'private-code-forbidden') return null
  const hasWorkflows = d.ci.some(c => c.kind === 'github-actions' || c.kind === 'forgejo-actions')
  switch (m.id) {
    case 'gitleaks':
    case 'trufflehog': return 'always'
    case 'shellcheck': return d.shell_scripts ? 'shell' : null
    case 'actionlint':
    case 'zizmor': return hasWorkflows ? 'workflows' : null
    case 'hadolint': return d.containers.length ? 'containers' : null
    case 'bandit': return d.languages.includes('python') ? 'python' : null
    case 'osv-scanner': return d.package_managers.length ? 'lockfiles' : null
    case 'syft':
    case 'grype': return d.package_managers.length || d.containers.length ? 'lockfiles' : null
    case 'checkov':
    case 'kics': return d.categories.includes('iac') ? 'iac' : null
    case 'semgrep':
    case 'opengrep': return d.categories.includes('sast') ? 'languages' : null
    default: break
  }
  if (m.categories.includes('dast')) return null
  return m.categories.some(c => (d.categories as string[]).includes(c)) ? 'category' : null
}

/**
 * Complète la détection avec le catalogue : modules pertinents (installés ou à
 * installer, rien n'est installé ici) et catégories qu'aucun module ne couvre.
 */
export function suggestModules(d: Raw, catalog: CatalogModuleLite[], installed: InstalledLite[]): Detection {
  const byId = new Map(installed.map(i => [i.id, i]))
  const modules: SuggestedModule[] = []
  for (const m of catalog) {
    const reason = moduleRelevance(m, d)
    if (!reason) continue
    const inst = byId.get(m.id)
    modules.push({
      id: m.id,
      name: m.name,
      categories: m.categories,
      installed: !!inst,
      enabled: !!inst && inst.enabled && inst.status === 'healthy',
      reason,
    })
  }
  modules.sort((a, b) => Number(b.installed) - Number(a.installed) || a.id.localeCompare(b.id))
  const covered = new Set(catalog.filter(m => m.type === 'scanner' || m.type === 'service').flatMap(m => m.categories))
  const gaps = d.categories.filter(c => !covered.has(c))
  return { ...d, modules, coverage_gaps: gaps }
}
