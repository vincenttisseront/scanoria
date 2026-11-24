// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Types et textes communs aux pages Projets et Forges (chantier A) : messages
// d'erreur propres (projects.errors.*), puis ceux de la console.

export interface ProjectDetection {
  version: number
  analyzed_at: string
  error?: string
  ref?: string | null
  commit?: string | null
  truncated?: boolean
  files?: number
  languages?: string[]
  language_files?: Record<string, number>
  package_managers?: { name: string, manifest: string, lockfile: string | null }[]
  missing_lockfiles?: string[]
  containers?: string[]
  iac?: { terraform: boolean, kubernetes: boolean, helm: boolean, ansible: boolean }
  ci?: { kind: string, path: string }[]
  shell_scripts?: number
  license?: { spdx: string, source: string } | null
  categories?: string[]
  profile?: string
  pr_profile?: string
  modules?: { id: string, name: string, categories: string[], installed: boolean, enabled: boolean, reason: string }[]
  coverage_gaps?: string[]
}

export interface Project {
  id: string
  slug: string
  name: string
  source_kind: 'git' | 'archive'
  forge_id: string | null
  forge_name: string | null
  forge_kind: string | null
  repo_full_name: string | null
  repo_url: string | null
  has_credential: boolean
  credential_hint: string | null
  credential_kind: string | null
  ssh_known_hosts: string | null
  upload_id: string | null
  default_branch: string | null
  tracked_branches: string[]
  schedule: 'none' | 'daily' | 'on-commit'
  profile_id: string
  profile_slug: string
  gate_id: string
  gate_slug: string
  spdx_license: string | null
  ai_opt_out: boolean
  detection: ProjectDetection | null
  last_commit: string | null
  last_polled_at: string | null
  created_at: string
  archived_at: string | null
  last_scan: { id: string, number: number, status: string, verdict: string | null, queued_at: string } | null
}

export interface Forge {
  id: string
  kind: 'forgejo' | 'github' | 'gitlab'
  name: string
  base_url: string
  discovery: boolean
  has_token: boolean
  token_hint: string | null
  token_user: string | null
  last_discovery_at: string | null
  last_error: string | null
  created_at: string
  projects: number
}

export interface ForgeRepo {
  full_name: string
  description: string | null
  private: boolean
  archived: boolean
  empty: boolean
  default_branch: string | null
  project_id: string | null
}

export function useProjects() {
  const { t, te } = useI18n()
  const { api, errorMessage } = useApi()

  function message(err: unknown): string {
    const code = errorCode(err)
    if (code && te(`projects.errors.${code}`)) return t(`projects.errors.${code}`)
    return errorMessage(err)
  }

  /** Libellé traduit d'une valeur d'énumération, ou la valeur elle-même. */
  function label(group: string, value: string): string {
    const key = `projects.${group}.${value}`
    return te(key) ? t(key) : value
  }

  function sourceLabel(p: Project): string {
    if (p.source_kind === 'archive') return t('projects.source.archive')
    if (p.forge_name) return `${p.forge_name} · ${p.repo_full_name}`
    return p.repo_url ?? ''
  }

  return { api, message, label, sourceLabel }
}
