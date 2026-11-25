// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// J3 (0.8, chantier C) : modèles CI officiels livrés dans
// /usr/share/scanoria/ci-templates (src/rootfs), téléchargeables depuis la
// console et ajoutés aux dépôts par la PR d'intégration (J2).
// Le rendu ne remplace que des valeurs d'exemple connues (adresse, projet,
// mode, empreinte du client) par des valeurs vérifiées : aucun texte libre
// n'entre dans un fichier de CI.

import { createHash } from 'node:crypto'
import { constants } from 'node:fs'
import { open } from 'node:fs/promises'
import { join } from 'node:path'
import { CLIENT_FILE } from '../api/gates/client.get'

export const TEMPLATES_DIR = '/usr/share/scanoria/ci-templates'
const MAX_TEMPLATE_BYTES = 64 * 1024

export type CiKind = 'github' | 'forgejo' | 'gitlab' | 'jenkins' | 'tekton'

export interface TemplateFile {
  /** Chemin dans le dossier des modèles. */
  source: string
  ci: CiKind | 'common'
  description: 'workflow' | 'action' | 'component' | 'library' | 'task' | 'step' | 'readme'
}

/** Liste fermée : seuls ces fichiers sont servis (aucun chemin venu de la requête). */
export const TEMPLATE_FILES: TemplateFile[] = [
  { source: 'README.md', ci: 'common', description: 'readme' },
  { source: 'scanoria-ci.sh', ci: 'common', description: 'step' },
  { source: 'github/scanoria.yml', ci: 'github', description: 'workflow' },
  { source: 'github/action.yml', ci: 'github', description: 'action' },
  { source: 'forgejo/scanoria.yml', ci: 'forgejo', description: 'workflow' },
  { source: 'forgejo/action.yml', ci: 'forgejo', description: 'action' },
  { source: 'gitlab/scanoria.yml', ci: 'gitlab', description: 'component' },
  { source: 'jenkins/vars/scanoria.groovy', ci: 'jenkins', description: 'library' },
  { source: 'tekton/scanoria-task.yaml', ci: 'tekton', description: 'task' },
]

export function templatesDir(): string {
  return process.env.NUXT_CI_TEMPLATES_DIR || TEMPLATES_DIR
}

async function readBounded(path: string, max: number): Promise<Buffer> {
  // Ouvert sans suivre de lien, contrôlé et lu par le même descripteur.
  const fh = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW)
  try {
    const st = await fh.stat()
    if (!st.isFile() || st.size > max) throw new Error('E_TEMPLATE')
    return await fh.readFile()
  }
  finally {
    await fh.close()
  }
}

export async function readTemplate(source: string): Promise<string> {
  const t = TEMPLATE_FILES.find(f => f.source === source)
  if (!t) throw new Error('E_TEMPLATE')
  return (await readBounded(join(templatesDir(), t.source), MAX_TEMPLATE_BYTES)).toString('utf8')
}

/** Empreinte SHA-256 du client scanoria-scan servi par /api/gates/client (null s'il manque). */
export async function clientSha256(): Promise<string | null> {
  try {
    const body = await readBounded(process.env.NUXT_SCANORIA_SCAN_CLIENT || CLIENT_FILE, 256 * 1024)
    return createHash('sha256').update(body).digest('hex')
  }
  catch {
    return null
  }
}

// Valeurs d'exemple des modèles publiés, remplacées au rendu.
export const EXAMPLE_URL = 'https://analyse.exemple.test'
export const EXAMPLE_PROJECT = '00000000-0000-4000-8000-000000000000'

export interface RenderContext {
  url: string
  projectId: string
  mode: 'push' | 'pull'
  clientSha256: string | null
  /** Motifs de tags des releases (projects.release_patterns), mode tiré. */
  tagPatterns?: string[]
}

const URL_RE = /^https:\/\/[A-Za-z0-9.-]+(:\d{1,5})?$/
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/
const SHA_RE = /^[0-9a-f]{64}$/
const TAG_PATTERN_RE = /^[A-Za-z0-9._*/-]{1,100}$/

function checkContext(ctx: RenderContext): void {
  if (!URL_RE.test(ctx.url) || !UUID_RE.test(ctx.projectId) || (ctx.clientSha256 !== null && !SHA_RE.test(ctx.clientSha256))) throw new Error('E_TEMPLATE_CONTEXT')
}

/** Rend un workflow GitHub ou Forgejo (mode poussé : PR, main, tags ; tiré : tags seulement). */
export function renderWorkflow(template: string, ctx: RenderContext): string {
  checkContext(ctx)
  let out = template
    .replaceAll(EXAMPLE_URL, ctx.url)
    .replaceAll(EXAMPLE_PROJECT, ctx.projectId)
    .replace('SCANORIA_MODE: push', `SCANORIA_MODE: ${ctx.mode}`)
    .replace('SCANORIA_CLIENT_SHA256: ""', `SCANORIA_CLIENT_SHA256: "${ctx.clientSha256 ?? ''}"`)
  const tags = (ctx.tagPatterns ?? ['v*']).filter(t => TAG_PATTERN_RE.test(t)).slice(0, 20)
  const tagList = `[${(tags.length ? tags : ['v*']).map(t => JSON.stringify(t)).join(', ')}]`
  out = out.replace('    tags: ["v*"]', `    tags: ${tagList}`)
  // Mode tiré : l'appliance analyse les PR et les tags d'elle-même ; la CI ne
  // fait qu'attendre le statut scanoria/release-gate des tags.
  if (ctx.mode === 'pull') out = out.replace('  pull_request:\n  push:\n    branches: [main]\n', '  push:\n')
  return out
}

/** Include GitLab du composant, avec ses entrées (valeurs vérifiées). */
export function gitlabInclude(ctx: RenderContext): string {
  checkContext(ctx)
  return [
    'include:',
    '  - local: .gitlab/scanoria.yml',
    '    inputs:',
    `      url: ${ctx.url}`,
    `      project: ${ctx.projectId}`,
    `      client-sha256: "${ctx.clientSha256 ?? ''}"`,
    '',
  ].join('\n')
}

/** Ajoute l'include Scanoria à un .gitlab-ci.yml sans clé include (sinon null : ajout manuel). */
export function appendGitlabInclude(existing: string | null, ctx: RenderContext): string | null {
  const block = gitlabInclude(ctx)
  if (existing === null) return `# Scanoria (J2) : étape d'analyse et verdict du quality gate.\n${block}`
  if (/^include\s*:/m.test(existing)) return null
  return `${existing.replace(/\s*$/, '\n')}\n# Scanoria (J2) : étape d'analyse et verdict du quality gate.\n${block}`
}
