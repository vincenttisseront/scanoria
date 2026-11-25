// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// J2 (0.8, chantier C) : PR d'intégration automatique et protection de branche.
// - Pour chaque dépôt enrôlé dont la CI ne mentionne pas encore Scanoria,
//   l'appliance ouvre UNE PR (integration_requests, une seule demande active
//   par projet et par sorte) avec le modèle J3 de la CI détectée (F1) et le
//   mode tiré ou poussé du projet. Elle ne la fusionne jamais ; son état
//   (ouverte, fusionnée, fermée) est suivi.
// - La règle de protection qui exige le statut Scanoria est PROPOSÉE ; elle
//   n'est appliquée par l'API de la forge qu'après la confirmation d'un
//   administrateur humain (decided_by, audit). Un droit manquant de
//   l'application de forge est signalé, jamais contourné.

import type { Queryable } from '../utils/db'
import { writeAudit } from '../utils/audit'
import { ForgeError } from '../forges/http'
import { forgeAccess, getForge, type ForgeRow } from '../forges'
import { consoleUrl } from '../forges/context'
import { integrationWriter, type IntegrationFile, type PrState } from '../forges/integration'
import { openForge } from '../forges'
import type { CiWorkflow, Detection } from '../projects/detect'
import { appendGitlabInclude, clientSha256, gitlabInclude, readTemplate, renderWorkflow, type CiKind, type RenderContext } from './templates'

export type IntegrationKind = 'ci-pr' | 'branch-protection'
export type IntegrationState = 'proposed' | 'open' | 'merged' | 'closed' | 'applied' | 'declined' | 'error'

export interface IntegrationRequestRow {
  id: string
  project_id: string
  kind: IntegrationKind
  state: IntegrationState
  external_id: string | null
  detail: Record<string, unknown>
  decided_by: string | null
  decided_by_username: string | null
  created_at: string
  updated_at: string
}

const ts = (col: string) => `to_char(r.${col} AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS ${col}`
const COLUMNS = `r.id::text, r.project_id::text, r.kind, r.state, r.external_id, r.detail, r.decided_by::text, u.username AS decided_by_username,
  ${ts('created_at')}, ${ts('updated_at')}`

export async function listIntegrationRequests(db: Queryable, projectId: string): Promise<IntegrationRequestRow[]> {
  const { rows } = await db.query<IntegrationRequestRow>(
    `SELECT ${COLUMNS} FROM integration_requests r LEFT JOIN users u ON u.id = r.decided_by
      WHERE r.project_id = $1 ORDER BY r.created_at DESC LIMIT 20`, [projectId])
  return rows
}

export async function getIntegrationRequest(db: Queryable, projectId: string, id: string): Promise<IntegrationRequestRow | null> {
  const { rows } = await db.query<IntegrationRequestRow>(
    `SELECT ${COLUMNS} FROM integration_requests r LEFT JOIN users u ON u.id = r.decided_by WHERE r.project_id = $1 AND r.id = $2`, [projectId, id])
  return rows[0] ?? null
}

async function latest(db: Queryable, projectId: string, kind: IntegrationKind): Promise<IntegrationRequestRow | null> {
  const { rows } = await db.query<IntegrationRequestRow>(
    `SELECT ${COLUMNS} FROM integration_requests r LEFT JOIN users u ON u.id = r.decided_by
      WHERE r.project_id = $1 AND r.kind = $2 ORDER BY r.created_at DESC LIMIT 1`, [projectId, kind])
  return rows[0] ?? null
}

// --- Choix du modèle ------------------------------------------------------------------------

export interface IntegrationPlan {
  ci: CiKind
  files: IntegrationFile[]
  /** Étape à ajouter à la main (Jenkins, include GitLab déjà présent). */
  manual: string | null
}

interface ProjectInfo {
  id: string
  slug: string
  forge_id: string | null
  repo_full_name: string | null
  default_branch: string | null
  archived: boolean
  suspended: boolean
  release_mode: 'pull' | 'push' | 'off'
  release_patterns: string[]
  autonomous_chain: boolean
  pr_profile: string | null
  detection: Detection | { error: string } | null
}

export async function getProjectInfo(db: Queryable, projectId: string): Promise<ProjectInfo | null> {
  const { rows } = await db.query<ProjectInfo>(
    `SELECT p.id::text, p.slug, p.forge_id::text, p.repo_full_name, p.default_branch,
            p.archived_at IS NOT NULL AS archived, p.suspended_at IS NOT NULL AS suspended,
            p.release_mode, p.release_patterns, p.autonomous_chain, pr.slug AS pr_profile, p.detection
       FROM projects p LEFT JOIN profiles pr ON pr.id = p.profile_pr_id WHERE p.id = $1`, [projectId])
  return rows[0] ?? null
}

/**
 * CI cible, d'après la forge et la détection F1 :
 * - GitHub : GitHub Actions ;
 * - Forgejo : le dossier de workflows déjà lu par Forgejo (.forgejo, sinon
 *   .gitea, sinon .github) : un nouveau .forgejo/workflows masquerait les autres ;
 * - GitLab : composant GitLab CI ;
 * - un dépôt qui n'a qu'un Jenkinsfile : shared library Jenkins (étape manuelle).
 */
export function chooseCi(forgeKind: ForgeRow['kind'], ci: CiWorkflow[]): { ci: CiKind, dir: string } {
  const kinds = new Set(ci.map(w => w.kind))
  const native = forgeKind === 'github' ? 'github-actions' : forgeKind === 'gitlab' ? 'gitlab-ci' : 'forgejo-actions'
  const hasNative = kinds.has(native) || (forgeKind === 'forgejo' && kinds.has('github-actions'))
  if (!hasNative && kinds.has('jenkins')) return { ci: 'jenkins', dir: 'ci/scanoria' }
  if (forgeKind === 'github') return { ci: 'github', dir: '.github' }
  if (forgeKind === 'gitlab') return { ci: 'gitlab', dir: '.gitlab' }
  // Forgejo lit .forgejo/workflows, à défaut .gitea/workflows, à défaut .github/workflows :
  // le nouveau workflow va dans le dossier déjà lu, pour ne masquer aucun workflow existant.
  const dirs = ['.forgejo', '.gitea', '.github'] as const
  const dir = dirs.find(d => ci.some(w => w.path.startsWith(`${d}/workflows/`))) ?? '.forgejo'
  return { ci: 'forgejo', dir }
}

/** Fichiers de la PR pour une CI donnée (aucun fichier existant écrasé, sauf l'include GitLab). */
export async function buildPlan(ci: { ci: CiKind, dir: string }, ctx: RenderContext & { defaultBranch: string }, existingGitlabCi: string | null): Promise<IntegrationPlan> {
  const step = await readTemplate('scanoria-ci.sh')
  const branch = (s: string) => s.replace('    branches: [main]', `    branches: [${JSON.stringify(ctx.defaultBranch)}]`)
  switch (ci.ci) {
    case 'github':
    case 'forgejo': {
      let wf = branch(renderWorkflow(await readTemplate(`${ci.ci}/scanoria.yml`), ctx))
      // Workflow Forgejo rangé dans .github/workflows : étape commune au même endroit.
      if (ci.dir !== `.${ci.ci}`) wf = wf.replaceAll(`.${ci.ci}/scanoria`, `${ci.dir}/scanoria`)
      return {
        ci: ci.ci,
        files: [
          { path: `${ci.dir}/workflows/scanoria.yml`, content: wf },
          { path: `${ci.dir}/scanoria/scanoria-ci.sh`, content: step },
        ],
        manual: null,
      }
    }
    case 'gitlab': {
      const files: IntegrationFile[] = [
        { path: '.gitlab/scanoria.yml', content: await readTemplate('gitlab/scanoria.yml') },
        { path: '.gitlab/scanoria-ci.sh', content: step },
      ]
      const updated = appendGitlabInclude(existingGitlabCi, ctx)
      if (updated !== null) files.push({ path: '.gitlab-ci.yml', content: updated, update: existingGitlabCi !== null })
      return { ci: 'gitlab', files, manual: updated === null ? gitlabInclude(ctx) : null }
    }
    case 'jenkins':
      return {
        ci: 'jenkins',
        files: [
          { path: 'ci/scanoria/vars/scanoria.groovy', content: await readTemplate('jenkins/vars/scanoria.groovy') },
          { path: 'ci/scanoria/resources/scanoria-ci.sh', content: step },
        ],
        manual: `scanoria(url: '${ctx.url}', project: '${ctx.projectId}', clientSha256: '${ctx.clientSha256 ?? ''}', credentialsId: 'scanoria-token')`,
      }
    default:
      throw new Error('E_TEMPLATE')
  }
}

// --- Textes publiés -------------------------------------------------------------------------

function prBody(locale: 'fr' | 'en', plan: IntegrationPlan, mode: 'push' | 'pull', projectUrl: string | null): string {
  const files = plan.files.map(f => `- \`${f.path}\``).join('\n')
  const manual = plan.manual ? `\n\n${locale === 'en' ? 'One line to add by hand:' : 'Une ligne à ajouter à la main :'}\n\n\`\`\`\n${plan.manual}\n\`\`\`` : ''
  const link = projectUrl ? `\n\n${locale === 'en' ? 'Project in Scanoria' : 'Projet dans Scanoria'} : ${projectUrl}` : ''
  if (locale === 'en') {
    return `This pull request adds the Scanoria step to the CI (${plan.ci}). Every pull request and every release then goes through all the tools installed on the appliance, and the quality gate decides.\n\n`
      + `Mode: **${mode === 'pull' ? 'pull' : 'push'}**. ${mode === 'pull'
        ? 'The appliance scans by itself and posts the scanoria/release-gate commit status; the CI only waits for it on release tags.'
        : 'The CI calls the appliance with its OIDC token (no secret to create) and waits for the verdict.'}\n\n`
        + `Files added:\n${files}${manual}\n\nThe appliance never merges this pull request: review it and merge it when it suits you.${link}`
  }
  return `Cette PR ajoute l'étape Scanoria à la CI (${plan.ci}). Chaque PR et chaque release passent alors par tous les outils installés sur l'appliance, et le quality gate décide.\n\n`
    + `Mode : **${mode === 'pull' ? 'tiré' : 'poussé'}**. ${mode === 'pull'
      ? 'L\'appliance analyse d\'elle-même et pose le statut de commit scanoria/release-gate ; la CI ne fait que l\'attendre sur les tags de release.'
      : 'La CI appelle l\'appliance avec son jeton OIDC (aucun secret à créer) et attend le verdict.'}\n\n`
      + `Fichiers ajoutés :\n${files}${manual}\n\nL'appliance ne fusionne jamais cette PR : relisez-la et fusionnez-la quand cela vous convient.${link}`
}

/** Droit à donner à l'application ou au compte de service quand la forge refuse l'écriture. */
export function missingPermission(forgeKind: ForgeRow['kind'], kind: IntegrationKind): string {
  if (forgeKind === 'github') return kind === 'ci-pr' ? 'contents: write, workflows: write, pull_requests: write' : 'administration: write'
  if (forgeKind === 'gitlab') return kind === 'ci-pr' ? 'Developer (api)' : 'Maintainer (api)'
  return kind === 'ci-pr' ? 'write:repository' : 'admin du dépôt (write:repository)'
}

function forgeErrorDetail(err: unknown, forgeKind: ForgeRow['kind'], kind: IntegrationKind): Record<string, unknown> {
  const code = err instanceof ForgeError ? err.code : 'E_INTEGRATION'
  return { error: code, status: err instanceof ForgeError ? err.status : null, ...(code === 'E_FORGE_AUTH' ? { missing_permission: missingPermission(forgeKind, kind) } : {}) }
}

// --- PR d'intégration -----------------------------------------------------------------------

const SCANORIA_STEP_RE = /scanoria/i
const MAX_CI_READS = 10

export type ProposeOutcome
  = | { outcome: 'opened', request: string, number: number }
    | { outcome: 'already-integrated' | 'exists' | 'not-applicable' | 'pending-detection', request?: string }
    | { outcome: 'error', request: string, code: string }

/**
 * Ouvre la PR d'intégration d'un projet si elle n'a jamais été ouverte (ou,
 * avec `force`, si la précédente a été fermée ou a échoué). Rend le résultat
 * sans lever pour une erreur de forge : elle est rangée dans la demande.
 */
export async function proposeIntegration(db: Queryable, projectId: string, opts: { force?: boolean, actor?: { userId: number, username: string } | null, locale?: 'fr' | 'en' } = {}): Promise<ProposeOutcome> {
  const p = await getProjectInfo(db, projectId)
  if (!p || p.archived || p.suspended || !p.forge_id || !p.repo_full_name || !p.default_branch) return { outcome: 'not-applicable' }
  const prev = await latest(db, projectId, 'ci-pr')
  if (prev && (['proposed', 'open', 'merged', 'applied'].includes(prev.state) || !opts.force)) return { outcome: 'exists', request: prev.id }
  const detection = p.detection && !('error' in p.detection) ? p.detection : null
  if (!detection) return { outcome: 'pending-detection' }
  const forge = await getForge(db, p.forge_id)
  if (!forge) return { outcome: 'not-applicable' }

  const access = await forgeAccess(db, forge)
  const audit = async (outcome: 'success' | 'failure', id: string, details: Record<string, unknown>) => writeAudit(db, {
    actor: opts.actor ? { type: 'user', userId: opts.actor.userId, username: opts.actor.username } : { type: 'system' },
    action: 'integration.ci-pr', outcome, targetType: 'project', targetId: projectId, details: { request: id, repo: p.repo_full_name, ...details },
  })

  // Étape Scanoria déjà présente dans un fichier de CI : rien à proposer.
  const client = await openForge(db, forge)
  let gitlabCi: string | null = null
  const ci = Array.isArray(detection.ci) ? detection.ci : []
  for (const w of ci.slice(0, MAX_CI_READS)) {
    const text = await client.readFile(p.repo_full_name, p.default_branch, w.path).catch(() => null)
    if (w.path === '.gitlab-ci.yml') gitlabCi = text
    if (text && SCANORIA_STEP_RE.test(text)) {
      const ins = await db.query<{ id: string }>(
        `INSERT INTO integration_requests (project_id, kind, state, detail) VALUES ($1, 'ci-pr', 'applied', $2) RETURNING id::text`,
        [projectId, JSON.stringify({ reason: 'already-integrated', path: w.path })])
      return { outcome: 'already-integrated', request: ins.rows[0]!.id }
    }
  }

  const url = await consoleUrl()
  const mode = p.release_mode === 'pull' ? 'pull' : 'push'
  const target = chooseCi(forge.kind, ci)
  const ins = await db.query<{ id: string }>(
    `INSERT INTO integration_requests (project_id, kind, state, detail) VALUES ($1, 'ci-pr', 'proposed', $2)
     ON CONFLICT DO NOTHING RETURNING id::text`,
    [projectId, JSON.stringify({ ci: target.ci, mode })])
  const id = ins.rows[0]?.id
  if (!id) return { outcome: 'exists' }

  try {
    // Adresse de la console obligatoire dans les deux modes : jamais une
    // adresse d'exemple publiée dans une PR.
    if (!url) throw new IntegrationError('E_CONSOLE_URL')
    const ctx = {
      url, projectId, mode, clientSha256: await clientSha256(),
      tagPatterns: p.release_patterns, defaultBranch: p.default_branch,
    } as const
    const plan = await buildPlan(target, ctx, gitlabCi)
    const branch = `scanoria/integration-${id.slice(0, 8)}`
    const writer = integrationWriter(access, { consoleUrl: url })
    const locale = opts.locale ?? 'fr'
    const pr = await writer.openPullRequest(p.repo_full_name, {
      base: p.default_branch,
      branch,
      title: locale === 'en' ? 'Scanoria: add the analysis step to the CI' : 'Scanoria : ajout de l\'étape d\'analyse à la CI',
      message: locale === 'en' ? 'ci: add the Scanoria step (J2)' : 'ci: ajoute l\'étape Scanoria (J2)',
      body: prBody(locale, plan, mode, `${url}/projects/${projectId}`),
      files: plan.files,
    })
    const detail = { ci: plan.ci, mode, branch, url: pr.url, files: plan.files.map(f => f.path), manual: plan.manual }
    await db.query(`UPDATE integration_requests SET state = 'open', external_id = $2, detail = $3, updated_at = now() WHERE id = $1`,
      [id, String(pr.number), JSON.stringify(detail)])
    await audit('success', id, { number: pr.number, ci: plan.ci, mode })
    // La PR est ouverte et suivie même si la proposition de protection échoue.
    await proposeProtection(db, p, forge.kind).catch((err: unknown) => console.error('[integration] protection', projectId, (err as Error)?.message))
    return { outcome: 'opened', request: id, number: pr.number }
  }
  catch (err) {
    const detail = err instanceof IntegrationError ? { error: err.code } : forgeErrorDetail(err, forge.kind, 'ci-pr')
    if (!(err instanceof IntegrationError) && !(err instanceof ForgeError)) console.error('[integration] PR', projectId, (err as Error)?.message)
    await db.query(`UPDATE integration_requests SET state = 'error', detail = detail || $2::jsonb, updated_at = now() WHERE id = $1`, [id, JSON.stringify(detail)])
    await audit('failure', id, detail)
    return { outcome: 'error', request: id, code: String(detail.error) }
  }
}

export class IntegrationError extends Error {
  constructor(public readonly code: 'E_CONSOLE_URL' | 'E_INTEGRATION_STATE' | 'E_INTEGRATION_NOT_FOUND' | 'E_INTEGRATION_CONTEXTS') {
    super(code)
    this.name = 'IntegrationError'
  }
}

/** Suit l'état d'une PR d'intégration ouverte (fusionnée, fermée). */
export async function syncIntegrationPr(db: Queryable, req: IntegrationRequestRow): Promise<PrState | null> {
  if (req.kind !== 'ci-pr' || req.state !== 'open' || !req.external_id) return null
  const p = await getProjectInfo(db, req.project_id)
  if (!p?.forge_id || !p.repo_full_name) return null
  const forge = await getForge(db, p.forge_id)
  if (!forge) return null
  const writer = integrationWriter(await forgeAccess(db, forge), { consoleUrl: null })
  const state = await writer.pullRequestState(p.repo_full_name, Number(req.external_id))
  if (state !== 'open') {
    await db.query(`UPDATE integration_requests SET state = $2, updated_at = now() WHERE id = $1 AND state = 'open'`, [req.id, state])
    await writeAudit(db, {
      actor: { type: 'system' }, action: `integration.pr-${state}`, outcome: 'success', targetType: 'project', targetId: req.project_id,
      details: { request: req.id, number: Number(req.external_id), repo: p.repo_full_name },
    })
  }
  return state
}

// --- Protection de branche ------------------------------------------------------------------

export const RELEASE_GATE_CONTEXT = 'scanoria/release-gate'

/** Contextes requis proposés : statut des PR (scanoria/<profil PR>), et en option le gate de release. */
export function proposedContexts(p: { pr_profile: string | null }, includeReleaseGate: boolean): string[] {
  const pr = `scanoria/${p.pr_profile && /^[a-z0-9][a-z0-9-]{0,62}$/.test(p.pr_profile) ? p.pr_profile : 'rapide'}`
  return includeReleaseGate ? [pr, RELEASE_GATE_CONTEXT] : [pr]
}

async function proposeProtection(db: Queryable, p: ProjectInfo, forgeKind: ForgeRow['kind']): Promise<string | null> {
  const prev = await latest(db, p.id, 'branch-protection')
  if (prev && prev.state !== 'error') return null
  const { rows } = await db.query<{ id: string }>(
    `INSERT INTO integration_requests (project_id, kind, state, detail) VALUES ($1, 'branch-protection', 'proposed', $2)
     ON CONFLICT DO NOTHING RETURNING id::text`,
    [p.id, JSON.stringify({ branch: p.default_branch, contexts: proposedContexts(p, false), forge: forgeKind })])
  return rows[0]?.id ?? null
}

/** Propose la protection à la main (projet déjà intégré, ou proposition refusée puis reprise). */
export async function requestProtection(db: Queryable, projectId: string): Promise<string | null> {
  const p = await getProjectInfo(db, projectId)
  if (!p?.forge_id || !p.default_branch || p.archived || p.suspended) return null
  const forge = await getForge(db, p.forge_id)
  if (!forge) return null
  const prev = await latest(db, projectId, 'branch-protection')
  if (prev?.state === 'proposed') return prev.id
  const { rows } = await db.query<{ id: string }>(
    `INSERT INTO integration_requests (project_id, kind, state, detail) VALUES ($1, 'branch-protection', 'proposed', $2)
     ON CONFLICT DO NOTHING RETURNING id::text`,
    [projectId, JSON.stringify({ branch: p.default_branch, contexts: proposedContexts(p, false), forge: forge.kind })])
  return rows[0]?.id ?? null
}

/**
 * Décision d'un administrateur humain sur la protection proposée : `apply`
 * l'applique par l'API de la forge (contextes exacts montrés dans la modale),
 * `decline` la refuse. Toujours tracé dans l'audit.
 */
export async function decideProtection(db: Queryable, projectId: string, requestId: string, decision: { action: 'apply' | 'decline', includeReleaseGate?: boolean, userId: number, username: string, ip?: string | null }): Promise<IntegrationRequestRow> {
  const req = await getIntegrationRequest(db, projectId, requestId)
  if (!req || req.kind !== 'branch-protection') throw new IntegrationError('E_INTEGRATION_NOT_FOUND')
  if (req.state !== 'proposed') throw new IntegrationError('E_INTEGRATION_STATE')
  const p = await getProjectInfo(db, projectId)
  const forge = p?.forge_id ? await getForge(db, p.forge_id) : null
  if (!p || !forge || !p.repo_full_name || !p.default_branch) throw new IntegrationError('E_INTEGRATION_NOT_FOUND')
  const actor = { type: 'user' as const, userId: decision.userId, username: decision.username, ip: decision.ip ?? null }
  const branch = typeof req.detail.branch === 'string' ? req.detail.branch : p.default_branch
  const contexts = proposedContexts(p, decision.includeReleaseGate === true)

  if (decision.action === 'decline') {
    const d = await db.query(`UPDATE integration_requests SET state = 'declined', decided_by = $2, updated_at = now() WHERE id = $1 AND state = 'proposed'`, [req.id, decision.userId])
    if (!d.rowCount) throw new IntegrationError('E_INTEGRATION_STATE')
    await writeAudit(db, { actor, action: 'integration.protection-decline', outcome: 'success', targetType: 'project', targetId: projectId, details: { request: req.id, branch, repo: p.repo_full_name } })
    return (await getIntegrationRequest(db, projectId, req.id))!
  }

  try {
    const writer = integrationWriter(await forgeAccess(db, forge), { consoleUrl: null })
    const res = await writer.protectBranch(p.repo_full_name, branch, contexts)
    // Décision concurrente : une seule passe de « proposed » à « applied » (et un seul audit).
    const u = await db.query(
      `UPDATE integration_requests SET state = 'applied', decided_by = $2, detail = detail - 'error' - 'missing_permission' - 'status' || $3::jsonb, updated_at = now() WHERE id = $1 AND state = 'proposed'`,
      [req.id, decision.userId, JSON.stringify({ branch, contexts, created_rule: res.created })])
    if (!u.rowCount) throw new IntegrationError('E_INTEGRATION_STATE')
    await writeAudit(db, { actor, action: 'integration.protection-apply', outcome: 'success', targetType: 'project', targetId: projectId, details: { request: req.id, branch, contexts, repo: p.repo_full_name } })
  }
  catch (err) {
    if (err instanceof IntegrationError) throw err
    const detail = forgeErrorDetail(err, forge.kind, 'branch-protection')
    // La proposition reste ouverte : l'administrateur corrige le droit puis réessaie.
    await db.query(`UPDATE integration_requests SET detail = detail || $2::jsonb, updated_at = now() WHERE id = $1`, [req.id, JSON.stringify(detail)])
    await writeAudit(db, { actor, action: 'integration.protection-apply', outcome: 'failure', targetType: 'project', targetId: projectId, details: { request: req.id, branch, contexts, ...detail } })
  }
  return (await getIntegrationRequest(db, projectId, req.id))!
}

// --- J16 : case « chaîne autonome » -----------------------------------------------------------

export async function setAutonomousChain(db: Queryable, projectId: string, enabled: boolean, actor: { userId: number, username: string, ip?: string | null }): Promise<boolean> {
  const r = await db.query('UPDATE projects SET autonomous_chain = $2 WHERE id = $1 AND autonomous_chain IS DISTINCT FROM $2', [projectId, enabled])
  if (r.rowCount) {
    await writeAudit(db, {
      actor: { type: 'user', userId: actor.userId, username: actor.username, ip: actor.ip ?? null },
      action: 'project.autonomous-chain', outcome: 'success', targetType: 'project', targetId: projectId, details: { enabled },
    })
  }
  return !!r.rowCount
}

// --- Passe périodique (scanoria-worker) -------------------------------------------------------

export const INTEGRATIONS_PER_CYCLE = 10
export const SYNCS_PER_CYCLE = 20

/**
 * Passe périodique : PR d'intégration des projets enrôlés depuis une forge et
 * déjà détectés (F1) qui n'en ont jamais eu, puis suivi des PR ouvertes.
 */
export async function runCiIntegration(db: Queryable): Promise<{ opened: number, synced: number, errors: number }> {
  const out = { opened: 0, synced: 0, errors: 0 }
  const { rows: todo } = await db.query<{ id: string }>(
    `SELECT p.id::text FROM projects p
      WHERE p.archived_at IS NULL AND p.suspended_at IS NULL AND p.forge_id IS NOT NULL AND p.repo_full_name IS NOT NULL
        AND p.detection IS NOT NULL AND NOT (p.detection ? 'error') AND jsonb_typeof(p.detection -> 'ci') = 'array'
        AND NOT EXISTS (SELECT 1 FROM integration_requests r WHERE r.project_id = p.id AND r.kind = 'ci-pr')
      ORDER BY p.created_at LIMIT ${INTEGRATIONS_PER_CYCLE}`)
  for (const { id } of todo) {
    try {
      const r = await proposeIntegration(db, id)
      if (r.outcome === 'opened') out.opened++
      else if (r.outcome === 'error') out.errors++
    }
    catch (err) {
      out.errors++
      if (!(err instanceof ForgeError)) console.error('[integration] project', id, (err as Error)?.message)
    }
  }
  const { rows: open } = await db.query<IntegrationRequestRow>(
    `SELECT ${COLUMNS} FROM integration_requests r LEFT JOIN users u ON u.id = r.decided_by
      WHERE r.kind = 'ci-pr' AND r.state = 'open' ORDER BY r.updated_at LIMIT ${SYNCS_PER_CYCLE}`)
  for (const req of open) {
    try {
      const s = await syncIntegrationPr(db, req)
      if (s) out.synced++
      // Même sans changement : la demande passe en fin de file.
      if (s === 'open') await db.query('UPDATE integration_requests SET updated_at = now() WHERE id = $1', [req.id])
    }
    catch {
      out.errors++
    }
  }
  return out
}
