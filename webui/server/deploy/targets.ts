// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// J11–J13 (0.8, chantier D) : cibles de déploiement d'un projet. Création,
// modification et retrait réservés à un administrateur, tracés dans l'audit.
// Jetons (deploy-token, registry-token) chiffrés comme les autres secrets,
// jamais rendus. Principe 8 : un workflow de déploiement détectable dans le
// dépôt (workflow_dispatch avec une entrée scanoria_report) est PROPOSÉ comme
// cible J11 ; l'administrateur le confirme une fois, puis il joue seul.

import type { Queryable } from '../utils/db'
import { writeAudit, type AuditActor } from '../utils/audit'
import { apiError } from '../utils/http'
import { deleteSecret, encryptSecret, rotateSecret, secretInfo } from '../utils/secrets'
import { projectForge } from '../forges/context'
import {
  CD_INPUTS, parseConfig, configSchema, type CdInput, type DeployKind, type TargetConfig,
  type targetCreateSchema, type targetUpdateSchema,
} from './config'
import type { z } from 'zod'

export interface TargetRow {
  id: string
  project_id: string
  kind: DeployKind
  environment: string
  on_trigger: 'release' | 'branch'
  config: Record<string, unknown>
  credential_hint: string | null
  auto_merge: boolean
  auto_merge_by: string | null
  enabled: boolean
  created_at: string
}

const COLUMNS = `t.id::text, t.project_id::text, t.kind, t.environment, t.on_trigger, t.config, t.credential_id::text,
  t.auto_merge, t.auto_merge_by::text, t.enabled, to_char(t.created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS created_at`

type Raw = Omit<TargetRow, 'credential_hint'> & { credential_id: string | null }

async function toPublic(db: Queryable, r: Raw): Promise<TargetRow> {
  const { credential_id, ...rest } = r
  const info = credential_id ? await secretInfo(db, credential_id) : null
  return { ...rest, credential_hint: info?.hint ?? null }
}

export async function listTargets(db: Queryable, projectId: string): Promise<TargetRow[]> {
  const r = await db.query<Raw>(`SELECT ${COLUMNS} FROM deploy_targets t WHERE t.project_id = $1 ORDER BY t.environment, t.kind`, [projectId])
  return Promise.all(r.rows.map(x => toPublic(db, x)))
}

export async function getTarget(db: Queryable, id: string): Promise<(TargetRow & { credential_id: string | null }) | null> {
  if (!/^[0-9a-f-]{36}$/.test(id)) return null
  const r = await db.query<Raw>(`SELECT ${COLUMNS} FROM deploy_targets t WHERE t.id = $1`, [id])
  const row = r.rows[0]
  return row ? { ...await toPublic(db, row), credential_id: row.credential_id } : null
}

function credentialKind(kind: DeployKind): 'deploy-token' | 'registry-token' {
  return kind === 'registry-promotion' ? 'registry-token' : 'deploy-token'
}

function validConfig(kind: DeployKind, raw: unknown, onTrigger: string): TargetConfig {
  const parsed = configSchema(kind).safeParse(raw)
  if (!parsed.success) throw apiError(400, 'E_VALIDATION', { issues: parsed.error.issues.map(i => ({ path: i.path.join('.'), code: i.code })) })
  if (onTrigger === 'branch' && !(parsed.data as { branch?: string }).branch) throw apiError(400, 'E_VALIDATION', { issues: [{ path: 'config.branch', code: 'required' }] })
  // J9 : l'attestation n'est signée par le helper que sur le relevé d'un rapport
  // de release qu'il a lui-même signé ; une promotion de branche n'en a pas.
  if (onTrigger === 'branch' && kind === 'registry-promotion') throw apiError(400, 'E_VALIDATION', { issues: [{ path: 'on_trigger', code: 'release_only' }] })
  return parsed.data
}

export async function createTarget(db: Queryable, projectId: string, input: z.infer<typeof targetCreateSchema>, actor: AuditActor): Promise<TargetRow> {
  const config = validConfig(input.kind, input.config, input.on_trigger)
  const dup = await db.query('SELECT 1 FROM deploy_targets WHERE project_id = $1 AND kind = $2 AND environment = $3', [projectId, input.kind, input.environment])
  if (dup.rowCount) throw apiError(409, 'E_PRECONDITION', { reason: 'duplicate' })
  const credentialId = input.credential
    ? await encryptSecret(db, { kind: credentialKind(input.kind), value: input.credential.value, username: input.credential.username ?? null, createdBy: actor.userId ?? null })
    : null
  const r = await db.query<{ id: string }>(
    `INSERT INTO deploy_targets (project_id, kind, environment, on_trigger, config, credential_id, enabled, created_by)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id::text`,
    [projectId, input.kind, input.environment, input.on_trigger, JSON.stringify(config), credentialId, input.enabled, actor.userId ?? null])
  const id = r.rows[0]!.id
  await writeAudit(db, { actor, action: 'deploy.target.create', outcome: 'success', targetType: 'deploy_target', targetId: id, details: { project_id: projectId, kind: input.kind, environment: input.environment, on_trigger: input.on_trigger, config } })
  return (await getTarget(db, id))!
}

export async function updateTarget(db: Queryable, target: TargetRow & { credential_id: string | null }, input: z.infer<typeof targetUpdateSchema>, actor: AuditActor): Promise<TargetRow> {
  if (input.auto_merge && target.kind !== 'gitops-pr') throw apiError(400, 'E_VALIDATION', { issues: [{ path: 'auto_merge', code: 'gitops-only' }] })
  const config = input.config ? validConfig(target.kind, input.config, target.on_trigger) : null
  let credentialId = target.credential_id
  if (input.credential) {
    if (credentialId) await rotateSecret(db, credentialId, input.credential.value, input.credential.username ?? null)
    else credentialId = await encryptSecret(db, { kind: credentialKind(target.kind), value: input.credential.value, username: input.credential.username ?? null, createdBy: actor.userId ?? null })
  }
  await db.query(
    `UPDATE deploy_targets SET enabled = COALESCE($2, enabled), config = COALESCE($3, config), credential_id = $4,
            auto_merge = COALESCE($5, auto_merge),
            auto_merge_by = CASE WHEN $5 IS NULL THEN auto_merge_by WHEN $5 THEN $6 ELSE NULL END
      WHERE id = $1`,
    [target.id, input.enabled ?? null, config ? JSON.stringify(config) : null, credentialId, input.auto_merge ?? null, actor.userId ?? null])
  await writeAudit(db, {
    actor, action: 'deploy.target.update', outcome: 'success', targetType: 'deploy_target', targetId: target.id,
    details: { project_id: target.project_id, enabled: input.enabled, auto_merge: input.auto_merge, config: config ?? undefined, credential_rotated: !!input.credential },
  })
  return (await getTarget(db, target.id))!
}

export async function deleteTarget(db: Queryable, target: TargetRow & { credential_id: string | null }, actor: AuditActor): Promise<void> {
  await db.query('DELETE FROM deploy_targets WHERE id = $1', [target.id])
  if (target.credential_id) await deleteSecret(db, target.credential_id)
  await writeAudit(db, { actor, action: 'deploy.target.delete', outcome: 'success', targetType: 'deploy_target', targetId: target.id, details: { project_id: target.project_id, kind: target.kind, environment: target.environment } })
}

// --- Proposition automatique (J11, principe 8) ---------------------------------------------

export interface TargetProposal {
  kind: 'cd-trigger'
  environment: string
  config: TargetConfig
  /** Pourquoi la cible est proposée (affiché dans la console). */
  reason: { workflow: string, path: string, inputs: CdInput[] }
}

const WORKFLOW_DIRS = ['.forgejo/workflows', '.gitea/workflows', '.github/workflows']

/**
 * Lit, sans rien exécuter, le bloc `on.workflow_dispatch.inputs` d'un
 * workflow : rend les entrées Scanoria déclarées, ou null si le workflow ne
 * se déclenche pas à la main ou n'attend pas scanoria_report.
 */
export function dispatchInputs(yaml: string): CdInput[] | null {
  if (yaml.length > 256 * 1024 || !/^\s*workflow_dispatch\s*:/m.test(yaml)) return null
  const declared = CD_INPUTS.filter(k => new RegExp(`^\\s+${k}\\s*:`, 'm').test(yaml))
  return declared.includes('scanoria_report') ? declared : null
}

function environmentOf(fileName: string): string {
  const base = fileName.replace(/\.ya?ml$/, '').toLowerCase()
  if (/prod/.test(base)) return 'production'
  if (/stag|recette|preprod/.test(base)) return 'staging'
  const clean = base.replace(/[^a-z0-9-]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 40)
  return /^[a-z0-9]/.test(clean) ? clean : 'deploy'
}

export async function proposeTargets(db: Queryable, projectId: string): Promise<TargetProposal[]> {
  const ctx = await projectForge(db, projectId)
  if (!ctx) return []
  const existing = await listTargets(db, projectId)
  const branch = (await ctx.client.repo(ctx.repo)).default_branch ?? 'main'
  const tree = await ctx.client.listTree(ctx.repo, branch, { maxEntries: 5000 })
  const out: TargetProposal[] = []
  for (const e of tree.entries) {
    const dir = WORKFLOW_DIRS.find(d => e.path.startsWith(`${d}/`))
    if (!dir || e.type !== 'file' || !/^[A-Za-z0-9._-]{1,100}\.ya?ml$/.test(e.path.slice(dir.length + 1))) continue
    const content = await ctx.client.readFile(ctx.repo, branch, e.path, { maxBytes: 256 * 1024 })
    const inputs = content ? dispatchInputs(content) : null
    if (!inputs) continue
    const workflow = e.path.slice(dir.length + 1)
    const config = parseConfig('cd-trigger', { provider: 'forge', workflow, inputs })
    const environment = environmentOf(workflow)
    if (!config || existing.some(t => t.kind === 'cd-trigger' && (t.environment === environment || (t.config as { workflow?: string }).workflow === workflow))) continue
    if (out.some(p => p.environment === environment)) continue
    out.push({ kind: 'cd-trigger', environment, config, reason: { workflow, path: e.path, inputs } })
    if (out.length >= 10) break
  }
  return out
}
