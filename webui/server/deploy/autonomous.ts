// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// J16 (0.8, chantier D) : chaîne autonome PR → analyse → fusion → release →
// déploiement, pour un projet qui l'a activée (projects.autonomous_chain).
// L'appliance ne fusionne jamais : après un verdict favorable de l'analyse de
// PR, elle active seulement la fusion automatique NATIVE de la forge
// (« fusionner quand les contrôles passent »), et seulement si l'auteur de la
// PR l'a demandé par la ligne « /scanoria auto-merge » de sa description. La
// suite (tag → profil release → J11, J12, J13) part du verdict de release.
// Un verdict défavorable ou non concluant arrête tout : rien n'est activé.

import type { Queryable } from '../utils/db'
import { writeAudit } from '../utils/audit'
import { getForge, forgeAccess } from '../forges'
import { consoleUrl } from '../forges/context'
import { forgeDeployer } from '../forges/deploy'
import { ForgeError } from '../forges/http'

export const AUTO_MERGE_MARKER = /^[ \t]*\/scanoria[ \t]+auto-merge[ \t]*$/m
export const AUTOMERGE_ACTION = 'deploy.autonomous.automerge'

/** Vrai si la description de la PR (écrite par son auteur) demande la fusion automatique. */
export function authorRequestedAutoMerge(body: string): boolean {
  return AUTO_MERGE_MARKER.test(body.slice(0, 65536))
}

interface PrScan {
  id: string
  project_id: string
  forge_id: string | null
  repo_full_name: string | null
  number: number
  head_sha: string | null
}

/**
 * Une passe : analyses de PR au verdict favorable des projets en chaîne
 * autonome, dont la fusion automatique n'a pas encore été traitée. Chaque PR
 * n'est traitée qu'une fois par analyse (ligne d'audit). Rend le nombre de
 * PR dont la fusion automatique a été activée.
 */
export async function autonomousPass(db: Queryable): Promise<number> {
  const r = await db.query<PrScan>(
    `SELECT s.id::text, s.project_id::text, p.forge_id::text, p.repo_full_name,
            (s.pull_request ->> 'number')::int AS number, s.pull_request ->> 'head_sha' AS head_sha
       FROM scans s JOIN projects p ON p.id = s.project_id
      WHERE p.autonomous_chain AND p.suspended_at IS NULL AND p.archived_at IS NULL
        AND s.pull_request IS NOT NULL AND s.status = 'done' AND s.verdict = 'passed'
        AND s.finished_at > now() - interval '2 hours'
        AND (s.pull_request ->> 'number') ~ '^[0-9]{1,9}$'
        AND NOT EXISTS (SELECT 1 FROM audit_log a WHERE a.action = $1 AND a.target_type = 'scan' AND a.target_id = s.id::text)
        AND NOT EXISTS (SELECT 1 FROM scans n WHERE n.project_id = s.project_id AND n.pull_request ->> 'number' = s.pull_request ->> 'number'
                         AND n.queued_at > s.queued_at)
      ORDER BY s.finished_at LIMIT 20`, [AUTOMERGE_ACTION])
  let enabled = 0
  for (const s of r.rows) {
    let outcome: 'enabled' | 'unsupported' | 'not-requested' | 'closed' | 'stale' | 'error' = 'error'
    let code: string | null = null
    try {
      const forge = s.forge_id ? await getForge(db, s.forge_id) : null
      if (!forge || !s.repo_full_name) throw new ForgeError('E_FORGE_UNSUPPORTED')
      const access = await forgeAccess(db, forge)
      if (!access.token) throw new ForgeError('E_FORGE_AUTH')
      const deployer = forgeDeployer(access, { consoleUrl: await consoleUrl() })
      const info = await deployer.pullRequestInfo(s.repo_full_name, s.number)
      if (!info.open) outcome = 'closed'
      else if (!authorRequestedAutoMerge(info.body)) outcome = 'not-requested'
      // Le verdict porte sur head_sha : une PR qui a reçu un autre commit depuis
      // attend sa propre analyse, et la forge refuse si la tête change encore.
      else if (!s.head_sha || info.headSha !== s.head_sha) outcome = 'stale'
      else outcome = await deployer.enableAutoMerge(s.repo_full_name, s.number, s.head_sha)
    }
    catch (err) {
      code = err instanceof ForgeError ? err.code : 'E_DEPLOY_INTERNAL'
    }
    if (outcome === 'enabled') enabled++
    await writeAudit(db, {
      actor: { type: 'system', username: 'system' },
      action: AUTOMERGE_ACTION,
      outcome: outcome === 'error' ? 'failure' : 'success',
      targetType: 'scan',
      targetId: s.id,
      details: { project_id: s.project_id, pull_request: s.number, head_sha: s.head_sha, result: outcome, ...(code ? { error: code } : {}) },
    })
  }
  return enabled
}
