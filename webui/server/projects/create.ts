// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Ajout d'un projet depuis l'API (assistant F1) : dépôt d'une forge connue,
// URL Git libre (HTTPS + jeton, SSH + clé et clés d'hôte confirmées) ou
// archive téléversée. Tout ce qui peut être déduit l'est (principe 8) :
// branche par défaut, branches suivies, détection, profil, gate, planification.

import type { Queryable } from '../utils/db'
import { writeAudit, type AuditActor } from '../utils/audit'
import { encryptSecret } from '../utils/secrets'
import { forgeClient, getForge, openForge } from '../forges'
import { mapProjectError, projectError } from './errors'
import { fullNameFromPath, parseGitUrl } from './git-url'
import { parseKnownHosts } from './ssh'
import { uploadReady } from './uploads'
import type { ProjectCreateBody } from './schemas'
import {
  ProjectExistsError, createProject, detectWithClient, detectionError, dropUnusedCredential, githubFullName, type DetectionError, type ProjectRow,
} from './service'
import type { Detection } from './detect'

/** Projet existant ayant la même forge et le même dépôt, ou la même URL. */
async function existing(db: Queryable, opts: { forgeId?: string, fullName?: string, url?: string }): Promise<boolean> {
  if (opts.forgeId && opts.fullName) {
    const r = await db.query(`SELECT 1 FROM projects WHERE forge_id = $1 AND lower(repo_full_name) = lower($2)`, [opts.forgeId, opts.fullName])
    if (r.rowCount) return true
  }
  if (opts.url) {
    const r = await db.query(`SELECT 1 FROM projects WHERE lower(repo_url) = lower($1)`, [opts.url])
    if (r.rowCount) return true
  }
  return false
}

async function detect(client: ReturnType<typeof forgeClient>, fullName: string, ref: string): Promise<Detection | DetectionError> {
  try {
    return await detectWithClient(client, fullName, ref)
  }
  catch (err) {
    return detectionError(err)
  }
}

export async function createFromBody(db: Queryable, body: ProjectCreateBody, actor: AuditActor): Promise<ProjectRow> {
  const createdBy = actor.userId ?? null
  let project: ProjectRow
  let credentialId: string | null = null
  try {
    if (body.source === 'forge') {
      const forge = await getForge(db, body.forge_id)
      if (!forge) throw projectError(422, 'E_FORGE_NOT_FOUND')
      const client = await openForge(db, forge)
      const repo = await client.repo(body.repo)
      if (await existing(db, { forgeId: forge.id, fullName: repo.full_name, url: repo.clone_url })) throw new ProjectExistsError()
      const ref = repo.default_branch
      const detection = ref ? await detect(client, repo.full_name, ref) : null
      project = await createProject(db, {
        name: body.name ?? repo.full_name,
        sourceKind: 'git',
        forgeId: forge.id,
        repoFullName: repo.full_name,
        repoUrl: repo.clone_url,
        credentialId: forge.credential_id,
        defaultBranch: ref,
        trackedBranches: body.tracked_branches ?? (ref ? [ref] : []),
        schedule: body.schedule ?? 'on-commit',
        aiOptOut: body.ai_opt_out ?? false,
        spdxLicense: detection && 'license' in detection ? detection.license?.spdx ?? null : null,
        detection,
        createdBy,
      })
    }
    else if (body.source === 'git') {
      const url = parseGitUrl(body.url)
      if (await existing(db, { url: url.url })) throw new ProjectExistsError()
      let knownHosts: string | null = null
      if (body.auth.kind === 'ssh-key') {
        if (url.kind !== 'ssh') throw projectError(400, 'E_GIT_URL')
        const keys = parseKnownHosts(body.auth.known_hosts, url.host, url.port)
        if (!keys) throw projectError(400, 'E_KNOWN_HOSTS')
        knownHosts = keys.map(k => k.line).join('\n')
        credentialId = await encryptSecret(db, { kind: 'ssh-key', value: body.auth.private_key, createdBy })
      }
      else if (url.kind === 'ssh') {
        throw projectError(400, 'E_KNOWN_HOSTS')
      }
      else if (body.auth.kind === 'token') {
        credentialId = await encryptSecret(db, { kind: 'token', value: body.auth.token, username: body.auth.username ?? null, createdBy })
      }
      // Dépôt public de github.com : API anonyme pour la branche, la détection
      // et l'interrogation à chaque commit, sans rien demander de plus.
      const ghName = body.auth.kind === 'none' ? githubFullName(url.url) : null
      let defaultBranch = body.default_branch ?? null
      let detection: Detection | DetectionError | null = null
      if (ghName) {
        const client = forgeClient({ kind: 'github', base_url: 'https://github.com' })
        try {
          defaultBranch ??= (await client.repo(ghName)).default_branch
          if (defaultBranch) detection = await detect(client, ghName, defaultBranch)
        }
        catch (err) {
          detection = detectionError(err)
        }
      }
      defaultBranch ??= 'main'
      project = await createProject(db, {
        name: body.name ?? (fullNameFromPath(url.path) ?? url.path),
        sourceKind: 'git',
        repoFullName: ghName ?? fullNameFromPath(url.path),
        repoUrl: url.url,
        credentialId,
        sshKnownHosts: knownHosts,
        defaultBranch,
        trackedBranches: body.tracked_branches ?? [defaultBranch],
        // Sans API de forge, pas d'interrogation à chaque commit : analyse quotidienne.
        schedule: body.schedule ?? (ghName ? 'on-commit' : 'daily'),
        aiOptOut: body.ai_opt_out ?? false,
        spdxLicense: detection && 'license' in detection ? detection.license?.spdx ?? null : null,
        detection: detection ?? { version: 1, analyzed_at: new Date().toISOString().replace(/\.\d{3}Z$/, 'Z'), error: 'E_NO_FORGE_ACCESS' },
        createdBy,
      })
    }
    else {
      if (!(await uploadReady(body.upload_id))) throw projectError(422, 'E_UPLOAD_MISSING')
      const taken = await db.query(`SELECT 1 FROM projects WHERE upload_id = $1`, [body.upload_id])
      if (taken.rowCount) throw projectError(422, 'E_UPLOAD_MISSING')
      project = await createProject(db, {
        name: body.name,
        sourceKind: 'archive',
        uploadId: body.upload_id,
        schedule: body.schedule ?? 'daily',
        aiOptOut: body.ai_opt_out ?? false,
        createdBy,
      })
    }
  }
  catch (err) {
    await dropUnusedCredential(db, credentialId).catch(() => {})
    if (err instanceof ProjectExistsError) throw projectError(409, 'E_PROJECT_EXISTS')
    mapProjectError(err)
  }
  await writeAudit(db, {
    actor, action: 'project.create', outcome: 'success', targetType: 'project', targetId: project.id,
    details: {
      slug: project.slug, source: body.source, forge: project.forge_name, repo: project.repo_full_name ?? project.repo_url,
      schedule: project.schedule, profile: project.profile_slug, gate: project.gate_slug,
      credential: project.credential_kind ?? 'none',
    },
  })
  return project
}
