// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Modification d'un projet : réglages, secret (jeton ou clé SSH, toujours
// chiffrés), clés d'hôte confirmées, nouvelle archive. Audit sans valeur.

import type { z } from 'zod'
import type { Queryable } from '../utils/db'
import { writeAudit, type AuditActor } from '../utils/audit'
import { apiError } from '../utils/http'
import { encryptSecret, rotateSecret } from '../utils/secrets'
import { mapProjectError, projectError } from './errors'
import { parseGitUrl } from './git-url'
import { parseKnownHosts } from './ssh'
import { removeUpload, uploadReady } from './uploads'
import type { projectUpdateSchema } from './schemas'
import { dropUnusedCredential, getProject, updateProject, type ProjectPatch, type ProjectRow } from './service'

type Body = z.infer<typeof projectUpdateSchema>

export async function patchFromBody(db: Queryable, project: ProjectRow, body: Body, actor: AuditActor): Promise<ProjectRow> {
  if (project.archived_at) throw projectError(409, 'E_ARCHIVED')
  const patch: ProjectPatch = {}
  const changed: string[] = []
  const set = <K extends keyof ProjectPatch>(k: K, v: ProjectPatch[K] | undefined) => {
    if (v === undefined) return
    patch[k] = v
    changed.push(k)
  }
  set('name', body.name)
  set('tracked_branches', body.tracked_branches)
  set('schedule', body.schedule)
  set('ai_opt_out', body.ai_opt_out)

  if (body.profile_id) {
    const r = await db.query(`SELECT 1 FROM profiles WHERE id = $1`, [body.profile_id])
    if (!r.rowCount) throw apiError(400, 'E_VALIDATION', { issues: [{ path: 'profile_id', code: 'not_found' }] })
    set('profile_id', body.profile_id)
  }
  if (body.gate_id) {
    const r = await db.query(`SELECT 1 FROM gates WHERE id = $1`, [body.gate_id])
    if (!r.rowCount) throw apiError(400, 'E_VALIDATION', { issues: [{ path: 'gate_id', code: 'not_found' }] })
    set('gate_id', body.gate_id)
  }

  const oldCredential = project.credential_id
  // Secret partagé avec la forge : jamais modifié depuis un projet (on le
  // remplace par un secret propre au projet).
  const ownCredential = async () => {
    if (!project.credential_id) return null
    const r = await db.query(`SELECT 1 FROM forges WHERE credential_id = $1`, [project.credential_id])
    return r.rowCount ? null : project.credential_id
  }

  if (body.token !== undefined) {
    if (project.source_kind !== 'git' || (project.repo_url && !project.repo_url.startsWith('https://'))) throw projectError(400, 'E_GIT_URL')
    if (body.token === null) {
      set('credential_id', null)
    }
    else {
      const own = await ownCredential()
      if (own && project.credential_kind === 'token') await rotateSecret(db, own, body.token)
      else set('credential_id', await encryptSecret(db, { kind: 'token', value: body.token, createdBy: actor.userId ?? null }))
    }
    changed.push('token')
  }

  if (body.ssh) {
    let url
    try {
      url = parseGitUrl(project.repo_url ?? '')
    }
    catch (err) {
      mapProjectError(err)
    }
    if (url.kind !== 'ssh') throw projectError(400, 'E_GIT_URL')
    const keys = parseKnownHosts(body.ssh.known_hosts, url.host, url.port)
    if (!keys) throw projectError(400, 'E_KNOWN_HOSTS')
    set('ssh_known_hosts', keys.map(k => k.line).join('\n'))
    if (body.ssh.private_key) {
      const own = await ownCredential()
      if (own && project.credential_kind === 'ssh-key') await rotateSecret(db, own, body.ssh.private_key)
      else set('credential_id', await encryptSecret(db, { kind: 'ssh-key', value: body.ssh.private_key, createdBy: actor.userId ?? null }))
      changed.push('ssh_key')
    }
  }

  if (body.upload_id) {
    if (project.source_kind !== 'archive') throw projectError(400, 'E_UPLOAD_MISSING')
    if (!(await uploadReady(body.upload_id))) throw projectError(422, 'E_UPLOAD_MISSING')
    set('upload_id', body.upload_id)
  }

  await updateProject(db, project.id, patch)
  if (patch.credential_id !== undefined && oldCredential && patch.credential_id !== oldCredential) {
    await dropUnusedCredential(db, oldCredential)
  }
  if (patch.upload_id && project.upload_id && project.upload_id !== patch.upload_id) await removeUpload(project.upload_id)
  await writeAudit(db, {
    actor, action: 'project.update', outcome: 'success', targetType: 'project', targetId: project.id,
    details: {
      slug: project.slug, changed,
      schedule: body.schedule, tracked_branches: body.tracked_branches, ai_opt_out: body.ai_opt_out,
    },
  })
  return (await getProject(db, project.id))!
}
