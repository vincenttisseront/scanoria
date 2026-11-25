// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// enqueueScan (contrat 4 de la 0.3) : met une analyse en file. Priorité de
// SCAN_PRIORITY selon le déclencheur, numéro croissant par projet, fusion
// d'une demande identique déjà en file (même projet, même commit ou même ref
// sans commit, même profil). Un rejeu (G11) reprend le plan d'origine.

import type pg from 'pg'
import { COMMIT_RE, SCAN_PRIORITY, SLUG_RE, type ScanTrigger } from '#shared/analysis'
import { UUID_V4_RE } from '#shared/schemas'
import { gitRef } from './contract'

export interface EnqueueScanInput {
  projectId: string
  ref: string
  commit?: string | null
  trigger: ScanTrigger
  profileSlug?: string | null
  requestedBy?: number | null
  apiTokenId?: string | null
  replayOf?: string | null
}

export interface EnqueueScanResult {
  scanId: string
  number: number
  /** true : une demande identique était déjà en file, elle est réutilisée. */
  merged: boolean
}

export type EnqueueErrorCode
  = | 'E_SCAN_PROJECT_NOT_FOUND' | 'E_SCAN_PROJECT_ARCHIVED' | 'E_SCAN_PROFILE' | 'E_SCAN_REF'
    | 'E_SCAN_REPLAY' | 'E_SCAN_SOURCE'

export class EnqueueScanError extends Error {
  constructor(readonly code: EnqueueErrorCode) {
    super(code)
    this.name = 'EnqueueScanError'
  }
}

type Db = Pick<pg.Pool, 'connect'>

interface ProjectRow {
  id: string
  source_kind: 'git' | 'archive'
  profile_id: string
  gate_id: string
  archived_at: Date | null
  extra: Record<string, unknown>
}

/** Référence d'une archive téléversée : aucune ref Git, une étiquette fixe. */
export const ARCHIVE_REF = 'archive'

export async function enqueueScan(db: Db, input: EnqueueScanInput): Promise<EnqueueScanResult> {
  if (!UUID_V4_RE.test(input.projectId)) throw new EnqueueScanError('E_SCAN_PROJECT_NOT_FOUND')
  if (input.commit != null && !COMMIT_RE.test(input.commit)) throw new EnqueueScanError('E_SCAN_REF')
  if (input.profileSlug != null && !SLUG_RE.test(input.profileSlug)) throw new EnqueueScanError('E_SCAN_PROFILE')
  if (input.replayOf != null && (!UUID_V4_RE.test(input.replayOf) || input.trigger !== 'replay')) throw new EnqueueScanError('E_SCAN_REPLAY')
  if (input.trigger === 'replay' && input.replayOf == null) throw new EnqueueScanError('E_SCAN_REPLAY')

  const client = await db.connect()
  try {
    await client.query('BEGIN')
    // Verrou du projet : numérotation et fusion sans course entre deux appels.
    const p = await client.query<ProjectRow>(
      `SELECT id, source_kind, profile_id, gate_id, archived_at,
              to_jsonb(projects) - 'detection' AS extra
         FROM projects WHERE id = $1 FOR UPDATE`, [input.projectId])
    const project = p.rows[0]
    if (!project) throw new EnqueueScanError('E_SCAN_PROJECT_NOT_FOUND')
    if (project.archived_at) throw new EnqueueScanError('E_SCAN_PROJECT_ARCHIVED')

    let ref = input.ref
    let commit = input.commit ?? null
    let profileId = project.profile_id
    let gateId = project.gate_id
    let plan: unknown = null
    // Archive : la dernière téléversée du projet (projects.upload_id, migration 004).
    const projectUpload = typeof project.extra.upload_id === 'string' ? project.extra.upload_id : null
    let uploadId: string | null = project.source_kind === 'archive' ? projectUpload : null

    if (input.trigger === 'replay') {
      const o = await client.query<{ commit_sha: string | null, ref: string, profile_id: string, gate_id: string, plan: unknown, upload_id: string | null }>(
        `SELECT commit_sha, ref, profile_id, gate_id, plan, upload_id FROM scans
          WHERE id = $1 AND project_id = $2 AND trigger <> 'trial'`,
        [input.replayOf, project.id])
      const orig = o.rows[0]
      // Une analyse d'essai (F13) ne se rejoue jamais : sa candidate n'est pas une version de production.
      if (!orig || !orig.plan) throw new EnqueueScanError('E_SCAN_REPLAY')
      ref = orig.ref
      commit = orig.commit_sha
      profileId = orig.profile_id
      gateId = orig.gate_id
      plan = orig.plan
      uploadId = orig.upload_id
    }
    else {
      if (project.source_kind === 'archive') {
        ref = ARCHIVE_REF
        if (!uploadId) throw new EnqueueScanError('E_SCAN_SOURCE')
      }
      else if (!gitRef.safeParse(ref).success) {
        throw new EnqueueScanError('E_SCAN_REF')
      }
      if (input.profileSlug) {
        const pr = await client.query<{ id: string }>('SELECT id FROM profiles WHERE slug = $1', [input.profileSlug])
        if (!pr.rows[0]) throw new EnqueueScanError('E_SCAN_PROFILE')
        profileId = pr.rows[0].id
      }
    }

    const priority = SCAN_PRIORITY[input.trigger]
    if (input.trigger !== 'replay') {
      const dup = await client.query<{ id: string, number: number }>(
        `SELECT id, number FROM scans
          WHERE project_id = $1 AND status = 'queued' AND profile_id = $2 AND gate_id = $6 AND trigger NOT IN ('replay', 'trial')
            AND ($3::text IS NULL AND commit_sha IS NULL AND ref = $4 OR commit_sha = $3)
            AND upload_id IS NOT DISTINCT FROM $5
          ORDER BY queued_at LIMIT 1`,
        [project.id, profileId, commit, ref, uploadId, gateId])
      if (dup.rows[0]) {
        // La demande la plus urgente l'emporte ; l'ancienneté est conservée.
        await client.query('UPDATE scans SET priority = GREATEST(priority, $2) WHERE id = $1', [dup.rows[0].id, priority])
        await client.query('COMMIT')
        return { scanId: dup.rows[0].id, number: dup.rows[0].number, merged: true }
      }
    }

    const ins = await client.query<{ id: string, number: number }>(
      `INSERT INTO scans (project_id, number, trigger, priority, ref, commit_sha, upload_id, profile_id, gate_id,
                          plan, replay_of, requested_by, api_token_id)
       VALUES ($1, (SELECT COALESCE(max(number), 0) + 1 FROM scans WHERE project_id = $1),
               $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
       RETURNING id, number`,
      [project.id, input.trigger, priority, ref, commit, uploadId, profileId, gateId,
        plan === null ? null : JSON.stringify(plan), input.replayOf ?? null, input.requestedBy ?? null, input.apiTokenId ?? null])
    await client.query('COMMIT')
    return { scanId: ins.rows[0]!.id, number: ins.rows[0]!.number, merged: false }
  }
  catch (err) {
    await client.query('ROLLBACK').catch(() => {})
    throw err
  }
  finally {
    client.release()
  }
}
