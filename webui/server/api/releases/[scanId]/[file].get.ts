// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Fichiers d'une release (§ 7.3), en téléchargement :
// - report.json : rapport signé (enveloppe vérifiée par scanoria-verify) ;
//   aussi lisible par le jeton d'API du projet (scanoria-scan --report) ;
// - results.sarif, sbom.cdx.json : fichiers rangés à la création du rapport,
//   dont l'empreinte est inscrite dans le rapport signé ;
// - vex.json : document OpenVEX de l'analyse, dont l'empreinte est dans le rapport ;
// - notes.md : annexe I6 non signée, proposée par IA (si elle existe).

import { defineEventHandler, getRouterParam, setHeader } from 'h3'
import { getPool } from '../../../utils/db'
import { apiError, clientAddress } from '../../../utils/http'
import { writeAudit } from '../../../utils/audit'
import { ciCaller, uuidParam } from '../../../gates/http'
import { readArtifact } from '../../../release/artifacts'
import { signedEnvelope } from '../../../release/sign'
import { getRelease, releaseError } from '../../../release/api'
import { notesMarkdown } from '../../../release/notes'

const FILES = {
  'report.json': 'application/json',
  'results.sarif': 'application/sarif+json',
  'sbom.cdx.json': 'application/vnd.cyclonedx+json',
  'notes.md': 'text/markdown; charset=utf-8',
  'vex.json': 'application/json',
} as const

export default defineEventHandler(async (event) => {
  const file = getRouterParam(event, 'file') ?? ''
  if (!(file in FILES)) throw apiError(404, 'E_NOT_FOUND')
  const name = file as keyof typeof FILES
  // Le jeton d'API ne lit que le rapport signé de son projet.
  const caller = ciCaller(event, 'scan:read', 'viewer')
  if (caller.kind === 'token' && name !== 'report.json') throw apiError(404, 'E_NOT_FOUND')
  const scanId = uuidParam(getRouterParam(event, 'scanId'))
  const pool = getPool()
  const rel = await getRelease(pool, scanId)
  if (!rel || (caller.kind === 'token' && rel.project_id !== caller.token.projectId)) throw releaseError(404, 'E_RELEASE_NOT_FOUND')
  let body: Buffer | string | null
  if (name === 'report.json') {
    if (rel.status !== 'signed') throw releaseError(409, 'E_RELEASE_NOT_SIGNED', { status: rel.status })
    body = signedEnvelope({ report: rel.report, report_sha256: rel.report_sha256, signature: rel.signature!, key_fingerprint: rel.key_fingerprint!, signed_at: rel.signed_at! })
  }
  else if (name === 'notes.md') body = await notesMarkdown(pool, scanId)
  else body = await readArtifact(scanId, name)
  if (!body) throw apiError(404, 'E_NOT_FOUND')
  await writeAudit(pool, {
    actor: caller.kind === 'user'
      ? { type: 'user', userId: caller.auth.user.id, username: caller.auth.user.username, ip: clientAddress(event) }
      : { type: 'system', username: `api-token:${caller.token.prefix}`, ip: clientAddress(event) },
    action: 'release.download', outcome: 'success', targetType: 'scan', targetId: scanId, details: { file: name, tag: rel.tag },
  })
  const safeTag = rel.tag.replace(/[^A-Za-z0-9._-]/g, '_')
  setHeader(event, 'content-type', FILES[name])
  setHeader(event, 'content-disposition', `attachment; filename="${rel.project_slug}-${safeTag}-${name}"`)
  setHeader(event, 'cache-control', 'no-store')
  return body
})
