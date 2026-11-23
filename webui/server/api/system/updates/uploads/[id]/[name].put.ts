// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// PUT /api/system/updates/uploads/:id/:name (admin) : reçoit un des quatre
// fichiers d'une release (corps brut, en flux, taille bornée). Noms admis :
// release.json, SHA256SUMS, SHA256SUMS.sig, scanoria-X.Y.Z.tar.zst. Aucune
// vérification cryptographique ici : le service root vérifie tout.

import { createWriteStream } from 'node:fs'
import { lstat, unlink } from 'node:fs/promises'
import { join } from 'node:path'
import { Transform } from 'node:stream'
import { pipeline } from 'node:stream/promises'
import { defineEventHandler, getHeader, getRouterParam, setResponseStatus } from 'h3'
import { getConfig } from '../../../../../utils/config'
import { apiError, requireRole } from '../../../../../utils/http'
import { ARCHIVE_NAME_RE, UPLOAD_FILE_NAMES, UUID_V4_RE } from '#shared/schemas'

const LIMITS: Record<string, number> = {
  'release.json': 128 * 1024,
  'SHA256SUMS': 4096,
  'SHA256SUMS.sig': 64,
}
const ARCHIVE_LIMIT = 1024 * 1024 * 1024

export default defineEventHandler(async (event) => {
  requireRole(event, 'admin')
  const id = getRouterParam(event, 'id') ?? ''
  const name = decodeURIComponent(getRouterParam(event, 'name') ?? '')
  if (!UUID_V4_RE.test(id)) throw apiError(404, 'E_NOT_FOUND')
  const isArchive = ARCHIVE_NAME_RE.test(name)
  if (!isArchive && !(UPLOAD_FILE_NAMES as readonly string[]).includes(name)) throw apiError(400, 'E_UPLOAD')
  const limit = isArchive ? ARCHIVE_LIMIT : LIMITS[name]!
  const declared = Number(getHeader(event, 'content-length') ?? '0')
  if (declared > limit) throw apiError(413, 'E_TOO_LARGE')
  const dir = join(getConfig().uploadsDir, id)
  try {
    const st = await lstat(dir)
    if (!st.isDirectory()) throw new Error('not a directory')
  }
  catch {
    throw apiError(404, 'E_NOT_FOUND')
  }
  const target = join(dir, name)
  let received = 0
  const guard = new Transform({
    transform(chunk: Buffer, _enc, callback) {
      received += chunk.length
      if (received > limit) callback(new Error('too large'))
      else callback(null, chunk)
    },
  })
  try {
    await pipeline(event.node.req, guard, createWriteStream(target, { flags: 'wx', mode: 0o600 }))
  }
  catch (err) {
    if ((err as NodeJS.ErrnoException).code !== 'EEXIST') await unlink(target).catch(() => {})
    if (received > limit) throw apiError(413, 'E_TOO_LARGE')
    throw apiError(400, 'E_UPLOAD')
  }
  setResponseStatus(event, 201)
  return { upload_id: id, name, size: received }
})
