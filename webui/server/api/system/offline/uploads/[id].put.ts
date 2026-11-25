// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// PUT /api/system/offline/uploads/:id (admin) : reçoit l'archive du lot (corps
// brut, en flux, 64 Gio au plus, sans tampon disque côté nginx). Aucune
// vérification cryptographique ici : le service root vérifie tout à l'import.

import { createWriteStream } from 'node:fs'
import { lstat, unlink } from 'node:fs/promises'
import { join } from 'node:path'
import { Transform } from 'node:stream'
import { pipeline } from 'node:stream/promises'
import { defineEventHandler, getHeader, getRouterParam, setResponseStatus } from 'h3'
import { getConfig } from '../../../../utils/config'
import { apiError, requireRole } from '../../../../utils/http'
import { UUID_V4_RE } from '#shared/schemas'
import { BUNDLE_UPLOAD_LIMIT, BUNDLE_UPLOAD_NAME } from '../../../../offline/upload'

export default defineEventHandler(async (event) => {
  requireRole(event, 'admin')
  const id = getRouterParam(event, 'id') ?? ''
  if (!UUID_V4_RE.test(id)) throw apiError(404, 'E_NOT_FOUND')
  const declared = Number(getHeader(event, 'content-length') ?? '0')
  if (declared > BUNDLE_UPLOAD_LIMIT) {
    event.node.req.resume()
    throw apiError(413, 'E_TOO_LARGE')
  }
  const dir = join(getConfig().uploadsDir, id)
  try {
    const st = await lstat(dir)
    if (!st.isDirectory()) throw new Error('not a directory')
  }
  catch {
    throw apiError(404, 'E_NOT_FOUND')
  }
  const target = join(dir, BUNDLE_UPLOAD_NAME)
  const refuse = (status: number, code: 'E_UPLOAD' | 'E_TOO_LARGE') => {
    // Corps non lu : vidé pour répondre proprement au lieu de couper la connexion.
    event.node.req.resume()
    return apiError(status, code)
  }
  if (await lstat(target).then(() => true, () => false)) throw refuse(400, 'E_UPLOAD')
  let received = 0
  const guard = new Transform({
    transform(chunk: Buffer, _enc, callback) {
      received += chunk.length
      if (received > BUNDLE_UPLOAD_LIMIT) callback(new Error('too large'))
      else callback(null, chunk)
    },
  })
  try {
    await pipeline(event.node.req, guard, createWriteStream(target, { flags: 'wx', mode: 0o600 }))
  }
  catch (err) {
    if ((err as NodeJS.ErrnoException).code !== 'EEXIST') await unlink(target).catch(() => {})
    if (received > BUNDLE_UPLOAD_LIMIT) throw refuse(413, 'E_TOO_LARGE')
    throw refuse(400, 'E_UPLOAD')
  }
  if (received === 0) {
    await unlink(target).catch(() => {})
    throw apiError(400, 'E_UPLOAD')
  }
  setResponseStatus(event, 201)
  return { upload_id: id, size: received }
})
