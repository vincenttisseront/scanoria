// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// PUT /api/projects/uploads (operator) : reçoit une archive de sources (corps
// brut, zip, tar ou tar.gz, 512 Mio au plus). Renvoie l'upload_id à donner à
// POST /api/projects ou PATCH /api/projects/:id.

import { defineEventHandler, getHeader, setResponseStatus } from 'h3'
import { apiError, requireRole } from '../../utils/http'
import { projectError } from '../../projects/errors'
import { ArchiveError, receiveArchive } from '../../projects/uploads'

export default defineEventHandler(async (event) => {
  requireRole(event, 'operator')
  try {
    const result = await receiveArchive(event.node.req, Number(getHeader(event, 'content-length') ?? '0'))
    setResponseStatus(event, 201)
    return result
  }
  catch (err) {
    if (err instanceof ArchiveError) {
      if (err.code === 'E_TOO_LARGE') throw apiError(413, 'E_TOO_LARGE')
      if (err.code === 'E_ARCHIVE_FORMAT') throw projectError(415, 'E_ARCHIVE_FORMAT')
      throw apiError(400, 'E_UPLOAD')
    }
    throw err
  }
})
