// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// GET /api/gates/client (public) : client scanoria-scan (POSIX sh, curl, jq)
// installé par l'appliance, à télécharger par la CI ou depuis la console.

import { lstat, readFile } from 'node:fs/promises'
import { defineEventHandler, setHeader } from 'h3'
import { apiError } from '../../utils/http'

export const CLIENT_FILE = '/usr/share/scanoria/client/scanoria-scan'

export default defineEventHandler(async (event) => {
  const path = process.env.NUXT_SCANORIA_SCAN_CLIENT || CLIENT_FILE
  try {
    const st = await lstat(path)
    if (!st.isFile() || st.size > 256 * 1024) throw new Error('not a regular file')
    const body = await readFile(path, 'utf8')
    if (!body.startsWith('#!/bin/sh')) throw new Error('unexpected content')
    setHeader(event, 'content-type', 'text/x-shellscript; charset=utf-8')
    setHeader(event, 'content-disposition', 'attachment; filename="scanoria-scan"')
    return body
  }
  catch {
    throw apiError(404, 'E_NOT_FOUND')
  }
})
