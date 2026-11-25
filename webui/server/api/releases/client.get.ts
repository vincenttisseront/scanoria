// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// GET /api/releases/client (public) : client scanoria-verify (POSIX sh,
// openssl) installé par l'appliance, qui vérifie un rapport de release signé.

import { constants } from 'node:fs'
import { open } from 'node:fs/promises'
import { defineEventHandler, setHeader } from 'h3'
import { apiError } from '../../utils/http'

export const VERIFY_CLIENT_FILE = '/usr/share/scanoria/client/scanoria-verify'

export default defineEventHandler(async (event) => {
  const path = process.env.NUXT_SCANORIA_VERIFY_CLIENT || VERIFY_CLIENT_FILE
  try {
    const fh = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW)
    let body: string
    try {
      const st = await fh.stat()
      if (!st.isFile() || st.size > 256 * 1024) throw new Error('not a regular file')
      body = await fh.readFile('utf8')
    }
    finally {
      await fh.close()
    }
    if (!body.startsWith('#!/bin/sh')) throw new Error('unexpected content')
    setHeader(event, 'content-type', 'text/x-shellscript; charset=utf-8')
    setHeader(event, 'content-disposition', 'attachment; filename="scanoria-verify"')
    return body
  }
  catch {
    throw apiError(404, 'E_NOT_FOUND')
  }
})
