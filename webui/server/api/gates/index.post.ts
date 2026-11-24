// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// POST /api/gates (admin) : crée un gate en copiant les règles de « defaut »
// (ou de copy_from). Audit gate.create.

import { defineEventHandler, setResponseStatus } from 'h3'
import { getPool } from '../../utils/db'
import { apiError, clientAddress, readValidated, requireRole } from '../../utils/http'
import { writeAudit } from '../../utils/audit'
import { SlugTakenError, createGate, gateCreateSchema } from '../../gates/gates'
import { gateError } from '../../gates/http'

export default defineEventHandler(async (event) => {
  const auth = requireRole(event, 'admin')
  const body = await readValidated(event, gateCreateSchema)
  const pool = getPool()
  try {
    const gate = await createGate(pool, { slug: body.slug, copyFrom: body.copy_from, userId: auth.user.id })
    if (!gate) throw apiError(404, 'E_NOT_FOUND')
    await writeAudit(pool, {
      actor: { type: 'user', userId: auth.user.id, username: auth.user.username, ip: clientAddress(event) },
      action: 'gate.create', outcome: 'success', targetType: 'gate', targetId: gate.id,
      details: { slug: gate.slug, copy_from: body.copy_from ?? 'defaut', rules: gate.rules },
    })
    setResponseStatus(event, 201)
    return gate
  }
  catch (err) {
    if (err instanceof SlugTakenError) throw gateError(409, 'E_SLUG_TAKEN')
    throw err
  }
})
