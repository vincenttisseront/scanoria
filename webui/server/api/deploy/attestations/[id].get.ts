// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// GET /api/deploy/attestations/:id (lecture) : enveloppe DSSE signée d'une
// attestation J9, téléchargeable même si le registre l'a refusée.

import { defineEventHandler, getRouterParam, setHeader } from 'h3'
import { getPool } from '../../../utils/db'
import { apiError, requireRole } from '../../../utils/http'
import { getAttestation } from '../../../attest'

export default defineEventHandler(async (event) => {
  requireRole(event, 'viewer')
  const id = getRouterParam(event, 'id') ?? ''
  const att = /^[0-9a-f-]{36}$/.test(id) ? await getAttestation(getPool(), id) : null
  if (!att?.envelope) throw apiError(404, 'E_NOT_FOUND')
  setHeader(event, 'content-type', 'application/vnd.dsse.envelope.v1+json')
  setHeader(event, 'content-disposition', `attachment; filename="attestation-${att.subject_digest.slice(7, 19)}.dsse.json"`)
  return att.envelope
})
