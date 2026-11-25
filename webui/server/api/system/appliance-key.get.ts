// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// GET /api/system/appliance-key (public, contrat 37) : clé publique Ed25519
// de l'appliance, qui signe les rapports de release (§ 7.3) et les lots hors
// ligne. { public_key (32 octets bruts en base64), fingerprint (SHA-256 de la
// clé brute, hexadécimal), pem (SubjectPublicKeyInfo) }. Jamais la clé privée,
// que la console ne voit pas. 503 E_KEY_UNAVAILABLE tant que le helper ne l'a
// pas créée. scanoria-verify --fetch-key exige en plus l'empreinte attendue.

import { createError, defineEventHandler } from 'h3'
import { applianceKey } from '../../release/sign'

export default defineEventHandler(async () => {
  const key = await applianceKey()
  if (!key) throw createError({ statusCode: 503, statusMessage: 'E_KEY_UNAVAILABLE', data: { code: 'E_KEY_UNAVAILABLE' } })
  return { algorithm: 'ed25519', public_key: key.public_key, fingerprint: key.fingerprint, pem: key.pem }
})
