// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Adresse du client. La console écoute sur 127.0.0.1 derrière nginx : quand la
// connexion vient de la boucle locale, l'adresse réelle est dans X-Real-IP
// (posé par nginx, jamais repris du client).

import { isIP } from 'node:net'
import { ADDRESS_RE } from '#shared/schemas'

export function normalizeAddress(raw: string | undefined | null): string | undefined {
  if (!raw) return undefined
  let value = raw.trim().toLowerCase()
  if (value.startsWith('::ffff:') && isIP(value.slice(7)) === 4) value = value.slice(7)
  const zone = value.indexOf('%')
  if (zone !== -1) value = value.slice(0, zone)
  if (isIP(value) === 0) return undefined
  return ADDRESS_RE.test(value) && value.length <= 45 ? value : undefined
}

function isLoopback(address: string | undefined): boolean {
  return !!address && (address === '::1' || address.startsWith('127.'))
}

export function resolveClientAddress(
  remoteAddress: string | undefined,
  realIpHeader: string | string[] | undefined,
  trustProxy: boolean,
): string | undefined {
  const remote = normalizeAddress(remoteAddress)
  if (trustProxy && isLoopback(remote) && typeof realIpHeader === 'string') {
    return normalizeAddress(realIpHeader) ?? remote
  }
  return remote
}
