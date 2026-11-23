// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// GET /api/auth/session : utilisateur connecté et jeton CSRF à renvoyer dans
// X-CSRF-Token. Sans session : {"authenticated": false}.

import { defineEventHandler } from 'h3'
import { clientAddress } from '../../utils/http'

export default defineEventHandler((event) => {
  const auth = event.context.auth
  if (!auth) return { authenticated: false as const }
  return {
    authenticated: true as const,
    csrf: auth.csrf,
    address: clientAddress(event) ?? null,
    user: {
      id: auth.user.id,
      username: auth.user.username,
      display_name: auth.user.displayName,
      role: auth.user.role,
      locale: auth.user.locale,
      must_change_password: auth.user.mustChangePassword,
    },
  }
})
