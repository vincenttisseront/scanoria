// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Session côté client : utilisateur, rôle, jeton CSRF (jamais le cookie, httpOnly).

import { hasRole as roleAtLeast, type Role } from '#shared/schemas'

export interface ClientUser {
  id: number
  username: string
  display_name: string | null
  role: Role
  locale: 'fr' | 'en'
  must_change_password: boolean
}

interface SessionState {
  loaded: boolean
  user: ClientUser | null
  csrf: string | null
  address: string | null
}

type SessionResponse
  = | { authenticated: false }
    | { authenticated: true, csrf: string, address: string | null, user: ClientUser }

export function useSession() {
  const state = useState<SessionState>('session', () => ({ loaded: false, user: null, csrf: null, address: null }))

  async function refresh(): Promise<void> {
    try {
      const res = await $fetch<SessionResponse>('/api/auth/session')
      if (res.authenticated) {
        state.value = { loaded: true, user: res.user, csrf: res.csrf, address: res.address }
      }
      else {
        state.value = { loaded: true, user: null, csrf: null, address: null }
      }
    }
    catch {
      state.value = { loaded: true, user: null, csrf: null, address: null }
    }
  }

  function clear(): void {
    state.value = { loaded: true, user: null, csrf: null, address: null }
  }

  function can(role: Role): boolean {
    return !!state.value.user && roleAtLeast(state.value.user.role, role)
  }

  return { state, refresh, clear, can }
}
