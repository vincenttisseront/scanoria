// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Garde de navigation : connexion exigée, changement de mot de passe imposé,
// rôle minimal par page (definePageMeta({ role })). Le serveur contrôle tout
// de nouveau : cette garde ne sert qu'à l'ergonomie.

import type { Role } from '#shared/schemas'

declare module '#app' {
  interface PageMeta {
    role?: Role
    public?: boolean
  }
}

export default defineNuxtRouteMiddleware(async (to) => {
  const session = useSession()
  if (!session.state.value.loaded) await session.refresh()
  const user = session.state.value.user
  if (to.meta.public) {
    if (to.path === '/login' && user) return navigateTo('/')
    return
  }
  if (!user) return navigateTo({ path: '/login', query: to.fullPath !== '/' ? { next: to.fullPath } : {} })
  if (user.must_change_password && to.path !== '/account') return navigateTo('/account')
  if (to.meta.role && !session.can(to.meta.role)) return navigateTo('/')
})
