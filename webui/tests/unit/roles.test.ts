// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront

import { describe, expect, it } from 'vitest'
import { ROLES, ROLE_RANK, hasRole } from '#shared/schemas'

describe('rôles viewer < operator < admin', () => {
  it('suit les rangs de la table roles (10, 20, 30)', () => {
    expect(ROLE_RANK).toEqual({ viewer: 10, operator: 20, admin: 30 })
  })

  it('applique la hiérarchie', () => {
    const matrix: Record<string, Record<string, boolean>> = {
      viewer: { viewer: true, operator: false, admin: false },
      operator: { viewer: true, operator: true, admin: false },
      admin: { viewer: true, operator: true, admin: true },
    }
    for (const actual of ROLES) {
      for (const required of ROLES) {
        expect(hasRole(actual, required), `${actual} >= ${required}`).toBe(matrix[actual]![required])
      }
    }
  })
})
