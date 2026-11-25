// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Socle de la 0.7 : verrous de profil (contrat 28).
import { describe, expect, it } from 'vitest'
import { ProfileLocks } from '#shared/analysis'

describe('socle 0.7 : verrous de profil (G8)', () => {
  it('défauts vides', () => {
    expect(ProfileLocks.parse({})).toEqual({ required_categories: [], required_modules: [], gate_floor: {}, ai_opt_out: false })
  })

  it('plancher de gate partiel, valeurs du gate validées', () => {
    const l = ProfileLocks.parse({ required_categories: ['secrets'], gate_floor: { max_secrets: 0, vuln_block_from: 'medium' }, ai_opt_out: true })
    expect(l.gate_floor).toEqual({ max_secrets: 0, vuln_block_from: 'medium' })
    expect(ProfileLocks.safeParse({ gate_floor: { vuln_block_from: 'tres-haut' } }).success).toBe(false)
    expect(ProfileLocks.safeParse({ gate_floor: { block_malicious: false } }).success).toBe(false)
  })

  it('clés inconnues, catégorie ou module invalides refusés', () => {
    expect(ProfileLocks.safeParse({ extra: 1 }).success).toBe(false)
    expect(ProfileLocks.safeParse({ gate_floor: { extra: 1 } }).success).toBe(false)
    expect(ProfileLocks.safeParse({ required_categories: ['inconnue'] }).success).toBe(false)
    expect(ProfileLocks.safeParse({ required_modules: ['../x'] }).success).toBe(false)
  })
})
