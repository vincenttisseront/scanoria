// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Corpus piégé de tests/b33-profils.sh (J8) : chaque fichier du répertoire
// B33_CORPUS est lu par le vrai analyseur, sans exécution.
// - repo-ok-*.yml : .scanoria.yml valide ; <nom>.requests donne le nombre de
//   demandes attendu ; aucune demande ne vise tout le dépôt ni ne sort du dépôt ;
// - repo-ko-*.yml : refusé, avec au moins un problème signalé ;
// - appliance-ko-*.yml : export de configuration refusé à l'import.
// Sans B33_CORPUS (exécution ordinaire de vitest), le fichier est ignoré.

import { existsSync, readdirSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { configRequests, parseRepoConfig } from '../../server/config/repo-config'
import { parseApplianceConfig } from '../../server/config/appliance'

const DIR = process.env.B33_CORPUS ?? ''
const files = DIR && existsSync(DIR) ? readdirSync(DIR).filter(f => f.endsWith('.yml')).sort() : []
const read = (f: string) => readFileSync(join(DIR, f)).toString('utf8')

describe.skipIf(!files.length)('config-hostile : corpus b33', () => {
  it.each(files.filter(f => f.startsWith('repo-ok-')))('%s accepté', (f) => {
    const r = parseRepoConfig(read(f))
    expect(r.ok, JSON.stringify(!r.ok && r.issues)).toBe(true)
    if (!r.ok) return
    const { requests } = configRequests(r.config, '2026-11-25')
    const want = join(DIR, f.replace(/\.yml$/, '.requests'))
    if (existsSync(want)) expect(requests.length).toBe(Number(readFileSync(want, 'utf8').trim()))
    for (const q of requests) {
      const glob = String((q.target as { glob?: string }).glob ?? '')
      expect(glob.split('/')).not.toContain('..')
      expect(glob).not.toMatch(/^\*+(\/\*+)*$/)
      expect(q.expires_on <= '2027-11-26').toBe(true)
    }
  })

  it.each(files.filter(f => f.startsWith('repo-ko-')))('%s refusé', (f) => {
    const r = parseRepoConfig(read(f))
    expect(r.ok).toBe(false)
    if (!r.ok) {
      expect(r.issues.length).toBeGreaterThan(0)
      expect(r.issues.length).toBeLessThanOrEqual(50)
    }
  })

  it.each(files.filter(f => f.startsWith('appliance-ko-')))('%s refusé à l’import', (f) => {
    const r = parseApplianceConfig(read(f))
    expect(r.ok).toBe(false)
  })

  it('aucun prototype pollué', () => {
    expect(({} as Record<string, unknown>).polluted).toBeUndefined()
    expect(Object.prototype.hasOwnProperty.call(Object.prototype, 'polluted')).toBe(false)
  })
})
