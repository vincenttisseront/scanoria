// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Verrous de profil (G8, contrat 28) et choix du profil (G9) : fonctions pures.

import { describe, expect, it } from 'vitest'
import { GateRules, ProfileLocks } from '#shared/analysis'
import {
  EMPTY_LOCKS, RULE_DIRECTION, applyGateFloor, compareStrictness, findLoosening, hardenedKeys,
  isCategory, mergeAll, mergeLocks, parseLocks, planGateFloor, stricter,
} from '../../server/profiles/locks'
import { mergeChain, profileForSlot, slotFor } from '../../server/profiles/resolve'
import { locksCover } from '../../server/profiles/assign'

const L = (v: unknown) => ProfileLocks.parse(v)
const DEFAULT_RULES = GateRules.parse({})

describe('profile-locks : strictness', () => {
  it('chaque règle a un sens', () => {
    expect(Object.keys(RULE_DIRECTION).sort()).toEqual(Object.keys(DEFAULT_RULES).sort())
  })

  it.each([
    ['new_code_only', false, true],
    ['max_secrets', 0, 3],
    ['max_secrets', 5, null],
    ['vuln_block_from', 'low', 'high'],
    ['vuln_block_from', 'critical', null],
    ['sast_block_from', 'medium', 'critical'],
    ['license_denied_blocks', true, false],
    ['kev_blocks', true, false],
    ['epss_block_from', 0.05, 0.5],
    ['epss_block_from', 0.9, null],
    ['quarantine_days', 14, 7],
    ['feed_max_age_days', 3, 30],
    ['feed_max_age_days', 365, null],
  ] as [keyof GateRules, unknown, unknown][])('%s : %s plus strict que %s', (k, strict, loose) => {
    expect(compareStrictness(k, strict, loose)).toBeLessThan(0)
    expect(compareStrictness(k, loose, strict)).toBeGreaterThan(0)
    expect(compareStrictness(k, strict, strict)).toBe(0)
    expect(stricter(k, loose as never, strict as never)).toBe(strict)
    expect(stricter(k, strict as never, loose as never)).toBe(strict)
  })

  it('règles fixes : jamais comparables', () => {
    expect(compareStrictness('block_malicious', true, true)).toBe(0)
    expect(compareStrictness('inconclusive_blocks', true, true)).toBe(0)
  })
})

describe('profile-locks : fusion', () => {
  it('exigences additionnées, plancher le plus strict, IA par OU', () => {
    const parent = L({ required_categories: ['secrets'], required_modules: ['gitleaks'], gate_floor: { max_secrets: 0, vuln_block_from: 'high' } })
    const child = L({ required_categories: ['sca', 'secrets'], gate_floor: { vuln_block_from: 'critical', kev_blocks: true }, ai_opt_out: true })
    const m = mergeLocks(parent, child)
    expect(m.required_categories).toEqual(['sca', 'secrets'])
    expect(m.required_modules).toEqual(['gitleaks'])
    expect(m.gate_floor).toEqual({ max_secrets: 0, vuln_block_from: 'high', kev_blocks: true })
    expect(m.ai_opt_out).toBe(true)
    expect(mergeLocks(child, L({})).ai_opt_out).toBe(true)
  })

  it('mergeAll sur une chaîne vide = verrous vides', () => {
    expect(mergeAll([])).toEqual(EMPTY_LOCKS)
    expect(mergeAll([L({ gate_floor: { quarantine_days: 3 } }), L({ gate_floor: { quarantine_days: 10 } })]).gate_floor.quarantine_days).toBe(10)
  })

  it('parseLocks : contenu illisible → vide, jamais une exception', () => {
    expect(parseLocks(null)).toEqual(EMPTY_LOCKS)
    expect(parseLocks({ gate_floor: { block_malicious: false } })).toEqual(EMPTY_LOCKS)
    expect(parseLocks({ unknown: 1 })).toEqual(EMPTY_LOCKS)
    expect(parseLocks({ ai_opt_out: true }).ai_opt_out).toBe(true)
  })
})

describe('profile-locks : assouplissements', () => {
  const inherited = L({ required_modules: ['gitleaks'], gate_floor: { max_secrets: 0, vuln_block_from: 'high', epss_block_from: 0.1 }, ai_opt_out: true })

  it('signale chaque règle plus souple, pas les plus strictes ni les libres', () => {
    const v = findLoosening(inherited, { locks: L({ gate_floor: { max_secrets: 2, vuln_block_from: 'medium', epss_block_from: null, sast_block_from: null } }) })
    expect(v.map(x => x.field).sort()).toEqual(['gate_floor.epss_block_from', 'gate_floor.max_secrets'])
    expect(v.find(x => x.field === 'gate_floor.max_secrets')).toEqual({ field: 'gate_floor.max_secrets', locked: 0, requested: 2 })
  })

  it('module exigé exclu ; ai_opt_out à false sans effet (OU)', () => {
    const v = findLoosening(inherited, { locks: L({ ai_opt_out: false }), exclude_modules: ['gitleaks', 'trivy'] })
    expect(v).toEqual([{ field: 'exclude_modules', locked: 'gitleaks', requested: 'gitleaks' }])
  })
})

describe('profile-locks : gate durci', () => {
  it('sans plancher : règles rendues telles quelles (rejeu G11)', () => {
    expect(applyGateFloor(DEFAULT_RULES, null)).toBe(DEFAULT_RULES)
    expect(applyGateFloor(DEFAULT_RULES, undefined)).toBe(DEFAULT_RULES)
  })

  it('plancher : durcit, n’assouplit jamais', () => {
    const r = applyGateFloor(DEFAULT_RULES, { vuln_block_from: 'low', max_secrets: 3, new_code_only: false, quarantine_days: 2, epss_block_from: 0.01 })
    expect(r.vuln_block_from).toBe('low')
    expect(r.max_secrets).toBe(0)
    expect(r.new_code_only).toBe(false)
    expect(r.quarantine_days).toBe(7)
    expect(r.epss_block_from).toBe(0.01)
    expect(hardenedKeys(DEFAULT_RULES, r).sort()).toEqual(['epss_block_from', 'new_code_only', 'vuln_block_from'])
  })

  it('plancher lu depuis le plan', () => {
    expect(planGateFloor(null)).toBeNull()
    expect(planGateFloor({ profile: { slug: 'complet' } })).toBeNull()
    expect(planGateFloor({ profile: { locks: { gate_floor: { max_secrets: 0 } } } })).toEqual({ max_secrets: 0 })
    expect(planGateFloor({ profile: { locks: { gate_floor: { block_malicious: false } } } })).toBeNull()
  })

  it('catégories', () => {
    expect(isCategory('secrets')).toBe(true)
    expect(isCategory('autre')).toBe(false)
  })
})

describe('profile-locks : profil effectif', () => {
  const row = (slug: string, o: Partial<Parameters<typeof mergeChain>[0][number]> = {}) => ({
    id: `id-${slug}`, slug, level: 'project' as const, parent_id: null, categories: [], include_modules: [], exclude_modules: [], locks: {}, rulesets: [], ...o,
  })

  it('profil sans parent : ordre conservé', () => {
    const e = mergeChain([row('complet', { level: 'enterprise', categories: ['sca', 'secrets', 'iac'] })])
    expect(e.categories).toEqual(['sca', 'secrets', 'iac'])
    expect(e.chain).toEqual([{ id: 'id-complet', slug: 'complet', level: 'enterprise' }])
    expect(e.locks).toEqual(EMPTY_LOCKS)
  })

  it('exclusion d’un enfant, réinclusion, verrous imposés en dernier', () => {
    const e = mergeChain([
      row('ent', { level: 'enterprise', include_modules: ['trivy', 'gitleaks'], locks: { required_modules: ['gitleaks'], required_categories: ['secrets'] }, rulesets: [{ ruleset_id: 'r1', slug: 'b', engine: 'opengrep', pinned_version: 1 }] }),
      row('team', { level: 'team', exclude_modules: ['trivy', 'gitleaks'], rulesets: [{ ruleset_id: 'r1', slug: 'b', engine: 'opengrep', pinned_version: 3 }, { ruleset_id: 'r2', slug: 'a', engine: 'gitleaks', pinned_version: null }] }),
    ], L({ required_categories: ['sast'] }))
    expect(e.include_modules).toEqual(['gitleaks'])
    expect(e.exclude_modules).toEqual(['trivy'])
    expect(e.categories).toEqual(['sast', 'secrets'])
    expect(e.rulesets.map(r => [r.slug, r.pinned_version])).toEqual([['a', null], ['b', 3]])
    expect(e.slug).toBe('team')
  })
})

describe('profile-locks : G9', () => {
  it('emplacement selon le déclencheur', () => {
    expect(slotFor('webhook', { number: 1 })).toBe('pr')
    expect(slotFor('release', { number: 1 })).toBe('pr')
    expect(slotFor('release')).toBe('release')
    expect(slotFor('schedule', null)).toBe('nightly')
    expect(slotFor('manual')).toBe('default')
    expect(slotFor('api')).toBe('default')
  })

  it('champ vide → profile_id', () => {
    const p = { profile_id: 'd', profile_pr_id: 'p', profile_nightly_id: null, profile_release_id: 'r' }
    expect(profileForSlot(p, 'pr')).toBe('p')
    expect(profileForSlot(p, 'nightly')).toBe('d')
    expect(profileForSlot(p, 'release')).toBe('r')
    expect(profileForSlot(p, 'default')).toBe('d')
  })

  it('locksCover : un profil de remplacement doit tenir les mêmes verrous', () => {
    const cur = L({ required_categories: ['secrets'], required_modules: ['gitleaks'], gate_floor: { max_secrets: 0 }, ai_opt_out: true })
    expect(locksCover(EMPTY_LOCKS, cur)).toBe(true)
    expect(locksCover(cur, cur)).toBe(true)
    expect(locksCover(cur, { ...cur, ai_opt_out: false })).toBe(false)
    expect(locksCover(cur, { ...cur, required_categories: [] })).toBe(false)
    expect(locksCover(cur, { ...cur, required_modules: [] })).toBe(false)
    expect(locksCover(cur, { ...cur, gate_floor: {} })).toBe(false)
    expect(locksCover(cur, { ...cur, gate_floor: { max_secrets: 1 } })).toBe(false)
    expect(locksCover(cur, { ...cur, gate_floor: { max_secrets: 0, kev_blocks: true } })).toBe(true)
  })
})
