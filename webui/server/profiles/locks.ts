// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Verrous de profil (G8, contrat 28). Fonctions pures : fusion des verrous le
// long de la hiérarchie entreprise → équipe → projet, détection d'un
// assouplissement (refusé à l'enregistrement comme par l'API) et durcissement
// des règles d'un quality gate par un plancher (gate_floor).
//
// « Plus strict », règle par règle :
// - new_code_only : false (tout le code est évalué) ;
// - max_secrets, feed_max_age_days, epss_block_from : nombre plus petit
//   (null = règle inactive, donc le plus souple) ;
// - vuln_block_from, sast_block_from, iac_block_from : gravité plus basse
//   (null = jamais bloquant, le plus souple) ;
// - license_denied_blocks, kev_blocks : true ;
// - quarantine_days : nombre plus grand (0 = pas de quarantaine) ;
// - block_malicious, inconclusive_blocks : toujours true (H4, G13).

import { CATEGORIES, GateRules, ProfileLocks, SEVERITY_RANK, type Category, type Severity } from '#shared/analysis'

export type GateFloor = ProfileLocks['gate_floor']
type FloorKey = keyof GateFloor

type Direction = 'false' | 'true' | 'lower' | 'higher' | 'severity' | 'fixed'

/** Sens du durcissement de chaque règle du gate. */
export const RULE_DIRECTION: Record<keyof GateRules, Direction> = {
  new_code_only: 'false',
  max_secrets: 'lower',
  vuln_block_from: 'severity',
  sast_block_from: 'severity',
  iac_block_from: 'severity',
  block_malicious: 'fixed',
  inconclusive_blocks: 'fixed',
  license_denied_blocks: 'true',
  kev_blocks: 'true',
  epss_block_from: 'lower',
  quarantine_days: 'higher',
  feed_max_age_days: 'lower',
}

/** Rang de sévérité d'un seuil : plus petit = plus strict ; null (jamais bloquant) = le plus souple. */
const severityStrictness = (v: Severity | null) => (v === null ? Number.POSITIVE_INFINITY : SEVERITY_RANK[v])
const numberStrictness = (v: number | null) => (v === null ? Number.POSITIVE_INFINITY : v)

/** Compare deux valeurs d'une règle : < 0 si a est plus strict que b, 0 si égales, > 0 si plus souple. */
export function compareStrictness(key: keyof GateRules, a: unknown, b: unknown): number {
  switch (RULE_DIRECTION[key]) {
    case 'false': return (a ? 1 : 0) - (b ? 1 : 0)
    case 'true': return (b ? 1 : 0) - (a ? 1 : 0)
    case 'lower': return Math.sign(numberStrictness(a as number | null) - numberStrictness(b as number | null)) || 0
    case 'higher': return Math.sign((b as number) - (a as number))
    case 'severity': return Math.sign(severityStrictness(a as Severity | null) - severityStrictness(b as Severity | null)) || 0
    case 'fixed': return 0
  }
}

/** La plus stricte de deux valeurs. */
export function stricter<K extends keyof GateRules>(key: K, a: GateRules[K], b: GateRules[K]): GateRules[K] {
  return compareStrictness(key, a, b) <= 0 ? a : b
}

const uniqueSorted = <T extends string>(xs: T[]) => [...new Set(xs)].sort()

/** Fusionne deux verrous (parent puis enfant) : exigences additionnées, plancher le plus strict. */
export function mergeLocks(parent: ProfileLocks, child: ProfileLocks): ProfileLocks {
  const floor: Record<string, unknown> = { ...parent.gate_floor }
  for (const [k, v] of Object.entries(child.gate_floor) as [FloorKey, unknown][]) {
    if (v === undefined) continue
    floor[k] = k in floor ? stricter(k, floor[k] as never, v as never) : v
  }
  return {
    required_categories: uniqueSorted([...parent.required_categories, ...child.required_categories]),
    required_modules: uniqueSorted([...parent.required_modules, ...child.required_modules]),
    gate_floor: floor as GateFloor,
    ai_opt_out: parent.ai_opt_out || child.ai_opt_out,
  }
}

export const EMPTY_LOCKS: ProfileLocks = Object.freeze(ProfileLocks.parse({})) as ProfileLocks

export function mergeAll(chain: ProfileLocks[]): ProfileLocks {
  return chain.reduce((acc, l) => mergeLocks(acc, l), EMPTY_LOCKS)
}

/** Relit un champ locks de la base ; un contenu illisible devient vide (jamais une exception). */
export function parseLocks(value: unknown): ProfileLocks {
  const parsed = ProfileLocks.safeParse(value ?? {})
  return parsed.success ? parsed.data : EMPTY_LOCKS
}

export interface LockViolation {
  /** gate_floor.<règle>, exclude_modules, ai_opt_out. */
  field: string
  /** Valeur verrouillée par un profil ancêtre. */
  locked: unknown
  /** Valeur demandée, plus souple. */
  requested: unknown
}

/**
 * Assouplissements d'un verrou hérité par un profil enfant : plancher plus
 * souple, module requis exclu, catégorie requise exclue par tous ses modules
 * (signalée par la résolution), « aucun envoi à l'IA » levé explicitement.
 */
export function findLoosening(inherited: ProfileLocks, child: {
  locks: ProfileLocks
  exclude_modules?: string[]
}): LockViolation[] {
  const out: LockViolation[] = []
  for (const [k, locked] of Object.entries(inherited.gate_floor) as [FloorKey, unknown][]) {
    const requested = child.locks.gate_floor[k]
    if (requested === undefined || locked === undefined) continue
    if (compareStrictness(k, requested, locked) > 0) out.push({ field: `gate_floor.${k}`, locked, requested })
  }
  for (const m of child.exclude_modules ?? []) {
    if (inherited.required_modules.includes(m)) out.push({ field: 'exclude_modules', locked: m, requested: m })
  }
  // ai_opt_out : fusionné par OU, un enfant ne peut pas le lever (aucun refus à produire).
  return out
}

/**
 * Durcit les règles d'un gate par un plancher (G8) : chaque règle posée dans
 * le plancher prend la valeur la plus stricte des deux. Sans plancher, les
 * règles sont rendues à l'identique (rejeu G11 d'un plan d'avant la 0.7).
 */
export function applyGateFloor(rules: GateRules, floor: GateFloor | null | undefined): GateRules {
  if (!floor) return rules
  const out: Record<string, unknown> = { ...rules }
  for (const [k, v] of Object.entries(floor) as [FloorKey, unknown][]) {
    if (v === undefined) continue
    out[k] = stricter(k, out[k] as never, v as never)
  }
  return GateRules.parse(out)
}

/** Règles durcies qui diffèrent du gate d'origine (affichées dans la console). */
export function hardenedKeys(before: GateRules, after: GateRules): (keyof GateRules)[] {
  return (Object.keys(after) as (keyof GateRules)[]).filter(k => after[k] !== before[k])
}

export function isCategory(v: string): v is Category {
  return (CATEGORIES as readonly string[]).includes(v)
}

/** Plancher de gate figé dans un plan (absent d'un plan d'avant la 0.7 : aucun durcissement). */
export function planGateFloor(plan: unknown): GateFloor | null {
  const locks = (plan as { profile?: { locks?: unknown } } | null)?.profile?.locks
  if (locks === undefined || locks === null) return null
  const parsed = ProfileLocks.safeParse(locks)
  return parsed.success ? parsed.data.gate_floor : null
}
