// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Aides des pages Quality gates (chantier E) : formulaire généré depuis le
// schéma GateRules, champs verrouillés (H4, G13), messages d'erreur gates.*.

import type { z } from 'zod'
import { GateRules } from '#shared/analysis'

export type GateField
  = | { key: string, kind: 'boolean' }
    | { key: string, kind: 'number', min: number, nullable?: boolean }
    | { key: string, kind: 'severity', options: string[], nullable: boolean }
    | { key: string, kind: 'locked', value: unknown, reason: string }

/** Champs non désactivables et la règle qui l'impose. */
export const LOCKED_REASONS: Record<string, string> = { block_malicious: 'H4', inconclusive_blocks: 'G13' }

interface Def { type: string, innerType?: z.ZodType, values?: unknown[] }
const defOf = (s: z.ZodType) => (s as unknown as { def: Def }).def

/** Champs du formulaire, dans l'ordre du schéma GateRules. */
export function gateFields(): GateField[] {
  const out: GateField[] = []
  for (const [key, schema] of Object.entries(GateRules.shape)) {
    let s = schema as z.ZodType
    let nullable = false
    for (;;) {
      const d = defOf(s)
      if (d.type === 'default' || d.type === 'nullable' || d.type === 'optional') {
        if (d.type === 'nullable') nullable = true
        s = d.innerType!
        continue
      }
      break
    }
    const d = defOf(s)
    if (d.type === 'literal') {
      out.push({ key, kind: 'locked', value: d.values?.[0], reason: LOCKED_REASONS[key] ?? '' })
    }
    else if (d.type === 'boolean') {
      out.push({ key, kind: 'boolean' })
    }
    else if (d.type === 'number') {
      out.push({ key, kind: 'number', min: (s as unknown as { minValue?: number }).minValue ?? 0, ...(nullable ? { nullable } : {}) })
    }
    else if (d.type === 'enum') {
      out.push({ key, kind: 'severity', options: (s as unknown as { options: string[] }).options, nullable })
    }
  }
  return out
}

const SEVERITY_RANK: Record<string, number> = { critical: 5, high: 4, medium: 3, low: 2, info: 1 }
/** Rang d'un seuil « bloquant à partir de » : plus il est haut, plus le seuil est souple ; null (ne bloque jamais) est le plus souple. */
const sevRank = (v: unknown) => (typeof v === 'string' ? SEVERITY_RANK[v] ?? 0 : Number.POSITIVE_INFINITY)
/** Rang d'un nombre « plus souple quand plus grand », null le plus souple. */
const upRank = (v: unknown) => (typeof v === 'number' ? v : Number.POSITIVE_INFINITY)

/**
 * Règles que les règles candidates ASSOUPLISSENT par rapport aux règles
 * actuelles (I19 et F9 : signalées avant l'enregistrement).
 */
export function loosenedRules(current: Record<string, unknown>, candidate: Record<string, unknown>): string[] {
  const out: string[] = []
  for (const k of Object.keys(candidate)) {
    const a = current[k]
    const b = candidate[k]
    if (a === b) continue
    let looser = false
    if (k.endsWith('_block_from') && k !== 'epss_block_from') looser = sevRank(b) > sevRank(a)
    else if (k === 'new_code_only') looser = b === true
    else if (typeof a === 'boolean' || typeof b === 'boolean') looser = a === true && b === false
    else if (k === 'max_secrets' || k === 'epss_block_from' || k === 'feed_max_age_days') looser = upRank(b) > upRank(a)
    else if (k === 'quarantine_days') looser = Number(b) < Number(a)
    if (looser) out.push(k)
  }
  return out
}

interface ErrLike { data?: { data?: { code?: string }, code?: string } }

/** Code d'erreur renvoyé par l'API (data.code). */
export function gateErrorCode(err: unknown): string | undefined {
  const e = err as ErrLike
  return e?.data?.data?.code ?? e?.data?.code
}
