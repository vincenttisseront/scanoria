// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Contexte joint à une tâche IA par l'appelant (ai_tasks.context, migration
// 006) : aujourd'hui, les extraits de journal d'une analyse en échec (I15).
// Le service scanoria-ai n'a aucun accès aux fichiers de la console ; c'est
// la file d'analyses (utilisateur scanoria) qui lit les journaux et passe ici
// une fin de journal, masquée (règle IA) et bornée, puis enqueueAiTask la
// revalide et la masque de nouveau avant de l'enregistrer.

import { z } from 'zod'
import { MODULE_ID_RE } from '#shared/schemas'
import { redactText } from './redact'
import { boundContext, MAX_EXCERPT_CHARS, ReachContext } from './reach-context'
import { boundApplianceContext, type ApplianceContext } from './appliance-context'
import { boundNlContext, type NlContext } from './tasks/nl-search'
import { boundRulegenContext, type RulegenContext } from './tasks/rulegen'

/** Taille maximale de tous les extraits réunis (octets UTF-8). */
export const MAX_CONTEXT_BYTES = 16_384
const MAX_LOGS = 8

export const AiLogContext = z.strictObject({
  logs: z.array(z.strictObject({
    module: z.string().regex(MODULE_ID_RE),
    excerpt: z.string().max(MAX_CONTEXT_BYTES),
  })).max(MAX_LOGS),
})
export type AiLogContext = z.infer<typeof AiLogContext>

/** Garde la fin d'un texte dans une limite en octets, sur une frontière de ligne si possible. */
export function tailBytes(text: string, maxBytes: number): string {
  const buf = Buffer.from(text, 'utf8')
  if (buf.length <= maxBytes) return text
  let tail = buf.subarray(buf.length - maxBytes).toString('utf8').replace(/^�+/, '')
  const nl = tail.indexOf('\n')
  if (nl >= 0 && nl < tail.length - 1) tail = tail.slice(nl + 1)
  return `…\n${tail}`
}

/**
 * Contexte d'un diagnostic (I15) à partir des journaux bruts des modules en
 * échec : chaque extrait est masqué puis réduit à sa fin, le tout tient dans
 * MAX_CONTEXT_BYTES. À appeler par la file d'analyses avant enqueueAiTask.
 */
export function aiLogContext(entries: { module: string, log: string }[]): AiLogContext {
  const valid = entries.filter(e => MODULE_ID_RE.test(e.module) && e.log).slice(0, MAX_LOGS)
  const each = valid.length ? Math.floor(MAX_CONTEXT_BYTES / valid.length) - 64 : 0
  return {
    logs: valid.map(e => ({
      module: e.module,
      // Masqué avant découpe (aucun secret coupé en deux et donc méconnu), puis à nouveau après.
      excerpt: redactText(tailBytes(redactText(e.log.slice(-200_000)).text, each)).text.slice(0, MAX_CONTEXT_BYTES),
    })),
  }
}

/** Tâches qui reçoivent un contexte joint ; assess-reachability n'existe pas sans lui (I11). */
export const CONTEXT_KINDS = ['diagnose-scan', 'assess-reachability', 'diagnose-appliance', 'nl-search', 'generate-rule'] as const
/** I16 (0.6) : diagnose-appliance n'existe pas non plus sans le contexte joint par la console. */
export const CONTEXT_REQUIRED = ['assess-reachability', 'diagnose-appliance', 'nl-search', 'generate-rule'] as const

/** I11 : emplacements de l'index revalidés, extraits remasqués, 16 Ko au plus. */
export function sanitizeReachContext(context: unknown): ReachContext | null {
  const parsed = ReachContext.safeParse(context)
  if (!parsed.success) return null
  return boundContext({
    ...parsed.data,
    symbols: parsed.data.symbols.map(s => redactText(s).text.slice(0, 200)).filter(Boolean),
    locations: parsed.data.locations.map(l => ({
      ...l,
      path: redactText(l.path).text.slice(0, 512) || '-',
      module: redactText(l.module).text.slice(0, 300) || '-',
      symbol: redactText(l.symbol).text.slice(0, 200),
      excerpt: redactText(l.excerpt).text.slice(0, MAX_EXCERPT_CHARS),
    })),
  })
}

/** Contexte accepté par enqueueAiTask : revalidé, remasqué, borné ; null sinon. */
export function sanitizeContext(kind: string, context: unknown): AiLogContext | ReachContext | ApplianceContext | NlContext | RulegenContext | null {
  if (context === undefined || context === null) return null
  // I8 et I12 (0.7) : phrase, vocabulaire et exemples remasqués et bornés.
  if (kind === 'nl-search') return boundNlContext(context)
  if (kind === 'generate-rule') return boundRulegenContext(context)
  if (kind === 'assess-reachability') return sanitizeReachContext(context)
  if (kind === 'diagnose-appliance') return boundApplianceContext(context)
  if (kind !== 'diagnose-scan') return null
  const parsed = AiLogContext.safeParse(context)
  if (!parsed.success) return null
  const out = aiLogContext(parsed.data.logs.map(l => ({ module: l.module, log: l.excerpt })))
  return Buffer.byteLength(JSON.stringify(out), 'utf8') <= MAX_CONTEXT_BYTES * 1.5 ? out : null
}
