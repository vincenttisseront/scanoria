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

/** Contexte accepté par enqueueAiTask : revalidé, remasqué, borné ; null sinon. */
export function sanitizeContext(kind: string, context: unknown): AiLogContext | null {
  if (context === undefined || context === null || kind !== 'diagnose-scan') return null
  const parsed = AiLogContext.safeParse(context)
  if (!parsed.success) return null
  const out = aiLogContext(parsed.data.logs.map(l => ({ module: l.module, log: l.excerpt })))
  return Buffer.byteLength(JSON.stringify(out), 'utf8') <= MAX_CONTEXT_BYTES * 1.5 ? out : null
}
