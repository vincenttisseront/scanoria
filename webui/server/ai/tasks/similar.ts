// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// I7, regroupement sémantique (embed-finding) : un embedding par résultat,
// calculé par le modèle d'embedding retenu (/api/embed) à partir de la règle,
// du message et du contexte MASQUÉ (même lecture cloisonnée que les autres
// tâches : findingInput, ni message ni extrait pour un secret). Le vecteur va
// dans ai_embeddings ; scanoria-ai compare ensuite ce résultat aux résultats
// ouverts du MÊME projet (ensemble borné, cosinus) et garde les plus proches
// au-dessus du seuil fixé par le banc d'essai.
//
// Les groupes sont des « semblables » : ils ne remplacent pas le recoupement
// exact de F16, n'entrent jamais dans le quality gate et ne changent aucun
// statut. Un tri commun reste un clic d'une personne (une ligne d'audit par
// résultat). Sans modèle d'embedding, la tâche est sautée (no-embedding-model)
// et la console masque I7 en le signalant : aucun repli inventé.

import { z } from 'zod'
import { findingInput, findingRow, type FindingInput, type TaskDefinition } from '../task-kit'

/** Texte envoyé au modèle d'embedding (octets bornés). */
export const MAX_EMBED_CHARS = 4000
/** Ensemble comparé : embeddings les plus récents des résultats ouverts du projet. */
export const MAX_NEIGHBOUR_POOL = 2000
export const MAX_NEIGHBOURS = 10
/** Seuil plancher : en dessous, deux résultats ne sont jamais dits « semblables ». */
export const MIN_SIMILARITY = 0.3

/** Texte d'un résultat masqué : règle, titre, message, références, composant, chemin, extrait. */
export function embedText(f: FindingInput): string {
  const pkg = f.package?.name ? `${f.package.ecosystem ?? ''} ${f.package.name}`.trim() : ''
  const parts = [
    `${f.tool} ${f.rule_id} (${f.category})`,
    f.title,
    // Message et extrait bornés : les références et le chemin restent dans le texte.
    (f.message ?? '').slice(0, 1200),
    [...f.cwe, ...f.vuln_ids].join(' '),
    pkg,
    f.path ?? '',
    (f.snippet ?? '').slice(0, 1200),
  ]
  return parts.filter(Boolean).join('\n').slice(0, MAX_EMBED_CHARS)
}

export const embedFinding: TaskDefinition<FindingInput, never> = {
  kind: 'embed-finding',
  subjectType: 'finding',
  timeoutMs: 60_000,
  async load(db, ctx) {
    const f = await findingRow(db, ctx)
    return f ? findingInput(f) : null
  },
  embed: embedText,
  // Inutilisés : une tâche d'embedding n'appelle jamais /api/chat.
  instruction: () => '',
  jsonSchema: {},
  output: z.never(),
  finalize: out => out,
}

// ---- Similarité -----------------------------------------------------------

export function norm(v: readonly number[]): number {
  let s = 0
  for (const x of v) s += x * x
  return Math.sqrt(s)
}

/** Cosinus de deux vecteurs de même taille ; 0 si l'un est nul ou si les tailles diffèrent. */
export function cosine(a: readonly number[], b: readonly number[], na = norm(a), nb = norm(b)): number {
  if (a.length !== b.length || na === 0 || nb === 0) return 0
  let dot = 0
  for (let i = 0; i < a.length; i++) dot += a[i]! * b[i]!
  return dot / (na * nb)
}

export interface Neighbour { id: string, score: number }

/** Plus proches voisins au-dessus du seuil, du plus semblable au moins semblable. */
export function nearest(vector: readonly number[], pool: { id: string, vector: readonly number[] }[], threshold: number, max = MAX_NEIGHBOURS): Neighbour[] {
  const n = norm(vector)
  const t = Math.max(threshold, MIN_SIMILARITY)
  return pool
    .map(p => ({ id: p.id, score: cosine(vector, p.vector, n) }))
    .filter(p => p.score >= t)
    .sort((a, b) => b.score - a.score || (a.id < b.id ? -1 : 1))
    .slice(0, max)
    .map(p => ({ id: p.id, score: Math.round(p.score * 1000) / 1000 }))
}

// ---- Banc d'essai (I23) : le seuil est fixé ici -------------------------------

export const EmbedPair = z.strictObject({
  id: z.string().regex(/^[a-z0-9-]{1,60}$/),
  a: z.string().min(1).max(MAX_EMBED_CHARS),
  b: z.string().min(1).max(MAX_EMBED_CHARS),
  similar: z.boolean(),
})
export const EmbedSuite = z.strictObject({
  kind: z.literal('embed-finding'),
  /** Part minimale de paires bien classées au meilleur seuil. */
  threshold: z.number().min(0).max(1),
  pairs: z.array(EmbedPair).min(4).max(50),
}).refine(s => s.pairs.some(p => p.similar) && s.pairs.some(p => !p.similar), { message: 'both kinds of pairs are required' })
export type EmbedSuite = z.infer<typeof EmbedSuite>

export interface ThresholdChoice {
  threshold: number
  accuracy: number
}

/**
 * Seuil de similarité qui classe le mieux les paires connues (semblable si
 * cosinus ≥ seuil). À précision égale, le seuil le plus haut : mieux vaut
 * proposer moins de groupes que des groupes faux.
 */
export function chooseThreshold(scored: { score: number, similar: boolean }[]): ThresholdChoice {
  const scores = [...new Set(scored.map(s => s.score))].sort((a, b) => a - b)
  const candidates = [scores[0]! - 0.001, ...scores.map((s, i) => (i + 1 < scores.length ? (s + scores[i + 1]!) / 2 : s + 0.001))]
  let best: ThresholdChoice = { threshold: 1, accuracy: -1 }
  for (const c of candidates) {
    const t = Math.min(0.999, Math.max(MIN_SIMILARITY, c))
    const ok = scored.filter(s => (s.score >= t) === s.similar).length / scored.length
    if (ok > best.accuracy || (ok === best.accuracy && t > best.threshold)) best = { threshold: t, accuracy: ok }
  }
  return { threshold: Math.round(best.threshold * 1000) / 1000, accuracy: Math.round(best.accuracy * 1000) / 1000 }
}
