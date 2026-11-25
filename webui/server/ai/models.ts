// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Découverte des modèles (/api/tags, /api/show) et choix automatique du
// modèle de chaque tâche (CLAUDE.md § 3.5, principe 8). Le choix est
// expliqué par un motif stable, traduit par la console ; l'administrateur
// peut forcer un modèle par tâche, sans y être obligé.

export interface ModelInfo {
  name: string
  digest: string
  capabilities: string[]
  context: number | null
  parameters_b: number | null
  family: string | null
}

export type SelectionReason = 'admin-choice' | 'admin-default' | 'admin-choice-missing-default' | 'only-model' | 'best-balance' | 'largest-context' | 'admin-choice-missing'

/**
 * Clés réservées des choix forcés (appliance_settings ai.models), à côté des
 * types de tâche : « default » = modèle de rédaction de toutes les tâches sans
 * choix propre, « embedding » = modèle d'embedding (I7). Une seule liste
 * déroulante suffit donc dans le cas courant.
 */
export const DEFAULT_KEY = 'default'
export const EMBEDDING_KEY = 'embedding'
/** 0.7 (contrat 31) : modèle de rédaction du relais IA des modules d'analyse ; suit « default ». */
export const RELAY_KEY = 'relay'

export interface ModelChoice {
  model: string
  digest: string
  context: number | null
  reason: SelectionReason
}

export interface Selection {
  /** Tâches de rédaction (completion). */
  tasks: Record<string, ModelChoice | null>
  /** Modèle d'embedding (I7 et suivantes) ; null = recherche lexicale. */
  embedding: ModelChoice | null
}

/** Paramètres en milliards depuis « 8.0B », « 70B », « 500M ». */
export function parseParameterSize(v: unknown): number | null {
  if (typeof v !== 'string') return null
  const m = /^([0-9]+(?:\.[0-9]+)?)\s*([BM])$/i.exec(v.trim())
  if (!m) return null
  const n = Number(m[1])
  return m[2]!.toUpperCase() === 'B' ? n : n / 1000
}

/** Informations utiles d'une réponse /api/show. */
export function modelInfo(name: string, digest: string, show: Record<string, unknown>): ModelInfo {
  const caps = Array.isArray(show.capabilities)
    ? show.capabilities.filter((c): c is string => typeof c === 'string' && /^[a-z][a-z_-]{0,30}$/.test(c)).slice(0, 16)
    : []
  let context: number | null = null
  const info = show.model_info
  if (info && typeof info === 'object') {
    for (const [k, v] of Object.entries(info as Record<string, unknown>)) {
      if (k.endsWith('.context_length') && typeof v === 'number' && Number.isInteger(v) && v > 0) context = v
    }
  }
  const details = (show.details && typeof show.details === 'object' ? show.details : {}) as Record<string, unknown>
  const family = typeof details.family === 'string' ? details.family.slice(0, 60) : null
  // Ollama ancien : pas de capabilities ; un modèle « bert » ou « nomic-bert » est un modèle d'embedding.
  const capabilities = caps.length ? caps : (family && /bert/i.test(family) ? ['embedding'] : ['completion'])
  return { name, digest, capabilities, context, parameters_b: parseParameterSize(details.parameter_size), family }
}

/** Plus haut = meilleur pour rédiger vite et bien : 7 à 34 milliards, contexte ≥ 8 k. */
export function completionScore(m: ModelInfo): number {
  const p = m.parameters_b
  let score = 0
  if (p === null) score += 10
  else if (p >= 7 && p <= 34) score += 30 + Math.min(p, 34) / 2
  else if (p > 34) score += 25 - Math.min(p - 34, 50) / 10
  else score += p * 3
  const ctx = m.context ?? 4096
  score += ctx >= 32_768 ? 12 : ctx >= 8192 ? 8 : ctx >= 4096 ? 2 : -20
  return score
}

function choice(m: ModelInfo, reason: SelectionReason): ModelChoice {
  return { model: m.name, digest: m.digest, context: m.context, reason }
}

export function selectModels(models: ModelInfo[], taskKinds: readonly string[], overrides: Record<string, string>): Selection {
  const completion = models.filter(m => m.capabilities.includes('completion'))
  const embeddings = models.filter(m => m.capabilities.includes('embedding'))
  const ranked = [...completion].sort((a, b) => completionScore(b) - completionScore(a) || a.name.localeCompare(b.name))
  const tasks: Record<string, ModelChoice | null> = {}
  const fallback = overrides[DEFAULT_KEY]
  const forcedDefault = fallback ? completion.find(m => m.name === fallback) : undefined
  for (const kind of taskKinds) {
    const own = overrides[kind]
    const forced = own ? completion.find(m => m.name === own) : undefined
    if (forced) tasks[kind] = choice(forced, 'admin-choice')
    else if (forcedDefault) tasks[kind] = choice(forcedDefault, own ? 'admin-choice-missing-default' : 'admin-default')
    else if (ranked.length === 0) tasks[kind] = null
    else tasks[kind] = choice(ranked[0]!, own || fallback ? 'admin-choice-missing' : ranked.length === 1 ? 'only-model' : 'best-balance')
  }
  const wantedEmb = overrides[EMBEDDING_KEY]
  const forcedEmb = wantedEmb ? embeddings.find(m => m.name === wantedEmb) : undefined
  const emb = [...embeddings].sort((a, b) => (b.context ?? 0) - (a.context ?? 0) || a.name.localeCompare(b.name))[0]
  const embedding = forcedEmb
    ? choice(forcedEmb, 'admin-choice')
    : emb ? choice(emb, wantedEmb ? 'admin-choice-missing' : embeddings.length === 1 ? 'only-model' : 'largest-context') : null
  return { tasks, embedding }
}

/** Contexte dimensionné à la demande : entrée estimée + réponse, arrondi au kilo-jeton. */
export function contextFor(promptChars: number, modelContext: number | null, outputTokens = 2048): number {
  const need = Math.ceil(promptChars / 3) + outputTokens
  const rounded = Math.max(4096, Math.ceil(need / 1024) * 1024)
  return modelContext ? Math.min(rounded, modelContext) : rounded
}

/** Modèle et début de son empreinte, tels que journalisés et affichés sur un résultat IA. */
export function modelLabel(m: Pick<ModelChoice, 'model' | 'digest'>): string {
  return `${m.model}@${m.digest.slice(0, 12)}`
}

/** « nom@empreinte » → {model, digest} (affichage d'un résultat IA). */
export function parseModelLabel(label: string | null | undefined): { model: string, digest: string | null } | null {
  if (!label) return null
  const i = label.lastIndexOf('@')
  if (i <= 0) return { model: label, digest: null }
  const digest = label.slice(i + 1)
  return /^[0-9a-f]{12}$/.test(digest) ? { model: label.slice(0, i), digest } : { model: label, digest: null }
}
