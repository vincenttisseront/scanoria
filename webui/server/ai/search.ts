// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// I8 (0.7), côté console de la recherche en langage naturel : vocabulaire
// permis, dépôt de la tâche nl-search, puis lecture de la sortie traduite en
// paramètres des API habituelles (GET /api/findings, GET /api/components).
// Les filtres sont rendus à la page, affichés et modifiables, et ne sont
// exécutés que par ces API, avec les droits de la personne. Rien n'est
// exécuté ici, et rien n'est jamais traduit en SQL.

import { z } from 'zod'
import type { Role } from '#shared/schemas'
import type { Queryable } from '../utils/db'
import { findingQuerySchema } from '../findings/schemas'
import { componentQuerySchema } from '../sbom/search'
import { AI_PRIORITY, connectorEnabled, enqueueAiTask } from './enqueue'
import {
  boundNlContext, MAX_PHRASE, NL_SUBJECT_RE, NL_TARGETS, nlSubjectId, NlSearchOutput,
  type NlContext, type NlTarget,
} from './tasks/nl-search'

export const SearchBody = z.strictObject({
  phrase: z.string().trim().min(3).max(MAX_PHRASE),
  target: z.enum([...NL_TARGETS, 'auto']).default('auto'),
  locale: z.enum(['fr', 'en']).optional(),
})
export type SearchBody = z.infer<typeof SearchBody>

export const SearchQuery = z.strictObject({
  /** Absent : seulement l'état du connecteur, pour afficher ou masquer le champ. */
  subject_id: z.string().regex(NL_SUBJECT_RE).optional(),
  locale: z.enum(['fr', 'en']).optional(),
})

/** Écosystèmes proposés quand aucun SBOM n'en contient encore (formulaire de la page Composants). */
const DEFAULT_ECOSYSTEMS = ['npm', 'pypi', 'maven', 'golang', 'cargo', 'gem', 'nuget', 'composer', 'deb', 'rpm', 'apk']

/**
 * Vocabulaire permis : projets actifs qui acceptent l'IA (jamais un projet
 * « aucun envoi à l'IA », pas même son nom), outils déjà vus dans des
 * résultats, écosystèmes des SBOM. Des noms seulement, aucune donnée.
 */
export async function nlVocabulary(db: Queryable): Promise<NlContext['vocabulary']> {
  const [projects, tools, ecosystems] = await Promise.all([
    db.query<{ slug: string }>(`SELECT slug FROM projects WHERE archived_at IS NULL AND NOT ai_opt_out ORDER BY slug LIMIT 500`),
    db.query<{ tool: string }>(
      `SELECT DISTINCT f.tool FROM findings f JOIN projects p ON p.id = f.project_id
        WHERE p.archived_at IS NULL AND NOT p.ai_opt_out ORDER BY f.tool LIMIT 200`),
    db.query<{ ecosystem: string }>(
      `SELECT DISTINCT lower(c.ecosystem) AS ecosystem FROM sbom_components c JOIN projects p ON p.id = c.project_id
        WHERE p.archived_at IS NULL AND NOT p.ai_opt_out AND c.ecosystem ~ '^[A-Za-z0-9.+-]{1,32}$' ORDER BY 1 LIMIT 40`),
  ])
  const eco = ecosystems.rows.map(r => r.ecosystem)
  return {
    projects: projects.rows.map(r => r.slug).filter(s => /^[a-z0-9][a-z0-9-]{0,62}$/.test(s)),
    tools: tools.rows.map(r => r.tool).filter(s => /^[a-z0-9][a-z0-9-]{1,40}$/.test(s)),
    ecosystems: eco.length ? eco : DEFAULT_ECOSYSTEMS,
  }
}

/** Dépose la traduction d'une phrase ; subject_id permet de lire le résultat. task_id null : IA inactive. */
export async function requestSearch(db: Queryable, body: SearchBody, userId: number, userLocale: 'fr' | 'en', today = new Date()) {
  if (!(await connectorEnabled())) return { subject_id: null, task_id: null }
  const context = boundNlContext({
    phrase: body.phrase,
    target: body.target,
    today: today.toISOString().slice(0, 10),
    vocabulary: await nlVocabulary(db),
  })
  if (!context) return { subject_id: null, task_id: null }
  const subjectId = nlSubjectId(context)
  const taskId = await enqueueAiTask(db, {
    kind: 'nl-search', subjectType: 'query', subjectId, projectId: null,
    locale: body.locale ?? userLocale, priority: AI_PRIORITY.interactive, requestedBy: userId, context,
  })
  return { subject_id: taskId ? subjectId : null, task_id: taskId }
}

export interface FilterChip {
  key: string
  value: string
}

export interface ResolvedSearch {
  target: NlTarget
  /** Paramètres de l'API de la page (GET /api/findings ou /api/components), déjà validés. */
  query: Record<string, string>
  /** Chaque filtre, pour l'affichage et la modification avant exécution. */
  chips: FilterChip[]
  explanation: string
  unsupported: string[]
}

/**
 * Sortie de l'IA → paramètres des API, avec les droits de la personne :
 * un projet doit exister, être actif (ou la personne administratrice) et
 * accepter l'IA ; chaque paramètre est revalidé par le schéma de l'API, et
 * un paramètre refusé est écarté et signalé. Rien n'est exécuté ici.
 */
export async function resolveSearch(db: Queryable, raw: unknown, role: Role): Promise<ResolvedSearch | null> {
  const parsed = NlSearchOutput.safeParse(raw)
  if (!parsed.success) return null
  const out = parsed.data
  const unsupported = [...out.unsupported]
  const query: Record<string, string> = {}
  const projectSlug = out.target === 'findings' ? out.findings?.project : out.components?.project
  if (projectSlug) {
    const { rows } = await db.query<{ id: string }>(
      `SELECT id FROM projects WHERE slug = $1 AND NOT ai_opt_out AND ($2::boolean OR archived_at IS NULL)`,
      [projectSlug, role === 'admin'],
    )
    if (rows[0]) query.project_id = rows[0].id
    else unsupported.push(`project=${projectSlug}`)
  }
  const candidate: Record<string, string> = {}
  if (out.target === 'findings') {
    const f = out.findings ?? {}
    if (f.tool) candidate.tool = f.tool
    if (f.severity?.length) candidate.severity = f.severity.join(',')
    if (f.category) candidate.category = f.category
    if (f.status?.length) candidate.status = f.status.join(',')
    for (const k of ['is_new', 'secret', 'malicious', 'kev'] as const) if (f[k]) candidate[k] = 'true'
    if (f.epss_min !== undefined) candidate.epss_min = String(f.epss_min)
    if (f.origin) candidate.origin = f.origin
    if (f.text) candidate.q = f.text
  }
  else {
    const c = out.components ?? {}
    if (c.name) candidate.name = c.name
    if (c.ecosystem) candidate.ecosystem = c.ecosystem
    if (c.version) candidate.version = c.version
    if (c.vuln) candidate.vuln = c.vuln
  }
  // Chaque paramètre est accepté par le schéma de l'API, seul ou avec les autres.
  const schema = out.target === 'findings' ? findingQuerySchema : componentQuerySchema
  // La recherche de composants exige un nom, un purl ou une vulnérabilité : un
  // paramètre seul est éprouvé à côté d'un nom fictif.
  const probe = (k: string, v: string) => (out.target === 'components' && !['name', 'purl', 'vuln'].includes(k) ? { name: 'x', [k]: v } : { [k]: v })
  for (const [k, v] of Object.entries(candidate)) {
    if (schema.safeParse(probe(k, v)).success) query[k] = v
    else unsupported.push(`${k}=${v}`)
  }
  if (out.target === 'findings' && !schema.safeParse(query).success) return null
  const chips = Object.entries(query).map(([key, value]) => ({ key, value: key === 'project_id' ? projectSlug! : value }))
  return { target: out.target, query, chips, explanation: out.explanation, unsupported: [...new Set(unsupported)].slice(0, 8) }
}

/** État de la traduction et filtres résolus pour cette personne ; null si le sujet est inconnu. */
export async function readSearch(db: Queryable, q: z.infer<typeof SearchQuery>, role: Role, userLocale: 'fr' | 'en') {
  const enabled = await connectorEnabled()
  if (!enabled || !q.subject_id) return { enabled, task: null, result: null }
  const locale = q.locale ?? userLocale
  const { rows } = await db.query<{ id: string, status: string, output: unknown, error: string | null, model: string | null, model_digest: string | null, finished_at: Date | null }>(
    `SELECT id, status, output, error, model, model_digest, finished_at FROM ai_tasks
      WHERE kind = 'nl-search' AND subject_type = 'query' AND subject_id = $1 AND project_id IS NULL
      ORDER BY (status = 'done') DESC, (locale = $2) DESC, created_at DESC LIMIT 1`,
    [q.subject_id, locale],
  )
  const t = rows[0]
  if (!t) return null
  const result = t.status === 'done' ? await resolveSearch(db, t.output, role) : null
  return {
    enabled: true,
    task: {
      id: t.id,
      status: t.status === 'done' && !result ? 'error' : t.status,
      error: t.status === 'done' && !result ? 'invalid-output' : t.error,
      model: t.model,
      model_digest: t.model_digest,
      generated_at: t.finished_at?.toISOString() ?? null,
    },
    result,
  }
}
