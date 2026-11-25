// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Briques communes des tâches IA (CLAUDE.md § 3.5) : définition d'une tâche,
// lecture d'un résultat cloisonnée au projet et masquée, aides de schéma.
// Chaque tâche lit ses données en restant dans le projet de la tâche,
// masque les secrets, fixe un schéma JSON passé à Ollama, revalide la sortie
// par zod puis l'échappe. Aucune n'écrit hors des tables ai_*.

import type { z } from 'zod'
import type { AiSubjectType } from '#shared/analysis'
import type { Queryable } from '../utils/db'
import type { Locale } from './prompt'
import { redactText } from './redact'

export interface TaskContext {
  projectId: string | null
  subjectId: string
  /** Contexte joint par l'appelant (ai_tasks.context), déjà masqué et borné. */
  context?: unknown
}

export interface TaskDefinition<I = unknown, O = unknown> {
  kind: string
  subjectType: AiSubjectType
  /**
   * false : sujet transverse sans projet (traduction d'une règle d'outil, I17) ;
   * la tâche ne lit alors que des textes d'outil, jamais de code, et jamais
   * rien d'un projet « aucun envoi à l'IA ».
   */
  projectScoped?: boolean
  /** Forme de l'identifiant du sujet (uuid par défaut). */
  subjectPattern?: RegExp
  /** Données d'entrée, déjà masquées ; null = sujet introuvable dans ce projet. */
  load: (db: Queryable, ctx: TaskContext) => Promise<I | null>
  instruction: (locale: Locale) => string
  jsonSchema: Record<string, unknown>
  output: z.ZodType<O>
  /** Échappement et compléments fiables (références) après validation. */
  finalize: (output: O, input: I) => O
  /**
   * Contrôle propre à la tâche, après finalize (I12 : structure de la règle
   * selon le moteur demandé) : false rejette la sortie comme invalide, elle
   * n'est jamais affichée ni mise en cache.
   */
  accept?: (output: O, input: I) => boolean
  /** Délai d'un appel, en millisecondes. */
  timeoutMs: number
  /**
   * Tâche d'embedding (I7, /api/embed) : texte envoyé au modèle d'embedding,
   * déjà masqué. Une telle tâche n'appelle jamais /api/chat ; instruction,
   * jsonSchema, output et finalize ne servent pas.
   */
  embed?: (input: I) => string
}

export const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/

/** Schéma JSON d'une chaîne non vide bornée. */
export const text = (max: number) => ({ type: 'string', minLength: 1, maxLength: max })
/** Schéma JSON d'une énumération. */
export const oneOf = (values: readonly string[]) => ({ type: 'string', enum: [...values] })

export interface FindingInput {
  tool: string
  rule_id: string
  category: string
  severity: string
  native_severity: string | null
  title: string
  message: string | null
  path: string | null
  start_line: number | null
  end_line: number | null
  cwe: string[]
  vuln_ids: string[]
  package: { ecosystem?: string, name?: string, version?: string, fixed?: string[] } | null
  malicious: boolean
  secret_type: string | null
  snippet: string | null
}

export function pickPackage(p: unknown): FindingInput['package'] {
  if (!p || typeof p !== 'object') return null
  const o = p as Record<string, unknown>
  const s = (v: unknown) => (typeof v === 'string' ? v.slice(0, 200) : undefined)
  return {
    ecosystem: s(o.ecosystem),
    name: s(o.name),
    version: s(o.version),
    fixed: Array.isArray(o.fixed) ? o.fixed.filter((x): x is string => typeof x === 'string').slice(0, 10) : undefined,
  }
}

/** Champs d'un résultat lus par les tâches (une seule requête, cloisonnée au projet). */
export const FINDING_COLUMNS = `tool, rule_id, category, severity, native_severity, title, message, path, start_line, end_line,
  cwe, vuln_ids, package, malicious, secret_type, snippet`

export function isSecretRow(f: Record<string, unknown>): boolean {
  return f.category === 'secrets' || (f.secret_type !== null && f.secret_type !== undefined)
}

/** Résultat masqué : pour un secret, ni message ni extrait (F7). */
export function findingInput(f: Record<string, unknown>): FindingInput {
  const secret = isSecretRow(f)
  return {
    tool: String(f.tool).slice(0, 100),
    rule_id: String(f.rule_id).slice(0, 255),
    category: String(f.category).slice(0, 40),
    severity: String(f.severity),
    native_severity: typeof f.native_severity === 'string' ? f.native_severity.slice(0, 64) : null,
    title: redactText(String(f.title)).text,
    message: secret || typeof f.message !== 'string' ? null : redactText(f.message).text,
    path: typeof f.path === 'string' ? f.path.slice(0, 1024) : null,
    start_line: typeof f.start_line === 'number' ? f.start_line : null,
    end_line: typeof f.end_line === 'number' ? f.end_line : null,
    cwe: Array.isArray(f.cwe) ? (f.cwe as string[]).slice(0, 10) : [],
    vuln_ids: Array.isArray(f.vuln_ids) ? (f.vuln_ids as string[]).slice(0, 20) : [],
    package: pickPackage(f.package),
    malicious: f.malicious === true,
    secret_type: typeof f.secret_type === 'string' ? f.secret_type.slice(0, 100) : null,
    snippet: secret || typeof f.snippet !== 'string' ? null : redactText(f.snippet).text,
  }
}

/** Ligne brute d'un résultat du projet, ou null (autre projet, absent). */
export async function findingRow(db: Queryable, ctx: TaskContext, extra = ''): Promise<Record<string, unknown> | null> {
  if (!ctx.projectId || !UUID_RE.test(ctx.subjectId)) return null
  const { rows } = await db.query(
    `SELECT ${FINDING_COLUMNS}${extra ? `, ${extra}` : ''} FROM findings WHERE id = $1 AND project_id = $2`,
    [ctx.subjectId, ctx.projectId],
  )
  return (rows[0] as Record<string, unknown> | undefined) ?? null
}

/** Indices déterministes tirés du chemin (aucun appel au modèle). */
export function pathHints(path: string | null): { test: boolean, vendored: boolean, example: boolean, generated: boolean } {
  const p = (path ?? '').toLowerCase()
  return {
    test: /(?:(?:^|\/)(?:tests?|__tests__|spec|specs|testdata|test-data|fixtures?|mocks?)(?:\/|$))|(?:[._-](?:test|spec)\.[a-z0-9]+$)|(?:(?:^|\/)test_[^/]+$)/.test(p),
    vendored: /(^|\/)(vendor|third[_-]?party|node_modules|external)(\/|$)/.test(p),
    example: /(?:(?:^|\/)(?:examples?|samples?|demo|docs?)(?:\/|$))|(?:\.(?:example|sample|dist|template)(?:\.|$))/.test(p),
    generated: /(?:(?:^|\/)(?:dist|build|generated|gen)(?:\/|$))|(?:\.(?:min\.js|pb\.go|generated\.[a-z]+)$)/.test(p),
  }
}

/** Texte normalisé pour vérifier qu'une citation figure bien dans les données. */
export function normalizeForQuote(s: string): string {
  return s.normalize('NFC').toLowerCase().replace(/\s+/g, ' ').trim()
}

/** Une citation n'est retenue que si elle figure mot pour mot dans l'une des sources. */
export function quoteFound(quote: string, sources: (string | null | undefined)[]): boolean {
  const q = normalizeForQuote(quote)
  if (q.length < 3) return false
  return sources.some(s => typeof s === 'string' && normalizeForQuote(s).includes(q))
}
