// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Options d'un module (G3) : le manifeste les décrit par un schéma JSON
// restreint (module.schema.json, chantier A) : objet sans propriété
// supplémentaire, chaque propriété de type string, integer, number, boolean
// ou array de string, avec enum, minimum/maximum, minLength/maxLength,
// pattern, default (toujours présent : rien n'est obligatoire, principe 8),
// title et description ; traductions dans options_i18n (à côté du schéma). Le même code construit le formulaire du
// client et valide les valeurs côté serveur.

export type OptionType = 'string' | 'integer' | 'number' | 'boolean' | 'array'

export interface OptionField {
  key: string
  type: OptionType
  default: unknown
  enum?: (string | number)[]
  minimum?: number
  maximum?: number
  minLength?: number
  maxLength?: number
  pattern?: string
  title?: string
  description?: string
  i18n?: Record<string, { title?: string, description?: string }>
}

export interface OptionIssue {
  key: string
  code: 'unknown' | 'type' | 'enum' | 'minimum' | 'maximum' | 'minLength' | 'maxLength' | 'pattern' | 'schema'
}

const KEY_RE = /^[A-Za-z_][A-Za-z0-9_-]{0,63}$/
const TYPES = new Set<OptionType>(['string', 'integer', 'number', 'boolean', 'array'])

/** Copie d'une valeur JSON (structuredClone refuse les objets réactifs de Vue). */
export const cloneValue = <T>(v: T): T => (v === undefined ? v : JSON.parse(JSON.stringify(v)) as T)

const num = (v: unknown) => (typeof v === 'number' && Number.isFinite(v) ? v : undefined)
const str = (v: unknown, max = 2000) => (typeof v === 'string' && v.length <= max ? v : undefined)

/**
 * Lit le schéma d'options (liste vide s'il est absent). Les traductions viennent
 * du champ options_i18n du manifeste : {<option>: {fr: {title, description}, en: …}}.
 */
export function optionFields(schema: unknown, i18n?: Record<string, unknown> | null): OptionField[] {
  if (!schema || typeof schema !== 'object') return []
  const props = (schema as { properties?: unknown }).properties
  if (!props || typeof props !== 'object' || Array.isArray(props)) return []
  const out: OptionField[] = []
  for (const [key, raw] of Object.entries(props as Record<string, unknown>).slice(0, 64)) {
    if (!KEY_RE.test(key) || !raw || typeof raw !== 'object') continue
    const p = raw as Record<string, unknown>
    const type = p.type as OptionType
    if (!TYPES.has(type)) continue
    const field: OptionField = { key, type, default: p.default }
    if (Array.isArray(p.enum)) field.enum = p.enum.filter(v => typeof v === 'string' || typeof v === 'number').slice(0, 100)
    for (const k of ['minimum', 'maximum', 'minLength', 'maxLength'] as const) {
      const v = num(p[k])
      if (v !== undefined) field[k] = v
    }
    if (str(p.pattern, 512) !== undefined) field.pattern = p.pattern as string
    if (str(p.title, 200) !== undefined) field.title = p.title as string
    if (str(p.description) !== undefined) field.description = p.description as string
    const tr = i18n?.[key]
    if (tr && typeof tr === 'object' && !Array.isArray(tr)) {
      field.i18n = {}
      for (const [lang, v] of Object.entries(tr as Record<string, unknown>)) {
        if (!/^[a-z]{2}$/.test(lang) || !v || typeof v !== 'object') continue
        const e = v as Record<string, unknown>
        field.i18n[lang] = { title: str(e.title, 200), description: str(e.description) }
      }
    }
    out.push(field)
  }
  return out
}

/** Valeurs par défaut de chaque option. */
export function optionDefaults(fields: OptionField[]): Record<string, unknown> {
  return Object.fromEntries(fields.map(f => [f.key, cloneValue(f.default)]))
}

function safeRegExp(pattern: string): RegExp | null {
  try {
    return new RegExp(pattern, 'u')
  }
  catch {
    return null
  }
}

function checkScalar(f: OptionField, v: unknown, type: OptionType): OptionIssue['code'] | null {
  if (type === 'boolean') return typeof v === 'boolean' ? null : 'type'
  if (type === 'integer' || type === 'number') {
    if (typeof v !== 'number' || !Number.isFinite(v) || (type === 'integer' && !Number.isInteger(v))) return 'type'
    if (f.minimum !== undefined && v < f.minimum) return 'minimum'
    if (f.maximum !== undefined && v > f.maximum) return 'maximum'
    return null
  }
  if (typeof v !== 'string') return 'type'
  if (f.minLength !== undefined && v.length < f.minLength) return 'minLength'
  if (f.maxLength !== undefined && v.length > f.maxLength) return 'maxLength'
  if (v.length > 4096) return 'maxLength'
  if (f.pattern !== undefined) {
    const re = safeRegExp(f.pattern)
    if (!re) return 'schema'
    if (!re.test(v)) return 'pattern'
  }
  return null
}

/** Contrôle une valeur ; null si elle est valide. */
export function checkOption(f: OptionField, v: unknown): OptionIssue['code'] | null {
  if (f.type === 'array') {
    if (!Array.isArray(v) || v.length > 256) return 'type'
    for (const item of v) {
      const c = checkScalar(f, item, 'string')
      if (c) return c
      if (f.enum && !f.enum.includes(item as string)) return 'enum'
    }
    return null
  }
  const c = checkScalar(f, v, f.type)
  if (c) return c
  if (f.enum && !f.enum.includes(v as string | number)) return 'enum'
  return null
}

/**
 * Complète les valeurs fournies par les défauts et les valide.
 * Une clé inconnue est refusée (additionalProperties: false).
 */
export function resolveOptions(schema: unknown, given: Record<string, unknown> = {}): { values: Record<string, unknown>, issues: OptionIssue[] } {
  const fields = optionFields(schema)
  const known = new Map(fields.map(f => [f.key, f]))
  const issues: OptionIssue[] = []
  for (const key of Object.keys(given)) if (!known.has(key)) issues.push({ key, code: 'unknown' })
  const values: Record<string, unknown> = {}
  for (const f of fields) {
    const v = Object.hasOwn(given, f.key) ? given[f.key] : cloneValue(f.default)
    const code = checkOption(f, v)
    if (code) issues.push({ key: f.key, code })
    values[f.key] = v
  }
  return { values, issues }
}

/** Options qui diffèrent des défauts (pour dire ce qui a été changé). */
export function changedOptions(schema: unknown, values: Record<string, unknown>): string[] {
  return optionFields(schema)
    .filter(f => JSON.stringify(values[f.key]) !== JSON.stringify(f.default))
    .map(f => f.key)
}
