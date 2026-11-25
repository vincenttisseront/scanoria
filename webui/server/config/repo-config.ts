// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Configuration en code (J8) : fichier facultatif .scanoria.yml à la racine
// du dépôt. Il est lu comme une DONNÉE hostile, jamais exécuté :
// - taille bornée (64 Kio), un seul document YAML, schéma « core » (aucun
//   type ni étiquette propre au langage), clés en double refusées ;
// - aucune ancre ni alias (pas de « milliard de rires ») ;
// - contenu validé par un schéma strict (zod) ; le schéma JSON équivalent est
//   publié dans docs/ et par l'API.
// Il porte un profil par déclencheur, des demandes d'exception (motif et date
// de fin obligatoires) et des chemins ignorés ; tout s'applique dans les
// limites des verrous (G8) et passe par le circuit d'approbation (F5).

import { z } from 'zod'
import { SLUG_RE } from '#shared/analysis'
import { MODULE_ID_RE } from '#shared/schemas'
import { MAX_EXCEPTION_DAYS, isValidDay, isoDay } from '../findings/exceptions'
import { parseSafeYaml, type ConfigIssue } from './yaml'

export const REPO_CONFIG_FILE = '.scanoria.yml'
export const REPO_CONFIG_MAX_BYTES = 64 * 1024
export const REPO_CONFIG_VERSION = 1

const day = z.string().refine(isValidDay, { message: 'date AAAA-MM-JJ' })
const reason = z.string().trim().min(3).max(2000)
const tool = z.string().min(1).max(64).regex(/^[A-Za-z0-9._-]+$/)
const glob = z.string().min(1).max(512).regex(/^[^\0\n\r]+$/)
  .refine(v => !v.split('/').includes('..') && !v.startsWith('/'), { message: 'relative path without ..' })
  // « ** », « * », « */* »… : tout le dépôt, jamais une exception de chemin.
  .refine(v => !/^\*+(\/\*+)*\/?$/.test(v), { message: 'whole repository' })

const exceptionEntry = z.discriminatedUnion('kind', [
  z.strictObject({ kind: z.literal('path'), path: glob, tool: tool.optional(), reason, until: day }),
  z.strictObject({ kind: z.literal('rule'), rule: z.string().min(1).max(255), tool: tool.optional(), reason, until: day }),
  z.strictObject({ kind: z.literal('vuln'), vuln: z.string().regex(/^[A-Za-z][A-Za-z0-9]*-[A-Za-z0-9._:-]{1,120}$/), package: z.string().min(1).max(255).optional(), reason, until: day }),
  z.strictObject({ kind: z.literal('module'), module: z.string().regex(MODULE_ID_RE), reason, until: day }),
])

const ignoreEntry = z.union([
  glob,
  z.strictObject({ path: glob, reason: reason.optional(), until: day.optional() }),
])

export const repoConfigSchema = z.strictObject({
  version: z.literal(REPO_CONFIG_VERSION),
  /** Profil par déclencheur (G9), par slug ; « default » remplace profile_id. */
  profiles: z.strictObject({
    default: z.string().regex(SLUG_RE).optional(),
    pr: z.string().regex(SLUG_RE).optional(),
    nightly: z.string().regex(SLUG_RE).optional(),
    release: z.string().regex(SLUG_RE).optional(),
  }).optional(),
  exceptions: z.array(exceptionEntry).max(200).optional(),
  ignore: z.array(ignoreEntry).max(100).optional(),
})
export type RepoConfig = z.infer<typeof repoConfigSchema>

export type { ConfigIssue }

export type ParseOutcome = { ok: true, config: RepoConfig } | { ok: false, issues: ConfigIssue[] }

/** Lit le texte d'un .scanoria.yml ; jamais d'exception, jamais d'exécution. */
export function parseRepoConfig(text: string): ParseOutcome {
  const raw = parseSafeYaml(text, REPO_CONFIG_MAX_BYTES)
  if (!raw.ok) return raw
  const parsed = repoConfigSchema.safeParse(raw.value)
  if (!parsed.success) {
    return { ok: false, issues: parsed.error.issues.slice(0, 20).map(i => ({ path: i.path.join('.'), message: i.code })) }
  }
  return { ok: true, config: parsed.data }
}

export interface ConfigRequests {
  requests: { kind: 'path' | 'rule' | 'vuln' | 'module', target: Record<string, unknown>, reason: string, expires_on: string }[]
  ignored: { path: string, until: string }[]
}

/** Demandes d'exception portées par la configuration (exceptions et chemins ignorés). */
export function configRequests(config: RepoConfig, today = isoDay()): ConfigRequests {
  const defaultUntil = isoDay(90, new Date(`${today}T00:00:00Z`))
  const maxUntil = isoDay(MAX_EXCEPTION_DAYS, new Date(`${today}T00:00:00Z`))
  const clamp = (d: string) => (d > maxUntil ? maxUntil : d)
  const requests: ConfigRequests['requests'] = []
  for (const e of config.exceptions ?? []) {
    const until = clamp(e.until)
    if (e.kind === 'path') requests.push({ kind: 'path', target: { glob: e.path, ...(e.tool ? { tool: e.tool } : {}) }, reason: e.reason, expires_on: until })
    else if (e.kind === 'rule') requests.push({ kind: 'rule', target: { rule_id: e.rule, ...(e.tool ? { tool: e.tool } : {}) }, reason: e.reason, expires_on: until })
    else if (e.kind === 'vuln') requests.push({ kind: 'vuln', target: { vuln_id: e.vuln, ...(e.package ? { package: e.package } : {}) }, reason: e.reason, expires_on: until })
    else requests.push({ kind: 'module', target: { module_id: e.module }, reason: e.reason, expires_on: until })
  }
  const ignored: ConfigRequests['ignored'] = []
  for (const i of config.ignore ?? []) {
    const path = typeof i === 'string' ? i : i.path
    const until = clamp(typeof i === 'string' ? defaultUntil : (i.until ?? defaultUntil))
    const why = typeof i === 'string' ? undefined : i.reason
    ignored.push({ path, until })
    // Un chemin ignoré par le dépôt ne s'exclut du verdict qu'une fois approuvé (F5) :
    // il devient une demande d'exception de chemin.
    requests.push({ kind: 'path', target: { glob: path }, reason: why ?? `${REPO_CONFIG_FILE} : chemin ignoré`, expires_on: until })
  }
  return { requests, ignored }
}

/** Schéma JSON publié (docs/ et GET /api/config/schema), équivalent au schéma zod. */
export function repoConfigJsonSchema(): Record<string, unknown> {
  const s = z.toJSONSchema(repoConfigSchema, { target: 'draft-2020-12', unrepresentable: 'any' }) as Record<string, unknown>
  return {
    $id: 'https://scanoria.exemple.test/schemas/scanoria-config.schema.json',
    title: '.scanoria.yml',
    description: 'Configuration en code d\'un dépôt analysé par Scanoria (J8). Lue sans exécution, dans les limites des verrous de profil.',
    ...s,
  }
}
