// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Catalogue des modules vu par la console (lecture seule) :
// - index vérifié par le helper (/var/lib/scanoria/catalog/catalog-index.json) ;
// - état des modules (/var/lib/scanoria/modules/state.json) ;
// - état DNS (/var/lib/scanoria/dns/status.json).
// Les fichiers sont relus à chaque appel et validés sans confiance : une entrée
// mal formée est écartée, jamais servie telle quelle.

import { readFile } from 'node:fs/promises'
import { z } from 'zod'
import { BACKUP_ID_RE, MODULE_ID_RE, MODULE_VERSION_RE, TIMESTAMP_RE } from '#shared/schemas'

export const MODULE_TYPES = ['scanner', 'service', 'feed', 'runner'] as const
export const RESTRICTIONS = ['none', 'private-code-forbidden', 'no-redistribution', 'other'] as const
export const MODULE_STATUSES = ['installing', 'testing', 'healthy', 'failed', 'disabled', 'removing'] as const

const id = z.string().regex(MODULE_ID_RE)
const ids = z.array(id).max(64).default([])
const text = (max: number) => z.string().max(max)
const httpsUrl = z.string().max(512).regex(/^https:\/\/[^\s"<>]+$/)
const nullableTimestamp = z.string().regex(TIMESTAMP_RE).nullable().optional()

/** Texte traduit du catalogue, toujours servi sous la forme { fr, en }. */
export interface LocalizedText { fr: string, en: string }
const localizedText = z.union([
  text(2000).transform(s => ({ fr: s, en: s })),
  z.object({ fr: text(2000).optional(), en: text(2000).optional() })
    .refine(o => o.fr !== undefined || o.en !== undefined)
    .transform(o => ({ fr: o.fr ?? o.en ?? '', en: o.en ?? o.fr ?? '' })),
])

const moduleSchema = z.object({
  id,
  name: text(128),
  type: z.enum(MODULE_TYPES),
  version: z.string().regex(MODULE_VERSION_RE),
  // Manifeste : { fr, en } (catalog/schema/module.schema.json) ; texte seul accepté.
  description: localizedText.optional(),
  categories: z.array(text(32)).max(16).default([]),
  license: z.object({
    spdx: text(128),
    url: httpsUrl.optional(),
    restrictions: z.enum(RESTRICTIONS),
    note: text(2000).optional(),
  }),
  upstream: z.object({ homepage: httpsUrl.optional(), source: httpsUrl.optional() }).partial().optional(),
  image: text(512).optional(),
  resources: z.object({
    min_ram_mb: z.number().int().min(0).max(1_048_576).default(0),
    min_cpu: z.number().min(0).max(1024).default(0),
    disk_mb: z.number().int().min(0).max(16_777_216).default(0),
  }).default({ min_ram_mb: 0, min_cpu: 0, disk_mb: 0 }),
  hostname: z.string().regex(MODULE_ID_RE).nullable().optional(),
  needs: z.object({
    feeds: ids,
    sysctl: z.record(z.string().max(128), z.union([z.string().max(64), z.number()])).default({}),
    postgres: z.boolean().default(false),
  }).partial().optional(),
  requires: z.object({
    modules: ids,
    feeds: ids,
    appliance: z.string().max(32).optional(),
  }).partial().optional(),
  conflicts: ids,
  options: z.record(z.string(), z.unknown()).nullable().optional(),
  options_i18n: z.record(z.string(), z.unknown()).nullable().optional(),
  outputs: z.record(z.string(), z.unknown()).optional(),
  testbed: z.record(z.string(), z.unknown()).nullable().optional(),
  service: z.record(z.string(), z.unknown()).nullable().optional(),
})
export type CatalogModule = z.infer<typeof moduleSchema>

const packSchema = z.object({
  id,
  name: text(128),
  modules: z.array(id).min(1).max(32),
  technologies: z.array(text(32)).max(32).default([]),
  description: localizedText.optional(),
})
export type CatalogPack = z.infer<typeof packSchema>

export interface CatalogIndex {
  version: number
  generated_at: string | null
  modules: CatalogModule[]
  packs: CatalogPack[]
  /** Entrées écartées car mal formées (nombre seulement). */
  rejected: number
}

const testbedSchema = z.object({
  passed: z.boolean().nullable(),
  at: nullableTimestamp,
  details: z.unknown().optional(),
}).nullable().optional()

const installedSchema = z.object({
  id,
  version: z.string().regex(MODULE_VERSION_RE),
  type: z.enum(MODULE_TYPES),
  status: z.enum(MODULE_STATUSES),
  enabled: z.boolean(),
  installed_at: nullableTimestamp,
  options: z.record(z.string(), z.unknown()).default({}),
  testbed: testbedSchema,
  route: z.object({ hostname: text(253).nullable(), url: httpsUrl.nullable() }).nullable().optional(),
  last_error: z.union([text(2000), z.object({ code: text(64).optional(), message: text(2000).optional() })]).nullable().optional(),
  // Fonctions optionnelles d'un service (variantes : plugin de branches de SonarQube).
  features: z.record(z.string().regex(/^[a-z][a-z0-9_]{0,30}$/), z.object({
    active: z.boolean(),
    version: text(64).nullable(),
    code: z.enum(['disabled', 'incompatible', 'unavailable']).nullable().optional(),
    reason: text(500).nullable(),
  })).optional(),
  // Modules permanents (0.4) : sauvegardes complètes, la plus récente en premier.
  backups: z.array(z.object({
    id: z.string().regex(BACKUP_ID_RE),
    created_at: z.string().regex(TIMESTAMP_RE),
    module_version: z.string().regex(MODULE_VERSION_RE),
    reason: z.enum(['manual', 'update', 'scheduled']),
    size_bytes: z.number().int().min(0),
    database: z.boolean(),
    volumes: z.array(text(31)).max(32),
  })).max(20).optional(),
})
export type InstalledModule = z.infer<typeof installedSchema>

const operationSchema = z.object({
  id: text(64),
  request_id: text(64).nullable().optional(),
  kind: text(32),
  module: z.string().regex(MODULE_ID_RE).nullable().optional(),
  step: text(64).nullable().optional(),
  progress: z.number().min(0).max(100).nullable().optional(),
  started_at: nullableTimestamp,
  finished_at: nullableTimestamp,
  result: z.unknown().optional(),
  message: text(500).nullable().optional(),
})
export type ModuleOperation = z.infer<typeof operationSchema>

/** Base d'un module feed (0.3.4) : âge, taille, état du dernier téléchargement. */
const feedStatusSchema = z.object({
  id,
  updated_at: nullableTimestamp,
  checked_at: nullableTimestamp.optional(),
  size_mb: z.number().min(0).nullable(),
  status: z.enum(['ok', 'stale', 'failed', 'missing']),
  error: text(500).nullable().optional(),
})
export type FeedStatus = z.infer<typeof feedStatusSchema>

export interface ModulesState {
  available: boolean
  modules: InstalledModule[]
  operations: ModuleOperation[]
  feeds: FeedStatus[]
}

const dnsRecordSchema = z.object({
  name: text(255),
  type: z.enum(['A', 'AAAA']),
  expected: text(64),
  resolved: z.array(text(64)).max(32).default([]),
  ok: z.boolean(),
})
const dnsStatusSchema = z.object({
  fqdn: text(253).nullable(),
  checked_at: nullableTimestamp,
  records: z.array(dnsRecordSchema).max(256).default([]),
})
export type DnsStatus = z.infer<typeof dnsStatusSchema>

const deniedLogged = new Set<string>()

async function readJson(path: string, max: number): Promise<unknown> {
  try {
    const buf = await readFile(path)
    if (buf.length > max) return undefined
    return JSON.parse(buf.toString('utf8'))
  }
  catch (err) {
    // Un fichier présent mais illisible (droits du répertoire) ressemble à un
    // fichier absent pour l'utilisateur : on le signale une fois dans le journal.
    const code = (err as NodeJS.ErrnoException).code
    if ((code === 'EACCES' || code === 'EPERM') && !deniedLogged.has(path)) {
      deniedLogged.add(path)
      console.warn(`[catalog] ${path} : lecture refusée (${code}), vérifier les droits du répertoire`)
    }
    return undefined
  }
}

/** Garde les éléments valides d'une liste ; compte les autres. */
function keepValid<S extends z.ZodType>(schema: S, items: unknown): { ok: z.infer<S>[], rejected: number } {
  const ok: z.infer<S>[] = []
  let rejected = 0
  for (const item of Array.isArray(items) ? items.slice(0, 1000) : []) {
    const parsed = schema.safeParse(item)
    if (parsed.success) ok.push(parsed.data)
    else rejected++
  }
  return { ok, rejected }
}

export async function readCatalogIndex(path: string): Promise<CatalogIndex | null> {
  const raw = await readJson(path, 8 * 1024 * 1024)
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null
  const doc = raw as Record<string, unknown>
  if (doc.schema !== 1 || !Number.isInteger(doc.version)) return null
  const modules = keepValid(moduleSchema, doc.modules)
  const packs = keepValid(packSchema, doc.packs)
  return {
    version: doc.version as number,
    generated_at: typeof doc.generated_at === 'string' && TIMESTAMP_RE.test(doc.generated_at) ? doc.generated_at : null,
    modules: modules.ok,
    packs: packs.ok,
    rejected: modules.rejected + packs.rejected,
  }
}

export async function readModulesState(path: string): Promise<ModulesState> {
  const raw = await readJson(path, 2 * 1024 * 1024)
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return { available: false, modules: [], operations: [], feeds: [] }
  const doc = raw as Record<string, unknown>
  return {
    available: true,
    modules: keepValid(installedSchema, doc.modules).ok,
    operations: keepValid(operationSchema, doc.operations).ok,
    feeds: keepValid(feedStatusSchema, doc.feeds).ok,
  }
}

export async function readDnsStatus(path: string): Promise<DnsStatus | null> {
  const parsed = dnsStatusSchema.safeParse(await readJson(path, 512 * 1024))
  return parsed.success ? parsed.data : null
}

/** Comparaison de versions : segments numériques, puis texte. */
export function compareVersions(a: string, b: string): number {
  const pa = a.split(/[.+_-]/)
  const pb = b.split(/[.+_-]/)
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const x = pa[i] ?? ''
    const y = pb[i] ?? ''
    if (x === y) continue
    const nx = /^[0-9]+$/.test(x) ? Number(x) : Number.NaN
    const ny = /^[0-9]+$/.test(y) ? Number(y) : Number.NaN
    if (!Number.isNaN(nx) && !Number.isNaN(ny)) return nx - ny
    // Segment absent : 0 face à un nombre ; une version finale passe devant une pré-version.
    if (x === '') return Number.isNaN(ny) ? 1 : -ny || 0
    if (y === '') return Number.isNaN(nx) ? -1 : nx || 0
    return x < y ? -1 : 1
  }
  return 0
}

/** Dernière version de chaque module de l'index (un id peut figurer en plusieurs versions). */
export function latestModules(index: CatalogIndex | null): Map<string, CatalogModule> {
  const out = new Map<string, CatalogModule>()
  for (const m of index?.modules ?? []) {
    const cur = out.get(m.id)
    if (!cur || compareVersions(m.version, cur.version) > 0) out.set(m.id, m)
  }
  return out
}

export function findModule(index: CatalogIndex | null, moduleId: string, version?: string): CatalogModule | undefined {
  if (version) return index?.modules.find(m => m.id === moduleId && m.version === version)
  return latestModules(index).get(moduleId)
}

/** « >=x.y.z » (seule forme du contrat 0.2) ; une contrainte absente est satisfaite. */
export function satisfiesAppliance(constraint: string | undefined, version: string): boolean {
  if (!constraint) return true
  const m = /^>=\s*([0-9]+\.[0-9]+\.[0-9]+)$/.exec(constraint.trim())
  if (!m) return false
  return compareVersions(version, m[1]!) >= 0
}

/** Modules recommandés au premier accès (CLAUDE.md § 5.3) : légers, sans service permanent. */
export const RECOMMENDED_IDS = ['gitleaks', 'osv-scanner', 'trivy', 'syft', 'grype', 'shellcheck', 'actionlint', 'checkov', 'epss', 'kev'] as const
