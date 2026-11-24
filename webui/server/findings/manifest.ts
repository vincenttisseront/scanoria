// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Ce que l'ingestion lit du manifeste d'un module dans l'index vérifié du
// catalogue : ses catégories et sa table de gravités (scan.severity_map,
// contrat 9). Lecture tolérante : un index absent donne des valeurs vides.

import { z } from 'zod'
import { SEVERITIES } from '#shared/analysis'
import { getConfig } from '../utils/config'
import { compareVersions } from '../utils/catalog'
import { readBoundedText } from './fsread'

export interface ModuleHints {
  categories: string[]
  severityMap: Record<string, string> | null
}

const hintsSchema = z.object({
  id: z.string(),
  version: z.string(),
  categories: z.array(z.string().max(32)).max(16).catch([]),
  scan: z.object({
    severity_map: z.record(z.string().max(64), z.enum(SEVERITIES)).catch({}).optional(),
  }).passthrough().nullable().catch(null).optional(),
}).passthrough()

const MAX_INDEX_BYTES = 8 * 1024 * 1024

export async function readModuleHints(moduleId: string, version?: string | null, file = getConfig().catalogIndexFile): Promise<ModuleHints> {
  const empty: ModuleHints = { categories: [], severityMap: null }
  let doc: unknown
  try {
    const text = await readBoundedText(file, MAX_INDEX_BYTES)
    if (text === null) return empty
    doc = JSON.parse(text)
  }
  catch {
    return empty
  }
  const modules = doc && typeof doc === 'object' && Array.isArray((doc as { modules?: unknown }).modules)
    ? (doc as { modules: unknown[] }).modules
    : []
  let best: z.infer<typeof hintsSchema> | undefined
  for (const raw of modules) {
    const parsed = hintsSchema.safeParse(raw)
    if (!parsed.success || parsed.data.id !== moduleId) continue
    const m = parsed.data
    if (version && m.version === version) {
      best = m
      break
    }
    if (!best || compareVersions(m.version, best.version) > 0) best = m
  }
  if (!best) return empty
  const map = best.scan?.severity_map
  return { categories: best.categories, severityMap: map && Object.keys(map).length ? map : null }
}
