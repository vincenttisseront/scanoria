// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Suites d'un résultat du runner propres à la 0.6 (chantier D), appelées par
// le worker après l'enregistrement des modules :
// - V4 : sortie reprise du cache (reused_from, compteur LRU) ; sortie neuve
//   d'un module « ok » rangée sous sa clé (jamais pour une analyse d'essai) ;
// - V6 : détection du contenu rangée par arbre (content_detection) ; module
//   « not-applicable » noté dans la couverture (G15) ;
// - V3 : module qui préfère le SBOM de l'analyse mais a dû lire le dépôt,
//   noté dans la couverture.

import type { Queryable } from '../utils/db'
import { mergeCoverageGaps, type CoverageGap } from '../findings/coverage'
import type { ScanResult } from './contract'
import { readModulesState } from '../utils/catalog'
import { readPlanCatalog } from './plan'
import { liveDigests, purgeResultCache, recordCacheHit, resultCacheDir, resultCacheMaxBytes, storeCachedOutputs } from './result-cache'

export interface OrchestrationInput {
  scanId: string
  jobId: string
  scansDir: string
  cacheDir?: string
  log?: (msg: string) => void
}

/** Nombre de clés de détection gardées (borne de content_detection.detected). */
const MAX_DETECTION_KEYS = 64

export function detectionOf(raw: Record<string, unknown> | undefined): Record<string, number> {
  const out: Record<string, number> = {}
  for (const [k, v] of Object.entries(raw ?? {}).slice(0, MAX_DETECTION_KEYS)) {
    if (/^[a-z][a-z0-9-]{0,31}$/.test(k) && Number.isInteger(v) && (v as number) >= 0) out[k] = v as number
  }
  return out
}

export function orchestrationGaps(result: ScanResult): CoverageGap[] {
  const gaps: CoverageGap[] = []
  for (const m of result.modules) {
    if (m.status === 'not-applicable') gaps.push({ kind: 'not-applicable', code: 'not-applicable', module: m.id, reason: 'no-matching-files' })
    else if (m.sbom_fallback) gaps.push({ kind: 'sbom-fallback', module: m.id })
    // 0.7 (§ 3.5) : panne d'un module d'IA rendue « skipped » par le runner ; la classe
    // « input » (pas de connecteur, « aucun envoi à l'IA ») est un choix, pas une panne.
    else if (m.ai_relay && m.status === 'skipped' && m.error && m.error.class !== 'input') {
      gaps.push({ kind: 'ai-module-failed', module: m.id, code: m.error.code })
    }
  }
  return gaps
}

export async function recordOrchestration(db: Queryable, result: ScanResult, input: OrchestrationInput): Promise<void> {
  const log = input.log ?? (() => {})
  const scan = await db.query<{ trigger: string }>('SELECT trigger FROM scans WHERE id = $1', [input.scanId])
  const trigger = scan.rows[0]?.trigger
  if (!trigger) return
  if (result.source.tree) {
    await db.query(
      `INSERT INTO content_detection (tree_sha, detected) VALUES ($1, $2)
       ON CONFLICT (tree_sha) DO UPDATE SET detected = EXCLUDED.detected, computed_at = now()`,
      [result.source.tree, JSON.stringify({ v: 1, keys: detectionOf(result.source.detection), files: result.source.files })])
  }
  await mergeCoverageGaps(db, input.scanId, orchestrationGaps(result), ['not-applicable', 'sbom-fallback', 'ai-module-failed'])
  const rows = await db.query<{ module_id: string, status: string, image_digest: string | null, results_count: number | null, duration_ms: number | null }>(
    'SELECT module_id, status, image_digest, results_count, duration_ms FROM scan_modules WHERE scan_id = $1', [input.scanId])
  const byId = new Map(rows.rows.map(r => [r.module_id, r]))
  for (const m of result.modules) {
    const row = byId.get(m.id)
    if (!row || row.status !== 'ok') continue
    try {
      if (m.reused_from) {
        // Contrat 21 : un résultat réutilisé est ingéré comme neuf ; seule la provenance est notée.
        const key = trigger === 'trial' ? null : await recordCacheHit(db, m.reused_from)
        await db.query('UPDATE scan_modules SET reused_from = $3 WHERE scan_id = $1 AND module_id = $2', [input.scanId, m.id, key])
      }
      else if (m.cache_key && trigger !== 'trial' && trigger !== 'external') {
        await storeCachedOutputs(db, {
          cacheDir: input.cacheDir ?? resultCacheDir(), scansDir: input.scansDir, jobId: input.jobId, scanId: input.scanId,
          key: m.cache_key, moduleId: m.id, imageDigest: row.image_digest ?? m.image_digest,
          outputs: Object.fromEntries(Object.entries(m.outputs).filter((e): e is [string, string] => typeof e[1] === 'string')),
          resultsCount: row.results_count, durationMs: row.duration_ms,
        })
      }
    }
    catch (e) {
      // Le cache n'est qu'un raccourci : son échec ne touche ni l'analyse ni son verdict.
      log(`scan ${input.scanId} module ${m.id}: result cache: ${(e as Error).message}`)
    }
  }
}

/**
 * Éviction du cache (V4) : images qui ne sont plus installées ni figées, puis
 * LRU au-delà de la taille maximale. État des modules illisible : LRU seule.
 */
export async function purgeCache(db: Queryable, paths: { modulesStateFile: string, catalogIndexFile: string }, cacheDir = resultCacheDir()): Promise<number> {
  const state = await readModulesState(paths.modulesStateFile)
  const catalog = state.available ? await readPlanCatalog(paths.catalogIndexFile) : new Map()
  const live = state.available && (catalog.size > 0 || state.modules.length === 0)
    ? await liveDigests(db, state.modules.map(m => ({ id: m.id, digest: catalog.get(`${m.id}@${m.version}`)?.image?.split('@')[1] ?? null })))
    : null
  const r = await purgeResultCache(db, { cacheDir, maxBytes: resultCacheMaxBytes(), liveDigests: live })
  return r.removed
}
