// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// V8 — verdict défavorable anticipé (0.7, chantier D, contrat 35).
// Pendant l'analyse, le runner écrit results/<job>/progress.json après chaque
// module (modules finis, sorties validées). Le worker y relève les modules
// « ok » terminés, ingère leurs sorties tout de suite (l'ingestion est
// idempotente : elle est refaite à la fin, à l'identique), puis évalue le
// quality gate sur ce qui est déjà connu. Une raison bloquante CERTAINE,
// qu'aucun module restant ne peut lever, est publiée aussitôt :
// scans.early_failure, puis statut d'échec dans la forge. Le verdict complet
// suit à la fin de l'analyse. Un verdict favorable n'est jamais anticipé
// (G13 : il attend tous les modules).

import { z } from 'zod'
import type pg from 'pg'
import { join } from 'node:path'
import { MODULE_ID_RE } from '#shared/schemas'
import { VerdictDetails } from '#shared/analysis'
import { readContainedFile, resultDir, resultsRoot } from './files'
import { planModuleIds } from '../gates/evaluate'

/** Raisons certaines (contrat 35) : une fois les exceptions appliquées, un module de plus ne les lève pas. */
export const CERTAIN_REASONS = ['malicious-package', 'secret', 'kev', 'license-denied'] as const

const MAX_PROGRESS_BYTES = 256 * 1024
const OUTPUT_RE = /^[A-Za-z0-9._-]+(\/[A-Za-z0-9._-]+)*$/

const progressSchema = z.object({
  schema: z.literal(1),
  modules: z.array(z.object({
    id: z.string().regex(MODULE_ID_RE),
    status: z.string().max(32).nullable(),
    outputs: z.record(z.string(), z.string().max(512).regex(OUTPUT_RE).refine(v => !v.split('/').some(x => x === '.' || x === '..'))).default({}),
  })).max(64),
})

export interface EarlyDeps {
  ingestModuleOutputs: (db: pg.Pool, args: { scanId: string, moduleId: string, resultDir: string, outputs: Record<string, string> }) => Promise<{ errors: unknown[] }>
  finalizeScanFindings: (db: pg.Pool, scanId: string, opts: { complete: boolean }) => Promise<unknown>
  evaluateGate: (db: pg.Pool, scanId: string) => Promise<VerdictDetails>
  /** Publication du statut d'échec anticipé (contrat 30) ; ne lève jamais. */
  publish?: (db: pg.Pool, scanId: string, reasons: string[]) => Promise<unknown>
}

/** Raisons certaines bloquantes d'un verdict partiel. */
export function certainReasons(details: VerdictDetails): string[] {
  return [...new Set(details.reasons.filter(r => r.blocking && (CERTAIN_REASONS as readonly string[]).includes(r.code)).map(r => r.code))]
}

/** Relit progress.json ; null s'il manque ou est invalide. */
export async function readProgress(scansDir: string, jobId: string) {
  const raw = await readContainedFile(resultsRoot(scansDir), join(resultDir(scansDir, jobId), 'progress.json'), MAX_PROGRESS_BYTES)
  if (!raw || raw === 'too-large' || raw === 'not-regular') return null
  try {
    const parsed = progressSchema.safeParse(JSON.parse(raw.toString('utf8')))
    return parsed.success ? parsed.data : null
  }
  catch {
    return null
  }
}

/**
 * Une passe de V8 sur une analyse en cours. ingested : modules déjà ingérés
 * en avance (mémoire du worker ; après un redémarrage, la reprise est sans
 * effet de bord). Rend les raisons publiées, ou null.
 */
export async function checkEarlyFailure(db: pg.Pool, deps: EarlyDeps, scan: { id: string, job_id: string, plan: unknown }, scansDir: string, ingested: Set<string>): Promise<string[] | null> {
  const st = await db.query<{ early_failure: unknown, trigger: string, status: string }>(
    'SELECT early_failure, trigger, status FROM scans WHERE id = $1 AND job_id = $2', [scan.id, scan.job_id])
  const row = st.rows[0]
  if (!row || row.early_failure || row.status !== 'running' || ['trial', 'external', 'recorrelate'].includes(row.trigger)) return null
  const progress = await readProgress(scansDir, scan.job_id)
  if (!progress) return null
  const planned = new Set(planModuleIds(scan.plan))
  let fresh = false
  for (const m of progress.modules) {
    if (m.status !== 'ok' || ingested.has(m.id) || !planned.has(m.id)) continue
    ingested.add(m.id)
    const outputs = Object.fromEntries(Object.entries(m.outputs).filter(([k]) => k === 'sarif' || k === 'cyclonedx'))
    if (!Object.keys(outputs).length) continue
    const out = await deps.ingestModuleOutputs(db, { scanId: scan.id, moduleId: m.id, resultDir: resultDir(scansDir, scan.job_id), outputs })
    // Sortie invalide : rien d'anticipé sur ce module (la fin de l'analyse tranche).
    if (!out.errors.length) fresh = true
  }
  if (!fresh) return null
  await deps.finalizeScanFindings(db, scan.id, { complete: false })
  const details = VerdictDetails.parse(await deps.evaluateGate(db, scan.id))
  const reasons = certainReasons(details)
  if (!reasons.length) return null
  const upd = await db.query(
    `UPDATE scans SET early_failure = $2 WHERE id = $1 AND early_failure IS NULL AND status = 'running'`,
    [scan.id, JSON.stringify({
      at: new Date().toISOString(),
      reasons,
      modules: [...ingested].sort(),
      finding_ids: details.reasons.filter(r => reasons.includes(r.code)).flatMap(r => r.finding_ids).slice(0, 50),
    })])
  if (!upd.rowCount) return null
  await deps.publish?.(db, scan.id, reasons)
  return reasons
}
