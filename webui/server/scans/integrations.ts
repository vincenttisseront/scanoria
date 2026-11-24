// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Points d'appel du worker vers les autres chantiers de la 0.3, par leur
// contrat seulement (chantiers-0.3/README.md) :
// - A : decryptSecret (contrat 2), runProjectSchedules ;
// - D : ingestModuleOutputs, finalizeScanFindings (contrat 5) ;
// - E : evaluateGate (contrat 6) ;
// - F : enqueueAiTask (contrat 7).
// D, E et F sont branchés (F : version d'attente de ai/enqueue.ts, remplacée par F).
// Tant qu'un chantier n'est pas fusionné, son entrée est un bouchon sans
// effet ; le bouchon du verdict rend « non concluant » (G13 : jamais un
// verdict favorable par défaut). À la fusion, chaque bouchon est remplacé par
// l'import réel, sans autre changement.

import type pg from 'pg'
import type { Queryable } from '../utils/db'
import type { VerdictDetails } from '#shared/analysis'
import { GateRules } from '#shared/analysis'
import { enqueueAiTask } from '../ai/enqueue'
import { finalizeScanFindings, ingestModuleOutputs } from '../findings/ingest'
import { evaluateGate } from '../gates/evaluate'
import type { enqueueScan } from './enqueue'

export interface IngestOutcome { count: number, newCount: number, errors: unknown[] }

/** Contrat 7 (webui/server/ai/enqueue.ts). */
export interface AiTaskRequest {
  kind: string
  subjectType: 'finding' | 'scan' | 'testbed'
  subjectId: string
  projectId: string | null
  locale?: 'fr' | 'en'
  priority?: number
  requestedBy?: number | null
}

export interface Integrations {
  decryptSecret: (db: Queryable, credentialId: string) => Promise<{ kind: string, value: string, username: string | null | undefined }>
  ingestModuleOutputs: (db: pg.Pool, args: { scanId: string, moduleId: string, resultDir: string, outputs: Record<string, string> }) => Promise<IngestOutcome>
  finalizeScanFindings: (db: pg.Pool, scanId: string, opts: { complete: boolean }) => Promise<unknown>
  evaluateGate: (db: pg.Pool, scanId: string) => Promise<VerdictDetails>
  enqueueAiTask: (db: Queryable, req: AiTaskRequest) => Promise<string | null>
  /** A : planification ; reçoit enqueueScan (contrat 4) et ne lève jamais. */
  runProjectSchedules: (db: pg.Pool, now: Date, enqueue: typeof enqueueScan) => Promise<unknown>
}

/** Bouchon du contrat 6 : verdict non concluant, sans raison inventée. */
export async function pendingGate(db: Queryable, scanId: string): Promise<VerdictDetails> {
  const r = await db.query<{ gate_id: string, rules: unknown, plan_rules: unknown }>(
    `SELECT s.gate_id, g.rules, s.plan -> 'gate' -> 'rules' AS plan_rules
       FROM scans s JOIN gates g ON g.id = s.gate_id WHERE s.id = $1`, [scanId])
  const row = r.rows[0]
  const rules = GateRules.parse(row?.plan_rules ?? row?.rules ?? {})
  return {
    verdict: 'inconclusive',
    gate_id: row?.gate_id ?? scanId,
    rules,
    evaluated_at: new Date().toISOString(),
    new_code_only: rules.new_code_only,
    counts: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
    reasons: [],
    exceptions_applied: [],
  }
}

export const defaultIntegrations: Integrations = {
  decryptSecret: async () => {
    throw new Error('secrets unavailable')
  },
  ingestModuleOutputs: (db, args) => ingestModuleOutputs(db, args),
  finalizeScanFindings: (db, scanId, opts) => finalizeScanFindings(db, scanId, opts),
  evaluateGate: (db, scanId) => evaluateGate(db, scanId),
  enqueueAiTask,
  runProjectSchedules: async () => undefined,
}
