// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Ordonnancement (G17) : priorité de SCAN_PRIORITY, puis ancienneté.
// Anti-famine : la priorité effective gagne 1 point toutes les AGING_STEP_S
// secondes d'attente, plafonnée juste sous celle d'une release, qui garde
// toujours la main. La même formule est appliquée en SQL (pickNextScan).

import { SCAN_PRIORITY } from '#shared/analysis'

export const AGING_STEP_S = 300
/** Plafond d'une analyse vieillie : jamais au niveau d'une release. */
export const AGING_CAP = SCAN_PRIORITY.release - 1

export function effectivePriority(priority: number, waitedMs: number): number {
  if (priority >= SCAN_PRIORITY.release) return priority
  const bonus = Math.floor(Math.max(0, waitedMs) / 1000 / AGING_STEP_S)
  return Math.min(AGING_CAP, priority + bonus)
}

/** Expression SQL équivalente, pour une ligne de scans aliasée « s ». */
export const EFFECTIVE_PRIORITY_SQL = `CASE WHEN s.priority >= ${SCAN_PRIORITY.release} THEN s.priority
  ELSE LEAST(${AGING_CAP}, s.priority + floor(extract(epoch FROM (now() - s.queued_at)) / ${AGING_STEP_S})::int) END`

export interface QueueEntry {
  id: string
  projectId: string
  priority: number
  queuedAt: Date
  notBefore?: Date | null
}

/**
 * Choix de la prochaine analyse (référence pure de la requête SQL) : priorité
 * effective décroissante, puis la plus ancienne ; projets au quota exclus ;
 * relances pas encore dues exclues.
 */
export function pickNext(queue: QueueEntry[], inFlight: Map<string, number>, perProjectLimit: number, now: Date): QueueEntry | undefined {
  return queue
    .filter(e => (inFlight.get(e.projectId) ?? 0) < perProjectLimit)
    .filter(e => !e.notBefore || e.notBefore.getTime() <= now.getTime())
    .sort((a, b) => effectivePriority(b.priority, now.getTime() - b.queuedAt.getTime())
      - effectivePriority(a.priority, now.getTime() - a.queuedAt.getTime())
      || a.queuedAt.getTime() - b.queuedAt.getTime())[0]
}

/** Recul d'une relance infra : base, puis double à chaque tentative (G12). */
export function retryDelayS(attempt: number, baseS: number): number {
  return baseS * 2 ** Math.max(0, attempt - 1)
}
