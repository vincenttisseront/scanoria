// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Badge SVG du dernier verdict d'un projet (§ 6.3). Texte fixe, aucune donnée
// saisie n'entre dans le SVG.

import type { Queryable } from '../utils/db'
import type { Verdict } from '#shared/analysis'

const COLORS: Record<Verdict | 'unknown', string> = {
  passed: '#2e7d32',
  failed: '#c62828',
  inconclusive: '#ef6c00',
  unknown: '#757575',
}
const LABELS: Record<Verdict | 'unknown', string> = {
  passed: 'passed',
  failed: 'failed',
  inconclusive: 'inconclusive',
  unknown: 'unknown',
}

/** Largeur approchée d'un texte Verdana 11 px (badges usuels). */
function textWidth(s: string): number {
  return Math.round(s.length * 6.6 + 10)
}

export function badgeSvg(verdict: Verdict | null): string {
  const key = verdict ?? 'unknown'
  const left = 'scanoria'
  const right = LABELS[key]
  const lw = textWidth(left)
  const rw = textWidth(right)
  const w = lw + rw
  return `<svg xmlns="http://www.w3.org/2000/svg" width="${w}" height="20" role="img" aria-label="${left}: ${right}">`
    + `<title>${left}: ${right}</title>`
    + `<rect width="${lw}" height="20" fill="#555"/>`
    + `<rect x="${lw}" width="${rw}" height="20" fill="${COLORS[key]}"/>`
    + `<g fill="#fff" text-anchor="middle" font-family="Verdana,DejaVu Sans,sans-serif" font-size="11">`
    + `<text x="${lw / 2}" y="14">${left}</text>`
    + `<text x="${lw + rw / 2}" y="14">${right}</text>`
    + `</g></svg>`
}

/**
 * Dernier verdict rendu sur la branche par défaut, sinon sur n'importe quelle référence.
 * Les téléversements externes (J6) n'en font jamais partie : le badge public reflète
 * les analyses de l'appliance, pas un document envoyé par la CI.
 */
export async function latestVerdict(db: Queryable, projectId: string, defaultBranch: string | null): Promise<Verdict | null> {
  const res = await db.query<{ verdict: Verdict }>(
    `SELECT verdict FROM scans
      WHERE project_id = $1 AND verdict IS NOT NULL AND status = 'done' AND trigger <> 'external'
      ORDER BY (ref = $2) DESC, finished_at DESC NULLS LAST, number DESC
      LIMIT 1`,
    [projectId, defaultBranch ?? ''],
  )
  return res.rows[0]?.verdict ?? null
}
