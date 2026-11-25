// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// I6 : annexe « notes de sécurité » d'une release, en Markdown, depuis la
// dernière sortie de la tâche release-notes. Annexe NON signée, marquée
// « proposé par IA » avec le modèle et son empreinte ; le rapport signé n'en
// dépend pas. Passée par sanitizeForForge (mentions et images neutralisées,
// liens limités) avant tout envoi à la forge comme dans la console.

import type { Queryable } from '../utils/db'
import { consoleUrl } from '../forges/context'
import { sanitizeForForge } from '../forges/sanitize'
import { forgeLocale } from '../forges/publish'

interface NotesRow { output: { headline?: unknown, fixed?: unknown, introduced?: unknown, accepted?: unknown } | null, model: string | null, model_digest: string | null, tag: string }

const T = {
  fr: { title: 'Notes de sécurité', mark: 'Proposé par IA', unsigned: 'annexe non signée : le rapport de release signé fait foi', fixed: 'Corrigé', introduced: 'Introduit', accepted: 'Accepté' },
  en: { title: 'Security notes', mark: 'Proposed by AI', unsigned: 'unsigned appendix: the signed release report is authoritative', fixed: 'Fixed', introduced: 'Introduced', accepted: 'Accepted' },
}

/** Markdown des notes I6 d'une release, ou null si aucune sortie n'est prête. */
export async function notesMarkdown(db: Queryable, scanId: string, locale = forgeLocale()): Promise<string | null> {
  const r = await db.query<NotesRow>(
    `SELECT t.output, t.model, t.model_digest, rr.tag FROM ai_tasks t JOIN release_reports rr ON rr.scan_id::text = t.subject_id
      WHERE t.kind = 'release-notes' AND t.subject_type = 'release' AND t.subject_id = $1 AND t.status = 'done'
      ORDER BY (t.locale = $2) DESC, t.finished_at DESC NULLS LAST LIMIT 1`, [scanId, locale])
  const row = r.rows[0]
  const o = row?.output
  if (!row || !o) return null
  const t = T[locale]
  const str = (v: unknown) => (typeof v === 'string' ? v : '')
  const model = `${row.model ?? '?'}${row.model_digest ? ` (${row.model_digest.slice(0, 19)})` : ''}`
  const md = [
    `# ${t.title} · ${row.tag}`,
    '',
    `_${t.mark} · ${model} · ${t.unsigned}_`,
    '',
    str(o.headline),
    '',
    `## ${t.fixed}`, '', str(o.fixed), '',
    `## ${t.introduced}`, '', str(o.introduced), '',
    `## ${t.accepted}`, '', str(o.accepted), '',
  ].join('\n')
  return sanitizeForForge(md, { consoleUrl: await consoleUrl() })
}
