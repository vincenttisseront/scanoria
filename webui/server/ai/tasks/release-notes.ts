// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// I6, notes de sécurité de release (release-notes, 0.8 chantier A) : texte
// prêt à publier à partir de la comparaison F2 et du rapport de release
// signé : ce qui est corrigé, ce qui est introduit, ce qui est accepté avec
// son motif. Annexe NON signée, marquée « proposé par IA » avec le modèle et
// son empreinte : le rapport signé reste inchangé, et l'IA ne décide rien.
//
// Sujet « release » (identifiant = analyse de release). Ne lit que le rapport
// de ce projet (métadonnées : outil, règle, gravité, titre, motif masqué),
// jamais de code ; rien pour un projet « aucun envoi à l'IA » (enqueue.ts).

import { z } from 'zod'
import { redactText } from '../redact'
import { sanitizeText } from '../sanitize'
import { text, UUID_RE, type TaskDefinition } from '../task-kit'

const MAX_ITEMS = 15

interface NoteItem { tool: string, rule_id: string, severity: string, title: string }

export interface ReleaseNotesInput {
  tag: string
  previous_tag: string | null
  verdict: string
  introduced: { total: number, by_severity: Record<string, number>, items: NoteItem[] }
  fixed: { total: number, by_severity: Record<string, number>, items: NoteItem[] }
  accepted: { kind: string, reason: string, expires_on: string, vex_status: string | null }[]
}

export const ReleaseNotesOutput = z.strictObject({
  headline: z.string().min(1).max(300),
  fixed: z.string().min(1).max(1500),
  introduced: z.string().min(1).max(1500),
  accepted: z.string().min(1).max(1500),
})
export type ReleaseNotesOutput = z.infer<typeof ReleaseNotesOutput>

type Bucket = { total?: number, by_severity?: Record<string, number>, findings?: { id: string, severity: string }[] }

async function items(db: Parameters<TaskDefinition['load']>[0], projectId: string, b: Bucket | undefined): Promise<ReleaseNotesInput['introduced']> {
  const ids = (b?.findings ?? []).map(f => f.id).filter(id => UUID_RE.test(id)).slice(0, MAX_ITEMS)
  const r = ids.length
    ? await db.query<NoteItem>(
        `SELECT tool, rule_id, severity, title FROM findings WHERE project_id = $1 AND id = ANY($2::uuid[])
          ORDER BY array_position(ARRAY['critical', 'high', 'medium', 'low', 'info'], severity), tool, rule_id`, [projectId, ids])
    : { rows: [] }
  return {
    total: typeof b?.total === 'number' ? b.total : 0,
    by_severity: b?.by_severity ?? {},
    items: r.rows.map(x => ({ tool: x.tool.slice(0, 100), rule_id: x.rule_id.slice(0, 255), severity: x.severity, title: redactText(x.title.slice(0, 300)).text })),
  }
}

export const releaseNotes: TaskDefinition<ReleaseNotesInput, ReleaseNotesOutput> = {
  kind: 'release-notes',
  subjectType: 'release',
  timeoutMs: 180_000,
  async load(db, ctx) {
    if (!ctx.projectId || !UUID_RE.test(ctx.subjectId)) return null
    const { rows } = await db.query<{ report: Record<string, unknown> }>(
      `SELECT report FROM release_reports WHERE scan_id = $1 AND project_id = $2 AND status = 'signed'`, [ctx.subjectId, ctx.projectId])
    const rep = rows[0]?.report
    if (!rep) return null
    const cmp = rep.comparison as { previous?: { tag?: string }, introduced?: Bucket, fixed?: Bucket } | null
    const exc = Array.isArray(rep.exceptions) ? rep.exceptions as { kind?: string, reason?: string, expires_on?: string, vex_status?: string | null }[] : []
    return {
      tag: String(rep.tag ?? '').slice(0, 255),
      previous_tag: typeof cmp?.previous?.tag === 'string' ? cmp.previous.tag.slice(0, 255) : null,
      verdict: String((rep.verdict as { value?: string } | undefined)?.value ?? 'inconclusive'),
      introduced: await items(db, ctx.projectId, cmp?.introduced),
      fixed: await items(db, ctx.projectId, cmp?.fixed),
      accepted: exc.slice(0, MAX_ITEMS).map(e => ({
        kind: String(e.kind ?? '').slice(0, 20),
        reason: redactText(String(e.reason ?? '').slice(0, 600)).text,
        expires_on: String(e.expires_on ?? '').slice(0, 10),
        vex_status: typeof e.vex_status === 'string' ? e.vex_status : null,
      })),
    }
  },
  instruction: locale => locale === 'fr'
    ? 'Rédige les notes de sécurité de cette release, prêtes à publier, sans rien inventer : headline (une phrase), fixed (ce qui est corrigé depuis previous_tag), introduced (ce qui est introduit, par gravité), accepted (risques acceptés avec leur motif et leur date de fin, ou « aucun »). Sans release précédente, dis-le.'
    : 'Write the security notes of this release, ready to publish, without inventing anything: headline (one sentence), fixed (what is fixed since previous_tag), introduced (what is introduced, by severity), accepted (accepted risks with their reason and end date, or "none"). Without a previous release, say so.',
  jsonSchema: {
    type: 'object',
    additionalProperties: false,
    required: ['headline', 'fixed', 'introduced', 'accepted'],
    properties: { headline: text(300), fixed: text(1500), introduced: text(1500), accepted: text(1500) },
  },
  output: ReleaseNotesOutput,
  finalize: out => ({
    headline: sanitizeText(out.headline, 300),
    fixed: sanitizeText(out.fixed, 1500),
    introduced: sanitizeText(out.introduced, 1500),
    accepted: sanitizeText(out.accepted, 1500),
  }),
}
