// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// I17, traduction des messages des outils (translate-rule) : le titre d'une
// règle d'outil (description courte, en anglais) traduit dans la langue de
// l'utilisateur, le texte d'origine restant toujours affiché. Sujet « rule »,
// clé « outil:version:règle », sans projet : la traduction vaut pour toute
// l'appliance et se met en cache par règle et par version d'outil.
//
// Seul le texte de la règle est envoyé, jamais de code : le titre (qui vient
// de la description de la règle, pas du résultat), lu sur un résultat d'un
// projet qui accepte l'IA, masqué. Ni message, ni extrait, ni chemin.

import { z } from 'zod'
import { redactText } from '../redact'
import { sanitizeText } from '../sanitize'
import { text, type TaskDefinition } from '../task-kit'

/** outil:version:règle ; l'outil et la version sans « : ». */
export const RULE_KEY_RE = /^([a-z0-9][a-z0-9-]{1,40}):([A-Za-z0-9._+~-]{1,64}):([^\s]{1,255})$/

export function ruleKey(tool: string, version: string | null | undefined, ruleId: string): string | null {
  const v = (version ?? 'unknown').replace(/[^A-Za-z0-9._+~-]/g, '-').slice(0, 64) || 'unknown'
  const key = `${tool}:${v}:${ruleId.replace(/\s+/g, '_').slice(0, 255)}`
  return RULE_KEY_RE.test(key) ? key : null
}

export interface TranslateInput {
  tool: string
  rule_id: string
  text: string
}

export const TranslateOutput = z.strictObject({
  translation: z.string().min(1).max(600),
})
export type TranslateOutput = z.infer<typeof TranslateOutput>

export const translateRule: TaskDefinition<TranslateInput, TranslateOutput> = {
  kind: 'translate-rule',
  subjectType: 'rule',
  projectScoped: false,
  subjectPattern: RULE_KEY_RE,
  timeoutMs: 60_000,
  async load(db, ctx) {
    const m = RULE_KEY_RE.exec(ctx.subjectId)
    if (!m) return null
    const [, tool, , ruleId] = m
    // Le titre le plus fréquent de la règle, sur les projets qui acceptent l'IA seulement.
    const { rows } = await db.query<{ title: string }>(
      `SELECT f.title FROM findings f JOIN projects p ON p.id = f.project_id
        WHERE f.tool = $1 AND f.rule_id = $2 AND NOT p.ai_opt_out AND p.archived_at IS NULL AND f.category <> 'secrets'
        GROUP BY f.title ORDER BY count(*) DESC, f.title LIMIT 1`,
      [tool, ruleId],
    )
    const title = rows[0]?.title
    if (!title) return null
    return { tool: tool!, rule_id: ruleId!.slice(0, 255), text: redactText(title.slice(0, 500)).text }
  },
  instruction: locale => locale === 'fr'
    ? 'Traduis en français le texte de cette règle d\'outil d\'analyse : translation. Garde tels quels les identifiants techniques (noms de fonctions, de paquets, CWE, CVE, options). Ne réponds que par la traduction.'
    : 'Translate the text of this analysis tool rule into English: translation. Keep technical identifiers (function, package names, CWE, CVE, options) unchanged. Answer only with the translation.',
  jsonSchema: {
    type: 'object',
    additionalProperties: false,
    required: ['translation'],
    properties: { translation: text(600) },
  },
  output: TranslateOutput,
  finalize: out => ({ translation: sanitizeText(out.translation, 600) }),
}
