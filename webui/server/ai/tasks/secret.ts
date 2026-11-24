// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// I14, typage des secrets génériques (classify-secret) : un candidat sans
// type connu (forte entropie, règle « generic ») est classé mot de passe,
// jeton interne, clé privée ou faux positif probable, à partir du CONTEXTE
// SEULEMENT. La valeur n'est jamais en base (F7) ; ce qui part au modèle est
// le chemin, la règle, la ligne, le message masqué et la forme de la valeur
// (type, longueur, jeu de caractères). Le résultat alimente F7 comme une
// suggestion affichée à côté du suivi du secret, jamais comme un état.

import { z } from 'zod'
import { redactText } from '../redact'
import { sanitizeText } from '../sanitize'
import { findingRow, isSecretRow, oneOf, pathHints, text, type TaskDefinition } from '../task-kit'

export const SECRET_CLASSES = ['password', 'internal-token', 'private-key', 'likely-false-positive', 'other'] as const
export const CONFIDENCE = ['low', 'medium', 'high'] as const

/** Type sans signification propre : seul un tel candidat est classé (I14). */
export const GENERIC_SECRET_RE = /generic|entropy|unknown|^secrets?$|^hardcoded|^credential|^password$|^token$/i

export function isGenericSecret(f: { category?: unknown, secret_type?: unknown, rule_id?: unknown }): boolean {
  if (!isSecretRow(f as Record<string, unknown>)) return false
  const t = typeof f.secret_type === 'string' ? f.secret_type : ''
  return t === '' || GENERIC_SECRET_RE.test(t) || GENERIC_SECRET_RE.test(String(f.rule_id ?? ''))
}

export interface SecretInput {
  tool: string
  rule_id: string
  secret_type: string | null
  path: string | null
  file_name: string | null
  extension: string | null
  line: number | null
  message: string | null
  /** Forme de la valeur telle que le résultat la décrit (jamais la valeur). */
  value_shape: string | null
  path_hints: ReturnType<typeof pathHints>
}

export const SecretOutput = z.strictObject({
  class: z.enum(SECRET_CLASSES),
  confidence: z.enum(CONFIDENCE),
  summary: z.string().min(1).max(300),
  reasons: z.array(z.string().min(1).max(300)).min(1).max(4),
})
export type SecretOutput = z.infer<typeof SecretOutput>

/** « [secret masqué : snippet, longueur 40] » → « longueur 40 » ; aucune autre information. */
function shapeOf(snippet: unknown): string | null {
  if (typeof snippet !== 'string') return null
  const m = /\[secret masqué : [a-z0-9-]+, longueur ([0-9]+)\]/.exec(snippet)
  return m ? `length=${m[1]}` : null
}

export const classifySecret: TaskDefinition<SecretInput, SecretOutput> = {
  kind: 'classify-secret',
  subjectType: 'finding',
  timeoutMs: 90_000,
  async load(db, ctx) {
    const f = await findingRow(db, ctx)
    if (!f || !isGenericSecret(f)) return null
    const path = typeof f.path === 'string' ? f.path.slice(0, 1024) : null
    const name = path ? path.split('/').pop() ?? null : null
    const ext = name && name.includes('.') ? name.split('.').pop()!.slice(0, 16).toLowerCase() : null
    return {
      tool: String(f.tool).slice(0, 100),
      rule_id: String(f.rule_id).slice(0, 255),
      secret_type: typeof f.secret_type === 'string' ? redactText(f.secret_type.slice(0, 64)).text : null,
      path,
      file_name: name,
      extension: ext,
      line: typeof f.start_line === 'number' ? f.start_line : null,
      // Message de l'outil masqué à l'ingestion, masqué de nouveau ici (règle IA, plus large).
      message: typeof f.message === 'string' ? redactText(f.message.slice(0, 1000)).text : null,
      value_shape: shapeOf(f.snippet),
      path_hints: pathHints(path),
    }
  },
  instruction: locale => locale === 'fr'
    ? 'Classe ce secret candidat d\'après son contexte seulement (la valeur n\'est jamais fournie et ne doit pas être devinée) : class parmi password, internal-token, private-key, likely-false-positive, other ; confidence (low, medium, high) ; summary (une phrase) ; reasons (1 à 4 indices tirés du chemin, du nom du fichier, de la règle ou du message). Un fichier de test, d\'exemple ou de documentation rend un faux positif plus probable. Tu suggères seulement : une personne décide de la révocation.'
    : 'Classify this candidate secret from its context only (the value is never provided and must not be guessed): class among password, internal-token, private-key, likely-false-positive, other; confidence (low, medium, high); summary (one sentence); reasons (1 to 4 clues taken from the path, file name, rule or message). A test, example or documentation file makes a false positive more likely. You only suggest: a person decides on revocation.',
  jsonSchema: {
    type: 'object',
    additionalProperties: false,
    required: ['class', 'confidence', 'summary', 'reasons'],
    properties: {
      class: oneOf(SECRET_CLASSES),
      confidence: oneOf(CONFIDENCE),
      summary: text(300),
      reasons: { type: 'array', minItems: 1, maxItems: 4, items: text(300) },
    },
  },
  output: SecretOutput,
  finalize: out => ({
    class: out.class,
    confidence: out.confidence,
    summary: sanitizeText(out.summary, 300),
    reasons: out.reasons.map(r => sanitizeText(r, 300)),
  }),
}
