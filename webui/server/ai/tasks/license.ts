// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// I18, explication des licences (explain-license) : pour une licence « à
// revoir » ou inhabituelle d'un SBOM (F8), obligations principales,
// compatibilité avec la licence déclarée du projet (projects.spdx_license) et
// conditions d'usage à vérifier. Une aide, jamais un avis juridique, et
// jamais une décision : la politique de licences reste réglée par une
// personne (F8).
//
// Sujet « license », sans projet : clé « <licence>|<licence du projet> »
// (« none » si le projet n'en déclare pas). La sortie ne dépend d'aucun code :
// elle est mise en cache par licence et par licence de projet pour toute
// l'appliance. Rien n'est envoyé d'autre que ces deux identifiants, et
// seulement si un projet qui accepte l'IA a cette licence de projet et un
// composant sous cette licence (rien d'un projet « aucun envoi à l'IA »).

import { z } from 'zod'
import { sanitizeText } from '../sanitize'
import { oneOf, text, type TaskDefinition } from '../task-kit'

/** Identifiant ou expression SPDX (LicenseRef-…, « MIT OR Apache-2.0 », « … WITH … »). */
const SPDX_PART = '[A-Za-z0-9][A-Za-z0-9.+:() -]{0,127}'
const PROJECT_PART = '[A-Za-z0-9][A-Za-z0-9.+-]{0,63}'
export const LICENSE_KEY_RE = new RegExp(`^(${SPDX_PART})\\|(${PROJECT_PART})$`)
export const NO_PROJECT_LICENSE = 'none'

/** Clé de la tâche, ou null si l'un des identifiants n'a pas la forme SPDX attendue. */
export function licenseKey(license: string, projectLicense: string | null | undefined): string | null {
  const l = license.trim().replace(/\s+/g, ' ')
  const p = (projectLicense ?? '').trim() || NO_PROJECT_LICENSE
  const key = `${l}|${p}`
  return LICENSE_KEY_RE.test(key) && !/\s\s|\|.*\|/.test(key) ? key : null
}

export function parseLicenseKey(key: string): { license: string, project: string | null } | null {
  const m = LICENSE_KEY_RE.exec(key)
  if (!m) return null
  return { license: m[1]!, project: m[2] === NO_PROJECT_LICENSE ? null : m[2]! }
}

/** Licences courantes et sans surprise : une licence hors de cette liste est « inhabituelle ». */
export const COMMON_LICENSES = new Set([
  'MIT', 'MIT-0', 'Apache-2.0', 'BSD-2-Clause', 'BSD-3-Clause', 'ISC', '0BSD', 'Unlicense', 'CC0-1.0',
  'Zlib', 'BSL-1.0', 'Python-2.0', 'PSF-2.0', 'BlueOak-1.0.0',
])

export const COMPATIBILITY = ['compatible', 'conditional', 'incompatible', 'unknown'] as const

export interface LicenseInput {
  license: string
  project_license: string | null
}

export const LicenseOutput = z.strictObject({
  summary: z.string().min(1).max(600),
  obligations: z.array(z.string().min(1).max(300)).max(8),
  compatibility: z.enum(COMPATIBILITY),
  compatibility_note: z.string().min(1).max(600),
  to_check: z.array(z.string().min(1).max(300)).max(8),
})
export type LicenseOutput = z.infer<typeof LicenseOutput>

export const explainLicense: TaskDefinition<LicenseInput, LicenseOutput> = {
  kind: 'explain-license',
  subjectType: 'license',
  projectScoped: false,
  subjectPattern: LICENSE_KEY_RE,
  timeoutMs: 120_000,
  async load(db, ctx) {
    const k = parseLicenseKey(ctx.subjectId)
    if (!k) return null
    // Seulement pour une licence réellement rencontrée dans un projet qui accepte l'IA
    // et qui déclare cette licence de projet : aucun identifiant d'un projet exclu ne sort.
    const { rows } = await db.query(
      `SELECT 1 FROM projects p
        WHERE NOT p.ai_opt_out AND p.archived_at IS NULL
          AND COALESCE(NULLIF(btrim(p.spdx_license), ''), $2) = $3
          AND EXISTS (SELECT 1 FROM sbom_components c WHERE c.project_id = p.id AND $1 = ANY (c.licenses))
        LIMIT 1`,
      [k.license, 'none', k.project ?? 'none'],
    )
    if (!rows.length) return null
    return { license: k.license, project_license: k.project }
  },
  instruction: locale => locale === 'fr'
    ? 'Explique cette licence de composant à une équipe de développement, sans donner d\'avis juridique : summary (une ou deux phrases), obligations (obligations principales quand on redistribue ou qu\'on fournit le logiciel par le réseau), compatibility (compatible, conditional, incompatible, ou unknown si la licence du projet est absente ou inconnue) et compatibility_note (avec la licence du projet project_license), to_check (conditions d\'usage à faire vérifier). Si tu ne connais pas la licence, dis-le et réponds unknown.'
    : 'Explain this component licence to a development team, without giving legal advice: summary (one or two sentences), obligations (main obligations when redistributing the software or providing it over a network), compatibility (compatible, conditional, incompatible, or unknown when the project licence is missing or unknown) and compatibility_note (with the project licence project_license), to_check (conditions of use to have checked). If you do not know the licence, say so and answer unknown.',
  jsonSchema: {
    type: 'object',
    additionalProperties: false,
    required: ['summary', 'obligations', 'compatibility', 'compatibility_note', 'to_check'],
    properties: {
      summary: text(600),
      obligations: { type: 'array', maxItems: 8, items: text(300) },
      compatibility: oneOf(COMPATIBILITY),
      compatibility_note: text(600),
      to_check: { type: 'array', maxItems: 8, items: text(300) },
    },
  },
  output: LicenseOutput,
  finalize: (out, input) => ({
    summary: sanitizeText(out.summary, 600),
    obligations: out.obligations.map(o => sanitizeText(o, 300)),
    // Sans licence de projet déclarée, aucune compatibilité n'est affirmée.
    compatibility: input.project_license ? out.compatibility : 'unknown',
    compatibility_note: sanitizeText(out.compatibility_note, 600),
    to_check: out.to_check.map(o => sanitizeText(o, 300)),
  }),
}
