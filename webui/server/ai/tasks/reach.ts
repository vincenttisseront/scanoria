// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// I11, atteignabilité assistée (assess-reachability) : pour une vulnérabilité
// de dépendance, avis argumenté « appel probable / improbable / indéterminé »
// à partir des emplacements trouvés par le module reach-index (imports et
// appels du composant, relevés SANS RIEN EXÉCUTER), joints par la console
// dans ai_tasks.context (extraits masqués, 16 Ko au plus : server/ai/reach.ts et reach-context.ts).
//
// Garde-fou (CLAUDE.md § 3.5) : l'avis ne lève jamais un blocage, ne change
// ni la gravité ni le statut, et n'entre pas dans le verdict. Il s'affiche à
// côté de la priorité (EPSS, KEV) et servira à la rédaction VEX (I10, 0.7).
// Un avis tranché doit citer un emplacement des données, sinon il redevient
// « indéterminé » ; « improbable » n'est permis que si l'index couvre le
// langage du composant et n'a pas été tronqué.

import { z } from 'zod'
import { redactText } from '../redact'
import { sanitizeText } from '../sanitize'
import { findingRow, oneOf, pickPackage, text, type TaskDefinition } from '../task-kit'
import { ecosystemLanguages, ReachContext } from '../reach-context'

export const REACHABILITY = ['probable', 'improbable', 'indeterminate'] as const

export interface ReachLocation {
  ref: number
  kind: 'import' | 'call'
  path: string
  line: number
  symbol: string
  module: string
  excerpt: string
}

export interface ReachInput {
  vulnerability: {
    tool: string
    rule_id: string
    title: string
    severity: string
    vuln_ids: string[]
    package: ReturnType<typeof pickPackage>
  }
  /** Fonctions ou symboles vulnérables, quand l'avis les donne. */
  symbols: string[]
  index: { languages: string[], files: number, truncated: boolean, covers_ecosystem: boolean }
  locations: ReachLocation[]
}

export const ReachOutput = z.strictObject({
  reachability: z.enum(REACHABILITY),
  summary: z.string().min(1).max(800),
  reasons: z.array(z.strictObject({
    ref: z.number().int().min(0).max(1000),
    explanation: z.string().min(1).max(400),
  })).max(8),
  // Ajoutés par finalize : jamais repris du modèle.
  downgraded: z.boolean().optional(),
  cited: z.array(z.strictObject({
    ref: z.number().int(),
    kind: z.enum(['import', 'call']),
    path: z.string(),
    line: z.number().int(),
    symbol: z.string(),
  })).optional(),
})
export type ReachOutput = z.infer<typeof ReachOutput>

/** Résultat éligible : vulnérabilité d'un composant (catégorie SCA, composant nommé). */
export function isDependencyVuln(f: { category?: unknown, package?: unknown, vuln_ids?: unknown }): boolean {
  const pkg = pickPackage(f.package)
  return f.category === 'sca' && !!pkg?.name && Array.isArray(f.vuln_ids) && f.vuln_ids.length > 0
}

export const assessReachability: TaskDefinition<ReachInput, ReachOutput> = {
  kind: 'assess-reachability',
  subjectType: 'finding',
  timeoutMs: 180_000,
  async load(db, ctx) {
    const f = await findingRow(db, ctx)
    if (!f || !isDependencyVuln(f)) return null
    const parsed = ReachContext.safeParse(ctx.context)
    // Sans index joint, rien à évaluer : la tâche n'est pas déposée (enqueue), ni lancée ici.
    if (!parsed.success) return null
    const c = parsed.data
    const pkg = pickPackage(f.package)
    const langs = ecosystemLanguages(pkg?.ecosystem)
    return {
      vulnerability: {
        tool: String(f.tool).slice(0, 100),
        rule_id: String(f.rule_id).slice(0, 255),
        title: redactText(String(f.title)).text.slice(0, 500),
        severity: String(f.severity),
        vuln_ids: (f.vuln_ids as string[]).slice(0, 20),
        package: pkg,
      },
      symbols: c.symbols,
      index: {
        languages: c.index.languages,
        files: c.index.files,
        truncated: c.index.truncated,
        covers_ecosystem: langs.length > 0 && langs.some(l => (c.index.languages as string[]).includes(l)),
      },
      // Remasqué à la lecture (le contexte l'est déjà à l'écriture).
      locations: c.locations.map((l, i) => ({ ref: i + 1, ...l, excerpt: redactText(l.excerpt).text })),
    }
  },
  instruction: locale => locale === 'fr'
    ? 'Évalue si le code de ce dépôt appelle probablement la partie vulnérable de ce composant, d\'après les emplacements fournis (imports et appels relevés sans exécution) : reachability (probable, improbable ou indeterminate), summary (deux phrases au plus), reasons (chaque raison cite un emplacement par son numéro ref ; ref 0 pour une raison générale). Si les emplacements ne suffisent pas, réponds indeterminate. N\'invente aucun emplacement.'
    : 'Assess whether the code of this repository probably calls the vulnerable part of this component, from the provided locations (imports and calls found without execution): reachability (probable, improbable or indeterminate), summary (two sentences at most), reasons (each reason cites a location by its ref number; ref 0 for a general reason). If the locations are not enough, answer indeterminate. Do not invent any location.',
  jsonSchema: {
    type: 'object',
    additionalProperties: false,
    required: ['reachability', 'summary', 'reasons'],
    properties: {
      reachability: oneOf(REACHABILITY),
      summary: text(800),
      reasons: {
        type: 'array',
        maxItems: 8,
        items: {
          type: 'object',
          additionalProperties: false,
          required: ['ref', 'explanation'],
          properties: { ref: { type: 'integer', minimum: 0, maximum: 1000 }, explanation: text(400) },
        },
      },
    },
  },
  output: ReachOutput,
  finalize(out, input) {
    const byRef = new Map(input.locations.map(l => [l.ref, l]))
    const reasons = out.reasons
      .filter(r => r.ref === 0 || byRef.has(r.ref))
      .map(r => ({ ref: r.ref, explanation: sanitizeText(r.explanation, 400) }))
    const citedRefs = [...new Set(reasons.map(r => r.ref).filter(r => r > 0))]
    let reachability = out.reachability
    // « Probable » sans emplacement cité, ou « improbable » sur un index qui ne
    // couvre pas le langage ou a été tronqué : redevient « indéterminé ».
    const unsupported = (reachability === 'probable' && citedRefs.length === 0)
      || (reachability === 'improbable' && (input.index.truncated || !input.index.covers_ecosystem))
    if (unsupported) reachability = 'indeterminate'
    return {
      reachability,
      summary: sanitizeText(out.summary, 800),
      reasons,
      downgraded: unsupported,
      cited: citedRefs.map((r) => {
        const l = byRef.get(r)!
        return { ref: r, kind: l.kind, path: l.path, line: l.line, symbol: l.symbol }
      }),
    }
  },
}
