// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// I16 (0.6), diagnostic de l'appliance (diagnose-appliance) : explique en
// clair une alerte de santé, un échec de scanoria-selftest, d'une mise à jour
// ou de l'installation d'un module, et propose UNE action parmi celles qui
// existent dans la console. Aucune action n'est faite : la console affiche un
// lien vers la page et le bouton, la personne décide (§ 3.5).
//
// Sujet « appliance », sans projet. Le contexte vient de la console
// (server/ai/appliance.ts), masqué et neutralisé ; il est revalidé ici,
// masqué et neutralisé de nouveau (adresses, adresses de messagerie, noms
// internes). Aucun secret de la console n'y figure jamais : la console ne lit
// que l'état publié, les demandes au service root (paramètres déjà expurgés)
// et l'historique des mises à jour.

import { z } from 'zod'
import { sanitizeText } from '../sanitize'
import { oneOf, text, type TaskDefinition } from '../task-kit'
import { APPLIANCE_SUBJECT_RE, boundApplianceContext, type ApplianceContext } from '../appliance-context'

export const APPLIANCE_CAUSES = [
  'disk', 'memory', 'network', 'dns', 'certificate', 'signature', 'service', 'health-check',
  'configuration', 'resources', 'unknown',
] as const

/**
 * Actions de la console, chacune liée à une page et à un bouton existants
 * (app/components/ai/ApplianceDiagnosis.vue). « none » : rien à faire dans la
 * console (attendre, voir l'hôte).
 */
export const APPLIANCE_ACTIONS = [
  'none', 'rerun-selftest', 'check-update', 'retry-update', 'rollback-update', 'import-update',
  'retry-install', 'update-module', 'uninstall-module', 'renew-certificate', 'check-dns',
  'check-admin-networks', 'check-ai-connector', 'view-scan-health',
] as const
export type ApplianceAction = (typeof APPLIANCE_ACTIONS)[number]

/** Actions pertinentes pour chaque sujet : une autre proposition devient « none ». */
const ACTIONS_FOR: Record<ApplianceContext['subject'], readonly ApplianceAction[]> = {
  alert: ['none', 'rerun-selftest', 'check-update', 'rollback-update', 'import-update', 'renew-certificate', 'check-dns', 'check-admin-networks', 'check-ai-connector', 'update-module', 'uninstall-module', 'view-scan-health'],
  selftest: ['none', 'rerun-selftest', 'check-update', 'rollback-update', 'renew-certificate', 'check-dns', 'check-admin-networks', 'check-ai-connector', 'update-module', 'uninstall-module'],
  update: ['none', 'check-update', 'retry-update', 'rollback-update', 'import-update', 'rerun-selftest'],
  install: ['none', 'retry-install', 'update-module', 'uninstall-module', 'check-dns', 'rerun-selftest'],
}
const MODULE_ACTIONS = new Set<ApplianceAction>(['retry-install', 'update-module', 'uninstall-module'])

export const DiagnoseApplianceOutput = z.strictObject({
  cause: z.enum(APPLIANCE_CAUSES),
  summary: z.string().min(1).max(600),
  explanation: z.string().min(1).max(1500),
  action: z.enum(APPLIANCE_ACTIONS),
  action_reason: z.string().min(1).max(300),
  steps: z.array(z.string().min(1).max(300)).max(5),
  /** Ajouté après validation, depuis le contexte (jamais du modèle). */
  subject: z.enum(['alert', 'selftest', 'update', 'install']).optional(),
  module: z.string().max(64).nullable().optional(),
})
export type DiagnoseApplianceOutput = z.infer<typeof DiagnoseApplianceOutput>

/** Action retenue : proposée par le modèle, gardée seulement si elle a un sens pour ce sujet. */
export function allowedAction(action: ApplianceAction, input: Pick<ApplianceContext, 'subject' | 'module'>): ApplianceAction {
  if (!ACTIONS_FOR[input.subject].includes(action)) return 'none'
  if (MODULE_ACTIONS.has(action) && !input.module) return 'none'
  return action
}

export const diagnoseAppliance: TaskDefinition<ApplianceContext, DiagnoseApplianceOutput> = {
  kind: 'diagnose-appliance',
  subjectType: 'appliance',
  projectScoped: false,
  subjectPattern: APPLIANCE_SUBJECT_RE,
  timeoutMs: 120_000,
  async load(_db, ctx) {
    if (!APPLIANCE_SUBJECT_RE.test(ctx.subjectId)) return null
    const c = boundApplianceContext(ctx.context)
    if (!c || !ctx.subjectId.startsWith(`${c.subject}:`)) return null
    return c
  },
  instruction: locale => locale === 'fr'
    ? 'Diagnostique ce problème de l\'appliance d\'analyse de code (alerte, contrôle de santé, mise à jour ou installation d\'un module) à partir des faits et du journal fournis : cause parmi disk, memory, network, dns, certificate, signature, service, health-check, configuration, resources, unknown ; summary (cause probable en une ou deux phrases) ; explanation (explication en clair pour un administrateur) ; action (une seule action de la console parmi none, rerun-selftest, check-update, retry-update, rollback-update, import-update, retry-install, update-module, uninstall-module, renew-certificate, check-dns, check-admin-networks, check-ai-connector, view-scan-health ; none si rien ne se règle dans la console) ; action_reason (pourquoi cette action) ; steps (au plus 5 étapes concrètes). Les jetons entre crochets ([appliance], [host-1], [addr-1]) remplacent des noms et adresses : garde-les tels quels. N\'invente aucune commande.'
    : 'Diagnose this problem of the code analysis appliance (alert, health check, update or module installation) from the provided facts and log: cause among disk, memory, network, dns, certificate, signature, service, health-check, configuration, resources, unknown; summary (probable cause in one or two sentences); explanation (plain explanation for an administrator); action (a single console action among none, rerun-selftest, check-update, retry-update, rollback-update, import-update, retry-install, update-module, uninstall-module, renew-certificate, check-dns, check-admin-networks, check-ai-connector, view-scan-health; none when nothing can be fixed from the console); action_reason (why this action); steps (at most 5 concrete steps). Tokens in brackets ([appliance], [host-1], [addr-1]) stand for names and addresses: keep them as they are. Do not invent any command.',
  jsonSchema: {
    type: 'object',
    additionalProperties: false,
    required: ['cause', 'summary', 'explanation', 'action', 'action_reason', 'steps'],
    properties: {
      cause: oneOf(APPLIANCE_CAUSES),
      summary: text(600),
      explanation: text(1500),
      action: oneOf(APPLIANCE_ACTIONS),
      action_reason: text(300),
      steps: { type: 'array', maxItems: 5, items: text(300) },
    },
  },
  output: DiagnoseApplianceOutput,
  finalize: (out, input) => ({
    cause: out.cause,
    summary: sanitizeText(out.summary, 600),
    explanation: sanitizeText(out.explanation, 1500),
    action: allowedAction(out.action, input),
    action_reason: sanitizeText(out.action_reason, 300),
    steps: out.steps.map(s => sanitizeText(s, 300)),
    subject: input.subject,
    module: input.module,
  }),
}
