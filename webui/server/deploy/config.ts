// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// J11–J13 (0.8, chantier D) : configuration d'une cible de déploiement
// (deploy_targets.config, 64 Kio au plus en base). Tout est validé ici, à
// l'enregistrement ET à chaque exécution : une ligne modifiée en base ne
// contourne aucun contrôle. Aucun chemin absolu, aucun « .. », aucun schéma
// autre que https, aucune adresse de bouclage.

import { isIP } from 'node:net'
import { z } from 'zod'
import { WORKFLOW_RE } from '../forges/deploy'
import { isSafeRef } from '../forges/types'

export const DEPLOY_KINDS = ['cd-trigger', 'gitops-pr', 'registry-promotion'] as const
export type DeployKind = (typeof DEPLOY_KINDS)[number]

const FULL_NAME_RE = /^[A-Za-z0-9._-]+(\/[A-Za-z0-9._-]+)+$/
const IMAGE_REPO_RE = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+(:\d{1,5})?(\/[a-z0-9]+([._-][a-z0-9]+)*){1,10}$/
const JENKINS_JOB_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,99}(\/[A-Za-z0-9][A-Za-z0-9._-]{0,99}){0,9}$/
const TEMPLATE_RE = /^[A-Za-z0-9._{}-]{1,128}$/
const LOOPBACK_RE = /^(localhost|.+\.localhost|127\.\d+\.\d+\.\d+|0\.0\.0\.0|\[::1?\]|169\.254\.\d+\.\d+)$/i

/** Entrées passées au workflow (J11) ; documentées dans docs/DEPLOIEMENT.md. */
export const CD_INPUTS = ['scanoria_report', 'scanoria_commit', 'scanoria_tag', 'scanoria_image'] as const
export type CdInput = (typeof CD_INPUTS)[number]

const fullName = z.string().max(300).regex(FULL_NAME_RE).refine(s => !s.split('/').some(x => x === '.' || x === '..'), { message: 'path' })
const gitRef = z.string().max(255).refine(isSafeRef, { message: 'ref' })
/**
 * Registres et Jenkins sont désignés par leur nom, jamais par une adresse
 * littérale : le transport résout le nom et refuse les adresses interdites
 * (bouclage, appliance) ; une adresse écrite en dur contournerait ce contrôle.
 */
const isIpLiteral = (host: string) => isIP(host.replace(/^\[|\]$/g, '')) !== 0
const imageRepo = z.string().max(300).regex(IMAGE_REPO_RE).refine(r => !isIpLiteral(r.split('/')[0]!.replace(/:\d+$/, '')), { message: 'address' })
/** Branche configurée d'une cible « branch » (on_trigger) ; ignorée pour une release. */
const branchField = gitRef.optional()

/** Chemin relatif dans un dépôt : sans « .. », sans « / » initial, sans contrôle. */
export const repoPath = z.string().min(1).max(512).refine(p => !p.startsWith('/') && !p.includes('\\') && !p.includes('\0')
  // eslint-disable-next-line no-control-regex
  && !/[\u0000-\u001F]/.test(p) && !p.split('/').some(s => s === '' || s === '.' || s === '..'), { message: 'path' })

const httpsBase = z.string().max(300).refine((s) => {
  try {
    const u = new URL(s)
    return u.protocol === 'https:' && !u.username && !u.password && !u.search && !u.hash && !LOOPBACK_RE.test(u.hostname) && !isIpLiteral(u.hostname)
  }
  catch {
    return false
  }
}, { message: 'url' })

/** Gabarit d'étiquette : {tag}, {commit}, {short_commit} et caractères d'étiquette OCI. */
const tagTemplate = z.string().regex(TEMPLATE_RE).refine(t => (t.match(/\{[^}]*\}/g) ?? []).every(x => ['{tag}', '{commit}', '{short_commit}'].includes(x)), { message: 'template' })

export const cdTriggerConfig = z.discriminatedUnion('provider', [
  z.strictObject({
    provider: z.literal('forge'),
    /** Dépôt du workflow ; défaut : celui du projet. */
    repo: fullName.optional(),
    /** Fichier du workflow (.forgejo/workflows ou .github/workflows) ; ignoré par GitLab. */
    workflow: z.string().regex(WORKFLOW_RE),
    /** Référence lancée ; défaut : le tag de la release, ou la branche analysée. */
    ref: gitRef.optional(),
    inputs: z.array(z.enum(CD_INPUTS)).max(CD_INPUTS.length).default(['scanoria_report', 'scanoria_commit', 'scanoria_tag']),
    branch: branchField,
  }),
  z.strictObject({
    provider: z.literal('jenkins'),
    url: httpsBase,
    job: z.string().regex(JENKINS_JOB_RE),
    inputs: z.array(z.enum(CD_INPUTS)).max(CD_INPUTS.length).default(['scanoria_report', 'scanoria_commit', 'scanoria_tag']),
    branch: branchField,
  }),
])

export const gitopsConfig = z.strictObject({
  /** Dépôt de déploiement (Argo CD, Flux), sur la forge du projet. */
  repo: fullName,
  base: gitRef.default('main'),
  /** Fichiers et image dont l'empreinte est remplacée (modification textuelle bornée). */
  files: z.array(z.strictObject({ path: repoPath, image: imageRepo })).min(1).max(20),
  branch: branchField,
})

export const registryConfig = z.strictObject({
  /** Dépôt « candidat » où la CI a poussé l'image. */
  source: imageRepo,
  /** Étiquette de la candidate dans la source ; défaut « {tag} » (la release). */
  source_tag: tagTemplate.default('{tag}'),
  /** Dépôt « validé ». Même registre ou un autre. */
  destination: imageRepo,
  /** Étiquette posée en plus dans la destination (mêmes octets) ; null : empreinte seule. */
  destination_tag: tagTemplate.nullable().default('{tag}'),
  branch: branchField,
}).refine(c => c.source !== c.destination, { message: 'same' })

export type CdTriggerConfig = z.infer<typeof cdTriggerConfig>
export type GitopsConfig = z.infer<typeof gitopsConfig>
export type RegistryConfig = z.infer<typeof registryConfig>
export type TargetConfig = CdTriggerConfig | GitopsConfig | RegistryConfig

export function configSchema(kind: DeployKind) {
  switch (kind) {
    case 'cd-trigger': return cdTriggerConfig
    case 'gitops-pr': return gitopsConfig
    case 'registry-promotion': return registryConfig
  }
}

/** Valide une configuration ; null si invalide (relue à chaque exécution). */
export function parseConfig(kind: DeployKind, raw: unknown): TargetConfig | null {
  const r = configSchema(kind).safeParse(raw)
  return r.success ? r.data : null
}

/** Remplit un gabarit d'étiquette ; null si le résultat n'est pas une étiquette OCI valide. */
export function fillTemplate(template: string, v: { tag: string | null, commit: string }): string | null {
  if (template.includes('{tag}') && !v.tag) return null
  const out = template.replaceAll('{tag}', v.tag ?? '').replaceAll('{commit}', v.commit).replaceAll('{short_commit}', v.commit.slice(0, 12))
  return /^[A-Za-z0-9_][A-Za-z0-9._-]{0,127}$/.test(out) ? out : null
}

export const ENVIRONMENT_RE = /^[a-z0-9][a-z0-9-]{0,39}$/

export const targetCreateSchema = z.strictObject({
  kind: z.enum(DEPLOY_KINDS),
  environment: z.string().regex(ENVIRONMENT_RE),
  on_trigger: z.enum(['release', 'branch']).default('release'),
  config: z.record(z.string(), z.unknown()),
  /** Jeton deploy-token (Jenkins, déclencheur GitLab) ou registry-token (J13). */
  credential: z.strictObject({ username: z.string().max(200).optional(), value: z.string().min(8).max(8192) }).optional(),
  enabled: z.boolean().default(true),
})

export const targetUpdateSchema = z.strictObject({
  enabled: z.boolean().optional(),
  config: z.record(z.string(), z.unknown()).optional(),
  credential: z.strictObject({ username: z.string().max(200).optional(), value: z.string().min(8).max(8192) }).optional(),
  /** J12 : fusion automatique de la forge autorisée par un administrateur (GitOps seulement). */
  auto_merge: z.boolean().optional(),
})
