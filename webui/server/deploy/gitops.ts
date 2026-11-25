// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// J12 (0.8, chantier D) : remplacement textuel borné de l'empreinte d'une
// image dans un fichier de déploiement (manifeste Kubernetes, kustomization,
// valeurs Helm…). Aucun outil du dépôt n'est exécuté : seules les références
// « <image>[:<étiquette>]@sha256:<hex> » déjà présentes voient leur empreinte
// changer, le reste du fichier est conservé à l'octet près.

export const MAX_FILE_BYTES = 256 * 1024
export const MAX_REPLACEMENTS = 100

export type GitopsErrorCode = 'E_DEPLOY_GITOPS_BINARY' | 'E_DEPLOY_GITOPS_TOO_LARGE' | 'E_DEPLOY_GITOPS_NO_MATCH' | 'E_DEPLOY_GITOPS_DIGEST' | 'E_DEPLOY_GITOPS_TOO_MANY'

export class GitopsError extends Error {
  constructor(public readonly code: GitopsErrorCode) {
    super(code)
    this.name = 'GitopsError'
  }
}

const DIGEST_RE = /^sha256:[0-9a-f]{64}$/

function escapeRe(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
}

/**
 * Remplace l'empreinte de chaque référence à `image` par `digest`. Rend le
 * nouveau contenu et le nombre de références changées (0 si l'empreinte est
 * déjà la bonne partout). Lève si le fichier est binaire, trop gros, ne
 * contient aucune référence épinglée à cette image ou en contient trop.
 */
export function replaceImageDigest(content: string, image: string, digest: string): { content: string, changed: number, found: number } {
  if (!DIGEST_RE.test(digest)) throw new GitopsError('E_DEPLOY_GITOPS_DIGEST')
  if (Buffer.byteLength(content, 'utf8') > MAX_FILE_BYTES) throw new GitopsError('E_DEPLOY_GITOPS_TOO_LARGE')
  if (content.includes('\0')) throw new GitopsError('E_DEPLOY_GITOPS_BINARY')
  const hex = digest.slice(7)
  // Frontières : l'image n'est pas le suffixe d'un autre nom (« x/app » dans
  // « y/x/app »), ni suivie d'un autre segment de chemin.
  const re = new RegExp(`(^|[\\s"'=,\\[(])(${escapeRe(image)}(?::[A-Za-z0-9_][A-Za-z0-9._-]{0,127})?@sha256:)([0-9a-f]{64})(?![0-9a-f])`, 'gm')
  let found = 0
  let changed = 0
  const out = content.replace(re, (_m, pre: string, ref: string, old: string) => {
    found++
    if (old !== hex) changed++
    return `${pre}${ref}${hex}`
  })
  if (!found) throw new GitopsError('E_DEPLOY_GITOPS_NO_MATCH')
  if (found > MAX_REPLACEMENTS) throw new GitopsError('E_DEPLOY_GITOPS_TOO_MANY')
  return { content: out, changed, found }
}

/** Nom de branche de promotion : scanoria/promote/<environnement>-<empreinte courte>. */
export function promotionBranch(environment: string, scanId: string): string {
  return `scanoria/promote/${environment}-${scanId.slice(0, 8)}`
}
