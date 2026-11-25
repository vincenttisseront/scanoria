// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// J12 (0.8, chantier D) : remplacement textuel borné de l'empreinte d'une
// image, fichiers piégés (binaire, géant, sans référence, empreinte mal formée).

import { describe, expect, it } from 'vitest'
import { GitopsError, MAX_FILE_BYTES, promotionBranch, replaceImageDigest } from '../../server/deploy/gitops'

const OLD = 'a'.repeat(64)
const NEW = `sha256:${'b'.repeat(64)}`
const IMG = 'registre.exemple.test/valide/app'

const code = (fn: () => unknown) => {
  try {
    fn()
  }
  catch (err) {
    return err instanceof GitopsError ? err.code : 'other'
  }
  return null
}

describe('deploy-gitops', () => {
  it('remplace seulement l\'empreinte, le reste à l\'octet près', () => {
    const yaml = `spec:\n  containers:\n    - image: ${IMG}@sha256:${OLD}\n    - image: "${IMG}:v1@sha256:${OLD}"\n    - image: autre.exemple.test/x@sha256:${OLD}\n# fin\n`
    const r = replaceImageDigest(yaml, IMG, NEW)
    expect(r).toMatchObject({ found: 2, changed: 2 })
    expect(r.content).toBe(yaml.replaceAll(`${IMG}@sha256:${OLD}`, `${IMG}@${NEW}`).replace(`${IMG}:v1@sha256:${OLD}`, `${IMG}:v1@${NEW}`))
    expect(r.content).toContain(`autre.exemple.test/x@sha256:${OLD}`)
    expect(replaceImageDigest(r.content, IMG, NEW).changed).toBe(0)
  })

  it('ne touche pas une image dont le nom n\'est qu\'un suffixe ou un préfixe', () => {
    const yaml = `a: miroir.exemple.test/${IMG}@sha256:${OLD}\nb: ${IMG}-bis@sha256:${OLD}\nc: ${IMG}/sous@sha256:${OLD}\n`
    expect(code(() => replaceImageDigest(yaml, IMG, NEW))).toBe('E_DEPLOY_GITOPS_NO_MATCH')
  })

  it('refuse empreinte mal formée, binaire, fichier géant, trop de références', () => {
    const yaml = `image: ${IMG}@sha256:${OLD}\n`
    expect(code(() => replaceImageDigest(yaml, IMG, 'sha256:xyz'))).toBe('E_DEPLOY_GITOPS_DIGEST')
    expect(code(() => replaceImageDigest(yaml, IMG, `${NEW}\n`))).toBe('E_DEPLOY_GITOPS_DIGEST')
    expect(code(() => replaceImageDigest(`${yaml}\0`, IMG, NEW))).toBe('E_DEPLOY_GITOPS_BINARY')
    expect(code(() => replaceImageDigest(yaml + 'x'.repeat(MAX_FILE_BYTES), IMG, NEW))).toBe('E_DEPLOY_GITOPS_TOO_LARGE')
    expect(code(() => replaceImageDigest(yaml.repeat(101), IMG, NEW))).toBe('E_DEPLOY_GITOPS_TOO_MANY')
    expect(code(() => replaceImageDigest(`image: ${IMG}:latest\n`, IMG, NEW))).toBe('E_DEPLOY_GITOPS_NO_MATCH')
  })

  it('caractères spéciaux du nom d\'image traités littéralement', () => {
    expect(code(() => replaceImageDigest(`image: registreXexemple.test/valide/app@sha256:${OLD}`, IMG, NEW))).toBe('E_DEPLOY_GITOPS_NO_MATCH')
  })

  it('branche de promotion déterministe', () => {
    expect(promotionBranch('production', '0b7c2f0e-9a4d')).toBe('scanoria/promote/production-0b7c2f0e')
  })
})
