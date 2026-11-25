// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Chantier B (0.8) : H7, panneau VEX de la page d'un projet. Déclarations en
// vigueur, liens d'export, import avec aperçu puis confirmation (modale de
// la console), erreurs de format traduites, lecture seule pour un lecteur.

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { enableAutoUnmount } from '@vue/test-utils'
import { mockNuxtImport } from '@nuxt/test-utils/runtime'
import { createError } from 'h3'
import { apiFail, bodyText, button, callsTo, clearBody, click, mountIn, resetApi, route, setLocale, settle, setUser } from './helpers'
import VexProjectPanel from '~/components/vex/ProjectPanel.vue'

const { toastAdd } = vi.hoisted(() => ({ toastAdd: vi.fn() }))
mockNuxtImport('useToast', () => () => ({ add: toastAdd }))

enableAutoUnmount(afterEach)

const PROJECT = '33333333-3333-4333-8333-333333333333'
const SHA = 'c'.repeat(64)
const statements = [
  { vuln_id: 'CVE-2026-0001', product: 'pkg:npm/lodash@4.17.20', status: 'not_affected', justification: 'vulnerable_code_not_in_execute_path', impact_statement: null, timestamp: '2026-11-25T08:00:00Z' },
  { vuln_id: 'CVE-2026-0002', product: 'pkg:npm/minimist@1.2.0', status: 'affected', justification: null, impact_statement: null, timestamp: '2026-11-25T08:00:00Z' },
]
const doc = JSON.stringify({ '@context': 'https://openvex.dev/ns/v0.2.0', 'statements': [] })

beforeEach(async () => {
  await setLocale('fr')
  toastAdd.mockReset()
})
afterEach(() => {
  resetApi()
  clearBody()
})

async function typeDocument(text: string) {
  const area = document.body.querySelector<HTMLTextAreaElement>('textarea')!
  area.value = text
  area.dispatchEvent(new Event('input'))
  await settle()
}

describe('H7 : panneau VEX', () => {
  it('déclarations et liens d’export ; import : aperçu puis confirmation', async () => {
    setUser('operator')
    route('GET', `/api/vex/projects/${PROJECT}/statements`, () => ({ sha256: SHA, statements }))
    route('POST', `/api/vex/projects/${PROJECT}/import`, (_e, body) => {
      const dry = (body as { dry_run: boolean }).dry_run
      return {
        format: 'openvex', dry_run: dry,
        effects: [
          { vuln_id: 'CVE-2026-0003', product: 'pkg:npm/a@1', status: 'not_affected', justification: null, action: 'request' },
          { vuln_id: 'MAL-2026-1', product: 'pkg:npm/b@1', status: 'not_affected', justification: null, action: 'refused', reason: 'malicious' },
        ],
        counts: { request: 1, store: 0, duplicate: 0, refused: 1 },
      }
    })
    await mountIn(VexProjectPanel, { props: { projectId: PROJECT } })
    await settle()
    const text = bodyText()
    expect(text).toContain('CVE-2026-0001')
    expect(text).toContain('non concerné')
    expect(text).toContain('code vulnérable jamais exécuté')
    expect(text).toContain('concerné')
    expect(text).toContain(SHA)
    expect(document.body.querySelector('[data-testid="vex-export-openvex"]')!.getAttribute('href')).toBe(`/api/vex/projects/${PROJECT}/export?format=openvex`)

    await click(document.body.querySelector('[data-testid="vex-import"]')!)
    const confirm = () => document.body.querySelector<HTMLButtonElement>('[data-testid="vex-import-confirm"]')!
    expect(confirm().disabled).toBe(true)
    await typeDocument(doc)
    await click(document.body.querySelector('[data-testid="vex-preview-button"]')!)
    expect(callsTo('POST', `/api/vex/projects/${PROJECT}/import`)[0]!.body).toEqual({ document: doc, dry_run: true })
    const preview = document.body.querySelector('[data-testid="vex-preview"]')!.textContent!
    expect(preview).toContain('1 demande(s) d’exception')
    expect(preview).toContain('paquet malveillant, aucune exception possible')
    expect(confirm().disabled).toBe(false)
    await click(confirm())
    expect(callsTo('POST', `/api/vex/projects/${PROJECT}/import`)[1]!.body).toEqual({ document: doc, dry_run: false })
    expect(toastAdd).toHaveBeenCalledWith(expect.objectContaining({ title: 'Import terminé : 1 demande(s) d’exception créée(s).' }))
    expect(callsTo('GET', `/api/vex/projects/${PROJECT}/statements`)).toHaveLength(2)
  })

  it('document invalide : erreur de format traduite', async () => {
    setUser('operator')
    route('GET', `/api/vex/projects/${PROJECT}/statements`, () => ({ sha256: SHA, statements: [] }))
    route('POST', `/api/vex/projects/${PROJECT}/import`, () => {
      throw createError({ statusCode: 400, statusMessage: 'E_VALIDATION', data: { code: 'E_VALIDATION', reason: 'E_VEX_FORMAT', field: null } })
    })
    await mountIn(VexProjectPanel, { props: { projectId: PROJECT } })
    await settle()
    expect(bodyText()).toContain('Aucune déclaration VEX.')
    await click(button('Importer'))
    await typeDocument('{"x": 1}')
    await click(document.body.querySelector('[data-testid="vex-preview-button"]')!)
    expect(bodyText()).toContain('Format non reconnu : OpenVEX 0.2 ou CycloneDX VEX attendu.')
  })

  it('lecteur : pas d’import ; erreur de chargement affichée', async () => {
    setUser('viewer')
    route('GET', `/api/vex/projects/${PROJECT}/statements`, () => apiFail(500, 'E_INTERNAL'))
    await mountIn(VexProjectPanel, { props: { projectId: PROJECT } })
    await settle()
    expect(document.body.querySelector('[data-testid="vex-import"]')).toBeNull()
    expect(bodyText()).toContain('Erreur interne de la console.')
  })
})
