// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// J6 (0.6) : lecture bornée du corps, JSON, détection du format et de l'outil,
// identifiant de module ext-<slug>. L'ingestion complète est testée contre
// PostgreSQL dans tests/integration/external-api.test.ts.

import { Readable } from 'node:stream'
import { describe, expect, it } from 'vitest'
import { ExternalError, detectDocument, externalModuleId, parseJson, readBoundedBody } from '../../server/external/ingest'

const fail = (fn: () => unknown): ExternalError => {
  try {
    fn()
  }
  catch (err) {
    expect(err).toBeInstanceOf(ExternalError)
    return err as ExternalError
  }
  throw new Error('aucune erreur')
}

describe('externalModuleId', () => {
  it('nom d\'outil → ext-<slug> borné', () => {
    expect(externalModuleId('Acme SAST')).toBe('ext-acme-sast')
    expect(externalModuleId('Équipe Sécurité 2.0')).toBe('ext-equipe-securite-2-0')
    expect(externalModuleId('  --Tool--  ')).toBe('ext-tool')
    expect(externalModuleId('x'.repeat(100))).toBe(`ext-${'x'.repeat(36)}`)
    expect(externalModuleId('!!!')).toBeNull()
  })
})

describe('parseJson', () => {
  it('BOM toléré, vide et invalide refusés', () => {
    expect(parseJson(Buffer.from('﻿{"a":1}'))).toEqual({ a: 1 })
    expect(fail(() => parseJson(Buffer.alloc(0)))).toMatchObject({ code: 'E_EXTERNAL_JSON', status: 400 })
    expect(fail(() => parseJson(Buffer.from('{"a":')))).toMatchObject({ code: 'E_EXTERNAL_JSON' })
  })
})

describe('readBoundedBody', () => {
  it('lit un flux sous la limite, refuse au-delà ou sur longueur annoncée', async () => {
    expect((await readBoundedBody(Readable.from([Buffer.from('ab'), 'cd']), null, 10)).toString()).toBe('abcd')
    await expect(readBoundedBody(Readable.from([Buffer.alloc(6), Buffer.alloc(6)]), null, 10)).rejects.toMatchObject({ code: 'E_EXTERNAL_TOO_LARGE', status: 413 })
    await expect(readBoundedBody(Readable.from([]), 11, 10)).rejects.toMatchObject({ code: 'E_EXTERNAL_TOO_LARGE' })
    const broken = new Readable({
      read() {
        this.destroy(new Error('coupé'))
      },
    })
    await expect(readBoundedBody(broken, null, 10)).rejects.toMatchObject({ code: 'E_EXTERNAL_UPLOAD' })
  })
})

describe('detectDocument', () => {
  const run = (name: string, results: unknown[] = []) => ({ tool: { driver: { name, version: '1.2' } }, results })
  it('SARIF : outil, version, surcharge', () => {
    expect(detectDocument({ version: '2.1.0', runs: [run('Tool')] })).toEqual({ source: { format: 'sarif', formatVersion: '2.1.0', tool: 'Tool', version: '1.2' }, issues: [] })
    expect(detectDocument({ version: '2.1.0', runs: [run('Tool')] }, { tool: 'Autre', version: '3' }).source).toMatchObject({ tool: 'Autre', version: '3' })
    expect(detectDocument({ version: '2.1.0', runs: [run('A'), run('a')] }).issues).toEqual([])
    expect(detectDocument({ version: '2.1.0', runs: [run('A'), run('B')] }, { tool: 'C' }).issues).toEqual([])
  })
  it('SARIF : défauts de structure', () => {
    const { issues } = detectDocument({ version: '2.1.0', runs: [{ tool: {}, results: {} }, run('B', [42, { message: {} }])] })
    expect(issues).toEqual([
      { path: '/runs/0/tool/driver/name', code: 'required' },
      { path: '/runs/0/results', code: 'not-an-array' },
      { path: '/runs/1/results/0', code: 'not-an-object' },
      { path: '/runs/1/results/1/message', code: 'required' },
    ])
    expect(detectDocument({ version: '2.1.0', runs: Array.from({ length: 33 }, () => run('A')) }).issues[0]).toMatchObject({ code: 'too-many' })
    expect(detectDocument({ $schema: 'https://example.test/sarif.json' }).issues).toEqual(expect.arrayContaining([{ path: '/version', code: 'unsupported-version', detail: 'absent' }, { path: '/runs', code: 'required' }]))
  })
  it('CycloneDX : versions, outils (forme 1.5 et forme héritée), vulnérabilités', () => {
    const cdx = (extra: Record<string, unknown>) => ({ bomFormat: 'CycloneDX', specVersion: '1.5', ...extra })
    expect(detectDocument(cdx({ metadata: { tools: [{ name: 'Old', version: '1' }] } })).source).toMatchObject({ format: 'cyclonedx', tool: 'Old', version: '1' })
    expect(detectDocument(cdx({ metadata: { tools: { services: [{ name: 'Svc' }] } } })).source.tool).toBe('Svc')
    expect(detectDocument(cdx({})).source.tool).toBe('cyclonedx')
    expect(detectDocument(cdx({ specVersion: '1.4' })).issues[0]).toMatchObject({ code: 'unsupported-version', detail: '1.4' })
    expect(detectDocument(cdx({ components: {}, vulnerabilities: {} })).issues.map(i => i.code)).toEqual(['not-an-array', 'not-an-array'])
    expect(detectDocument(cdx({ vulnerabilities: [{ id: 'CVE-1' }, {}] })).issues).toEqual([{ path: '/vulnerabilities/1/id', code: 'required' }])
  })
  it('format inconnu → 415', () => {
    expect(fail(() => detectDocument([1]))).toMatchObject({ code: 'E_EXTERNAL_FORMAT', status: 415 })
    expect(fail(() => detectDocument({ hello: 1 }))).toMatchObject({ code: 'E_EXTERNAL_FORMAT' })
  })
})
