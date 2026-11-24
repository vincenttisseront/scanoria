// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Délais d'exécution (0.6, chantier C) côté worker : préchargement des images
// demandé après une image absente (V1), une seule demande à la fois ; liste des
// projets publiée pour le runner (miroirs Git et caches des projets retirés).

import { mkdir, mkdtemp, readFile, readdir, rm, stat } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { LIVE_PROJECTS_FILE, PREFETCH_EVERY_MS, needsPrefetch, publishLiveProjects, requestPrefetch } from '../../server/scans/execution'
import type { Queryable } from '../../server/utils/db'

let dir: string
beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), 'scanoria-exec-'))
  await mkdir(join(dir, 'requests', 'tmp'), { recursive: true, mode: 0o700 })
  await mkdir(join(dir, 'requests', 'incoming'), { recursive: true, mode: 0o700 })
})
afterEach(async () => {
  await rm(dir, { recursive: true, force: true })
})

interface Call { sql: string, params: unknown[] }
function fakeDb(pending: number, projects: string[] = []): Queryable & { calls: Call[] } {
  const calls: Call[] = []
  return {
    calls,
    async query(sql: string, params: unknown[] = []) {
      calls.push({ sql, params })
      if (sql.includes('count(*)')) return { rows: [{ n: pending }], rowCount: 1 }
      if (sql.includes('FROM projects')) return { rows: projects.map(id => ({ id })), rowCount: projects.length }
      return { rows: [], rowCount: 1 }
    },
  } as unknown as Queryable & { calls: Call[] }
}

const err = (code: string) => ({ code, class: 'infra' as const, message: 'x' })

describe('V1 : préchargement des images', () => {
  it('needsPrefetch : image absente au niveau de l’analyse ou d’un module', () => {
    expect(needsPrefetch({ error: err('E_IMAGE_MISSING'), modules: [] })).toBe(true)
    expect(needsPrefetch({ error: null, modules: [{ error: err('E_IMAGE_MISSING') }, { error: null }] } as never)).toBe(true)
    expect(needsPrefetch({ error: err('E_OOM'), modules: [{ error: err('E_TIMEOUT') }] } as never)).toBe(false)
    expect(needsPrefetch({ error: null, modules: [] })).toBe(false)
  })

  it('dépose prefetch-images sans paramètre, au nom du système', async () => {
    const db = fakeDb(0)
    const now = new Date('2026-11-24T10:00:00Z')
    const id = await requestPrefetch(db, join(dir, 'requests'), now)
    expect(id).toMatch(/^[0-9a-f-]{36}$/)
    const since = db.calls[0]!.params[0] as string
    expect(Date.parse(since)).toBe(now.getTime() - PREFETCH_EVERY_MS)
    const insert = db.calls.find(c => c.sql.includes('INSERT INTO helper_requests'))!
    expect(insert.params[1]).toBe('prefetch-images')
    expect(insert.params[3]).toBeNull()
    expect(JSON.parse(insert.params[4] as string)).toEqual({ reason: 'image-missing' })
    const files = await readdir(join(dir, 'requests', 'incoming'))
    expect(files).toHaveLength(1)
    const env = JSON.parse(await readFile(join(dir, 'requests', 'incoming', files[0]!), 'utf8'))
    expect(env).toMatchObject({ type: 'prefetch-images', params: {} })
  })

  it('une demande en cours ou récente : rien de plus', async () => {
    const db = fakeDb(1)
    expect(await requestPrefetch(db, join(dir, 'requests'))).toBeNull()
    expect(db.calls.some(c => c.sql.includes('INSERT'))).toBe(false)
    expect(await readdir(join(dir, 'requests', 'incoming'))).toHaveLength(0)
  })
})

describe('liste des projets pour le runner', () => {
  it('écrit jobs/tmp/live-projects.json en 0600, atomiquement', async () => {
    const ids = ['3f1c2a9e-7b4d-4e2a-9c1f-0a1b2c3d4e5f', '8b2d4f6a-1c3e-4a5b-8c7d-9e0f1a2b3c4d']
    const n = await publishLiveProjects(fakeDb(0, ids), join(dir, 'scans'), new Date('2026-11-24T10:00:00Z'))
    expect(n).toBe(2)
    const file = join(dir, 'scans', 'jobs', 'tmp', LIVE_PROJECTS_FILE)
    expect(JSON.parse(await readFile(file, 'utf8'))).toEqual({ schema: 1, at: '2026-11-24T10:00:00.000Z', projects: ids })
    expect((await stat(file)).mode & 0o777).toBe(0o600)
    expect((await readdir(join(dir, 'scans', 'jobs', 'tmp'))).filter(f => f.endsWith('.part'))).toEqual([])
    // Republication : le fichier est remplacé, jamais complété.
    await publishLiveProjects(fakeDb(0, []), join(dir, 'scans'))
    expect(JSON.parse(await readFile(file, 'utf8')).projects).toEqual([])
  })
})
