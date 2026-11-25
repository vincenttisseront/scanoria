// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// 0.8 (A, contrat 42) : clients « release » de Forgejo, GitHub et GitLab sur
// un transport simulé : tags et releases fusionnés (pré-versions, brouillons
// ignorés, tags invalides écartés), fichiers joints (release absente, fichier
// déjà présent, 409/422, téléversement), et jamais de jeton vers un autre
// hôte que celui des téléversements de la forge.

import { afterEach, describe, expect, it } from 'vitest'
import { ForgeError, setForgeTransport } from '../../server/forges/http'
import { isSafeTag, isUploadPath, missingAssetPermission, multipartFile, releaseForge } from '../../server/forges/release'

interface Seen { method: string, url: string, auth: string | null, body: string }
const seen: Seen[] = []
const SHA1 = '1'.repeat(40)
const SHA2 = '2'.repeat(40)

type Reply = { status?: number, json?: unknown }
function transport(routes: (method: string, url: URL) => Reply | undefined) {
  setForgeTransport(async (url, init) => {
    const u = new URL(url)
    const method = (init.method ?? 'GET').toUpperCase()
    const raw = init.body
    const body = raw == null ? '' : Buffer.isBuffer(raw) ? raw.toString('utf8') : typeof raw === 'string' ? raw : Buffer.from(raw as ArrayBuffer).toString('utf8')
    const headers = new Headers(init.headers)
    seen.push({ method, url: `${u.origin}${u.pathname}${u.search}`, auth: headers.get('authorization'), body })
    const r = routes(method, u) ?? { status: 404, json: { message: 'not found' } }
    return new Response(JSON.stringify(r.json ?? {}), { status: r.status ?? 200, headers: { 'content-type': 'application/json' } })
  })
}

afterEach(() => {
  setForgeTransport()
  seen.length = 0
})

const DATA = Buffer.from('{"a":1}\n')

describe('outils', () => {
  it('tags sûrs, chemin de téléversement, droit manquant, multipart', () => {
    expect(isSafeTag('v1.2.0')).toBe(true)
    for (const bad of ['../x', 'v1/', 'a//b', 'x.lock', '-v1', 'a..b']) expect(isSafeTag(bad)).toBe(false)
    expect(isUploadPath('/repos/o/r/releases/12/assets')).toBe(true)
    expect(isUploadPath('/api/uploads/repos/o/r/releases/12/assets')).toBe(true)
    for (const bad of ['/repos/o/releases/12/assets', '/repos/o/r/releases/x/assets', '/repos/o/r/releases/12/assets/1', 'repos/o/r/releases/1/assets', '/other/o/r/releases/1/assets'])
      expect(isUploadPath(bad)).toBe(false)
    expect(missingAssetPermission('github', { contents: 'read' })).toBe('contents:write')
    expect(missingAssetPermission('github', { contents: 'write' })).toBeNull()
    expect(missingAssetPermission('github', null)).toBeNull()
    expect(missingAssetPermission('forgejo', { contents: 'read' })).toBeNull()
    const mp = multipartFile('file', 'r.json', DATA, 'application/json')
    expect(mp.contentType).toMatch(/^multipart\/form-data; boundary=scanoria-[0-9a-f]{24}$/)
    expect(mp.body.toString('utf8')).toContain('filename="r.json"')
  })

  it('forge inconnue : E_FORGE_UNSUPPORTED', () => {
    expect(() => releaseForge({ kind: 'svn' as 'forgejo', base_url: 'https://forge.exemple.test' })).toThrow(ForgeError)
  })
})

describe('GitHub', () => {
  const gh = () => releaseForge({ kind: 'github', base_url: 'https://github.com', token: 'jeton-de-test' })

  it('tags et releases fusionnés : pré-version, brouillon ignoré, tag invalide écarté', async () => {
    transport((m, u) => {
      if (u.pathname === '/repos/o/r/tags') return { json: [{ name: 'v1.0.0', commit: { sha: SHA1 } }, { name: 'v2.0.0-rc1', commit: { sha: SHA2 } }, { name: '../x', commit: { sha: SHA2 } }, { name: 'v3', commit: { sha: 'court' } }] }
      if (u.pathname === '/repos/o/r/releases') return { json: [{ tag_name: 'v2.0.0-rc1', prerelease: true }, { tag_name: 'v1.0.0', draft: true }] }
      return undefined
    })
    expect(await gh().tags('o/r')).toEqual([
      { name: 'v1.0.0', commit_sha: SHA1, release: false, prerelease: false },
      { name: 'v2.0.0-rc1', commit_sha: SHA2, release: true, prerelease: true },
    ])
    expect(seen.every(s => s.url.startsWith('https://api.github.com/'))).toBe(true)
  })

  it('fichier joint : release absente, déjà présent, téléversé vers uploads.github.com seulement', async () => {
    let assets: { name: string }[] = []
    let uploadUrl = 'https://uploads.github.com/repos/o/r/releases/7/assets{?name,label}'
    transport((m, u) => {
      if (u.pathname === '/repos/o/r/releases/tags/v1.0.0') return { json: { id: 7, upload_url: uploadUrl, assets } }
      if (m === 'POST' && u.hostname === 'uploads.github.com') return { status: 201, json: { id: 1 } }
      return undefined
    })
    expect(await gh().uploadAsset('o/r', 'v9.9.9', 'r.json', DATA, 'application/json')).toBe('no-release')
    expect(await gh().uploadAsset('o/r', 'v1.0.0', 'r.json', DATA, 'application/json')).toBe('uploaded')
    const post = seen.find(s => s.method === 'POST')!
    expect(post.url).toBe('https://uploads.github.com/repos/o/r/releases/7/assets?name=r.json')
    expect(post.body).toBe('{"a":1}\n')
    assets = [{ name: 'r.json' }]
    expect(await gh().uploadAsset('o/r', 'v1.0.0', 'r.json', DATA, 'application/json')).toBe('exists')
    assets = []
    // Adresse de téléversement fournie par la réponse, vers un autre hôte : refusée, sans envoi.
    uploadUrl = 'https://evil.exemple.test/repos/o/r/releases/7/assets'
    seen.length = 0
    await expect(gh().uploadAsset('o/r', 'v1.0.0', 'r.json', DATA, 'application/json')).rejects.toMatchObject({ code: 'E_FORGE_URL' })
    expect(seen.filter(s => s.method === 'POST')).toHaveLength(0)
    uploadUrl = ''
    await expect(gh().uploadAsset('o/r', 'v1.0.0', 'r.json', DATA, 'application/json')).rejects.toMatchObject({ code: 'E_FORGE_RESPONSE' })
    await expect(gh().uploadAsset('o/r', '../x', 'r.json', DATA, 'application/json')).rejects.toMatchObject({ code: 'E_FORGE_INPUT' })
    await expect(gh().uploadAsset('o/r', 'v1.0.0', '../r.json', DATA, 'application/json')).rejects.toMatchObject({ code: 'E_FORGE_INPUT' })
  })

  it('GitHub Enterprise : téléversement sur la même instance, conflit 422 rendu « exists »', async () => {
    transport((m, u) => {
      if (u.pathname === '/api/v3/repos/o/r/releases/tags/v1.0.0') return { json: { id: 3, upload_url: 'https://ghe.exemple.test/api/uploads/repos/o/r/releases/3/assets{?name}', assets: [] } }
      if (m === 'POST' && u.pathname === '/api/uploads/repos/o/r/releases/3/assets') return { status: 422, json: { errors: [{ code: 'already_exists' }] } }
      return undefined
    })
    const ghe = releaseForge({ kind: 'github', base_url: 'https://ghe.exemple.test', token: 'jeton-de-test' })
    expect(await ghe.uploadAsset('o/r', 'v1.0.0', 'r.json', DATA, 'application/json')).toBe('exists')
  })
})

describe('GitLab', () => {
  const gl = () => releaseForge({ kind: 'gitlab', base_url: 'https://gitlab.exemple.test', token: 'jeton-de-test' })

  it('tags (commit.id) et releases à venir', async () => {
    transport((m, u) => {
      if (u.pathname === '/api/v4/projects/g%2Fr/repository/tags') return { json: [{ name: 'v1.0.0', commit: { id: SHA1 } }] }
      if (u.pathname === '/api/v4/projects/g%2Fr/releases') return { json: [{ tag_name: 'v1.0.0', upcoming_release: true }] }
      return undefined
    })
    expect(await gl().tags('g/r')).toEqual([{ name: 'v1.0.0', commit_sha: SHA1, release: true, prerelease: true }])
  })

  it('fichier joint : téléversement puis lien de release ; déjà présent ; réponse invalide', async () => {
    let links: { name: string }[] = []
    let fullPath: unknown = '/-/project/1/uploads/abc/r.json'
    transport((m, u) => {
      if (m === 'GET' && u.pathname === '/api/v4/projects/g%2Fr/releases/v1.0.0') return { json: { assets: { links } } }
      if (m === 'POST' && u.pathname === '/api/v4/projects/g%2Fr/uploads') return { status: 201, json: { full_path: fullPath } }
      if (m === 'POST' && u.pathname === '/api/v4/projects/g%2Fr/releases/v1.0.0/assets/links') return { status: 201, json: { id: 1 } }
      return undefined
    })
    expect(await gl().uploadAsset('g/r', 'v2.0.0', 'r.json', DATA, 'application/json')).toBe('no-release')
    expect(await gl().uploadAsset('g/r', 'v1.0.0', 'r.json', DATA, 'application/json')).toBe('uploaded')
    const link = seen.find(s => s.url.endsWith('/assets/links'))!
    expect(JSON.parse(link.body)).toEqual({ name: 'r.json', url: 'https://gitlab.exemple.test/-/project/1/uploads/abc/r.json', link_type: 'other' })
    links = [{ name: 'r.json' }]
    expect(await gl().uploadAsset('g/r', 'v1.0.0', 'r.json', DATA, 'application/json')).toBe('exists')
    links = []
    fullPath = 'https://evil.exemple.test/x'
    await expect(gl().uploadAsset('g/r', 'v1.0.0', 'r.json', DATA, 'application/json')).rejects.toMatchObject({ code: 'E_FORGE_RESPONSE' })
    await expect(gl().uploadAsset('g/r', 'v1/', 'r.json', DATA, 'application/json')).rejects.toMatchObject({ code: 'E_FORGE_INPUT' })
  })
})

describe('Forgejo', () => {
  const fj = () => releaseForge({ kind: 'forgejo', base_url: 'https://forge.exemple.test', token: 'jeton-de-test' })

  it('fichier déjà présent dans la liste, réponse sans id, conflit 409', async () => {
    let rel: unknown = { id: 4 }
    let assets: { name: string }[] = [{ name: 'r.json' }]
    transport((m, u) => {
      if (u.pathname === '/api/v1/repos/o/r/releases/tags/v1.0.0') return { json: rel }
      if (m === 'GET' && u.pathname === '/api/v1/repos/o/r/releases/4/assets') return { json: assets }
      if (m === 'POST' && u.pathname === '/api/v1/repos/o/r/releases/4/assets') return { status: 409, json: {} }
      return undefined
    })
    expect(await fj().uploadAsset('o/r', 'v1.0.0', 'r.json', DATA, 'application/json')).toBe('exists')
    assets = []
    expect(await fj().uploadAsset('o/r', 'v1.0.0', 'r.json', DATA, 'application/json')).toBe('exists')
    rel = { id: 'x' }
    await expect(fj().uploadAsset('o/r', 'v1.0.0', 'r.json', DATA, 'application/json')).rejects.toMatchObject({ code: 'E_FORGE_RESPONSE' })
    await expect(fj().uploadAsset('o/r', 'x..y', 'r.json', DATA, 'application/json')).rejects.toMatchObject({ code: 'E_FORGE_INPUT' })
  })
})
