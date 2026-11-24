// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Entrées hostiles du chantier A : URL de forge, URL Git, références, chemins,
// known_hosts, archives, et répartition des analyses quotidiennes.

import { createHash } from 'node:crypto'
import { describe, expect, it } from 'vitest'
import { ForgeError, normalizeBaseUrl } from '../../server/forges/http'
import { checkFullName, checkPath, cloneUrlFor, isSafeRef } from '../../server/forges/types'
import { githubApiBase } from '../../server/forges/github'
import { GitUrlError, fullNameFromPath, parseGitUrl } from '../../server/projects/git-url'
import { fingerprint, hostPattern, parseKnownHosts, scanHostKeys, setKeyscan } from '../../server/projects/ssh'
import { sniffFormat } from '../../server/projects/uploads'
import { currentDailySlot, dailySlotMinute } from '../../server/projects/schedule'
import { slugify } from '../../server/projects/service'
import { projectCreateSchema } from '../../server/projects/schemas'

const KEY_B64 = Buffer.from('cle-publique-de-test-ed25519').toString('base64')

describe('URL de forge', () => {
  it('normalise une URL HTTPS', () => {
    expect(normalizeBaseUrl('https://forge.exemple.test/')).toBe('https://forge.exemple.test')
    expect(normalizeBaseUrl(' https://forge.exemple.test:8443/git// ')).toBe('https://forge.exemple.test:8443/git')
  })

  it.each([
    'http://forge.exemple.test', 'file:///etc/passwd', 'ext::sh -c id', 'ssh://forge.exemple.test',
    'https://user:pass@forge.exemple.test', 'https://jeton@forge.exemple.test', 'https://forge.exemple.test/?a=1',
    'https://forge.exemple.test/#x', 'https://localhost', 'https://a.localhost', 'https://127.0.0.1',
    'https://127.1.2.3:8443', 'https://[::1]', 'https://0.0.0.0', 'https://169.254.169.254', 'https://[fe80::1]',
    'https://localhost./', 'https://a.localhost..', 'https://[::ffff:127.0.0.1]/', 'https://[::ffff:169.254.169.254]',
    'pas une url', `https://forge.exemple.test/${'a'.repeat(600)}`,
  ])('refuse %s', (url) => {
    expect(() => normalizeBaseUrl(url)).toThrow(ForgeError)
  })

  it('API GitHub : api.github.com ou /api/v3 de GitHub Enterprise', () => {
    expect(githubApiBase('https://github.com')).toBe('https://api.github.com')
    expect(githubApiBase('https://ghe.exemple.test')).toBe('https://ghe.exemple.test/api/v3')
    expect(githubApiBase('https://ghe.exemple.test/api/v3')).toBe('https://ghe.exemple.test/api/v3')
  })
})

describe('références, noms et chemins', () => {
  it.each(['main', 'release/1.2', 'feat/x-y_z', 'v1.0.0'])('référence sûre : %s', (r) => {
    expect(isSafeRef(r)).toBe(true)
  })
  it.each(['--upload-pack=touch /tmp/x', '-x', 'a..b', 'a//b', '/main', 'main/', 'a@{1}', 'x.lock', '.hidden', 'a b', 'a;b', ''])(
    'référence refusée : %s', (r) => {
      expect(isSafeRef(r)).toBe(false)
    })

  it('nom complet et chemin de fichier', () => {
    expect(checkFullName('equipe/depot')).toBe('equipe/depot')
    for (const bad of ['depot', '../x', 'a/..', 'a/b c', 'a/b?x']) expect(() => checkFullName(bad)).toThrow(ForgeError)
    expect(checkPath('src/a.ts')).toBe('src/a.ts')
    for (const bad of ['/etc/passwd', '../x', 'a//b', 'a\\b', 'a/./b', '']) expect(() => checkPath(bad)).toThrow(ForgeError)
  })
})

describe('URL Git libre', () => {
  it('HTTPS et SSH', () => {
    expect(parseGitUrl('https://git.exemple.test/equipe/depot.git')).toEqual({
      kind: 'https', url: 'https://git.exemple.test/equipe/depot.git', host: 'git.exemple.test', port: 443, path: 'equipe/depot.git',
    })
    expect(parseGitUrl('ssh://git@git.exemple.test:2222/equipe/depot.git')).toMatchObject({ kind: 'ssh', host: 'git.exemple.test', port: 2222 })
    expect(parseGitUrl('git@git.exemple.test:equipe/depot.git')).toMatchObject({ kind: 'ssh', host: 'git.exemple.test', port: 22, path: 'equipe/depot.git' })
    expect(fullNameFromPath('equipe/depot.git')).toBe('equipe/depot')
    expect(fullNameFromPath('depot')).toBeNull()
    expect(parseGitUrl('https://github.com/exemple/scanoria.git')).toMatchObject({ host: 'github.com', path: 'exemple/scanoria.git' })
  })

  it('URL de clonage d’une forge : reconstruite depuis son adresse, jamais reprise de l’API', () => {
    expect(cloneUrlFor('https://forge.exemple.test/git/', 'equipe/depot')).toBe('https://forge.exemple.test/git/equipe/depot.git')
    expect(() => cloneUrlFor('https://forge.exemple.test', '../x')).toThrow(ForgeError)
  })

  it.each([
    'file:///srv/depot', 'ext::sh -c touch% /tmp/x', 'git://git.exemple.test/a/b', 'http://git.exemple.test/a/b',
    'https://jeton@git.exemple.test/a/b', 'https://u:p@git.exemple.test/a/b', 'https://127.0.0.1/a/b', 'https://localhost/a/b',
    'ssh://git@127.0.0.1/a/b', 'git@localhost:a/b', '-oProxyCommand=id', 'git@git.exemple.test:-oProxyCommand=id',
    'ssh://-oProxyCommand=id@h/a', 'git@git.exemple.test::a', 'https://git.exemple.test/a/../b', 'https://git.exemple.test/a b',
    'ssh://git@git.exemple.test:99999/a', 'git@-h:a/b', 'https://git.exemple.test/%E0%A4%A',
    'https://github.com/exemple/scanoria/tree/v0.1.0', 'git@github.com:exemple/scanoria/x', 'https://github.com/exemple',
  ])('refuse %s', (url) => {
    expect(() => parseGitUrl(url)).toThrow(GitUrlError)
  })
})

describe('known_hosts', () => {
  it('accepte les lignes de l’hôte et du port du dépôt, calcule l’empreinte', () => {
    const keys = parseKnownHosts(`# commentaire\ngit.exemple.test ssh-ed25519 ${KEY_B64}\n`, 'git.exemple.test', 22)!
    expect(keys).toHaveLength(1)
    expect(keys[0]!.fingerprint).toBe(`SHA256:${createHash('sha256').update(Buffer.from(KEY_B64, 'base64')).digest('base64').replace(/=+$/, '')}`)
    expect(fingerprint(KEY_B64)).toBe(keys[0]!.fingerprint)
    expect(hostPattern('git.exemple.test', 2222)).toBe('[git.exemple.test]:2222')
    expect(parseKnownHosts(`[git.exemple.test]:2222 ssh-ed25519 ${KEY_B64}`, 'git.exemple.test', 2222)).toHaveLength(1)
  })

  it.each([
    `autre.exemple.test ssh-ed25519 ${KEY_B64}`,
    `git.exemple.test ssh-dss ${KEY_B64}`,
    `git.exemple.test ssh-ed25519 pas-du-base64!`,
    `* ssh-ed25519 ${KEY_B64}`,
    `@cert-authority git.exemple.test ssh-ed25519 ${KEY_B64}`,
    '',
  ])('refuse %s', (line) => {
    expect(parseKnownHosts(line, 'git.exemple.test', 22)).toBeNull()
  })

  it('ssh-keyscan simulé : clés retenues, hôte muet → null', async () => {
    setKeyscan(async host => `# ${host}:22 SSH-2.0\n${host} ssh-ed25519 ${KEY_B64}\n`)
    expect(await scanHostKeys('git.exemple.test', 22)).toHaveLength(1)
    setKeyscan(async () => {
      throw new Error('timeout')
    })
    expect(await scanHostKeys('git.exemple.test', 22)).toBeNull()
    setKeyscan()
  })
})

describe('archives et divers', () => {
  it('format reconnu par l’en-tête seulement', () => {
    expect(sniffFormat(Buffer.from([0x50, 0x4b, 0x03, 0x04, 0]))).toBe('zip')
    expect(sniffFormat(Buffer.from([0x1f, 0x8b, 8]))).toBe('tar.gz')
    const tar = Buffer.alloc(512)
    tar.write('ustar', 257, 'latin1')
    expect(sniffFormat(tar)).toBe('tar')
    expect(sniffFormat(Buffer.from('#!/bin/sh\n'))).toBeNull()
  })

  it('créneau quotidien stable, dans la journée, étalé', () => {
    const ids = Array.from({ length: 50 }, (_, i) => `00000000-0000-4000-8000-${String(i).padStart(12, '0')}`)
    const minutes = ids.map(dailySlotMinute)
    expect(minutes.every(m => m >= 0 && m < 1440)).toBe(true)
    expect(new Set(minutes).size).toBeGreaterThan(40)
    expect(dailySlotMinute(ids[0]!)).toBe(minutes[0])
    const now = new Date('2026-11-24T12:00:00Z')
    const slot = currentDailySlot(ids[0]!, now)
    expect(slot <= now).toBe(true)
    expect(now.getTime() - slot.getTime()).toBeLessThan(86_400_000)
  })

  it('slug', () => {
    expect(slugify('Équipe/Dépôt Principal')).toBe('equipe-depot-principal')
    expect(slugify('---')).toBe('projet')
    expect(slugify('_x')).toBe('x')
  })

  it('corps de création : source obligatoire, champs inconnus refusés, clé SSH au format OpenSSH', () => {
    expect(projectCreateSchema.safeParse({ source: 'forge', forge_id: '00000000-0000-4000-8000-000000000000', repo: 'a/b' }).success).toBe(true)
    expect(projectCreateSchema.safeParse({ source: 'forge', forge_id: '00000000-0000-4000-8000-000000000000', repo: 'a/b', extra: 1 }).success).toBe(false)
    expect(projectCreateSchema.safeParse({ source: 'git', url: 'https://git.exemple.test/a/b', tracked_branches: ['--upload-pack=x'] }).success).toBe(false)
    expect(projectCreateSchema.safeParse({ source: 'git', url: 'git@git.exemple.test:a/b', auth: { kind: 'ssh-key', private_key: 'pas une clé', known_hosts: 'x' } }).success).toBe(false)
  })
})
