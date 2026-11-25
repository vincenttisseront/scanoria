// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Chantier A de la 0.8 (CLAUDE.md § 7.3), fonctions pures : forme canonique
// du rapport (identique à celle du helper Python), enveloppe signée et
// vérification Ed25519, état du statut scanoria/release-gate, motifs et ordre
// des tags, noms de tags sûrs, corps multipart, écouteurs du contrat 40.

import { execFileSync, spawnSync } from 'node:child_process'
import { createHash, createPublicKey, generateKeyPairSync, sign } from 'node:crypto'
import { fileURLToPath } from 'node:url'
import { describe, expect, it, vi } from 'vitest'
import { CanonicalError, canonicalBytes, canonicalJson, sha256Hex, toSafeJson } from '../../server/release/canonical'
import { publicKeyPem, signedEnvelope, verifySignature, SIGNED_REPORT_SCHEMA } from '../../server/release/sign'
import { gateState } from '../../server/release/gate'
import { releaseTags, tagMatches } from '../../server/release/poll'
import { compareTags } from '../../server/release/compare'
import { isSafeTag, missingAssetPermission, multipartFile } from '../../server/forges/release'
import { clearReleaseVerdictListeners, emitReleaseVerdict, onReleaseVerdict } from '../../server/release/events'
import { ReleaseNotesOutput, releaseNotes } from '../../server/ai/tasks/release-notes'

const PY = fileURLToPath(new URL('../../../src/rootfs/usr/lib/scanoria/py', import.meta.url))
const hasPython = spawnSync('python3', ['--version']).status === 0

function pythonCanonical(v: unknown): Buffer {
  return execFileSync('python3', ['-I', '-c', `import json, sys; sys.path.insert(0, ${JSON.stringify(PY)}); from scanoria import release
sys.stdout.buffer.write(release.canonical_bytes(json.loads(sys.stdin.read())))`], { input: JSON.stringify(v) })
}

describe('forme canonique (rapport de release)', () => {
  const sample = {
    schema: 'scanoria-release-report/1', z: [3, { b: true, a: null }], a: 'é — 漢字 😀', n: -42, big: 2 ** 53 - 1,
    nested: { y: 'x"\\\n\t', x: [] },
  }

  it('clés triées, sans espaces, UTF-8 non échappé ; même octets quel que soit l\'ordre d\'insertion', () => {
    expect(canonicalJson({ b: 1, a: [2, 1] })).toBe('{"a":[2,1],"b":1}')
    const reversed = Object.fromEntries(Object.entries(sample).reverse())
    expect(canonicalBytes(reversed).equals(canonicalBytes(sample))).toBe(true)
    expect(canonicalBytes(sample).toString('utf8')).toContain('é — 漢字 😀')
    expect(sha256Hex(canonicalBytes(sample))).toMatch(/^[0-9a-f]{64}$/)
    expect(sha256Hex('abc')).toBe(createHash('sha256').update('abc').digest('hex'))
  })

  it.skipIf(!hasPython)('identique octet pour octet à release.canonical_bytes du helper', () => {
    expect(pythonCanonical(sample).equals(canonicalBytes(sample))).toBe(true)
    const tricky = { 'k-1': 'a b', 'K': 0, 'k': [-0, 1e3], 'ctl': '\u0001\u001f', '~': 'é' }
    expect(pythonCanonical(tricky).equals(canonicalBytes(tricky))).toBe(true)
  })

  it('refuse ce qui n\'a pas de forme canonique stable', () => {
    expect(() => canonicalJson({ a: 1.5 })).toThrow(CanonicalError)
    expect(() => canonicalJson({ a: 2 ** 53 })).toThrow(CanonicalError)
    expect(() => canonicalJson({ a: Number.NaN })).toThrow(CanonicalError)
    expect(() => canonicalJson({ clé: 1 })).toThrow(CanonicalError)
    expect(canonicalJson({ a: undefined, b: 1 })).toBe('{"b":1}')
    expect(() => canonicalJson({ a: '\ud800' })).toThrow(CanonicalError)
    let deep: unknown = 1
    for (let i = 0; i < 40; i++) deep = [deep]
    expect(() => canonicalJson({ deep })).toThrow(CanonicalError)
  })

  it('toSafeJson : nombres non entiers en texte, NUL retiré, chaînes bien formées, dates et grands entiers', () => {
    expect(toSafeJson({ a: 1.5, b: 2n, c: 'x\u0000y', d: '\ud800', e: Number.POSITIVE_INFINITY, f: [undefined, 1], g: true, h: null }))
      .toEqual({ a: '1.5', b: '2', c: 'xy', d: '�', e: null, f: [null, 1], g: true, h: null })
    const safe = toSafeJson({ when: new Date('2026-11-25T00:00:00Z'), deep: { x: 0.1 } })
    expect(() => canonicalJson(safe)).not.toThrow()
  })
})

describe('enveloppe signée et vérification', () => {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519')
  const raw = publicKey.export({ type: 'spki', format: 'der' }).subarray(12)
  const pub = raw.toString('base64')
  const report = { schema: 'scanoria-release-report/1', scan_id: 'x', commit_sha: 'a'.repeat(40) }
  const bytes = canonicalBytes(report)
  const sig = sign(null, bytes, privateKey).toString('base64')

  it('PEM SubjectPublicKeyInfo depuis la clé brute ; clé invalide refusée', () => {
    const pem = publicKeyPem(pub)!
    expect(createPublicKey(pem).asymmetricKeyType).toBe('ed25519')
    expect(publicKeyPem('AAAA')).toBeNull()
    expect(publicKeyPem(Buffer.alloc(31).toString('base64'))).toBeNull()
  })

  it('signature vérifiée ; un octet changé, une autre clé ou une signature mal formée refusés', () => {
    expect(verifySignature(pub, bytes, sig)).toBe(true)
    const tampered = Buffer.from(bytes)
    tampered[5] = tampered[5]! ^ 1
    expect(verifySignature(pub, tampered, sig)).toBe(false)
    const other = generateKeyPairSync('ed25519').publicKey.export({ type: 'spki', format: 'der' }).subarray(12).toString('base64')
    expect(verifySignature(other, bytes, sig)).toBe(false)
    expect(verifySignature(pub, bytes, 'pas-une-signature')).toBe(false)
  })

  it('enveloppe : une ligne, clés triées, contenu signé en base64, empreinte revérifiée', () => {
    const env = signedEnvelope({ report, report_sha256: sha256Hex(bytes), signature: sig, key_fingerprint: sha256Hex(raw), signed_at: new Date('2026-11-25T10:00:00.123Z') })
    const text = env.toString('utf8')
    expect(text.endsWith('\n')).toBe(true)
    expect(text.trimEnd()).not.toContain('\n')
    const obj = JSON.parse(text)
    expect(Object.keys(obj)).toEqual([...Object.keys(obj)].sort())
    expect(obj).toMatchObject({ schema: SIGNED_REPORT_SCHEMA, signed_at: '2026-11-25T10:00:00Z', key_fingerprint: sha256Hex(raw) })
    expect(Buffer.from(obj.payload, 'base64').equals(bytes)).toBe(true)
    expect(() => signedEnvelope({ report, report_sha256: '0'.repeat(64), signature: sig, key_fingerprint: 'x', signed_at: new Date() })).toThrow('E_SIGN_DIGEST')
  })
})

describe('statut scanoria/release-gate', () => {
  const base = { tag: 'v1.0.0', verdict: 'passed', verdict_details: { reasons: [] }, scan_status: 'done', report_status: 'signed' as string | null }

  it('en attente pendant l\'analyse et la signature ; favorable seulement avec un rapport signé', () => {
    expect(gateState({ ...base, verdict: null, scan_status: 'running' }, 'fr').state).toBe('pending')
    expect(gateState({ ...base, report_status: 'pending' }, 'fr')).toMatchObject({ state: 'pending', description: 'v1.0.0 : signature du rapport en cours' })
    expect(gateState({ ...base, report_status: null }, 'en').state).toBe('pending')
    expect(gateState({ ...base, report_status: 'error' }, 'fr')).toMatchObject({ state: 'failure', description: 'v1.0.0 : rapport non signé : bloquant' })
    expect(gateState(base, 'fr').state).toBe('success')
    expect(gateState(base, 'en').description.startsWith('v1.0.0 : ')).toBe(true)
  })

  it('défavorable ou non concluant : bloquant, même rapport signé', () => {
    expect(gateState({ ...base, verdict: 'failed' }, 'fr').state).toBe('failure')
    expect(['failure', 'error']).toContain(gateState({ ...base, verdict: 'inconclusive' }, 'fr').state)
    expect(['failure', 'error']).toContain(gateState({ ...base, verdict: 'inconclusive', verdict_details: 'invalide' }, 'en').state)
  })
})

describe('tags de release', () => {
  it('motifs glob : « * » et « ? » seulement, caractères spéciaux littéraux', () => {
    expect(tagMatches('v1.2.3', ['v*'])).toBe(true)
    expect(tagMatches('release-1', ['v*', 'release-?'])).toBe(true)
    expect(tagMatches('v1x2', ['v1.2'])).toBe(false)
    expect(tagMatches('docs', ['v*'])).toBe(false)
    expect(tagMatches('a+b', ['a+b'])).toBe(true)
  })

  it('tags retenus : motif ou pré-version, jamais un nom dangereux', () => {
    const tags = [
      { name: 'v1.0.0', commit_sha: 'a'.repeat(40), release: true, prerelease: false },
      { name: 'rc-7', commit_sha: 'b'.repeat(40), release: true, prerelease: true },
      { name: 'docs', commit_sha: 'c'.repeat(40), release: false, prerelease: false },
      { name: 'v../x', commit_sha: 'd'.repeat(40), release: false, prerelease: true },
    ]
    expect(releaseTags(tags, ['v*']).map(t => t.name)).toEqual(['v1.0.0', 'rc-7'])
  })

  it('ordre : numérique, pré-version avant la version, préfixe ignoré', () => {
    const sorted = ['v1.10.0', 'v1.2.0', 'v1.2.0-rc.2', 'v1.2.0-rc.10', 'v2.0.0', '1.9'].sort(compareTags)
    expect(sorted).toEqual(['v1.2.0-rc.2', 'v1.2.0-rc.10', 'v1.2.0', '1.9', 'v1.10.0', 'v2.0.0'])
    expect(compareTags('v1.0', 'v1.0.1')).toBeLessThan(0)
    expect(compareTags('v1.0.0', 'v1.0.0')).toBe(0)
  })

  it('noms sûrs : ni « .. », ni chemin, ni option, ni caractère de contrôle', () => {
    for (const ok of ['v1.0.0', 'release/2026.11', 'v1+build.5', 'A_b-c']) expect(isSafeTag(ok)).toBe(true)
    for (const bad of ['', '../x', 'a..b', '-v1', 'a/', 'a//b', 'x.lock', 'a b', 'a\nb', 'é', 'x'.repeat(300)]) expect(isSafeTag(bad)).toBe(false)
  })

  it('droit manquant pour joindre des fichiers (GitHub : contents:write)', () => {
    expect(missingAssetPermission('github', { contents: 'read' })).toBe('contents:write')
    expect(missingAssetPermission('github', { contents: 'write' })).toBeNull()
    expect(missingAssetPermission('github', null)).toBeNull()
    expect(missingAssetPermission('forgejo', { contents: 'read' })).toBeNull()
  })

  it('corps multipart d\'un fichier : délimiteur aléatoire, contenu intact', () => {
    const data = Buffer.from([0, 1, 2, 255])
    const a = multipartFile('attachment', 'r.json', data, 'application/json')
    const b = multipartFile('attachment', 'r.json', data, 'application/json')
    expect(a.contentType).not.toBe(b.contentType)
    const boundary = /boundary=(.+)$/.exec(a.contentType)![1]!
    expect(a.body.includes(Buffer.from(`--${boundary}--`))).toBe(true)
    expect(a.body.includes(data)).toBe(true)
    expect(a.body.toString('latin1')).toContain('name="attachment"; filename="r.json"')
  })
})

describe('contrat 40 : onReleaseVerdict', () => {
  it('chaque écouteur est appelé ; une erreur est comptée sans arrêter les autres ; désinscription', async () => {
    clearReleaseVerdictListeners()
    const seen: string[] = []
    const err = vi.spyOn(console, 'error').mockImplementation(() => {})
    const off = onReleaseVerdict((_db, e) => {
      seen.push(`a:${e.verdict}`)
    })
    onReleaseVerdict(() => {
      throw new Error('panne')
    })
    onReleaseVerdict(async (_db, e) => {
      seen.push(`c:${e.scanId}`)
    })
    const ev = { scanId: 's1', projectId: 'p1', verdict: 'passed' as const, reportSha256: null }
    expect(await emitReleaseVerdict({} as never, ev)).toBe(1)
    expect(seen).toEqual(['a:passed', 'c:s1'])
    off()
    await emitReleaseVerdict({} as never, ev)
    expect(seen).toEqual(['a:passed', 'c:s1', 'c:s1'])
    clearReleaseVerdictListeners()
    expect(await emitReleaseVerdict({} as never, ev)).toBe(0)
    err.mockRestore()
  })
})

describe('I6 : notes de sécurité de release (tâche IA)', () => {
  it('sortie stricte, nettoyée ; sujet « release »', () => {
    expect(releaseNotes.subjectType).toBe('release')
    expect(ReleaseNotesOutput.safeParse({ headline: 'h', fixed: 'f', introduced: 'i', accepted: 'a', extra: 1 }).success).toBe(false)
    const out = releaseNotes.finalize!({ headline: '<b>Titre</b>', fixed: 'f', introduced: 'i', accepted: 'a' }, {} as never)
    expect(JSON.stringify(out)).not.toContain('<b>')
    expect(releaseNotes.instruction('fr')).toContain('sans rien inventer')
    expect(releaseNotes.instruction('en')).toContain('without inventing')
  })
})
