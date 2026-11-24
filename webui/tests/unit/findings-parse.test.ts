// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Chantier D : lecture SARIF / CycloneDX, normalisation, empreintes stables
// (G19), gravités (G5) et masquage des secrets (F7). Les SARIF réels viennent
// des bancs d'essai des modules (modules/*/tests/recorded.sarif). Aucun motif
// de secret n'est écrit dans ce fichier : les valeurs sont générées au test.

import { randomBytes } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'
import { parseCycloneDx, parseSarif, MAX_RESULTS } from '../../server/findings/parse'
import {
  cleanText, ecosystemFromPath, extractCwe, extractVulnIds, fingerprintOf, inferCategory, isVulnId, normalizePath,
  packageFromMessage, parsePurl, primaryVulnId,
} from '../../server/findings/normalize'
import { defaultSeverity, nativeKey, originSeverity, severityFromScore } from '../../server/findings/severity'
import { entropy, redact, redactText, secretShape } from '../../server/findings/redact'

const MODULES = fileURLToPath(new URL('../../../modules/', import.meta.url))
const recorded = (id: string) => JSON.parse(readFileSync(`${MODULES}${id}/tests/recorded.sarif`, 'utf8')) as unknown
const alnum = (n: number) => randomBytes(n * 2).toString('base64').replace(/[^A-Za-z0-9]/g, '').slice(0, n)
const b64url = (s: string) => Buffer.from(s).toString('base64url')
/** Jeton JWT factice, construit au test. */
const fakeJwt = () => `${b64url('{"alg":"HS256","typ":"JWT"}')}.${b64url(`{"sub":"${alnum(12)}"}`)}.${alnum(43)}`

const sarif = (results: unknown[], rules: unknown[] = [], extra: Record<string, unknown> = {}) => ({
  version: '2.1.0',
  runs: [{ tool: { driver: { name: 'x', rules } }, results, ...extra }],
})
const result = (ruleId: string, uri: string, snippet: string, startLine = 1, extra: Record<string, unknown> = {}) => ({
  ruleId,
  message: { text: `${ruleId} found` },
  locations: [{ physicalLocation: { artifactLocation: { uri }, region: { startLine, snippet: { text: snippet } } } }],
  ...extra,
})

describe('findings : SARIF réels des bancs d\'essai', () => {
  it('gitleaks : secrets masqués, type de secret, gravité native par défaut', () => {
    const out = parseSarif(recorded('gitleaks'), { moduleId: 'gitleaks', moduleCategories: ['secrets'] })
    expect(out.issues).toEqual([])
    expect(out.findings).toHaveLength(3)
    for (const f of out.findings) {
      expect(f.category).toBe('secrets')
      expect(f.secretType).toBe(f.ruleId)
      expect(f.tool).toBe('gitleaks')
      expect(f.nativeSeverity).toBe('level:warning')
      expect(f.fingerprint).toMatch(/^[0-9a-f]{64}$/)
    }
    expect(new Set(out.findings.map(f => f.fingerprint)).size).toBe(3)
    expect(out.findings.map(f => f.path).sort()).toEqual(['.env', '.env', 'config/app.yaml'])
  })

  it('le secret factice du banc d\'essai gitleaks n\'apparaît dans aucun champ, même si l\'outil l\'a laissé', () => {
    const env = readFileSync(`${MODULES}gitleaks/testbed/.env`, 'utf8')
    const values = env.split('\n').filter(l => /^[A-Z_]+=/.test(l)).map(l => l.slice(l.indexOf('=') + 1).trim())
    expect(values.length).toBeGreaterThanOrEqual(2)
    const doc = recorded('gitleaks') as { runs: { results: { message: { text: string }, locations: { physicalLocation: { region: { snippet: { text: string } } } }[] }[] }[] }
    // Version sans --redact : la valeur figure dans l'extrait et le message.
    doc.runs[0]!.results.forEach((r, i) => {
      const v = values[i % values.length]!
      r.locations[0]!.physicalLocation.region.snippet.text = `KEY=${v}`
      r.message.text = `found ${v}`
    })
    const out = parseSarif(doc, { moduleId: 'gitleaks', moduleCategories: ['secrets'] })
    const dump = JSON.stringify(out)
    for (const v of values) expect(dump).not.toContain(v)
    expect(dump).toContain('[secret masqué : ')
  })

  it('OSV-Scanner : avis, paquet, versions corrigées, chemin file:///src', () => {
    const out = parseSarif(recorded('osv-scanner'), { moduleId: 'osv-scanner', moduleCategories: ['sca'] })
    expect(out.findings).toHaveLength(1)
    const f = out.findings[0]!
    expect(f.path).toBe('package-lock.json')
    expect(f.category).toBe('sca')
    expect(f.vulnIds).toEqual(expect.arrayContaining(['CVE-2021-44906', 'GHSA-xvch-5gv4-984h']))
    expect(f.package).toEqual({ ecosystem: 'npm', name: 'minimist', version: '1.2.5', fixed: ['0.2.4', '1.2.6'] })
    expect(f.nativeSeverity).toBe('security-severity:critical')
    expect(f.malicious).toBe(false)
  })

  it('Trivy : vulnérabilité et mauvaises configurations (uriBaseId ROOTPATH)', () => {
    const out = parseSarif(recorded('trivy'), { moduleId: 'trivy', moduleCategories: ['sca', 'iac', 'container', 'sbom', 'secrets'] })
    expect(out.findings).toHaveLength(5)
    const vuln = out.findings.find(f => f.ruleId === 'CVE-2021-44906')!
    expect(vuln.category).toBe('sca')
    expect(vuln.package).toMatchObject({ ecosystem: 'npm', name: 'minimist', version: '1.2.5', fixed: ['1.2.6', '0.2.4'] })
    expect(vuln.nativeSeverity).toBe('critical')
    const ds = out.findings.filter(f => f.ruleId.startsWith('DS-'))
    expect(ds.map(f => f.category)).toEqual(['iac', 'iac', 'iac', 'iac'])
    expect(ds.every(f => f.path === 'Dockerfile')).toBe(true)
    expect(ds.map(f => f.nativeSeverity).sort()).toEqual(['high', 'high', 'low', 'medium'])
    // Deux règles distinctes sur la même ligne sans extrait : empreintes distinctes.
    expect(new Set(out.findings.map(f => f.fingerprint)).size).toBe(5)
  })
})

describe('findings : documents hostiles', () => {
  const ctx = { moduleId: 'semgrep', moduleCategories: ['sast'] }

  it('chemins sortants rejetés et comptés', () => {
    const out = parseSarif(sarif([
      result('r1', '../../etc/passwd', 'x'),
      result('r2', '/etc/shadow', 'x'),
      result('r3', 'file:///etc/hosts', 'x'),
      result('r4', 'https://exemple.test/a.js', 'x'),
      result('r5', 'src/%2e%2e/%2e%2e/x', 'x'),
      result('r6', 'src\\..\\..\\x', 'x'),
      result('r7', 'src/ok.ts', 'x'),
    ]), ctx)
    expect(out.findings.map(f => f.path)).toEqual(['src/ok.ts'])
    expect(out.issues).toContainEqual({ code: 'path-outside', detail: '6' })
  })

  it('HTML et caractères de contrôle conservés comme texte, bornés', () => {
    const html = '<img src=x onerror=alert(1)><script>alert(2)</script>\u0007'
    const out = parseSarif(sarif([{ ...result('xss', 'a.html', html), message: { text: `${html}${'a'.repeat(5000)}` } }],
      [{ id: 'xss', shortDescription: { text: html } }]), ctx)
    const f = out.findings[0]!
    expect(f.title).toContain('<script>')
    expect(f.title).not.toContain('\u0007')
    expect(f.message!.length).toBeLessThanOrEqual(4000)
  })

  it('trop de résultats : borné et signalé', () => {
    const many = Array.from({ length: MAX_RESULTS + 5 }, (_, i) => result('r', `f${i}.js`, `line ${i}`))
    const out = parseSarif(sarif(many), ctx)
    expect(out.findings).toHaveLength(MAX_RESULTS)
    expect(out.issues).toContainEqual({ code: 'truncated', detail: String(MAX_RESULTS + 5) })
  })

  it('document invalide, résultats sans règle, version inconnue', () => {
    expect(parseSarif('nope', ctx).issues[0]!.code).toBe('invalid-document')
    expect(parseSarif({ version: '1.0.0', runs: [] }, ctx).issues[0]!.code).toBe('invalid-document')
    const out = parseSarif(sarif([null, { message: { text: 'x' } }, result('ok', 'a', 'b')]), ctx)
    expect(out.findings).toHaveLength(1)
    expect(out.issues).toContainEqual({ code: 'invalid-result', detail: '2' })
  })

  it('un nom de fichier « MAL-… » cité dans un message ne marque pas un paquet malveillant', () => {
    const out = parseSarif(sarif([{ ...result('generic-api-key', 'MAL-2024-1234.txt', 'x'), message: { text: 'secret in MAL-2024-1234.txt' } }]),
      { moduleId: 'gitleaks', moduleCategories: ['secrets'] })
    expect(out.findings[0]!.malicious).toBe(false)
    expect(out.findings[0]!.vulnIds).toEqual([])
  })

  it('avis MAL- d\'OSV : malveillant', () => {
    const out = parseSarif(sarif([{ ...result('MAL-2024-1234', 'package-lock.json', ''), message: { text: 'Package \'evil-pkg@1.0.0\' is vulnerable to \'MAL-2024-1234\'.' } }]),
      { moduleId: 'osv-scanner', moduleCategories: ['sca'] })
    expect(out.findings[0]).toMatchObject({ malicious: true, vulnIds: ['MAL-2024-1234'], package: { name: 'evil-pkg', version: '1.0.0', ecosystem: 'npm' } })
  })
})

describe('findings : empreintes stables (G19)', () => {
  const ctx = { moduleId: 'semgrep', moduleCategories: ['sast'] }
  const code = 'const q = "SELECT * FROM t WHERE id = " + req.query.id'

  it('un déplacement de code (lignes, indentation) ne change pas l\'empreinte', () => {
    const a = parseSarif(sarif([result('sqli', 'src/a.js', code, 10)]), ctx).findings[0]!
    const b = parseSarif(sarif([result('sqli', 'src/a.js', `    ${code.replace(/ /g, '  ')}\n`, 250)]), ctx).findings[0]!
    expect(b.fingerprint).toBe(a.fingerprint)
  })

  it('une modification réelle, un autre fichier ou une autre règle en créent une nouvelle', () => {
    const a = parseSarif(sarif([result('sqli', 'src/a.js', code)]), ctx).findings[0]!
    expect(parseSarif(sarif([result('sqli', 'src/a.js', code.replace('id', 'name'))]), ctx).findings[0]!.fingerprint).not.toBe(a.fingerprint)
    expect(parseSarif(sarif([result('sqli', 'src/b.js', code)]), ctx).findings[0]!.fingerprint).not.toBe(a.fingerprint)
    expect(parseSarif(sarif([result('xss', 'src/a.js', code)]), ctx).findings[0]!.fingerprint).not.toBe(a.fingerprint)
  })

  it('occurrences identiques sans contexte : rang d\'occurrence', () => {
    const out = parseSarif(sarif([result('r', 'a.js', '', 5), result('r', 'a.js', '', 9)]), ctx)
    expect(new Set(out.findings.map(f => f.fingerprint)).size).toBe(2)
  })

  it('partialFingerprints utilisés quand non vides ; dépendance : écosystème, nom, version, avis', () => {
    const pf = (h: string) => parseSarif(sarif([result('r', 'a.js', code, 1, { partialFingerprints: { primaryLocationLineHash: h } })]), ctx).findings[0]!.fingerprint
    expect(pf('abc')).toBe(pf('abc'))
    expect(pf('abc')).not.toBe(pf('def'))
    const dep = (path: string) => fingerprintOf({ tool: 'trivy', ruleId: 'CVE-2021-44906', path, context: '', pkg: { ecosystem: 'npm', name: 'm', version: '1', fixed: [] }, vulnId: 'CVE-2021-44906', partial: null })
    expect(dep('a/package-lock.json')).toBe(dep('b/package-lock.json'))
  })
})

describe('findings : normalisation', () => {
  it('chemins', () => {
    expect(normalizePath('./src//a.ts')).toBe('src/a.ts')
    expect(normalizePath('file:///src/a%20b.ts')).toBe('a b.ts')
    expect(normalizePath('a.ts', 'file:///src/')).toBe('a.ts')
    expect(normalizePath(undefined)).toBe('')
    expect(normalizePath('a/\u0000b')).toBeNull()
    expect(normalizePath('%E0%A4%A')).toBeNull()
    expect(normalizePath('x'.repeat(3000))).toBeNull()
    expect(normalizePath('/src')).toBe('')
  })

  it('CWE, avis, paquets, écosystèmes', () => {
    expect(extractCwe([['external/cwe/cwe-79', 'CWE-89: SQL'], 'cwe_22', 352, ['x']])).toEqual(['CWE-79', 'CWE-89', 'CWE-22', 'CWE-352'])
    expect(extractVulnIds(['CVE-2024-12345 and GHSA-abcd-efgh-jkmp? no', ['PYSEC-2021-1', 'GO-2023-1234']])).toEqual(['CVE-2024-12345', 'PYSEC-2021-1', 'GO-2023-1234'])
    expect(isVulnId('CVE-2024-1234')).toBe(true)
    expect(isVulnId('CVE-2024-1234x')).toBe(false)
    expect(primaryVulnId(['GHSA-xvch-5gv4-984h', 'CVE-2021-44906'])).toBe('CVE-2021-44906')
    expect(primaryVulnId([])).toBeNull()
    expect(parsePurl('pkg:npm/%40scope/name@1.0.0?x=1')).toEqual({ ecosystem: 'npm', name: '@scope/name', version: '1.0.0', fixed: [] })
    expect(parsePurl('pkg:golang/x/y')).toMatchObject({ ecosystem: 'Go', version: null })
    expect(parsePurl('nope')).toBeNull()
    expect(parsePurl('pkg:npm/%E0%A4%A@1')).toBeNull()
    expect(packageFromMessage('nothing')).toBeNull()
    expect(ecosystemFromPath('a/poetry.lock')).toBe('PyPI')
    expect(ecosystemFromPath('README.md')).toBeNull()
    expect(ecosystemFromPath(null)).toBeNull()
    expect(cleanText(42, 10)).toBe('')
  })

  it('catégories', () => {
    expect(inferCategory({ moduleCategories: ['sast'], tags: [], hasVuln: false, hasPackage: false })).toBe('sast')
    expect(inferCategory({ moduleCategories: ['container'], tags: [], hasVuln: true, hasPackage: true })).toBe('container')
    expect(inferCategory({ moduleCategories: ['sca', 'secrets'], tags: ['secret'], hasVuln: false, hasPackage: false })).toBe('secrets')
    expect(inferCategory({ moduleCategories: ['licenses'], tags: ['license'], hasVuln: false, hasPackage: false })).toBe('licenses')
    expect(inferCategory({ moduleCategories: [], tags: [], hasVuln: false, hasPackage: false })).toBe('quality')
  })
})

describe('findings : gravités (G5)', () => {
  it('clé native : étiquette, puis security-severity, puis niveau SARIF', () => {
    expect(nativeKey({ label: 'CRITICAL', score: 1, level: 'note' })).toBe('critical')
    expect(nativeKey({ score: '7.5', level: 'note' })).toBe('security-severity:high')
    expect(nativeKey({ level: 'error' })).toBe('level:error')
    expect(nativeKey({})).toBe('level:warning')
    expect(nativeKey({ label: 'bizarre', level: 'nope' })).toBe('level:warning')
  })

  it('défauts du § 12.6 et table du manifeste', () => {
    expect(defaultSeverity('level:error')).toBe('high')
    expect(defaultSeverity('level:warning')).toBe('medium')
    expect(defaultSeverity('level:note')).toBe('low')
    expect(defaultSeverity('level:none')).toBe('info')
    expect(defaultSeverity('security-severity:critical')).toBe('critical')
    expect(defaultSeverity('weird')).toBe('medium')
    expect([9, 7, 4, 0.1, 0].map(severityFromScore)).toEqual(['critical', 'high', 'medium', 'low', 'info'])
    expect(originSeverity('level:warning', { WARNING: 'high' })).toBe('high')
    expect(originSeverity('critical', { critical: 'nope' })).toBe('critical')
    expect(originSeverity('level:note', null)).toBe('low')
  })
})

describe('findings : CycloneDX', () => {
  it('vulnérabilités rattachées aux composants', () => {
    const doc = {
      bomFormat: 'CycloneDX', specVersion: '1.5',
      components: [{ 'bom-ref': 'c1', 'name': 'minimist', 'version': '1.2.5', 'purl': 'pkg:npm/minimist@1.2.5' },
        { 'bom-ref': 'c2', 'name': 'lib', 'version': '2', 'components': [{ 'bom-ref': 'c3', 'name': 'inner', 'version': '1' }] }],
      vulnerabilities: [
        { id: 'CVE-2021-44906', ratings: [{ score: 9.8, severity: 'critical' }], cwes: [1321], description: 'Prototype pollution', affects: [{ ref: 'c1' }, { ref: 'c3' }, { ref: 'missing' }] },
        { id: 'X-1', affects: [{ ref: 'c2' }] },
        'junk',
      ],
    }
    const out = parseCycloneDx(doc, { moduleId: 'grype', moduleCategories: ['sca'] })
    expect(out.findings).toHaveLength(3)
    const first = out.findings.find(f => f.package?.name === 'minimist')!
    expect(first).toMatchObject({ category: 'sca', nativeSeverity: 'critical', cwe: ['CWE-1321'], package: { ecosystem: 'npm' } })
    expect(out.findings.find(f => f.package?.name === 'inner')!.package!.ecosystem).toBeNull()
    expect(parseCycloneDx({}, { moduleId: 'x', moduleCategories: [] }).issues[0]!.code).toBe('invalid-document')
  })
})

describe('findings : masquage des secrets (F7)', () => {
  it('motifs connus masqués avec type et longueur', () => {
    const jwt = fakeJwt()
    const aws = `AKIA${alnum(40).toUpperCase().replace(/[^A-Z0-9]/g, '').slice(0, 16).padEnd(16, 'Q')}`
    const gh = `ghp_${alnum(36)}`
    const pw = alnum(14)
    const text = `token=${jwt}\naws ${aws}\nGH ${gh}\npassword: "${pw}"\nhttps://u:${pw}@exemple.test/x\nAuthorization: Bearer ${alnum(30)}`
    const { text: out, found } = redactText(text)
    for (const v of [jwt, aws, gh, pw]) expect(out).not.toContain(v)
    expect(out).toContain(`[secret masqué : jwt, longueur ${jwt.length}]`)
    expect(found.map(f => f.type)).toEqual(expect.arrayContaining(['jwt', 'aws-access-key', 'github-token', 'assignment', 'url-password', 'bearer']))
    // Idempotent.
    expect(redact(out)).toBe(out)
  })

  it('clé privée PEM, chaînes aléatoires en mode agressif seulement', () => {
    const pem = ['-----BEGIN', ' RSA PRIVATE KEY-----\n', alnum(64), '\n-----END RSA PRIVATE', ' KEY-----'].join('')
    expect(redact(`x ${pem} y`)).toBe(`x [secret masqué : private-key, longueur ${pem.length}] y`)
    const random = alnum(32)
    expect(redact(`value ${random}`)).toContain(random)
    expect(redact(`value ${random}`, { aggressive: true })).not.toContain(random)
    expect(redact('a_long_identifier_name_without_digits', { aggressive: true })).toBe('a_long_identifier_name_without_digits')
    expect(redact('Package: minimist author: someone token in file')).toBe('Package: minimist author: someone token in file')
  })

  it('secret sans mot-clé : l\'extrait d\'un résultat de secret n\'est jamais gardé ; CWE-798 = secret', () => {
    const value = `Xq7!mZ9pLr2#${alnum(8)}&kLm`
    const out = parseSarif(sarif([result('generic-api-key', 'a.cfg', `value ${value} end`)]), { moduleId: 'gitleaks', moduleCategories: ['secrets'] })
    expect(JSON.stringify(out)).not.toContain(value)
    expect(out.findings[0]!.snippet).toMatch(/^\[secret masqué : snippet, longueur \d+\]$/)
    const sast = parseSarif(sarif([result('hardcoded', 'a.py', `pw = "${value}"`, 1, { properties: { tags: ['CWE-798'] } })]), { moduleId: 'semgrep', moduleCategories: ['sast'] })
    expect(sast.findings[0]).toMatchObject({ category: 'secrets', secretType: 'hardcoded' })
    expect(JSON.stringify(sast)).not.toContain(value)
  })

  it('aucun retour arrière quadratique ; texte borné', () => {
    const t0 = Date.now()
    redact(`token${' '.repeat(200_000)}x`)
    redact(`Bearer${' '.repeat(200_000)}x`)
    redact(`password${'a'.repeat(200_000)}`, { aggressive: true })
    expect(Date.now() - t0).toBeLessThan(2000)
    expect(redact('a'.repeat(20_000)).length).toBeLessThanOrEqual(8001)
  })

  it('forme d\'une valeur', () => {
    expect(secretShape('0123', 't')).toEqual({ type: 't', length: 4, charset: 'digits' })
    expect(secretShape('deadbeef').charset).toBe('hex')
    expect(secretShape('abcXYZ1').charset).toBe('alnum')
    expect(secretShape('ab-_c').charset).toBe('base64url')
    expect(secretShape('ab+/c==').charset).toBe('base64')
    expect(secretShape('a b').charset).toBe('printable')
    expect(entropy('aaaa')).toBe(0)
  })
})

describe('G19 : empreintes inchangées par le masquage élargi de la 0.4', () => {
  // Extraits que le masquage de la 0.4 traite autrement que celui de la 0.3,
  // construits par morceaux (aucun secret d'apparence réelle dans le dépôt).
  const CASES = [
    'password = "un deux trois quatre"',
    `const k = '${'AI' + 'za'}${'Bc1De2Fg3Hi4Jk5Lm6No7Pq8Rs9Tu0Vw1Xy2'.slice(0, 35)}'`,
    `Authorization: ${'Ba' + 'sic'} ${'Zm9vOmJhcg'.repeat(3)}`,
    'auth=abc',
    `jdbc:postgresql://user:p${'@'}ss@db.exemple.test/base`,
    'client_secret: "xyz"',
    'x = 1',
  ]
  // Empreintes calculées par le code de main avant la 0.4 (commit c6f7b32), sur ces mêmes entrées.
  const GOLDEN = [
    '88002f3e8c141ad79f41f0489312a45e86ed03cd1fa8f1d49552477a969054c8',
    'e56fe8bd76e936695b45611f67884ddc521f4617f8b978b19f94035b45096ea1',
    '43f5fb12256230115b42833bf5b9c993061310d2ff1aa35cf56a89fcaaddacf8',
    '25cb1ba6633b6df9876e209b7fcb36f3024a44877738227679dc67a7c169473c',
    'b5e576414052cb46a48c13247420753c555a55eda1bf47844c4de4b18bd58c18',
    '9fa3d104319607fb25355ab3cafb16f89a075d2ae3d6789aef107b7736c22270',
    '76edd6016e6c7f17d4276ab90dcc8ee132d82f7461b36306e852804e5fe7bc57',
  ]

  it('même empreinte qu’avant la PR, extrait masqué plus largement', () => {
    const doc = sarif(CASES.map((s, i) => result('python.rule', `app/f${i}.py`, s)).map(r => ({ ...r, message: { text: 'm' } })))
    const out = parseSarif(doc, { moduleId: 'semgrep', moduleCategories: ['sast'] })
    expect(out.findings.map(f => f.fingerprint)).toEqual(GOLDEN)
    // L'affichage, lui, profite du masquage élargi.
    expect(out.findings[0]!.snippet).not.toContain('trois')
    expect(out.findings[2]!.snippet).not.toContain('Zm9v')
    expect(out.findings[4]!.snippet).toContain('@db.exemple.test/base')
    expect(out.findings[4]!.snippet).not.toContain('@ss')
  })
})
