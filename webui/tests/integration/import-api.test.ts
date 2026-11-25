// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Reprise de l'existant (J5) contre un vrai PostgreSQL 16 : statuts de tri
// d'instances SonarQube, Dependency-Track et DefectDojo (faux serveurs), jeton
// d'administration chiffré puis effacé, demandes seulement (jamais
// d'approbation), aperçu sans écriture, audit.

import { randomBytes, randomUUID } from 'node:crypto'
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest'
import { DATABASE_URL } from '../helpers/db'
import { startHarness, type Client, type Harness } from '../helpers/console-harness'
import { setForgeTransport } from '../../server/forges'
import type { ForgeClient } from '../../server/forges/types'
import { NOSEC_MAX_FILES, readRepoImports, resolveScoped, runImport } from '../../server/imports/service'
import { parseImportFile } from '../../server/imports/repo-files'

const DT_PROJECT = randomUUID()

describe.skipIf(!DATABASE_URL)('reprise de l’existant (PostgreSQL réel)', () => {
  let h: Harness
  let admin: Client
  let operator: Client
  let projectId: string
  let findingId: string
  let token: string
  const seen: { url: string, headers: Headers }[] = []

  beforeAll(async () => {
    h = await startHarness('import')
    admin = await h.login('iadmin', 'admin')
    operator = await h.login('ioperator', 'operator')
    const p = await h.db.pool.query<{ id: string }>(
      `INSERT INTO projects (slug, name, source_kind, profile_id, gate_id, default_branch)
       VALUES ('depot-import', 'Dépôt import', 'archive', (SELECT id FROM profiles WHERE slug = 'complet'),
               (SELECT id FROM gates WHERE slug = 'defaut'), 'main') RETURNING id`)
    projectId = p.rows[0]!.id
    const f = await h.db.pool.query<{ id: string }>(
      `INSERT INTO findings (project_id, fingerprint, tool, rule_id, category, severity, title, path, start_line)
       VALUES ($1, encode(sha256(gen_random_uuid()::text::bytea), 'hex'), 'sonar-scanner', 'typescript:S2068', 'sast', 'high', 'Mot de passe', 'src/config.ts', 3)
       RETURNING id::text`, [projectId])
    findingId = f.rows[0]!.id
    token = randomBytes(20).toString('hex')
    setForgeTransport(async (url, init) => {
      seen.push({ url, headers: new Headers(init.headers) })
      const u = new URL(url)
      const json = (v: unknown) => new Response(JSON.stringify(v), { status: 200, headers: { 'content-type': 'application/json' } })
      if (u.host === 'sonar.exemple.test') {
        return json({
          paging: { total: 2 },
          issues: [
            { rule: 'typescript:S2068', component: 'exemple:src/config.ts', resolution: 'FALSE-POSITIVE', message: 'Valeur de test' },
            { rule: 'typescript:S1234', component: 'exemple:src/autre.ts', resolution: 'WONTFIX' },
          ],
        })
      }
      if (u.host === 'dtrack.exemple.test') {
        return json([
          { analysis: { state: 'NOT_AFFECTED', isSuppressed: true }, vulnerability: { vulnId: 'CVE-2026-1111' }, component: { name: 'lodash' } },
          { analysis: { state: 'EXPLOITABLE' }, vulnerability: { vulnId: 'CVE-2026-2222' } },
          { analysis: { state: 'FALSE_POSITIVE' }, vulnerability: { vulnId: 'MAL-2026-9' } },
          { analysis: { isSuppressed: true }, vulnerability: { vulnId: '<script>' } },
        ])
      }
      if (u.host === 'dojo.exemple.test') {
        const fp = u.searchParams.get('false_p') === 'true'
        return json({
          next: null,
          results: fp
            ? [{ id: 1, vulnerability_ids: [{ vulnerability_id: 'GHSA-aaaa-bbbb-cccc' }], component_name: 'left-pad', title: 'Prototype' }]
            : [{ id: 2, file_path: 'src/config.ts', vuln_id_from_tool: 'typescript:S2068', title: 'Accepté' }, { id: 1 }, { id: 3, title: 'Inconnu' }],
        })
      }
      if (u.host === 'down.exemple.test') return new Response('nope', { status: 500 })
      return new Response('not found', { status: 404 })
    })
  })
  afterEach(() => {
    seen.length = 0
  })
  afterAll(async () => {
    setForgeTransport()
    await h?.close()
  })

  const preview = (json: Record<string, unknown>, client = admin) => h.call(`/api/projects/${projectId}/imports/preview`, { method: 'POST', client, json })
  const apply = (json: Record<string, unknown>, client = admin) => h.call(`/api/projects/${projectId}/imports/apply`, { method: 'POST', client, json })
  const tokens = async () => (await h.db.pool.query(`SELECT id FROM credentials WHERE username = 'scanoria-import'`)).rowCount

  it('droits et validation', async () => {
    expect((await preview({ repo: false }, operator)).status).toBe(403)
    expect((await preview({ repo: false })).status).toBe(400)
    expect((await preview({ repo: false, instance: { kind: 'sonarqube', base_url: 'ftp://sonar.exemple.test', project: 'x', token } })).status).toBe(400)
    expect((await preview({ repo: false, expires_on: '2020-01-01', instance: { kind: 'sonarqube', base_url: 'https://sonar.exemple.test', project: 'exemple', token } })).status).toBe(400)
    // Archive : pas de dépôt à lire.
    expect((await preview({ repo: true })).status).toBeGreaterThanOrEqual(400)
  })

  it('SonarQube : aperçu sans écriture, jeton chiffré, puis application', async () => {
    const p = await preview({ repo: false, instance: { kind: 'sonarqube', base_url: 'https://sonar.exemple.test', project: 'exemple', token } })
    expect(p.status, JSON.stringify(p.data)).toBe(200)
    expect(seen[0]!.headers.get('authorization')).toBe(`Bearer ${token}`)
    expect(p.data.requests).toEqual([expect.objectContaining({ kind: 'finding', target: { finding_id: findingId }, status: 'new' })])
    expect(p.data.unsupported).toHaveLength(1)
    expect(p.data.import_token).toMatch(/^[0-9a-f-]{36}$/)
    expect(p.text).not.toContain(token)
    expect((await h.db.pool.query('SELECT 1 FROM exceptions WHERE project_id = $1', [projectId])).rowCount).toBe(0)
    expect(await tokens()).toBe(1)

    const a = await apply({ repo: false, instance: { kind: 'sonarqube', base_url: 'https://sonar.exemple.test', project: 'exemple' }, import_token: p.data.import_token })
    expect(a.status, JSON.stringify(a.data)).toBe(200)
    expect(a.data.outcome.created).toHaveLength(1)
    expect(await tokens()).toBe(0)
    const ex = await h.db.pool.query(`SELECT status, requested_via, requester_is_human, decided_at, reason FROM exceptions WHERE project_id = $1`, [projectId])
    expect(ex.rows[0]).toMatchObject({ status: 'requested', requested_via: 'tool-import', requester_is_human: false, decided_at: null })
    expect(ex.rows[0].reason).toContain('importé (sonarqube)')
    const audit = await h.db.pool.query<{ details: Record<string, unknown> }>(`SELECT details FROM audit_log WHERE action = 'project.import' AND target_id = $1`, [projectId])
    expect(audit.rowCount).toBe(1)
    expect(JSON.stringify(audit.rows[0]!.details)).not.toContain(token)
    // Jeton déjà effacé : un second import doit refuser.
    expect((await apply({ repo: false, instance: { kind: 'sonarqube', base_url: 'https://sonar.exemple.test', project: 'exemple' }, import_token: p.data.import_token })).status).toBeGreaterThanOrEqual(400)
  })

  it('Dependency-Track : clé d’API, états non exploitables seulement, MAL- refusé', async () => {
    const p = await preview({ repo: false, instance: { kind: 'dependency-track', base_url: 'https://dtrack.exemple.test', project: DT_PROJECT, token } })
    expect(p.status, JSON.stringify(p.data)).toBe(200)
    expect(seen[0]!.headers.get('x-api-key')).toBe(token)
    expect(seen[0]!.headers.get('authorization')).toBeNull()
    expect(p.data.requests.map((r: { target: unknown, status: string }) => [r.target, r.status])).toEqual([
      [{ vuln_id: 'CVE-2026-1111', package: 'lodash' }, 'new'],
      [{ vuln_id: 'MAL-2026-9' }, 'malicious'],
    ])
    expect(p.data.unsupported).toHaveLength(1)
    const a = await apply({ repo: false, instance: { kind: 'dependency-track', base_url: 'https://dtrack.exemple.test', project: DT_PROJECT }, import_token: p.data.import_token })
    expect(a.data.outcome.created).toHaveLength(1)
    expect((await h.db.pool.query(`SELECT 1 FROM exceptions WHERE target->>'vuln_id' LIKE 'MAL-%'`)).rowCount).toBe(0)
  })

  it('DefectDojo : faux positifs et risques acceptés, dédoublonnés', async () => {
    const p = await preview({ repo: false, instance: { kind: 'defectdojo', base_url: 'https://dojo.exemple.test', project: '42', token } })
    expect(p.status).toBe(200)
    expect(seen[0]!.headers.get('authorization')?.toLowerCase()).toBe(`token ${token}`)
    expect(p.data.requests.map((r: { kind: string, status: string }) => [r.kind, r.status])).toEqual([['vuln', 'new'], ['finding', 'duplicate']])
    expect(p.data.unsupported).toHaveLength(1)
    await apply({ repo: false, instance: { kind: 'defectdojo', base_url: 'https://dojo.exemple.test', project: '42' }, import_token: p.data.import_token })
    expect(await tokens()).toBe(0)
  })

  it('instance en erreur : aucun jeton conservé', async () => {
    const r = await preview({ repo: false, instance: { kind: 'sonarqube', base_url: 'https://down.exemple.test', project: 'x', token } })
    expect(r.status).toBeGreaterThanOrEqual(400)
    expect(r.text).not.toContain(token)
    expect(await tokens()).toBe(0)
  })

  it('identifiants de projet invalides signalés', async () => {
    const dt = await preview({ repo: false, instance: { kind: 'dependency-track', base_url: 'https://dtrack.exemple.test', project: 'pas-un-uuid', token } })
    expect(dt.data.unsupported[0].entry).toBe('project must be a UUID')
    const dd = await preview({ repo: false, instance: { kind: 'defectdojo', base_url: 'https://dojo.exemple.test', project: 'abc', token } })
    expect(dd.data.unsupported[0].entry).toBe('product must be a numeric id')
    expect(seen).toHaveLength(0)
  })

  describe('fichiers du dépôt', () => {
    const files: Record<string, string> = {
      '.gitleaks.toml': '[allowlist]\npaths = [\'\'\'^tests/fixtures/.*$\'\'\']\n',
      '.trivyignore': 'CVE-2026-4242\n',
      'osv-scanner.toml': '[[IgnoredVulns]]\nid = "GHSA-2345-6789-cfgh"\nreason = "x"\n',
      'app/db.py': 'q = 1  # nosec B608\n',
      'big.py': 'print(1)\n',
    }
    const client = (opts: { truncated?: boolean, py?: number, tooLarge?: string[] } = {}): ForgeClient => ({
      kind: 'forgejo',
      check: async () => ({ login: null }),
      listRepos: async () => [],
      repo: async () => { throw new Error('unused') },
      branches: async () => ['main'],
      latestCommit: async () => 'a'.repeat(40),
      listTree: async () => ({
        truncated: !!opts.truncated,
        entries: [
          ...Object.keys(files).map(path => ({ path, type: 'file' as const, size: files[path]!.length })),
          { path: 'tests', type: 'dir' as const, size: null },
          { path: '.venv/lib/x.py', type: 'file' as const, size: 1 },
          ...Array.from({ length: opts.py ?? 0 }, (_, i) => ({ path: `gen/m${i}.py`, type: 'file' as const, size: 100 + i })),
        ],
      }),
      readFile: async (_r, _ref, path) => (opts.tooLarge?.includes(path) ? null : files[path] ?? ''),
    })

    it('lit les fichiers repérés et les « # nosec », signale ce qui n’est pas lu', async () => {
      const r = await readRepoImports({ client: client({ truncated: true, py: NOSEC_MAX_FILES, tooLarge: ['.trivyignore'] }), fullName: 'equipe/depot', ref: 'main' }, '2027-02-23')
      expect(r.requests.map(q => [q.kind, q.target])).toEqual([
        ['path', { glob: 'tests/fixtures/**', tool: 'gitleaks' }],
        ['vuln', { vuln_id: 'GHSA-2345-6789-cfgh' }],
        ['path', { glob: 'app/db.py', tool: 'bandit' }],
      ])
      expect(r.requests[2]!.match).toEqual({ tool: 'bandit', glob: 'app/db.py', line: 1, rules: ['B608'] })
      expect(r.sources.map(s => s.source)).toEqual(['.gitleaks.toml', 'osv-scanner.toml', '# nosec'])
      expect(r.unsupported).toEqual(expect.arrayContaining([
        { source: '.trivyignore', entry: 'file too large' },
        { source: 'tree', entry: 'repository tree truncated' },
        expect.objectContaining({ source: '# nosec' }),
      ]))
    })

    it('application : demandes déposées, dates bornées, source absente refusée', async () => {
      // Résultats Bandit : celui de la ligne marquée (repris) et un autre du même fichier (jamais exempté).
      const ins = (rule: string, line: number) => h.db.pool.query<{ id: string }>(
        `INSERT INTO findings (project_id, fingerprint, tool, rule_id, category, severity, title, path, start_line)
         VALUES ($1, encode(sha256(gen_random_uuid()::text::bytea), 'hex'), 'bandit', $2, 'sast', 'medium', 'x', 'app/db.py', $3)
         RETURNING id::text`, [projectId, rule, line])
      const banditId = (await ins('B608', 1)).rows[0]!.id
      await ins('B602', 7)
      const repo = { client: client(), fullName: 'equipe/depot', ref: 'main' }
      const dry = await runImport(h.db.pool, { projectId, repo, instance: null, userId: 1, dryRun: true })
      // Aperçu : ce qui serait créé, sans identifiant, rien en base.
      expect(dry.outcome.created.every(c => c.id === '')).toBe(true)
      const before = (await h.db.pool.query('SELECT 1 FROM exceptions WHERE project_id = $1', [projectId])).rowCount!
      const fresh = dry.requests.filter(r => r.status === 'new').length
      expect(fresh).toBeGreaterThan(0)
      const done = await runImport(h.db.pool, { projectId, repo, instance: null, userId: 1, dryRun: false })
      expect(done.outcome.created).toHaveLength(fresh)
      expect((await h.db.pool.query('SELECT 1 FROM exceptions WHERE project_id = $1', [projectId])).rowCount).toBe(before + fresh)
      const rows = await h.db.pool.query<{ requested_via: string, status: string, reason: string }>(
        `SELECT requested_via, status, reason FROM exceptions WHERE project_id = $1 AND requested_via = 'tool-import'`, [projectId])
      expect(rows.rows.every(r => r.status === 'requested' && r.reason.startsWith('importé ('))).toBe(true)
      expect(rows.rows.map(r => r.reason)).toEqual(expect.arrayContaining(['importé (osv-scanner.toml) : x', 'importé (# nosec) : app/db.py:1 (B608)']))
      // « # nosec » : une demande sur le résultat Bandit de la ligne, jamais une exception du fichier entier.
      const nosec = await h.db.pool.query<{ kind: string, target: { finding_id?: string } }>(
        `SELECT kind, target FROM exceptions WHERE project_id = $1 AND reason LIKE 'importé (# nosec)%'`, [projectId])
      expect(nosec.rows).toEqual([{ kind: 'finding', target: { finding_id: banditId } }])
      await expect(runImport(h.db.pool, { projectId, repo: null, instance: null, userId: 1, dryRun: true })).rejects.toThrow('E_IMPORT_NO_SOURCE')
      await expect(runImport(h.db.pool, { projectId, repo, instance: null, userId: 1, dryRun: true, expiresOn: '2099-01-01' })).rejects.toThrow('E_IMPORT_DATE')
      await expect(runImport(h.db.pool, { projectId, repo: null, instance: { kind: 'sonarqube', base_url: 'https://sonar.exemple.test', project: 'x' }, userId: 1, dryRun: false })).rejects.toThrow('E_IMPORT_TOKEN')
    })

    it('projet sur archive : la lecture du dépôt est refusée par l’API', async () => {
      const r = await preview({ repo: true })
      expect(r.data.data.code).toBe('E_IMPORT_NO_SOURCE')
    })
  })
  it('portée combinée (chemin ET règle) : seulement les résultats qui y correspondent, sinon non traduite', async () => {
    const ins = (tool: string, rule: string, path: string) => h.db.pool.query<{ id: string }>(
      `INSERT INTO findings (project_id, fingerprint, tool, rule_id, category, severity, title, path, start_line)
       VALUES ($1, encode(sha256(gen_random_uuid()::text::bytea), 'hex'), $2, $3, 'secrets', 'high', 'x', $4, 1)
       RETURNING id::text`, [projectId, tool, rule, path])
    const hit = (await ins('gitleaks', 'generic-api-key', 'docs/guide.md')).rows[0]!.id
    await ins('gitleaks', 'private-key', 'docs/cle.pem')
    await ins('gitleaks', 'generic-api-key', 'src/app.ts')
    const parsed = parseImportFile('.gitleaks.toml', `
[[allowlists]]
targetRules = ["generic-api-key"]
paths = ['''^docs/''']
[[allowlists]]
targetRules = ["aws-access-token"]
paths = ['''^infra/''']
`, '2027-02-23')
    await resolveScoped(h.db.pool, projectId, parsed)
    expect(parsed.requests.map(r => [r.kind, r.target])).toEqual([['finding', { finding_id: hit }]])
    expect(parsed.unsupported.map(u => u.entry)).toEqual(['no matching finding: gitleaks aws-access-token infra/**'])
  })
})
