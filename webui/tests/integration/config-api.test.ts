// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Configuration en code (J8) contre un vrai PostgreSQL 16 : .scanoria.yml lu à
// chaque analyse (demandes, jamais d'approbation ; fichier invalide signalé,
// configuration précédente conservée ; profil par déclencheur) et export /
// import de la configuration de l'appliance (aucun secret, aperçu des écarts,
// empreinte, audit).

import { randomBytes } from 'node:crypto'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { DATABASE_URL } from '../helpers/db'
import { startHarness, type Client, type Harness } from '../helpers/console-harness'
import { appliedConfig, parseConfigState, refreshRepoConfig } from '../../server/config/refresh'
import { RepoConfigPending, planProfile } from '../../server/profiles/plan-profile'
import { encryptSecret } from '../../server/utils/secrets'
import { parse, stringify } from 'yaml'
import { GateRules } from '#shared/analysis'

const NOW = new Date('2026-11-25T08:00:00Z')

describe.skipIf(!DATABASE_URL)('configuration en code (PostgreSQL réel)', () => {
  let h: Harness
  let admin: Client
  let operator: Client
  let projectId: string

  beforeAll(async () => {
    h = await startHarness('config')
    admin = await h.login('cadmin', 'admin')
    operator = await h.login('coperator', 'operator')
    const r = await h.db.pool.query<{ id: string }>(
      `INSERT INTO projects (slug, name, source_kind, profile_id, gate_id, default_branch)
       VALUES ('depot-config', 'Dépôt config', 'archive', (SELECT id FROM profiles WHERE slug = 'complet'),
               (SELECT id FROM gates WHERE slug = 'defaut'), 'main') RETURNING id`)
    projectId = r.rows[0]!.id
  })
  afterAll(async () => {
    await h?.close()
  })

  describe('.scanoria.yml', () => {
    const GOOD = [
      'version: 1',
      'profiles:',
      '  pr: rapide',
      '  nightly: inexistant',
      'exceptions:',
      '  - kind: path',
      '    path: "tests/fixtures/**"',
      '    reason: Jeux d\'essai volontairement vulnérables',
      '    until: 2027-03-01',
      '  - kind: vuln',
      '    vuln: MAL-2026-1',
      '    reason: Paquet malveillant à garder',
      '    until: 2027-01-01',
      'ignore:',
      '  - "docs/**"',
    ].join('\n')

    it('fichier valide : état ok, demandes déposées sans approbation, profil inconnu signalé', async () => {
      const s = await refreshRepoConfig(h.db.pool, projectId, 'a'.repeat(40), async () => GOOD, NOW)
      expect(s.status).toBe('ok')
      expect(s.issues).toEqual([{ path: 'profiles.nightly', message: 'unknown profile' }])
      const ex = await h.db.pool.query<{ kind: string, status: string, requested_via: string, requester_is_human: boolean, decided_at: string | null, target: { glob?: string } }>(
        `SELECT kind, status, requested_via, requester_is_human, decided_at, target FROM exceptions WHERE project_id = $1 ORDER BY id`, [projectId])
      expect(ex.rows.length).toBe(2)
      for (const r of ex.rows) {
        expect(r).toMatchObject({ status: 'requested', requested_via: 'config', requester_is_human: false, decided_at: null })
      }
      expect(ex.rows.map(r => r.target.glob).sort()).toEqual(['docs/**', 'tests/fixtures/**'])
      // MAL- : jamais d'exception (H4), même demandée.
      expect(s.requests).toEqual({ created: 2, skipped: 1 })
      const audit = await h.db.pool.query(`SELECT 1 FROM audit_log WHERE action = 'config.requests' AND target_id = $1`, [projectId])
      expect(audit.rowCount).toBe(1)
    })

    it('relecture identique : aucune demande en double', async () => {
      const s = await refreshRepoConfig(h.db.pool, projectId, 'b'.repeat(40), async () => GOOD, NOW)
      expect(s.requests).toEqual({ created: 0, skipped: 3 })
      expect((await h.db.pool.query('SELECT 1 FROM exceptions WHERE project_id = $1', [projectId])).rowCount).toBe(2)
    })

    it('profil appliqué par emplacement ; inconnu ignoré ; couverture notée', async () => {
      const st = (await h.db.pool.query('SELECT config_state FROM projects WHERE id = $1', [projectId])).rows[0].config_state
      expect(appliedConfig(st, 'pr').profileSlug).toBe('rapide')
      expect(appliedConfig(st, 'nightly').profileSlug).toBeNull()
      expect(appliedConfig(st, 'pr').coverage).toMatchObject({ status: 'ok', ignored: ['docs/**'], profile: 'rapide' })
      expect(appliedConfig(null, 'pr')).toEqual({ profileSlug: null, coverage: null })

      const scan = await h.db.pool.query<{ id: string }>(
        `INSERT INTO scans (project_id, number, trigger, priority, ref, profile_id, gate_id, status, pull_request)
         SELECT id, 1, 'webhook', 50, 'main', profile_id, gate_id, 'queued', '{"number":7,"base_sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}'::jsonb FROM projects WHERE id = $1 RETURNING id`, [projectId])
      const { profile, config } = await planProfile(h.db.pool, { id: scan.rows[0]!.id, project_id: projectId, trigger: 'webhook', profile_id: (await h.db.pool.query('SELECT profile_id FROM projects WHERE id = $1', [projectId])).rows[0].profile_id, pull_request: { number: 7 } })
      expect(profile.slug).toBe('rapide')
      expect(profile.source).toBe('config')
      expect(config?.profile).toBe('rapide')
      // Le dépôt ne fait qu'ajouter : rien du profil de l'emplacement (complet) n'est retiré.
      const slotCats = (await h.db.pool.query<{ categories: string[] }>(`SELECT categories FROM profiles WHERE slug = 'complet'`)).rows[0]!.categories
      expect(profile.categories).toEqual(expect.arrayContaining(slotCats))
      const saved = await h.db.pool.query<{ slug: string }>('SELECT p.slug FROM scans s JOIN profiles p ON p.id = s.profile_id WHERE s.id = $1', [scan.rows[0]!.id])
      expect(saved.rows[0]!.slug).toBe('rapide')
    })

    it('analyse d’un autre commit : le plan attend la lecture de sa propre configuration', async () => {
      const f = await h.db.pool.query<{ id: string }>(
        `INSERT INTO forges (kind, name, base_url) VALUES ('forgejo', 'forge-config', 'https://forge.exemple.test') RETURNING id::text`)
      const p = await h.db.pool.query<{ id: string }>(
        `INSERT INTO projects (slug, name, source_kind, repo_url, forge_id, repo_full_name, profile_id, gate_id, default_branch)
         VALUES ('depot-config-git', 'Dépôt config git', 'git', 'https://forge.exemple.test/equipe/config.git', $1, 'equipe/config',
                 (SELECT id FROM profiles WHERE slug = 'complet'), (SELECT id FROM gates WHERE slug = 'defaut'), 'main') RETURNING id::text`, [f.rows[0]!.id])
      const pid = p.rows[0]!.id
      const scan = async (sha: string) => (await h.db.pool.query<{ id: string, profile_id: string }>(
        `INSERT INTO scans (project_id, number, trigger, priority, ref, commit_sha, profile_id, gate_id, status)
         SELECT id, (SELECT count(*) + 1 FROM scans WHERE project_id = $1), 'manual', 50, 'main', $2, profile_id, gate_id, 'queued'
           FROM projects WHERE id = $1 RETURNING id::text, profile_id::text`, [pid, sha])).rows[0]!
      const a = await scan('1'.repeat(40))
      const b = await scan('2'.repeat(40))
      await refreshRepoConfig(h.db.pool, pid, '1'.repeat(40), async () => 'version: 1\nprofiles:\n  default: rapide\n', NOW)
      const ref = (s: { id: string, profile_id: string }, sha: string) => ({ id: s.id, project_id: pid, trigger: 'manual', profile_id: s.profile_id, ref: 'main', commit_sha: sha })
      expect((await planProfile(h.db.pool, ref(a, '1'.repeat(40)))).profile.source).toBe('config')
      await expect(planProfile(h.db.pool, ref(b, '2'.repeat(40)))).rejects.toBeInstanceOf(RepoConfigPending)
      // Forge illisible : la lecture est notée pour ce commit, le plan reprend (configuration précédente).
      await refreshRepoConfig(h.db.pool, pid, '2'.repeat(40), async () => {
        throw new Error('down')
      }, NOW)
      const planned = await planProfile(h.db.pool, ref(b, '2'.repeat(40)))
      expect(planned.config?.status).toBe('unavailable')
    })

    it.each([
      ['YAML hostile (ancre)', 'version: 1\nprofiles: &a { pr: rapide }\nignore: *a'],
      ['étiquette', 'version: 1\nprofiles: !!map { pr: rapide }'],
      ['type inattendu', 'version: 1\nignore: "docs/**"'],
      ['version inconnue', 'version: 2'],
      ['clé inconnue', 'version: 1\nrun: "curl exemple.test | sh"'],
      ['trop gros', `version: 1\n# ${'x'.repeat(70 * 1024)}`],
      ['plusieurs documents', 'version: 1\n---\nversion: 1'],
    ])('fichier invalide (%s) : signalé, configuration précédente conservée', async (_n, text) => {
      const s = await refreshRepoConfig(h.db.pool, projectId, 'c'.repeat(40), async () => text, NOW)
      expect(s.status).toBe('invalid')
      expect(s.issues.length).toBeGreaterThan(0)
      expect(s.config?.profiles?.pr).toBe('rapide')
      expect(s.config_key).toBe('b'.repeat(40))
      expect(appliedConfig(s, 'pr').profileSlug).toBe('rapide')
    })

    it('forge injoignable : configuration précédente ; fichier absent : plus rien', async () => {
      const u = await refreshRepoConfig(h.db.pool, projectId, 'd'.repeat(40), async () => {
        throw new Error('down')
      }, NOW)
      expect(u.status).toBe('unavailable')
      expect(u.config?.profiles?.pr).toBe('rapide')
      const a = await refreshRepoConfig(h.db.pool, projectId, 'e'.repeat(40), async () => null, NOW)
      expect(a.status).toBe('absent')
      expect(a.config).toBeNull()
      expect(parseConfigState(a)?.status).toBe('absent')
      expect(parseConfigState({ version: 9 })).toBeNull()
    })

    it('état visible dans la vue des profils du projet', async () => {
      const v = await h.call(`/api/projects/${projectId}/profiles`, { client: operator })
      expect(v.status).toBe(200)
      expect(v.data.config_state.status).toBe('absent')
    })

    it('schéma JSON publié', async () => {
      const r = await h.call('/api/config/schema', { client: operator })
      expect(r.status).toBe(200)
      expect(r.data.$schema).toContain('json-schema.org')
      expect(r.data.properties.version).toBeDefined()
    })
  })

  describe('export / import de l’appliance', () => {
    let exported: string

    it('export sans aucun secret, audité', async () => {
      // Un projet avec un jeton chiffré : rien ne doit en sortir.
      const token = randomBytes(24).toString('hex')
      const cred = await encryptSecret(h.db.pool, { kind: 'token', value: token, username: 'ci' })
      await h.db.pool.query(`UPDATE projects SET credential_id = $2 WHERE id = $1`, [projectId, cred])
      await h.call('/api/profiles', { method: 'POST', client: admin, json: { slug: 'entreprise', level: 'enterprise', categories: ['secrets'], locks: { gate_floor: { max_secrets: 0 } } } })
      await h.call('/api/profiles', { method: 'POST', client: admin, json: { slug: 'equipe', level: 'team', parent_id: (await h.db.pool.query(`SELECT id FROM profiles WHERE slug = 'entreprise'`)).rows[0].id } })
      expect((await h.call('/api/config/export', { client: operator })).status).toBe(403)
      const r = await h.call('/api/config/export', { client: admin })
      expect(r.status).toBe(200)
      exported = r.data.yaml
      expect(r.data.filename).toMatch(/^scanoria-config-\d{4}-\d{2}-\d{2}\.yml$/)
      expect(exported).toContain('scanoria_config: 1')
      expect(exported).toContain('depot-config')
      expect(exported).not.toContain(token)
      expect(exported).not.toMatch(/credential|password|secret:|token:/i)
      expect((await h.db.pool.query(`SELECT 1 FROM audit_log WHERE action = 'config.export'`)).rowCount).toBe(1)
    })

    it('réimport identique : aucun changement', async () => {
      const r = await h.call('/api/config/import/preview', { method: 'POST', client: admin, json: { yaml: exported } })
      expect(r.status, JSON.stringify(r.data)).toBe(200)
      expect(r.data.issues).toEqual([])
      expect(r.data.changes.filter((c: { action: string }) => c.action !== 'unchanged')).toEqual([])
    })

    it('aperçu des écarts, empreinte exigée, application auditée', async () => {
      const changed = exported
        .replace('slug: equipe\n', 'slug: equipe\n')
        .concat('')
      const doc = changed.replace(/(slug: equipe\n(?:.*\n)*?\s+description: )null/, '$1Équipe web')
      const withNew = doc.replace('profiles:\n', 'profiles:\n  - slug: importe\n    level: enterprise\n    parent: null\n    categories: [sca]\n    include_modules: []\n    exclude_modules: []\n    description: null\n    locks: {}\n    rulesets: []\n')
      const p = await h.call('/api/config/import/preview', { method: 'POST', client: admin, json: { yaml: withNew } })
      expect(p.status, JSON.stringify(p.data)).toBe(200)
      expect(p.data.changes).toEqual(expect.arrayContaining([expect.objectContaining({ section: 'profiles', key: 'importe', action: 'create' })]))
      // Empreinte d'un autre texte : refusée.
      const bad = await h.call('/api/config/import/apply', { method: 'POST', client: admin, json: { yaml: withNew, digest: '0'.repeat(64) } })
      expect(bad.status).toBe(409)
      expect((await h.call('/api/config/import/apply', { method: 'POST', client: operator, json: { yaml: withNew, digest: p.data.digest } })).status).toBe(403)
      const ok = await h.call('/api/config/import/apply', { method: 'POST', client: admin, json: { yaml: withNew, digest: p.data.digest } })
      expect(ok.status, JSON.stringify(ok.data)).toBe(200)
      expect((await h.db.pool.query(`SELECT categories FROM profiles WHERE slug = 'importe'`)).rows[0].categories).toEqual(['sca'])
      const audit = await h.db.pool.query<{ outcome: string }>(`SELECT outcome FROM audit_log WHERE action = 'config.import' ORDER BY id`)
      expect(audit.rows.map(a => a.outcome)).toEqual(['failure', 'success'])
    })

    it('verrous respectés à l’import : un enfant plus souple est refusé', async () => {
      const loose = exported.replace('profiles:\n', 'profiles:\n  - slug: souple\n    level: team\n    parent: entreprise\n    categories: []\n    include_modules: []\n    exclude_modules: []\n    description: null\n    locks: { gate_floor: { max_secrets: 9 } }\n    rulesets: []\n')
      const p = await h.call('/api/config/import/preview', { method: 'POST', client: admin, json: { yaml: loose } })
      expect(p.status).toBe(200)
      expect(p.data.issues.length).toBeGreaterThan(0)
      const a = await h.call('/api/config/import/apply', { method: 'POST', client: admin, json: { yaml: loose, digest: p.data.digest } })
      expect(a.status).toBe(422)
      expect((await h.db.pool.query(`SELECT 1 FROM profiles WHERE slug = 'souple'`)).rowCount).toBe(0)
    })

    it('import de chaque section : jeu de règles, gate, profil, gravité, projet, règle de tri', async () => {
      const cfg = parse((await h.call('/api/config/export', { client: admin })).data.yaml)
      cfg.rulesets.push({ slug: 'regles-maison', engine: 'gitleaks', name: 'Règles maison', description: null, content: '[[rules]]\nid = "maison"\nregex = "x"\n' })
      cfg.gates.push({ slug: 'strict', rules: { ...GateRules.parse({}), vuln_block_from: 'medium' } })
      cfg.profiles.push({ slug: 'avec-regles', level: 'enterprise', parent: null, categories: ['secrets'], include_modules: [], exclude_modules: [], description: 'Import', locks: {}, rulesets: [{ slug: 'regles-maison', version: null }] })
      cfg.severity_maps.push({ module: 'trivy', native: 'UNKNOWN', severity: 'low' })
      cfg.projects.push({ slug: 'nouveau-depot', name: 'Nouveau dépôt', source_kind: 'git', repo_url: 'https://forge.exemple.test/equipe/depot.git', default_branch: 'main', profiles: { default: 'avec-regles', pr: 'rapide' }, gate: 'strict' })
      cfg.triage_rules.push({ project: 'nouveau-depot', match: { path: 'tests/**' }, action: 'false-positive', reason: 'Jeux d\'essai', expires_on: '2027-01-15' })
      // Un projet existant change de gate ; un profil existant change de description.
      cfg.projects.find((p: { slug: string }) => p.slug === 'depot-config').gate = 'strict'
      cfg.profiles.find((p: { slug: string }) => p.slug === 'equipe').description = 'Équipe'
      const yaml = stringify(cfg)
      const p = await h.call('/api/config/import/preview', { method: 'POST', client: admin, json: { yaml } })
      expect(p.status, JSON.stringify(p.data)).toBe(200)
      expect(p.data.issues).toEqual([])
      const actions = Object.fromEntries((p.data.changes as { section: string, key: string, action: string }[]).filter(c => c.action !== 'unchanged').map(c => [`${c.section}:${c.key}`, c.action]))
      expect(actions).toMatchObject({
        'rulesets:regles-maison': 'create', 'gates:strict': 'create', 'profiles:avec-regles': 'create', 'profiles:equipe': 'update',
        'severity_maps:trivy/UNKNOWN': 'create', 'projects:nouveau-depot': 'create', 'projects:depot-config': 'update',
      })
      const a = await h.call('/api/config/import/apply', { method: 'POST', client: admin, json: { yaml, digest: p.data.digest } })
      expect(a.status, JSON.stringify(a.data)).toBe(200)
      const q = async (sql: string, args: unknown[] = []) => (await h.db.pool.query(sql, args)).rows
      expect(await q(`SELECT r.engine, v.version FROM rulesets r JOIN ruleset_versions v ON v.ruleset_id = r.id WHERE r.slug = 'regles-maison'`)).toEqual([{ engine: 'gitleaks', version: 1 }])
      expect((await q(`SELECT rules FROM gates WHERE slug = 'strict'`))[0].rules.vuln_block_from).toBe('medium')
      expect(await q(`SELECT r.slug FROM profile_rulesets pr JOIN profiles p ON p.id = pr.profile_id JOIN rulesets r ON r.id = pr.ruleset_id WHERE p.slug = 'avec-regles'`)).toEqual([{ slug: 'regles-maison' }])
      expect((await q(`SELECT severity FROM severity_maps WHERE module_id = 'trivy' AND native = 'UNKNOWN'`))[0].severity).toBe('low')
      const proj = (await q(`SELECT x.id, x.source_kind, g.slug AS gate, pp.slug AS pr FROM projects x JOIN gates g ON g.id = x.gate_id LEFT JOIN profiles pp ON pp.id = x.profile_pr_id WHERE x.slug = 'nouveau-depot'`))[0]
      expect(proj).toMatchObject({ source_kind: 'git', gate: 'strict', pr: 'rapide' })
      expect((await q(`SELECT action FROM triage_rules WHERE project_id = $1`, [proj.id]))[0].action).toBe('false-positive')
      expect((await q(`SELECT g.slug FROM projects x JOIN gates g ON g.id = x.gate_id WHERE x.slug = 'depot-config'`))[0].slug).toBe('strict')
      expect((await q(`SELECT description FROM profiles WHERE slug = 'equipe'`))[0].description).toBe('Équipe')
      // Réimport : tout est inchangé, contenu du jeu de règles compris.
      const again = await h.call('/api/config/import/preview', { method: 'POST', client: admin, json: { yaml: (await h.call('/api/config/export', { client: admin })).data.yaml } })
      expect(again.data.changes.filter((c: { action: string }) => c.action !== 'unchanged')).toEqual([])
    })

    it('problèmes signalés à l’aperçu : références inconnues, sources, triage expiré, empreinte de règles', async () => {
      const cfg = parse((await h.call('/api/config/export', { client: admin })).data.yaml)
      cfg.profiles.push({ slug: 'orphelin', level: 'team', parent: 'absent', categories: [], include_modules: [], exclude_modules: [], description: null, locks: {}, rulesets: [{ slug: 'inconnu', version: null }] })
      cfg.profiles.push({ slug: 'cycle-a', level: 'team', parent: 'cycle-b', categories: [], include_modules: [], exclude_modules: [], description: null, locks: {}, rulesets: [] })
      cfg.profiles.push({ slug: 'cycle-b', level: 'team', parent: 'cycle-a', categories: [], include_modules: [], exclude_modules: [], description: null, locks: {}, rulesets: [] })
      cfg.rulesets.find((r: { slug: string }) => r.slug === 'regles-maison').engine = 'opengrep'
      cfg.rulesets.push({ slug: 'faux', engine: 'gitleaks', name: 'Faux', description: null, content: 'x', sha256: '0'.repeat(64) })
      cfg.projects.push({ slug: 'archive', name: 'Archive', source_kind: 'archive', profiles: { default: 'complet' }, gate: 'defaut' })
      cfg.projects.push({ slug: 'sans-url', name: 'Sans URL', source_kind: 'git', profiles: { default: 'inconnu' }, gate: 'inconnu' })
      cfg.projects.find((p: { slug: string }) => p.slug === 'depot-config').source_kind = 'git'
      cfg.triage_rules.push({ project: 'absent', match: {}, action: 'accepted', reason: 'Motif', expires_on: '2020-01-01' })
      cfg.triage_rules.push({ project: 'absent', match: {}, action: 'accepted', reason: 'Motif', expires_on: '2027-01-01' })
      const p = await h.call('/api/config/import/preview', { method: 'POST', client: admin, json: { yaml: stringify(cfg) } })
      expect(p.status, JSON.stringify(p.data)).toBe(200)
      const paths = (p.data.issues as { path: string }[]).map(i => i.path)
      expect(paths).toEqual(expect.arrayContaining([
        'profiles.orphelin.parent', 'profiles.orphelin.rulesets', 'rulesets.regles-maison.engine', 'rulesets.faux.sha256',
        'projects.archive', 'projects.sans-url.repo_url', 'projects.sans-url.profiles.default', 'projects.sans-url.gate',
        'projects.depot-config', 'triage_rules.1.expires_on', 'triage_rules.2.project',
      ]))
      expect(paths.some(x => x.startsWith('profiles.cycle-'))).toBe(true)
    })

    it.each([
      ['ancres', 'scanoria_config: 1\nexported_at: 2026-11-25T00:00:00Z\nprofiles: &p []\ngates: *p\nrulesets: []\nseverity_maps: []\ntriage_rules: []\nprojects: []'],
      ['bombe d’alias', `a: &a [x, x]\nb: &b [*a, *a]\nc: [*b, *b]`],
      ['étiquette', 'scanoria_config: !!str 1'],
      ['secret glissé', 'scanoria_config: 1\nexported_at: 2026-11-25T00:00:00Z\nprofiles: []\ngates: []\nrulesets: []\nseverity_maps: []\ntriage_rules: []\nprojects: []\ncredentials: [{ token: abc }]'],
      ['pas un objet', '- 1\n- 2'],
      ['YAML cassé', 'scanoria_config: [1'],
    ])('import hostile refusé (%s)', async (_n, text) => {
      const r = await h.call('/api/config/import/preview', { method: 'POST', client: admin, json: { yaml: text } })
      expect(r.status).toBe(422)
      expect(r.data.data.code).toBe('E_CONFIG_INVALID')
    })
  })
})
