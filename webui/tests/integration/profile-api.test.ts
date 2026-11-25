// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Profils (0.7, chantier C) contre un vrai PostgreSQL 16 : hiérarchie et
// cycles (G8), chaque verrou (contrat 28), gate durci et rejeu d'un plan
// d'avant la 0.7 (G11), profil par déclencheur (G9, contrat 29), « aucun envoi
// à l'IA » imposé, aperçu (G10), archivage, audit.

import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { DATABASE_URL } from '../helpers/db'
import { startHarness, type Client, type Harness } from '../helpers/console-harness'
import { enqueueScan } from '../../server/scans/enqueue'
import { evaluateGate } from '../../server/gates/evaluate'
import { effectiveProfile, resolveProfile } from '../../server/profiles/resolve'
import { planProfile } from '../../server/profiles/plan-profile'
import { aiOptOutLocked } from '../../server/profiles/service'

const PLAN_GATE = { new_code_only: true, max_secrets: 0, vuln_block_from: 'high', sast_block_from: 'high', iac_block_from: 'high', block_malicious: true, inconclusive_blocks: true }

describe.skipIf(!DATABASE_URL)('profils (PostgreSQL réel)', () => {
  let h: Harness
  let admin: Client
  let operator: Client
  let viewer: Client
  const ids = {} as Record<'rapide' | 'complet' | 'release' | 'entreprise' | 'equipe' | 'projet' | 'sous', string>

  const create = (json: Record<string, unknown>, client = admin) => h.call('/api/profiles', { method: 'POST', client, json })
  const patch = (id: string, json: Record<string, unknown>, client = admin) => h.call(`/api/profiles/${id}`, { method: 'PATCH', client, json })
  const code = (r: { data: Record<string, unknown> }) => (r.data as { data?: { code?: string } }).data?.code

  async function newProject(slug: string): Promise<string> {
    const r = await h.db.pool.query<{ id: string }>(
      `INSERT INTO projects (slug, name, source_kind, profile_id, gate_id, default_branch)
       VALUES ($1, $1, 'archive', $2, (SELECT id FROM gates WHERE slug = 'defaut'), 'main') RETURNING id`, [slug, ids.complet])
    return r.rows[0]!.id
  }

  beforeAll(async () => {
    h = await startHarness('profiles')
    admin = await h.login('padmin', 'admin')
    operator = await h.login('poperator', 'operator')
    viewer = await h.login('pviewer', 'viewer')
    for (const r of (await h.db.pool.query<{ id: string, slug: string }>('SELECT id::text, slug FROM profiles')).rows) (ids as Record<string, string>)[r.slug] = r.id
  })
  afterAll(async () => {
    await h?.close()
  })

  describe('hiérarchie (G8)', () => {
    it('crée entreprise → équipe → projet ; refuse un parent de mauvais niveau', async () => {
      const ent = await create({ slug: 'entreprise', level: 'enterprise', categories: ['secrets'], locks: { required_categories: ['secrets'], gate_floor: { max_secrets: 0, vuln_block_from: 'high' } } })
      expect(ent.status, JSON.stringify(ent.data)).toBe(201)
      ids.entreprise = ent.data.id
      const team = await create({ slug: 'equipe-web', level: 'team', parent_id: ids.entreprise, categories: ['sca'], include_modules: ['trivy'] })
      expect(team.status).toBe(201)
      ids.equipe = team.data.id
      const proj = await create({ slug: 'projet-web', level: 'project', parent_id: ids.equipe, categories: ['iac'] })
      expect(proj.status).toBe(201)
      ids.projet = proj.data.id
      expect(proj.data.parent_slug).toBe('equipe-web')

      expect(code(await create({ slug: 'sans-parent', level: 'team' }))).toBe('E_PROFILE_PARENT')
      expect(code(await create({ slug: 'ent-parent', level: 'enterprise', parent_id: ids.entreprise }))).toBe('E_PROFILE_PARENT')
      expect(code(await create({ slug: 'team-sous-projet', level: 'team', parent_id: ids.projet }))).toBe('E_PROFILE_LEVEL')
      expect(code(await create({ slug: 'team-sous-team', level: 'team', parent_id: ids.equipe }))).toBe('E_PROFILE_LEVEL')
      expect((await create({ slug: 'projet-direct', level: 'project', parent_id: ids.entreprise })).status).toBe(201)
      expect(code(await create({ slug: 'entreprise', level: 'enterprise' }))).toBe('E_PROFILE_SLUG_TAKEN')
    })

    it('cycle et rétrogradation d’un parent refusés (application et base)', async () => {
      // L'équipe ne peut pas devenir enfant de son propre enfant.
      expect(code(await patch(ids.equipe, { level: 'project', parent_id: ids.projet }))).toMatch(/E_PROFILE_(CYCLE|LEVEL|CHILDREN)/)
      // Rétrograder l'entreprise en équipe alors qu'elle a des enfants.
      expect(code(await patch(ids.entreprise, { level: 'team', parent_id: ids.rapide }))).toBe('E_PROFILE_CHILDREN')
      // En base : déclencheur profiles_hierarchy (014), même sans l'application.
      await expect(h.db.pool.query(`UPDATE profiles SET parent_id = $2 WHERE id = $1`, [ids.equipe, ids.projet])).rejects.toThrow(/higher level|profiles_parent_level/)
      await expect(h.db.pool.query(`UPDATE profiles SET level = 'project', parent_id = $2 WHERE id = $1`, [ids.entreprise, ids.rapide])).rejects.toThrow(/lower level|profiles_parent_level/)
    })

    it('profil intégré : ni niveau ni parent modifiables, jamais archivé', async () => {
      expect(code(await patch(ids.rapide, { level: 'team', parent_id: ids.entreprise }))).toBe('E_PROFILE_BUILTIN')
      expect(code(await h.call(`/api/profiles/${ids.rapide}/archive`, { method: 'POST', client: admin, json: { archived: true } }))).toBe('E_PROFILE_BUILTIN')
      const desc = await patch(ids.rapide, { description: 'Analyse rapide des PR' })
      expect(desc.status).toBe(200)
      expect(desc.data.description).toBe('Analyse rapide des PR')
    })

    it('droits : lecture pour tous, écriture admin seulement', async () => {
      expect((await h.call('/api/profiles', { client: viewer })).status).toBe(200)
      expect((await create({ slug: 'op', level: 'enterprise' }, operator)).status).toBe(403)
      expect((await patch(ids.projet, { description: 'x' }, operator)).status).toBe(403)
      expect((await h.call('/api/profiles', {})).status).toBe(401)
    })

    it('schéma strict : clé inconnue, catégorie ou module invalides refusés', async () => {
      expect((await create({ slug: 'x1', level: 'enterprise', extra: true })).status).toBe(400)
      expect((await create({ slug: 'x2', level: 'enterprise', categories: ['inconnue'] })).status).toBe(400)
      expect((await create({ slug: 'x3', level: 'enterprise', include_modules: ['../evil'] })).status).toBe(400)
      expect((await create({ slug: 'x4', level: 'enterprise', locks: { gate_floor: { block_malicious: false } } })).status).toBe(400)
      expect((await create({ slug: 'x5', level: 'enterprise', description: 'a\u0007b' })).status).toBe(400)
    })
  })

  describe('verrous (contrat 28)', () => {
    it('un enfant ne peut assouplir aucun plancher hérité', async () => {
      const r = await patch(ids.projet, { locks: { gate_floor: { max_secrets: 3, vuln_block_from: 'critical' } } })
      expect(r.status).toBe(409)
      expect(code(r)).toBe('E_PROFILE_LOCKED')
      const fields = (r.data.data.violations as { field: string }[]).map(v => v.field).sort()
      expect(fields).toEqual(['gate_floor.max_secrets', 'gate_floor.vuln_block_from'])
      // null (jamais bloquant) est plus souple que tout seuil.
      expect(code(await patch(ids.projet, { locks: { gate_floor: { vuln_block_from: null } } }))).toBe('E_PROFILE_LOCKED')
      // Durcir est permis.
      const ok = await patch(ids.projet, { locks: { gate_floor: { vuln_block_from: 'medium', kev_blocks: true } } })
      expect(ok.status, JSON.stringify(ok.data)).toBe(200)
    })

    it('chaque règle du plancher, dans son sens', async () => {
      const sub = await create({ slug: 'sous-ent', level: 'team', parent_id: ids.entreprise })
      ids.sous = sub.data.id
      const lock = async (floor: Record<string, unknown>) => patch(ids.entreprise, { locks: { required_categories: ['secrets'], gate_floor: floor } })
      const child = async (floor: Record<string, unknown>) => code(await patch(ids.sous, { locks: { gate_floor: floor } }))
      expect((await lock({ max_secrets: 0, vuln_block_from: 'high', new_code_only: false, license_denied_blocks: true, kev_blocks: true, epss_block_from: 0.1, quarantine_days: 7, feed_max_age_days: 7 })).status).toBe(200)
      expect(await child({ new_code_only: true })).toBe('E_PROFILE_LOCKED')
      expect(await child({ license_denied_blocks: false })).toBe('E_PROFILE_LOCKED')
      expect(await child({ kev_blocks: false })).toBe('E_PROFILE_LOCKED')
      expect(await child({ epss_block_from: 0.5 })).toBe('E_PROFILE_LOCKED')
      expect(await child({ epss_block_from: null })).toBe('E_PROFILE_LOCKED')
      expect(await child({ quarantine_days: 2 })).toBe('E_PROFILE_LOCKED')
      expect(await child({ feed_max_age_days: 30 })).toBe('E_PROFILE_LOCKED')
      expect(await child({ feed_max_age_days: null })).toBe('E_PROFILE_LOCKED')
      expect(await child({ sast_block_from: null })).toBeUndefined() // règle non verrouillée : libre
      expect((await patch(ids.sous, { locks: { gate_floor: { epss_block_from: 0.05, quarantine_days: 14, feed_max_age_days: 3 } } })).status).toBe(200)
    })

    it('un module exigé ne s’exclut pas ; catégories et modules s’ajoutent en descendant', async () => {
      expect((await patch(ids.equipe, { locks: { required_modules: ['gitleaks'] } })).status).toBe(200)
      const r = await patch(ids.projet, { exclude_modules: ['gitleaks'] })
      expect(code(r)).toBe('E_PROFILE_LOCKED')
      expect(r.data.data.violations[0].field).toBe('exclude_modules')
      expect(code(await create({ slug: 'auto-exclu', level: 'enterprise', exclude_modules: ['trivy'], locks: { required_modules: ['trivy'] } }))).toBe('E_PROFILE_LOCKED')
      const e = await effectiveProfile(h.db.pool, ids.projet)
      expect(e.chain.map(c => c.slug)).toEqual(['entreprise', 'equipe-web', 'projet-web'])
      expect(e.categories).toEqual(expect.arrayContaining(['secrets', 'sca', 'iac']))
      expect(e.include_modules).toEqual(expect.arrayContaining(['trivy', 'gitleaks']))
      expect(e.locks.required_categories).toEqual(['secrets'])
      expect(e.locks.required_modules).toEqual(['gitleaks'])
      expect(e.locks.gate_floor.vuln_block_from).toBe('medium')
      expect(e.locks.gate_floor.max_secrets).toBe(0)
    })

    it('un parent durci ne peut pas laisser un descendant plus souple', async () => {
      // sous-ent exige epss 0.05 ; l'entreprise peut descendre à 0.01 (plus strict) : le descendant devient plus souple.
      const r = await patch(ids.entreprise, { locks: { required_categories: ['secrets'], gate_floor: { epss_block_from: 0.01, max_secrets: 0, vuln_block_from: 'high' } } })
      expect(code(r)).toBe('E_PROFILE_LOCKED')
      expect(r.data.data.profile).toBe('sous-ent')
    })

    it('audit avec l’avant et l’après', async () => {
      const a = await h.db.pool.query<{ details: { changes: Record<string, unknown> } }>(
        `SELECT details FROM audit_log WHERE action = 'profile.update' AND target_id = $1 ORDER BY id DESC LIMIT 1`, [ids.projet])
      expect(a.rows[0]!.details.changes.locks).toBeDefined()
    })
  })

  describe('« aucun envoi à l’IA » imposé (G8, § 3.5)', () => {
    it('le verrou bascule les projets du profil et ne se lève pas', async () => {
      const p = await newProject('ia-projet')
      expect((await h.call(`/api/projects/${p}/profiles`, { method: 'PUT', client: admin, json: { default: ids.projet } })).status).toBe(200)
      expect((await h.db.pool.query('SELECT ai_opt_out FROM projects WHERE id = $1', [p])).rows[0].ai_opt_out).toBe(false)
      const r = await patch(ids.equipe, { locks: { required_modules: ['gitleaks'], ai_opt_out: true } })
      expect(r.status).toBe(200)
      expect(r.data.ai_opt_out_imposed).toContain('ia-projet')
      expect((await h.db.pool.query('SELECT ai_opt_out FROM projects WHERE id = $1', [p])).rows[0].ai_opt_out).toBe(true)
      const view = await h.call(`/api/projects/${p}/profiles`, { client: viewer })
      expect(view.data.ai_opt_out_locked).toBe(true)
      // Le projet ne peut pas le lever.
      const off = await h.call(`/api/projects/${p}`, { method: 'PATCH', client: admin, json: { ai_opt_out: false } })
      expect(off.status).toBe(409)
      expect(code(off)).toBe('E_AI_OPT_OUT_LOCKED')
      // Le profil enfant non plus : son false n'efface pas le verrou hérité.
      expect((await patch(ids.projet, { locks: { ai_opt_out: false, gate_floor: { vuln_block_from: 'medium', kev_blocks: true } } })).status).toBe(200)
      expect((await effectiveProfile(h.db.pool, ids.projet)).locks.ai_opt_out).toBe(true)
      expect((await h.db.pool.query('SELECT ai_opt_out FROM projects WHERE id = $1', [p])).rows[0].ai_opt_out).toBe(true)
    })
  })

  describe('jeux de règles d’un profil (G4)', () => {
    it('attacher, épingler, détacher par le PATCH ; version inexistante ou jeu archivé refusés', async () => {
      const rs = (await h.db.pool.query<{ id: string }>(
        `INSERT INTO rulesets (slug, engine, name) VALUES ('regles-profil', 'opengrep', 'Règles du profil') RETURNING id::text`)).rows[0]!.id
      await h.db.pool.query(
        `INSERT INTO ruleset_versions (ruleset_id, version, content, sha256) VALUES ($1, 1, 'rules: []', repeat('a', 64)), ($1, 2, 'rules: [] ', repeat('b', 64))`, [rs])
      const patch = (rulesets: unknown) => h.call(`/api/profiles/${ids.equipe}`, { method: 'PATCH', client: admin, json: { rulesets } })
      expect((await patch([{ ruleset_id: rs, pinned_version: 1 }])).status).toBe(200)
      let got = await h.call(`/api/profiles/${ids.equipe}`, { client: viewer })
      expect(got.data.profile.rulesets).toEqual([expect.objectContaining({ ruleset_id: rs, slug: 'regles-profil', pinned_version: 1 })])
      expect((await patch([{ ruleset_id: rs, pinned_version: 9 }])).status).toBe(400)
      expect((await h.call(`/api/profiles/${ids.equipe}`, { method: 'PATCH', client: operator, json: { rulesets: [] } })).status).toBe(403)
      expect((await patch([])).status).toBe(200)
      got = await h.call(`/api/profiles/${ids.equipe}`, { client: viewer })
      expect(got.data.profile.rulesets).toEqual([])
      await h.db.pool.query('UPDATE rulesets SET archived_at = now() WHERE id = $1', [rs])
      expect((await patch([{ ruleset_id: rs, pinned_version: null }])).status).toBe(404)
    })
  })

  describe('profil par déclencheur (G9, contrat 29)', () => {
    it('défauts de l’entreprise : PR → rapide, nuit → complet, release → release', async () => {
      const p = await h.db.pool.query<{ id: string }>(
        `SELECT id FROM projects WHERE slug = 'ia-projet'`)
      const v = await h.call(`/api/projects/${p.rows[0]!.id}/profiles`, { client: viewer })
      expect(v.status).toBe(200)
      expect(v.data.slots.default.slug).toBe('projet-web')
      // Projet inséré directement (hors création) : défauts absents, champ vide → profile_id.
      expect(v.data.slots.pr.profile_id).toBeNull()
      expect(v.data.slots.pr.slug).toBe('projet-web')
    })

    it('choix selon l’événement, champ vide → profile_id, verrous du profil remplacé conservés', async () => {
      const p = await newProject('g9')
      await h.call(`/api/projects/${p}/profiles`, { method: 'PUT', client: admin, json: { pr: ids.rapide, nightly: ids.complet, release: ids.release } })
      const pr = await resolveProfile(h.db.pool, p, 'webhook', { pullRequest: { number: 3, base_sha: 'a'.repeat(40) } })
      expect([pr.chosen.slot, pr.chosen.slug]).toEqual(['pr', 'rapide'])
      expect((await resolveProfile(h.db.pool, p, 'schedule')).chosen.slug).toBe('complet')
      expect((await resolveProfile(h.db.pool, p, 'release')).chosen.slug).toBe('release')
      expect((await resolveProfile(h.db.pool, p, 'manual')).chosen.slug).toBe('complet')
      expect((await resolveProfile(h.db.pool, p, 'webhook')).chosen.slot).toBe('default')
      await h.call(`/api/projects/${p}/profiles`, { method: 'PUT', client: admin, json: { pr: null } })
      expect((await resolveProfile(h.db.pool, p, 'webhook', { pullRequest: { number: 4 } })).chosen.slug).toBe('complet')
      // Profil explicite (CI) : les verrous du profil de l'emplacement s'ajoutent.
      await h.call(`/api/projects/${p}/profiles`, { method: 'PUT', client: admin, json: { release: ids.projet } })
      const explicit = await resolveProfile(h.db.pool, p, 'release', { profileId: ids.rapide })
      expect(explicit.chosen.source).toBe('explicit')
      expect(explicit.effective.slug).toBe('rapide')
      expect(explicit.effective.locks.required_modules).toContain('gitleaks')
      expect(explicit.effective.locks.ai_opt_out).toBe(true)
      expect(explicit.effective.categories).toContain('secrets')
      // Choix non humain (jeton d'API, dépôt) ou release : il n'ajoute qu'au profil de l'emplacement.
      const slot = await resolveProfile(h.db.pool, p, 'release')
      const additive = await resolveProfile(h.db.pool, p, 'release', { profileId: ids.rapide, additive: true })
      expect(additive.effective.slug).toBe('rapide')
      expect(additive.effective.categories).toEqual(expect.arrayContaining(slot.effective.categories))
      expect(additive.effective.include_modules).toEqual(expect.arrayContaining(slot.effective.include_modules))
      expect(explicit.effective.categories.length).toBeLessThanOrEqual(additive.effective.categories.length)
    })

    it('planProfile : profil demandé par un jeton d’API borné par l’emplacement, choix humain respecté hors release', async () => {
      const p = await newProject('g9-additif')
      await h.call(`/api/projects/${p}/profiles`, { method: 'PUT', client: admin, json: { default: ids.complet } })
      const complet = (await resolveProfile(h.db.pool, p, 'api')).effective.categories
      const mk = async (trigger: string, requestedBy: number | null) => (await h.db.pool.query<{ id: string }>(
        `INSERT INTO scans (project_id, number, trigger, priority, ref, profile_id, gate_id, status, requested_by)
         SELECT id, (SELECT count(*) + 1 FROM scans WHERE project_id = $1), $2, 50, 'main', $3, gate_id, 'queued', $4
           FROM projects WHERE id = $1 RETURNING id::text`, [p, trigger, ids.rapide, requestedBy])).rows[0]!.id
      const user = (await h.db.pool.query<{ id: number }>(`SELECT id FROM users WHERE role = 'admin' LIMIT 1`)).rows[0]!.id
      const token = await planProfile(h.db.pool, { id: await mk('api', null), project_id: p, trigger: 'api', profile_id: ids.rapide })
      expect(token.profile.categories).toEqual(expect.arrayContaining(complet))
      const human = await planProfile(h.db.pool, { id: await mk('manual', user), project_id: p, trigger: 'manual', profile_id: ids.rapide })
      expect(human.profile.categories.length).toBeLessThan(complet.length)
    })

    it('« aucun envoi à l’IA » d’un profil choisi pour une analyse : imposé au projet, durablement', async () => {
      const p = await newProject('g8-ia-analyse')
      expect((await h.db.pool.query<{ ai_opt_out: boolean }>('SELECT ai_opt_out FROM projects WHERE id = $1', [p])).rows[0]!.ai_opt_out).toBe(false)
      const s = (await h.db.pool.query<{ id: string }>(
        `INSERT INTO scans (project_id, number, trigger, priority, ref, profile_id, gate_id, status)
         SELECT id, 1, 'api', 50, 'main', $2, gate_id, 'queued' FROM projects WHERE id = $1 RETURNING id::text`, [p, ids.projet])).rows[0]!.id
      const { profile } = await planProfile(h.db.pool, { id: s, project_id: p, trigger: 'api', profile_id: ids.projet })
      expect(profile.locks!.ai_opt_out).toBe(true)
      expect((await h.db.pool.query<{ ai_opt_out: boolean }>('SELECT ai_opt_out FROM projects WHERE id = $1', [p])).rows[0]!.ai_opt_out).toBe(true)
      expect(await aiOptOutLocked(h.db.pool, p)).toBe(true)
    })

    it('enqueueScan choisit le profil du déclencheur', async () => {
      const p = await newProject('g9-file')
      await h.db.pool.query(`UPDATE projects SET upload_id = gen_random_uuid() WHERE id = $1`, [p])
      await h.call(`/api/projects/${p}/profiles`, { method: 'PUT', client: admin, json: { nightly: ids.rapide, release: ids.release } })
      const s1 = await enqueueScan(h.db.pool, { projectId: p, ref: 'main', trigger: 'schedule' })
      const s2 = await enqueueScan(h.db.pool, { projectId: p, ref: 'main', trigger: 'release' })
      const s3 = await enqueueScan(h.db.pool, { projectId: p, ref: 'main', trigger: 'manual' })
      const rows = await h.db.pool.query<{ id: string, slug: string }>(
        `SELECT s.id::text, p.slug FROM scans s JOIN profiles p ON p.id = s.profile_id WHERE s.id = ANY($1::uuid[])`, [[s1.scanId, s2.scanId, s3.scanId]])
      const by = Object.fromEntries(rows.rows.map(r => [r.id, r.slug]))
      expect([by[s1.scanId], by[s2.scanId], by[s3.scanId]]).toEqual(['rapide', 'release', 'complet'])
      // Profil archivé refusé par la CI.
      await create({ slug: 'jetable', level: 'enterprise' })
      const j = (await h.db.pool.query<{ id: string }>(`SELECT id FROM profiles WHERE slug = 'jetable'`)).rows[0]!.id
      await h.call(`/api/profiles/${j}/archive`, { method: 'POST', client: admin, json: { archived: true } })
      await expect(enqueueScan(h.db.pool, { projectId: p, ref: 'main', trigger: 'api', profileSlug: 'jetable' })).rejects.toThrow('E_SCAN_PROFILE')
    })

    it('opérateur : un profil plus souple exige l’administrateur', async () => {
      const p = await newProject('g9-op')
      expect((await h.call(`/api/projects/${p}/profiles`, { method: 'PUT', client: admin, json: { release: ids.projet } })).status).toBe(200)
      const looser = await h.call(`/api/projects/${p}/profiles`, { method: 'PUT', client: operator, json: { release: ids.rapide } })
      expect(looser.status).toBe(403)
      expect(code(looser)).toBe('E_PROFILE_LOOSER')
      expect((await h.call(`/api/projects/${p}/profiles`, { method: 'PUT', client: operator, json: { pr: ids.rapide } })).status).toBe(200)
      expect((await h.call(`/api/projects/${p}/profiles`, { method: 'PUT', client: viewer, json: { pr: ids.complet } })).status).toBe(403)
      const audit = await h.db.pool.query(`SELECT 1 FROM audit_log WHERE action = 'project.profiles' AND target_id = $1`, [p])
      expect(audit.rowCount).toBe(2)
      // Même règle par la route de modification du projet.
      await h.call(`/api/projects/${p}/profiles`, { method: 'PUT', client: admin, json: { default: ids.projet } })
      const viaPatch = await h.call(`/api/projects/${p}`, { method: 'PATCH', client: operator, json: { profile_id: ids.rapide } })
      expect(viaPatch.status).toBe(403)
      expect(code(viaPatch)).toBe('E_PROFILE_LOOSER')
      expect((await h.call(`/api/projects/${p}`, { method: 'PATCH', client: admin, json: { profile_id: ids.rapide } })).status).toBe(200)
    })
  })

  describe('gate durci et rejeu (G8, G11)', () => {
    async function scanWithPlan(projectId: string, plan: unknown): Promise<string> {
      const r = await h.db.pool.query<{ id: string }>(
        `INSERT INTO scans (project_id, number, trigger, priority, ref, profile_id, gate_id, status, plan)
         SELECT $1, COALESCE((SELECT max(number) FROM scans WHERE project_id = $1), 0) + 1, 'manual', 50, 'main', profile_id, gate_id, 'ingesting', $2
           FROM projects WHERE id = $1 RETURNING id`, [projectId, JSON.stringify(plan)])
      return r.rows[0]!.id
    }

    it('plan d’avant la 0.7 : règles inchangées ; plan 0.7 : plancher appliqué', async () => {
      const p = await newProject('gate-floor')
      const base = { version: 1, created_at: '2026-11-01T00:00:00Z', source: { kind: 'archive', ref: 'archive', commit: null, history: 'shallow' }, modules: [], gaps: [], timeout_s: 0 }
      const old = await scanWithPlan(p, { ...base, profile: { id: ids.complet, slug: 'complet', categories: [], include_modules: [], exclude_modules: [] }, gate: { id: 'x', slug: 'defaut', rules: PLAN_GATE } })
      const v1 = await evaluateGate(h.db.pool, old)
      expect(v1.rules.vuln_block_from).toBe('high')
      expect(v1.rules.max_secrets).toBe(0)
      const locks = { required_categories: [], required_modules: [], gate_floor: { vuln_block_from: 'low', new_code_only: false, max_secrets: 0 }, ai_opt_out: false }
      const hard = await scanWithPlan(p, { ...base, profile: { id: ids.projet, slug: 'projet-web', categories: [], include_modules: [], exclude_modules: [], locks }, gate: { id: 'x', slug: 'defaut', rules: PLAN_GATE } })
      const v2 = await evaluateGate(h.db.pool, hard)
      expect(v2.rules.vuln_block_from).toBe('low')
      expect(v2.rules.new_code_only).toBe(false)
      expect(v2.new_code_only).toBe(false)
      // Un plancher plus souple que le gate ne l'assouplit jamais.
      const soft = await scanWithPlan(p, { ...base, profile: { id: ids.projet, slug: 'projet-web', categories: [], include_modules: [], exclude_modules: [], locks: { ...locks, gate_floor: { vuln_block_from: 'critical', max_secrets: 5 } } }, gate: { id: 'x', slug: 'defaut', rules: PLAN_GATE } })
      const v3 = await evaluateGate(h.db.pool, soft)
      expect(v3.rules.vuln_block_from).toBe('high')
      expect(v3.rules.max_secrets).toBe(0)
      // Rejeu : même plan, même verdict, même règles.
      expect((await evaluateGate(h.db.pool, hard)).rules).toEqual(v2.rules)
    })

    it('planProfile fige profil effectif, chaîne, verrous et emplacement', async () => {
      const p = await newProject('plan-profile')
      await h.call(`/api/projects/${p}/profiles`, { method: 'PUT', client: admin, json: { default: ids.projet } })
      const s = await scanWithPlan(p, null)
      const { profile } = await planProfile(h.db.pool, { id: s, project_id: p, trigger: 'manual', profile_id: ids.projet })
      expect(profile.chain).toEqual(['entreprise', 'equipe-web', 'projet-web'])
      expect(profile.slot).toBe('default')
      expect(profile.locks!.required_modules).toEqual(['gitleaks'])
      expect(profile.categories).toEqual(expect.arrayContaining(['secrets', 'sca', 'iac']))
    })
  })

  describe('aperçu (G10)', () => {
    it('modules résolus, manquants à installer, durée, ressources, couverture', async () => {
      const scan = (_cats: string[]) => ({ inputs: ['repo', 'archive'], timeout_s: 300 })
      await h.setModules({
        version: 1, updated_at: '2026-11-25T08:00:00Z',
        modules: [
          { id: 'gitleaks', version: '8.0.0', type: 'scanner', status: 'healthy', enabled: true, installed_at: null, options: {} },
          { id: 'trivy', version: '0.60.0', type: 'scanner', status: 'healthy', enabled: true, installed_at: null, options: {} },
        ],
        operations: [], feeds: [],
      }, {
        schema: 1, version: 1, generated_at: '2026-11-25T00:00:00Z', packs: [],
        modules: [
          { id: 'gitleaks', name: 'gitleaks', type: 'scanner', version: '8.0.0', categories: ['secrets'], license: { spdx: 'MIT', restrictions: 'none' }, resources: { min_ram_mb: 256, min_cpu: 1, disk_mb: 50 }, scan: scan(['secrets']) },
          { id: 'trivy', name: 'Trivy', type: 'scanner', version: '0.60.0', categories: ['sca', 'iac'], license: { spdx: 'Apache-2.0', restrictions: 'none' }, resources: { min_ram_mb: 1024, min_cpu: 1, disk_mb: 500 }, scan: scan(['sca']) },
          { id: 'checkov', name: 'Checkov', type: 'scanner', version: '3.0.0', categories: ['iac'], license: { spdx: 'Apache-2.0', restrictions: 'none' }, scan: scan(['iac']) },
          { id: 'opengrep', name: 'Opengrep', type: 'scanner', version: '1.0.0', categories: ['sast'], license: { spdx: 'LGPL-2.1', restrictions: 'none' }, scan: scan(['sast']) },
        ],
      })
      const p = await newProject('apercu')
      await h.db.pool.query(`UPDATE projects SET detection = $2 WHERE id = $1`, [p, JSON.stringify({ categories: ['secrets', 'sca', 'sast'] })])
      // Durée mesurée de gitleaks sur l'appliance.
      const s = await scanWithPlanForDuration(p)
      await h.db.pool.query(`INSERT INTO scan_modules (scan_id, module_id, module_version, status, duration_ms, finished_at) VALUES ($1, 'gitleaks', '8.0.0', 'ok', 4200, now())`, [s])
      const r = await h.call('/api/profiles/preview', { method: 'POST', client: operator, json: { parent_id: ids.equipe, categories: ['sast'], project_id: p } })
      expect(r.status, JSON.stringify(r.data)).toBe(200)
      expect(r.data.effective.chain).toEqual(['entreprise', 'equipe-web', 'apercu'])
      expect(r.data.modules.map((m: { id: string }) => m.id).sort()).toEqual(['gitleaks', 'trivy'])
      const sast = r.data.missing.find((m: { category: string }) => m.category === 'sast')
      expect(sast.install.map((m: { id: string }) => m.id)).toEqual(['opengrep'])
      expect(r.data.estimate.duration_ms).toBe(4200)
      expect(r.data.estimate.unmeasured).toEqual(['trivy'])
      expect(r.data.estimate.peak_ram_mb).toBe(1024)
      expect(r.data.coverage).toMatchObject({ detected: true, covered: ['sca', 'secrets'], uncovered: ['sast'] })
      expect(r.data.violations).toEqual([])
      const loose = await h.call('/api/profiles/preview', { method: 'POST', client: operator, json: { parent_id: ids.equipe, exclude_modules: ['gitleaks'] } })
      expect(loose.data.violations[0].field).toBe('exclude_modules')
      expect((await h.call('/api/profiles/preview', { method: 'POST', client: viewer, json: {} })).status).toBe(403)
    })

    async function scanWithPlanForDuration(projectId: string): Promise<string> {
      const r = await h.db.pool.query<{ id: string }>(
        `INSERT INTO scans (project_id, number, trigger, priority, ref, profile_id, gate_id, status)
         SELECT $1, COALESCE((SELECT max(number) FROM scans WHERE project_id = $1), 0) + 1, 'manual', 50, 'main', profile_id, gate_id, 'done'
           FROM projects WHERE id = $1 RETURNING id`, [projectId])
      return r.rows[0]!.id
    }
  })

  describe('archivage', () => {
    it('refusé si utilisé ou parent, permis sinon, restaurable', async () => {
      expect(code(await h.call(`/api/profiles/${ids.equipe}/archive`, { method: 'POST', client: admin, json: { archived: true } }))).toMatch(/E_PROFILE_(IN_USE|CHILDREN)/)
      const solo = await create({ slug: 'solo', level: 'enterprise' })
      const a = await h.call(`/api/profiles/${solo.data.id}/archive`, { method: 'POST', client: admin, json: { archived: true } })
      expect(a.status).toBe(200)
      expect(a.data.archived_at).toBeTruthy()
      expect((await h.call('/api/profiles', { client: viewer })).data.items.some((p: { slug: string }) => p.slug === 'solo')).toBe(false)
      expect((await h.call('/api/profiles?archived=1', { client: viewer })).data.items.some((p: { slug: string }) => p.slug === 'solo')).toBe(true)
      expect(code(await patch(solo.data.id, { description: 'x' }))).toBe('E_PROFILE_ARCHIVED')
      expect(code(await create({ slug: 'sous-solo', level: 'team', parent_id: solo.data.id }))).toBe('E_PROFILE_ARCHIVED')
      expect((await h.call(`/api/profiles/${solo.data.id}/archive`, { method: 'POST', client: admin, json: { archived: false } })).data.archived_at).toBeNull()
    })

    it('détail : chaîne, verrous hérités, projets', async () => {
      const r = await h.call(`/api/profiles/${ids.projet}`, { client: viewer })
      expect(r.status).toBe(200)
      expect(r.data.inherited_locks.required_modules).toEqual(['gitleaks'])
      expect(r.data.effective.chain.map((c: { slug: string }) => c.slug)).toEqual(['entreprise', 'equipe-web', 'projet-web'])
      expect(r.data.projects.length).toBeGreaterThan(0)
      expect((await h.call('/api/profiles/00000000-0000-4000-8000-000000000000', { client: viewer })).status).toBe(404)
    })
  })
})
