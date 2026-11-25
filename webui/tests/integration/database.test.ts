// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Intégration contre un vrai PostgreSQL 16 (DATABASE_URL) : migrations,
// lanceur migrate.mjs, contraintes, audit en ajout seul, comptes, sessions,
// verrouillage, premier administrateur.

import { execFile } from 'node:child_process'
import { readFileSync } from 'node:fs'
import { mkdtemp, readdir, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { promisify } from 'node:util'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { DATABASE_URL, MIGRATIONS_DIR, createTestDatabase, type TestDatabase } from '../helpers/db'
import { applyMigrations, loadMigrationsFromDir, prepareMigrations } from '../../migrate.mjs'
import { hashPassword } from '../../server/utils/password'
import { authenticate, countActiveAdmins, createUser, deleteUser, UsernameTakenError } from '../../server/utils/users'
import { createSession, resolveSession, revokeSession, revokeUserSessions } from '../../server/utils/sessions'
import { getAuthSettings, clearSettingsCache } from '../../server/utils/settings'
import { listAudit, writeAudit } from '../../server/utils/audit'
import { consumeBootstrapAdmin } from '../../server/utils/bootstrap'

const run = promisify(execFile)
const WEBUI = fileURLToPath(new URL('../../', import.meta.url))

describe.skipIf(!DATABASE_URL)('base de la console (PostgreSQL réel)', () => {
  let db: TestDatabase

  beforeAll(async () => {
    db = await createTestDatabase()
  })
  afterAll(async () => {
    await db?.drop()
  })

  describe('re-corrélation (009, 011)', () => {
    it('supprimer l’analyse source supprime ses re-corrélations, et une re-corrélation exige sa source', async () => {
      const q = db.pool
      const p = (await q.query<{ id: string }>(`SELECT id FROM profiles ORDER BY slug LIMIT 1`)).rows[0]!.id
      const g = (await q.query<{ id: string }>(`SELECT id FROM gates WHERE slug = 'defaut'`)).rows[0]!.id
      const project = (await q.query<{ id: string }>(
        `INSERT INTO projects (slug, name, source_kind, profile_id, gate_id) VALUES ('recorr', 'recorr', 'archive', $1, $2) RETURNING id`, [p, g])).rows[0]!.id
      const mk = async (n: number, trigger: string, source: string | null) => (await q.query<{ id: string }>(
        `INSERT INTO scans (project_id, number, trigger, priority, ref, profile_id, gate_id, sbom_source)
         VALUES ($1, $2, $3, 10, 'main', $4, $5, $6) RETURNING id`, [project, n, trigger, p, g, source])).rows[0]!.id
      const src = await mk(1, 'manual', null)
      const rec = await mk(2, 'recorrelate', src)
      await expect(mk(3, 'recorrelate', null)).rejects.toThrow(/scans_recorrelate_source/)
      await expect(mk(4, 'manual', src)).rejects.toThrow(/scans_recorrelate_source/)
      await q.query('DELETE FROM scans WHERE id = $1', [src])
      expect((await q.query('SELECT 1 FROM scans WHERE id = $1', [rec])).rowCount).toBe(0)
      await q.query('DELETE FROM projects WHERE id = $1', [project])
    })
  })

  describe('socle 0.7 (013)', () => {
    it('exceptions : demande sans décision, personne ne décide de sa propre demande', async () => {
      const q = db.pool
      const p = (await q.query<{ id: string }>(`SELECT id FROM profiles ORDER BY slug LIMIT 1`)).rows[0]!.id
      const g = (await q.query<{ id: string }>(`SELECT id FROM gates WHERE slug = 'defaut'`)).rows[0]!.id
      const project = (await q.query<{ id: string }>(
        `INSERT INTO projects (slug, name, source_kind, profile_id, gate_id) VALUES ('socle07', 'socle07', 'archive', $1, $2) RETURNING id`, [p, g])).rows[0]!.id
      const u = (await q.query<{ id: number }>(`INSERT INTO users (username, role, kind, password_hash) VALUES ('agent07', 'operator', 'agent', $1) RETURNING id`, [await hashPassword('x-long-password-for-tests')])).rows[0]!.id
      const legacy = (await q.query<{ status: string, decided_at: Date | null }>(
        `INSERT INTO exceptions (project_id, kind, target, reason, expires_on) VALUES ($1, 'path', '{"path": "tests/**"}', 'motif', current_date + 30) RETURNING status, decided_at`, [project])).rows[0]!
      expect(legacy.status).toBe('approved')
      expect(legacy.decided_at).not.toBeNull()
      const req = (await q.query<{ id: string }>(
        `INSERT INTO exceptions (project_id, kind, target, reason, expires_on, created_by, status, decided_at, requested_via, requester_is_human)
         VALUES ($1, 'path', '{"path": "docs/**"}', 'motif', current_date + 30, $2, 'requested', NULL, 'pr-comment', false) RETURNING id`, [project, u])).rows[0]!.id
      await expect(q.query(`UPDATE exceptions SET status = 'approved', decided_at = now(), decided_by = $2 WHERE id = $1`, [req, u]))
        .rejects.toThrow(/exceptions_not_self_decided/)
      await expect(q.query(`UPDATE exceptions SET status = 'approved' WHERE id = $1`, [req])).rejects.toThrow(/exceptions_decision/)
      await expect(q.query(`INSERT INTO exceptions (project_id, kind, target, reason, expires_on, status) VALUES ($1, 'path', '{"path": "x"}', 'motif', current_date + 1, 'requested')`, [project]))
        .rejects.toThrow(/exceptions_decision/)
      await q.query('DELETE FROM projects WHERE id = $1', [project])
      await q.query('DELETE FROM users WHERE id = $1', [u])
    })

    it('résultats IA, profils hiérarchiques et PR incrémentale', async () => {
      const q = db.pool
      const ent = (await q.query<{ id: string }>(`INSERT INTO profiles (slug, level) VALUES ('ent07', 'enterprise') RETURNING id`)).rows[0]!.id
      await expect(q.query(`INSERT INTO profiles (slug, level) VALUES ('team07', 'team')`)).rejects.toThrow(/profiles_level_parent/)
      await expect(q.query(`INSERT INTO profiles (slug, level, parent_id) VALUES ('ent07b', 'enterprise', $1)`, [ent])).rejects.toThrow(/profiles_level_parent/)
      await q.query(`INSERT INTO profiles (slug, level, parent_id) VALUES ('team07', 'team', $1)`, [ent])
      await expect(q.query('DELETE FROM profiles WHERE id = $1', [ent])).rejects.toThrow(/foreign key/)
      await q.query(`DELETE FROM profiles WHERE slug IN ('team07', 'ent07')`)
      const p = (await q.query<{ id: string }>(`SELECT id FROM profiles ORDER BY slug LIMIT 1`)).rows[0]!.id
      const g = (await q.query<{ id: string }>(`SELECT id FROM gates WHERE slug = 'defaut'`)).rows[0]!.id
      const project = (await q.query<{ id: string }>(
        `INSERT INTO projects (slug, name, source_kind, profile_id, gate_id) VALUES ('socle07b', 'socle07b', 'archive', $1, $2) RETURNING id`, [p, g])).rows[0]!.id
      await expect(q.query(`INSERT INTO scans (project_id, number, trigger, priority, ref, profile_id, gate_id, incremental) VALUES ($1, 1, 'webhook', 70, 'main', $2, $3, true)`, [project, p, g]))
        .rejects.toThrow(/scans_incremental_pr/)
      await q.query(`INSERT INTO scans (project_id, number, trigger, priority, ref, profile_id, gate_id, incremental, pull_request)
        VALUES ($1, 2, 'webhook', 70, 'refs/pull/7/head', $2, $3, true, '{"number": 7, "base_sha": "${'a'.repeat(40)}"}')`, [project, p, g])
      await expect(q.query(`INSERT INTO ai_calls (kind, outcome, via) VALUES ('x', 'ok', 'relay')`)).rejects.toThrow(/ai_calls_relay_module/)
      await q.query(`INSERT INTO ai_calls (kind, outcome, via, module_id) VALUES ('x', 'ok', 'relay', 'kodus')`)
      await q.query('DELETE FROM projects WHERE id = $1', [project])
    })
  })

  describe('0.7 (014 profils, 015 forges)', () => {
    it('hiérarchie des profils sans cycle, archivage', async () => {
      const q = db.pool
      const ent = (await q.query<{ id: string }>(`INSERT INTO profiles (slug, level) VALUES ('ent14', 'enterprise') RETURNING id`)).rows[0]!.id
      const team = (await q.query<{ id: string }>(`INSERT INTO profiles (slug, level, parent_id) VALUES ('team14', 'team', $1) RETURNING id`, [ent])).rows[0]!.id
      const proj = (await q.query<{ id: string }>(`INSERT INTO profiles (slug, level, parent_id) VALUES ('proj14', 'project', $1) RETURNING id`, [team])).rows[0]!.id
      await q.query(`INSERT INTO profiles (slug, level, parent_id) VALUES ('proj14b', 'project', $1)`, [ent])
      await expect(q.query(`INSERT INTO profiles (slug, level, parent_id) VALUES ('team14b', 'team', $1)`, [team])).rejects.toThrow(/profiles_parent_level|higher level/)
      await expect(q.query(`INSERT INTO profiles (slug, level, parent_id) VALUES ('team14c', 'team', $1)`, [proj])).rejects.toThrow(/higher level/)
      await expect(q.query(`UPDATE profiles SET parent_id = $1 WHERE id = $2`, [proj, team])).rejects.toThrow(/higher level/)
      await expect(q.query(`UPDATE profiles SET level = 'project' WHERE id = $1`, [team])).rejects.toThrow(/lower level/)
      await q.query(`UPDATE profiles SET archived_at = now() WHERE id = $1`, [proj])
      await q.query(`DELETE FROM profiles WHERE slug IN ('proj14', 'proj14b')`)
      await q.query(`DELETE FROM profiles WHERE slug IN ('team14', 'ent14')`)
    })

    it('G9 : profils par déclencheur par défaut posés sur les projets existants', async () => {
      const q = db.pool
      const p = (await q.query<{ id: string }>(`SELECT id FROM profiles WHERE slug = 'complet'`)).rows[0]!.id
      const g = (await q.query<{ id: string }>(`SELECT id FROM gates WHERE slug = 'defaut'`)).rows[0]!.id
      const project = (await q.query<{ id: string }>(
        `INSERT INTO projects (slug, name, source_kind, profile_id, gate_id, profile_release_id) VALUES ('socle14', 'socle14', 'archive', $1, $2, $1) RETURNING id`, [p, g])).rows[0]!.id
      const sql = readFileSync(new URL('../../server/db/migrations/014_profiles.sql', import.meta.url), 'utf8')
      await q.query(sql.slice(sql.indexOf('UPDATE projects p')))
      const r = (await q.query<{ pr: string, nightly: string, release: string }>(
        `SELECT pr.slug AS pr, n.slug AS nightly, r.slug AS release FROM projects x
           JOIN profiles pr ON pr.id = x.profile_pr_id JOIN profiles n ON n.id = x.profile_nightly_id JOIN profiles r ON r.id = x.profile_release_id
          WHERE x.id = $1`, [project])).rows[0]!
      expect(r).toEqual({ pr: 'rapide', nightly: 'complet', release: 'complet' })
      await q.query('DELETE FROM projects WHERE id = $1', [project])
    })

    it('jetons de forge et suspension des projets', async () => {
      const q = db.pool
      const kinds = (await q.query<{ def: string }>(`SELECT pg_get_constraintdef(oid) AS def FROM pg_constraint WHERE conname = 'forge_apps_kind'`)).rows[0]!.def
      for (const k of ['github-app', 'forgejo-oauth', 'gitlab-oauth', 'forgejo-token', 'gitlab-token']) expect(kinds).toContain(`'${k}'`)
      const p = (await q.query<{ id: string }>(`SELECT id FROM profiles ORDER BY slug LIMIT 1`)).rows[0]!.id
      const g = (await q.query<{ id: string }>(`SELECT id FROM gates WHERE slug = 'defaut'`)).rows[0]!.id
      const project = (await q.query<{ id: string }>(
        `INSERT INTO projects (slug, name, source_kind, profile_id, gate_id) VALUES ('socle15', 'socle15', 'archive', $1, $2) RETURNING id`, [p, g])).rows[0]!.id
      await expect(q.query(`UPDATE projects SET suspended_at = now() WHERE id = $1`, [project])).rejects.toThrow(/projects_suspension/)
      await expect(q.query(`UPDATE projects SET suspended_at = now(), suspended_reason = 'console' WHERE id = $1`, [project])).rejects.toThrow(/suspended_reason/)
      await q.query(`UPDATE projects SET suspended_at = now(), suspended_reason = 'forge-archived' WHERE id = $1`, [project])
      await q.query(`UPDATE projects SET suspended_at = NULL, suspended_reason = NULL WHERE id = $1`, [project])
      await q.query('DELETE FROM projects WHERE id = $1', [project])
    })

    it('demande validate-ruleset (017) acceptée, types de 012 conservés', async () => {
      const def = (await db.pool.query<{ def: string }>(`SELECT pg_get_constraintdef(oid) AS def FROM pg_constraint WHERE conname = 'helper_requests_type_check'`)).rows[0]!.def
      for (const t of ['validate-ruleset', 'prefetch-images', 'start-trial', 'set-hostname', 'package-dates']) expect(def).toContain(`'${t}'`)
    })

    it('inventaire des agents (016) : cadres connus, taille bornée, suppression en cascade', async () => {
      const q = db.pool
      const p = (await q.query<{ id: string }>(`SELECT id FROM profiles ORDER BY slug LIMIT 1`)).rows[0]!.id
      const g = (await q.query<{ id: string }>(`SELECT id FROM gates WHERE slug = 'defaut'`)).rows[0]!.id
      const project = (await q.query<{ id: string }>(
        `INSERT INTO projects (slug, name, source_kind, profile_id, gate_id) VALUES ('socle16', 'socle16', 'archive', $1, $2) RETURNING id`, [p, g])).rows[0]!.id
      const scan = (await q.query<{ id: string }>(
        `INSERT INTO scans (project_id, number, trigger, priority, ref, profile_id, gate_id) VALUES ($1, 1, 'manual', 5, 'main', $2, $3) RETURNING id`, [project, p, g])).rows[0]!.id
      const ins = (fw: string[], inv: string) => q.query(
        `INSERT INTO agent_inventories (scan_id, project_id, module_version, frameworks, inventory) VALUES ($1, $2, '0.1.0', $3, $4::jsonb)`, [scan, project, fw, inv])
      await expect(ins(['inconnu'], '{}')).rejects.toThrow(/agent_inventories_frameworks_check/)
      await expect(ins(['crewai'], '[]')).rejects.toThrow(/agent_inventories_inventory_check/)
      await expect(ins(['crewai'], JSON.stringify({ x: 'a'.repeat(1048576) }))).rejects.toThrow(/agent_inventories_inventory_check/)
      await ins(['langgraph', 'crewai'], '{"agents": []}')
      await q.query('DELETE FROM projects WHERE id = $1', [project])
      expect((await q.query('SELECT 1 FROM agent_inventories WHERE scan_id = $1', [scan])).rowCount).toBe(0)
    })
  })

  describe('socle 0.8 (018 release)', () => {
    const fixture = async (slug: string) => {
      const q = db.pool
      const p = (await q.query<{ id: string }>(`SELECT id FROM profiles WHERE slug = 'release'`)).rows[0]!.id
      const g = (await q.query<{ id: string }>(`SELECT id FROM gates WHERE slug = 'defaut'`)).rows[0]!.id
      const project = (await q.query<{ id: string, release_mode: string, release_patterns: string[], autonomous_chain: boolean }>(
        `INSERT INTO projects (slug, name, source_kind, profile_id, gate_id) VALUES ($1, $1, 'archive', $2, $3)
         RETURNING id, release_mode, release_patterns, autonomous_chain`, [slug, p, g])).rows[0]!
      const scan = (await q.query<{ id: string }>(
        `INSERT INTO scans (project_id, number, trigger, priority, ref, profile_id, gate_id) VALUES ($1, 1, 'release', 1, 'v1.0.0', $2, $3) RETURNING id`,
        [project.id, p, g])).rows[0]!.id
      return { project, scan }
    }
    const sha = 'a'.repeat(40)
    const sig = 'A'.repeat(86) + '=='

    it('mode de release par défaut tiré, motifs v*, chaîne autonome désactivée', async () => {
      const { project } = await fixture('socle18a')
      expect(project).toMatchObject({ release_mode: 'pull', release_patterns: ['v*'], autonomous_chain: false })
      await expect(db.pool.query(`UPDATE projects SET release_mode = 'auto' WHERE id = $1`, [project.id])).rejects.toThrow(/release_mode/)
      await db.pool.query(`INSERT INTO release_candidates (project_id, tag, commit_sha, source) VALUES ($1, 'v1.0.0', $2, 'pull')`, [project.id, sha])
      await expect(db.pool.query(`INSERT INTO release_candidates (project_id, tag, commit_sha, source) VALUES ($1, 'v1.0.0', $2, 'push')`, [project.id, sha])).rejects.toThrow(/release_candidates_pkey/)
      await db.pool.query('DELETE FROM projects WHERE id = $1', [project.id])
    })

    it('rapport de release : signé complet, puis immuable', async () => {
      const q = db.pool
      const { project, scan } = await fixture('socle18b')
      const ins = (status: string, signature: string | null) => q.query(
        `INSERT INTO release_reports (scan_id, project_id, tag, commit_sha, report, report_sha256, status, signature, key_fingerprint, signed_at)
         VALUES ($1, $2, 'v1.0.0', $3, '{"verdict":"passed"}', $4, $5, $6, $7, $8)`,
        [scan, project.id, sha, 'b'.repeat(64), status, signature, signature ? 'c'.repeat(64) : null, signature ? new Date() : null])
      await expect(ins('signed', null)).rejects.toThrow(/release_reports_signed/)
      await expect(ins('pending', 'pas-une-signature')).rejects.toThrow(/release_reports_signature_check/)
      await ins('pending', null)
      await q.query(`UPDATE release_reports SET status = 'signed', signature = $2, key_fingerprint = $3, signed_at = now() WHERE scan_id = $1`, [scan, sig, 'c'.repeat(64)])
      await expect(q.query(`UPDATE release_reports SET report = '{"verdict":"failed"}' WHERE scan_id = $1`, [scan])).rejects.toThrow(/immutable/)
      await q.query('DELETE FROM projects WHERE id = $1', [project.id])
      expect((await q.query('SELECT 1 FROM release_reports WHERE scan_id = $1', [scan])).rowCount).toBe(0)
    })

    it('VEX : statuts OpenVEX, not_affected justifié, source cohérente', async () => {
      const q = db.pool
      const { project } = await fixture('socle18c')
      const ins = (status: string, justification: string | null, source = 'import') => q.query(
        `INSERT INTO vex_statements (project_id, vuln_id, product, status, justification, source) VALUES ($1, 'CVE-2026-0001', 'pkg:npm/exemple@1.0.0', $2, $3, $4)`,
        [project.id, status, justification, source])
      await expect(ins('not_affected', null)).rejects.toThrow(/vex_not_affected_justified/)
      await expect(ins('ignored', null)).rejects.toThrow(/vex_statements_status_check/)
      await expect(ins('affected', null, 'exception')).rejects.toThrow(/vex_exception_source/)
      await ins('not_affected', 'vulnerable_code_not_in_execute_path')
      await ins('under_investigation', null)
      await expect(q.query(`UPDATE exceptions SET vex_status = 'ignored' WHERE false`)).resolves.toBeDefined()
      const def = (await q.query<{ def: string }>(`SELECT pg_get_constraintdef(oid) AS def FROM pg_constraint WHERE conname = 'exceptions_vex_status_check'`)).rows[0]!.def
      expect(def).toContain(`'not_affected'`)
      await q.query('DELETE FROM projects WHERE id = $1', [project.id])
    })

    it('simulation de gate, OIDC, intégration, attestations et déploiements', async () => {
      const q = db.pool
      const { project, scan } = await fixture('socle18d')
      await expect(q.query(`INSERT INTO gate_simulations (project_id, rules, since, origin, status) VALUES ($1, '{}', now(), 'manual', 'done')`, [project.id])).rejects.toThrow(/gate_simulations_done/)
      await q.query(`INSERT INTO gate_simulations (project_id, rules, since, origin, status) VALUES ($1, '{}', now(), 'ai', 'pending')`, [project.id])
      await expect(q.query(`INSERT INTO oidc_issuers (kind, issuer, audience) VALUES ('github', 'http://ci.exemple.test', 'scanoria')`)).rejects.toThrow(/oidc_issuers_issuer_check/)
      const issuer = (await q.query<{ id: string }>(`INSERT INTO oidc_issuers (kind, issuer, audience) VALUES ('forgejo', 'https://forge.exemple.test/api/actions', 'scanoria') RETURNING id`)).rows[0]!.id
      await q.query(`INSERT INTO oidc_bindings (issuer_id, project_id, repository) VALUES ($1, $2, 'equipe/depot')`, [issuer, project.id])
      // 019 : identifiant immuable du dépôt, numérique seulement.
      await q.query(`INSERT INTO oidc_bindings (issuer_id, project_id, repository, repository_id) VALUES ($1, $2, 'equipe/epingle', '123456')`, [issuer, project.id])
      await expect(q.query(`INSERT INTO oidc_bindings (issuer_id, project_id, repository, repository_id) VALUES ($1, $2, 'equipe/piege', 'equipe/depot')`, [issuer, project.id])).rejects.toThrow(/oidc_bindings_repository_id_check/)
      await expect(q.query(`UPDATE oidc_bindings SET repository_id = '' WHERE repository = 'equipe/depot'`)).rejects.toThrow(/oidc_bindings_repository_id_check/)
      await expect(q.query(`INSERT INTO integration_requests (project_id, kind, state) VALUES ($1, 'branch-protection', 'applied')`, [project.id])).rejects.toThrow(/integration_protection_decided/)
      await q.query(`INSERT INTO integration_requests (project_id, kind, state) VALUES ($1, 'ci-pr', 'open')`, [project.id])
      await expect(q.query(`INSERT INTO integration_requests (project_id, kind, state) VALUES ($1, 'ci-pr', 'proposed')`, [project.id])).rejects.toThrow(/integration_requests_active/)
      await expect(q.query(`INSERT INTO attestations (scan_id, subject_name, subject_digest, predicate_type, status) VALUES ($1, 'registre.exemple.test/app', $2, 'https://in-toto.io/attestation/scai/v0.3', 'signed')`, [scan, 'sha256:' + 'd'.repeat(64)])).rejects.toThrow(/attestations_signed/)
      await expect(q.query(`INSERT INTO deploy_targets (project_id, kind, environment, config, auto_merge) VALUES ($1, 'cd-trigger', 'production', '{}', true)`, [project.id])).rejects.toThrow(/deploy_auto_merge_gitops/)
      const target = (await q.query<{ id: string }>(`INSERT INTO deploy_targets (project_id, kind, environment, config) VALUES ($1, 'cd-trigger', 'production', '{"workflow":"deploy.yml"}') RETURNING id`, [project.id])).rows[0]!.id
      await expect(q.query(`INSERT INTO deployments (target_id, scan_id, status) VALUES ($1, $2, 'refused')`, [target, scan])).rejects.toThrow(/deployments_refused/)
      await expect(q.query(`INSERT INTO deployments (target_id, scan_id, status, external_url) VALUES ($1, $2, 'running', 'http://ci.exemple.test/1')`, [target, scan])).rejects.toThrow(/deployments_external_url_check/)
      await q.query(`INSERT INTO deployments (target_id, scan_id, status, refused_reason) VALUES ($1, $2, 'refused', 'verdict-not-passed')`, [target, scan])
      await q.query('DELETE FROM projects WHERE id = $1', [project.id])
      await q.query('DELETE FROM oidc_issuers WHERE id = $1', [issuer])
    })

    it('demandes de signature, jetons de CD et sujets IA (018)', async () => {
      const def = async (n: string) => (await db.pool.query<{ def: string }>(`SELECT pg_get_constraintdef(oid) AS def FROM pg_constraint WHERE conname = $1`, [n])).rows[0]!.def
      for (const t of ['sign-release-report', 'sign-attestation', 'validate-ruleset', 'set-hostname']) expect(await def('helper_requests_type_check')).toContain(`'${t}'`)
      for (const k of ['deploy-token', 'registry-token', 'oauth-secret']) expect(await def('credentials_kind_check')).toContain(`'${k}'`)
      for (const t of ['release', 'gate', 'query']) expect(await def('ai_tasks_subject_type_check')).toContain(`'${t}'`)
    })
  })

  describe('socle 0.6 (012)', () => {
    it('essais, résultats externes, statut not-applicable et réutilisation', async () => {
      const q = db.pool
      const p = (await q.query<{ id: string }>(`SELECT id FROM profiles ORDER BY slug LIMIT 1`)).rows[0]!.id
      const g = (await q.query<{ id: string, rules: Record<string, unknown> }>(`SELECT id, rules FROM gates WHERE slug = 'defaut'`)).rows[0]!
      expect(g.rules.feed_max_age_days).toBe(7)
      const project = (await q.query<{ id: string }>(
        `INSERT INTO projects (slug, name, source_kind, profile_id, gate_id) VALUES ('socle06', 'socle06', 'archive', $1, $2) RETURNING id`, [p, g.id])).rows[0]!.id
      const digest = `sha256:${'a'.repeat(64)}`
      const trial = (await q.query<{ id: string }>(
        `INSERT INTO module_trials (module_id, from_version, to_version, to_digest) VALUES ('trivy', '1.0.0', '1.1.0', $1) RETURNING id`, [digest])).rows[0]!.id
      await expect(q.query(`INSERT INTO module_trials (module_id, from_version, to_version, to_digest) VALUES ('trivy', '1.0.0', '1.2.0', $1)`, [digest]))
        .rejects.toThrow(/module_trials_running_idx/)
      const mk = async (n: number, trigger: string, trialId: string | null, ext: string | null) => (await q.query<{ id: string }>(
        `INSERT INTO scans (project_id, number, trigger, priority, ref, profile_id, gate_id, trial_id, external_source)
         VALUES ($1, $2, $3, 5, 'main', $4, $5, $6, $7::jsonb) RETURNING id`, [project, n, trigger, p, g.id, trialId, ext])).rows[0]!.id
      const t = await mk(1, 'trial', trial, null)
      await expect(mk(2, 'trial', null, null)).rejects.toThrow(/scans_trial_id/)
      await expect(mk(3, 'manual', trial, null)).rejects.toThrow(/scans_trial_id/)
      await mk(4, 'external', null, '{"tool": "outil-interne", "format": "sarif"}')
      await expect(mk(5, 'external', null, null)).rejects.toThrow(/scans_external_source/)
      await expect(mk(6, 'manual', null, '{"tool": "x"}')).rejects.toThrow(/scans_external_source/)
      await q.query(`INSERT INTO result_cache (cache_key, module_id, image_digest, results_count) VALUES ($1, 'trivy', $2, 0)`, ['b'.repeat(64), digest])
      await q.query(`INSERT INTO scan_modules (scan_id, module_id, module_version, status, reused_from) VALUES ($1, 'trivy', '1.1.0', 'ok', $2)`, [t, 'b'.repeat(64)])
      await q.query(`INSERT INTO scan_modules (scan_id, module_id, module_version, status) VALUES ($1, 'hadolint', '2.0.0', 'not-applicable')`, [t])
      await q.query('DELETE FROM result_cache')
      expect((await q.query(`SELECT reused_from FROM scan_modules WHERE scan_id = $1 AND module_id = 'trivy'`, [t])).rows[0].reused_from).toBeNull()
      await q.query('DELETE FROM module_trials WHERE id = $1', [trial])
      expect((await q.query('SELECT 1 FROM scans WHERE id = $1', [t])).rowCount).toBe(0)
      await expect(q.query(`INSERT INTO self_vulns (subject, vuln_id, purl, severity) VALUES ('module:Trivy', 'CVE-2026-0001', 'pkg:npm/x', 'high')`))
        .rejects.toThrow(/self_vulns_subject_check/)
      await q.query('DELETE FROM projects WHERE id = $1', [project])
    })
  })

  describe('migrations', () => {
    it('crée toutes les tables et enregistre chaque migration avec son empreinte', async () => {
      const { rows } = await db.pool.query<{ table_name: string }>(
        `SELECT table_name FROM information_schema.tables WHERE table_schema = 'public' ORDER BY 1`,
      )
      expect(rows.map(r => r.table_name)).toEqual([
        'agent_inventories', 'ai_cache', 'ai_calls', 'ai_embeddings', 'ai_feedback', 'ai_tasks', 'api_tokens', 'appliance_settings', 'attestations', 'audit_log', 'canary_runs', 'content_detection', 'credentials', 'deploy_targets', 'deployments', 'exceptions',
        'findings', 'forge_apps', 'forge_publications', 'forges', 'gate_simulations', 'gates', 'helper_requests', 'integration_requests', 'license_policies', 'module_samples', 'module_trials', 'offline_bundles', 'oidc_bindings', 'oidc_issuers', 'owner_mappings', 'profile_rulesets', 'profiles', 'project_module_pins', 'projects', 'release_candidates', 'release_reports', 'result_cache', 'roles', 'ruleset_versions', 'rulesets', 'sbom_components', 'scan_findings', 'scan_modules',
        'scans', 'schema_migrations', 'self_vulns', 'sessions', 'severity_maps', 'triage_rules', 'trusted_keys', 'update_history', 'users', 'vex_statements', 'vuln_intel', 'webhook_deliveries',
      ])
      const mig = await db.pool.query('SELECT version, name, checksum FROM schema_migrations ORDER BY version')
      const files = loadMigrationsFromDir(MIGRATIONS_DIR)
      expect(files.map(f => f.name)).toEqual(['001_initial.sql', '002_modules.sql', '003_analyses.sql', '004_complements.sql', '005_upload_unique.sql', '006_modules_ia.sql', '007_reset_service_admin.sql', '008_refresh_feeds.sql', '009_sbom.sql', '010_ai_license.sql', '011_recorrelate_cascade.sql', '012_offline.sql', '013_triage_forges.sql', '014_profiles.sql', '015_forges.sql', '016_agent_inventories.sql', '017_validate_ruleset.sql', '018_release.sql', '019_oidc_repository_id.sql'])
      expect(mig.rows).toEqual(files.map((f, i) => ({ version: i + 1, name: f.name, checksum: f.checksum })))
    })

    it('est idempotente', async () => {
      const client = await db.pool.connect()
      try {
        expect(await applyMigrations(client, loadMigrationsFromDir(MIGRATIONS_DIR))).toEqual([])
      }
      finally {
        client.release()
      }
    })

    it('refuse une migration publiée puis modifiée, ou une base plus récente que le code', async () => {
      const client = await db.pool.connect()
      try {
        const tampered = prepareMigrations([{ name: '001_initial.sql', content: '-- modified\n' }])
        await expect(applyMigrations(client, tampered)).rejects.toThrow(/checksum mismatch/)
        await expect(applyMigrations(client, [])).rejects.toThrow(/unknown to this version/)
      }
      finally {
        client.release()
      }
    })

    it('annule une migration fautive en entier (transaction)', async () => {
      const client = await db.pool.connect()
      try {
        const shipped = loadMigrationsFromDir(MIGRATIONS_DIR)
        const num = (n: number) => String(n).padStart(3, '0')
        const broken = `${num(shipped.length + 1)}_broken.sql`
        const list = [
          ...shipped,
          ...prepareMigrations([
            ...shipped.map((_m, i) => ({ name: `${num(i + 1)}_x.sql`, content: '' })),
            { name: broken, content: 'CREATE TABLE half_done (id int); SELECT * FROM no_such_table;' },
          ]).slice(shipped.length),
        ]
        await expect(applyMigrations(client, list)).rejects.toThrow(new RegExp(`${broken} failed`))
        const t = await client.query(`SELECT to_regclass('public.half_done') AS t`)
        expect(t.rows[0].t).toBeNull()
        const v = await client.query('SELECT max(version) AS v FROM schema_migrations')
        expect(v.rows[0].v).toBe(shipped.length)
      }
      finally {
        client.release()
      }
    })

    it('migrate.mjs : code 0 sur une base neuve puis à jour, code 1 si une empreinte diffère', async () => {
      const fresh = await createTestDatabase({ migrate: false })
      const tmp = await mkdtemp(join(tmpdir(), 'scanoria-mig-'))
      try {
        const env = { ...process.env, NUXT_DATABASE_URL: fresh.url }
        const first = await run(process.execPath, [join(WEBUI, 'migrate.mjs')], { env })
        expect(first.stdout).toMatch(/applying 001_initial.sql/)
        const second = await run(process.execPath, [join(WEBUI, 'migrate.mjs')], { env })
        expect(second.stdout).toMatch(/0 applied now/)
        await writeFile(join(tmp, '001_initial.sql'), '-- not the released file\n')
        await expect(run(process.execPath, [join(WEBUI, 'migrate.mjs')], { env: { ...env, NUXT_MIGRATIONS_DIR: tmp } }))
          .rejects.toMatchObject({ code: 1 })
      }
      finally {
        await rm(tmp, { recursive: true, force: true })
        await fresh.drop()
      }
    })
  })

  describe('contraintes du schéma', () => {
    it('refuse un mot de passe hors format PHC, un nom invalide, un rôle inconnu', async () => {
      await expect(db.pool.query(`INSERT INTO users (username, password_hash) VALUES ('bob', 'plain')`)).rejects.toThrow()
      await expect(db.pool.query(`INSERT INTO users (username, password_hash) VALUES ('Bob', $1)`, [await hashPassword('x-long-password')])).rejects.toThrow()
      await expect(db.pool.query(`INSERT INTO users (username, role, password_hash) VALUES ('bob', 'root', $1)`, [await hashPassword('x-long-password')])).rejects.toThrow()
    })

    it('journal d’audit en ajout seul', async () => {
      await writeAudit(db.pool, { actor: { type: 'system' }, action: 'test.append', outcome: 'success', details: { password: 'hidden', n: 1 } })
      const { items } = await listAudit(db.pool, { limit: 10, offset: 0, action: 'test.' })
      expect(items).toHaveLength(1)
      expect(items[0]!.details).toEqual({ n: 1 })
      await expect(db.pool.query(`UPDATE audit_log SET outcome = 'failure'`)).rejects.toThrow(/append-only/)
    })

    it('supprime un compte qui figure dans le journal d’audit, sans toucher au journal', async () => {
      const carol = await createUser(db.pool, { username: 'carol', role: 'viewer', password: 'carol-long-password' })
      await writeAudit(db.pool, { actor: { type: 'user', userId: Number(carol.id), username: 'carol', ip: '192.0.2.20' }, action: 'auth.login', outcome: 'success' })
      expect(await deleteUser(db.pool, Number(carol.id))).toBe(true)
      const { items } = await listAudit(db.pool, { limit: 10, offset: 0, action: 'auth.login' })
      const row = items.find(i => i.actor_username === 'carol')
      expect(row).toBeDefined()
      expect(row!.actor_user_id).toBe(String(carol.id))
    })

    it('filtre le journal sans injection par le préfixe', async () => {
      const { items } = await listAudit(db.pool, { limit: 10, offset: 0, action: 'x\' OR 1=1 --' })
      expect(items).toEqual([])
    })
  })

  describe('comptes, sessions, verrouillage', () => {
    it('crée un compte et refuse un doublon', async () => {
      await createUser(db.pool, { username: 'alice', role: 'operator', password: 'alice-long-password' })
      await expect(createUser(db.pool, { username: 'alice', role: 'viewer', password: 'other-long-password' }))
        .rejects.toBeInstanceOf(UsernameTakenError)
    })

    it('authentifie puis verrouille après 5 échecs', async () => {
      clearSettingsCache()
      const settings = await getAuthSettings(db.pool, 0)
      expect(settings.lockoutThreshold).toBe(5)
      expect((await authenticate(db.pool, 'alice', 'alice-long-password', settings)).ok).toBe(true)
      expect(await authenticate(db.pool, 'nobody', 'whatever', settings)).toMatchObject({ ok: false, reason: 'unknown' })
      for (let i = 0; i < 4; i++) {
        expect(await authenticate(db.pool, 'alice', 'wrong', settings)).toMatchObject({ ok: false, reason: 'bad-password', lockedNow: false })
      }
      expect(await authenticate(db.pool, 'alice', 'wrong', settings)).toMatchObject({ ok: false, lockedNow: true })
      expect(await authenticate(db.pool, 'alice', 'alice-long-password', settings)).toMatchObject({ ok: false, reason: 'locked' })
      await db.pool.query(`UPDATE users SET locked_until = now() - interval '1 second' WHERE username = 'alice'`)
      expect((await authenticate(db.pool, 'alice', 'alice-long-password', settings)).ok).toBe(true)
    })

    it('ne stocke que l’empreinte du jeton ; révocation et compte désactivé', async () => {
      const settings = await getAuthSettings(db.pool, 0)
      const user = await db.pool.query<{ id: string }>(`SELECT id FROM users WHERE username = 'alice'`)
      const userId = Number(user.rows[0]!.id)
      const { token } = await createSession(db.pool, userId, settings, { ip: '192.0.2.10', userAgent: 'vitest' })
      const stored = await db.pool.query('SELECT token_hash FROM sessions WHERE user_id = $1', [userId])
      expect(stored.rows.some(r => r.token_hash === token)).toBe(false)
      const resolved = await resolveSession(db.pool, token, settings)
      expect(resolved?.user).toMatchObject({ username: 'alice', role: 'operator' })
      await revokeSession(db.pool, resolved!.tokenHash)
      expect(await resolveSession(db.pool, token, settings)).toBeNull()

      const second = await createSession(db.pool, userId, settings, {})
      await db.pool.query(`UPDATE users SET is_active = false WHERE id = $1`, [userId])
      expect(await resolveSession(db.pool, second.token, settings)).toBeNull()
      await db.pool.query(`UPDATE users SET is_active = true WHERE id = $1`, [userId])
      expect(await revokeUserSessions(db.pool, userId)).toBe(1)
      expect(await resolveSession(db.pool, second.token, settings)).toBeNull()
    })

    it('expire une session inactive', async () => {
      const settings = await getAuthSettings(db.pool, 0)
      const user = await db.pool.query<{ id: string }>(`SELECT id FROM users WHERE username = 'alice'`)
      const { token } = await createSession(db.pool, Number(user.rows[0]!.id), settings, {})
      await db.pool.query(`UPDATE sessions SET last_seen_at = now() - interval '2 hours' WHERE revoked_at IS NULL`)
      expect(await resolveSession(db.pool, token, settings)).toBeNull()
    })
  })

  describe('premier administrateur (bootstrap/admin.json)', () => {
    it('crée le compte s’il n’existe aucun administrateur, audite, supprime le fichier', async () => {
      const dir = await mkdtemp(join(tmpdir(), 'scanoria-boot-'))
      try {
        expect(await consumeBootstrapAdmin(db.pool, dir)).toBe('absent')
        expect(await countActiveAdmins(db.pool)).toBe(0)
        const hash = await hashPassword('first-admin-password')
        await writeFile(join(dir, 'admin.json'), JSON.stringify({ username: 'admin', password_hash: hash }), { mode: 0o600 })
        expect(await consumeBootstrapAdmin(db.pool, dir)).toBe('created')
        expect(await readdir(dir)).toEqual([])
        const settings = await getAuthSettings(db.pool, 0)
        expect((await authenticate(db.pool, 'admin', 'first-admin-password', settings)).ok).toBe(true)
        const audit = await listAudit(db.pool, { limit: 5, offset: 0, action: 'system.bootstrap-admin' })
        expect(audit.items[0]).toMatchObject({ outcome: 'success', actor_type: 'system' })

        await writeFile(join(dir, 'admin.json'), JSON.stringify({ username: 'other', password_hash: hash }))
        expect(await consumeBootstrapAdmin(db.pool, dir)).toBe('admin-exists')
        expect(await readdir(dir)).toEqual([])

        await writeFile(join(dir, 'admin.json'), JSON.stringify({ username: 'x', password_hash: 'plain' }))
        expect(await consumeBootstrapAdmin(db.pool, dir)).toBe('invalid')
        expect(await readdir(dir)).toEqual([])
      }
      finally {
        await rm(dir, { recursive: true, force: true })
      }
    })
  })
})
