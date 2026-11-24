// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Cœur de scanoria-worker (ARCHITECTURE § 12.1) : une passe = relever les
// résultats du runner, déclarer perdues les tâches sans réponse, puis déposer
// de nouvelles tâches tant que le runner annonce une place libre.
// Tout l'état vit en base et dans la file de fichiers : un worker arrêté puis
// relancé reprend là où il en était (rien n'est gardé en mémoire).

import { randomUUID } from 'node:crypto'
import { readdir, rm } from 'node:fs/promises'
import { join } from 'node:path'
import type pg from 'pg'
import { GateRules, VerdictDetails, type ErrorClass, type ScanModuleStatus } from '#shared/analysis'
import { UUID_V4_RE } from '#shared/schemas'
import { readModulesState } from '../utils/catalog'
import { logExcerpt, MAX_AI_EXCERPT } from '../health/log'
import { FAILED_MODULE_STATUSES } from '../health/scans'
import { gitRef, scanJobSchema, type JobCredential, type RunnerError, type ScanJob, type ScanResult } from './contract'
import { copyModuleLog, jobPending, listIncomingJobs, readResult, readRunnerState, resultDir, withdrawJob, writeJob } from './files'
import { pendingGate, type Integrations } from './integrations'
import {
  PLAN_VERSION, parsePlan, planHistory, planTimeout, readPlanCatalog, replayAvailability, resolveProfile,
  type PlannedModule, type ScanPlan,
} from './plan'
import { EFFECTIVE_PRIORITY_SQL, retryDelayS } from './priority'
import { makeRedactor } from './redact'
import { loadTimeoutOverrides } from '../ai/overrides'
import { aiLogContext } from '../ai/context'
import type { WorkerConfig } from './config'
import { awaitPackageDates, recordDatesGap } from '../sbom/dates'
import { isRecorrelation, recorrelationPlan, recorrelationSource, reportRecorrelation } from './recorrelate'

export interface WorkerPaths {
  modulesStateFile: string
  catalogIndexFile: string
}

type Log = (msg: string) => void

interface QueuedRow {
  id: string
  project_id: string
  trigger: string
  ref: string
  commit_sha: string | null
  upload_id: string | null
  attempt: number
  plan: unknown
  profile_id: string
  gate_id: string
}

interface ActiveRow {
  id: string
  project_id: string
  status: 'dispatched' | 'running' | 'ingesting'
  job_id: string
  attempt: number
  started_at: Date | null
  plan: unknown
}

class ScanFailure extends Error {
  constructor(readonly error: RunnerError) {
    super(error.message)
  }
}

/** État de l'appliance momentanément illisible : l'analyse reste en file, rien n'est figé (G12). */
class Deferred extends Error {
  constructor(readonly error: RunnerError) {
    super(error.message)
  }
}

/** Délai avant de reprendre une analyse laissée en « ingesting » sans tâche (arrêt du worker). */
const ORPHAN_INGEST_S = 120
/** Âge minimal d'une tâche de incoming/ sans analyse « dispatched » avant son retrait. */
const ORPHAN_JOB_S = 60
/** Nouvel essai quand l'état des modules ou le catalogue est illisible. */
const DEFER_S = 30

/** Tâche refusée par le runner avant lecture de scan_id : la correspondance se fait par l'id de tâche. */
const UNREADABLE_SCAN_ID = '00000000-0000-4000-8000-000000000000'

const err = (code: string, cls: ErrorClass, message: string): RunnerError => ({ code, class: cls, message: message.slice(0, 2000) })

export class ScanWorker {
  private readonly log: Log

  constructor(
    private readonly pool: pg.Pool,
    private readonly cfg: WorkerConfig,
    private readonly paths: WorkerPaths,
    private readonly integrations: Integrations,
    log?: Log,
  ) {
    this.log = log ?? (msg => console.log(`[worker] ${msg}`))
  }

  /** Une passe complète. */
  async tick(now = new Date()): Promise<void> {
    await this.withdrawCancelled()
    await this.sweepIncoming(now)
    await this.collect(now)
    await this.recoverOrphans()
    await this.dispatch(now)
  }

  // ---------------------------------------------------------------- dépôt

  /** Places libres : ce qu'annonce le runner, moins les tâches déjà déposées. */
  async freeSlots(now = new Date()): Promise<number> {
    const state = await readRunnerState(this.cfg.runnerStateFile, this.cfg.runnerStaleS, now)
    if (!state) return 0
    const r = await this.pool.query<{ n: number }>(`SELECT count(*)::int AS n FROM scans WHERE status IN ('dispatched', 'running')`)
    const inFlight = r.rows[0]?.n ?? 0
    return Math.max(0, Math.min(state.slots - state.busy, state.slots - inFlight))
  }

  async dispatch(now = new Date()): Promise<number> {
    const state = await readRunnerState(this.cfg.runnerStateFile, this.cfg.runnerStaleS, now)
    let free = await this.freeSlots(now)
    let dispatched = 0
    while (free > 0) {
      const outcome = await this.dispatchOne(state?.slots)
      if (outcome === 'empty' || outcome === 'deferred') break
      if (outcome === 'dispatched') {
        dispatched++
        free--
      }
    }
    return dispatched
  }

  /**
   * Prend l'analyse en file de plus haute priorité effective (G17), verrouillée
   * (FOR UPDATE SKIP LOCKED : un second worker ne la prend jamais), puis
   * dépose sa tâche. 'finished' : analyse conclue sans runner (plan vide,
   * source invalide) ; 'deferred' : état de l'appliance illisible, réessai plus tard.
   * Un verrou de transaction sérialise les dépôts entre workers : le quota par
   * projet et les places du runner sont recomptés sous ce verrou.
   */
  async dispatchOne(maxInFlight = Number.POSITIVE_INFINITY): Promise<'empty' | 'dispatched' | 'finished' | 'deferred'> {
    const client = await this.pool.connect()
    let finished: { scanId: string, error: RunnerError | null } | null = null
    let jobId: string | null = null
    try {
      await client.query('BEGIN')
      await client.query(`SELECT pg_advisory_xact_lock(hashtextextended('scanoria:dispatch', 0))`)
      const inflight = await client.query<{ n: number }>(`SELECT count(*)::int AS n FROM scans WHERE status IN ('dispatched', 'running')`)
      if ((inflight.rows[0]?.n ?? 0) >= maxInFlight) {
        await client.query('COMMIT')
        return 'empty'
      }
      const r = await client.query<QueuedRow>(
        `SELECT s.id, s.project_id, s.trigger, s.ref, s.commit_sha, s.upload_id, s.attempt, s.plan, s.profile_id, s.gate_id
           FROM scans s
          WHERE s.status = 'queued'
            AND (s.error ->> 'retry_at' IS NULL OR (s.error ->> 'retry_at')::timestamptz <= now())
            AND (SELECT count(*) FROM scans r
                  WHERE r.project_id = s.project_id AND r.status IN ('dispatched', 'running', 'ingesting')) < $1
          ORDER BY ${EFFECTIVE_PRIORITY_SQL} DESC, s.queued_at ASC
          LIMIT 1
          FOR UPDATE OF s SKIP LOCKED`, [this.cfg.perProjectLimit])
      const scan = r.rows[0]
      if (!scan) {
        await client.query('COMMIT')
        return 'empty'
      }
      let planned
      try {
        planned = await this.planFor(client, scan)
      }
      catch (e) {
        if (!(e instanceof Deferred)) throw e
        await client.query(
          `UPDATE scans SET error = $2::jsonb || jsonb_build_object('retry_at', now() + make_interval(secs => $3)) WHERE id = $1`,
          [scan.id, JSON.stringify(e.error), DEFER_S])
        await client.query('COMMIT')
        this.log(`scan ${scan.id}: ${e.error.code}, deferred ${DEFER_S}s`)
        return 'deferred'
      }
      try {
        const { plan, missing } = planned
        await client.query('DELETE FROM scan_modules WHERE scan_id = $1', [scan.id])
        for (const m of plan.modules) {
          const isMissing = missing.some(x => x.id === m.id)
          await client.query(
            `INSERT INTO scan_modules (scan_id, module_id, module_version, image_digest, feeds, status, error_class)
             VALUES ($1, $2, $3, $4, $5, $6, $7)`,
            [scan.id, m.id, m.version, m.image_digest, JSON.stringify(m.feeds), isMissing ? 'missing' : 'pending', isMissing ? 'input' : null])
        }
        const runnable = plan.modules.filter(m => !missing.some(x => x.id === m.id))
        const coverage = JSON.stringify({ gaps: plan.gaps })
        if (runnable.length === 0) {
          await client.query(
            `UPDATE scans SET plan = $2, coverage = COALESCE(coverage, '{}'::jsonb) || $3::jsonb, status = 'ingesting',
                    started_at = COALESCE(started_at, now()), job_id = NULL, error = NULL WHERE id = $1`,
            [scan.id, JSON.stringify(plan), coverage])
          finished = { scanId: scan.id, error: null }
        }
        else {
          const job = await this.buildJob(client, scan, plan, runnable)
          jobId = job.id
          await writeJob(this.cfg.scansDir, job)
          await client.query(
            `UPDATE scans SET plan = $2, coverage = COALESCE(coverage, '{}'::jsonb) || $3::jsonb, status = 'dispatched',
                    job_id = $4, started_at = now(), error = NULL WHERE id = $1`,
            [scan.id, JSON.stringify(plan), coverage, job.id])
        }
      }
      catch (e) {
        if (!(e instanceof ScanFailure)) throw e
        await client.query(
          `UPDATE scans SET status = 'ingesting', started_at = COALESCE(started_at, now()), job_id = NULL, error = $2 WHERE id = $1`,
          [scan.id, JSON.stringify(e.error)])
        await client.query(
          `UPDATE scan_modules SET status = 'error', error_class = 'input', finished_at = now()
            WHERE scan_id = $1 AND status IN ('pending', 'running')`, [scan.id])
        finished = { scanId: scan.id, error: e.error }
      }
      await client.query('COMMIT')
    }
    catch (e) {
      await client.query('ROLLBACK').catch(() => {})
      if (jobId) await withdrawJob(this.cfg.scansDir, jobId)
      throw e
    }
    finally {
      client.release()
    }
    if (finished) {
      await this.conclude(finished.scanId, { status: finished.error ? 'error' : 'done', error: finished.error, complete: false })
      return 'finished'
    }
    this.log(`dispatched job ${jobId}`)
    return 'dispatched'
  }

  /** Plan figé de l'analyse : repris tel quel (rejeu, relance), sinon résolu depuis le profil. */
  private async planFor(client: pg.PoolClient, scan: QueuedRow): Promise<{ plan: ScanPlan, missing: PlannedModule[] }> {
    const state = await readModulesState(this.paths.modulesStateFile)
    if (!state.available) throw new Deferred(err('E_MODULES_STATE', 'infra', 'installed modules state is unavailable'))
    const existing = scan.plan ? parsePlan(scan.plan) : null
    if (scan.plan && !existing) throw new ScanFailure(err('E_SCAN_PLAN', 'input', 'stored plan is invalid'))
    if (existing) {
      const { missing } = replayAvailability(existing, state.modules)
      return { plan: existing, missing }
    }
    const pr = await client.query<{ source_kind: 'git' | 'archive', spdx_license: string | null }>(
      'SELECT source_kind, spdx_license FROM projects WHERE id = $1', [scan.project_id])
    const project = pr.rows[0]!
    const prof = await client.query<{ id: string, slug: string, categories: string[], include_modules: string[], exclude_modules: string[] }>(
      'SELECT id, slug, categories, include_modules, exclude_modules FROM profiles WHERE id = $1', [scan.profile_id])
    const gate = await client.query<{ id: string, slug: string, rules: unknown }>('SELECT id, slug, rules FROM gates WHERE id = $1', [scan.gate_id])
    const rules = GateRules.safeParse(gate.rows[0]!.rules)
    if (!rules.success) throw new ScanFailure(err('E_SCAN_GATE', 'input', 'quality gate rules are invalid'))
    const catalog = await readPlanCatalog(this.paths.catalogIndexFile)
    if (catalog.size === 0 && state.modules.length > 0) throw new Deferred(err('E_CATALOG', 'infra', 'catalog index is unavailable'))
    // 0.5 (B, contrat 16) : une re-corrélation ne lance que les modules SCA qui lisent un SBOM.
    const recorrelate = scan.trigger === 'recorrelate'
    const { modules, gaps } = recorrelate
      ? recorrelationPlan({ installed: state.modules, catalog })
      : resolveProfile({
          profile: prof.rows[0]!,
          sourceKind: project.source_kind,
          projectLicense: project.spdx_license,
          installed: state.modules,
          catalog,
          timeoutOverrides: await loadTimeoutOverrides(client),
        })
    const plan: ScanPlan = {
      version: PLAN_VERSION,
      created_at: new Date().toISOString(),
      source: { kind: recorrelate ? 'sbom' : project.source_kind, ref: scan.ref, commit: scan.commit_sha, history: recorrelate ? 'shallow' : planHistory(modules) },
      profile: prof.rows[0]!,
      gate: { id: gate.rows[0]!.id, slug: gate.rows[0]!.slug, rules: rules.data },
      modules,
      gaps,
      timeout_s: planTimeout(modules),
    }
    return { plan, missing: [] }
  }

  /** Tâche du runner ; le secret de la source est déchiffré ici, au dernier moment, et jamais journalisé. */
  private async buildJob(client: pg.PoolClient, scan: QueuedRow, plan: ScanPlan, modules: PlannedModule[]): Promise<ScanJob> {
    const pr = await client.query<{ source_kind: string, repo_url: string | null, credential_id: string | null, extra: Record<string, unknown> }>(
      `SELECT source_kind, repo_url, credential_id, to_jsonb(projects) - 'detection' AS extra FROM projects WHERE id = $1`, [scan.project_id])
    const project = pr.rows[0]!
    let source: ScanJob['source']
    if (plan.source.kind === 'sbom') {
      const sbom = await recorrelationSource(client, scan.id)
      if (!sbom) throw new ScanFailure(err('E_SCAN_SOURCE', 'input', 'the SBOM to recorrelate is missing or too large'))
      source = sbom
    }
    else if (plan.source.kind === 'archive') {
      if (!scan.upload_id) throw new ScanFailure(err('E_SCAN_SOURCE', 'input', 'no uploaded archive for this project'))
      source = { kind: 'archive', upload_id: scan.upload_id }
    }
    else {
      if (!project.repo_url) throw new ScanFailure(err('E_SCAN_SOURCE', 'input', 'project has no repository URL'))
      source = {
        kind: 'git',
        url: project.repo_url,
        ref: plan.source.ref,
        // Branche par défaut transmise seulement si elle est valide : elle ne fait jamais refuser la tâche.
        ...(gitRef.safeParse(project.extra.default_branch).success ? { default_branch: project.extra.default_branch as string } : {}),
        history: plan.source.history,
        credential: await this.credential(client, project.credential_id, project.extra),
        ...(plan.source.commit ? { commit: plan.source.commit } : {}),
      }
    }
    const job = {
      schema: 1 as const,
      id: randomUUID(),
      scan_id: scan.id,
      project_id: scan.project_id,
      created_at: new Date().toISOString(),
      source,
      modules: modules.map(m => ({ id: m.id, version: m.version, options: m.options })),
    }
    const parsed = scanJobSchema.safeParse(job)
    // Message générique : la tâche peut contenir un secret, jamais recopié.
    if (!parsed.success) throw new ScanFailure(err('E_SCAN_SOURCE', 'input', 'scan source rejected (URL, ref or credential)'))
    return parsed.data
  }

  private async credential(client: pg.PoolClient, credentialId: string | null, extra: Record<string, unknown>): Promise<JobCredential> {
    if (!credentialId) return null
    let secret
    try {
      secret = await this.integrations.decryptSecret(client, credentialId)
    }
    catch {
      throw new ScanFailure(err('E_SCAN_CREDENTIAL', 'input', 'repository credential cannot be decrypted'))
    }
    if (secret.kind === 'token') {
      return { kind: 'token', token: secret.value, ...(secret.username ? { username: secret.username } : {}) }
    }
    if (secret.kind === 'ssh-key') {
      const knownHosts = typeof extra.ssh_known_hosts === 'string' ? extra.ssh_known_hosts : ''
      if (!knownHosts) throw new ScanFailure(err('E_SCAN_KNOWN_HOSTS', 'input', 'SSH host key not confirmed for this project'))
      return { kind: 'ssh-key', private_key: secret.value, known_hosts: knownHosts }
    }
    throw new ScanFailure(err('E_SCAN_CREDENTIAL', 'input', 'unsupported repository credential'))
  }

  // ------------------------------------------------------------ relevé

  /** Relève les résultats, passe les tâches prises en « running », déclare perdues les autres. */
  async collect(now = new Date()): Promise<void> {
    const r = await this.pool.query<ActiveRow>(
      `SELECT id, project_id, status, job_id, attempt, started_at, plan FROM scans
        WHERE status IN ('dispatched', 'running', 'ingesting') AND job_id IS NOT NULL
        ORDER BY started_at NULLS FIRST`)
    for (const scan of r.rows) {
      // Une analyse en échec n'arrête pas le relevé des autres.
      try {
        await this.collectOne(scan, now)
      }
      catch (e) {
        this.log(`scan ${scan.id}: collect failed: ${(e as Error).message}`)
      }
    }
  }

  private async collectOne(scan: ActiveRow, now: Date): Promise<void> {
    const read = await readResult(this.cfg.scansDir, scan.job_id)
    if (read.kind !== 'absent') {
      await this.withScanLock(scan.id, () => this.processResult(scan, read))
      return
    }
    if (scan.status === 'dispatched' && !(await jobPending(this.cfg.scansDir, scan.job_id))) {
      await this.pool.query(`UPDATE scans SET status = 'running' WHERE id = $1 AND status = 'dispatched' AND job_id = $2`, [scan.id, scan.job_id])
    }
    const plan = parsePlan(scan.plan)
    const deadline = (scan.started_at?.getTime() ?? now.getTime()) + ((plan?.timeout_s ?? 0) + this.cfg.resultMarginS) * 1000
    if (now.getTime() > deadline) {
      await this.withScanLock(scan.id, async () => {
        if (!(await this.stillCurrent(scan))) return
        await withdrawJob(this.cfg.scansDir, scan.job_id)
        await this.failInfra(scan, err('E_RESULT_TIMEOUT', 'infra', 'no result from the runner before the plan deadline'))
      })
    }
  }

  /** Verrou consultatif par analyse : un seul worker ingère une analyse donnée. */
  private async withScanLock(scanId: string, fn: () => Promise<void>): Promise<void> {
    const client = await this.pool.connect()
    try {
      const got = await client.query<{ ok: boolean }>('SELECT pg_try_advisory_lock(hashtextextended($1, 0)) AS ok', [`scan:${scanId}`])
      if (!got.rows[0]?.ok) return
      try {
        await fn()
      }
      finally {
        await client.query('SELECT pg_advisory_unlock(hashtextextended($1, 0))', [`scan:${scanId}`])
      }
    }
    finally {
      client.release()
    }
  }

  /** Relit l'analyse sous verrou : elle a pu être annulée ou relancée entre-temps. */
  private async stillCurrent(scan: ActiveRow): Promise<boolean> {
    const r = await this.pool.query<{ ok: boolean }>(
      `SELECT true AS ok FROM scans WHERE id = $1 AND job_id = $2 AND status IN ('dispatched', 'running', 'ingesting')`,
      [scan.id, scan.job_id])
    return !!r.rows[0]
  }

  private async processResult(scan: ActiveRow, read: Exclude<Awaited<ReturnType<typeof readResult>>, { kind: 'absent' }>): Promise<void> {
    if (!(await this.stillCurrent(scan))) return
    if (read.kind === 'invalid' || read.result.id !== scan.job_id || (read.result.scan_id !== scan.id && read.result.scan_id !== UNREADABLE_SCAN_ID)) {
      await this.failInfra(scan, err('E_RESULT_INVALID', 'infra', `runner result rejected (${read.kind === 'invalid' ? read.reason : 'identifiers'})`))
      return
    }
    // Rien de ce que renvoie le runner n'est stocké ni affiché avant masquage du secret de la source.
    const redact = await this.redactorFor(scan.project_id)
    const result = redactResult(read.result, redact)
    const infra = result.error?.class === 'infra' ? result.error : result.modules.find(m => m.error?.class === 'infra')?.error
    if (infra && scan.status !== 'ingesting' && scan.attempt <= this.cfg.maxInfraRetries) {
      await this.retry(scan, infra)
      return
    }
    const plan = parsePlan(scan.plan)
    const wanted = plan?.source.commit ?? null
    const moved = await this.pool.query(
      `UPDATE scans SET status = 'ingesting',
              commit_sha = COALESCE(commit_sha, $2),
              plan = CASE WHEN $2::text IS NULL OR $4::boolean THEN plan ELSE jsonb_set(plan, '{source,commit}', to_jsonb($2::text)) END
        WHERE id = $1 AND job_id = $3 AND status IN ('dispatched', 'running', 'ingesting')`,
      [scan.id, result.source.commit, scan.job_id, wanted !== null])
    if (!moved.rowCount) return
    // G11 : un rejeu ou une analyse épinglée doit porter sur le commit demandé, sinon rien n'est ingéré.
    if (wanted && result.source.commit && result.source.commit !== wanted) {
      await this.pool.query(
        `UPDATE scan_modules SET status = 'error', error_class = 'input', finished_at = now()
          WHERE scan_id = $1 AND status IN ('pending', 'running')`, [scan.id])
      await this.conclude(scan.id, { status: 'error', error: err('E_COMMIT_MISMATCH', 'input', 'the runner analysed another commit than the planned one'), complete: false })
      return
    }
    const complete = await this.recordModules(scan, result, plan, redact)
    await this.mergeSourceCoverage(scan.id, result)
    await this.conclude(scan.id, {
      status: result.status === 'ok' ? 'done' : 'error',
      error: result.status === 'ok' ? null : (result.error ?? err('E_RUNNER', 'infra', 'runner reported an error')),
      complete,
    })
  }

  /** Met à jour scan_modules, copie les journaux (G20), ingère les sorties (contrat 5). */
  private async recordModules(scan: ActiveRow, result: ScanResult, plan: ScanPlan | null, redact: (t: string) => string): Promise<boolean> {
    const rows = await this.pool.query<{ module_id: string, status: ScanModuleStatus }>('SELECT module_id, status FROM scan_modules WHERE scan_id = $1', [scan.id])
    let complete = result.status === 'ok'
    for (const row of rows.rows) {
      const m = result.modules.find(x => x.id === row.module_id)
      if (!m) {
        if (row.status === 'pending' || row.status === 'running') {
          const cls: ErrorClass = result.error?.class ?? 'infra'
          await this.pool.query(`UPDATE scan_modules SET status = 'error', error_class = $3, finished_at = now() WHERE scan_id = $1 AND module_id = $2`, [scan.id, row.module_id, cls])
        }
        complete = false
        continue
      }
      let status: ScanModuleStatus = m.status
      let errorClass: ErrorClass | null = m.error?.class ?? null
      let count: number | null = null
      // G11 : l'image exécutée doit être celle du plan (empreinte), sinon le module n'est pas concluant.
      const plannedDigest = plan?.modules.find(x => x.id === m.id)?.image_digest ?? null
      if (m.status === 'ok' && plannedDigest && m.image_digest && m.image_digest !== plannedDigest) {
        this.log(`scan ${scan.id} module ${m.id}: image digest differs from the plan`)
        status = 'error'
        errorClass = 'infra'
      }
      else if (m.status === 'ok') {
        try {
          const outputs = Object.fromEntries(Object.entries(m.outputs).filter((e): e is [string, string] => typeof e[1] === 'string'))
          const out = await this.integrations.ingestModuleOutputs(this.pool, { scanId: scan.id, moduleId: m.id, resultDir: resultDir(this.cfg.scansDir, scan.job_id), outputs })
          count = out.count
          if (out.errors.length) this.log(`scan ${scan.id} module ${m.id}: ${out.errors.length} ingestion error(s)`)
          // Sortie illisible ou non conforme (G2) : module non concluant ; une troncature reste un succès.
          if (out.errors.some(e => (e as { code?: string })?.code !== 'truncated')) {
            status = 'invalid-output'
            errorClass = 'tool'
          }
        }
        catch (e) {
          this.log(`scan ${scan.id} module ${m.id}: ingestion failed: ${(e as Error).message}`)
          status = 'invalid-output'
          errorClass = 'tool'
        }
      }
      if (status !== 'ok' && status !== 'skipped') complete = false
      let logPath: string | null = null
      if (m.log) {
        try {
          logPath = await copyModuleLog(this.cfg.scansDir, scan.job_id, m.log, this.cfg.scanLogsDir, scan.id, m.id, redact)
        }
        catch (e) {
          this.log(`scan ${scan.id} module ${m.id}: log copy failed: ${(e as Error).message}`)
        }
      }
      await this.pool.query(
        `UPDATE scan_modules SET status = $3, error_class = $4, image_digest = COALESCE($5, image_digest), feeds = $6,
                results_count = $7, duration_ms = $8, log_path = $9, started_at = $10, finished_at = $11,
                attempts = $12, peak_memory_mb = $13, cpu_ms = $14
          WHERE scan_id = $1 AND module_id = $2`,
        [scan.id, m.id, status, errorClass, m.image_digest, JSON.stringify(m.feeds), count,
          m.stats?.duration_ms ?? null, logPath, m.started_at ?? null, m.finished_at ?? null, scan.attempt,
          // F14, G20 : mesures du runner ; absentes, elles restent NULL (jamais 0).
          m.stats?.peak_memory_mb ?? null, m.stats?.cpu_ms ?? null])
    }
    return complete
  }

  /** Fichiers ignorés par le runner (G15), ajoutés à la couverture ; D la complète. */
  private async mergeSourceCoverage(scanId: string, result: ScanResult): Promise<void> {
    const source = { files: result.source.files, bytes: result.source.bytes, history: result.source.history, skipped: result.source.skipped }
    await this.pool.query(`UPDATE scans SET coverage = COALESCE(coverage, '{}'::jsonb) || jsonb_build_object('source', $2::jsonb) WHERE id = $1`,
      [scanId, JSON.stringify(source)])
  }

  /** Erreur infra (G12) : relance avec recul tant qu'il reste des essais, sinon analyse en erreur. */
  private async failInfra(scan: ActiveRow, error: RunnerError): Promise<void> {
    if (scan.attempt <= this.cfg.maxInfraRetries) {
      await this.retry(scan, error)
      return
    }
    const moved = await this.pool.query(
      `UPDATE scans SET status = 'ingesting' WHERE id = $1 AND job_id = $2 AND status IN ('dispatched', 'running', 'ingesting')`,
      [scan.id, scan.job_id])
    if (!moved.rowCount) return
    await this.pool.query(
      `UPDATE scan_modules SET status = 'error', error_class = 'infra', finished_at = now()
        WHERE scan_id = $1 AND status IN ('pending', 'running')`, [scan.id])
    await this.conclude(scan.id, { status: 'error', error, complete: false })
  }

  private async retry(scan: ActiveRow, error: RunnerError): Promise<void> {
    const delay = retryDelayS(scan.attempt, this.cfg.retryBaseS)
    const res = await this.pool.query(
      `UPDATE scans SET status = 'queued', attempt = attempt + 1, job_id = NULL,
              error = $3::jsonb || jsonb_build_object('retry_at', now() + make_interval(secs => $4))
        WHERE id = $1 AND job_id = $2 AND status IN ('dispatched', 'running', 'ingesting')`,
      [scan.id, scan.job_id, JSON.stringify(error), delay])
    if (res.rowCount) {
      await this.pool.query(
        `UPDATE scan_modules SET status = 'pending', error_class = NULL, results_count = NULL, duration_ms = NULL,
                peak_memory_mb = NULL, cpu_ms = NULL, started_at = NULL, finished_at = NULL WHERE scan_id = $1 AND status <> 'missing'`, [scan.id])
      this.log(`scan ${scan.id}: ${error.code}, retry ${scan.attempt + 1} in ${delay}s`)
    }
  }

  /** Masquage du secret de la source du projet (déchiffré ici, jamais journalisé). */
  private async redactorFor(projectId: string): Promise<(text: string) => string> {
    const r = await this.pool.query<{ credential_id: string | null }>('SELECT credential_id FROM projects WHERE id = $1', [projectId])
    const id = r.rows[0]?.credential_id
    if (!id) return makeRedactor([])
    try {
      const secret = await this.integrations.decryptSecret(this.pool, id)
      return makeRedactor([secret.value])
    }
    catch {
      return makeRedactor([])
    }
  }

  /**
   * Analyses laissées en « ingesting » sans tâche (worker arrêté entre la
   * transition et la conclusion) : conclues à la reprise, sinon elles
   * occuperaient le quota du projet pour toujours.
   */
  async recoverOrphans(): Promise<number> {
    const r = await this.pool.query<{ id: string, error: RunnerError | null }>(
      `SELECT id, error FROM scans
        WHERE status = 'ingesting' AND job_id IS NULL AND started_at < now() - make_interval(secs => $1)`, [ORPHAN_INGEST_S])
    for (const row of r.rows) {
      await this.withScanLock(row.id, () => this.conclude(row.id, { status: row.error ? 'error' : 'done', error: row.error, complete: false }))
    }
    return r.rows.length
  }

  /**
   * Tâches de incoming/ qu'aucune analyse « dispatched » ne réclame (arrêt
   * entre le dépôt et la validation, analyse annulée pendant l'arrêt du
   * worker) : retirées, car elles portent le secret de la source.
   */
  async sweepIncoming(now = new Date()): Promise<number> {
    const jobs = (await listIncomingJobs(this.cfg.scansDir)).filter(j => j.mtimeMs < now.getTime() - ORPHAN_JOB_S * 1000)
    if (!jobs.length) return 0
    const r = await this.pool.query<{ job_id: string }>(
      `SELECT job_id::text FROM scans WHERE job_id = ANY($1::uuid[]) AND status = 'dispatched'`, [jobs.map(j => j.id)])
    const wanted = new Set(r.rows.map(x => x.job_id))
    let n = 0
    for (const j of jobs) {
      if (wanted.has(j.id)) continue
      if (await withdrawJob(this.cfg.scansDir, j.id)) {
        this.log(`orphan job ${j.id} withdrawn`)
        n++
      }
    }
    return n
  }

  /**
   * Fin d'une analyse : résultats finalisés (contrat 5), verdict (contrat 6),
   * enregistré, puis explication IA demandée (contrat 7, sans effet si l'IA est inactive).
   */
  async conclude(scanId: string, outcome: { status: 'done' | 'error', error: RunnerError | null, complete: boolean }): Promise<void> {
    // 0.5 (B) : une re-corrélation ne déclare jamais un résultat corrigé (contrat 16) ;
    // une release attend les dates de publication de ses composants (H5).
    const complete = outcome.complete && !(await isRecorrelation(this.pool, scanId))
    // H5 : une release attend les dates (90 s au plus) ; au-delà, les dates manquantes restent visibles dans la couverture (G15).
    const dated = await awaitPackageDates(this.pool, scanId).catch((e: unknown) => {
      this.log(`scan ${scanId}: package dates: ${(e as Error).message}`)
      return false
    })
    if (!dated) await recordDatesGap(this.pool, scanId).catch(() => {})
    try {
      await this.integrations.finalizeScanFindings(this.pool, scanId, { complete })
    }
    catch (e) {
      this.log(`scan ${scanId}: finalize failed: ${(e as Error).message}`)
    }
    let details: VerdictDetails
    try {
      details = VerdictDetails.parse(await this.integrations.evaluateGate(this.pool, scanId))
    }
    catch (e) {
      this.log(`scan ${scanId}: gate evaluation failed: ${(e as Error).message}`)
      details = await pendingGate(this.pool, scanId)
    }
    const r = await this.pool.query<{ project_id: string }>(
      `UPDATE scans SET status = $2, verdict = $3, verdict_details = $4, error = $5, finished_at = now()
        WHERE id = $1 AND status = 'ingesting' RETURNING project_id`,
      [scanId, outcome.status, details.verdict, JSON.stringify(details), outcome.error ? JSON.stringify(outcome.error) : null])
    if (!r.rows[0]) return
    this.log(`scan ${scanId}: ${outcome.status}, verdict ${details.verdict}`)
    try {
      await this.integrations.enqueueAiTask(this.pool, {
        kind: 'explain-verdict', subjectType: 'scan', subjectId: scanId, projectId: r.rows[0].project_id, priority: 10,
      })
      // I5 : résumé de l'analyse, même branchement (contrat 13).
      await this.integrations.enqueueAiTask(this.pool, {
        kind: 'summarize-scan', subjectType: 'scan', subjectId: scanId, projectId: r.rows[0].project_id, priority: 10,
      })
      // 0.5 : I11 (atteignabilité, index reach-index lu dans le dossier de résultats) et I18 (licences), même branchement.
      await this.integrations.enqueueAfterVerdict?.(this.pool, { scanId, projectId: r.rows[0].project_id, scansDir: this.cfg.scansDir })
    }
    catch (e) {
      this.log(`scan ${scanId}: AI task not queued: ${(e as Error).message}`)
    }
    await this.requestDiagnosis(scanId, r.rows[0].project_id)
    await reportRecorrelation(this.pool, scanId).catch((e: unknown) => this.log(`scan ${scanId}: recorrelation report: ${(e as Error).message}`))
  }

  /**
   * I15 : un module fini en error, timeout, oom ou invalid-output demande le
   * diagnostic IA de l'analyse (contrat 13), une seule fois, après le dernier
   * module. Contexte joint au format du chantier D, {logs: [{module, excerpt}]} :
   * fin masquée du journal de chaque module en échec (8 au plus, 16 Ko en tout),
   * seule source lisible par scanoria-ai. Sans effet sans connecteur.
   */
  private async requestDiagnosis(scanId: string, projectId: string): Promise<void> {
    try {
      const failed = await this.pool.query<{ module_id: string, log_path: string | null }>(
        `SELECT module_id, log_path FROM scan_modules
          WHERE scan_id = $1 AND status = ANY($2::text[]) ORDER BY module_id LIMIT 8`, [scanId, [...FAILED_MODULE_STATUSES]])
      if (!failed.rows.length) return
      const share = Math.floor(MAX_AI_EXCERPT / failed.rows.length)
      const logs: { module: string, excerpt: string }[] = []
      for (const m of failed.rows) {
        const excerpt = await logExcerpt(this.cfg.scanLogsDir, m.log_path, share).catch(() => null)
        if (excerpt) logs.push({ module: m.module_id, excerpt })
      }
      await this.integrations.enqueueAiTask(this.pool, {
        kind: 'diagnose-scan', subjectType: 'scan', subjectId: scanId, projectId,
        // Format et bornes du chantier D : masqué de nouveau (règle IA), fin de journal, 16 Ko en tout.
        context: aiLogContext(logs.map(l => ({ module: l.module, log: l.excerpt }))),
      })
    }
    catch (e) {
      this.log(`scan ${scanId}: diagnosis not queued: ${(e as Error).message}`)
    }
  }

  // ----------------------------------------------------------- annulation

  /**
   * Tâches d'analyses annulées pas encore prises par le runner : retirées de
   * incoming/ (la console, sans droit d'écriture sur la file, ne fait que
   * marquer l'analyse annulée). Au-delà d'une heure, sweepIncoming s'en charge.
   */
  async withdrawCancelled(): Promise<number> {
    const r = await this.pool.query<{ job_id: string }>(
      `SELECT job_id FROM scans WHERE status = 'cancelled' AND job_id IS NOT NULL AND finished_at > now() - interval '1 hour'`)
    let n = 0
    for (const row of r.rows) {
      if (await withdrawJob(this.cfg.scansDir, row.job_id)) n++
    }
    return n
  }

  /** Journaux d'analyses disparues (projet supprimé) : purgés (G20). */
  async purgeOrphanLogs(): Promise<number> {
    let names: string[]
    try {
      names = await readdir(this.cfg.scanLogsDir)
    }
    catch {
      return 0
    }
    const ids = names.filter(n => UUID_V4_RE.test(n))
    if (!ids.length) return 0
    const r = await this.pool.query<{ id: string }>('SELECT id FROM scans WHERE id = ANY($1::uuid[])', [ids])
    const alive = new Set(r.rows.map(x => x.id))
    let purged = 0
    for (const id of ids) {
      if (alive.has(id)) continue
      await rm(join(this.cfg.scanLogsDir, id), { recursive: true, force: true })
      purged++
    }
    return purged
  }
}

/**
 * Annulation (API) : une analyse en file, déposée ou en cours. La tâche est
 * retirée de la file par le worker si le runner ne l'a pas prise ; sinon elle
 * va à son terme et son résultat est ignoré.
 */
export async function cancelScan(db: Pick<pg.Pool, 'query'>, scanId: string): Promise<boolean> {
  const r = await db.query(
    `UPDATE scans SET status = 'cancelled', finished_at = now()
      WHERE id = $1 AND status IN ('queued', 'dispatched', 'running')`, [scanId])
  if (!r.rowCount) return false
  await db.query(`UPDATE scan_modules SET status = 'skipped' WHERE scan_id = $1 AND status IN ('pending', 'running')`, [scanId])
  return true
}

/** Copie du résultat dont les messages d'erreur sont masqués. */
function redactResult(result: ScanResult, redact: (t: string) => string): ScanResult {
  const fix = <E extends { message: string } | null | undefined>(e: E): E => (e ? { ...e, message: redact(e.message).slice(0, 2000) } : e)
  return { ...result, error: fix(result.error), modules: result.modules.map(m => ({ ...m, error: fix(m.error) })) }
}
