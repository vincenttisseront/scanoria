// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// J9, J11–J13 (0.8, chantier D) : avancement des exécutions d'une analyse au
// verdict favorable, par passes successives et dans cet ordre :
//   1. J13 : empreinte de la candidate résolue dans le dépôt « candidat » ;
//   2. J9  : attestation de chaque image, signée par le helper root ;
//   3. J13 : copie par empreinte vers le dépôt « validé », attestation jointe ;
//   4. J12 : PR GitOps qui porte la nouvelle empreinte ;
//   5. J11 : déclenchement de la CD existante, puis suivi borné.
// Une étape ne commence que si les précédentes ont réussi : à la première
// étape en échec, les suivantes échouent avec E_DEPLOY_PREVIOUS (« arrêt
// net », J16). L'appliance ne détient aucun accès à la production, ne lance
// ni SSH, ni Ansible, ni kubectl, et ne fusionne aucune PR.

import type { Queryable } from '../utils/db'
import { writeAudit } from '../utils/audit'
import { decryptSecret } from '../utils/secrets'
import { getForge, forgeAccess } from '../forges'
import { consoleUrl } from '../forges/context'
import { ForgeError, forgeGet, forgeSend, type ForgeRequest } from '../forges/http'
import { MAX_GITOPS_FILE_BYTES, forgeDeployer, type ForgeDeployer } from '../forges/deploy'
import { escapeInline } from '../forges/sanitize'
import { collectSignatures, listAttestations, requestAttestation } from '../attest'
import { PREDICATE_TYPE, type VerdictPredicate } from '../attest/dsse'
import { parseConfig, fillTemplate, type CdTriggerConfig, type DeployKind, type GitopsConfig, type RegistryConfig } from './config'
import { claimDeployment, finishDeployment, safeUrl, setExternal, type DeploymentStatus } from './runs'
import { RegistryClient, RegistryError, copyImage, parseRepository, pushAttestation } from './registry'
import { GitopsError, promotionBranch, replaceImageDigest } from './gitops'

export const CD_TIMEOUT_MS = 6 * 3600_000
export const ATTEST_TIMEOUT_MS = 15 * 60_000
const SYSTEM = { type: 'system' as const, username: 'system' }

interface ScanInfo {
  id: string
  project_id: string
  commit_sha: string
  ref: string
  tag: string | null
  report_sha256: string | null
  evaluated_at: string
  forge_id: string | null
  repo_full_name: string | null
  verdict: string | null
}

interface Run {
  id: string
  target_id: string
  kind: DeployKind
  environment: string
  status: DeploymentStatus
  config: unknown
  credential_id: string | null
  auto_merge: boolean
  external_id: string | null
  error: string | null
  created_at: Date
}

const ORDER: DeployKind[] = ['registry-promotion', 'gitops-pr', 'cd-trigger']

async function loadScan(db: Queryable, scanId: string): Promise<ScanInfo | null> {
  const r = await db.query<ScanInfo>(
    `SELECT s.id::text, s.project_id::text, s.commit_sha, s.ref, s.verdict,
            COALESCE(rr.tag, rc.tag) AS tag, rr.report_sha256,
            to_char(COALESCE((s.verdict_details ->> 'evaluated_at')::timestamptz, s.finished_at) AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS evaluated_at,
            p.forge_id::text, p.repo_full_name
       FROM scans s JOIN projects p ON p.id = s.project_id
       LEFT JOIN release_reports rr ON rr.scan_id = s.id AND rr.status = 'signed'
       LEFT JOIN release_candidates rc ON rc.scan_id = s.id
      WHERE s.id = $1`, [scanId])
  return r.rows[0] ?? null
}

async function loadRuns(db: Queryable, scanId: string): Promise<Run[]> {
  const r = await db.query<Run>(
    `SELECT d.id::text, d.target_id::text, t.kind, t.environment, d.status, t.config, t.credential_id::text, t.auto_merge,
            d.external_id, d.error, d.created_at
       FROM deployments d JOIN deploy_targets t ON t.id = d.target_id
      WHERE d.scan_id = $1 AND d.status <> 'refused'
      ORDER BY t.environment, t.kind`, [scanId])
  return r.rows
}

const terminal = (s: DeploymentStatus) => s === 'succeeded' || s === 'failed' || s === 'refused'

function predicateOf(scan: ScanInfo, url: string | null): VerdictPredicate {
  return {
    scan_id: scan.id,
    project_id: scan.project_id,
    verdict: 'passed',
    commit_sha: scan.commit_sha,
    ref: scan.ref,
    ...(scan.tag ? { tag: scan.tag } : {}),
    ...(scan.report_sha256 ? { report_sha256: scan.report_sha256 } : {}),
    ...(url ? { report_url: `${url}/scans/${scan.id}` } : {}),
    evaluated_at: scan.evaluated_at,
  }
}

async function registryClient(db: Queryable, host: string, credentialId: string | null): Promise<RegistryClient> {
  if (!credentialId) return new RegistryClient(host)
  const s = await decryptSecret(db, credentialId)
  return new RegistryClient(host, { username: s.username ?? null, password: s.value })
}

async function deployerFor(db: Queryable, scan: ScanInfo): Promise<ForgeDeployer> {
  const forge = scan.forge_id ? await getForge(db, scan.forge_id) : null
  if (!forge) throw new ForgeError('E_FORGE_UNSUPPORTED')
  const access = await forgeAccess(db, forge)
  if (!access.token) throw new ForgeError('E_FORGE_AUTH')
  return forgeDeployer(access, { consoleUrl: await consoleUrl() })
}

function errorCode(err: unknown): string {
  if (err instanceof RegistryError || err instanceof ForgeError || err instanceof GitopsError) return err.message.slice(0, 200)
  return 'E_DEPLOY_INTERNAL'
}

async function audit(db: Queryable, action: string, run: Run, scan: ScanInfo, details: Record<string, unknown>, outcome: 'success' | 'failure' = 'success') {
  await writeAudit(db, { actor: SYSTEM, action, outcome, targetType: 'deployment', targetId: run.id, details: { scan_id: scan.id, project_id: scan.project_id, environment: run.environment, ...details } })
}

// --- 1 à 3 : registre et attestations ------------------------------------------------------

async function advancePromotion(db: Queryable, run: Run, scan: ScanInfo, url: string | null): Promise<void> {
  const cfg = parseConfig('registry-promotion', run.config) as RegistryConfig | null
  if (!cfg) return finishDeployment(db, run.id, 'failed', { error: 'E_DEPLOY_CONFIG' })
  const src = parseRepository(cfg.source)
  const dst = parseRepository(cfg.destination)
  if (run.status === 'pending') {
    // 1. Empreinte de la candidate : l'étiquette n'est lue qu'ici, ensuite tout se fait par empreinte.
    const tag = fillTemplate(cfg.source_tag, { tag: scan.tag, commit: scan.commit_sha })
    if (!tag) return finishDeployment(db, run.id, 'failed', { error: 'E_DEPLOY_TAG' })
    const client = await registryClient(db, src.host, run.credential_id)
    const digest = await client.resolve(src.repo, tag)
    if (!await claimDeployment(db, run.id, digest)) return
    run.external_id = digest
    run.status = 'running'
  }
  const digest = run.external_id
  if (!digest || !/^sha256:[0-9a-f]{64}$/.test(digest)) return finishDeployment(db, run.id, 'failed', { error: 'E_DEPLOY_DIGEST' })
  // 2. Attestation J9 du sujet (dépôt « validé », même empreinte).
  const att = await requestAttestation(db, { scanId: scan.id, subjectName: cfg.destination, digest, predicate: predicateOf(scan, url) })
  if (att.status === 'pending') {
    if (Date.now() - run.created_at.getTime() > ATTEST_TIMEOUT_MS) return finishDeployment(db, run.id, 'failed', { error: 'E_DEPLOY_ATTESTATION_TIMEOUT' })
    return
  }
  if (att.status === 'error' || !att.envelope) return finishDeployment(db, run.id, 'failed', { error: `E_DEPLOY_ATTESTATION ${att.error ?? ''}`.trim() })
  // 3. Copie par empreinte, empreinte relue dans la destination, attestation jointe.
  const srcClient = await registryClient(db, src.host, run.credential_id)
  const dstClient = src.host === dst.host ? srcClient : await registryClient(db, dst.host, run.credential_id)
  const destTag = cfg.destination_tag ? fillTemplate(cfg.destination_tag, { tag: scan.tag, commit: scan.commit_sha }) : null
  await copyImage(srcClient, src.repo, dstClient, dst.repo, digest, destTag)
  const envelope = Buffer.from(JSON.stringify(att.envelope))
  try {
    const where = await pushAttestation(dstClient, dst.repo, digest, envelope, PREDICATE_TYPE)
    await db.query(`UPDATE attestations SET status = 'pushed', pushed_to = $2, error = NULL WHERE id = $1`, [att.id, where])
  }
  catch (err) {
    // Sans droit d'écriture sur l'étiquette .att : l'attestation reste
    // téléchargeable depuis la console, et c'est signalé.
    await db.query(`UPDATE attestations SET error = $2 WHERE id = $1`, [att.id, `push: ${errorCode(err)}`.slice(0, 1000)])
  }
  await finishDeployment(db, run.id, 'succeeded', { externalId: digest })
  await audit(db, 'deploy.registry.promote', run, scan, { source: cfg.source, destination: cfg.destination, digest })
}

// --- 4 : GitOps ----------------------------------------------------------------------------

async function advanceGitops(db: Queryable, run: Run, scan: ScanInfo, digests: Map<string, string>, allowAutoMerge: boolean): Promise<void> {
  const cfg = parseConfig('gitops-pr', run.config) as GitopsConfig | null
  if (!cfg) return finishDeployment(db, run.id, 'failed', { error: 'E_DEPLOY_CONFIG' })
  const missing = cfg.files.find(f => !digests.has(f.image))
  if (missing) return finishDeployment(db, run.id, 'failed', { error: 'E_DEPLOY_GITOPS_IMAGE' })
  const forge = await deployerFor(db, scan)
  // Chaque fichier est lu une seule fois ; plusieurs images peuvent viser le même fichier.
  const originals = new Map<string, { content: string, sha: string | null }>()
  const byPath = new Map<string, string>()
  for (const f of cfg.files) {
    if (!originals.has(f.path)) {
      const orig = await forge.readFile(cfg.repo, cfg.base, f.path, MAX_GITOPS_FILE_BYTES)
      if (!orig) return finishDeployment(db, run.id, 'failed', { error: 'E_DEPLOY_GITOPS_FILE' })
      originals.set(f.path, orig)
      byPath.set(f.path, orig.content)
    }
    byPath.set(f.path, replaceImageDigest(byPath.get(f.path)!, f.image, digests.get(f.image)!).content)
  }
  const changes = [...byPath].filter(([path, content]) => originals.get(path)!.content !== content)
    .map(([path, content]) => ({ path, content, sha: originals.get(path)!.sha }))
  if (!changes.length) return finishDeployment(db, run.id, 'succeeded', { error: 'already up to date' })
  if (!await claimDeployment(db, run.id)) return
  const branch = promotionBranch(run.environment, scan.id)
  const label = scan.tag ?? scan.commit_sha.slice(0, 12)
  await forge.commitFiles(cfg.repo, cfg.base, branch, `Promotion ${run.environment} : ${label} (Scanoria)`, changes)
  const url = await consoleUrl()
  const body = [
    `Promotion **${escapeInline(run.environment, 40)}** proposée par Scanoria après un verdict favorable.`,
    '',
    `- Commit analysé : \`${scan.commit_sha}\``,
    scan.tag ? `- Release : \`${escapeInline(scan.tag, 255)}\`` : null,
    ...cfg.files.map(f => `- \`${escapeInline(f.path, 200)}\` : \`${escapeInline(f.image, 200)}@${digests.get(f.image)}\``),
    url ? `- Rapport : ${url}/scans/${scan.id}` : null,
    '',
    'Retour arrière : revert de cette PR. Scanoria ne fusionne jamais une PR.',
  ].filter(x => x !== null).join('\n')
  const pr = await forge.openPullRequest(cfg.repo, { head: branch, base: cfg.base, title: `Promotion ${run.environment} : ${label}`, body })
  await setExternal(db, run.id, String(pr.number), pr.url)
  let autoMerge: string = 'off'
  if (run.auto_merge && allowAutoMerge) {
    // Fusion automatique NATIVE de la forge, autorisée par un administrateur pour cette cible.
    autoMerge = await forge.enableAutoMerge(cfg.repo, pr.number).catch(() => 'unsupported')
  }
  await finishDeployment(db, run.id, 'succeeded', { externalId: String(pr.number), externalUrl: pr.url })
  await audit(db, 'deploy.gitops.pr', run, scan, { repo: cfg.repo, number: pr.number, files: changes.map(c => c.path), auto_merge: autoMerge })
}

// --- 5 : CD existante ----------------------------------------------------------------------

function cdInputs(cfg: CdTriggerConfig, scan: ScanInfo, url: string | null, digests: Map<string, string>): Record<string, string> {
  const first = [...digests.entries()][0]
  const all: Record<string, string> = {
    scanoria_report: url ? `${url}/scans/${scan.id}` : '',
    scanoria_commit: scan.commit_sha,
    scanoria_tag: scan.tag ?? '',
    scanoria_image: first ? `${first[0]}@${first[1]}` : '',
  }
  return Object.fromEntries(cfg.inputs.map(k => [k, all[k]!]))
}

function jenkinsJobPath(job: string): string {
  return job.split('/').map(s => `job/${encodeURIComponent(s)}`).join('/')
}

async function jenkinsRequest(db: Queryable, credentialId: string | null): Promise<ForgeRequest> {
  if (!credentialId) throw new ForgeError('E_FORGE_AUTH')
  const s = await decryptSecret(db, credentialId)
  return { authScheme: 'Bearer', headers: { authorization: `Basic ${Buffer.from(`${s.username ?? ''}:${s.value}`).toString('base64')}` } }
}

async function advanceCd(db: Queryable, run: Run, scan: ScanInfo, digests: Map<string, string>): Promise<void> {
  const cfg = parseConfig('cd-trigger', run.config) as CdTriggerConfig | null
  if (!cfg) return finishDeployment(db, run.id, 'failed', { error: 'E_DEPLOY_CONFIG' })
  const url = await consoleUrl()
  const age = Date.now() - run.created_at.getTime()
  if (cfg.provider === 'jenkins') {
    const base = cfg.url.replace(/\/+$/, '')
    const req = await jenkinsRequest(db, run.credential_id)
    if (run.status === 'pending') {
      if (!await claimDeployment(db, run.id)) return
      const q = new URLSearchParams(Object.entries(cdInputs(cfg, scan, url, digests)).map(([k, v]) => [k.toUpperCase(), v]))
      const res = await forgeSend(`${base}/${jenkinsJobPath(cfg.job)}/buildWithParameters?${q}`, req, { method: 'POST' })
      const loc = res.headers.get('location')
      const queue = loc && new URL(loc, base).origin === new URL(base).origin ? new URL(loc, base).toString() : null
      const m = queue ? /\/queue\/item\/(\d{1,19})\/?$/.exec(new URL(queue).pathname) : null
      await setExternal(db, run.id, m ? `queue:${m[1]}` : null, null)
      await audit(db, 'deploy.cd.trigger', run, scan, { provider: 'jenkins', job: cfg.job })
      return
    }
    if (age > CD_TIMEOUT_MS) return finishDeployment(db, run.id, 'failed', { error: 'E_DEPLOY_TIMEOUT' })
    const ext = run.external_id ?? ''
    if (ext.startsWith('queue:')) {
      const res = await forgeGet(`${base}/queue/item/${ext.slice(6)}/api/json`, req)
      const item = JSON.parse(res.body.toString('utf8')) as { executable?: { number?: unknown }, cancelled?: unknown }
      if (item.cancelled === true) return finishDeployment(db, run.id, 'failed', { error: 'cancelled' })
      if (typeof item.executable?.number === 'number') await setExternal(db, run.id, `build:${item.executable.number}`, `${base}/${jenkinsJobPath(cfg.job)}/${item.executable.number}/`)
      return
    }
    if (ext.startsWith('build:')) {
      const n = ext.slice(6)
      if (!/^\d{1,19}$/.test(n)) return finishDeployment(db, run.id, 'failed', { error: 'E_DEPLOY_INTERNAL' })
      const res = await forgeGet(`${base}/${jenkinsJobPath(cfg.job)}/${n}/api/json`, req)
      const b = JSON.parse(res.body.toString('utf8')) as { building?: unknown, result?: unknown }
      if (b.building === true || b.result === null) return
      return finishDeployment(db, run.id, b.result === 'SUCCESS' ? 'succeeded' : 'failed', { error: b.result === 'SUCCESS' ? null : String(b.result).slice(0, 40) })
    }
    if (age > 10 * 60_000) return finishDeployment(db, run.id, 'succeeded', { error: 'E_DEPLOY_UNTRACKED' })
    return
  }
  const forge = await deployerFor(db, scan)
  const repo = cfg.repo ?? scan.repo_full_name
  if (!repo) return finishDeployment(db, run.id, 'failed', { error: 'E_DEPLOY_CONFIG' })
  if (run.status === 'pending') {
    // Réservée AVANT le déclenchement : une passe interrompue ne déclenche
    // jamais deux fois (au pire, l'exécution échoue par délai).
    if (!await claimDeployment(db, run.id)) return
    const triggerToken = forge.kind === 'gitlab' && run.credential_id ? (await decryptSecret(db, run.credential_id)).value : null
    const ref = cfg.ref ?? scan.tag ?? scan.ref.replace(/^refs\/(heads|tags)\//, '')
    const r = await forge.dispatchWorkflow(repo, cfg.workflow, ref, cdInputs(cfg, scan, url, digests), triggerToken)
    await setExternal(db, run.id, r.runId, r.url)
    await audit(db, 'deploy.cd.trigger', run, scan, { provider: forge.kind, repo, workflow: cfg.workflow, ref, run_id: r.runId })
    return
  }
  if (age > CD_TIMEOUT_MS) return finishDeployment(db, run.id, 'failed', { error: 'E_DEPLOY_TIMEOUT' })
  let runId = run.external_id
  if (!runId) {
    const found = await forge.findDispatchedRun(repo, cfg.workflow, run.created_at)
    if (found?.runId) {
      runId = found.runId
      await setExternal(db, run.id, found.runId, found.url)
    }
    else if (age > 10 * 60_000) return finishDeployment(db, run.id, 'succeeded', { error: 'E_DEPLOY_UNTRACKED' })
    else return
  }
  const st = await forge.runStatus(repo, runId)
  if (st.state === 'running') {
    if (st.url) await setExternal(db, run.id, null, st.url)
    return
  }
  await finishDeployment(db, run.id, st.state, { externalUrl: safeUrl(st.url), error: st.state === 'failed' ? 'E_DEPLOY_CD_FAILED' : null })
}

// --- Orchestration d'une analyse -----------------------------------------------------------

/**
 * Avance d'un pas les exécutions d'une analyse. Ne lève jamais : une erreur
 * fait échouer l'exécution concernée avec son code (jamais un texte libre de
 * la forge ou du registre).
 */
export async function advanceScan(db: Queryable, scanId: string): Promise<void> {
  const scan = await loadScan(db, scanId)
  if (!scan) return
  const runs = await loadRuns(db, scanId)
  if (!runs.some(r => !terminal(r.status))) return
  if (scan.verdict !== 'passed') {
    // Contrat 40 : jamais d'action sans verdict favorable (verdict changé depuis).
    for (const r of runs.filter(x => !terminal(x.status))) await finishDeployment(db, r.id, 'failed', { error: 'verdict-not-passed' })
    return
  }
  await collectSignatures(db)
  const url = await consoleUrl()
  for (const kind of ORDER) {
    const before = runs.filter(r => ORDER.indexOf(r.kind) < ORDER.indexOf(kind))
    const mine = runs.filter(r => r.kind === kind && !terminal(r.status))
    if (!mine.length) continue
    if (before.some(r => !terminal(r.status))) return
    if (before.some(r => r.status === 'failed')) {
      for (const r of mine) {
        await finishDeployment(db, r.id, 'failed', { error: 'E_DEPLOY_PREVIOUS' })
        r.status = 'failed'
      }
      continue
    }
    const digests = await promotedDigests(db, scanId)
    for (const run of mine) {
      try {
        if (kind === 'registry-promotion') await advancePromotion(db, run, scan, url)
        else if (kind === 'gitops-pr') await advanceGitops(db, run, scan, digests, true)
        else await advanceCd(db, run, scan, digests)
      }
      catch (err) {
        const code = errorCode(err)
        // Erreur passagère pendant un suivi : on réessaie à la passe suivante.
        if (run.status === 'running' && kind === 'cd-trigger' && /E_FORGE_(TIMEOUT|UNREACHABLE|RATE_LIMITED)/.test(code)) continue
        await finishDeployment(db, run.id, 'failed', { error: code })
        await audit(db, `deploy.${kind === 'registry-promotion' ? 'registry' : kind === 'gitops-pr' ? 'gitops' : 'cd'}.error`, run, scan, { error: code }, 'failure')
      }
    }
    const refreshed = await loadRuns(db, scanId)
    runs.splice(0, runs.length, ...refreshed)
    if (runs.some(r => r.kind === kind && !terminal(r.status))) return
  }
}

/** Images promues de l'analyse : dépôt (source et destination) → empreinte. */
export async function promotedDigests(db: Queryable, scanId: string): Promise<Map<string, string>> {
  const out = new Map<string, string>()
  const r = await db.query<{ config: unknown, external_id: string | null }>(
    `SELECT t.config, d.external_id FROM deployments d JOIN deploy_targets t ON t.id = d.target_id
      WHERE d.scan_id = $1 AND t.kind = 'registry-promotion' AND d.status = 'succeeded'`, [scanId])
  for (const x of r.rows) {
    const cfg = parseConfig('registry-promotion', x.config) as RegistryConfig | null
    if (!cfg || !x.external_id || !/^sha256:[0-9a-f]{64}$/.test(x.external_id)) continue
    out.set(cfg.destination, x.external_id)
    out.set(cfg.source, x.external_id)
  }
  for (const a of await listAttestations(db, scanId)) if (!out.has(a.subject_name)) out.set(a.subject_name, a.subject_digest)
  return out
}
