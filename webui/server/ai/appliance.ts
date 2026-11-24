// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// I16 (0.6), côté console : assemble le contexte d'un diagnostic de
// l'appliance (voir server/ai/appliance-context.ts pour les sujets), puis
// dépose la tâche diagnose-appliance. Sources lues, toutes déjà sans secret :
// l'état publié par le service root, l'état des modules, les demandes au
// service root (paramètres expurgés à l'écriture) et l'historique des mises
// à jour. Rien n'est jamais lu d'un projet, ni des tables de secrets.

import type { Queryable } from '../utils/db'
import { getConfig } from '../utils/config'
import { readPublishedState } from '../utils/appliance'
import { readDnsStatus, readModulesState } from '../utils/catalog'
import { fqdnSchema } from '#shared/schemas'
import { APPLIANCE_SUBJECT_RE, boundApplianceContext, jsonLines, type ApplianceContext, type ApplianceNames } from './appliance-context'
import { AI_PRIORITY, enqueueAiTask } from './enqueue'
import { aiPaths, loadEndpoint } from './config'

export const DIAGNOSE_APPLIANCE = 'diagnose-appliance'
/** Disque « presque plein » : moins de 10 % libres (même seuil que le tableau de bord). */
export const DISK_ALERT_RATIO = 0.1
/** Certificat « proche de l'expiration » : moins de 14 jours. */
export const TLS_ALERT_DAYS = 14

type Obj = Record<string, unknown>
const isObj = (v: unknown): v is Obj => !!v && typeof v === 'object' && !Array.isArray(v)
const str = (v: unknown, max = 300): string | null => (typeof v === 'string' && v ? v.slice(0, max) : null)
const code = (v: unknown): string | null => (typeof v === 'string' && /^(?:OK|E_[A-Z0-9_]{1,60})$/.test(v) ? v : null)
const iso = (v: unknown): string | null => (v instanceof Date ? v.toISOString() : str(v, 40))

export interface ApplianceSources {
  state: Obj | null
  modules: { modules: Obj[], operations: Obj[] }
}

async function loadSources(): Promise<ApplianceSources> {
  const cfg = getConfig()
  const [published, modules] = await Promise.all([readPublishedState(cfg.stateFile), readModulesState(cfg.modulesStateFile)])
  return {
    state: published.state,
    modules: { modules: modules.modules as unknown as Obj[], operations: modules.operations as unknown as Obj[] },
  }
}

/** Noms à neutraliser : celui de l'appliance, ceux de son certificat et du serveur Ollama. */
export async function applianceNames(state: Obj | null): Promise<ApplianceNames> {
  const appliance = isObj(state?.appliance) ? state.appliance : {}
  const tls = isObj(state?.tls) ? state.tls : {}
  const sans = Array.isArray(tls.subject_alt_names) ? tls.subject_alt_names.filter((s): s is string => typeof s === 'string') : []
  let aiHost: string | null
  try {
    const ep = await loadEndpoint(aiPaths().endpointFile)
    aiHost = ep.enabled ? ep.host : null
  }
  catch {
    aiHost = null
  }
  // Nom de l'appliance : état publié, sinon dernier contrôle DNS ; inconnu, tout nom est neutralisé.
  let fqdn = str(appliance.fqdn, 253)
  if (!fqdn) {
    const dns = await readDnsStatus(getConfig().dnsStatusFile).catch(() => null)
    fqdn = fqdnSchema.safeParse(dns?.fqdn).success ? dns!.fqdn as string : null
  }
  return { fqdn, extra: [...sans.slice(0, 20), aiHost], strict: !fqdn }
}

interface RequestRow { id: string, type: string, status: string, code: string | null, message: string | null, output: unknown, params: unknown, created_at: Date, finished_at: Date | null }

function requestLog(r: RequestRow | undefined): string {
  if (!r) return ''
  return [
    `request ${r.type} ${r.status}${r.code ? ` ${r.code}` : ''} at ${iso(r.finished_at ?? r.created_at)}`,
    ...(r.message ? [`message: ${r.message.slice(0, 2000)}`] : []),
    ...jsonLines(r.output, 'output'),
  ].join('\n')
}

function alertContext(key: string, state: Obj | null, last?: RequestRow): ApplianceContext | null {
  if (!state) return null
  const appliance = isObj(state.appliance) ? state.appliance : {}
  const base = { version: str(appliance.version, 40), previous_version: str(appliance.previous_version, 40) }
  if (key === 'update-rollback') {
    const update = isObj(state.update) ? state.update : {}
    const a = isObj(update.alert) ? update.alert : null
    if (!a) return null
    return {
      subject: 'alert', title: 'Rollback of an appliance update failed', status: 'alert', code: code(a.code), module: null,
      facts: { ...base, channel: str(update.channel, 20), target_version: str(a.version, 40), at: str(a.at, 40) },
      log: [`alert: ${str(a.message, 2000) ?? ''}`, requestLog(last)].filter(Boolean).join('\n'),
    }
  }
  if (key === 'tls-expiry') {
    const tls = isObj(state.tls) ? state.tls : {}
    const notAfter = str(tls.not_after, 40)
    const days = notAfter ? Math.floor((Date.parse(notAfter) - Date.now()) / 86_400_000) : null
    if (days === null || Number.isNaN(days) || days > TLS_ALERT_DAYS) return null
    return {
      subject: 'alert', title: 'Appliance certificate close to expiry', status: days < 0 ? 'expired' : 'expiring', code: null, module: null,
      facts: { ...base, mode: str(tls.mode, 20), not_after: notAfter, days_left: days, ca_not_after: str(tls.ca_not_after, 40) },
      log: '',
    }
  }
  if (key.startsWith('service:')) {
    const name = key.slice('service:'.length)
    const services = isObj(state.services) ? state.services : {}
    const status = str(services[name], 40)
    if (!status || ['active', 'running', 'ok'].includes(status)) return null
    return {
      subject: 'alert', title: `Appliance service ${name} is not running`, status, code: null, module: null,
      facts: { ...base, service: name, ...Object.fromEntries(Object.entries(services).slice(0, 15).map(([k, v]) => [`services.${k.replace(/[^a-z0-9_.-]/gi, '-').toLowerCase().slice(0, 30)}`, str(v, 40)])) },
      log: '',
    }
  }
  if (key.startsWith('disk:')) {
    const slug = key.slice('disk:'.length)
    const disks = Array.isArray(state.disks) ? state.disks.filter(isObj) : []
    const d = disks.find(x => diskKey(String(x.mount)) === slug)
    if (!d || typeof d.size_mb !== 'number' || typeof d.avail_mb !== 'number' || d.size_mb <= 0 || d.avail_mb / d.size_mb >= DISK_ALERT_RATIO) return null
    return {
      subject: 'alert', title: `Disk ${String(d.mount)} almost full`, status: 'low-space', code: null, module: null,
      facts: { ...base, mount: str(d.mount, 100), size_mb: d.size_mb, avail_mb: d.avail_mb, free_percent: Math.round((d.avail_mb / d.size_mb) * 1000) / 10 },
      log: disks.slice(0, 10).map(x => `disk ${String(x.mount)}: ${String(x.avail_mb)} MB free of ${String(x.size_mb)} MB`).join('\n'),
    }
  }
  return null
}

/** Clé d'un point de montage dans un sujet (« / » → root, « /var/lib » → var-lib). */
export function diskKey(mount: string): string {
  const k = mount.replace(/^\/+|\/+$/g, '').replace(/[^a-z0-9._-]+/gi, '-').toLowerCase()
  return (k || 'root').slice(0, 80)
}

/** Alertes de l'état publié qu'un administrateur peut faire diagnostiquer (clés des sujets alert:…). */
export function stateAlertKeys(state: Obj | null): string[] {
  if (!state) return []
  return ['update-rollback', 'tls-expiry',
    ...Object.keys(isObj(state.services) ? state.services : {}).map(n => `service:${n}`),
    ...(Array.isArray(state.disks) ? state.disks.filter(isObj).map(d => `disk:${diskKey(String(d.mount))}`) : []),
  ].filter(k => APPLIANCE_SUBJECT_RE.test(`alert:${k}`) && alertContext(k, state) !== null)
}

const MODULE_REQUEST_TYPES = ['install-modules', 'update-module', 'uninstall-module', 'set-module-state', 'backup-module', 'restore-module']

/** Contexte brut d'un sujet (avant masquage et neutralisation), ou null s'il n'y a rien à diagnostiquer. */
export async function applianceContext(db: Queryable, subjectId: string, sources?: ApplianceSources): Promise<ApplianceContext | null> {
  if (!APPLIANCE_SUBJECT_RE.test(subjectId)) return null
  const [kind, ...rest] = subjectId.split(':')
  const key = rest.join(':')
  const src = sources ?? await loadSources()
  if (kind === 'alert') {
    const last = key === 'update-rollback'
      ? (await db.query<RequestRow>(
          `SELECT id, type, status, code, message, output, params, created_at, finished_at FROM helper_requests
            WHERE type IN ('apply-update', 'rollback-update') ORDER BY created_at DESC LIMIT 1`)).rows[0]
      : undefined
    return alertContext(key, src.state, last)
  }
  if (kind === 'selftest') {
    const r = (await db.query<RequestRow>(
      `SELECT id, type, status, code, message, output, params, created_at, finished_at FROM helper_requests
        WHERE type = 'run-selftest' AND status IN ('ok', 'error', 'rejected', 'lost') ORDER BY created_at DESC LIMIT 1`)).rows[0]
    if (!r) return null
    const report = isObj(r.output) ? r.output : {}
    const checks = Array.isArray(report.checks) ? report.checks.filter(isObj) : []
    const failing = checks.filter(c => c.status === 'fail' || c.status === 'warn')
    const status = str(report.status, 10) ?? r.status
    if (status === 'pass' && r.status === 'ok') return null
    return {
      subject: 'selftest', title: 'Appliance self-test', status, code: code(r.code), module: null,
      facts: {
        appliance_version: str(report.appliance_version, 40), finished_at: str(report.finished_at, 40),
        checks: checks.length, failing: failing.length, quick: isObj(r.params) && r.params.quick === true,
      },
      // Contrôles en échec d'abord, puis le reste : la fin du journal est gardée en cas de dépassement.
      log: [...checks.filter(c => !failing.includes(c)), ...failing]
        .map(c => [`check ${String(c.id)} ${String(c.status)}: ${str(c.message, 500) ?? ''}`, ...jsonLines(c.details, `  ${String(c.id)}`)].join('\n'))
        .concat(r.status !== 'ok' ? [requestLog(r)] : [])
        .join('\n'),
    }
  }
  if (kind === 'update') {
    const h = (await db.query<{ action: string, from_version: string, to_version: string, channel: string | null, source: string | null, status: string, code: string | null, details: unknown, started_at: Date, finished_at: Date | null, request_id: string | null }>(
      `SELECT action, from_version, to_version, channel, source, status, code, details, started_at, finished_at, request_id
         FROM update_history WHERE id = $1`, [key])).rows[0]
    if (!h || h.status === 'success') return null
    const r = h.request_id
      ? (await db.query<RequestRow>('SELECT id, type, status, code, message, output, params, created_at, finished_at FROM helper_requests WHERE id = $1', [h.request_id])).rows[0]
      : undefined
    return {
      subject: 'update', title: `Appliance ${h.action} ${h.from_version} → ${h.to_version}`, status: h.status, code: code(h.code), module: null,
      facts: { action: h.action, from_version: h.from_version, to_version: h.to_version, channel: h.channel, source: h.source, started_at: iso(h.started_at), finished_at: iso(h.finished_at) },
      log: [...jsonLines(h.details, 'details'), requestLog(r)].filter(Boolean).join('\n'),
    }
  }
  // install:<module>
  const installed = src.modules.modules.find(m => m.id === key)
  const r = (await db.query<RequestRow>(
    `SELECT id, type, status, code, message, output, params, created_at, finished_at FROM helper_requests
      WHERE type = ANY($2::text[]) AND (params->>'id' = $1 OR params->'modules' @> jsonb_build_array(jsonb_build_object('id', $1::text)))
      ORDER BY created_at DESC LIMIT 1`, [key, MODULE_REQUEST_TYPES])).rows[0]
  const requestFailed = !!r && ['error', 'rejected', 'lost'].includes(r.status)
  const moduleFailed = !!installed && (installed.status === 'failed' || !!installed.last_error || (isObj(installed.testbed) && installed.testbed.passed === false))
  if (!requestFailed && !moduleFailed) return null
  const lastError = installed?.last_error
  const ops = src.modules.operations.filter(o => o.module === key).slice(-5)
  return {
    subject: 'install', title: `Module ${key}${r ? `: ${r.type}` : ''}`, status: requestFailed ? r!.status : String(installed?.status ?? 'failed').slice(0, 40),
    code: code(r?.code) ?? (isObj(lastError) ? code(lastError.code) : null), module: key,
    facts: {
      installed: !!installed, version: str(installed?.version, 64), type: str(installed?.type, 20), enabled: installed ? installed.enabled === true : null,
      testbed_passed: isObj(installed?.testbed) && typeof installed.testbed.passed === 'boolean' ? installed.testbed.passed : null,
    },
    log: [
      ...(lastError ? [`last_error: ${typeof lastError === 'string' ? lastError : JSON.stringify(lastError)}`] : []),
      ...(isObj(installed?.testbed) ? jsonLines(installed.testbed.details, 'testbed') : []),
      ...ops.map(o => `operation ${String(o.kind)} ${String(o.step ?? '')} ${str(o.message, 500) ?? ''}`.trim()),
      requestLog(r),
    ].filter(Boolean).join('\n'),
  }
}

/** Demande interactive : contexte assemblé, masqué, neutralisé, puis tâche déposée (null sans connecteur). */
export async function requestApplianceDiagnosis(db: Queryable, subjectId: string, userId: number, locale: 'fr' | 'en', sources?: ApplianceSources) {
  const src = sources ?? await loadSources()
  const raw = await applianceContext(db, subjectId, src)
  if (!raw) return { found: false as const }
  const context = boundApplianceContext(raw, await applianceNames(src.state))
  if (!context) return { found: false as const }
  const taskId = await enqueueAiTask(db, {
    kind: DIAGNOSE_APPLIANCE, subjectType: 'appliance', subjectId, projectId: null, locale, priority: AI_PRIORITY.interactive, requestedBy: userId, context,
  })
  return { found: true as const, task_id: taskId }
}

/**
 * Sujets qu'un diagnostic peut expliquer maintenant : alertes de l'état
 * publié, dernier selftest en échec, mises à jour en échec récentes, modules
 * dont la dernière opération a échoué. La console n'affiche le diagnostic que
 * pour ceux-là.
 */
export async function diagnosableSubjects(db: Queryable, sources?: ApplianceSources): Promise<string[]> {
  const src = sources ?? await loadSources()
  const out = stateAlertKeys(src.state).map(k => `alert:${k}`)
  if (await applianceContext(db, 'selftest:last', src)) out.push('selftest:last')
  const updates = await db.query<{ id: string }>(
    `SELECT id::text AS id FROM update_history WHERE status <> 'success' ORDER BY started_at DESC LIMIT 10`)
  out.push(...updates.rows.map(r => `update:${r.id}`))
  // Dernière demande de chaque module, en échec ; modules installés en échec.
  const reqs = await db.query<{ module: string, status: string }>(
    `SELECT DISTINCT ON (m.module) m.module, r.status FROM helper_requests r
       CROSS JOIN LATERAL (
         SELECT r.params->>'id' AS module WHERE r.params ? 'id'
         UNION ALL SELECT e->>'id' FROM jsonb_array_elements(CASE WHEN jsonb_typeof(r.params->'modules') = 'array' THEN r.params->'modules' ELSE '[]'::jsonb END) e
       ) m
      WHERE r.type = ANY($1::text[]) AND m.module IS NOT NULL AND r.created_at > now() - interval '30 days'
      ORDER BY m.module, r.created_at DESC`, [MODULE_REQUEST_TYPES])
  const failedModules = new Set(reqs.rows.filter(r => ['error', 'rejected', 'lost'].includes(r.status)).map(r => r.module))
  for (const m of src.modules.modules) {
    if (m.status === 'failed' || m.last_error || (isObj(m.testbed) && m.testbed.passed === false)) failedModules.add(String(m.id))
  }
  out.push(...[...failedModules].sort().map(m => `install:${m}`))
  return out.filter(s => APPLIANCE_SUBJECT_RE.test(s)).slice(0, 100)
}
