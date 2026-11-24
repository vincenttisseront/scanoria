// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Quality gate (ARCHITECTURE § 12.7, contrat 6) : evaluateGate(db, scanId) lit
// l'analyse, son plan, ses résultats et les exceptions actives, puis délègue à
// computeVerdict, fonction pure qui rend VerdictDetails :
// - H4 : un résultat malveillant bloque toujours, aucune exception possible ;
// - G13 : un module du plan absent, en erreur, en délai dépassé, à court de
//   mémoire, à sortie invalide ou inachevé rend le verdict non concluant, donc
//   bloquant, sauf exception datée de type « module » ;
// - secrets au-delà de max_secrets, vulnérabilités, SAST et IaC à partir des
//   seuils *_block_from ; nouveau code seulement si new_code_only ;
// - trou de couverture signalé, sans bloquer (0.3).
// Les raisons sont ordonnées : malveillant, secrets, résultats bloquants du plus
// grave au moins grave, modules en échec, puis informations non bloquantes.
// L'IA (I9) ne fait que rédiger à partir de cette sortie : elle n'y entre jamais.

import type { z } from 'zod'
import type { Queryable } from '../utils/db'
import {
  ExceptionTargets, GateRules, SEVERITIES, SEVERITY_RANK, VerdictDetails,
  type ExceptionKind, type ScanModuleStatus, type Severity,
} from '#shared/analysis'

type Reason = z.infer<typeof VerdictDetails>['reasons'][number]
type Action = Reason['actions'][number]

/** Famille d'un résultat pour le gate. */
export type GateFamily = 'malicious' | 'secret' | 'vuln' | 'sast' | 'iac' | 'other'

export interface GateFinding {
  id: string
  tool: string
  rule_id: string
  category: string
  severity: Severity
  path: string | null
  vuln_ids: string[]
  package_name: string | null
  malicious: boolean
  secret_type: string | null
  /** Suivi F7 : un secret classé faux positif n'est plus compté. */
  secret_state?: string | null
  status: string
  status_until: string | null
  is_new: boolean
}

export interface GateModule {
  module_id: string
  status: ScanModuleStatus | string
}

export interface GateException {
  id: string
  kind: ExceptionKind | string
  target: unknown
  reason: string
  expires_on: string
}

export interface GateInput {
  gateId: string
  rules: GateRules
  modules: GateModule[]
  /** Modules figés dans le plan (G11) : un module du plan sans ligne scan_modules est absent. */
  planModules?: string[]
  findings: GateFinding[]
  exceptions: GateException[]
  coverage?: unknown
  /** Date du jour (AAAA-MM-JJ), pour les exceptions et les acceptations datées. */
  today: string
  evaluatedAt: string
}

const MAX_IDS = 50

const FAMILY_OF_CATEGORY: Record<string, GateFamily> = {
  secrets: 'secret',
  sca: 'vuln', container: 'vuln', sbom: 'vuln', dast: 'vuln',
  sast: 'sast', ci: 'sast',
  iac: 'iac',
}

export function familyOf(f: Pick<GateFinding, 'category' | 'malicious' | 'secret_type'>): GateFamily {
  if (f.malicious) return 'malicious'
  if (f.secret_type) return 'secret'
  return FAMILY_OF_CATEGORY[f.category] ?? 'other'
}

/** Glob simple : « ** » (avec ou sans « / » final) traverse les dossiers, « * » et « ? » restent dans un segment. */
export function globToRegExp(glob: string): RegExp {
  let re = ''
  for (let i = 0; i < glob.length; i++) {
    const c = glob[i]!
    if (c === '*' && glob[i + 1] === '*') {
      i++
      if (glob[i + 1] === '/') {
        i++
        re += '(?:.*/)?'
      }
      else {
        re += '.*'
      }
    }
    else if (c === '*') {
      re += '[^/]*'
    }
    else if (c === '?') {
      re += '[^/]'
    }
    else {
      re += c.replace(/[.+^${}()|[\]\\]/g, '\\$&')
    }
  }
  return new RegExp(`^${re}$`)
}

function normalizePath(p: string): string {
  return p.replace(/\\/g, '/').replace(/^\.\//, '').replace(/^\/+/, '')
}

interface CompiledException {
  source: GateException
  kind: ExceptionKind
  matchFinding: (f: GateFinding) => boolean
  module: string | null
}

function compileException(e: GateException, today: string): CompiledException | null {
  if (e.expires_on < today) return null
  const kind = e.kind as ExceptionKind
  const schema = (ExceptionTargets as Record<string, z.ZodType>)[kind]
  if (!schema) return null
  const parsed = schema.safeParse(e.target)
  if (!parsed.success) return null
  const t = parsed.data as Record<string, string | undefined>
  const toolOk = (f: GateFinding) => !t.tool || t.tool === f.tool
  const base = { source: e, kind, module: null }
  switch (kind) {
    case 'path': {
      // Au plus 8 jokers : borne le retour arrière de l'expression (chemins ≤ 1024).
      if ((t.glob!.match(/[*?]/g) ?? []).length > 8) return null
      const re = globToRegExp(normalizePath(t.glob!))
      return { ...base, matchFinding: f => !!f.path && toolOk(f) && re.test(normalizePath(f.path)) }
    }
    case 'rule':
      return { ...base, matchFinding: f => f.rule_id === t.rule_id && toolOk(f) }
    case 'vuln': {
      const id = t.vuln_id!.toUpperCase()
      return {
        ...base,
        matchFinding: f => f.vuln_ids.some(v => v.toUpperCase() === id) && (!t.package || t.package === f.package_name),
      }
    }
    case 'finding':
      return { ...base, matchFinding: f => f.id === t.finding_id }
    case 'module':
      return { ...base, module: t.module_id!, matchFinding: () => false }
    default:
      return null
  }
}

/** Triés : un tri humain qui écarte le résultat (faux positif, accepté encore valide, corrigé). */
function triagedOut(f: GateFinding, today: string): boolean {
  if (f.status === 'false-positive' || f.status === 'fixed') return true
  if (f.secret_state === 'false-positive') return true
  return f.status === 'accepted' && !!f.status_until && f.status_until >= today
}

const MODULE_REASON: Record<string, { code: Reason['code'], actions: Action[] }> = {
  'missing': { code: 'module-missing', actions: ['install-module', 'request-exception'] },
  'invalid-output': { code: 'output-invalid', actions: ['rerun', 'request-exception'] },
  'error': { code: 'module-error', actions: ['rerun', 'request-exception'] },
  'timeout': { code: 'module-error', actions: ['rerun', 'request-exception'] },
  'oom': { code: 'module-error', actions: ['rerun', 'request-exception'] },
  'pending': { code: 'module-error', actions: ['rerun', 'request-exception'] },
  'running': { code: 'module-error', actions: ['rerun', 'request-exception'] },
}

function blocks(threshold: Severity | null, s: Severity): boolean {
  return threshold !== null && SEVERITY_RANK[s] >= SEVERITY_RANK[threshold]
}

function coverageGaps(coverage: unknown): number {
  if (!coverage || typeof coverage !== 'object') return 0
  const gaps = (coverage as { gaps?: unknown }).gaps
  return Array.isArray(gaps) ? gaps.length : 0
}

function reason(code: Reason['code'], blocking: boolean, items: GateFinding[], severity: Severity | null, actions: Action[]): Reason {
  return { code, blocking, count: items.length, severity, module: null, finding_ids: items.slice(0, MAX_IDS).map(f => f.id), actions }
}

/** Calcul du verdict, sans effet de bord ni accès à la base. */
export function computeVerdict(input: GateInput): VerdictDetails {
  const rules = GateRules.parse(input.rules)
  const exceptions = input.exceptions.map(e => compileException(e, input.today)).filter((e): e is CompiledException => !!e)
  const applied = new Map<string, GateException>()

  // 1. Résultats retenus : présents dans l'analyse, non écartés par un tri humain,
  //    nouveaux si new_code_only (sauf malveillants, toujours retenus : H4).
  const counted: GateFinding[] = []
  for (const f of input.findings) {
    if (f.malicious) {
      counted.push(f)
      continue
    }
    if (triagedOut(f, input.today)) continue
    if (rules.new_code_only && !f.is_new) continue
    const ex = exceptions.find(e => e.matchFinding(f))
    if (ex) {
      applied.set(ex.source.id, ex.source)
      continue
    }
    counted.push(f)
  }

  const counts = Object.fromEntries(SEVERITIES.map(s => [s, 0])) as Record<Severity, number>
  for (const f of counted) counts[f.severity]++

  const byFamily = new Map<GateFamily, GateFinding[]>()
  for (const f of counted) {
    const fam = familyOf(f)
    byFamily.set(fam, [...(byFamily.get(fam) ?? []), f])
  }
  const sortBySeverity = (list: GateFinding[]) => [...list].sort((a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity])

  const blockingReasons: Reason[] = []
  const infoReasons: Reason[] = []

  // 2. H4 : paquets malveillants, jamais exceptables.
  const malicious = byFamily.get('malicious') ?? []
  if (malicious.length) {
    blockingReasons.push(reason('malicious-package', true, sortBySeverity(malicious), maxSeverity(malicious), ['fix']))
  }

  // 3. Secrets : au-delà de max_secrets.
  const secrets = byFamily.get('secret') ?? []
  if (secrets.length) {
    const blocking = secrets.length > rules.max_secrets
    ;(blocking ? blockingReasons : infoReasons).push(
      reason('secret', blocking, sortBySeverity(secrets), maxSeverity(secrets), blocking ? ['fix', 'request-exception'] : []),
    )
  }

  // 4. Vulnérabilités, SAST, IaC : une raison par famille et par gravité.
  const thresholds: [GateFamily, Reason['code'], Severity | null][] = [
    ['vuln', 'vuln', rules.vuln_block_from],
    ['sast', 'sast', rules.sast_block_from],
    ['iac', 'iac', rules.iac_block_from],
    ['other', 'other', null],
  ]
  const severityReasons: Reason[] = []
  for (const [family, code, threshold] of thresholds) {
    const list = byFamily.get(family) ?? []
    for (const s of SEVERITIES) {
      const items = list.filter(f => f.severity === s)
      if (!items.length) continue
      const blocking = blocks(threshold, s)
      severityReasons.push(reason(code, blocking, items, s, blocking ? ['fix', 'request-exception'] : []))
    }
  }
  const bySeverityDesc = (a: Reason, b: Reason) => SEVERITY_RANK[b.severity!] - SEVERITY_RANK[a.severity!]
  blockingReasons.push(...severityReasons.filter(r => r.blocking).sort(bySeverityDesc))
  infoReasons.push(...severityReasons.filter(r => !r.blocking).sort(bySeverityDesc))

  // 5. G13 : modules du plan en échec ou absents.
  const moduleReasons: Reason[] = []
  if (input.modules.length === 0) {
    moduleReasons.push({ code: 'module-missing', blocking: true, count: 0, severity: null, module: null, finding_ids: [], actions: ['install-module'] })
  }
  const seen = new Set(input.modules.map(m => m.module_id))
  const absent = (input.planModules ?? []).filter(id => !seen.has(id)).map(id => ({ module_id: id, status: 'missing' }))
  for (const m of [...input.modules, ...absent].sort((a, b) => a.module_id.localeCompare(b.module_id))) {
    const r = MODULE_REASON[m.status]
    if (!r) continue
    const ex = exceptions.find(e => e.module === m.module_id)
    if (ex) applied.set(ex.source.id, ex.source)
    moduleReasons.push({ code: r.code, blocking: !ex, count: 1, severity: null, module: m.module_id, finding_ids: [], actions: ex ? [] : r.actions })
  }

  // 6. G15 : trous de couverture, signalés sans bloquer.
  const gaps = coverageGaps(input.coverage)
  if (gaps > 0) infoReasons.push({ code: 'coverage-gap', blocking: false, count: gaps, severity: null, module: null, finding_ids: [], actions: ['install-module'] })

  // Un résultat bloquant donne « failed » même si un module a échoué : le
  // blocage est déjà certain ; les modules en échec restent listés à la suite.
  const findingBlock = blockingReasons.length > 0
  const moduleBlock = moduleReasons.some(r => r.blocking)
  const verdict = findingBlock ? 'failed' : moduleBlock ? 'inconclusive' : 'passed'

  return VerdictDetails.parse({
    verdict,
    gate_id: input.gateId,
    rules,
    evaluated_at: input.evaluatedAt,
    new_code_only: rules.new_code_only,
    counts,
    reasons: [
      ...blockingReasons,
      ...moduleReasons.filter(r => r.blocking),
      ...moduleReasons.filter(r => !r.blocking),
      ...infoReasons,
    ],
    exceptions_applied: [...applied.values()]
      .sort((a, b) => a.expires_on.localeCompare(b.expires_on) || a.id.localeCompare(b.id))
      .map(e => ({ id: e.id, reason: e.reason, expires_on: e.expires_on })),
  })
}

function maxSeverity(list: GateFinding[]): Severity {
  return list.reduce<Severity>((m, f) => (SEVERITY_RANK[f.severity] > SEVERITY_RANK[m] ? f.severity : m), 'info')
}

export class ScanNotFoundError extends Error {
  constructor() {
    super('scan not found')
  }
}

/** Règles figées dans le plan (G11) si présentes et valides, sinon celles du gate. */
/**
 * G11 : un plan figé avant la 0.5 ne connaît pas les règles F8, H3 et H5.
 * Rejoué, il garde le verdict de l'époque : ces règles y sont désactivées
 * au lieu de prendre les défauts actuels.
 */
const PRE_05_RULES = { license_denied_blocks: false, kev_blocks: false, epss_block_from: null, quarantine_days: 0 } as const
function isPre05(rules: unknown): rules is Record<string, unknown> {
  return typeof rules === 'object' && rules !== null && !Array.isArray(rules)
    && !Object.keys(PRE_05_RULES).some(k => k in rules)
}

export function rulesFromPlan(plan: unknown): GateRules | null {
  const rules = (plan as { gate?: { rules?: unknown } } | null)?.gate?.rules
  if (rules === undefined) return null
  const parsed = GateRules.safeParse(isPre05(rules) ? { ...PRE_05_RULES, ...rules } : rules)
  return parsed.success ? parsed.data : null
}

/** Identifiants des modules figés dans le plan : plan.modules[].id ou .module_id. */
export function planModuleIds(plan: unknown): string[] {
  const list = (plan as { modules?: unknown } | null)?.modules
  if (!Array.isArray(list)) return []
  const ids = list.map((m) => {
    const o = m as { id?: unknown, module_id?: unknown } | null
    return typeof o?.id === 'string' ? o.id : typeof o?.module_id === 'string' ? o.module_id : null
  })
  return [...new Set(ids.filter((id): id is string => !!id && /^[a-z0-9][a-z0-9-]{1,40}$/.test(id)))]
}

/** Contrat 6 : évalue le quality gate d'une analyse (sans l'enregistrer : C le fait). */
export async function evaluateGate(db: Queryable, scanId: string, now = new Date()): Promise<VerdictDetails> {
  const scan = await db.query<{ project_id: string, gate_id: string, plan: unknown, coverage: unknown, gate_rules: unknown, today: string }>(
    `SELECT s.project_id, s.gate_id, s.plan, s.coverage, g.rules AS gate_rules,
            to_char(($2::timestamptz AT TIME ZONE current_setting('TimeZone'))::date, 'YYYY-MM-DD') AS today
       FROM scans s JOIN gates g ON g.id = s.gate_id
      WHERE s.id = $1`,
    [scanId, now.toISOString()],
  )
  const row = scan.rows[0]
  if (!row) throw new ScanNotFoundError()
  const rules = rulesFromPlan(row.plan) ?? GateRules.parse(row.gate_rules)

  const [modules, findings, exceptions] = await Promise.all([
    db.query<GateModule>('SELECT module_id, status FROM scan_modules WHERE scan_id = $1', [scanId]),
    db.query<GateFinding>(
      `SELECT f.id, f.tool, f.rule_id, f.category, f.severity, f.path, f.vuln_ids,
              f.package->>'name' AS package_name, f.malicious, f.secret_type, f.secret_state, f.status,
              to_char(f.status_until, 'YYYY-MM-DD') AS status_until, sf.is_new
         FROM scan_findings sf JOIN findings f ON f.id = sf.finding_id
        WHERE sf.scan_id = $1`,
      [scanId],
    ),
    db.query<GateException>(
      `SELECT id, kind, target, reason, to_char(expires_on, 'YYYY-MM-DD') AS expires_on
         FROM exceptions
        WHERE project_id = $1 AND revoked_at IS NULL AND expires_on >= $2::date`,
      [row.project_id, row.today],
    ),
  ])

  return computeVerdict({
    gateId: row.gate_id,
    rules,
    modules: modules.rows,
    planModules: planModuleIds(row.plan),
    findings: findings.rows,
    exceptions: exceptions.rows,
    coverage: row.coverage,
    today: row.today,
    evaluatedAt: now.toISOString().replace(/\.\d{3}Z$/, 'Z'),
  })
}
