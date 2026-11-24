// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// F19, alertes sur l'appliance elle-même. Le helper publie chaque jour les
// SARIF de Grype et d'OSV-Scanner sur le SBOM de la console et des images des
// modules installés (vigilance.py) ; la console les range dans self_vulns :
// apparition (first_seen), persistance (last_seen), résolution (resolved_at).
// Un sujet n'est résolu que si tous ses comparateurs ont réussi : un outil en
// échec ne fait jamais disparaître une vulnérabilité.
// Alerte « module X vulnérable, mise à jour disponible » quand le catalogue
// propose une version plus récente du module (ou la console une mise à jour) :
// bandeau du tableau de bord et de Mises à jour, événement d'audit.

import type { Queryable } from '../utils/db'
import { writeAudit } from '../utils/audit'
import { compareVersions, type CatalogIndex, type InstalledModule } from '../utils/catalog'
import { readOutput } from '../findings/ingest'
import { readModuleHints } from '../findings/manifest'
import { parseSarif } from '../findings/parse'
import { resolveSeverities } from '../findings/severity'
import { SEVERITY_RANK, type Severity } from '#shared/analysis'
import type { SelfStatus } from './state'

const SETTING_KEY = 'vigilance.self_sbom_at'
const VULN_ID_RE = /^[A-Za-z][A-Za-z0-9]*-[A-Za-z0-9._:-]{1,120}$/
const MAX_PER_SUBJECT = 5000

export interface SelfVulnRow {
  subject: string
  vuln_id: string
  purl: string
  severity: Severity
  fixed_version: string | null
}

/** purl d'un paquet trouvé ; l'écosystème sert de type (« generic » s'il manque). */
export function purlOf(pkg: { ecosystem: string | null, name: string, version: string | null }): string | null {
  const type = (pkg.ecosystem ?? 'generic').toLowerCase().replace(/[^a-z0-9.+-]/g, '') || 'generic'
  const name = pkg.name.replace(/[\s@?#]/g, '')
  if (!name) return null
  const purl = `pkg:${type}/${name}${pkg.version ? `@${pkg.version.replace(/\s/g, '')}` : ''}`
  return purl.length <= 1024 ? purl : null
}

/** Vulnérabilités d'une sortie SARIF d'un comparateur, gravités normalisées (G5). */
export async function readSelfSarif(db: Queryable, selfDir: string, toolId: string, rel: string, subject: string): Promise<SelfVulnRow[] | null> {
  const { doc, error } = await readOutput(selfDir, rel)
  if (error) return null
  const hints = await readModuleHints(toolId)
  const out = parseSarif(doc, { moduleId: toolId, moduleCategories: ['sca'] })
  if (out.issues.some(i => i.code === 'invalid-document')) return null
  const sev = await resolveSeverities(db, toolId, out.findings.map(f => f.nativeSeverity), hints.severityMap)
  const rows: SelfVulnRow[] = []
  for (const f of out.findings) {
    const vuln = f.vulnIds[0] ?? (VULN_ID_RE.test(f.ruleId) ? f.ruleId : null)
    const purl = f.package ? purlOf(f.package) : null
    if (!vuln || !VULN_ID_RE.test(vuln) || !purl) continue
    rows.push({ subject, vuln_id: vuln, purl, severity: sev.get(f.nativeSeverity) ?? 'medium', fixed_version: f.package?.fixed[0]?.slice(0, 256) ?? null })
  }
  return rows
}

/** Version plus récente disponible pour le sujet (module du catalogue, ou console). */
export function updateFor(subject: string, ctx: { installed: InstalledModule[], index: CatalogIndex | null, consoleUpdate: string | null }): string | null {
  if (subject === 'console') return ctx.consoleUpdate
  const id = subject.slice('module:'.length)
  const cur = ctx.installed.find(m => m.id === id)
  if (!cur) return null
  const newer = (ctx.index?.modules ?? []).filter(m => m.id === id && compareVersions(m.version, cur.version) > 0)
    .sort((a, b) => compareVersions(b.version, a.version))
  return newer[0]?.version ?? null
}

/** Range un relevé du helper dans self_vulns ; null si déjà rangé. */
export interface SelfIngestContext {
  selfDir: string
  installed: InstalledModule[]
  index: CatalogIndex | null
  consoleUpdate: string | null
}

export async function ingestSelfStatus(db: Queryable, status: SelfStatus | null, ctx: SelfIngestContext): Promise<{ subjects: number, new: number, resolved: number } | null> {
  if (!status) return null
  const last = await db.query<{ value: unknown }>('SELECT value FROM appliance_settings WHERE key = $1', [SETTING_KEY])
  if (last.rows[0]?.value === status.at) return null
  let created = 0
  let resolved = 0
  let subjects = 0
  for (const s of status.subjects) {
    if (s.error || !s.tools.length) continue
    const rows: SelfVulnRow[] = []
    let complete = true
    for (const t of s.tools) {
      const found = t.ok && t.output ? await readSelfSarif(db, ctx.selfDir, t.id, t.output, s.subject) : null
      if (found === null) complete = false
      else rows.push(...found)
    }
    const unique = [...new Map(rows.map(r => [`${r.vuln_id}|${r.purl}`, r])).values()].slice(0, MAX_PER_SUBJECT)
    const upd = updateFor(s.subject, ctx) !== null
    const prev = await db.query<{ vuln_id: string, purl: string }>(
      'SELECT vuln_id, purl FROM self_vulns WHERE subject = $1 AND resolved_at IS NULL', [s.subject])
    const open = new Set(prev.rows.map(r => `${r.vuln_id}|${r.purl}`))
    const fresh: SelfVulnRow[] = []
    for (const r of unique) {
      const ins = await db.query<{ inserted: boolean }>(
        `INSERT INTO self_vulns (subject, vuln_id, purl, severity, fixed_version, update_available)
         VALUES ($1, $2, $3, $4, $5, $6)
         ON CONFLICT (subject, vuln_id, purl) DO UPDATE
           SET severity = EXCLUDED.severity, fixed_version = EXCLUDED.fixed_version,
               update_available = EXCLUDED.update_available, last_seen = now(), resolved_at = NULL,
               first_seen = CASE WHEN self_vulns.resolved_at IS NULL THEN self_vulns.first_seen ELSE now() END
         RETURNING (xmax = 0) AS inserted`,
        [r.subject, r.vuln_id, r.purl, r.severity, r.fixed_version, upd])
      if (ins.rows[0]?.inserted || !open.has(`${r.vuln_id}|${r.purl}`)) fresh.push(r)
    }
    created += fresh.length
    if (complete) {
      const seen = unique.map(r => `${r.vuln_id}|${r.purl}`)
      const res = await db.query(
        `UPDATE self_vulns SET resolved_at = now()
          WHERE subject = $1 AND resolved_at IS NULL AND NOT ((vuln_id || '|' || purl) = ANY($2::text[]))`, [s.subject, seen])
      resolved += res.rowCount ?? 0
    }
    subjects++
    const serious = fresh.filter(r => SEVERITY_RANK[r.severity] >= SEVERITY_RANK.high)
    if (serious.length || (fresh.length && upd)) {
      await writeAudit(db, {
        actor: { type: 'system' }, action: 'appliance.self-vuln', outcome: 'success', targetType: 'appliance', targetId: s.subject,
        details: {
          subject: s.subject, new: fresh.length, critical: fresh.filter(r => r.severity === 'critical').length,
          high: fresh.filter(r => r.severity === 'high').length, update_available: updateFor(s.subject, ctx),
          vuln_ids: fresh.slice(0, 20).map(r => r.vuln_id),
        },
      })
    }
  }
  // Sujet disparu parce que le module est désinstallé : ses vulnérabilités sont
  // résolues. Un sujet absent du relevé pour une autre raison (Syft absent, délai
  // atteint) garde les siennes : un relevé manqué ne fait rien disparaître.
  const kept = ['console', ...ctx.installed.map(m => `module:${m.id}`)]
  const gone = await db.query(`UPDATE self_vulns SET resolved_at = now() WHERE resolved_at IS NULL AND NOT (subject = ANY($1::text[]))`, [kept])
  resolved += gone.rowCount ?? 0
  await db.query(
    `INSERT INTO appliance_settings (key, value, updated_at) VALUES ($1, $2, now())
     ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()`, [SETTING_KEY, JSON.stringify(status.at)])
  return { subjects, new: created, resolved }
}

export interface SelfVulnSummary {
  subject: string
  critical: number
  high: number
  medium: number
  low: number
  info: number
  update_available: string | null
  fixed: number
}

/** Vulnérabilités ouvertes par sujet, avec la version qui pourrait corriger. */
export async function selfVulnSummary(db: Queryable, ctx: { installed: InstalledModule[], index: CatalogIndex | null, consoleUpdate: string | null }): Promise<SelfVulnSummary[]> {
  const r = await db.query<{ subject: string, severity: Severity, n: number, fixed: number }>(
    `SELECT subject, severity, count(*)::int AS n, count(*) FILTER (WHERE fixed_version IS NOT NULL)::int AS fixed
       FROM self_vulns WHERE resolved_at IS NULL GROUP BY subject, severity ORDER BY subject`)
  const by = new Map<string, SelfVulnSummary>()
  for (const row of r.rows) {
    const s = by.get(row.subject) ?? { subject: row.subject, critical: 0, high: 0, medium: 0, low: 0, info: 0, update_available: updateFor(row.subject, ctx), fixed: 0 }
    s[row.severity] += row.n
    s.fixed += row.fixed
    by.set(row.subject, s)
  }
  return [...by.values()]
}

export async function listSelfVulns(db: Queryable, subject: string, limit = 200) {
  const r = await db.query<{ vuln_id: string, purl: string, severity: Severity, fixed_version: string | null, update_available: boolean, first_seen: Date, last_seen: Date }>(
    `SELECT vuln_id, purl, severity, fixed_version, update_available, first_seen, last_seen FROM self_vulns
      WHERE subject = $1 AND resolved_at IS NULL
      ORDER BY CASE severity WHEN 'critical' THEN 5 WHEN 'high' THEN 4 WHEN 'medium' THEN 3 WHEN 'low' THEN 2 ELSE 1 END DESC, vuln_id
      LIMIT $2`, [subject, limit])
  return r.rows.map(x => ({ ...x, first_seen: x.first_seen.toISOString(), last_seen: x.last_seen.toISOString() }))
}
