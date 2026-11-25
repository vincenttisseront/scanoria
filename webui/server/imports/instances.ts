// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Reprise des statuts de tri d'une instance existante (J5) : SonarQube,
// Dependency-Track ou DefectDojo, lus par leur API en HTTPS avec un jeton
// fourni par l'administrateur (chiffré, puis effacé après l'import). Une
// acceptation faite dans l'outil devient une DEMANDE d'exception, jamais une
// approbation (J15). Lecture bornée (pages, taille), même transport que les
// forges (HTTPS seul, aucune redirection vers un autre hôte, adresses de
// l'appliance refusées).

import { z } from 'zod'
import type { Queryable } from '../utils/db'
import { forgeGetJson, normalizeBaseUrl } from '../forges/http'
import type { ImportedRequest, ParsedImport } from './repo-files'

export const INSTANCE_KINDS = ['sonarqube', 'dependency-track', 'defectdojo'] as const
export type InstanceKind = (typeof INSTANCE_KINDS)[number]

export const instanceSchema = z.strictObject({
  kind: z.enum(INSTANCE_KINDS),
  base_url: z.string().url().max(512).refine(u => u.startsWith('https://'), { message: 'https only' }),
  /** Clé du projet SonarQube, UUID Dependency-Track, identifiant de produit DefectDojo. */
  project: z.string().min(1).max(255).regex(/^[A-Za-z0-9._:/@-]+$/),
})
export type InstanceRef = z.infer<typeof instanceSchema>

const PAGE = 500
const MAX_PAGES = 10
const MAX_BYTES = 16 * 1024 * 1024

interface FindingIndex { byRulePath: Map<string, string>, byVuln: Set<string> }

/** Résultats du projet (outil, règle, chemin) pour rattacher une acceptation à un résultat précis. */
async function findingIndex(db: Queryable, projectId: string, tool: string): Promise<FindingIndex> {
  const r = await db.query<{ id: string, rule_id: string, path: string | null }>(
    `SELECT id::text, rule_id, path FROM findings WHERE project_id = $1 AND tool = $2 AND NOT malicious LIMIT 50000`, [projectId, tool])
  return { byRulePath: new Map(r.rows.map(f => [`${f.rule_id}\u0000${f.path ?? ''}`, f.id])), byVuln: new Set() }
}

const reason = (kind: InstanceKind, what: string, extra?: string | null) =>
  `importé (${kind}) : ${what}${extra ? ` ; ${extra.replace(/\s+/g, ' ').slice(0, 300)}` : ''}`.slice(0, 2000)

async function sonarqube(ref: InstanceRef, token: string, db: Queryable, projectId: string, until: string): Promise<ParsedImport> {
  const base = normalizeBaseUrl(ref.base_url)
  const out: ParsedImport = { requests: [], unsupported: [] }
  const index = await findingIndex(db, projectId, 'sonar-scanner')
  for (let p = 1; p <= MAX_PAGES; p++) {
    const url = `${base}/api/issues/search?componentKeys=${encodeURIComponent(ref.project)}&resolved=true&resolutions=FALSE-POSITIVE,WONTFIX&ps=${PAGE}&p=${p}`
    const { data } = await forgeGetJson<{ issues?: unknown[], paging?: { total?: number } }>(url, { token, authScheme: 'Bearer', maxBytes: MAX_BYTES })
    const issues = Array.isArray(data.issues) ? data.issues : []
    for (const i of issues) {
      const o = (i && typeof i === 'object' ? i : {}) as Record<string, unknown>
      const rule = typeof o.rule === 'string' ? o.rule : null
      const component = typeof o.component === 'string' ? o.component : ''
      const path = component.includes(':') ? component.slice(component.indexOf(':') + 1) : null
      const res = typeof o.resolution === 'string' ? o.resolution : ''
      const id = rule ? index.byRulePath.get(`${rule}\u0000${path ?? ''}`) : undefined
      if (!id) {
        out.unsupported.push({ source: 'sonarqube', entry: `${rule ?? '?'} ${path ?? ''} (${res})`.slice(0, 160) })
        continue
      }
      out.requests.push({ kind: 'finding', target: { finding_id: id }, reason: reason('sonarqube', `${res} ${rule}`, typeof o.message === 'string' ? o.message : null), expires_on: until, source: `sonarqube:${path}` })
    }
    if (issues.length < PAGE || p * PAGE >= (data.paging?.total ?? 0)) break
  }
  return out
}

const VULN_RE = /^[A-Za-z][A-Za-z0-9]*-[A-Za-z0-9._:-]{1,120}$/

async function dependencyTrack(ref: InstanceRef, token: string, until: string): Promise<ParsedImport> {
  const base = normalizeBaseUrl(ref.base_url)
  const out: ParsedImport = { requests: [], unsupported: [] }
  if (!/^[0-9a-f-]{36}$/i.test(ref.project)) return { requests: [], unsupported: [{ source: 'dependency-track', entry: 'project must be a UUID' }] }
  const { data } = await forgeGetJson<unknown[]>(`${base}/api/v1/finding/project/${ref.project}?suppressed=true`, {
    token: null, authScheme: 'Bearer', headers: { 'x-api-key': token }, maxBytes: MAX_BYTES,
  })
  for (const f of (Array.isArray(data) ? data : []).slice(0, PAGE * MAX_PAGES)) {
    const o = (f && typeof f === 'object' ? f : {}) as Record<string, Record<string, unknown> | undefined>
    const state = typeof o.analysis?.state === 'string' ? o.analysis.state : null
    const suppressed = o.analysis?.isSuppressed === true
    if (!suppressed && state !== 'NOT_AFFECTED' && state !== 'FALSE_POSITIVE') continue
    const vuln = typeof o.vulnerability?.vulnId === 'string' ? o.vulnerability.vulnId : null
    const pkg = typeof o.component?.name === 'string' ? o.component.name.slice(0, 255) : undefined
    if (!vuln || !VULN_RE.test(vuln)) {
      out.unsupported.push({ source: 'dependency-track', entry: String(vuln ?? '?').slice(0, 120) })
      continue
    }
    const r: ImportedRequest = { kind: 'vuln', target: { vuln_id: vuln, ...(pkg ? { package: pkg } : {}) }, reason: reason('dependency-track', `${state ?? 'SUPPRESSED'} ${vuln}`), expires_on: until, source: `dependency-track:${pkg ?? ''}` }
    out.requests.push(r)
  }
  return out
}

async function defectDojo(ref: InstanceRef, token: string, db: Queryable, projectId: string, until: string): Promise<ParsedImport> {
  const base = normalizeBaseUrl(ref.base_url)
  const out: ParsedImport = { requests: [], unsupported: [] }
  if (!/^\d{1,12}$/.test(ref.project)) return { requests: [], unsupported: [{ source: 'defectdojo', entry: 'product must be a numeric id' }] }
  const seen = new Set<number>()
  for (const filter of ['false_p=true', 'risk_accepted=true']) {
    for (let p = 0; p < MAX_PAGES; p++) {
      const url = `${base}/api/v2/findings/?test__engagement__product=${ref.project}&${filter}&limit=${PAGE}&offset=${p * PAGE}`
      const { data } = await forgeGetJson<{ results?: unknown[], next?: unknown }>(url, { token, authScheme: 'token', maxBytes: MAX_BYTES })
      const results = Array.isArray(data.results) ? data.results : []
      for (const f of results) {
        const o = (f && typeof f === 'object' ? f : {}) as Record<string, unknown>
        if (typeof o.id === 'number') {
          if (seen.has(o.id)) continue
          seen.add(o.id)
        }
        const ids = Array.isArray(o.vulnerability_ids)
          ? (o.vulnerability_ids as { vulnerability_id?: unknown }[]).map(v => v?.vulnerability_id).filter((v): v is string => typeof v === 'string')
          : []
        if (typeof o.cve === 'string') ids.push(o.cve)
        const what = filter.startsWith('false') ? 'false positive' : 'risk accepted'
        const pkg = typeof o.component_name === 'string' && o.component_name ? o.component_name.slice(0, 255) : undefined
        const vuln = ids.find(v => VULN_RE.test(v))
        if (vuln) {
          out.requests.push({ kind: 'vuln', target: { vuln_id: vuln, ...(pkg ? { package: pkg } : {}) }, reason: reason('defectdojo', `${what} ${vuln}`, typeof o.title === 'string' ? o.title : null), expires_on: until, source: `defectdojo:${String(o.id ?? '')}` })
          continue
        }
        // Sans avis : rattaché à un résultat de même chemin et même titre de règle s'il existe.
        const path = typeof o.file_path === 'string' ? o.file_path : null
        const rule = typeof o.vuln_id_from_tool === 'string' ? o.vuln_id_from_tool : null
        const match = path && rule
          ? (await db.query<{ id: string }>('SELECT id::text FROM findings WHERE project_id = $1 AND rule_id = $2 AND path = $3 AND NOT malicious LIMIT 1', [projectId, rule, path])).rows[0]
          : undefined
        if (match) out.requests.push({ kind: 'finding', target: { finding_id: match.id }, reason: reason('defectdojo', `${what} ${rule}`), expires_on: until, source: `defectdojo:${path}` })
        else out.unsupported.push({ source: 'defectdojo', entry: `${String(o.title ?? o.id ?? '?')}`.slice(0, 120) })
      }
      if (!data.next || results.length < PAGE) break
    }
  }
  return out
}

export async function readInstance(ref: InstanceRef, token: string, db: Queryable, projectId: string, until: string): Promise<ParsedImport> {
  switch (ref.kind) {
    case 'sonarqube': return sonarqube(ref, token, db, projectId, until)
    case 'dependency-track': return dependencyTrack(ref, token, until)
    case 'defectdojo': return defectDojo(ref, token, db, projectId, until)
  }
}
