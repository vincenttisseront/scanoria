// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// H7 : formats VEX, sans base ni dépendance (lu aussi par tests/b38-vex.sh
// avec node --experimental-strip-types) :
// - rendu OpenVEX 0.2.0 et CycloneDX VEX 1.6 en forme canonique (clés triées,
//   JSON sans espaces) : le même jeu de déclarations donne toujours les mêmes
//   octets, ce qui permet au rapport de release (contrat 36) d'en citer
//   l'empreinte ;
// - lecture STRICTE d'un document importé, considéré comme hostile : taille,
//   profondeur, nombre de déclarations et de produits bornés, identifiants de
//   vulnérabilité et purl vérifiés, statuts et justifications inconnus
//   refusés, textes sans caractère de contrôle. Le moindre écart refuse tout
//   le document : rien n'est importé à moitié.

import { createHash } from 'node:crypto'

export const VEX_STATUSES = ['not_affected', 'affected', 'fixed', 'under_investigation'] as const
export type VexStatus = (typeof VEX_STATUSES)[number]
export const VEX_JUSTIFICATIONS = [
  'component_not_present', 'vulnerable_code_not_present', 'vulnerable_code_not_in_execute_path',
  'vulnerable_code_cannot_be_controlled_by_adversary', 'inline_mitigations_already_exist',
] as const
export type VexJustification = (typeof VEX_JUSTIFICATIONS)[number]

export const OPENVEX_CONTEXT = 'https://openvex.dev/ns/v0.2.0'
export const VEX_AUTHOR = 'Scanoria'

/** Bornes d'un document importé. */
export const VEX_LIMITS = {
  maxBytes: 1_048_576,
  maxDepth: 16,
  maxStatements: 1000,
  maxProducts: 50,
  maxText: 2000,
} as const

/** Même forme que vex_statements.vuln_id (018). */
/** Ordre des points de code (et non de la locale) : forme canonique identique partout. */
export const byCodepoint = (a: string, b: string): number => (a < b ? -1 : a > b ? 1 : 0)

export const VULN_ID_RE = /^[A-Za-z][A-Za-z0-9._:-]{2,100}$/
/** purl : type, espace de noms et nom, version et qualificatifs facultatifs ; aucun espace ni caractère de contrôle. */
export const PURL_RE = /^pkg:[a-z][a-z0-9.+-]{0,31}\/[^\s/?#@][^\s?#]{0,400}(?:\?[^\s#]{1,200})?(?:#[^\s]{1,100})?$/

/** Déclaration VEX normalisée (une vulnérabilité, un produit). */
export interface VexStatement {
  vuln_id: string
  product: string
  status: VexStatus
  justification: VexJustification | null
  impact_statement: string | null
  action_statement: string | null
  /** ISO 8601, à la seconde. */
  timestamp: string
}

export class VexFormatError extends Error {
  code: string
  detail: string | null
  constructor(code: string, detail: string | null = null) {
    super(code)
    this.code = code
    this.detail = detail
  }
}

/** JSON canonique : clés triées à tous les niveaux, aucun espace. */
export function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value)
  if (Array.isArray(value)) return `[${value.map(v => canonicalJson(v === undefined ? null : v)).join(',')}]`
  const obj = value as Record<string, unknown>
  const keys = Object.keys(obj).filter(k => obj[k] !== undefined).sort(byCodepoint)
  return `{${keys.map(k => `${JSON.stringify(k)}:${canonicalJson(obj[k])}`).join(',')}}`
}

export function validPurl(p: unknown): p is string {
  return typeof p === 'string' && p.length >= 6 && p.length <= 500 && PURL_RE.test(p) && !hasControl(p)
}

function hasControl(v: string): boolean {
  for (const ch of v) {
    const c = ch.codePointAt(0)!
    if ((c < 0x20 && c !== 0x0a && c !== 0x09) || c === 0x7f || (c >= 0x80 && c < 0xa0) || c === 0x2028 || c === 0x2029 || (c >= 0x202a && c <= 0x202e) || (c >= 0x2066 && c <= 0x2069)) return true
  }
  return false
}

function cleanText(v: unknown, field: string): string | null {
  if (v === undefined || v === null) return null
  if (typeof v !== 'string') throw new VexFormatError('E_VEX_FIELD', field)
  if (v.length > VEX_LIMITS.maxText || hasControl(v)) throw new VexFormatError('E_VEX_FIELD', field)
  const t = v.trim()
  return t ? t : null
}

function isoSecond(v: unknown, fallback: string): string {
  if (typeof v !== 'string' || v.length > 40) return fallback
  const t = Date.parse(v)
  if (!Number.isFinite(t)) return fallback
  return new Date(t).toISOString().replace(/\.\d{3}Z$/, 'Z')
}

/** Ordre stable des déclarations : vulnérabilité, produit, statut. */
export function sortStatements(list: VexStatement[]): VexStatement[] {
  const key = (s: VexStatement) => `${s.vuln_id}\u0000${s.product}\u0000${s.status}`
  return [...list].sort((a, b) => (key(a) < key(b) ? -1 : key(a) > key(b) ? 1 : 0))
}

/** Une seule déclaration par couple (vulnérabilité, produit) : la plus récente l'emporte. */
export function dedupeStatements(list: VexStatement[]): VexStatement[] {
  const best = new Map<string, VexStatement>()
  for (const s of list) {
    const k = `${s.vuln_id.toUpperCase()}\u0000${s.product}`
    const cur = best.get(k)
    if (!cur || s.timestamp > cur.timestamp || (s.timestamp === cur.timestamp && canonicalJson(s) > canonicalJson(cur))) best.set(k, s)
  }
  return sortStatements([...best.values()])
}

export function sha256Hex(text: string): string {
  return createHash('sha256').update(text, 'utf8').digest('hex')
}

/** Identifiant stable d'un document : empreinte de ses déclarations. */
export function documentId(statements: VexStatement[]): string {
  return `urn:scanoria:vex:${sha256Hex(canonicalJson(sortStatements(statements)))}`
}

export interface RenderInput {
  statements: VexStatement[]
  /** Horodatage du document (fin de l'analyse, ou déclaration la plus récente). */
  timestamp: string
  /** Version de l'appliance, pour « tooling ». */
  tooling?: string
}

/**
 * OpenVEX 0.2.0 : une déclaration par vulnérabilité et par texte identique,
 * avec la liste de ses produits (purl). Rendu canonique.
 */
export function renderOpenVex(input: RenderInput): { document: Record<string, unknown>, canonical: string } {
  const list = sortStatements(input.statements)
  const groups = new Map<string, { s: VexStatement, products: string[] }>()
  for (const s of list) {
    const k = canonicalJson([s.vuln_id, s.status, s.justification, s.impact_statement, s.action_statement, s.timestamp])
    const g = groups.get(k)
    if (g) g.products.push(s.product)
    else groups.set(k, { s, products: [s.product] })
  }
  const statements = [...groups.values()].map(({ s, products }) => {
    const st: Record<string, unknown> = {
      vulnerability: { name: s.vuln_id },
      products: [...new Set(products)].sort(byCodepoint).map(p => ({ '@id': p, 'identifiers': { purl: p } })),
      status: s.status,
      timestamp: s.timestamp,
    }
    if (s.status === 'not_affected') {
      if (s.justification) st.justification = s.justification
      // Une déclaration not_affected a toujours une justification ou une déclaration d'impact (OpenVEX).
      st.impact_statement = s.impact_statement ?? (s.justification ? undefined : 'Not affected.')
    }
    else if (s.status === 'affected') {
      st.action_statement = s.action_statement ?? s.impact_statement ?? 'Remediation pending.'
    }
    else if (s.impact_statement) {
      st.status_notes = s.impact_statement
    }
    return st
  })
  const document: Record<string, unknown> = {
    '@context': OPENVEX_CONTEXT,
    '@id': documentId(list),
    'author': VEX_AUTHOR,
    'timestamp': input.timestamp,
    'version': 1,
    'statements': statements,
  }
  if (input.tooling) document.tooling = input.tooling
  const canonical = canonicalJson(document)
  return { document: JSON.parse(canonical) as Record<string, unknown>, canonical }
}

const CDX_STATE: Record<VexStatus, string> = {
  not_affected: 'not_affected', affected: 'exploitable', fixed: 'resolved', under_investigation: 'in_triage',
}
const CDX_JUSTIFICATION: Record<VexJustification, string> = {
  component_not_present: 'code_not_present',
  vulnerable_code_not_present: 'code_not_present',
  vulnerable_code_not_in_execute_path: 'code_not_reachable',
  vulnerable_code_cannot_be_controlled_by_adversary: 'requires_environment',
  inline_mitigations_already_exist: 'protected_by_mitigating_control',
}
const FROM_CDX_STATE: Record<string, VexStatus> = {
  not_affected: 'not_affected', false_positive: 'not_affected', exploitable: 'affected',
  resolved: 'fixed', resolved_with_pedigree: 'fixed', in_triage: 'under_investigation',
}
const FROM_CDX_JUSTIFICATION: Record<string, VexJustification> = {
  code_not_present: 'vulnerable_code_not_present',
  code_not_reachable: 'vulnerable_code_not_in_execute_path',
  requires_configuration: 'vulnerable_code_cannot_be_controlled_by_adversary',
  requires_dependency: 'vulnerable_code_cannot_be_controlled_by_adversary',
  requires_environment: 'vulnerable_code_cannot_be_controlled_by_adversary',
  protected_by_compiler: 'inline_mitigations_already_exist',
  protected_at_runtime: 'inline_mitigations_already_exist',
  protected_at_perimeter: 'inline_mitigations_already_exist',
  protected_by_mitigating_control: 'inline_mitigations_already_exist',
}

/** purl → nom lisible (dernier segment, sans version), pour le composant CycloneDX. */
function purlName(p: string): string {
  const path = p.slice(4).split(/[?#]/)[0]!
  const last = path.split('/').pop() ?? path
  const at = last.lastIndexOf('@')
  const raw = at > 0 ? last.slice(0, at) : last
  try {
    return decodeURIComponent(raw).slice(0, 200) || 'component'
  }
  catch {
    return raw.slice(0, 200) || 'component'
  }
}

/** CycloneDX 1.6 (VEX dans un BOM) : un composant par produit, une vulnérabilité par déclaration groupée. */
export function renderCycloneDxVex(input: RenderInput): { document: Record<string, unknown>, canonical: string } {
  const list = sortStatements(input.statements)
  const products = [...new Set(list.map(s => s.product))].sort(byCodepoint)
  const groups = new Map<string, { s: VexStatement, refs: string[] }>()
  for (const s of list) {
    const k = canonicalJson([s.vuln_id, s.status, s.justification, s.impact_statement, s.action_statement, s.timestamp])
    const g = groups.get(k)
    if (g) g.refs.push(s.product)
    else groups.set(k, { s, refs: [s.product] })
  }
  const id = documentId(list).slice('urn:scanoria:vex:'.length)
  // urn:uuid dérivé de l'empreinte : stable pour un même contenu.
  const serial = `urn:uuid:${id.slice(0, 8)}-${id.slice(8, 12)}-5${id.slice(13, 16)}-${((Number.parseInt(id[16]!, 16) & 0x3) | 0x8).toString(16)}${id.slice(17, 20)}-${id.slice(20, 32)}`
  const document: Record<string, unknown> = {
    bomFormat: 'CycloneDX',
    specVersion: '1.6',
    serialNumber: serial,
    version: 1,
    metadata: {
      timestamp: input.timestamp,
      tools: { components: [{ type: 'application', name: VEX_AUTHOR, ...(input.tooling ? { version: input.tooling } : {}) }] },
    },
    components: products.map(p => ({ 'type': 'library', 'bom-ref': p, 'name': purlName(p), 'purl': p })),
    vulnerabilities: [...groups.values()].map(({ s, refs }) => {
      const analysis: Record<string, unknown> = { state: CDX_STATE[s.status], lastUpdated: s.timestamp }
      if (s.justification && s.status === 'not_affected') analysis.justification = CDX_JUSTIFICATION[s.justification]
      const detail = s.status === 'affected' ? (s.action_statement ?? s.impact_statement) : s.impact_statement
      if (detail) analysis.detail = detail
      return {
        id: s.vuln_id,
        analysis,
        affects: [...new Set(refs)].sort(byCodepoint).map(ref => ({ ref })),
      }
    }),
  }
  const canonical = canonicalJson(document)
  return { document: JSON.parse(canonical) as Record<string, unknown>, canonical }
}

function depthOf(v: unknown, max: number, d = 0): number {
  if (d > max) return d
  if (v === null || typeof v !== 'object') return d
  let m = d
  for (const x of Array.isArray(v) ? v : Object.values(v as Record<string, unknown>)) {
    m = Math.max(m, depthOf(x, max, d + 1))
    if (m > max) return m
  }
  return m
}

function vulnId(v: unknown, field: string): string {
  if (typeof v !== 'string' || !VULN_ID_RE.test(v)) throw new VexFormatError('E_VEX_VULN_ID', field)
  return v
}

function enumValue<T extends string>(v: unknown, allowed: readonly T[], code: string, field: string): T {
  if (typeof v !== 'string' || !(allowed as readonly string[]).includes(v)) throw new VexFormatError(code, field)
  return v as T
}

export interface ParsedVex {
  format: 'openvex' | 'cyclonedx'
  statements: VexStatement[]
}

function parseOpenVex(doc: Record<string, unknown>, now: string): VexStatement[] {
  if (typeof doc['@context'] !== 'string' || !doc['@context'].startsWith('https://openvex.dev/ns/')) throw new VexFormatError('E_VEX_FORMAT', '@context')
  const statements = doc.statements
  if (!Array.isArray(statements) || statements.length === 0) throw new VexFormatError('E_VEX_FORMAT', 'statements')
  if (statements.length > VEX_LIMITS.maxStatements) throw new VexFormatError('E_VEX_TOO_MANY', 'statements')
  const docTime = isoSecond(doc.timestamp, now)
  const out: VexStatement[] = []
  statements.forEach((raw, i) => {
    if (!raw || typeof raw !== 'object' || Array.isArray(raw)) throw new VexFormatError('E_VEX_FORMAT', `statements[${i}]`)
    const s = raw as Record<string, unknown>
    const vuln = s.vulnerability as Record<string, unknown> | undefined
    const id = vulnId(vuln && typeof vuln === 'object' ? vuln.name : undefined, `statements[${i}].vulnerability.name`)
    const status = enumValue(s.status, VEX_STATUSES, 'E_VEX_STATUS', `statements[${i}].status`)
    const justification = s.justification === undefined ? null : enumValue(s.justification, VEX_JUSTIFICATIONS, 'E_VEX_JUSTIFICATION', `statements[${i}].justification`)
    const impact = cleanText(s.impact_statement ?? s.status_notes, `statements[${i}].impact_statement`)
    const action = cleanText(s.action_statement, `statements[${i}].action_statement`)
    if (status === 'not_affected' && !justification && !impact) throw new VexFormatError('E_VEX_JUSTIFICATION', `statements[${i}]`)
    const products = s.products
    if (!Array.isArray(products) || products.length === 0) throw new VexFormatError('E_VEX_PRODUCT', `statements[${i}].products`)
    if (products.length > VEX_LIMITS.maxProducts) throw new VexFormatError('E_VEX_TOO_MANY', `statements[${i}].products`)
    const timestamp = isoSecond(s.timestamp, docTime)
    products.forEach((p, j) => {
      const o = p as Record<string, unknown> | null
      const ids = o && typeof o === 'object' ? o.identifiers as Record<string, unknown> | undefined : undefined
      const purl = ids && typeof ids === 'object' && ids.purl !== undefined ? ids.purl : o?.['@id']
      if (!validPurl(purl)) throw new VexFormatError('E_VEX_PRODUCT', `statements[${i}].products[${j}]`)
      out.push({ vuln_id: id, product: purl, status, justification, impact_statement: impact, action_statement: action, timestamp })
    })
  })
  return out
}

function parseCycloneDx(doc: Record<string, unknown>, now: string): VexStatement[] {
  if (doc.bomFormat !== 'CycloneDX' || !['1.4', '1.5', '1.6'].includes(String(doc.specVersion))) throw new VexFormatError('E_VEX_FORMAT', 'specVersion')
  const vulns = doc.vulnerabilities
  if (!Array.isArray(vulns) || vulns.length === 0) throw new VexFormatError('E_VEX_FORMAT', 'vulnerabilities')
  if (vulns.length > VEX_LIMITS.maxStatements) throw new VexFormatError('E_VEX_TOO_MANY', 'vulnerabilities')
  const refs = new Map<string, string>()
  const comps = Array.isArray(doc.components) ? doc.components : []
  if (comps.length > VEX_LIMITS.maxStatements) throw new VexFormatError('E_VEX_TOO_MANY', 'components')
  for (const c of comps) {
    const o = c as Record<string, unknown> | null
    if (o && typeof o['bom-ref'] === 'string' && o['bom-ref'].length <= 500 && validPurl(o.purl)) refs.set(o['bom-ref'], o.purl)
  }
  const docTime = isoSecond((doc.metadata as Record<string, unknown> | undefined)?.timestamp, now)
  const out: VexStatement[] = []
  vulns.forEach((raw, i) => {
    if (!raw || typeof raw !== 'object' || Array.isArray(raw)) throw new VexFormatError('E_VEX_FORMAT', `vulnerabilities[${i}]`)
    const v = raw as Record<string, unknown>
    const id = vulnId(v.id, `vulnerabilities[${i}].id`)
    const a = v.analysis as Record<string, unknown> | undefined
    if (!a || typeof a !== 'object') throw new VexFormatError('E_VEX_STATUS', `vulnerabilities[${i}].analysis`)
    const state = enumValue(a.state, Object.keys(FROM_CDX_STATE), 'E_VEX_STATUS', `vulnerabilities[${i}].analysis.state`)
    const status = FROM_CDX_STATE[state]!
    const justification = a.justification === undefined
      ? null
      : FROM_CDX_JUSTIFICATION[enumValue(a.justification, Object.keys(FROM_CDX_JUSTIFICATION), 'E_VEX_JUSTIFICATION', `vulnerabilities[${i}].analysis.justification`)]!
    const detail = cleanText(a.detail, `vulnerabilities[${i}].analysis.detail`)
    if (status === 'not_affected' && !justification && !detail) throw new VexFormatError('E_VEX_JUSTIFICATION', `vulnerabilities[${i}]`)
    const affects = v.affects
    if (!Array.isArray(affects) || affects.length === 0) throw new VexFormatError('E_VEX_PRODUCT', `vulnerabilities[${i}].affects`)
    if (affects.length > VEX_LIMITS.maxProducts) throw new VexFormatError('E_VEX_TOO_MANY', `vulnerabilities[${i}].affects`)
    const timestamp = isoSecond(a.lastUpdated ?? a.firstIssued, docTime)
    affects.forEach((af, j) => {
      const ref = (af as Record<string, unknown> | null)?.ref
      const purl = typeof ref === 'string' ? (refs.get(ref) ?? ref) : undefined
      if (!validPurl(purl)) throw new VexFormatError('E_VEX_PRODUCT', `vulnerabilities[${i}].affects[${j}]`)
      out.push({
        vuln_id: id, product: purl, status, justification,
        impact_statement: status === 'affected' ? null : detail,
        action_statement: status === 'affected' ? detail : null,
        timestamp,
      })
    })
  })
  return out
}

/** Lecture stricte d'un document VEX importé (OpenVEX 0.2 ou CycloneDX 1.4 à 1.6). */
export function parseVexDocument(text: string, now = new Date()): ParsedVex {
  if (typeof text !== 'string') throw new VexFormatError('E_VEX_FORMAT')
  if (Buffer.byteLength(text, 'utf8') > VEX_LIMITS.maxBytes) throw new VexFormatError('E_VEX_TOO_LARGE')
  let doc: unknown
  try {
    doc = JSON.parse(text)
  }
  catch {
    throw new VexFormatError('E_VEX_JSON')
  }
  if (!doc || typeof doc !== 'object' || Array.isArray(doc)) throw new VexFormatError('E_VEX_FORMAT')
  if (depthOf(doc, VEX_LIMITS.maxDepth) > VEX_LIMITS.maxDepth) throw new VexFormatError('E_VEX_TOO_DEEP')
  const at = now.toISOString().replace(/\.\d{3}Z$/, 'Z')
  const o = doc as Record<string, unknown>
  if ('@context' in o) return { format: 'openvex', statements: parseOpenVex(o, at) }
  if (o.bomFormat === 'CycloneDX') return { format: 'cyclonedx', statements: parseCycloneDx(o, at) }
  throw new VexFormatError('E_VEX_FORMAT')
}

/**
 * Marque de justification en tête d'un motif d'exception (« [vulnerable_code_not_in_execute_path] … ») :
 * posée par l'import et par la rédaction I10, relue à la génération.
 */
export function justificationFromReason(reason: string): { justification: VexJustification | null, text: string } {
  const m = /^\[([a-z_]{10,60})\]\s*/.exec(reason)
  if (m && (VEX_JUSTIFICATIONS as readonly string[]).includes(m[1]!)) {
    return { justification: m[1] as VexJustification, text: reason.slice(m[0].length).trim() || reason }
  }
  return { justification: null, text: reason }
}
