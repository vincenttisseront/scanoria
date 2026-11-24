// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Lecture des sorties de scanners : SARIF 2.1.0 et CycloneDX (vulnérabilités).
// Les documents sont hostiles : tailles bornées, chemins vérifiés, textes
// nettoyés et masqués (aucun secret), aucun HTML interprété (l'interface
// échappe tout). Fonctions pures, sans accès à la base.

import { maskToken, redact } from './redact'
import { redactForFingerprint } from './redact-v1'
import {
  cleanText, ecosystemFromPath, extractCwe, extractVulnIds, fingerprintOf, fixedFromHelp,
  inferCategory, isVulnId, normalizePath, packageFromMessage, parsePurl, primaryVulnId, splitVersions,
  type PackageRef,
} from './normalize'
import { nativeKey } from './severity'

export const MAX_RESULTS = 10_000
export const MAX_SNIPPET = 2000

export interface ParsedFinding {
  fingerprint: string
  tool: string
  ruleId: string
  category: string
  nativeSeverity: string
  title: string
  message: string | null
  path: string | null
  startLine: number | null
  endLine: number | null
  snippet: string | null
  cwe: string[]
  vulnIds: string[]
  package: PackageRef | null
  malicious: boolean
  secretType: string | null
}

export interface ParseIssue {
  code: 'invalid-document' | 'path-outside' | 'truncated' | 'invalid-result'
  detail?: string
}

export interface ParseContext {
  /** Identifiant du module (findings.tool). */
  moduleId: string
  /** Catégories déclarées par le module (manifeste). */
  moduleCategories: string[]
}

export interface ParseOutput {
  findings: ParsedFinding[]
  issues: ParseIssue[]
}

type Obj = Record<string, unknown>
const isObj = (v: unknown): v is Obj => !!v && typeof v === 'object' && !Array.isArray(v)
const arr = (v: unknown): unknown[] => (Array.isArray(v) ? v : [])
const str = (v: unknown): string | undefined => (typeof v === 'string' ? v : undefined)
const text = (v: unknown): string | undefined => (isObj(v) ? str(v.text) ?? str(v.markdown) : undefined)
const line = (v: unknown): number | null => (typeof v === 'number' && Number.isInteger(v) && v > 0 && v < 10_000_000 ? v : null)

const SEVERITY_TAG_RE = /^(critical|high|medium|low|unknown|info)$/i

/**
 * Ajoute un rang d'occurrence aux empreintes répétées (même règle, même fichier,
 * même contexte). Limite connue : insérer une occurrence identique au-dessus
 * renumérote les suivantes.
 */
function dedupe(findings: ParsedFinding[]): ParsedFinding[] {
  const seen = new Map<string, number>()
  const out: ParsedFinding[] = []
  const sorted = [...findings].sort((a, b) => (a.startLine ?? 0) - (b.startLine ?? 0))
  for (const f of sorted) {
    const n = seen.get(f.fingerprint) ?? 0
    seen.set(f.fingerprint, n + 1)
    if (n === 0) out.push(f)
    else out.push({ ...f, fingerprint: fingerprintOf({ tool: f.tool, ruleId: f.ruleId, path: f.path, context: `#${n}|${f.fingerprint}`, pkg: null, vulnId: null, partial: null }) })
  }
  return out
}

interface Draft {
  ruleId: string
  title: string
  message: string
  tags: string[]
  path: string | null
  startLine: number | null
  endLine: number | null
  snippet: string
  cweSources: unknown[]
  vulnIds: string[]
  pkg: PackageRef | null
  native: string
  partial: Record<string, unknown> | null
  secretHint: string | null
}

function finish(ctx: ParseContext, d: Draft): ParsedFinding {
  const vulnId = primaryVulnId(d.vulnIds) ?? (d.pkg ? d.ruleId : null)
  const cwe = extractCwe(d.cweSources)
  const category = inferCategory({
    moduleCategories: ctx.moduleCategories,
    tags: d.tags,
    hasVuln: d.vulnIds.length > 0,
    hasPackage: !!d.pkg,
    cwe,
  })
  const secret = category === 'secrets'
  // Secrets : masquage agressif (toute chaîne aléatoire), jamais la valeur ;
  // l'extrait d'un secret n'est jamais gardé, seulement sa forme.
  const mask = (s: string) => redact(s, { aggressive: secret })
  const snippet = !d.snippet ? '' : secret ? maskToken('snippet', d.snippet.length) : mask(d.snippet)
  const title = mask(d.title || d.ruleId)
  const message = mask(d.message)
  const ruleId = cleanText(d.ruleId, 255) || 'unknown'
  // G19 : l'empreinte garde le masquage de la 0.3 (figé), jamais le masquage
  // élargi de l'affichage : un résultat déjà trié garde son identité.
  const fpContext = !d.snippet ? '' : secret ? snippet : redactForFingerprint(d.snippet)
  return {
    fingerprint: fingerprintOf({ tool: ctx.moduleId, ruleId, path: d.path, context: fpContext, pkg: d.pkg, vulnId, partial: d.partial }),
    tool: ctx.moduleId,
    ruleId,
    category,
    nativeSeverity: d.native,
    title: cleanText(title, 500) || ruleId,
    message: message ? cleanText(message, 4000) : null,
    path: d.path,
    startLine: d.startLine,
    endLine: d.endLine ?? d.startLine,
    snippet: snippet ? cleanText(snippet, MAX_SNIPPET) : null,
    cwe,
    vulnIds: d.vulnIds,
    package: d.pkg,
    malicious: d.vulnIds.some(i => i.startsWith('MAL-')),
    secretType: secret ? cleanText(redact(d.secretHint ?? ruleId, { aggressive: true }), 64) : null,
  }
}

/**
 * Valeurs de result.kind qui ne décrivent pas un problème (SARIF 2.1.0 § 3.27.9),
 * écartées seulement pour les modules dont toute la sortie est un index (reach-index,
 * I11) : pour les autres scanners, rien n'est écarté sans trace.
 */
const NOT_A_PROBLEM = new Set(['pass', 'notApplicable', 'informational'])
const INDEX_MODULES = new Set(['reach-index'])

/** SARIF 2.1.0 → résultats. */
export function parseSarif(doc: unknown, ctx: ParseContext): ParseOutput {
  const issues: ParseIssue[] = []
  if (!isObj(doc) || !Array.isArray(doc.runs) || (doc.version !== undefined && doc.version !== '2.1.0')) {
    return { findings: [], issues: [{ code: 'invalid-document', detail: 'sarif' }] }
  }
  const drafts: Draft[] = []
  let outside = 0
  let invalid = 0
  let total = 0
  let declaredTruncated = false
  for (const run of doc.runs.slice(0, 32)) {
    if (!isObj(run)) continue
    // Troncature déclarée par l'outil lui-même (run.properties.scanoria.truncated,
    // convertisseur SonarQube) : elle ne peut qu'ajouter un trou de couverture.
    const runProps = isObj(run.properties) && isObj(run.properties.scanoria) ? run.properties.scanoria : {}
    if (runProps.truncated === true) declaredTruncated = true
    const tool = isObj(run.tool) ? run.tool : {}
    const driver = isObj(tool.driver) ? tool.driver : {}
    const rules: Obj[] = arr(driver.rules).filter(isObj)
    for (const ext of arr(tool.extensions).slice(0, 32)) {
      if (isObj(ext)) rules.push(...arr(ext.rules).filter(isObj))
    }
    const byId = new Map<string, Obj>()
    for (const r of rules) if (typeof r.id === 'string') byId.set(r.id, r)
    const bases = isObj(run.originalUriBaseIds) ? run.originalUriBaseIds : {}
    for (const res of arr(run.results)) {
      // Index reach-index (I11) : ses entrées « informational » ne sont pas des résultats.
      if (INDEX_MODULES.has(ctx.moduleId) && isObj(res) && typeof res.kind === 'string' && NOT_A_PROBLEM.has(res.kind)) continue
      total++
      if (drafts.length >= MAX_RESULTS) continue
      if (!isObj(res)) {
        invalid++
        continue
      }
      const ruleIndex = typeof res.ruleIndex === 'number' ? res.ruleIndex : isObj(res.rule) && typeof res.rule.index === 'number' ? res.rule.index : -1
      const ruleId = str(res.ruleId) ?? (isObj(res.rule) ? str(res.rule.id) : undefined) ?? str(rules[ruleIndex]?.id)
      if (!ruleId) {
        invalid++
        continue
      }
      const rule = byId.get(ruleId) ?? (ruleIndex >= 0 ? rules[ruleIndex] : undefined) ?? {}
      const rprops = isObj(rule.properties) ? rule.properties : {}
      const props = isObj(res.properties) ? res.properties : {}
      const loc = isObj(arr(res.locations)[0]) ? arr(res.locations)[0] as Obj : {}
      const phys = isObj(loc.physicalLocation) ? loc.physicalLocation : {}
      const art = isObj(phys.artifactLocation) ? phys.artifactLocation : {}
      const baseId = str(art.uriBaseId)
      const base = baseId && isObj(bases[baseId]) ? str((bases[baseId] as Obj).uri) : undefined
      const path = str(art.uri) === undefined ? null : normalizePath(str(art.uri), base)
      if (path === null && str(art.uri) !== undefined) {
        outside++
        continue
      }
      const region = isObj(phys.region) ? phys.region : {}
      const ctxRegion = isObj(phys.contextRegion) ? phys.contextRegion : {}
      const snippet = text(region.snippet) ?? text(ctxRegion.snippet) ?? ''
      const tags = [...arr(rprops.tags), ...arr(props.tags)].filter((t): t is string => typeof t === 'string').slice(0, 50)
      const message = text(res.message) ?? text(rule.fullDescription) ?? ''
      // Identifiants d'avis : règle, alias déclarés ; le message seulement pour une règle d'avis
      // (le message d'un autre outil peut citer un nom de fichier choisi par le dépôt analysé).
      const idSources: unknown[] = [ruleId, rule.id, rule.deprecatedIds, rprops.aliases, props.aliases, props.vulnerabilityId]
      const advisoryRule = isVulnId(ruleId)
      if (advisoryRule) idSources.push(message)
      const vulnIds = extractVulnIds(idSources)
      let pkg = parsePurl(props.purl) ?? parsePurl(rprops.purl) ?? (advisoryRule || vulnIds.length ? packageFromMessage(message) : null)
      if (pkg) {
        pkg = { ...pkg, ecosystem: pkg.ecosystem ?? ecosystemFromPath(path) }
        if (!pkg.fixed.length) {
          const help = isObj(rule.help) ? str(rule.help.markdown) ?? str(rule.help.text) ?? '' : ''
          pkg.fixed = fixedFromHelp(help, pkg.name)
          if (!pkg.fixed.length) pkg.fixed = splitVersions(str(props.fixedVersion) ?? str(props.fixed_version))
        }
      }
      const label = str(props.severity) ?? str(rprops.severity) ?? str(rprops['problem.severity'])
        ?? tags.find(t => SEVERITY_TAG_RE.test(t))
      const level = str(res.level) ?? (isObj(rule.defaultConfiguration) ? str(rule.defaultConfiguration.level) : undefined)
      const pf = isObj(res.partialFingerprints) ? res.partialFingerprints : null
      drafts.push({
        ruleId,
        title: text(rule.shortDescription) ?? str(rule.name) ?? ruleId,
        message,
        tags,
        path,
        startLine: line(region.startLine),
        endLine: line(region.endLine),
        snippet,
        cweSources: [tags, rprops.cwe, props.cwe, rprops.cwes, arr(rule.relationships).map(r => (isObj(r) && isObj(r.target) ? r.target.id : null))],
        vulnIds,
        pkg,
        native: nativeKey({ label, score: props['security-severity'] ?? rprops['security-severity'], level }),
        partial: pf,
        secretHint: str(props.secretType) ?? str(rprops.secretType) ?? null,
      })
    }
  }
  if (total > MAX_RESULTS) issues.push({ code: 'truncated', detail: `${total}` })
  else if (declaredTruncated) issues.push({ code: 'truncated', detail: 'declared' })
  if (outside) issues.push({ code: 'path-outside', detail: `${outside}` })
  if (invalid) issues.push({ code: 'invalid-result', detail: `${invalid}` })
  return { findings: dedupe(drafts.map(d => finish(ctx, d))), issues }
}

/** CycloneDX (1.4 à 1.6) : seules les vulnérabilités deviennent des résultats. */
export function parseCycloneDx(doc: unknown, ctx: ParseContext): ParseOutput {
  if (!isObj(doc) || doc.bomFormat !== 'CycloneDX') return { findings: [], issues: [{ code: 'invalid-document', detail: 'cyclonedx' }] }
  const issues: ParseIssue[] = []
  const components = new Map<string, Obj>()
  const visit = (list: unknown, depth: number) => {
    if (depth > 8) return
    for (const c of arr(list).slice(0, 100_000)) {
      if (!isObj(c)) continue
      if (typeof c['bom-ref'] === 'string') components.set(c['bom-ref'], c)
      visit(c.components, depth + 1)
    }
  }
  visit(doc.components, 0)
  const vulns = arr(doc.vulnerabilities)
  if (vulns.length > MAX_RESULTS) issues.push({ code: 'truncated', detail: `${vulns.length}` })
  const drafts: Draft[] = []
  for (const v of vulns.slice(0, MAX_RESULTS)) {
    if (!isObj(v) || typeof v.id !== 'string') continue
    const ids = extractVulnIds([v.id, arr(v.references).map(r => (isObj(r) ? r.id : null))])
    const ratings = arr(v.ratings).filter(isObj)
    const score = ratings.map(r => r.score).find(s => typeof s === 'number')
    const label = ratings.map(r => str(r.severity)).find(s => !!s && s !== 'unknown')
    const fixed: string[] = []
    for (const a of arr(v.affects).slice(0, 100)) {
      if (drafts.length >= MAX_RESULTS) {
        if (!issues.some(i => i.code === 'truncated')) issues.push({ code: 'truncated', detail: 'affects' })
        break
      }
      if (!isObj(a) || typeof a.ref !== 'string') continue
      const comp = components.get(a.ref)
      const pkg = parsePurl(comp?.purl ?? a.ref) ?? (comp && typeof comp.name === 'string'
        ? { ecosystem: null, name: cleanText(comp.name, 255), version: typeof comp.version === 'string' ? cleanText(comp.version, 128) : null, fixed }
        : null)
      if (!pkg) continue
      drafts.push({
        ruleId: v.id,
        title: str(v.description)?.split('\n')[0] ?? v.id,
        message: str(v.detail) ?? str(v.description) ?? '',
        tags: ['vulnerability'],
        path: null,
        startLine: null,
        endLine: null,
        snippet: '',
        cweSources: [arr(v.cwes)],
        vulnIds: ids.length ? ids : [],
        pkg,
        native: nativeKey({ label, score }),
        partial: null,
        secretHint: null,
      })
    }
  }
  return { findings: dedupe(drafts.map(d => finish(ctx, d))), issues }
}
