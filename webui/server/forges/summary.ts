// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Textes publiés dans la forge (fonctions pures, testées seules) :
// - statut de commit scanoria/<profil> : verdict, lien, explication courte ;
// - commentaire de synthèse d'une PR (un seul, mis à jour en place) :
//   verdict et ce qui bloque (I9), nouveaux résultats avec leur explication
//   courte I2 marquée « proposé par IA » (I25), lien « demander une
//   exception » (J15), revue des dépendances (H6), commande /scanoria ;
// - annotations ligne à ligne (J7), en nombre borné.
// Tout texte libre (message d'outil, chemin, sortie de l'IA) est échappé ici
// (escapeInline) ; le texte entier passe ensuite par sanitizeForForge.

import type { VerdictDetails } from '#shared/analysis'
import { escapeInline } from './sanitize'
import type { Annotation, CommitState } from './pr-types'

export type ForgeLocale = 'fr' | 'en'
export type Phase = 'pending' | 'early' | 'final'

export interface SummaryFinding {
  id: string
  tool: string
  rule_id: string
  title: string
  severity: string
  path: string | null
  start_line: number | null
  category: string
  malicious: boolean
  secret_type: string | null
  /** I2 : explication courte de l'IA (summary), si elle existe. */
  ai_summary: string | null
  ai_model: string | null
  /** Résultat d'un module d'analyse par IA (K1–K7, contrat 32). */
  origin?: string
}

export interface DependencyChange {
  purl: string
  name: string
  version: string | null
  licenses: string[]
  decision: 'allowed' | 'review' | 'denied'
  /** H5 : âge de la version, en jours (null : inconnu). */
  age_days: number | null
  /** npm : paquet qui exécute un script à l'installation. */
  install_script: boolean
  /** H2 : score Scorecard du dépôt amont (0 à 10), quand le chantier A le fournit. */
  scorecard?: number | null
}

export interface SummaryInput {
  locale: ForgeLocale
  phase: Phase
  scanUrl: string | null
  /** Lien de la console pour demander une exception (J15) : ajouté de l'identifiant du résultat. */
  exceptionUrl: (findingId: string) => string | null
  scanNumber: number
  profile: string
  verdict: VerdictDetails['verdict'] | null
  details: VerdictDetails | null
  earlyReasons: string[]
  newFindings: SummaryFinding[]
  totalNew: number
  /** H6 : différence de SBOM base → PR (null : pas de SBOM). */
  dependencies: { added: DependencyChange[], removed: number, baseKnown: boolean } | null
  quarantineDays: number
  /** I9 : explication de l'IA, si elle existe déjà. */
  aiVerdict: { text: string, model: string | null } | null
}

const T = {
  fr: {
    title: 'Scanoria',
    passed: '✅ Réussi', failed: '❌ Échec', inconclusive: '⚠️ Non concluant', pending: '⏳ Analyse en cours',
    early: '❌ Échec anticipé : un blocage certain est déjà connu ; le rapport complet suit.',
    scan: 'Analyse', profile: 'profil', open: 'Ouvrir dans la console',
    blocking: 'Ce qui bloque', newFindings: 'Nouveaux résultats', none: 'Aucun nouveau résultat.',
    more: (n: number) => `… et ${n} autre(s), dans la console.`,
    cols: '| Gravité | Outil | Règle | Emplacement | Résultat | Explication |',
    ai: 'proposé par IA', request: 'demander une exception',
    deps: 'Dépendances (base → PR)', added: 'ajoutée(s)', removed: 'retirée(s)', noBase: 'base de la PR non analysée : toutes les dépendances sont listées',
    depCols: '| Composant | Version | Licence | Âge | Script d\'installation |',
    recent: (d: number) => `${d} j (récente)`, days: (d: number) => `${d} j`, unknown: 'inconnu', yes: 'oui', no: 'non',
    accept: 'Pour demander une exception depuis la PR, répondez :',
    acceptNote: 'La demande est approuvée ou refusée par un administrateur dans la console ; l\'auteur du commit et les comptes non humains ne peuvent pas approuver.',
    statusPassed: 'Quality gate réussi', statusFailed: 'Quality gate en échec', statusInconclusive: 'Verdict non concluant (bloquant)',
    statusPending: 'Analyse en cours', statusEarly: 'Échec anticipé',
    reasons: {
      'malicious-package': 'paquet malveillant (MAL-), sans exception possible', 'secret': 'secret dans le code',
      'vuln': 'vulnérabilité au-dessus du seuil', 'sast': 'résultat SAST au-dessus du seuil', 'iac': 'résultat IaC au-dessus du seuil',
      'other': 'résultat au-dessus du seuil', 'module-error': 'outil en erreur', 'module-missing': 'outil absent',
      'output-invalid': 'sortie d\'outil invalide', 'coverage-gap': 'trou de couverture', 'feed-stale': 'base de vulnérabilités trop ancienne',
      'license-denied': 'licence interdite', 'license-review': 'licence à revoir', 'kev': 'vulnérabilité exploitée activement (KEV)',
      'epss': 'probabilité d\'exploitation élevée (EPSS)', 'quarantine': 'dépendance trop récente (quarantaine)',
    } as Record<string, string>,
  },
  en: {
    title: 'Scanoria',
    passed: '✅ Passed', failed: '❌ Failed', inconclusive: '⚠️ Inconclusive', pending: '⏳ Analysis running',
    early: '❌ Early failure: a certain blocker is already known; the full report follows.',
    scan: 'Analysis', profile: 'profile', open: 'Open in the console',
    blocking: 'What blocks', newFindings: 'New findings', none: 'No new finding.',
    more: (n: number) => `… and ${n} more, in the console.`,
    cols: '| Severity | Tool | Rule | Location | Finding | Explanation |',
    ai: 'suggested by AI', request: 'request an exception',
    deps: 'Dependencies (base → PR)', added: 'added', removed: 'removed', noBase: 'PR base not analysed: every dependency is listed',
    depCols: '| Component | Version | License | Age | Install script |',
    recent: (d: number) => `${d} d (recent)`, days: (d: number) => `${d} d`, unknown: 'unknown', yes: 'yes', no: 'no',
    accept: 'To request an exception from the PR, reply:',
    acceptNote: 'An administrator approves or refuses the request in the console; the commit author and non-human accounts cannot approve.',
    statusPassed: 'Quality gate passed', statusFailed: 'Quality gate failed', statusInconclusive: 'Inconclusive verdict (blocking)',
    statusPending: 'Analysis running', statusEarly: 'Early failure',
    reasons: {
      'malicious-package': 'malicious package (MAL-), no exception possible', 'secret': 'secret in the code',
      'vuln': 'vulnerability above the threshold', 'sast': 'SAST finding above the threshold', 'iac': 'IaC finding above the threshold',
      'other': 'finding above the threshold', 'module-error': 'tool error', 'module-missing': 'missing tool',
      'output-invalid': 'invalid tool output', 'coverage-gap': 'coverage gap', 'feed-stale': 'vulnerability database too old',
      'license-denied': 'denied license', 'license-review': 'license to review', 'kev': 'actively exploited vulnerability (KEV)',
      'epss': 'high exploit probability (EPSS)', 'quarantine': 'dependency too recent (quarantine)',
    } as Record<string, string>,
  },
}

export const SEVERITY_ICON: Record<string, string> = { critical: '🟥 critical', high: '🟧 high', medium: '🟨 medium', low: '🟦 low', info: '⬜ info' }

/** Forme courte d'un identifiant de résultat (8 caractères), utilisée par /scanoria accept. */
export function shortId(id: string): string {
  return id.replace(/-/g, '').slice(0, 8)
}

/** État et texte du statut de commit. */
export function statusFor(phase: Phase, verdict: SummaryInput['verdict'], details: VerdictDetails | null, earlyReasons: string[], locale: ForgeLocale): { state: CommitState, description: string } {
  const t = T[locale]
  if (phase === 'pending') return { state: 'pending', description: t.statusPending }
  if (phase === 'early') return { state: 'failure', description: `${t.statusEarly} : ${earlyReasons.map(c => t.reasons[c] ?? c).join(', ')}` }
  const reasons = (details?.reasons ?? []).filter(r => r.blocking).map(r => `${t.reasons[r.code] ?? r.code} (${r.count})`)
  if (verdict === 'passed') return { state: 'success', description: t.statusPassed }
  if (verdict === 'failed') return { state: 'failure', description: `${t.statusFailed} : ${reasons.join(', ')}` }
  return { state: 'failure', description: `${t.statusInconclusive}${reasons.length ? ` : ${reasons.join(', ')}` : ''}` }
}

function link(label: string, url: string | null): string {
  return url ? `[${label}](${url})` : label
}

/** Commentaire de synthèse d'une PR (Markdown, avant sanitizeForForge). */
export function buildSummary(input: SummaryInput): string {
  const t = T[input.locale]
  const head = input.phase === 'pending'
    ? t.pending
    : input.phase === 'early'
      ? t.early
      : input.verdict === 'passed' ? t.passed : input.verdict === 'failed' ? t.failed : t.inconclusive
  const out: string[] = [
    `### ${t.title} · ${head}`,
    '',
    `${t.scan} n° ${input.scanNumber} · ${t.profile} ${escapeInline(input.profile, 64)} · ${link(t.open, input.scanUrl)}`,
  ]

  const blocking = input.phase === 'early'
    ? input.earlyReasons.map(c => `- ${t.reasons[c] ?? escapeInline(c, 40)}`)
    : (input.details?.reasons ?? []).filter(r => r.blocking).map(r => `- ${t.reasons[r.code] ?? escapeInline(r.code, 40)} : ${r.count}${r.module ? ` (${escapeInline(r.module, 64)})` : ''}`)
  if (blocking.length) out.push('', `#### ${t.blocking}`, ...blocking)
  if (input.aiVerdict) out.push('', `> ${escapeInline(input.aiVerdict.text, 1200)}`, `> _${t.ai}${input.aiVerdict.model ? ` · ${escapeInline(input.aiVerdict.model, 80)}` : ''}_`)

  out.push('', `#### ${t.newFindings} (${input.totalNew})`)
  if (!input.newFindings.length) out.push(t.none)
  else {
    out.push(t.cols, '|---|---|---|---|---|---|')
    for (const f of input.newFindings) {
      const where = f.path ? `\`${f.path.replace(/[`|]/g, '').slice(0, 200)}${f.start_line ? `:${f.start_line}` : ''}\`` : '—'
      const expl = f.ai_summary
        ? `${escapeInline(f.ai_summary, 280)} _(${t.ai}${f.ai_model ? ` · ${escapeInline(f.ai_model, 60)}` : ''})_`
        : '—'
      const req = f.malicious ? '' : ` · ${link(t.request, input.exceptionUrl(f.id))}`
      out.push(`| ${SEVERITY_ICON[f.severity] ?? escapeInline(f.severity, 20)} | ${escapeInline(f.tool, 40)} | ${escapeInline(f.rule_id, 80)} | ${where} | \`${shortId(f.id)}\` ${escapeInline(f.title, 160)}${f.origin === 'ai' ? ' _(IA)_' : ''}${req} | ${expl} |`)
    }
    if (input.totalNew > input.newFindings.length) out.push('', t.more(input.totalNew - input.newFindings.length))
  }

  const deps = input.dependencies
  if (deps && (deps.added.length || deps.removed)) {
    out.push('', `#### ${t.deps}`, `${deps.added.length} ${t.added} · ${deps.removed} ${t.removed}${deps.baseKnown ? '' : ` · ${t.noBase}`}`)
    if (deps.added.length) {
      out.push('', t.depCols.replace(/\|$/, deps.added.some(d => d.scorecard != null) ? '| Scorecard |' : '|'), `|---|---|---|---|---|${deps.added.some(d => d.scorecard != null) ? '---|' : ''}`)
      for (const d of deps.added.slice(0, 30)) {
        const lic = d.licenses.length ? escapeInline(d.licenses.join(' / '), 80) : t.unknown
        const decision = d.decision === 'denied' ? ` ❌` : d.decision === 'review' ? ` ⚠️` : ''
        const age = d.age_days == null ? t.unknown : d.age_days < input.quarantineDays ? `⚠️ ${t.recent(d.age_days)}` : t.days(d.age_days)
        const sc = deps.added.some(x => x.scorecard != null) ? ` ${d.scorecard == null ? '—' : d.scorecard.toFixed(1)} |` : ''
        out.push(`| ${escapeInline(d.name, 120)} | ${escapeInline(d.version ?? '—', 60)} | ${lic}${decision} | ${age} | ${d.install_script ? `⚠️ ${t.yes}` : t.no} |${sc}`)
      }
      if (deps.added.length > 30) out.push('', t.more(deps.added.length - 30))
    }
  }

  if (input.phase !== 'pending' && input.newFindings.some(f => !f.malicious)) {
    out.push('', `_${t.accept}_`, '', '```', input.locale === 'fr' ? '/scanoria accept <résultat> --until AAAA-MM-JJ --reason "motif"' : '/scanoria accept <finding> --until YYYY-MM-DD --reason "reason"', '```', `_${t.acceptNote}_`)
  }
  return out.join('\n')
}

/** J7 : annotations des nouveaux résultats situés dans les fichiers modifiés, les plus graves d'abord. */
export function buildAnnotations(findings: SummaryFinding[], changed: Set<string> | null, locale: ForgeLocale, max: number): Annotation[] {
  const rank: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 }
  return findings
    .filter(f => f.path && f.start_line && f.start_line > 0 && (!changed || changed.has(f.path)))
    .sort((a, b) => (rank[a.severity] ?? 5) - (rank[b.severity] ?? 5) || a.path!.localeCompare(b.path!) || a.start_line! - b.start_line!)
    .slice(0, max)
    .map(f => ({
      path: f.path!,
      line: f.start_line!,
      level: f.severity === 'critical' || f.severity === 'high' ? 'failure' : f.severity === 'medium' ? 'warning' : 'notice',
      title: `${f.severity} · ${f.tool} · ${f.rule_id}`,
      message: `${escapeInline(f.title, 300)} (\`${shortId(f.id)}\`)${f.ai_summary ? `\n\n${escapeInline(f.ai_summary, 400)} _(${T[locale].ai})_` : ''}`,
    }))
}
