// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// I16 (0.6) : contexte d'un diagnostic de l'appliance (diagnose-appliance),
// joint à la tâche par la console (ai_tasks.context). Le service scanoria-ai
// ne lit ni l'état publié ni les journaux : la console assemble ici un
// contexte borné à 16 Ko, masqué (secrets remplacés par leur forme, § 3.5),
// où les noms et adresses de l'appliance et du réseau sont remplacés par des
// jetons neutres ([appliance], [host-1], [addr-1]…). La tâche le revalide,
// le masque et le neutralise de nouveau avant l'envoi.
//
// Sujets (subject_id) :
//   alert:update-rollback      alerte permanente d'un retour arrière échoué ;
//   alert:service:<nom>        service de l'appliance en échec ;
//   alert:disk:<point>         disque presque plein ;
//   alert:tls-expiry           certificat proche de son expiration ;
//   selftest:last              dernière exécution de scanoria-selftest ;
//   update:<n>                 ligne de l'historique des mises à jour ;
//   install:<module>           dernière opération en échec sur un module.

import { z } from 'zod'
import { MODULE_ID_RE } from '#shared/schemas'
import { redactText } from './redact'
import { tailBytes } from './context'

export const APPLIANCE_SUBJECT_RE
  = /^(?:alert:(?:update-rollback|tls-expiry|service:[a-z0-9][a-z0-9@._-]{0,79}|disk:[a-z0-9][a-z0-9._-]{0,79})|selftest:last|update:[1-9][0-9]{0,17}|install:[a-z0-9][a-z0-9-]{1,40})$/

export const APPLIANCE_SUBJECTS = ['alert', 'selftest', 'update', 'install'] as const
export type ApplianceSubject = (typeof APPLIANCE_SUBJECTS)[number]

/** Taille maximale du contexte entier (octets UTF-8), journal compris. */
export const MAX_APPLIANCE_CONTEXT_BYTES = 16_384
const MAX_LOG_BYTES = 12_000
const MAX_FACTS = 24

const FactValue = z.union([z.string().max(300), z.number().finite(), z.boolean(), z.null()])
export const ApplianceContext = z.strictObject({
  subject: z.enum(APPLIANCE_SUBJECTS),
  title: z.string().min(1).max(200),
  status: z.string().min(1).max(40),
  code: z.string().regex(/^(?:OK|E_[A-Z0-9_]{1,60})$/).nullable(),
  /** Module concerné (install:<module>, ou module d'une alerte), pour les actions proposées. */
  module: z.string().regex(MODULE_ID_RE).nullable(),
  facts: z.record(z.string().regex(/^[a-z][a-z0-9_.-]{0,40}$/), FactValue),
  /** Journal brut accepté jusqu'à 200 000 caractères : seule sa fin est gardée (boundApplianceContext). */
  log: z.string().max(200_000),
})
export type ApplianceContext = z.infer<typeof ApplianceContext>

/** Noms propres à l'appliance et à son réseau, à neutraliser avant l'envoi. */
export interface ApplianceNames {
  /** Nom complet de l'appliance (analyse.exemple.test). */
  fqdn?: string | null
  /** Autres noms connus : noms alternatifs du certificat, serveur Ollama, forge… */
  extra?: (string | null | undefined)[]
}

const HOST_RE = /^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?)+$/
const escapeRe = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')

function cleanName(n: string | null | undefined): string | null {
  const v = (n ?? '').trim().toLowerCase().replace(/^\*\./, '').replace(/\.$/, '')
  return HOST_RE.test(v) ? v : null
}

/** Domaine de l'appliance (exemple.test pour analyse.exemple.test), s'il a au moins deux étiquettes. */
function domainOf(fqdn: string): string | null {
  const parts = fqdn.split('.')
  return parts.length >= 3 ? parts.slice(1).join('.') : null
}

const IPV4_RE = /(?<![\d.])(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}(?![\d.]*\d)/g
// IPv6 : au moins quatre groupes, ou une forme compressée « :: » entourée de chiffres hexadécimaux.
const IPV6_RE = /(?<![\w:])(?:(?:[0-9a-f]{1,4}:){3,7}[0-9a-f]{1,4}|(?:[0-9a-f]{1,4}:){1,6}:(?:[0-9a-f]{1,4}(?::[0-9a-f]{1,4}){0,5})?|::(?:[0-9a-f]{1,4}(?::[0-9a-f]{1,4}){0,6}))(?![\w:])/gi
const EMAIL_RE = /[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,24}/g
/** Suffixes de noms internes courants, neutralisés même sans être déclarés. */
const INTERNAL_HOST_RE = /\b(?:[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?\.)+(?:local|lan|internal|intra|intranet|corp|home|localdomain)\b/gi
/** Adresses conservées : bouclage et non spécifiées, sans valeur d'identification. */
const KEPT_ADDRESSES = new Set(['127.0.0.1', '0.0.0.0', '::1', '::'])

/**
 * Remplace les noms et adresses par des jetons neutres et stables dans un même
 * contexte (la même adresse donne toujours le même jeton). Les sous-noms de
 * l'appliance gardent leur libellé (sonarqube.[appliance]) : il dit quel module
 * est en cause sans rien révéler du réseau.
 */
export class Neutralizer {
  private readonly hosts = new Map<string, string>()
  private readonly addrs = new Map<string, string>()
  private readonly fqdn: string | null
  private readonly names: string[]

  constructor(names: ApplianceNames = {}) {
    this.fqdn = cleanName(names.fqdn)
    const domain = this.fqdn ? domainOf(this.fqdn) : null
    const extra = (names.extra ?? []).map(cleanName).filter((n): n is string => !!n && n !== this.fqdn)
    // Plus longs d'abord : le nom de l'appliance avant son domaine.
    this.names = [...new Set([...extra, ...(domain ? [domain] : [])])].sort((a, b) => b.length - a.length)
  }

  private host(name: string): string {
    const key = name.toLowerCase()
    let token = this.hosts.get(key)
    if (!token) {
      token = `[host-${this.hosts.size + 1}]`
      this.hosts.set(key, token)
    }
    return token
  }

  private addr(value: string): string {
    const key = value.toLowerCase()
    if (KEPT_ADDRESSES.has(key)) return value
    let token = this.addrs.get(key)
    if (!token) {
      token = `[addr-${this.addrs.size + 1}]`
      this.addrs.set(key, token)
    }
    return token
  }

  text(input: string): string {
    let out = input.replace(EMAIL_RE, '[email]')
    if (this.fqdn) {
      out = out.replace(new RegExp(`(?<![a-z0-9-])((?:[a-z0-9-]{1,63}\\.)*)${escapeRe(this.fqdn)}(?![a-z0-9-])`, 'gi'),
        (_m, sub: string) => `${sub.toLowerCase()}[appliance]`)
    }
    for (const n of this.names) {
      out = out.replace(new RegExp(`(?<![a-z0-9-])(?:[a-z0-9-]{1,63}\\.)*${escapeRe(n)}(?![a-z0-9-])`, 'gi'), m => this.host(m))
    }
    out = out.replace(INTERNAL_HOST_RE, m => this.host(m))
    out = out.replace(IPV4_RE, m => this.addr(m))
    out = out.replace(IPV6_RE, (m) => {
      // Une heure (10:00:00) n'a que trois groupes et n'est pas retenue ; un groupe sans chiffre
      // hexadécimal significatif non plus.
      return /^[0-9:]+$/.test(m) && !m.includes('::') && m.split(':').length < 5 ? m : this.addr(m)
    })
    return out
  }
}

/** Texte masqué puis neutralisé (masqué avant : aucun secret découpé par un remplacement). */
function clean(text: string, n: Neutralizer, max: number): string {
  return redactText(n.text(redactText(text).text)).text.slice(0, max)
}

/**
 * Contexte prêt à joindre à la tâche : chaque texte masqué et neutralisé, le
 * journal réduit à sa fin, le tout tenant dans MAX_APPLIANCE_CONTEXT_BYTES.
 * null si le contexte n'a pas la forme attendue.
 */
export function boundApplianceContext(raw: unknown, names: ApplianceNames = {}): ApplianceContext | null {
  const parsed = ApplianceContext.safeParse(raw)
  if (!parsed.success) return null
  const n = new Neutralizer(names)
  const c = parsed.data
  const facts = Object.fromEntries(Object.entries(c.facts).slice(0, MAX_FACTS)
    .map(([k, v]) => [k, typeof v === 'string' ? clean(v, n, 300) : v]))
  const head = {
    subject: c.subject,
    title: clean(c.title, n, 200) || c.subject,
    status: clean(c.status, n, 40) || '?',
    code: c.code,
    module: c.module,
    facts,
  }
  const room = Math.min(MAX_LOG_BYTES, MAX_APPLIANCE_CONTEXT_BYTES - Buffer.byteLength(JSON.stringify(head), 'utf8') - 64)
  const log = room > 0 ? tailBytes(clean(c.log, n, 200_000), room) : ''
  const out = { ...head, log: redactText(log).text }
  return Buffer.byteLength(JSON.stringify(out), 'utf8') <= MAX_APPLIANCE_CONTEXT_BYTES ? out : { ...out, log: '' }
}

/** Faits d'un objet JSON rendus lisibles en lignes « clé: valeur », pour le journal joint. */
export function jsonLines(value: unknown, prefix = '', depth = 0, out: string[] = []): string[] {
  if (out.length >= 400 || depth > 4) return out
  if (value === null || typeof value !== 'object') {
    out.push(`${prefix || 'value'}: ${String(value).slice(0, 500)}`)
    return out
  }
  const entries = Array.isArray(value) ? value.slice(0, 100).map((v, i) => [String(i), v] as const) : Object.entries(value).slice(0, 100)
  for (const [k, v] of entries) jsonLines(v, prefix ? `${prefix}.${k}` : k, depth + 1, out)
  return out
}
