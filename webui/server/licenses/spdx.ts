// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// F8 : analyse et évaluation des expressions de licence SPDX (annexe D de la
// spécification SPDX 2.3), sans dépendance :
//   expr   := and ( OR and )*
//   and    := with ( AND with )*
//   with   := atom ( WITH exception )?
//   atom   := identifiant [+] | LicenseRef-… | DocumentRef-…:LicenseRef-… | ( expr )
// Opérateurs insensibles à la casse ; AND lie plus fort que OR. Entrée bornée
// (longueur, nombre de jetons, profondeur) : une expression hostile tirée d'un
// SBOM ne peut ni boucler ni épuiser la pile. Évaluation : OR = au moins une
// option acceptable (la meilleure), AND = toutes (la pire), WITH = licence de
// base (l'exception ne fait qu'ajouter une permission).

export type LicenseDecision = 'allowed' | 'review' | 'denied'

export type SpdxNode
  = | { type: 'license', id: string, orLater: boolean }
    | { type: 'with', license: { type: 'license', id: string, orLater: boolean }, exception: string }
    | { type: 'and' | 'or', items: SpdxNode[] }

export const MAX_EXPRESSION = 1024
const MAX_TOKENS = 256
const MAX_DEPTH = 32

const ID_RE = /^(?:DocumentRef-[A-Za-z0-9.-]+:)?[A-Za-z0-9][A-Za-z0-9.-]*\+?$/

export class SpdxParseError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'SpdxParseError'
  }
}

function tokenize(expr: string): string[] {
  if (expr.length > MAX_EXPRESSION) throw new SpdxParseError('expression too long')
  const tokens: string[] = []
  const re = /\s*(\(|\)|[^\s()]+)/y
  let pos = 0
  while (pos < expr.length) {
    re.lastIndex = pos
    const m = re.exec(expr)
    if (!m) {
      if (/^\s*$/.test(expr.slice(pos))) break
      throw new SpdxParseError('unexpected character')
    }
    tokens.push(m[1]!)
    if (tokens.length > MAX_TOKENS) throw new SpdxParseError('too many tokens')
    pos = re.lastIndex
  }
  return tokens
}

const isOp = (t: string | undefined, op: string) => t !== undefined && t.toUpperCase() === op

/** Analyse une expression SPDX ; lève SpdxParseError si elle est mal formée. */
export function parseSpdx(expr: string): SpdxNode {
  const tokens = tokenize(expr)
  if (tokens.length === 0) throw new SpdxParseError('empty expression')
  let i = 0

  const license = (): { type: 'license', id: string, orLater: boolean } => {
    const t = tokens[i]
    if (t === undefined || t === '(' || t === ')' || ['AND', 'OR', 'WITH'].includes(t.toUpperCase()) || !ID_RE.test(t)) {
      throw new SpdxParseError('license identifier expected')
    }
    i++
    const orLater = t.endsWith('+')
    return { type: 'license', id: orLater ? t.slice(0, -1) : t, orLater }
  }

  const atom = (depth: number): SpdxNode => {
    if (tokens[i] === '(') {
      if (depth >= MAX_DEPTH) throw new SpdxParseError('expression too deep')
      i++
      const inner = or(depth + 1)
      if (tokens[i] !== ')') throw new SpdxParseError('closing parenthesis expected')
      i++
      return inner
    }
    const lic = license()
    if (isOp(tokens[i], 'WITH')) {
      i++
      const ex = tokens[i]
      if (ex === undefined || ex === '(' || ex === ')' || !/^[A-Za-z0-9][A-Za-z0-9.-]*$/.test(ex)) throw new SpdxParseError('exception identifier expected')
      i++
      return { type: 'with', license: lic, exception: ex }
    }
    return lic
  }

  const and = (depth: number): SpdxNode => {
    const items = [atom(depth)]
    while (isOp(tokens[i], 'AND')) {
      i++
      items.push(atom(depth))
    }
    return items.length === 1 ? items[0]! : { type: 'and', items }
  }

  const or = (depth: number): SpdxNode => {
    const items = [and(depth)]
    while (isOp(tokens[i], 'OR')) {
      i++
      items.push(and(depth))
    }
    return items.length === 1 ? items[0]! : { type: 'or', items }
  }

  const node = or(0)
  if (i !== tokens.length) throw new SpdxParseError('unexpected token')
  return node
}

const RANK: Record<LicenseDecision, number> = { denied: 0, review: 1, allowed: 2 }
const best = (a: LicenseDecision, b: LicenseDecision) => (RANK[a] >= RANK[b] ? a : b)
const worst = (a: LicenseDecision, b: LicenseDecision) => (RANK[a] <= RANK[b] ? a : b)

/** Identifiants simples présents dans l'expression (licences de base, sans exception). */
export function licenseIds(node: SpdxNode): string[] {
  switch (node.type) {
    case 'license': return [node.id]
    case 'with': return [node.license.id]
    default: return [...new Set(node.items.flatMap(licenseIds))]
  }
}

/**
 * Décision d'une expression : decide(id, orLater) donne la décision d'une
 * licence simple. OR prend la meilleure option, AND la pire, WITH la base.
 */
export function evaluateSpdx(node: SpdxNode, decide: (id: string, orLater: boolean) => LicenseDecision): LicenseDecision {
  switch (node.type) {
    case 'license': return decide(node.id, node.orLater)
    case 'with': return decide(node.license.id, node.license.orLater)
    case 'or': return node.items.map(n => evaluateSpdx(n, decide)).reduce(best)
    case 'and': return node.items.map(n => evaluateSpdx(n, decide)).reduce(worst)
  }
}
