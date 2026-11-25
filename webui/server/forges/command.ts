// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// J15 côté forge : commande de commentaire de PR
//   /scanoria accept <résultat> --until <AAAA-MM-JJ> --reason "…"
// <résultat> : identifiant du résultat (UUID) ou sa forme courte de 8 à 12
// caractères hexadécimaux, telle que l'affiche le commentaire de synthèse.
// Le texte vient d'un commentaire quelconque : il est analysé strictement, et
// une commande malformée reçoit une aide, jamais une exception.
// Aucune dépendance : le module est aussi chargé seul par tests/b34-forges.sh.

export const MAX_COMMAND_CHARS = 4000

export type ScanoriaCommand
  = | { kind: 'accept', finding: string, until: string, reason: string }
    | { kind: 'help', error: CommandError | null }

export type CommandError = 'E_CMD_SYNTAX' | 'E_CMD_FINDING' | 'E_CMD_UNTIL' | 'E_CMD_REASON' | 'E_CMD_UNKNOWN' | 'E_CMD_TOO_LONG'

const FINDING_RE = /^(?:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|[0-9a-f]{8,12})$/i

/** Date réelle AAAA-MM-JJ (le 31 novembre est refusé). */
export function isRealDay(value: string): boolean {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(value)) return false
  const d = new Date(`${value}T00:00:00Z`)
  return !Number.isNaN(d.getTime()) && d.toISOString().slice(0, 10) === value
}

/** Découpe une ligne en mots ; guillemets droits, typographiques et « » acceptés. */
export function tokenize(line: string): string[] | null {
  const out: string[] = []
  const closers: Record<string, string> = { '"': '"', '“': '”', '«': '»', '\'': '\'' }
  let i = 0
  while (i < line.length) {
    const c = line[i]!
    if (/\s/.test(c)) {
      i++
      continue
    }
    if (Object.hasOwn(closers, c)) {
      const end = line.indexOf(closers[c]!, i + 1)
      if (end < 0) return null
      out.push(line.slice(i + 1, end).trim())
      i = end + 1
      continue
    }
    let j = i
    while (j < line.length && !/\s/.test(line[j]!)) {
      // « --option="texte entre guillemets" » : la valeur citée reste d'un seul tenant.
      if (line[j - 1] === '=' && Object.hasOwn(closers, line[j]!)) {
        const end = line.indexOf(closers[line[j]!]!, j + 1)
        if (end < 0) return null
        out.push(`${line.slice(i, j)}${line.slice(j + 1, end).trim()}`)
        j = end + 1
        i = -1
        break
      }
      j++
    }
    if (i >= 0) out.push(line.slice(i, j))
    i = j
  }
  return out
}

/**
 * Cherche une commande /scanoria en début de ligne. null : le commentaire n'en
 * contient pas (rien à répondre). Une seule commande par commentaire : la première.
 */
export function parseScanoriaCommand(body: string): ScanoriaCommand | null {
  if (typeof body !== 'string') return null
  const lines = body.replace(/\r\n?/g, '\n').split('\n')
  // Une commande citée ou dans un bloc de code (exemple du commentaire de Scanoria) n'en est pas une.
  let fenced = false
  const line = lines.find((l) => {
    if (/^\s{0,3}(```|~~~)/.test(l)) {
      fenced = !fenced
      return false
    }
    return !fenced && /^\s{0,3}\/scanoria(\s|$)/i.test(l)
  })
  if (line === undefined) return null
  if (body.length > MAX_COMMAND_CHARS) return { kind: 'help', error: 'E_CMD_TOO_LONG' }
  // eslint-disable-next-line no-control-regex
  if (/[\u0000-\u0008\u000B-\u001F\u007F]/.test(line)) return { kind: 'help', error: 'E_CMD_SYNTAX' }
  const words = tokenize(line.trim())
  if (!words) return { kind: 'help', error: 'E_CMD_SYNTAX' }
  const verb = (words[1] ?? '').toLowerCase()
  if (verb === '' || verb === 'help' || verb === 'aide') return { kind: 'help', error: null }
  if (verb !== 'accept' && verb !== 'accepter') return { kind: 'help', error: 'E_CMD_UNKNOWN' }
  const finding = words[2]
  if (!finding || finding.startsWith('--') || !FINDING_RE.test(finding)) return { kind: 'help', error: 'E_CMD_FINDING' }
  let until: string | null = null
  let reason: string | null = null
  for (let k = 3; k < words.length; k++) {
    const w = words[k]!
    const [flag, inline] = w.includes('=') ? [w.slice(0, w.indexOf('=')), w.slice(w.indexOf('=') + 1)] : [w, null]
    if (flag !== '--until' && flag !== '--reason' && flag !== '--jusqu-au' && flag !== '--motif') return { kind: 'help', error: 'E_CMD_SYNTAX' }
    const value = inline ?? words[++k]
    if (value === undefined) return { kind: 'help', error: 'E_CMD_SYNTAX' }
    if (flag === '--until' || flag === '--jusqu-au') {
      if (until !== null) return { kind: 'help', error: 'E_CMD_SYNTAX' }
      until = value
    }
    else {
      if (reason !== null) return { kind: 'help', error: 'E_CMD_SYNTAX' }
      reason = value
    }
  }
  if (!until || !isRealDay(until)) return { kind: 'help', error: 'E_CMD_UNTIL' }
  const r = (reason ?? '').replace(/\s+/g, ' ').trim()
  if (r.length < 3 || r.length > 2000) return { kind: 'help', error: 'E_CMD_REASON' }
  return { kind: 'accept', finding: finding.toLowerCase(), until, reason: r }
}
