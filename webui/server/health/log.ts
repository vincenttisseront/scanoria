// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// G20 : journal complet d'un module d'analyse, pour le diagnostic. Le worker
// en a déjà retiré le secret de la source du projet à la copie ; on repasse
// ici le masquage commun (server/findings/redact.ts, celui de l'IA) avant tout
// téléchargement ou envoi : aucun motif de secret ne sort. Taille bornée.
// I15 : un extrait (fin du journal) borné à 16 Ko est joint à la tâche IA
// diagnose-scan, scanoria-ai n'ayant pas accès aux fichiers.

import { constants } from 'node:fs'
import { open } from 'node:fs/promises'
import { join } from 'node:path'
import { MAX_REDACT, redact } from '../findings/redact'
import { makeRedactor } from '../scans/redact'

/** Taille maximale lue d'un journal (celle de la copie du worker). */
export const MAX_LOG_DOWNLOAD = 2 * 1024 * 1024
/** Extrait joint à une tâche IA (contrat 13). */
export const MAX_AI_EXCERPT = 16 * 1024

const LOG_PATH_RE = /^[0-9a-f-]{36}\/[a-z0-9][a-z0-9-]{1,40}\.log$/
// Masques de forme (bloc de clé privée sur plusieurs lignes, URL avec identifiants, en-têtes).
const shapes = makeRedactor([])
// Morceaux traités par le masquage commun, sous sa limite (MAX_REDACT).
const CHUNK = Math.min(4000, MAX_REDACT - 100)

/**
 * Masquage d'un journal entier : formes multi-lignes d'abord, puis le masquage
 * commun morceau par morceau (coupé aux fins de ligne, une ligne trop longue
 * est découpée).
 */
export function maskLog(text: string): string {
  const pre = shapes(text)
  const out: string[] = []
  let buf = ''
  const flush = () => {
    if (buf) out.push(redact(buf))
    buf = ''
  }
  for (const line of pre.split(/(?<=\n)/)) {
    if (buf.length + line.length > CHUNK) flush()
    if (line.length > CHUNK) {
      for (let i = 0; i < line.length; i += CHUNK) out.push(redact(line.slice(i, i + CHUNK)))
      continue
    }
    buf += line
  }
  flush()
  return out.join('')
}

export interface ModuleLog {
  text: string
  /** Le journal dépassait la borne : seul le début est rendu. */
  truncated: boolean
}

/** Lit un journal copié par le worker (chemin relatif validé), borné puis masqué ; null s'il n'existe pas. */
export async function readModuleLog(logsDir: string, rel: string | null, opts: { maxBytes?: number, tail?: boolean } = {}): Promise<ModuleLog | null> {
  if (!rel || !LOG_PATH_RE.test(rel)) return null
  const max = opts.maxBytes ?? MAX_LOG_DOWNLOAD
  let fh
  try {
    fh = await open(join(logsDir, rel), constants.O_RDONLY | constants.O_NOFOLLOW)
  }
  catch {
    return null
  }
  try {
    const st = await fh.stat()
    if (!st.isFile()) return null
    const size = Math.min(st.size, max)
    const buf = Buffer.alloc(size)
    const { bytesRead } = await fh.read(buf, 0, size, opts.tail ? st.size - size : 0)
    let text = buf.subarray(0, bytesRead).toString('utf8')
    // Fin de journal : la première ligne, sans doute coupée, est retirée.
    if (opts.tail && st.size > size) text = text.slice(text.indexOf('\n') + 1)
    // La copie du worker est déjà bornée à cette taille : l'atteindre signale une troncature.
    return { text: maskLog(text), truncated: st.size > size || st.size >= MAX_LOG_DOWNLOAD }
  }
  finally {
    await fh.close()
  }
}

/** Fin du journal masquée, en caractères bornés, pour le diagnostic IA (I15). */
export async function logExcerpt(logsDir: string, rel: string | null, maxBytes = MAX_AI_EXCERPT): Promise<string | null> {
  const log = await readModuleLog(logsDir, rel, { maxBytes, tail: true })
  if (!log) return null
  // Le masquage peut allonger le texte : on garde la fin, sous la borne en octets.
  const buf = Buffer.from(log.text, 'utf8')
  if (buf.length <= maxBytes) return log.text
  return buf.subarray(buf.length - maxBytes).toString('utf8').replace(/^\uFFFD+/, '')
}
