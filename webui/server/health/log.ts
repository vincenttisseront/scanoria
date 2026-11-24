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

/** Délimiteurs où couper une ligne trop longue sans couper un secret (qui n'en contient pas). */
const CUT_RE = /[\s,;"'`{}[\]()<>|]/

/** Position de coupe d'une ligne longue : dernier délimiteur dans les 1000 derniers caractères, sinon coupe nette. */
function cutAt(line: string, from: number): number {
  const end = from + CHUNK
  if (end >= line.length) return line.length
  for (let i = end; i > end - 1000 && i > from; i--) {
    if (CUT_RE.test(line[i - 1]!)) return i
  }
  return end
}

/**
 * Masquage d'un journal entier : formes multi-lignes d'abord, puis le masquage
 * commun morceau par morceau (coupé aux fins de ligne ; une ligne trop longue
 * est coupée sur un délimiteur, pour ne pas partager un secret entre deux
 * morceaux). `aggressive` masque aussi toute chaîne longue et aléatoire sans
 * type connu : imposé pour tout ce qui part vers l'IA (§ 3.5).
 */
export function maskLog(text: string, opts: { aggressive?: boolean } = {}): string {
  const mask = (t: string) => redact(t, { aggressive: opts.aggressive })
  const pre = shapes(text)
  const out: string[] = []
  let buf = ''
  const flush = () => {
    if (buf) out.push(mask(buf))
    buf = ''
  }
  for (const line of pre.split(/(?<=\n)/)) {
    if (buf.length + line.length > CHUNK) flush()
    if (line.length > CHUNK) {
      for (let i = 0; i < line.length;) {
        const j = cutAt(line, i)
        out.push(mask(line.slice(i, j)))
        i = j
      }
      continue
    }
    buf += line
  }
  flush()
  return out.join('')
}

export interface ModuleLog {
  text: string
  /** Le journal dépassait la borne : le début et la fin sont rendus, le milieu est omis. */
  truncated: boolean
}

const OMITTED = '\n[…]\n'

/**
 * Lit un journal copié par le worker (chemin relatif validé), borné puis masqué ;
 * null s'il n'existe pas. Au-delà de la borne : début et fin (l'erreur est
 * souvent à la fin), ou la fin seule avec `tail`.
 */
export async function readModuleLog(logsDir: string, rel: string | null, opts: { maxBytes?: number, tail?: boolean, aggressive?: boolean } = {}): Promise<ModuleLog | null> {
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
    const read = async (pos: number, len: number) => {
      const buf = Buffer.alloc(len)
      const { bytesRead } = await fh.read(buf, 0, len, pos)
      return buf.subarray(0, bytesRead).toString('utf8')
    }
    // La copie du worker est déjà bornée à MAX_LOG_DOWNLOAD : l'atteindre signale une troncature.
    const truncated = st.size > max || st.size >= MAX_LOG_DOWNLOAD
    let text: string
    if (st.size <= max) {
      text = await read(0, st.size)
    }
    else if (opts.tail) {
      // Fin de journal : la première ligne, sans doute coupée, est retirée.
      text = await read(st.size - max, max)
      text = text.slice(text.indexOf('\n') + 1)
    }
    else {
      const half = Math.floor(max / 2)
      const head = await read(0, half)
      const tail = await read(st.size - half, half)
      text = head.slice(0, head.lastIndexOf('\n') + 1) + OMITTED + tail.slice(tail.indexOf('\n') + 1)
    }
    return { text: maskLog(text, { aggressive: opts.aggressive }), truncated }
  }
  finally {
    await fh.close()
  }
}

/** Fin du journal masquée (mode agressif), bornée en octets, pour le diagnostic IA (I15). */
export async function logExcerpt(logsDir: string, rel: string | null, maxBytes = MAX_AI_EXCERPT): Promise<string | null> {
  const log = await readModuleLog(logsDir, rel, { maxBytes, tail: true, aggressive: true })
  if (!log) return null
  // Le masquage peut allonger le texte : on garde la fin, sous la borne en octets.
  const buf = Buffer.from(log.text, 'utf8')
  if (buf.length <= maxBytes) return log.text
  return buf.subarray(buf.length - maxBytes).toString('utf8').replace(/^\uFFFD+/, '')
}
