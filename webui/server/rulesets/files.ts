// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Contenus des jeux de règles déposés pour le runner (G4, contrat 34) :
// jobs/rulesets/<sha256>, 0600, adressés par leur empreinte. Une tâche ou une
// demande validate-ruleset ne porte que l'empreinte (limites de taille des
// tâches et demandes) ; le runner relit le fichier sans faire confiance à la
// console (propriétaire, lien unique, empreinte). Ménage par tmpfiles (30 j) :
// un contenu réutilisé est simplement « touché ».

import { constants } from 'node:fs'
import { open, rename, unlink, utimes } from 'node:fs/promises'
import { createHash, randomUUID } from 'node:crypto'
import { join } from 'node:path'

export const rulesetsDir = (scansDir: string) => join(scansDir, 'jobs', 'rulesets')
export const consoleScansDir = (env: NodeJS.ProcessEnv = process.env) => env.SCANORIA_SCANS_DIR || '/var/lib/scanoria/scans'

const SHA_RE = /^[0-9a-f]{64}$/

/** Écrit (ou rafraîchit) le contenu ; refuse une empreinte qui ne correspond pas. */
export async function writeRulesetContent(scansDir: string, sha256: string, content: string): Promise<void> {
  if (!SHA_RE.test(sha256)) throw new Error('invalid sha256')
  const data = Buffer.from(content, 'utf8')
  if (createHash('sha256').update(data).digest('hex') !== sha256) throw new Error('content does not match its sha256')
  const dest = join(rulesetsDir(scansDir), sha256)
  const now = new Date()
  try {
    await utimes(dest, now, now)
    return
  }
  catch {
    // absent : on l'écrit
  }
  const tmp = join(scansDir, 'jobs', 'tmp', `ruleset-${randomUUID()}`)
  const fh = await open(tmp, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600)
  try {
    await fh.writeFile(data)
    await fh.sync()
  }
  catch (err) {
    await fh.close().catch(() => {})
    await unlink(tmp).catch(() => {})
    throw err
  }
  await fh.close()
  try {
    await rename(tmp, dest)
  }
  catch (err) {
    await unlink(tmp).catch(() => {})
    throw err
  }
}

/**
 * Dépose les contenus des jeux de règles d'un plan (relus en base par slug et
 * version, empreinte revérifiée). Rend les jeux introuvables ou altérés : la
 * tâche est alors refusée (classe input), jamais lancée sans ses règles.
 */
export async function stageRulesets(
  db: { query: <R = unknown>(sql: string, params?: unknown[]) => Promise<{ rows: R[] }> },
  scansDir: string,
  modules: { rulesets?: { slug: string, version: number, sha256: string }[] }[],
): Promise<string[]> {
  const bad: string[] = []
  const seen = new Set<string>()
  for (const r of modules.flatMap(m => m.rulesets ?? [])) {
    if (seen.has(r.sha256)) continue
    seen.add(r.sha256)
    const q = await db.query<{ content: string }>(
      `SELECT v.content FROM ruleset_versions v JOIN rulesets s ON s.id = v.ruleset_id
        WHERE s.slug = $1 AND v.version = $2 AND v.sha256 = $3`, [r.slug, r.version, r.sha256])
    const content = q.rows[0]?.content
    if (content === undefined || createHash('sha256').update(content, 'utf8').digest('hex') !== r.sha256) {
      bad.push(`${r.slug}@${r.version}`)
      continue
    }
    await writeRulesetContent(scansDir, r.sha256, content)
  }
  return bad
}
