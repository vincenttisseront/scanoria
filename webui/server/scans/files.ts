// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Fichiers partagés avec scanoria-runner (ARCHITECTURE § 12.2) :
// - jobs/tmp puis jobs/incoming : tâche écrite en 0600 puis renommée (atomique) ;
// - results/<job>/result.json : lu sans suivre de lien, taille bornée, validé ;
// - runner.json : capacité publiée par le runner.
// Le worker ne fait pas plus confiance au runner que l'inverse : chemins
// relatifs contrôlés, aucun lien suivi, tailles bornées.

import { constants } from 'node:fs'
import { lstat, mkdir, open, readdir, readlink, realpath, rename, rm, unlink, type FileHandle } from 'node:fs/promises'
import { join, relative, resolve, sep } from 'node:path'
import { runnerStateSchema, scanResultSchema, type RunnerState, type ScanJob, type ScanResult } from './contract'

export const MAX_RESULT_BYTES = 4 * 1024 * 1024
export const MAX_LOG_BYTES = 2 * 1024 * 1024

export const jobsTmpDir = (scansDir: string) => join(scansDir, 'jobs', 'tmp')
export const jobsIncomingDir = (scansDir: string) => join(scansDir, 'jobs', 'incoming')
export const resultDir = (scansDir: string, jobId: string) => join(scansDir, 'results', jobId)
export const resultsRoot = (scansDir: string) => join(scansDir, 'results')

/**
 * Ouvre en lecture un fichier situé sous base sans jamais suivre de lien,
 * à aucun niveau : chaque composant intermédiaire doit être un vrai
 * répertoire (lstat), le dernier est ouvert avec O_NOFOLLOW, puis le chemin
 * réel du descripteur obtenu (/proc/self/fd) est revérifié sous base, ce qui
 * ferme la course entre la vérification et l'ouverture.
 * undefined : absent ; 'not-regular' : lien, hors de base ou autre chose qu'un fichier.
 */
export async function openContained(base: string, full: string): Promise<FileHandle | undefined | 'not-regular'> {
  const root = resolve(base)
  const rel = relative(root, resolve(full))
  if (!rel || rel.startsWith('..') || rel.split(sep).includes('..')) return 'not-regular'
  const parts = rel.split(sep)
  let cur = root
  for (const part of parts.slice(0, -1)) {
    cur = join(cur, part)
    try {
      const st = await lstat(cur)
      if (!st.isDirectory()) return 'not-regular'
    }
    catch (err) {
      if ((err as NodeJS.ErrnoException).code === 'ENOENT') return undefined
      throw err
    }
  }
  let fh: FileHandle
  try {
    fh = await open(join(root, rel), constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK)
  }
  catch (err) {
    const code = (err as NodeJS.ErrnoException).code
    if (code === 'ENOENT') return undefined
    if (code === 'ELOOP' || code === 'ENOTDIR') return 'not-regular'
    throw err
  }
  try {
    const real = await readlink(`/proc/self/fd/${fh.fd}`).catch(() => null)
    if (real !== null) {
      const realRoot = await realpath(root)
      if (!real.startsWith(realRoot + sep)) {
        await fh.close()
        return 'not-regular'
      }
    }
    return fh
  }
  catch (err) {
    await fh.close().catch(() => {})
    throw err
  }
}

/** Lit un fichier ordinaire (jamais un lien), au plus max octets ; undefined s'il est absent. */
export async function readRegularFile(path: string, max: number): Promise<Buffer | undefined | 'too-large' | 'not-regular'> {
  let fh
  try {
    fh = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW)
  }
  catch (err) {
    const code = (err as NodeJS.ErrnoException).code
    if (code === 'ENOENT') return undefined
    if (code === 'ELOOP') return 'not-regular'
    throw err
  }
  try {
    const st = await fh.stat()
    if (!st.isFile()) return 'not-regular'
    if (st.size > max) return 'too-large'
    const buf = Buffer.alloc(st.size)
    const { bytesRead } = await fh.read(buf, 0, st.size, 0)
    return buf.subarray(0, bytesRead)
  }
  finally {
    await fh.close()
  }
}

/** Dépose une tâche : écriture 0600 dans tmp/, synchronisation, renommage dans incoming/. */
export async function writeJob(scansDir: string, job: ScanJob): Promise<void> {
  const tmp = join(jobsTmpDir(scansDir), `${job.id}.json`)
  const dest = join(jobsIncomingDir(scansDir), `${job.id}.json`)
  const fh = await open(tmp, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600)
  try {
    await fh.writeFile(JSON.stringify(job))
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

/** Retire une tâche pas encore prise par le runner ; true si elle y était. */
export async function withdrawJob(scansDir: string, jobId: string): Promise<boolean> {
  try {
    await unlink(join(jobsIncomingDir(scansDir), `${jobId}.json`))
    return true
  }
  catch {
    return false
  }
}

/** Tâches en attente dans incoming/ : id et date de dépôt (fichiers ordinaires seulement). */
export async function listIncomingJobs(scansDir: string): Promise<{ id: string, mtimeMs: number }[]> {
  let names: string[]
  try {
    names = await readdir(jobsIncomingDir(scansDir))
  }
  catch {
    return []
  }
  const out: { id: string, mtimeMs: number }[] = []
  for (const name of names) {
    const m = /^([0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})\.json$/.exec(name)
    if (!m) continue
    try {
      const st = await lstat(join(jobsIncomingDir(scansDir), name))
      if (st.isFile()) out.push({ id: m[1]!, mtimeMs: st.mtimeMs })
    }
    catch {
      // retirée entre-temps
    }
  }
  return out
}

/** La tâche attend-elle encore dans incoming/ ? */
export async function jobPending(scansDir: string, jobId: string): Promise<boolean> {
  try {
    await lstat(join(jobsIncomingDir(scansDir), `${jobId}.json`))
    return true
  }
  catch {
    return false
  }
}

export type ResultRead
  = | { kind: 'absent' }
    | { kind: 'invalid', reason: string }
    | { kind: 'ok', result: ScanResult }

/** Comme readRegularFile, mais contenu sous base sans lien à aucun niveau. */
export async function readContainedFile(base: string, full: string, max: number): Promise<Buffer | undefined | 'too-large' | 'not-regular'> {
  const fh = await openContained(base, full)
  if (fh === undefined || fh === 'not-regular') return fh
  try {
    const st = await fh.stat()
    if (!st.isFile()) return 'not-regular'
    if (st.size > max) return 'too-large'
    const buf = Buffer.alloc(st.size)
    const { bytesRead } = await fh.read(buf, 0, st.size, 0)
    return buf.subarray(0, bytesRead)
  }
  finally {
    await fh.close()
  }
}

export async function readResult(scansDir: string, jobId: string): Promise<ResultRead> {
  const raw = await readContainedFile(resultsRoot(scansDir), join(resultDir(scansDir, jobId), 'result.json'), MAX_RESULT_BYTES)
  if (raw === undefined) return { kind: 'absent' }
  if (raw === 'too-large' || raw === 'not-regular') return { kind: 'invalid', reason: raw }
  let doc: unknown
  try {
    doc = JSON.parse(raw.toString('utf8'))
  }
  catch {
    return { kind: 'invalid', reason: 'json' }
  }
  const parsed = scanResultSchema.safeParse(doc)
  if (!parsed.success) return { kind: 'invalid', reason: 'schema' }
  return { kind: 'ok', result: parsed.data }
}

/** Chemin d'un fichier publié par le runner, contenu dans results/<job>/ (sinon null). */
export function resultFile(scansDir: string, jobId: string, rel: string): string | null {
  const base = resolve(resultDir(scansDir, jobId))
  const full = resolve(base, rel)
  return full.startsWith(base + sep) ? full : null
}

/** Capacité du runner ; null s'il est absent, illisible ou muet depuis trop longtemps. */
export async function readRunnerState(path: string, staleS: number, now = new Date()): Promise<RunnerState | null> {
  let raw
  try {
    raw = await readRegularFile(path, 64 * 1024)
  }
  catch {
    return null
  }
  if (!Buffer.isBuffer(raw)) return null
  let doc: unknown
  try {
    doc = JSON.parse(raw.toString('utf8'))
  }
  catch {
    return null
  }
  const parsed = runnerStateSchema.safeParse(doc)
  if (!parsed.success) return null
  const age = now.getTime() - Date.parse(parsed.data.updated_at)
  return age <= staleS * 1000 ? parsed.data : null
}

/**
 * Copie le journal d'un module dans scan-logs/<scan>/<module>.log (0600,
 * tronqué), après masquage (redact) ; chemin relatif ou null.
 */
export async function copyModuleLog(
  scansDir: string, jobId: string, rel: string, logsDir: string, scanId: string, moduleId: string,
  redact: (text: string) => string = t => t,
): Promise<string | null> {
  const src = resultFile(scansDir, jobId, rel)
  if (!src) return null
  const fh = await openContained(resultsRoot(scansDir), src)
  if (fh === undefined || fh === 'not-regular') return null
  let data: Buffer
  try {
    const st = await fh.stat()
    if (!st.isFile()) return null
    const size = Math.min(st.size, MAX_LOG_BYTES)
    data = Buffer.alloc(size)
    const { bytesRead } = await fh.read(data, 0, size, 0)
    data = data.subarray(0, bytesRead)
  }
  finally {
    await fh.close()
  }
  const text = redact(data.toString('utf8'))
  const dir = join(logsDir, scanId)
  await mkdir(dir, { recursive: true, mode: 0o700 })
  const dest = join(dir, `${moduleId}.log`)
  await rm(dest, { force: true })
  const out = await open(dest, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600)
  try {
    await out.writeFile(text)
  }
  finally {
    await out.close()
  }
  return `${scanId}/${moduleId}.log`
}
