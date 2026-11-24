// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Archive téléversée d'un projet (zip, tar ou tar.gz) : reçue en flux, taille
// bornée, format reconnu par son en-tête (jamais par le nom fourni), écrite
// comme seul fichier de <uploads>/<upload_id>/ sous le nom source.zip,
// source.tar ou source.tar.gz (convention partagée avec le runner, chantier B).
// Rien n'est extrait ici : le runner extrait dans un conteneur confiné.

import { randomUUID } from 'node:crypto'
import { createWriteStream } from 'node:fs'
import { lstat, mkdir, readdir, rename, rm } from 'node:fs/promises'
import { join } from 'node:path'
import { Transform, type Readable } from 'node:stream'
import { pipeline } from 'node:stream/promises'
import { getConfig } from '../utils/config'

export const ARCHIVE_MAX_BYTES = 512 * 1024 * 1024
export const ARCHIVE_FORMATS = ['zip', 'tar', 'tar.gz'] as const
export type ArchiveFormat = (typeof ARCHIVE_FORMATS)[number]
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/
const SOURCE_RE = /^source\.(zip|tar|tar\.gz)$/

export class ArchiveError extends Error {
  constructor(public readonly code: 'E_TOO_LARGE' | 'E_ARCHIVE_FORMAT' | 'E_UPLOAD') {
    super(code)
  }
}

/** Format d'après les premiers octets : PK\3\4 (zip), 1f 8b (gzip), « ustar » à 257 (tar). */
export function sniffFormat(head: Buffer): ArchiveFormat | null {
  if (head.length >= 4 && head[0] === 0x50 && head[1] === 0x4b && head[2] === 0x03 && head[3] === 0x04) return 'zip'
  if (head.length >= 2 && head[0] === 0x1f && head[1] === 0x8b) return 'tar.gz'
  if (head.length >= 262 && head.subarray(257, 262).toString('latin1') === 'ustar') return 'tar'
  return null
}

export async function receiveArchive(body: Readable, declaredLength: number): Promise<{ upload_id: string, format: ArchiveFormat, size: number }> {
  if (declaredLength > ARCHIVE_MAX_BYTES) throw new ArchiveError('E_TOO_LARGE')
  const id = randomUUID()
  const dir = join(getConfig().uploadsDir, id)
  await mkdir(dir, { recursive: false, mode: 0o700 }).catch(async (err: NodeJS.ErrnoException) => {
    if (err.code !== 'ENOENT') throw err
    await mkdir(getConfig().uploadsDir, { recursive: true, mode: 0o700 })
    await mkdir(dir, { mode: 0o700 })
  })
  const partial = join(dir, '.partial')
  let received = 0
  let head = Buffer.alloc(0)
  const guard = new Transform({
    transform(chunk: Buffer, _enc, callback) {
      received += chunk.length
      if (head.length < 262) head = Buffer.concat([head, chunk.subarray(0, 262 - head.length)])
      if (received > ARCHIVE_MAX_BYTES) callback(new Error('too large'))
      else callback(null, chunk)
    },
  })
  try {
    await pipeline(body, guard, createWriteStream(partial, { flags: 'wx', mode: 0o600 }))
    const format = sniffFormat(head)
    if (!format) throw new ArchiveError('E_ARCHIVE_FORMAT')
    await rename(partial, join(dir, `source.${format}`))
    return { upload_id: id, format, size: received }
  }
  catch (err) {
    await rm(dir, { recursive: true, force: true }).catch(() => {})
    if (err instanceof ArchiveError) throw err
    throw new ArchiveError(received > ARCHIVE_MAX_BYTES ? 'E_TOO_LARGE' : 'E_UPLOAD')
  }
}

/** Vrai si l'upload existe, est un répertoire réel et contient exactement une archive. */
export async function uploadReady(uploadId: string): Promise<boolean> {
  if (!UUID_RE.test(uploadId)) return false
  const dir = join(getConfig().uploadsDir, uploadId)
  try {
    const st = await lstat(dir)
    if (!st.isDirectory()) return false
    const names = await readdir(dir)
    if (names.length !== 1 || !SOURCE_RE.test(names[0]!)) return false
    return (await lstat(join(dir, names[0]!))).isFile()
  }
  catch {
    return false
  }
}

export async function removeUpload(uploadId: string | null): Promise<void> {
  if (!uploadId || !UUID_RE.test(uploadId)) return
  await rm(join(getConfig().uploadsDir, uploadId), { recursive: true, force: true }).catch(() => {})
}
