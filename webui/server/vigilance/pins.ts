// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// G6, version d'un module figée par projet (contrat 24 de la 0.6).
// - Figer : réservé aux administrateurs, motif obligatoire, tracé dans l'audit ;
//   seule la version installée se fige (son empreinte vient de l'index vérifié).
// - Plan : l'empreinte figée remplace celle du catalogue (applyPins, appelée
//   depuis resolveProfile). Une image figée absente de la machine rend le
//   module « missing », classe infra (G12).
// - Helper : la console publie les versions figées dans pins.json ; une mise à
//   jour du module garde alors l'image de l'ancienne version (vigilance.py).
// - Avertissements : version retirée du catalogue, ou vulnérable (F19).

import { constants } from 'node:fs'
import { mkdir, open, rename } from 'node:fs/promises'
import { dirname } from 'node:path'
import type { Queryable } from '../utils/db'
import { writeAudit, type AuditActor } from '../utils/audit'
import type { CatalogIndex, InstalledModule } from '../utils/catalog'
import type { PlannedModule } from '../scans/plan'
import type { RetainedEntry } from './state'

export interface ModulePin {
  module_id: string
  version: string
  image_digest: string
  reason: string
  pinned_by: number | null
  pinned_at: string
}

/** Image retenue par le helper (vue de la console). */
export type RetainedImage = Pick<RetainedEntry, 'module' | 'version' | 'image_digest' | 'kind'>

const DIGEST_RE = /^sha256:[0-9a-f]{64}$/

/** Remplace image et version des modules figés (contrat 24). Une empreinte égale ne change rien. */
export function applyPins(modules: PlannedModule[], pins: Map<string, Pick<ModulePin, 'version' | 'image_digest'>>): PlannedModule[] {
  return modules.map((m) => {
    const pin = pins.get(m.id)
    if (!pin || !DIGEST_RE.test(pin.image_digest) || pin.image_digest === m.image_digest) return m
    const repo = m.image?.split('@')[0] ?? null
    return { ...m, version: pin.version, image_digest: pin.image_digest, image: repo ? `${repo}@${pin.image_digest}` : null, alternate: 'pin' as const }
  })
}

/**
 * Version figée ou candidate présente sur la machine. Sans état lisible
 * (undefined, null), le runner tranche lui-même (image absente = infra, G12).
 */
export function retainedAvailable(m: Pick<PlannedModule, 'id' | 'version' | 'image_digest'>, retained: RetainedImage[] | null | undefined): boolean {
  if (!retained) return true
  return retained.some(r => r.module === m.id && r.version === m.version && r.image_digest === m.image_digest)
}

export async function loadPins(db: Queryable, projectId: string): Promise<Map<string, ModulePin>> {
  const r = await db.query<ModulePin & { pinned_at: Date | string }>(
    `SELECT module_id, version, image_digest, reason, pinned_by::int AS pinned_by, pinned_at
       FROM project_module_pins WHERE project_id = $1 ORDER BY module_id`, [projectId])
  return new Map(r.rows.map(p => [p.module_id, { ...p, pinned_at: new Date(p.pinned_at).toISOString() }]))
}

export class PinError extends Error {
  constructor(readonly code: 'E_PIN_MODULE' | 'E_PIN_IMAGE' | 'E_PIN_PROJECT') {
    super(code)
  }
}

/**
 * Fige la version installée d'un module pour un projet. L'empreinte vient de
 * l'index vérifié (même version), jamais de la demande.
 */
export interface PinInput {
  projectId: string
  moduleId: string
  reason: string
  actor: AuditActor
  installed: InstalledModule[]
  index: CatalogIndex | null
}

export async function pinModule(db: Queryable, input: PinInput): Promise<ModulePin> {
  const cur = input.installed.find(m => m.id === input.moduleId)
  if (!cur || cur.type !== 'scanner') throw new PinError('E_PIN_MODULE')
  const entry = input.index?.modules.find(m => m.id === cur.id && m.version === cur.version)
  const digest = entry?.image?.split('@')[1]
  if (!digest || !DIGEST_RE.test(digest)) throw new PinError('E_PIN_IMAGE')
  const p = await db.query('SELECT 1 FROM projects WHERE id = $1', [input.projectId])
  if (!p.rowCount) throw new PinError('E_PIN_PROJECT')
  const r = await db.query<ModulePin & { pinned_at: Date }>(
    `INSERT INTO project_module_pins (project_id, module_id, version, image_digest, reason, pinned_by)
     VALUES ($1, $2, $3, $4, $5, $6)
     ON CONFLICT (project_id, module_id) DO UPDATE
       SET version = EXCLUDED.version, image_digest = EXCLUDED.image_digest, reason = EXCLUDED.reason,
           pinned_by = EXCLUDED.pinned_by, pinned_at = now()
     RETURNING module_id, version, image_digest, reason, pinned_by::int AS pinned_by, pinned_at`,
    [input.projectId, cur.id, cur.version, digest, input.reason, input.actor.userId ?? null])
  await writeAudit(db, {
    actor: input.actor, action: 'project.module-pin', outcome: 'success', targetType: 'project', targetId: input.projectId,
    details: { module: cur.id, version: cur.version, image_digest: digest, reason: input.reason },
  })
  const row = r.rows[0]!
  return { ...row, pinned_at: new Date(row.pinned_at).toISOString() }
}

export async function unpinModule(db: Queryable, input: { projectId: string, moduleId: string, actor: AuditActor }): Promise<boolean> {
  const r = await db.query<{ version: string }>(
    'DELETE FROM project_module_pins WHERE project_id = $1 AND module_id = $2 RETURNING version', [input.projectId, input.moduleId])
  if (!r.rows[0]) return false
  await writeAudit(db, {
    actor: input.actor, action: 'project.module-unpin', outcome: 'success', targetType: 'project', targetId: input.projectId,
    details: { module: input.moduleId, version: r.rows[0].version },
  })
  return true
}

/** Versions figées par au moins un projet, sans doublon (lues par le helper). */
export async function pinsDocument(db: Queryable): Promise<{ version: 1, pins: { module: string, version: string, image_digest: string }[] }> {
  const r = await db.query<{ module: string, version: string, image_digest: string }>(
    `SELECT DISTINCT module_id AS module, version, image_digest FROM project_module_pins ORDER BY 1, 2, 3 LIMIT 5000`)
  return { version: 1, pins: r.rows }
}

/** Publie pins.json (0640, écriture atomique, sans suivre de lien). Renvoie true s'il a changé. */
export async function publishPinsFile(db: Queryable, path: string, previous?: string): Promise<string> {
  const body = `${JSON.stringify(await pinsDocument(db))}\n`
  if (body === previous) return body
  await mkdir(dirname(path), { recursive: true, mode: 0o700 })
  const tmp = `${path}.${process.pid}.tmp`
  const fh = await open(tmp, constants.O_WRONLY | constants.O_CREAT | constants.O_TRUNC | constants.O_NOFOLLOW, 0o640)
  try {
    await fh.writeFile(body)
    await fh.sync()
  }
  finally {
    await fh.close()
  }
  await rename(tmp, path)
  return body
}

export type PinWarning = 'retired' | 'vulnerable' | 'missing'

/** Avertissements d'une version figée : retirée du catalogue, vulnérable (F19), absente de la machine. */
export function pinWarnings(pin: Pick<ModulePin, 'module_id' | 'version' | 'image_digest'>, ctx: {
  index: CatalogIndex | null
  installed: InstalledModule[]
  retained: RetainedImage[] | null
  vulnerable: Set<string>
}): PinWarning[] {
  const out: PinWarning[] = []
  if (ctx.index && !ctx.index.modules.some(m => m.id === pin.module_id && m.version === pin.version)) out.push('retired')
  if (ctx.vulnerable.has(pin.module_id)) out.push('vulnerable')
  const cur = ctx.installed.find(m => m.id === pin.module_id)
  if (!cur || (cur.version !== pin.version && !retainedAvailable({ id: pin.module_id, version: pin.version, image_digest: pin.image_digest }, ctx.retained))) out.push('missing')
  return out
}
