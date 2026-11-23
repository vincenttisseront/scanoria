// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Informations sur l'appliance lues sur disque : version, dépôt source,
// état publié par scanoria-state (/run/scanoria/state.json, § 5.7).

import { readFile } from 'node:fs/promises'
import { REPO_RE, VERSION_RE } from '#shared/schemas'

export interface BuildInfo {
  version: string
  sourceRepo: string
}

let buildInfo: BuildInfo = { version: '', sourceRepo: '' }

export function setBuildInfo(info: Partial<BuildInfo>): void {
  buildInfo = {
    version: VERSION_RE.test(info.version ?? '') ? info.version! : '',
    sourceRepo: REPO_RE.test(info.sourceRepo ?? '') ? info.sourceRepo! : '',
  }
}

export function getBuildInfo(): BuildInfo {
  return buildInfo
}

async function readSmallFile(path: string, max = 64 * 1024): Promise<string | null> {
  try {
    const buf = await readFile(path)
    return buf.length <= max ? buf.toString('utf8') : null
  }
  catch {
    return null
  }
}

/** Version du code en cours d'exécution (VERSION embarqué à la construction, sinon fichier). */
export async function getRunningVersion(versionFile: string): Promise<string> {
  if (buildInfo.version) return buildInfo.version
  const raw = (await readSmallFile(versionFile))?.trim() ?? ''
  return VERSION_RE.test(raw) ? raw : '0.0.0'
}

/** Dépôt GitHub d'origine : update-source.json (généré à la construction), sinon valeur embarquée. */
export async function getSourceRepo(updateSourceFile: string): Promise<string | null> {
  const raw = await readSmallFile(updateSourceFile)
  if (raw) {
    try {
      const repo = (JSON.parse(raw) as { repo?: unknown }).repo
      if (typeof repo === 'string' && REPO_RE.test(repo)) return repo
    }
    catch {
      // fichier illisible : valeur embarquée
    }
  }
  return buildInfo.sourceRepo || null
}

export function sourceUrlFor(repo: string | null, version: string): string | null {
  if (!repo || !REPO_RE.test(repo) || !VERSION_RE.test(version)) return null
  return `https://github.com/${repo}/tree/v${version}`
}

/** L'état est jugé indisponible au-delà de 3 minutes (§ 5.7). */
export const STATE_MAX_AGE_MS = 3 * 60_000

export interface PublishedState {
  available: boolean
  reason?: 'missing' | 'invalid' | 'stale'
  age_seconds?: number
  state: Record<string, unknown> | null
}

export async function readPublishedState(stateFile: string, now = Date.now()): Promise<PublishedState> {
  const raw = await readSmallFile(stateFile, 512 * 1024)
  if (raw === null) return { available: false, reason: 'missing', state: null }
  let parsed: unknown
  try {
    parsed = JSON.parse(raw)
  }
  catch {
    return { available: false, reason: 'invalid', state: null }
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    return { available: false, reason: 'invalid', state: null }
  }
  const state = parsed as Record<string, unknown>
  const generated = typeof state.generated_at === 'string' ? Date.parse(state.generated_at) : Number.NaN
  if (state.version !== 1 || Number.isNaN(generated)) return { available: false, reason: 'invalid', state: null }
  const age = Math.round((now - generated) / 1000)
  if (now - generated > STATE_MAX_AGE_MS) return { available: false, reason: 'stale', age_seconds: age, state }
  return { available: true, age_seconds: age, state }
}

/** Sous-objet typé de l'état, ou null s'il manque. */
export function stateSection<T>(state: Record<string, unknown> | null, key: string): T | null {
  const v = state?.[key]
  return v && typeof v === 'object' ? (v as T) : null
}
