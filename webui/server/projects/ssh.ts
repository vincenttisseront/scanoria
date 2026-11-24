// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Clés d'hôte SSH d'un dépôt : relevées à l'ajout (ssh-keyscan, sans shell),
// montrées avec leur empreinte SHA256 pour confirmation, puis gardées dans
// projects.ssh_known_hosts. Le runner n'accepte que ces clés.

import { createHash } from 'node:crypto'
import { execFile } from 'node:child_process'

const KEY_TYPES = /^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp(256|384|521)|sk-ssh-ed25519@openssh\.com|sk-ecdsa-sha2-nistp256@openssh\.com)$/
const B64_RE = /^[A-Za-z0-9+/]+={0,2}$/

export interface HostKey {
  type: string
  fingerprint: string
  line: string
}

export function hostPattern(host: string, port: number): string {
  return port === 22 ? host : `[${host}]:${port}`
}

export function fingerprint(b64: string): string {
  return `SHA256:${createHash('sha256').update(Buffer.from(b64, 'base64')).digest('base64').replace(/=+$/, '')}`
}

/**
 * Valide un contenu known_hosts pour un hôte donné : uniquement des lignes
 * « motif type clé » dont le motif est exactement l'hôte (et le port) du dépôt.
 * Renvoie les clés normalisées, ou null si une ligne est invalide.
 */
export function parseKnownHosts(text: string, host: string, port: number): HostKey[] | null {
  const pattern = hostPattern(host, port)
  const keys: HostKey[] = []
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim()
    if (!line || line.startsWith('#')) continue
    const parts = line.split(/\s+/)
    if (parts.length < 3 || parts.length > 4) return null
    const [hostField, type, key] = parts as [string, string, string]
    if (hostField.toLowerCase() !== pattern || !KEY_TYPES.test(type) || !B64_RE.test(key) || key.length > 8192) return null
    keys.push({ type, fingerprint: fingerprint(key), line: `${pattern} ${type} ${key}` })
  }
  if (!keys.length || keys.length > 10) return null
  return keys
}

export type Keyscan = (host: string, port: number) => Promise<string>

const realKeyscan: Keyscan = (host, port) => new Promise((resolve, reject) => {
  execFile('ssh-keyscan', ['-T', '5', '-p', String(port), '-t', 'ed25519,ecdsa,rsa', host],
    { timeout: 15_000, maxBuffer: 64 * 1024, env: { PATH: '/usr/bin:/bin' } },
    (err, stdout) => {
      if (err && !stdout) reject(new Error('E_SSH_KEYSCAN'))
      else resolve(stdout)
    })
})

let keyscan: Keyscan = realKeyscan

/** Tests seulement : remplace ssh-keyscan. Sans argument, rétablit l'outil. */
export function setKeyscan(fn?: Keyscan): void {
  keyscan = fn ?? realKeyscan
}

/** Relève les clés d'hôte ; null si l'hôte ne répond pas ou ne donne aucune clé valide. */
export async function scanHostKeys(host: string, port: number): Promise<HostKey[] | null> {
  let out: string
  try {
    out = await keyscan(host, port)
  }
  catch {
    return null
  }
  const lines = out.split(/\r?\n/).filter(l => l.trim() && !l.startsWith('#'))
  return parseKnownHosts(lines.join('\n'), host, port)
}
