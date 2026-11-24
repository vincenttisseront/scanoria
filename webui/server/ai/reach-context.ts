// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// I11 : forme du contexte joint à une tâche assess-reachability
// (ai_tasks.context) et correspondance entre un composant (écosystème, nom)
// et les modules importés relevés par reach-index. Sans dépendance vers la
// file : partagé par la tâche (service scanoria-ai) et par la console.

import { z } from 'zod'

/** Taille maximale du contexte (octets UTF-8, comme I15). */
export const MAX_REACH_CONTEXT_BYTES = 16_384
export const MAX_REACH_LOCATIONS = 40
export const MAX_EXCERPT_CHARS = 300

export const ReachLocationSchema = z.strictObject({
  kind: z.enum(['import', 'call']),
  path: z.string().min(1).max(512),
  line: z.number().int().min(1).max(10_000_000),
  symbol: z.string().max(200),
  module: z.string().min(1).max(300),
  excerpt: z.string().max(MAX_EXCERPT_CHARS),
})
export type ReachLocationCtx = z.infer<typeof ReachLocationSchema>

export const ReachContext = z.strictObject({
  index: z.strictObject({
    languages: z.array(z.enum(['javascript', 'typescript', 'python', 'go', 'java'])).max(10),
    files: z.number().int().min(0).max(10_000_000),
    truncated: z.boolean(),
  }),
  symbols: z.array(z.string().min(1).max(200)).max(20),
  locations: z.array(ReachLocationSchema).max(MAX_REACH_LOCATIONS),
})
export type ReachContext = z.infer<typeof ReachContext>

/**
 * Écosystèmes où le nom du composant est le nom importé (npm, Go) : là
 * seulement, « aucun import relevé » permet de dire « appel improbable ».
 * Ailleurs (PyPI, Maven), la correspondance est une heuristique.
 */
export function exactImportNames(ecosystem: string | null | undefined): boolean {
  return ['npm', 'go', 'golang'].includes((ecosystem ?? '').toLowerCase())
}

/** Langages dont reach-index relève les imports pour un écosystème (purl type ou nom OSV). */
export function ecosystemLanguages(ecosystem: string | null | undefined): string[] {
  switch ((ecosystem ?? '').toLowerCase()) {
    case 'npm': return ['javascript', 'typescript']
    case 'pypi': return ['python']
    case 'go': case 'golang': return ['go']
    case 'maven': return ['java']
    default: return []
  }
}

/** Nom d'import Python de quelques distributions dont le nom diffère (le reste : nom normalisé). */
const PYPI_IMPORTS: Record<string, string[]> = {
  'pyyaml': ['yaml'],
  'pillow': ['PIL'],
  'beautifulsoup4': ['bs4'],
  'scikit-learn': ['sklearn'],
  'python-dateutil': ['dateutil'],
  'protobuf': ['google.protobuf'],
  'pyjwt': ['jwt'],
  'opencv-python': ['cv2'],
  'psycopg2-binary': ['psycopg2'],
  'pycryptodome': ['Crypto'],
}

const pyNorm = (s: string) => s.toLowerCase().replace(/[-_.]+/g, '_')

/** Le module importé appartient-il au composant ? Heuristique par écosystème, sans exécution. */
export function moduleMatches(ecosystem: string | null | undefined, name: string, module: string): boolean {
  if (!name || !module) return false
  switch ((ecosystem ?? '').toLowerCase()) {
    case 'npm':
      return module === name || module.startsWith(`${name}/`)
    case 'pypi': {
      const known = PYPI_IMPORTS[name.toLowerCase()]
      if (known?.some(k => module === k || module.startsWith(`${k}.`))) return true
      // Chaque préfixe du module (google, google.auth…) comparé au nom normalisé
      // (google-auth → google_auth, ruamel.yaml → ruamel_yaml, python-jose → jose).
      const wanted = new Set([pyNorm(name), pyNorm(name).replace(/^python_/, '')])
      const parts = module.split('.')
      return parts.some((_, i) => wanted.has(pyNorm(parts.slice(0, i + 1).join('.'))))
    }
    case 'go': case 'golang':
      return module === name || module.startsWith(`${name}/`)
    case 'maven': {
      // groupe:artefact (ou groupe/artefact) : les paquets Java commencent par le groupe, ou par
      // son parent (com.fasterxml.jackson.core:jackson-databind → com.fasterxml.jackson.databind).
      const group = name.split(/[:/]/)[0]!
      const segs = group.split('.')
      const prefixes = [group, ...(segs.length >= 3 ? [segs.slice(0, -1).join('.')] : [])].filter(g => g.length > 2)
      return prefixes.some(g => module === g || module.startsWith(`${g}.`))
    }
    default:
      return module === name
  }
}

/** Contexte borné à MAX_REACH_CONTEXT_BYTES en retirant les derniers emplacements. */
export function boundContext(ctx: ReachContext): ReachContext {
  const out = { ...ctx, locations: [...ctx.locations] }
  while (out.locations.length && Buffer.byteLength(JSON.stringify(out), 'utf8') > MAX_REACH_CONTEXT_BYTES) {
    out.locations.pop()
    out.index = { ...out.index, truncated: true }
  }
  return out
}
