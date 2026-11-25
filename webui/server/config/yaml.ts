// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Lecture d'un YAML hostile (J8 : .scanoria.yml, import de configuration) :
// taille bornée, un seul document, schéma « core » (aucun type propre à un
// langage), clés en double refusées, aucune ancre, aucun alias, aucune
// étiquette explicite. Rend une valeur JSON simple ou la liste des problèmes,
// jamais une exception. La validation du contenu se fait ensuite par zod.

import { isMap, isScalar, isSeq, parseAllDocuments, visit, type Document } from 'yaml'

export interface ConfigIssue { path: string, message: string }

export type SafeYaml = { ok: true, value: unknown } | { ok: false, issues: ConfigIssue[] }

/** Ancre, alias ou étiquette explicite (« !!python/object », « !tag ») dans le document. */
function forbiddenNode(doc: Document.Parsed): 'alias' | 'tag' | null {
  let found: 'alias' | 'tag' | null = null
  visit(doc, {
    Alias() {
      found = 'alias'
      return visit.BREAK
    },
    Node(_key, node) {
      if ((isScalar(node) || isMap(node) || isSeq(node)) && node.anchor) found = 'alias'
      else if ((isScalar(node) || isMap(node) || isSeq(node)) && node.tag) found = 'tag'
      return found ? visit.BREAK : undefined
    },
  })
  return found
}

const fail = (message: string): SafeYaml => ({ ok: false, issues: [{ path: '', message }] })

export function parseSafeYaml(text: string, maxBytes: number): SafeYaml {
  if (Buffer.byteLength(text, 'utf8') > maxBytes) return fail('file too large')
  if (text.includes('\0')) return fail('binary content')
  // Octets non UTF-8, décodés en U+FFFD par la lecture : le fichier est refusé, jamais deviné.
  if (text.includes('\uFFFD')) return fail('invalid UTF-8')
  let docs
  try {
    docs = parseAllDocuments(text, { schema: 'core', uniqueKeys: true, merge: false, strict: true, prettyErrors: false })
  }
  catch {
    return fail('unreadable YAML')
  }
  if (!Array.isArray(docs)) return fail('unreadable YAML')
  if (docs.length !== 1) return fail(docs.length ? 'several YAML documents' : 'empty file')
  const doc = docs[0]!
  if (doc.errors.length) return { ok: false, issues: doc.errors.slice(0, 5).map(e => ({ path: '', message: e.code })) }
  const forbidden = forbiddenNode(doc)
  if (forbidden === 'alias') return fail('anchors and aliases are not allowed')
  if (forbidden === 'tag') return fail('tags are not allowed')
  try {
    return { ok: true, value: doc.toJS({ maxAliasCount: 0 }) }
  }
  catch {
    return fail('anchors and aliases are not allowed')
  }
}
