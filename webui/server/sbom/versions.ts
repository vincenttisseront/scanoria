// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// F3 : comparaison de versions pour les intervalles de la recherche
// transverse. Une seule règle, commune aux écosystèmes dont les versions sont
// ordonnées par segments (npm, crates.io, Go, PyPI, Maven, RubyGems, NuGet,
// Packagist, Hex, Pub) : segments numériques comparés comme des nombres,
// préversions (alpha, beta, rc, dev, pre, snapshot…) avant la version finale,
// métadonnées de construction (+…) ignorées, « v » initial ignoré. Pour un
// autre écosystème (deb, rpm, apk…), seule l'égalité est sûre : un intervalle
// n'y retient que les bornes elles-mêmes.

export const ORDERED_ECOSYSTEMS = new Set(['npm', 'cargo', 'golang', 'pypi', 'maven', 'gem', 'nuget', 'composer', 'hex', 'pub', 'swift', 'cocoapods'])

const PRE_TAGS: Record<string, number> = { dev: -6, snapshot: -5, alpha: -4, a: -4, beta: -3, b: -3, pre: -2, preview: -2, rc: -1, c: -1, cr: -1 }
const POST_TAGS: Record<string, number> = { post: 1, final: 0, ga: 0, release: 0, sp: 1 }

type Token = number | string

function tokens(v: string): Token[] {
  const s = v.trim().replace(/^v(?=\d)/i, '').split('+')[0]!.toLowerCase()
  const out: Token[] = []
  for (const m of s.matchAll(/\d+|[a-z]+/g)) out.push(/^\d/.test(m[0]) ? Number(m[0]) : m[0])
  return out.slice(0, 32)
}

/** Poids d'un segment alphabétique : préversion < 0 < postversion ; inconnu = préversion faible. */
function weight(t: string): number {
  return PRE_TAGS[t] ?? POST_TAGS[t] ?? -7
}

/** -1, 0 ou 1. */
export function compareVersions(a: string, b: string): number {
  const x = tokens(a)
  const y = tokens(b)
  for (let i = 0; i < Math.max(x.length, y.length); i++) {
    const p = x[i]
    const q = y[i]
    if (p === q) continue
    // Segment absent : une version plus courte vaut « .0 », sauf face à une préversion (1.0 > 1.0-rc1).
    if (p === undefined || q === undefined) {
      const other = (p ?? q)!
      const sign = p === undefined ? 1 : -1
      if (other === 0 || (typeof other === 'string' && weight(other) === 0)) continue
      // other est dans la version la plus longue : nombre > rien, préversion < rien.
      const longerIsGreater = typeof other === 'number' ? true : weight(other) >= 0
      return longerIsGreater ? -sign : sign
    }
    if (typeof p === 'number' && typeof q === 'number') return p < q ? -1 : 1
    if (typeof p === 'number') return weight(q as string) < 0 ? 1 : -1
    if (typeof q === 'number') return weight(p) < 0 ? -1 : 1
    const wp = weight(p)
    const wq = weight(q)
    if (wp !== wq) return wp < wq ? -1 : 1
    return p < q ? -1 : 1
  }
  return 0
}

/** La version est-elle dans [from, to] (bornes facultatives, incluses) ? */
export function inRange(ecosystem: string, version: string | null, from?: string, to?: string): boolean {
  if (!from && !to) return true
  if (!version) return false
  if (!ORDERED_ECOSYSTEMS.has(ecosystem.toLowerCase())) return version === from || version === to
  if (from && compareVersions(version, from) < 0) return false
  if (to && compareVersions(version, to) > 0) return false
  return true
}
