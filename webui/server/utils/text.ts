// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Petites opérations sur les chaînes, en temps linéaire (sans expression
// régulière ancrée en fin de chaîne, sujette au retour arrière).

/** Retire toutes les occurrences finales du caractère `ch`. */
export function trimEnd(s: string, ch: string): string {
  let end = s.length
  while (end > 0 && s[end - 1] === ch) end--
  return s.slice(0, end)
}

/** Retire toutes les occurrences initiales et finales du caractère `ch`. */
export function trimBoth(s: string, ch: string): string {
  let start = 0
  while (start < s.length && s[start] === ch) start++
  return trimEnd(s.slice(start), ch)
}
