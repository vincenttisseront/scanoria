// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Français et anglais : mêmes clés ; chaque code de résultat du helper, chaque
// code d'erreur de l'API et chaque étape publiée a sa traduction.

import { readFileSync, readdirSync, statSync } from 'node:fs'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'
import fr from '../../i18n/locales/fr'
import en from '../../i18n/locales/en'
import { RESULT_CODES } from '#shared/schemas'

type Tree = { [k: string]: string | Tree }

function keys(tree: Tree, prefix = ''): string[] {
  return Object.entries(tree).flatMap(([k, v]) => (typeof v === 'string' ? [`${prefix}${k}`] : keys(v, `${prefix}${k}.`)))
}
function get(tree: Tree, path: string): unknown {
  return path.split('.').reduce<unknown>((node, k) => (node as Tree | undefined)?.[k], tree)
}

const ROOT = fileURLToPath(new URL('../../', import.meta.url))

function sourceFiles(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const path = join(dir, name)
    if (statSync(path).isDirectory()) return sourceFiles(path)
    return /\.(ts|vue)$/.test(name) ? [path] : []
  })
}

describe('traductions', () => {
  it('fr et en ont exactement les mêmes clés', () => {
    expect(keys(en as Tree).sort()).toEqual(keys(fr as Tree).sort())
  })

  it('aucun message n’est vide ni ne contient de syntaxe réservée', () => {
    for (const locale of [fr, en] as Tree[]) {
      for (const k of keys(locale)) {
        const v = get(locale, k) as string
        expect(v.length, k).toBeGreaterThan(0)
        expect(v, k).not.toMatch(/[@|<>]/)
      }
    }
  })

  it('traduit chaque code de résultat du service root', () => {
    for (const code of RESULT_CODES) {
      expect(get(fr as Tree, `codes.${code}`), code).toBeTypeOf('string')
    }
  })

  it('traduit chaque code d’erreur de l’API', () => {
    const http = readFileSync(join(ROOT, 'server/utils/http.ts'), 'utf8')
    const block = http.slice(http.indexOf('export type ApiErrorCode'), http.indexOf('export function apiError'))
    const codes = [...block.matchAll(/'(E_[A-Z_]+)'/g)].map(m => m[1]!)
    expect(codes.length).toBeGreaterThan(10)
    for (const code of codes) expect(get(fr as Tree, `errors.${code}`), code).toBeTypeOf('string')
  })

  it('traduit chaque étape publiée (§ 5.7)', () => {
    for (const step of ['run', 'download', 'verify', 'extract', 'backup', 'stop', 'deploy', 'migrate', 'start', 'health', 'cleanup', 'rollback', 'restore']) {
      expect(get(fr as Tree, `steps.${step}`), step).toBeTypeOf('string')
    }
  })

  it('traduit chaque étape du service root (set_step, op.step)', () => {
    const py = join(ROOT, '../src/rootfs/usr/lib/scanoria/py/scanoria')
    const steps = new Set<string>()
    for (const name of readdirSync(py).filter(n => n.endsWith('.py'))) {
      const src = readFileSync(join(py, name), 'utf8')
      for (const m of src.matchAll(/(?:set_step|op\.step)\("([a-z0-9-]+)"/g)) steps.add(m[1]!)
    }
    expect(steps.size).toBeGreaterThan(10)
    for (const step of steps) {
      expect(get(fr as Tree, `steps.${step}`), step).toBeTypeOf('string')
      expect(get(en as Tree, `steps.${step}`), step).toBeTypeOf('string')
    }
  })

  it('chaque clé utilisée dans le code existe', () => {
    const used = new Set<string>()
    for (const file of [...sourceFiles(join(ROOT, 'app'))]) {
      const src = readFileSync(file, 'utf8')
      for (const m of src.matchAll(/\bte?\(\s*'([a-zA-Z][\w.-]*)'/g)) used.add(m[1]!)
    }
    expect(used.size).toBeGreaterThan(50)
    for (const k of used) expect(get(fr as Tree, k), k).toBeTypeOf('string')
  })

  it('jamais alert() ni confirm() dans la console', () => {
    for (const file of sourceFiles(join(ROOT, 'app'))) {
      const src = readFileSync(file, 'utf8')
      expect(src, file).not.toMatch(/\b(window\.)?(alert|confirm|prompt)\s*\(/)
    }
  })
})
