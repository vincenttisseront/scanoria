// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Services Node de l'appliance hors de Nitro (scanoria-worker, scanoria-ai) :
// chaque entrée présente est regroupée par esbuild en un seul fichier ESM
// (pg et zod inclus), écrit dans .output/services/<nom>.mjs. build.sh copie
// .output tel quel : le service est livré dans le lot, à côté de la console.
// Lancé par « npm run build » après « nuxt build ».

import { existsSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { build } from 'esbuild'

const root = fileURLToPath(new URL('..', import.meta.url))
const ENTRIES = { worker: 'worker/main.ts', ai: 'ai/main.ts' }

let built = 0
for (const [name, entry] of Object.entries(ENTRIES)) {
  if (!existsSync(`${root}${entry}`)) continue
  await build({
    entryPoints: [`${root}${entry}`],
    outfile: `${root}.output/services/${name}.mjs`,
    bundle: true,
    platform: 'node',
    format: 'esm',
    target: 'node22',
    // pg charge pg-native seulement s'il est demandé : jamais sur l'appliance.
    external: ['pg-native'],
    alias: { '#shared': `${root}shared` },
    // Dépendances CommonJS (pg) dans un module ESM.
    banner: { js: 'import { createRequire as __scanoriaCreateRequire } from \'node:module\'; const require = __scanoriaCreateRequire(import.meta.url);' },
    legalComments: 'inline',
    logLevel: 'warning',
  })
  console.log(`[bundle-services] .output/services/${name}.mjs`)
  built++
}
if (!built) console.log('[bundle-services] no service entry')
