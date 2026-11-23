// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Deux projets vitest, un seul rapport de couverture (coverage/lcov.info) :
// - « server » : tests unitaires et d'intégration du serveur (vrai PostgreSQL 16 :
//   DATABASE_URL, base d'administration ; chaque fichier crée sa base jetable) ;
// - « app » : pages, composants et composables de la console, montés dans
//   l'environnement Nuxt (@nuxt/test-utils, happy-dom), API simulée.

import { fileURLToPath } from 'node:url'
import { defineVitestProject } from '@nuxt/test-utils/config'
import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    coverage: {
      provider: 'v8',
      include: ['app/**/*.{ts,vue}', 'server/**/*.ts', 'shared/**/*.ts'],
      exclude: ['**/*.config.ts', '**/*.d.ts'],
      reporter: ['lcov', 'text'],
      reportsDirectory: 'coverage',
    },
    projects: [
      {
        resolve: {
          alias: {
            '#shared': fileURLToPath(new URL('./shared', import.meta.url)),
          },
        },
        test: {
          name: 'server',
          include: ['tests/unit/**/*.test.ts', 'tests/integration/**/*.test.ts'],
          environment: 'node',
          testTimeout: 30_000,
          hookTimeout: 60_000,
          fileParallelism: false,
        },
      },
      await defineVitestProject({
        test: {
          name: 'app',
          include: ['tests/app/**/*.test.ts'],
          environment: 'nuxt',
          environmentOptions: {
            nuxt: {
              domEnvironment: 'happy-dom',
            },
          },
          testTimeout: 30_000,
          hookTimeout: 60_000,
        },
      }),
    ],
  },
})
