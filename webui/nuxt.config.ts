// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Console Scanoria : Nuxt 4 + Nuxt UI, application monopage servie par Nitro,
// API REST sous /api. En production le serveur écoute sur 127.0.0.1:3000
// (NITRO_HOST / NITRO_PORT), nginx devant (docs/ARCHITECTURE.md § 3.6).

import { readFileSync } from 'node:fs'

const version = readFileSync(new URL('./VERSION', import.meta.url), 'utf8').trim()
// Dépôt d'origine connu à la construction (CI GitHub) : repli du lien « code source »
// quand /usr/share/scanoria/update-source.json est absent. Jamais écrit en dur.
const repo = process.env.GITHUB_REPOSITORY ?? ''
const sourceRepo = /^[A-Za-z0-9-]{1,39}\/[A-Za-z0-9._-]{1,100}$/.test(repo) ? repo : ''

export default defineNuxtConfig({
  modules: ['@nuxt/eslint', '@nuxt/ui', '@nuxtjs/i18n'],

  ssr: false,

  devtools: { enabled: false },

  app: {
    head: {
      title: 'Scanoria',
      meta: [
        { name: 'robots', content: 'noindex, nofollow' },
        { name: 'referrer', content: 'no-referrer' },
      ],
    },
  },

  css: ['~/assets/css/main.css'],

  ui: {
    fonts: false,
  },

  runtimeConfig: {
    buildVersion: version,
    buildSourceRepo: sourceRepo,
  },

  compatibilityDate: '2026-11-01',

  nitro: {
    serverAssets: [{ baseName: 'migrations', dir: './db/migrations' }],
    routeRules: {
      '/**': {
        headers: {
          'x-frame-options': 'DENY',
          'x-content-type-options': 'nosniff',
          'referrer-policy': 'no-referrer',
          'permissions-policy': 'camera=(), microphone=(), geolocation=()',
        },
      },
    },
  },

  typescript: {
    // Tests de la console (environnement Nuxt) : types de l'application (auto-imports, ~).
    tsConfig: {
      include: ['../tests/app/**/*.ts'],
    },
    nodeTsConfig: {
      include: [
        '../tests/unit/**/*.ts', '../tests/integration/**/*.ts', '../tests/e2e/**/*.ts', '../tests/helpers/**/*.ts',
        '../vitest.config.ts', '../vitest.e2e.config.ts', '../migrate.d.mts',
      ],
      compilerOptions: {
        paths: {
          '#shared': ['../shared'],
          '#shared/*': ['../shared/*'],
        },
      },
    },
  },

  eslint: {
    config: {
      stylistic: true,
    },
  },

  i18n: {
    strategy: 'no_prefix',
    defaultLocale: 'fr',
    locales: [
      { code: 'fr', language: 'fr-FR', name: 'Français', file: 'fr.ts' },
      { code: 'en', language: 'en-US', name: 'English', file: 'en.ts' },
    ],
    detectBrowserLanguage: {
      useCookie: true,
      cookieKey: 'scanoria_locale',
      redirectOn: 'root',
      fallbackLocale: 'fr',
    },
  },

  // Icônes servies par la console elle-même (appliance hors ligne possible) :
  // jamais d'appel à l'API Iconify publique.
  icon: {
    localApiEndpoint: '/_nuxt_icon',
    fallbackToApi: false,
    clientBundle: { scan: true },
  },
})
