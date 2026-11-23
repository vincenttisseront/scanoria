// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront

import withNuxt from './.nuxt/eslint.config.mjs'

export default withNuxt(
  {
    ignores: ['.output/**', '.nuxt/**', 'node_modules/**', 'coverage/**'],
  },
  {
    rules: {
      'no-alert': 'error',
      'no-eval': 'error',
      'vue/no-v-html': 'error',
    },
  },
)
