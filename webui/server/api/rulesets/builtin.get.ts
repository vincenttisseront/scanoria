// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// GET /api/rulesets/builtin : règles maison livrées avec l'appliance
// (slug réservé « scanoria-base », AGPL), en lecture seule. Elles sont
// ajoutées par le module Opengrep (option builtin_rules) ; pour les modifier,
// la page propose de les copier dans un nouveau jeu de règles.

import { readFile } from 'node:fs/promises'
import { defineEventHandler } from 'h3'
import { requireRole } from '../../utils/http'
import { sha256Hex } from '../../rulesets/store'

const FILE = '/usr/lib/scanoria/scan-tools/sast/rules/opengrep/scanoria-base.yaml'

export default defineEventHandler(async (event) => {
  requireRole(event, 'viewer')
  let content: string | null
  try {
    content = await readFile(process.env.SCANORIA_BUILTIN_RULES || FILE, 'utf8')
  }
  catch {
    content = null
  }
  return {
    items: content === null
      ? []
      : [{ slug: 'scanoria-base', engine: 'opengrep', license: 'AGPL-3.0-or-later', sha256: sha256Hex(content), content,
          rules: (content.match(/^[ \t]*-[ \t]+id:[ \t]*\S/gm) ?? []).length }],
  }
})
