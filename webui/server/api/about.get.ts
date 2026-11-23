// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// GET /api/about (public) : version, licence et lien vers le code source de la
// version installée (AGPL-3.0-or-later, article 13).

import { defineEventHandler } from 'h3'
import { getConfig } from '../utils/config'
import { getRunningVersion, getSourceRepo, sourceUrlFor } from '../utils/appliance'

export default defineEventHandler(async () => {
  const cfg = getConfig()
  const version = await getRunningVersion(cfg.versionFile)
  const repo = await getSourceRepo(cfg.updateSourceFile)
  return {
    product: 'Scanoria',
    version,
    license: 'AGPL-3.0-or-later',
    copyright: 'Copyright (C) 2026 Vincent Tisseront',
    license_url: 'https://www.gnu.org/licenses/agpl-3.0.html',
    source_url: sourceUrlFor(repo, version),
    repository_url: repo ? `https://github.com/${repo}` : null,
  }
})
