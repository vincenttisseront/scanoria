// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// POST /api/vigilance/self-sbom (admin) : relevé immédiat des SBOM et des
// vulnérabilités de l'appliance (F19), sans attendre le minuteur quotidien.

import { defineEventHandler } from 'h3'
import { submitHelperAction } from '../../utils/helper-actions'

export default defineEventHandler(event => submitHelperAction(event, 'self-sbom', {}))
