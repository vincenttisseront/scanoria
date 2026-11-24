// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// POST /api/catalog/modules/:id/update (admin) : demande update-module, vers la
// version indiquée ou, par défaut, la dernière de l'index. La version cible est
// contrôlée comme une installation (licence à accepter, appliance, conflits,
// dépendances installées, options, ressources) ; jamais de rétrogradation. À
// version égale, seule une variante devenue compatible (variantPending) est admise.
// Le helper sauvegarde le module avant et revient en arrière si la santé échoue (§ 4.3).

import { defineEventHandler } from 'h3'
import { apiError, readValidated } from '../../../../utils/http'
import { submitHelperAction } from '../../../../utils/helper-actions'
import { installedModuleParam } from '../../../../utils/catalog-actions'
import { compareVersions, findModule } from '../../../../utils/catalog'
import { buildInstallPlan } from '../../../../utils/module-plan'
import { variantPending } from '../../../../utils/catalog-view'
import { moduleUpdateBodySchema } from '#shared/schemas'

export default defineEventHandler(async (event) => {
  const { id, installed, ctx } = await installedModuleParam(event)
  const body = await readValidated(event, moduleUpdateBodySchema)
  const target = findModule(ctx.index, id, body.version)
  if (!target) throw apiError(404, 'E_NOT_FOUND')
  if (compareVersions(target.version, installed.version) <= 0 && !variantPending(installed, target)) throw apiError(409, 'E_NO_UPDATE')
  const plan = buildInstallPlan(
    [{ id, version: target.version, options: installed.options }],
    { ...ctx, installed: ctx.installed.filter(m => m.id !== id), acceptLicenses: body.accept_licenses },
  )
  // Une dépendance absente n'est pas installée par une mise à jour : elle bloque.
  const blockers = [
    ...plan.blockers,
    ...plan.items.filter(i => i.id !== id).map(i => ({ code: 'E_DEPENDENCY' as const, module: id, other: i.id })),
  ]
  if (blockers.length) throw apiError(409, 'E_PLAN', { blockers })
  return submitHelperAction(event, 'update-module', { id, version: target.version }, {
    auditDetails: { from_version: installed.version, licenses_accepted: plan.licenses_to_accept },
  })
})
