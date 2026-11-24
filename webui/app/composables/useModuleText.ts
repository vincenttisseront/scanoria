// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Libellés du catalogue : types, statuts, restrictions de licence, motifs des
// décisions automatiques du plan (principe 8 : l'écran dit ce qui a été fait
// et pourquoi), contrôles de ressources, étapes des opérations.

import type { InstalledModule, ModuleOperation, PlanIssue, PlanItem, ResourceCheck } from './useCatalog'

export function useModuleText() {
  const { t, te } = useI18n()
  const fmt = useFormat()

  const typeLabel = (type: string) => (te(`catalog.types.${type}`) ? t(`catalog.types.${type}`) : type)
  const statusLabel = (status: string) => (te(`catalog.statuses.${status}`) ? t(`catalog.statuses.${status}`) : status)
  const restrictionLabel = (r: string) => (te(`catalog.restrictions.${r}`) ? t(`catalog.restrictions.${r}`) : r)

  function issueText(issue: PlanIssue): string {
    const key = `catalog.issues.${issue.code}`
    const other = issue.code === 'E_RESOURCES' && issue.other ? t(`catalog.checks.kinds.${issue.other}`) : issue.other ?? ''
    if (issue.code === 'E_OPTIONS' && issue.options?.length) {
      return t('catalog.issues.E_OPTIONS', { module: issue.module ?? '', other: issue.options.map(o => o.key).join(', ') })
    }
    return te(key) ? t(key, { module: issue.module ?? '', other }) : issue.code
  }

  function reasonText(item: Pick<PlanItem, 'reason' | 'required_by'>): string {
    if (item.reason === 'requested') return t('catalog.plan.requested')
    return t(`catalog.plan.${item.reason}`, { by: item.required_by.join(', ') })
  }

  function amount(kind: ResourceCheck['kind'], v: number | null): string {
    if (v === null) return '?'
    return kind === 'cpu' ? String(v) : `${fmt.gb(v)} Go`
  }

  function checkText(c: ResourceCheck): string {
    return t(`catalog.checks.${c.kind}`, { needed: amount(c.kind, c.needed), available: amount(c.kind, c.available) })
  }

  function stepLabel(step: string | null | undefined): string {
    if (!step) return ''
    return te(`steps.${step}`) ? t(`steps.${step}`) : step
  }

  function operationLabel(op: ModuleOperation): string {
    const kind = te(`catalog.operations.kinds.${op.kind}`) ? t(`catalog.operations.kinds.${op.kind}`) : op.kind
    return op.module ? `${kind} : ${op.module}` : kind
  }

  function lastError(m: InstalledModule | null | undefined): string {
    const e = m?.last_error
    if (!e) return ''
    if (typeof e === 'string') return e
    const code = e.code && te(`codes.${e.code}`) ? t(`codes.${e.code}`) : e.code ?? ''
    return [code, e.message].filter(Boolean).join(' — ')
  }

  return { typeLabel, statusLabel, restrictionLabel, issueText, reasonText, checkText, stepLabel, operationLabel, lastError }
}
