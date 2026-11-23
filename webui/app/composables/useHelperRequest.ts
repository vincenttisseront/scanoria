// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Dépôt d'une demande au service root puis suivi jusqu'au résultat :
// indicateur d'attente, étape courante traduite, message final traduit
// à partir du code de résultat. Pendant une mise à jour la console redémarre :
// les erreurs réseau sont alors attendues et le suivi continue.

const FINAL = new Set(['ok', 'error', 'rejected', 'lost'])

export interface HelperRequestStatus {
  id: string
  type: string
  status: 'pending' | 'running' | 'ok' | 'error' | 'rejected' | 'lost'
  code: string | null
  message: string | null
  output: Record<string, unknown> | null
  step: string | null
}

export function useHelperRequest() {
  const { api, errorMessage } = useApi()
  const { t, te } = useI18n()
  const toast = useToast()

  const running = ref(false)
  const status = ref<HelperRequestStatus['status'] | null>(null)
  const step = ref<string | null>(null)
  const restarting = ref(false)
  const result = ref<HelperRequestStatus | null>(null)

  const label = computed(() => {
    if (restarting.value) return t('request.restarting')
    if (step.value) return t('request.stepLabel', { step: te(`steps.${step.value}`) ? t(`steps.${step.value}`) : step.value })
    if (status.value) return t(`request.${status.value}`)
    return ''
  })

  function codeMessage(code: string | null | undefined): string {
    return code && te(`codes.${code}`) ? t(`codes.${code}`) : t('errors.generic')
  }

  async function run(url: string, body: Record<string, unknown>, opts: { timeoutMs?: number, pollMs?: number } = {}) {
    running.value = true
    status.value = 'pending'
    step.value = null
    restarting.value = false
    result.value = null
    try {
      const submitted = await api<{ request_id: string }>(url, { method: 'POST', body })
      toast.add({ title: t('request.submitted'), color: 'info', icon: 'i-lucide-send' })
      const deadline = Date.now() + (opts.timeoutMs ?? 40 * 60_000)
      const pollMs = opts.pollMs ?? 2000
      while (Date.now() < deadline) {
        await new Promise(resolve => setTimeout(resolve, pollMs))
        try {
          const r = await api<HelperRequestStatus>(`/api/requests/${submitted.request_id}`)
          restarting.value = false
          status.value = r.status
          step.value = r.step
          if (FINAL.has(r.status)) {
            result.value = r
            break
          }
        }
        catch (err) {
          const code = errorCode(err)
          if (code === 'E_UNAUTHENTICATED' || code === 'E_FORBIDDEN') throw err
          restarting.value = true
        }
      }
      const final = result.value
      if (!final) {
        toast.add({ title: t('request.lost'), color: 'warning', icon: 'i-lucide-clock-alert' })
      }
      else if (final.status === 'ok') {
        toast.add({ title: codeMessage(final.code), color: 'success', icon: 'i-lucide-circle-check' })
      }
      else {
        toast.add({
          title: t(`request.${final.status}`),
          description: final.status === 'lost' ? undefined : codeMessage(final.code),
          color: 'error',
          icon: 'i-lucide-circle-x',
        })
      }
      return final
    }
    catch (err) {
      toast.add({ title: errorMessage(err), color: 'error', icon: 'i-lucide-circle-x' })
      return null
    }
    finally {
      running.value = false
      restarting.value = false
      step.value = null
    }
  }

  return { run, running, status, step, restarting, result, label, codeMessage }
}
