// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// I16 : sujets de l'appliance qu'un diagnostic IA peut expliquer (alertes,
// selftest, mises à jour, modules en échec). Administrateurs seulement ; vide
// sans connecteur, la page restant alors identique.

export function useApplianceDiagnosis() {
  const { api } = useApi()
  const session = useSession()
  const subjects = ref<string[]>([])
  const enabled = ref(false)

  async function refresh(): Promise<void> {
    if (!session.can('admin')) return
    try {
      const r = await api<{ enabled: boolean, subjects: string[] }>('/api/ai/appliance/subjects')
      enabled.value = r.enabled
      subjects.value = r.subjects
    }
    catch {
      enabled.value = false
      subjects.value = []
    }
  }

  onMounted(() => void refresh())
  const has = (subject: string) => enabled.value && subjects.value.includes(subject)
  const alerts = computed(() => subjects.value.filter(s => s.startsWith('alert:')))
  return { subjects, enabled, alerts, has, refresh }
}
