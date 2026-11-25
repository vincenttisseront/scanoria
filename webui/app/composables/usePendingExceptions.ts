// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Compteur « Exceptions à approuver » de la navigation (F5, 0.7). Partagé
// entre le menu et la page d'approbation, qui le rafraîchit après chaque
// décision ; relu au changement de page au plus toutes les 30 s. Toujours 0
// pour un rôle autre qu'administrateur (le serveur le garantit aussi).

export function usePendingExceptions() {
  const count = useState<number>('pending-exceptions', () => 0)
  const loadedAt = useState<number>('pending-exceptions-at', () => 0)
  const { api } = useApi()
  const session = useSession()

  async function refresh() {
    loadedAt.value = Date.now()
    if (!session.can('admin')) {
      count.value = 0
      return
    }
    try {
      count.value = (await api<{ count: number }>('/api/exceptions/pending-count')).count
    }
    catch {
      // compteur non affiché : sans conséquence
    }
  }
  async function refreshIfStale(maxAgeMs = 30_000) {
    if (Date.now() - loadedAt.value > maxAgeMs) await refresh()
  }
  return { count, refresh, refreshIfStale }
}
