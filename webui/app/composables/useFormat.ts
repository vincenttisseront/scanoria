// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Formats d'affichage selon la langue de la console.

export function useFormat() {
  const { locale, t } = useI18n()

  function date(iso: string | null | undefined): string {
    if (!iso) return t('common.never')
    const d = new Date(iso)
    if (Number.isNaN(d.getTime())) return iso
    return new Intl.DateTimeFormat(locale.value === 'en' ? 'en-GB' : 'fr-FR', {
      dateStyle: 'medium',
      timeStyle: 'short',
    }).format(d)
  }

  function gb(mb: number | null | undefined): string {
    if (typeof mb !== 'number') return '?'
    return (mb / 1024).toLocaleString(locale.value === 'en' ? 'en-GB' : 'fr-FR', { maximumFractionDigits: 1 })
  }

  /** Empreinte hexadécimale lisible : groupes de deux caractères. */
  function fingerprint(hex: string | null | undefined): string {
    return hex ? (hex.match(/.{2}/g) ?? []).join(':').toUpperCase() : '—'
  }

  return { date, gb, fingerprint }
}
