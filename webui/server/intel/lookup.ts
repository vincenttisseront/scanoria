// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// H3 : EPSS et KEV d'un résultat, lus dans vuln_intel. Les alias se résolvent
// par findings.vuln_ids : un résultat GHSA ou OSV qui cite son CVE en alias
// prend l'EPSS et le KEV de ce CVE (le plus haut si plusieurs CVE).

/**
 * Jointure latérale qui expose intel.epss, intel.epss_percentile, intel.kev
 * (jamais nul) et intel.kev_added pour la ligne `alias` de findings. Chaque
 * identifiant est cherché par la clé primaire (aucun parcours de la table).
 */
export function intelJoin(alias = 'f'): string {
  return `LEFT JOIN LATERAL (
    SELECT max(vi.epss) AS epss, max(vi.epss_percentile) AS epss_percentile,
           COALESCE(bool_or(vi.kev), false) AS kev, to_char(min(vi.kev_added), 'YYYY-MM-DD') AS kev_added
      FROM vuln_intel vi
     WHERE vi.vuln_id = ANY (ARRAY(SELECT upper(v) FROM unnest(${alias}.vuln_ids) AS v))
  ) intel ON true`
}

/** Colonnes publiées dans l'API des résultats. */
export const INTEL_COLUMNS = `intel.epss::float8 AS epss, intel.epss_percentile::float8 AS epss_percentile,
  intel.kev AS kev, intel.kev_added AS kev_added`
