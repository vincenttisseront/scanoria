-- SPDX-License-Identifier: AGPL-3.0-or-later
-- Copyright (C) 2026 Vincent Tisseront
--
-- 0.3 : compléments du socle demandés par les chantiers.

-- Chantier E : badge SVG du verdict, désactivé par défaut et activable par
-- projet (aucune notion de projet public en 0.3).
ALTER TABLE projects ADD COLUMN badge_enabled boolean NOT NULL DEFAULT false;

-- Chantier D : F7 trace l'auteur et la date du suivi d'un secret, distincts
-- du tri ; extrait de code masqué à l'ingestion (jamais de secret), affiché
-- dans le détail et utilisé par l'IA (I2) après la purge des sorties.
ALTER TABLE findings
    ADD COLUMN secret_state_by bigint REFERENCES users (id) ON DELETE SET NULL,
    ADD COLUMN secret_state_at timestamptz,
    ADD COLUMN snippet text CHECK (snippet IS NULL OR length(snippet) <= 2000);
