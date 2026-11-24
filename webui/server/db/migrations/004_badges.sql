-- SPDX-License-Identifier: AGPL-3.0-or-later
-- Copyright (C) 2026 Vincent Tisseront
--
-- 0.3 (chantier E) : badge SVG du verdict, désactivé par défaut et activable
-- par projet (aucune notion de projet public en 0.3).

ALTER TABLE projects ADD COLUMN badge_enabled boolean NOT NULL DEFAULT false;
