-- SPDX-License-Identifier: AGPL-3.0-or-later
-- Copyright (C) 2026 Vincent Tisseront
--
-- Correctif de 009 : ON DELETE SET NULL sur scans.sbom_source contredisait
-- scans_recorrelate_source (une re-corrélation exige sa source). Une
-- re-corrélation n'a pas de sens sans son SBOM : elle disparaît avec lui.
ALTER TABLE scans DROP CONSTRAINT scans_sbom_source_fkey;
ALTER TABLE scans ADD CONSTRAINT scans_sbom_source_fkey
    FOREIGN KEY (sbom_source) REFERENCES scans (id) ON DELETE CASCADE;
