-- SPDX-License-Identifier: AGPL-3.0-or-later
-- Copyright (C) 2026 Vincent Tisseront
--
-- 0.5, chantier D : sujet de tâche IA « license » pour I18 (explication des
-- licences d'un SBOM). Aucune donnée de code n'est rattachée à ce sujet.
ALTER TABLE ai_tasks DROP CONSTRAINT ai_tasks_subject_type_check;
ALTER TABLE ai_tasks ADD CONSTRAINT ai_tasks_subject_type_check
    CHECK (subject_type IN ('finding', 'scan', 'testbed', 'rule', 'module', 'license'));
