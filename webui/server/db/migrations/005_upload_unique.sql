-- SPDX-License-Identifier: AGPL-3.0-or-later
-- Copyright (C) 2026 Vincent Tisseront
--
-- 0.3 : une archive téléversée n'appartient qu'à un seul projet. La console le
-- vérifie déjà avant l'écriture ; l'index ferme la course entre deux requêtes
-- simultanées.
CREATE UNIQUE INDEX projects_upload_id_key ON projects (upload_id) WHERE upload_id IS NOT NULL;
