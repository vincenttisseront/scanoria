-- SPDX-License-Identifier: AGPL-3.0-or-later
-- Copyright (C) 2026 Vincent Tisseront
--
-- 0.8, chantier C (J4) : identifiant immuable du dépôt épinglé sur une
-- liaison OIDC (claim repository_id de GitHub et Forgejo, project_id de
-- GitLab). Rempli à l'enrôlement quand l'API de la forge le donne, sinon au
-- premier jeton accepté ; jamais écrasé automatiquement : un dépôt supprimé
-- puis recréé sous le même nom par un tiers ne passe pas la liaison. Seul un
-- administrateur réinitialise l'épingle (audité).
ALTER TABLE oidc_bindings ADD COLUMN repository_id text
    CHECK (repository_id IS NULL OR repository_id ~ '^[0-9]{1,20}$');
