-- SPDX-License-Identifier: AGPL-3.0-or-later
-- Copyright (C) 2026 Vincent Tisseront
--
-- 0.7, chantier D (J1) : Forgejo et GitLab par compte de service à jeton de
-- portée réduite (aucun manifeste d'application chez eux), et suspension d'un
-- projet dont le dépôt est archivé sur la forge, distincte d'un archivage fait
-- dans la console.

ALTER TABLE forge_apps DROP CONSTRAINT forge_apps_kind_check;
ALTER TABLE forge_apps ADD CONSTRAINT forge_apps_kind
    CHECK (kind IN ('github-app', 'forgejo-oauth', 'gitlab-oauth', 'forgejo-token', 'gitlab-token'));

ALTER TABLE projects
    ADD COLUMN suspended_at timestamptz,
    ADD COLUMN suspended_reason text CHECK (suspended_reason IN ('forge-archived')),
    ADD CONSTRAINT projects_suspension CHECK ((suspended_at IS NULL) = (suspended_reason IS NULL));

CREATE INDEX projects_active ON projects (id) WHERE suspended_at IS NULL;
