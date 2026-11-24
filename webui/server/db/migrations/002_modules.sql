-- SPDX-License-Identifier: AGPL-3.0-or-later
-- Copyright (C) 2026 Vincent Tisseront
--
-- 0.2 : nouveaux types de demandes au helper (moteur de modules et DNS).
-- Aucun état de module en base : la console lit l'état publié par le helper.

ALTER TABLE helper_requests DROP CONSTRAINT helper_requests_type_check;
ALTER TABLE helper_requests ADD CONSTRAINT helper_requests_type_check CHECK (type IN (
    'set-hostname', 'set-admin-networks', 'issue-certificate',
    'import-certificate', 'check-update', 'apply-update',
    'rollback-update', 'set-update-policy', 'run-selftest',
    'refresh-catalog', 'install-modules', 'uninstall-module',
    'set-module-state', 'update-module', 'check-dns'));
