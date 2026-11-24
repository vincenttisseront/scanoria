-- SPDX-License-Identifier: AGPL-3.0-or-later
-- Copyright (C) 2026 Vincent Tisseront
--
-- 0.4 : demande « reset-service-admin » (chantier B). Réinitialise le compte
-- administrateur d'un module « service » ; le mot de passe ne passe jamais
-- par la base (dépôt unique en mémoire vive, lu une fois par la console).
ALTER TABLE helper_requests DROP CONSTRAINT helper_requests_type_check;
ALTER TABLE helper_requests ADD CONSTRAINT helper_requests_type_check CHECK (type IN (
    'set-hostname', 'set-admin-networks', 'issue-certificate',
    'import-certificate', 'check-update', 'apply-update',
    'rollback-update', 'set-update-policy', 'run-selftest',
    'refresh-catalog', 'install-modules', 'uninstall-module',
    'set-module-state', 'update-module', 'check-dns',
    'set-ai-endpoint', 'backup-module', 'restore-module',
    'reset-service-admin'));
