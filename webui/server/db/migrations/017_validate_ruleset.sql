-- SPDX-License-Identifier: AGPL-3.0-or-later
-- Copyright (C) 2026 Vincent Tisseront
--
-- 0.7, chantier A (G4) : demande « validate-ruleset », validation d'un jeu de
-- règles par son moteur, dans le conteneur confiné d'une analyse.

ALTER TABLE helper_requests DROP CONSTRAINT helper_requests_type_check;
ALTER TABLE helper_requests ADD CONSTRAINT helper_requests_type_check CHECK (type IN (
    'set-hostname', 'set-admin-networks', 'issue-certificate',
    'import-certificate', 'check-update', 'apply-update',
    'rollback-update', 'set-update-policy', 'run-selftest',
    'refresh-catalog', 'install-modules', 'uninstall-module',
    'set-module-state', 'update-module', 'check-dns',
    'set-ai-endpoint', 'backup-module', 'restore-module',
    'reset-service-admin', 'refresh-feeds', 'package-dates',
    'export-bundle', 'import-bundle', 'set-mirror', 'trust-key',
    'self-sbom', 'run-canaries', 'start-trial', 'prefetch-images',
    'validate-ruleset'));
