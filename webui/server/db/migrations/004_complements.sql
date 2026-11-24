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

-- Chantier A : clé d'hôte SSH relevée à l'ajout et confirmée par l'opérateur
-- (transmise au runner), dernière archive téléversée (seul fichier de
-- /var/lib/scanoria/uploads/<upload_id>/ : source.zip, source.tar ou
-- source.tar.gz, 0600 scanoria), dernière interrogation de la forge.
ALTER TABLE projects
    ADD COLUMN ssh_known_hosts text CHECK (ssh_known_hosts IS NULL OR length(ssh_known_hosts) BETWEEN 1 AND 16384),
    ADD COLUMN upload_id uuid,
    ADD COLUMN last_polled_at timestamptz;

-- Chantier F : le rôle PostgreSQL de scanoria-ai (créé hors migration par
-- son unité) ne lit que le jeton IA, jamais les jetons de forge. Le
-- propriétaire (scanoria) contourne la sécurité par ligne : rien ne change
-- pour la console.
ALTER TABLE credentials ENABLE ROW LEVEL SECURITY;
CREATE POLICY credentials_ai_token_read ON credentials FOR SELECT USING (kind = 'ai-token');
