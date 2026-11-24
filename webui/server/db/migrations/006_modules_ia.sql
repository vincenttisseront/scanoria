-- SPDX-License-Identifier: AGPL-3.0-or-later
-- Copyright (C) 2026 Vincent Tisseront
--
-- 0.4 : modules « service », consommation réelle (F14), santé des analyses
-- (G20) et nouvelles tâches IA (I3, I5, I14, I15, I17, I24).

-- Demandes au helper : sauvegarde et restauration d'un module (base et
-- volumes), préalables à toute mise à jour d'un module « service ».
ALTER TABLE helper_requests DROP CONSTRAINT helper_requests_type_check;
ALTER TABLE helper_requests ADD CONSTRAINT helper_requests_type_check CHECK (type IN (
    'set-hostname', 'set-admin-networks', 'issue-certificate',
    'import-certificate', 'check-update', 'apply-update',
    'rollback-update', 'set-update-policy', 'run-selftest',
    'refresh-catalog', 'install-modules', 'uninstall-module',
    'set-module-state', 'update-module', 'check-dns',
    'set-ai-endpoint', 'backup-module', 'restore-module'));

-- G20 et F14 : mesures relevées par le runner pour chaque module d'une analyse
-- (contrat scan-result : peak_memory_mb, cpu_ms), absentes si non mesurées.
ALTER TABLE scan_modules
    ADD COLUMN peak_memory_mb integer CHECK (peak_memory_mb IS NULL OR peak_memory_mb >= 0),
    ADD COLUMN cpu_ms bigint CHECK (cpu_ms IS NULL OR cpu_ms >= 0);
CREATE INDEX scan_modules_module_idx ON scan_modules (module_id, finished_at DESC);

-- F14 : relevés périodiques des modules permanents (service, feed, runner),
-- publiés par le helper dans l'état et recopiés par la console. Rétention
-- bornée par la console (90 jours par défaut).
CREATE TABLE module_samples (
    module_id  text        NOT NULL CHECK (module_id ~ '^[a-z0-9][a-z0-9-]{1,40}$'),
    at         timestamptz NOT NULL,
    memory_mb  integer     CHECK (memory_mb IS NULL OR memory_mb >= 0),
    cpu_pct    real        CHECK (cpu_pct IS NULL OR cpu_pct >= 0),
    disk_mb    integer     CHECK (disk_mb IS NULL OR disk_mb >= 0),
    PRIMARY KEY (module_id, at)
);
CREATE INDEX module_samples_at_idx ON module_samples (at);

-- Tâches IA : sujets « rule » (I17, traduction d'une règle d'outil, clé
-- outil:version:règle) et « module » (I15 et I16, diagnostic).
ALTER TABLE ai_tasks DROP CONSTRAINT ai_tasks_subject_type_check;
ALTER TABLE ai_tasks ADD CONSTRAINT ai_tasks_subject_type_check
    CHECK (subject_type IN ('finding', 'scan', 'testbed', 'rule', 'module'));

-- I15 : contexte joint par l'appelant (extrait masqué et borné d'un journal),
-- seule source de journal lisible par scanoria-ai, qui n'a pas accès aux
-- fichiers de /var/lib/scanoria.
ALTER TABLE ai_tasks ADD COLUMN context jsonb CHECK (context IS NULL OR pg_column_size(context) <= 32768);

-- I24 : retour d'une personne sur une sortie IA (pouce, correction). Sert à
-- mesurer l'accord IA/humain par tâche et par modèle ; jamais envoyé à un
-- autre projet que celui de la tâche.
CREATE TABLE ai_feedback (
    id          bigint      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    task_id     uuid        NOT NULL REFERENCES ai_tasks (id) ON DELETE CASCADE,
    user_id     bigint      REFERENCES users (id) ON DELETE SET NULL,
    vote        smallint    NOT NULL CHECK (vote IN (-1, 1)),
    correction  text        CHECK (correction IS NULL OR length(correction) BETWEEN 1 AND 4000),
    created_at  timestamptz NOT NULL DEFAULT now(),
    UNIQUE (task_id, user_id)
);
