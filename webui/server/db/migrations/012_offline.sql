-- SPDX-License-Identifier: AGPL-3.0-or-later
-- Copyright (C) 2026 Vincent Tisseront
--
-- 0.6 : hors ligne (lots signés, appliance miroir F17), vigilance (F13, F19,
-- G6, G14, G16), résultats externes (J6), diagnostic IA de l'appliance (I16)
-- et délais d'analyse (V4, V6).

-- F17 et lots hors ligne : clés publiques Ed25519 de confiance, ajoutées
-- explicitement par un administrateur (une autre appliance qui exporte ses
-- bases, ou un catalogue privé en 0.10). Jamais de clé privée en base.
CREATE TABLE trusted_keys (
    id           uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    label        text        NOT NULL CHECK (length(label) BETWEEN 1 AND 100),
    purpose      text        NOT NULL CHECK (purpose IN ('bundle', 'catalog')),
    public_key   text        NOT NULL CHECK (public_key ~ '^[A-Za-z0-9+/]{43}=$'),  -- 32 octets en base64
    fingerprint  text        NOT NULL UNIQUE CHECK (fingerprint ~ '^[0-9a-f]{64}$'), -- SHA-256 de la clé brute
    added_by     bigint      REFERENCES users (id) ON DELETE SET NULL,
    added_at     timestamptz NOT NULL DEFAULT now(),
    revoked_at   timestamptz
);

-- Lots hors ligne exportés ou importés (contrat 19). Le fichier lui-même vit
-- sous /var/lib/scanoria/bundles/, géré par le helper.
CREATE TABLE offline_bundles (
    id                  uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    direction           text        NOT NULL CHECK (direction IN ('export', 'import')),
    status              text        NOT NULL DEFAULT 'queued' CHECK (status IN ('queued', 'running', 'done', 'error')),
    contents            jsonb       NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(contents) = 'object'),
    size_bytes          bigint      CHECK (size_bytes IS NULL OR size_bytes >= 0),
    sha256              text        CHECK (sha256 IS NULL OR sha256 ~ '^[0-9a-f]{64}$'),
    signer_fingerprint  text        CHECK (signer_fingerprint IS NULL OR signer_fingerprint ~ '^[0-9a-f]{64}$'),
    request_id          uuid,
    error               jsonb,
    requested_by        bigint      REFERENCES users (id) ON DELETE SET NULL,
    created_at          timestamptz NOT NULL DEFAULT now(),
    finished_at         timestamptz
);
CREATE INDEX offline_bundles_created_idx ON offline_bundles (created_at DESC);

-- G6 : version d'un module figée par projet (empreinte d'image obligatoire).
CREATE TABLE project_module_pins (
    project_id    uuid        NOT NULL REFERENCES projects (id) ON DELETE CASCADE,
    module_id     text        NOT NULL CHECK (module_id ~ '^[a-z0-9][a-z0-9-]{1,40}$'),
    version       text        NOT NULL CHECK (length(version) BETWEEN 1 AND 64),
    image_digest  text        NOT NULL CHECK (image_digest ~ '^sha256:[0-9a-f]{64}$'),
    reason        text        NOT NULL CHECK (length(reason) BETWEEN 3 AND 2000),
    pinned_by     bigint      REFERENCES users (id) ON DELETE SET NULL,
    pinned_at     timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (project_id, module_id)
);

-- F13 : mise à jour d'outil à l'essai. Les analyses d'essai (trigger 'trial')
-- rejouent les dernières analyses avec la version candidate ; elles ne
-- publient aucun verdict et ne touchent ni aux statuts ni aux résultats.
CREATE TABLE module_trials (
    id              uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    module_id       text        NOT NULL CHECK (module_id ~ '^[a-z0-9][a-z0-9-]{1,40}$'),
    from_version    text        NOT NULL CHECK (length(from_version) BETWEEN 1 AND 64),
    to_version      text        NOT NULL CHECK (length(to_version) BETWEEN 1 AND 64),
    to_digest       text        NOT NULL CHECK (to_digest ~ '^sha256:[0-9a-f]{64}$'),
    status          text        NOT NULL DEFAULT 'running' CHECK (status IN ('running', 'done', 'adopted', 'abandoned', 'error')),
    sample_size     smallint    NOT NULL DEFAULT 10 CHECK (sample_size BETWEEN 1 AND 50),
    summary         jsonb,      -- {new, gone, unchanged, duration_old_ms, duration_new_ms, per_scan[]}
    started_by      bigint      REFERENCES users (id) ON DELETE SET NULL,
    started_at      timestamptz NOT NULL DEFAULT now(),
    finished_at     timestamptz
);
CREATE UNIQUE INDEX module_trials_running_idx ON module_trials (module_id) WHERE status = 'running';

-- G14 : canaris nocturnes (banc d'essai F12 rejoué chaque nuit).
CREATE TABLE canary_runs (
    id              uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    module_id       text        NOT NULL CHECK (module_id ~ '^[a-z0-9][a-z0-9-]{1,40}$'),
    module_version  text        NOT NULL CHECK (length(module_version) BETWEEN 1 AND 64),
    image_digest    text        CHECK (image_digest IS NULL OR image_digest ~ '^sha256:[0-9a-f]{64}$'),
    ok              boolean     NOT NULL,
    details         jsonb       NOT NULL DEFAULT '{}'::jsonb,  -- attendus, observés, manquants
    duration_ms     integer     CHECK (duration_ms IS NULL OR duration_ms >= 0),
    run_at          timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX canary_runs_module_idx ON canary_runs (module_id, run_at DESC);

-- F19 : vulnérabilités de l'appliance elle-même (console, images des modules).
CREATE TABLE self_vulns (
    subject            text        NOT NULL CHECK (subject ~ '^(console|module:[a-z0-9][a-z0-9-]{1,40})$'),
    vuln_id            text        NOT NULL CHECK (vuln_id ~ '^[A-Za-z][A-Za-z0-9]*-[A-Za-z0-9._:-]{1,120}$'),
    purl               text        NOT NULL CHECK (length(purl) BETWEEN 5 AND 1024 AND purl LIKE 'pkg:%'),
    severity           text        NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
    fixed_version      text        CHECK (length(fixed_version) <= 256),
    update_available   boolean     NOT NULL DEFAULT false,
    first_seen         timestamptz NOT NULL DEFAULT now(),
    last_seen          timestamptz NOT NULL DEFAULT now(),
    resolved_at        timestamptz,
    PRIMARY KEY (subject, vuln_id, purl)
);

-- V4 : résultats réutilisés. Clé = contrat 21 ; les sorties rangées vivent
-- sous /var/lib/scanoria/console/result-cache/<clé>/.
CREATE TABLE result_cache (
    cache_key       text        PRIMARY KEY CHECK (cache_key ~ '^[0-9a-f]{64}$'),
    module_id       text        NOT NULL CHECK (module_id ~ '^[a-z0-9][a-z0-9-]{1,40}$'),
    image_digest    text        NOT NULL CHECK (image_digest ~ '^sha256:[0-9a-f]{64}$'),
    source_scan     uuid        REFERENCES scans (id) ON DELETE SET NULL,
    results_count   integer     NOT NULL CHECK (results_count >= 0),
    duration_ms     integer     CHECK (duration_ms IS NULL OR duration_ms >= 0),
    size_bytes      bigint      NOT NULL DEFAULT 0 CHECK (size_bytes >= 0),
    hits            integer     NOT NULL DEFAULT 0 CHECK (hits >= 0),
    created_at      timestamptz NOT NULL DEFAULT now(),
    last_hit_at     timestamptz
);
CREATE INDEX result_cache_lru_idx ON result_cache (coalesce(last_hit_at, created_at));
ALTER TABLE scan_modules ADD COLUMN reused_from text REFERENCES result_cache (cache_key) ON DELETE SET NULL;

-- V6 : détection du contenu (F1) mise en cache par arbre Git.
CREATE TABLE content_detection (
    tree_sha     text        PRIMARY KEY CHECK (tree_sha ~ '^[0-9a-f]{40,64}$'),
    detected     jsonb       NOT NULL CHECK (jsonb_typeof(detected) = 'object'),
    computed_at  timestamptz NOT NULL DEFAULT now()
);

-- V6 : un outil écarté faute de fichiers concernés est « not-applicable » :
-- noté dans la couverture (G15), jamais compté comme absent (G13).
ALTER TABLE scan_modules DROP CONSTRAINT scan_modules_status_check;
ALTER TABLE scan_modules ADD CONSTRAINT scan_modules_status_check CHECK (status IN (
    'pending', 'running', 'ok', 'error', 'timeout', 'oom', 'invalid-output', 'missing', 'skipped', 'not-applicable'));

-- F13 et J6 : analyses d'essai et résultats externes.
ALTER TABLE scans DROP CONSTRAINT scans_trigger_check;
ALTER TABLE scans ADD CONSTRAINT scans_trigger_check CHECK (trigger IN (
    'manual', 'schedule', 'commit', 'webhook', 'api', 'release', 'replay', 'recorrelate', 'trial', 'external'));
ALTER TABLE scans ADD COLUMN trial_id uuid REFERENCES module_trials (id) ON DELETE CASCADE;
ALTER TABLE scans ADD CONSTRAINT scans_trial_id CHECK ((trigger = 'trial') = (trial_id IS NOT NULL));
-- J6 : {tool, version, format, uploaded_via} ; obligatoire pour 'external', interdit sinon.
ALTER TABLE scans ADD COLUMN external_source jsonb CHECK (external_source IS NULL OR jsonb_typeof(external_source) = 'object');
ALTER TABLE scans ADD CONSTRAINT scans_external_source CHECK ((trigger = 'external') = (external_source IS NOT NULL));
-- J6 : origine d'un résultat. 'external' = téléversé ; affiché avec sa source.
ALTER TABLE findings ADD COLUMN origin text NOT NULL DEFAULT 'module' CHECK (origin IN ('module', 'external'));

-- I16 : diagnostic de l'appliance (alerte de santé, selftest, mise à jour,
-- installation de module).
ALTER TABLE ai_tasks DROP CONSTRAINT ai_tasks_subject_type_check;
ALTER TABLE ai_tasks ADD CONSTRAINT ai_tasks_subject_type_check
    CHECK (subject_type IN ('finding', 'scan', 'testbed', 'rule', 'module', 'license', 'appliance'));

-- Contrat 20 : G16, fraîcheur obligatoire. Au-delà de cet âge (jours), une
-- base utilisée rend le verdict non concluant ; null = seulement signalé.
UPDATE gates SET rules = '{"feed_max_age_days": 7}'::jsonb || rules, updated_at = now();

-- Demandes du helper de la 0.6 (contrat 19 et chantiers).
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
    'self-sbom', 'run-canaries', 'start-trial', 'prefetch-images'));
