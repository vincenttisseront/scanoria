-- SPDX-License-Identifier: AGPL-3.0-or-later
-- Copyright (C) 2026 Vincent Tisseront
--
-- 0.3 : socle des analyses (ARCHITECTURE § 12). Contrat commun aux chantiers
-- de la 0.3 : projets et forges, file d'analyses, résultats unifiés, quality
-- gates, jetons d'API et file de tâches IA. Les chantiers n'ajoutent pas de
-- migration : un besoin de colonne passe par l'intégrateur (004, 005…).

ALTER TABLE helper_requests DROP CONSTRAINT helper_requests_type_check;
ALTER TABLE helper_requests ADD CONSTRAINT helper_requests_type_check CHECK (type IN (
    'set-hostname', 'set-admin-networks', 'issue-certificate',
    'import-certificate', 'check-update', 'apply-update',
    'rollback-update', 'set-update-policy', 'run-selftest',
    'refresh-catalog', 'install-modules', 'uninstall-module',
    'set-module-state', 'update-module', 'check-dns',
    'set-ai-endpoint'));

-- Secrets chiffrés (AES-256-GCM, clé de la console, ARCHITECTURE § 12.3).
-- La valeur n'est jamais renvoyée par l'API ni journalisée.
CREATE TABLE credentials (
    id           uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    kind         text        NOT NULL CHECK (kind IN ('token', 'ssh-key', 'ai-token')),
    username     text        CHECK (username IS NULL OR length(username) <= 255),
    secret_enc   bytea       NOT NULL,   -- version (1 octet) | nonce (12) | chiffré | étiquette (16)
    hint         text        NOT NULL CHECK (length(hint) <= 64),  -- « …a1b2 » ou empreinte SSH
    created_by   bigint      REFERENCES users (id) ON DELETE SET NULL,
    created_at   timestamptz NOT NULL DEFAULT now(),
    rotated_at   timestamptz
);

CREATE TABLE forges (
    id                 uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    kind               text        NOT NULL CHECK (kind IN ('forgejo', 'github', 'gitlab')),
    name               text        NOT NULL UNIQUE CHECK (length(name) BETWEEN 1 AND 100),
    base_url           text        NOT NULL CHECK (base_url ~ '^https://[^/?#@]+(/[^?#@]*)?$'),
    credential_id      uuid        REFERENCES credentials (id) ON DELETE SET NULL,
    discovery          boolean     NOT NULL DEFAULT true,  -- principe 8 : dépôts découverts
    last_discovery_at  timestamptz,
    last_error         text,
    created_by         bigint      REFERENCES users (id) ON DELETE SET NULL,
    created_at         timestamptz NOT NULL DEFAULT now()
);

-- Profils par couverture (G7) : des catégories, résolues vers les modules
-- installés et actifs au moment de l'analyse.
CREATE TABLE profiles (
    id               uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    slug             text        NOT NULL UNIQUE CHECK (slug ~ '^[a-z0-9][a-z0-9-]{0,62}$'),
    builtin          boolean     NOT NULL DEFAULT false,
    categories       text[]      NOT NULL DEFAULT '{}',
    include_modules  text[]      NOT NULL DEFAULT '{}',
    exclude_modules  text[]      NOT NULL DEFAULT '{}',
    created_at       timestamptz NOT NULL DEFAULT now(),
    updated_at       timestamptz NOT NULL DEFAULT now()
);
INSERT INTO profiles (slug, builtin, categories) VALUES
    ('rapide',    true, '{secrets,sca,lint,ci}'),
    ('complet',   true, '{quality,sast,secrets,sca,iac,container,sbom,lint,licenses,ci}'),
    ('conteneur', true, '{container}'),
    ('release',   true, '{quality,sast,secrets,sca,iac,container,sbom,lint,licenses,ci,dast}');

-- Quality gates : règles au format de webui/shared/analysis.ts (GateRules).
CREATE TABLE gates (
    id          uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    slug        text        NOT NULL UNIQUE CHECK (slug ~ '^[a-z0-9][a-z0-9-]{0,62}$'),
    builtin     boolean     NOT NULL DEFAULT false,
    rules       jsonb       NOT NULL CHECK (jsonb_typeof(rules) = 'object'),
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now(),
    updated_by  bigint      REFERENCES users (id) ON DELETE SET NULL
);
INSERT INTO gates (slug, builtin, rules) VALUES ('defaut', true, '{
    "new_code_only": true,
    "max_secrets": 0,
    "vuln_block_from": "high",
    "sast_block_from": "high",
    "iac_block_from": "high",
    "block_malicious": true,
    "inconclusive_blocks": true
}'::jsonb);

CREATE TABLE projects (
    id                uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    slug              text        NOT NULL UNIQUE CHECK (slug ~ '^[a-z0-9][a-z0-9-]{0,62}$'),
    name              text        NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
    source_kind       text        NOT NULL CHECK (source_kind IN ('git', 'archive')),
    forge_id          uuid        REFERENCES forges (id) ON DELETE SET NULL,
    repo_full_name    text        CHECK (repo_full_name IS NULL OR repo_full_name ~ '^[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+)+$'),
    repo_url          text        CHECK (repo_url IS NULL OR repo_url ~ '^(https://[^?#@\s]+|ssh://[A-Za-z0-9._-]+@[^?#\s]+|[A-Za-z0-9._-]+@[A-Za-z0-9.-]+:[^?#\s]+)$'),
    credential_id     uuid        REFERENCES credentials (id) ON DELETE SET NULL,
    default_branch    text        CHECK (default_branch IS NULL OR length(default_branch) <= 255),
    tracked_branches  text[]      NOT NULL DEFAULT '{}',
    schedule          text        NOT NULL DEFAULT 'on-commit' CHECK (schedule IN ('none', 'daily', 'on-commit')),
    profile_id        uuid        NOT NULL REFERENCES profiles (id),
    gate_id           uuid        NOT NULL REFERENCES gates (id),
    spdx_license      text,                       -- licence OSI déclarée (CodeQL autorisé si open source)
    ai_opt_out        boolean     NOT NULL DEFAULT false,  -- § 3.5 « aucun envoi à l'IA »
    detection         jsonb,                      -- F1 : langages, gestionnaires, IaC, CI, modules proposés
    last_commit       text        CHECK (last_commit IS NULL OR last_commit ~ '^[0-9a-f]{40,64}$'),
    created_by        bigint      REFERENCES users (id) ON DELETE SET NULL,
    created_at        timestamptz NOT NULL DEFAULT now(),
    archived_at       timestamptz,
    CHECK (source_kind = 'archive' OR repo_url IS NOT NULL)
);
CREATE UNIQUE INDEX projects_forge_repo_idx ON projects (forge_id, repo_full_name) WHERE forge_id IS NOT NULL;

-- File d'analyses (G17) et analyses reproductibles (G11).
CREATE TABLE scans (
    id                uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id        uuid        NOT NULL REFERENCES projects (id) ON DELETE CASCADE,
    number            integer     NOT NULL CHECK (number > 0),
    trigger           text        NOT NULL CHECK (trigger IN ('manual', 'schedule', 'commit', 'webhook', 'api', 'release', 'replay')),
    priority          smallint    NOT NULL CHECK (priority BETWEEN 0 AND 100),
    ref               text        NOT NULL CHECK (length(ref) BETWEEN 1 AND 255),
    commit_sha        text        CHECK (commit_sha IS NULL OR commit_sha ~ '^[0-9a-f]{40,64}$'),
    upload_id         uuid,                       -- archive téléversée (source_kind = archive)
    profile_id        uuid        NOT NULL REFERENCES profiles (id),
    gate_id           uuid        NOT NULL REFERENCES gates (id),
    plan              jsonb,                      -- G11 : modules, versions, empreintes, bases, options, règles du gate
    status            text        NOT NULL DEFAULT 'queued' CHECK (status IN (
                          'queued', 'dispatched', 'running', 'ingesting', 'done', 'error', 'cancelled')),
    verdict           text        CHECK (verdict IN ('passed', 'failed', 'inconclusive')),
    verdict_details   jsonb,                      -- format VerdictDetails (webui/shared/analysis.ts)
    coverage          jsonb,                      -- G15 : trous de couverture, fichiers ignorés…
    attempt           smallint    NOT NULL DEFAULT 1,
    job_id            uuid,                       -- dernière tâche déposée pour scanoria-runner
    error             jsonb,                      -- {code, class, message}
    replay_of         uuid        REFERENCES scans (id) ON DELETE SET NULL,
    requested_by      bigint      REFERENCES users (id) ON DELETE SET NULL,
    api_token_id      uuid,
    queued_at         timestamptz NOT NULL DEFAULT now(),
    started_at        timestamptz,
    finished_at       timestamptz,
    UNIQUE (project_id, number)
);
CREATE INDEX scans_queue_idx ON scans (status, priority DESC, queued_at) WHERE status IN ('queued', 'dispatched', 'running', 'ingesting');
CREATE INDEX scans_project_idx ON scans (project_id, queued_at DESC);

CREATE TABLE scan_modules (
    scan_id         uuid        NOT NULL REFERENCES scans (id) ON DELETE CASCADE,
    module_id       text        NOT NULL CHECK (module_id ~ '^[a-z0-9][a-z0-9-]{1,40}$'),
    module_version  text        NOT NULL,
    image_digest    text        CHECK (image_digest IS NULL OR image_digest ~ '^sha256:[0-9a-f]{64}$'),
    feeds           jsonb       NOT NULL DEFAULT '[]'::jsonb,   -- [{id, version, updated_at}]
    status          text        NOT NULL DEFAULT 'pending' CHECK (status IN (
                        'pending', 'running', 'ok', 'error', 'timeout', 'oom', 'invalid-output', 'missing', 'skipped')),
    error_class     text        CHECK (error_class IN ('infra', 'tool', 'input')),
    attempts        smallint    NOT NULL DEFAULT 0,
    results_count   integer,
    duration_ms     integer,
    log_path        text,                       -- sous /var/lib/scanoria/console/scan-logs/ (G20)
    started_at      timestamptz,
    finished_at     timestamptz,
    PRIMARY KEY (scan_id, module_id)
);

-- Résultats unifiés (§ 6.3). Jamais la valeur d'un secret.
CREATE TABLE findings (
    id                 uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id         uuid        NOT NULL REFERENCES projects (id) ON DELETE CASCADE,
    fingerprint        text        NOT NULL CHECK (fingerprint ~ '^[0-9a-f]{64}$'),  -- G19
    tool               text        NOT NULL,
    rule_id            text        NOT NULL CHECK (length(rule_id) <= 255),
    category           text        NOT NULL,
    severity           text        NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
    native_severity    text,
    title              text        NOT NULL CHECK (length(title) <= 500),
    message            text        CHECK (length(message) <= 4000),
    path               text        CHECK (length(path) <= 1024),
    start_line         integer,
    end_line           integer,
    cwe                text[]      NOT NULL DEFAULT '{}',
    vuln_ids           text[]      NOT NULL DEFAULT '{}',   -- CVE-…, GHSA-…, OSV MAL-…
    package            jsonb,                               -- {ecosystem, name, version, fixed: []}
    malicious          boolean     NOT NULL DEFAULT false,  -- H4 : avis MAL-
    secret_type        text,                                -- F7 ; jamais la valeur
    secret_state       text        CHECK (secret_state IN ('to-revoke', 'revoked', 'false-positive')),
    status             text        NOT NULL DEFAULT 'new' CHECK (status IN ('new', 'confirmed', 'false-positive', 'accepted', 'fixed')),
    status_until       date,
    status_reason      text        CHECK (length(status_reason) <= 2000),
    status_by          bigint      REFERENCES users (id) ON DELETE SET NULL,
    status_at          timestamptz,
    first_scan_id      uuid        REFERENCES scans (id) ON DELETE SET NULL,
    first_commit       text,
    last_scan_id       uuid        REFERENCES scans (id) ON DELETE SET NULL,
    last_commit        text,
    created_at         timestamptz NOT NULL DEFAULT now(),
    updated_at         timestamptz NOT NULL DEFAULT now(),
    UNIQUE (project_id, fingerprint),
    CHECK (status <> 'accepted' OR (status_until IS NOT NULL AND status_reason IS NOT NULL))
);
CREATE INDEX findings_project_status_idx ON findings (project_id, status, severity);
CREATE INDEX findings_vuln_ids_idx ON findings USING gin (vuln_ids);

-- Présence d'un résultat dans une analyse (nouveau code, comparaison F2).
CREATE TABLE scan_findings (
    scan_id     uuid    NOT NULL REFERENCES scans (id) ON DELETE CASCADE,
    finding_id  uuid    NOT NULL REFERENCES findings (id) ON DELETE CASCADE,
    is_new      boolean NOT NULL,
    PRIMARY KEY (scan_id, finding_id)
);
CREATE INDEX scan_findings_finding_idx ON scan_findings (finding_id);

-- Normalisation des gravités éditable (G5).
CREATE TABLE severity_maps (
    module_id   text        NOT NULL,
    native      text        NOT NULL CHECK (length(native) <= 64),
    severity    text        NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
    builtin     boolean     NOT NULL DEFAULT true,
    updated_by  bigint      REFERENCES users (id) ON DELETE SET NULL,
    updated_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (module_id, native)
);

-- Exceptions motivées et datées (§ 6.1). Un avis MAL- n'est jamais exceptable (H4).
CREATE TABLE exceptions (
    id          uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id  uuid        NOT NULL REFERENCES projects (id) ON DELETE CASCADE,
    kind        text        NOT NULL CHECK (kind IN ('path', 'rule', 'vuln', 'finding', 'module')),
    target      jsonb       NOT NULL CHECK (jsonb_typeof(target) = 'object'),
    reason      text        NOT NULL CHECK (length(reason) BETWEEN 3 AND 2000),
    expires_on  date        NOT NULL,
    created_by  bigint      REFERENCES users (id) ON DELETE SET NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    revoked_at  timestamptz,
    revoked_by  bigint      REFERENCES users (id) ON DELETE SET NULL
);
CREATE INDEX exceptions_project_idx ON exceptions (project_id) WHERE revoked_at IS NULL;

-- Jetons d'API par projet pour la CI (§ 3.3, § 6.2). Seule l'empreinte est gardée.
CREATE TABLE api_tokens (
    id            uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id    uuid        NOT NULL REFERENCES projects (id) ON DELETE CASCADE,
    name          text        NOT NULL CHECK (length(name) BETWEEN 1 AND 100),
    token_hash    text        NOT NULL UNIQUE CHECK (token_hash ~ '^[0-9a-f]{64}$'),
    prefix        text        NOT NULL CHECK (prefix ~ '^scn_[A-Za-z0-9]{4}$'),
    scopes        text[]      NOT NULL DEFAULT '{scan:create,scan:read}',
    created_by    bigint      REFERENCES users (id) ON DELETE SET NULL,
    created_at    timestamptz NOT NULL DEFAULT now(),
    expires_at    timestamptz,
    last_used_at  timestamptz,
    revoked_at    timestamptz
);
ALTER TABLE scans ADD CONSTRAINT scans_api_token_fk FOREIGN KEY (api_token_id) REFERENCES api_tokens (id) ON DELETE SET NULL;

-- File de tâches IA (§ 3.5, I1). Rien n'y est envoyé pour un projet ai_opt_out.
CREATE TABLE ai_tasks (
    id             uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    kind           text        NOT NULL CHECK (kind ~ '^[a-z][a-z0-9-]{1,40}$'),  -- explain-finding, explain-verdict…
    project_id     uuid        REFERENCES projects (id) ON DELETE CASCADE,
    subject_type   text        NOT NULL CHECK (subject_type IN ('finding', 'scan', 'testbed')),
    subject_id     text        NOT NULL,
    locale         text        NOT NULL DEFAULT 'fr' CHECK (locale IN ('fr', 'en')),
    priority       smallint    NOT NULL DEFAULT 10,  -- interactif 50, précalcul 10
    status         text        NOT NULL DEFAULT 'queued' CHECK (status IN ('queued', 'running', 'done', 'error', 'skipped')),
    input_hash     text        CHECK (input_hash IS NULL OR input_hash ~ '^[0-9a-f]{64}$'),
    model          text,
    model_digest   text,
    output         jsonb,
    error          text,
    attempts       smallint    NOT NULL DEFAULT 0,
    requested_by   bigint      REFERENCES users (id) ON DELETE SET NULL,
    created_at     timestamptz NOT NULL DEFAULT now(),
    started_at     timestamptz,
    finished_at    timestamptz
);
CREATE INDEX ai_tasks_queue_idx ON ai_tasks (status, priority DESC, created_at) WHERE status IN ('queued', 'running');
CREATE INDEX ai_tasks_subject_idx ON ai_tasks (subject_type, subject_id, kind, locale);

CREATE TABLE ai_cache (
    kind          text        NOT NULL,
    input_hash    text        NOT NULL CHECK (input_hash ~ '^[0-9a-f]{64}$'),
    model_digest  text        NOT NULL,
    locale        text        NOT NULL,
    output        jsonb       NOT NULL,
    created_at    timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (kind, input_hash, model_digest, locale)
);

-- Journal des appels IA : métadonnées seulement, jamais le contenu (§ 3.5).
CREATE TABLE ai_calls (
    id           bigint      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    task_id      uuid        REFERENCES ai_tasks (id) ON DELETE SET NULL,
    kind         text        NOT NULL,
    project_id   uuid        REFERENCES projects (id) ON DELETE SET NULL,
    model        text,
    bytes_sent   integer     NOT NULL DEFAULT 0,
    duration_ms  integer,
    outcome      text        NOT NULL CHECK (outcome IN ('ok', 'invalid-output', 'timeout', 'error', 'circuit-open')),
    at           timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ai_calls_at_idx ON ai_calls (at DESC);
