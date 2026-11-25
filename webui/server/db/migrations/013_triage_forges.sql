-- SPDX-License-Identifier: AGPL-3.0-or-later
-- Copyright (C) 2026 Vincent Tisseront
--
-- 0.7 : tri en masse (F4), exceptions soumises à approbation (F5, J15),
-- affectation CODEOWNERS (F6), jeux de règles (G4), héritage et verrouillage
-- des profils (G8), profil par déclencheur (G9), configuration en code (J8),
-- application de forge (J1), PR et analyse incrémentale (G18, H6, I25, J7),
-- résultats des modules d'analyse par IA (K1–K7) et verdict anticipé (V8).

-- J15 : une identité non humaine peut demander, jamais approuver.
ALTER TABLE users ADD COLUMN kind text NOT NULL DEFAULT 'human' CHECK (kind IN ('human', 'agent', 'bot'));

-- F5 et J15 : circuit demande → approbation. Les exceptions existantes sont
-- approuvées (créées par un administrateur avant la 0.7).
ALTER TABLE exceptions
    ADD COLUMN status text NOT NULL DEFAULT 'approved' CHECK (status IN ('requested', 'approved', 'refused')),
    ADD COLUMN requested_via text NOT NULL DEFAULT 'console'
        CHECK (requested_via IN ('console', 'api', 'pr-comment', 'tool-import', 'config')),
    ADD COLUMN requester_label text CHECK (requester_label IS NULL OR length(requester_label) BETWEEN 1 AND 255),
    ADD COLUMN requester_is_human boolean NOT NULL DEFAULT true,
    ADD COLUMN decided_by bigint REFERENCES users (id) ON DELETE SET NULL,
    ADD COLUMN decided_at timestamptz DEFAULT now(),   -- une demande (status 'requested') l'insère explicitement à NULL
    ADD COLUMN decision_reason text CHECK (decision_reason IS NULL OR length(decision_reason) BETWEEN 3 AND 2000),
    ADD COLUMN commit_authors text[] NOT NULL DEFAULT '{}',   -- J15 : auteurs du commit analysé, exclus de l'approbation
    ADD COLUMN expiry_notified_at timestamptz;
-- Exceptions d'avant la 0.7 : décision datée de leur création, décideur
-- inconnu (NULL). Toute nouvelle décision porte son décideur (console).
UPDATE exceptions SET decided_at = created_at;
-- Personne n'approuve ni ne refuse sa propre demande. Le reste de J15 (auteur
-- du commit, identité non humaine, rôle) est appliqué par la console.
ALTER TABLE exceptions ADD CONSTRAINT exceptions_not_self_decided
    CHECK (decided_by IS NULL OR created_by IS NULL OR decided_by <> created_by);
ALTER TABLE exceptions ADD CONSTRAINT exceptions_decision
    CHECK ((status = 'requested') = (decided_at IS NULL));
CREATE INDEX exceptions_pending_idx ON exceptions (project_id, created_at) WHERE status = 'requested';

-- F4 : règles de tri en masse, avec justification et date de fin obligatoires.
CREATE TABLE triage_rules (
    id             uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id     uuid        REFERENCES projects (id) ON DELETE CASCADE,   -- NULL = toutes les analyses
    match          jsonb       NOT NULL CHECK (jsonb_typeof(match) = 'object'), -- {path, tool, rule, severity}
    action         text        NOT NULL CHECK (action IN ('false-positive', 'accepted', 'confirmed')),
    reason         text        NOT NULL CHECK (length(reason) BETWEEN 3 AND 2000),
    expires_on     date        NOT NULL,
    applied_count  integer     NOT NULL DEFAULT 0 CHECK (applied_count >= 0),
    created_by     bigint      REFERENCES users (id) ON DELETE SET NULL,
    created_at     timestamptz NOT NULL DEFAULT now(),
    revoked_at     timestamptz,
    revoked_by     bigint      REFERENCES users (id) ON DELETE SET NULL
);
ALTER TABLE findings ADD COLUMN triage_rule_id uuid REFERENCES triage_rules (id) ON DELETE SET NULL;

-- F6 : responsables lus dans CODEOWNERS (ou la table de correspondance).
ALTER TABLE findings ADD COLUMN owners text[] NOT NULL DEFAULT '{}' CHECK (cardinality(owners) <= 20);
CREATE TABLE owner_mappings (
    project_id  uuid        REFERENCES projects (id) ON DELETE CASCADE,   -- NULL = globale
    owner       text        NOT NULL CHECK (length(owner) BETWEEN 1 AND 255), -- « @equipe », « @login », adresse
    user_id     bigint      NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    created_at  timestamptz NOT NULL DEFAULT now(),
    UNIQUE NULLS NOT DISTINCT (project_id, owner, user_id)
);
CREATE INDEX findings_owners_idx ON findings USING gin (owners);

-- K1–K7 : un résultat d'un module d'analyse par IA n'entre dans le verdict
-- qu'une fois confirmé par une personne qui a le rôle requis (§ 3.5).
ALTER TABLE findings DROP CONSTRAINT findings_origin_check;
ALTER TABLE findings ADD CONSTRAINT findings_origin_check CHECK (origin IN ('module', 'external', 'ai'));
ALTER TABLE findings
    ADD COLUMN ai_confirmed_by bigint REFERENCES users (id) ON DELETE SET NULL,
    ADD COLUMN ai_confirmed_at timestamptz;
ALTER TABLE findings ADD CONSTRAINT findings_ai_confirmation
    CHECK (origin = 'ai' OR (ai_confirmed_by IS NULL AND ai_confirmed_at IS NULL));

-- G4 : jeux de règles versionnés et partagés.
CREATE TABLE rulesets (
    id          uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    slug        text        NOT NULL UNIQUE CHECK (slug ~ '^[a-z0-9][a-z0-9-]{0,62}$'),
    engine      text        NOT NULL CHECK (engine ~ '^[a-z][a-z0-9-]{1,40}$'),  -- opengrep, gitleaks, checkov…
    name        text        NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
    description text        CHECK (length(description) <= 2000),
    created_by  bigint      REFERENCES users (id) ON DELETE SET NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    archived_at timestamptz
);
CREATE TABLE ruleset_versions (
    ruleset_id  uuid        NOT NULL REFERENCES rulesets (id) ON DELETE CASCADE,
    version     integer     NOT NULL CHECK (version > 0),
    content     text        NOT NULL CHECK (octet_length(content) BETWEEN 1 AND 1048576),
    sha256      text        NOT NULL CHECK (sha256 ~ '^[0-9a-f]{64}$'),
    comment     text        CHECK (length(comment) <= 2000),
    origin      text        NOT NULL DEFAULT 'manual' CHECK (origin IN ('manual', 'import', 'ai')),  -- I12 : « ai » = généré puis confirmé
    created_by  bigint      REFERENCES users (id) ON DELETE SET NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (ruleset_id, version)
);
CREATE TABLE profile_rulesets (
    profile_id      uuid    NOT NULL REFERENCES profiles (id) ON DELETE CASCADE,
    ruleset_id      uuid    NOT NULL REFERENCES rulesets (id) ON DELETE RESTRICT,
    pinned_version  integer CHECK (pinned_version IS NULL OR pinned_version > 0),  -- NULL = dernière version
    PRIMARY KEY (profile_id, ruleset_id)
);

-- G8 : profil d'entreprise → équipe → projet, avec exigences verrouillées.
ALTER TABLE profiles
    ADD COLUMN parent_id uuid REFERENCES profiles (id) ON DELETE RESTRICT,
    ADD COLUMN level text NOT NULL DEFAULT 'enterprise' CHECK (level IN ('enterprise', 'team', 'project')),
    ADD COLUMN locks jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(locks) = 'object'),  -- contrat 28
    ADD COLUMN description text CHECK (length(description) <= 2000);
ALTER TABLE profiles ADD CONSTRAINT profiles_not_own_parent CHECK (parent_id IS NULL OR parent_id <> id);
ALTER TABLE profiles ADD CONSTRAINT profiles_level_parent CHECK ((level = 'enterprise') = (parent_id IS NULL));

-- G9 : profil par déclencheur (NULL = profile_id). J8 : dernière configuration
-- lue dans le dépôt (.scanoria.yml).
ALTER TABLE projects
    ADD COLUMN profile_pr_id uuid REFERENCES profiles (id),
    ADD COLUMN profile_nightly_id uuid REFERENCES profiles (id),
    ADD COLUMN profile_release_id uuid REFERENCES profiles (id),
    ADD COLUMN config_state jsonb CHECK (config_state IS NULL OR jsonb_typeof(config_state) = 'object');

-- J1 : application de forge créée par l'appliance (droits minimaux).
ALTER TABLE credentials DROP CONSTRAINT credentials_kind_check;
ALTER TABLE credentials ADD CONSTRAINT credentials_kind_check
    CHECK (kind IN ('token', 'ssh-key', 'ai-token', 'app-key', 'webhook-secret', 'oauth-secret'));
CREATE TABLE forge_apps (
    forge_id                 uuid        PRIMARY KEY REFERENCES forges (id) ON DELETE CASCADE,
    kind                     text        NOT NULL CHECK (kind IN ('github-app', 'forgejo-oauth', 'gitlab-oauth')),
    app_id                   text        CHECK (length(app_id) BETWEEN 1 AND 64),
    client_id                text        CHECK (length(client_id) BETWEEN 1 AND 128),
    slug                     text        CHECK (length(slug) BETWEEN 1 AND 128),
    key_credential_id        uuid        REFERENCES credentials (id) ON DELETE SET NULL,
    webhook_credential_id    uuid        REFERENCES credentials (id) ON DELETE SET NULL,
    installation_ids         text[]      NOT NULL DEFAULT '{}',
    permissions              jsonb       NOT NULL DEFAULT '{}'::jsonb,
    created_by               bigint      REFERENCES users (id) ON DELETE SET NULL,
    created_at               timestamptz NOT NULL DEFAULT now()
);

-- Webhooks reçus : rejeu refusé (identifiant de livraison unique par forge).
CREATE TABLE webhook_deliveries (
    forge_id     uuid        NOT NULL REFERENCES forges (id) ON DELETE CASCADE,
    delivery_id  text        NOT NULL CHECK (length(delivery_id) BETWEEN 1 AND 128),
    event        text        NOT NULL CHECK (length(event) BETWEEN 1 AND 64),
    status       text        NOT NULL CHECK (status IN ('accepted', 'ignored', 'rejected')),
    detail       text        CHECK (length(detail) <= 500),
    received_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (forge_id, delivery_id)
);
CREATE INDEX webhook_deliveries_received_idx ON webhook_deliveries (received_at);

-- G18, H6, J7, I25 : analyse d'une PR (incrémentale) et publication dans la forge.
ALTER TABLE scans ADD COLUMN pull_request jsonb CHECK (pull_request IS NULL OR (
    jsonb_typeof(pull_request) = 'object' AND pull_request ? 'number' AND pull_request ? 'base_sha'));
ALTER TABLE scans ADD COLUMN incremental boolean NOT NULL DEFAULT false;
ALTER TABLE scans ADD CONSTRAINT scans_incremental_pr CHECK (NOT incremental OR pull_request IS NOT NULL);
CREATE TABLE forge_publications (
    scan_id          uuid        NOT NULL REFERENCES scans (id) ON DELETE CASCADE,
    kind             text        NOT NULL CHECK (kind IN ('commit-status', 'check-run', 'pr-comment', 'pr-review')),
    external_id      text        CHECK (length(external_id) BETWEEN 1 AND 128),
    annotations      integer     NOT NULL DEFAULT 0 CHECK (annotations >= 0),
    state            text        NOT NULL CHECK (state IN ('pending', 'published', 'error')),
    error            text        CHECK (length(error) <= 1000),
    updated_at       timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (scan_id, kind)
);

-- V8 : verdict défavorable anticipé, publié avant la fin de l'analyse.
ALTER TABLE scans ADD COLUMN early_failure jsonb CHECK (early_failure IS NULL OR jsonb_typeof(early_failure) = 'object');

-- Relais compatible OpenAI de scanoria-ai (K1–K7) : appels journalisés comme
-- les autres, avec le module appelant.
ALTER TABLE ai_calls ADD COLUMN via text NOT NULL DEFAULT 'console' CHECK (via IN ('console', 'relay'));
ALTER TABLE ai_calls ADD COLUMN module_id text CHECK (module_id IS NULL OR module_id ~ '^[a-z0-9][a-z0-9-]{1,40}$');
ALTER TABLE ai_calls ADD CONSTRAINT ai_calls_relay_module CHECK ((via = 'relay') = (module_id IS NOT NULL));

-- I8 (recherche en langage naturel) et I10 (rédaction des exceptions).
ALTER TABLE ai_tasks DROP CONSTRAINT ai_tasks_subject_type_check;
ALTER TABLE ai_tasks ADD CONSTRAINT ai_tasks_subject_type_check
    CHECK (subject_type IN ('finding', 'scan', 'testbed', 'rule', 'module', 'license', 'appliance', 'exception', 'query'));
