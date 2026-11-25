-- SPDX-License-Identifier: AGPL-3.0-or-later
-- Copyright (C) 2026 Vincent Tisseront
--
-- Socle de la 0.8 : gate de release (CLAUDE.md § 7), comparaison entre
-- releases (F2), simulateur de quality gate (F9, I19), VEX (H7), intégration
-- CI (J2, J4), attestations et déploiement après verdict favorable (J9, J11,
-- J12, J13, J16). Schéma figé par l'intégrateur : toute autre colonne se
-- demande à lui (migration 019).

-- § 7.2 : mode d'intégration de la release, par projet. « pull » (défaut,
-- aucune exposition de l'appliance) interroge la forge ; « push » attend
-- l'appel de la CI (scanoria-scan) ; « off » n'analyse aucune release.
ALTER TABLE projects
    ADD COLUMN release_mode text NOT NULL DEFAULT 'pull' CHECK (release_mode IN ('pull', 'push', 'off')),
    ADD COLUMN release_patterns text[] NOT NULL DEFAULT '{v*}'
        CHECK (cardinality(release_patterns) BETWEEN 1 AND 20),
    ADD COLUMN autonomous_chain boolean NOT NULL DEFAULT false;

-- Mode tiré : tags et pré-versions déjà vus, pour ne jamais analyser deux fois
-- la même release (le cache V4 réutilise un commit déjà analysé).
CREATE TABLE release_candidates (
    project_id   uuid        NOT NULL REFERENCES projects (id) ON DELETE CASCADE,
    tag          text        NOT NULL CHECK (length(tag) BETWEEN 1 AND 255),
    commit_sha   text        NOT NULL CHECK (commit_sha ~ '^[0-9a-f]{40,64}$'),
    source       text        NOT NULL CHECK (source IN ('pull', 'push')),
    scan_id      uuid        REFERENCES scans (id) ON DELETE SET NULL,
    seen_at      timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (project_id, tag)
);
CREATE INDEX release_candidates_scan_idx ON release_candidates (scan_id);

-- § 7.3 : rapport de release signé par la clé de l'appliance (le helper root
-- signe, la console ne voit jamais la clé privée). Un rapport par analyse de
-- release, jamais modifié après signature.
CREATE TABLE release_reports (
    scan_id          uuid        PRIMARY KEY REFERENCES scans (id) ON DELETE CASCADE,
    project_id       uuid        NOT NULL REFERENCES projects (id) ON DELETE CASCADE,
    tag              text        NOT NULL CHECK (length(tag) BETWEEN 1 AND 255),
    commit_sha       text        NOT NULL CHECK (commit_sha ~ '^[0-9a-f]{40,64}$'),
    previous_scan_id uuid        REFERENCES scans (id) ON DELETE SET NULL,
    report           jsonb       NOT NULL CHECK (jsonb_typeof(report) = 'object' AND pg_column_size(report) <= 4194304),
    report_sha256    text        NOT NULL CHECK (report_sha256 ~ '^[0-9a-f]{64}$'),
    status           text        NOT NULL CHECK (status IN ('pending', 'signed', 'error')),
    signature        text        CHECK (signature ~ '^[A-Za-z0-9+/]{86}==$'),
    key_fingerprint  text        CHECK (key_fingerprint ~ '^[0-9a-f]{64}$'),
    error            text        CHECK (length(error) <= 1000),
    created_at       timestamptz NOT NULL DEFAULT now(),
    signed_at        timestamptz,
    CONSTRAINT release_reports_signed CHECK (
        (status = 'signed') = (signature IS NOT NULL AND key_fingerprint IS NOT NULL AND signed_at IS NOT NULL))
);
CREATE INDEX release_reports_project_idx ON release_reports (project_id, created_at DESC);
CREATE FUNCTION release_reports_frozen() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'release_reports: a signed report is immutable';
END $$;
CREATE TRIGGER release_reports_frozen BEFORE UPDATE ON release_reports FOR EACH ROW
    WHEN (OLD.status = 'signed') EXECUTE FUNCTION release_reports_frozen();

-- H7 : déclarations VEX, tirées des exceptions motivées ou importées
-- (OpenVEX, CycloneDX VEX). Statuts et justifications d'OpenVEX 0.2.
CREATE TABLE vex_statements (
    id              uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id      uuid        NOT NULL REFERENCES projects (id) ON DELETE CASCADE,
    vuln_id         text        NOT NULL CHECK (vuln_id ~ '^[A-Za-z][A-Za-z0-9._:-]{2,100}$'),
    product         text        NOT NULL CHECK (length(product) BETWEEN 1 AND 500),
    status          text        NOT NULL CHECK (status IN ('not_affected', 'affected', 'fixed', 'under_investigation')),
    justification   text        CHECK (justification IN ('component_not_present', 'vulnerable_code_not_present',
                        'vulnerable_code_not_in_execute_path', 'vulnerable_code_cannot_be_controlled_by_adversary',
                        'inline_mitigations_already_exist')),
    impact_statement text       CHECK (length(impact_statement) <= 2000),
    action_statement text       CHECK (length(action_statement) <= 2000),
    source          text        NOT NULL CHECK (source IN ('exception', 'import')),
    exception_id    uuid        REFERENCES exceptions (id) ON DELETE SET NULL,
    created_by      bigint      REFERENCES users (id) ON DELETE SET NULL,
    created_at      timestamptz NOT NULL DEFAULT now(),
    revoked_at      timestamptz,
    CONSTRAINT vex_not_affected_justified CHECK (status <> 'not_affected' OR justification IS NOT NULL OR impact_statement IS NOT NULL),
    CONSTRAINT vex_exception_source CHECK ((source = 'exception') = (exception_id IS NOT NULL))
);
CREATE INDEX vex_statements_project_idx ON vex_statements (project_id, vuln_id) WHERE revoked_at IS NULL;
-- I10 dès la 0.8 : statut VEX proposé avec la demande d'exception.
ALTER TABLE exceptions ADD COLUMN vex_status text CHECK (vex_status IN ('not_affected', 'affected', 'fixed', 'under_investigation'));

-- F9 et I19 : simulations de quality gate (jamais appliquées d'elles-mêmes).
CREATE TABLE gate_simulations (
    id          uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id  uuid        REFERENCES projects (id) ON DELETE CASCADE,
    gate_id     uuid        REFERENCES gates (id) ON DELETE CASCADE,
    rules       jsonb       NOT NULL CHECK (jsonb_typeof(rules) = 'object'),
    since       timestamptz NOT NULL,
    origin      text        NOT NULL CHECK (origin IN ('manual', 'ai')),
    status      text        NOT NULL CHECK (status IN ('pending', 'done', 'error')),
    result      jsonb       CHECK (result IS NULL OR (jsonb_typeof(result) = 'object' AND pg_column_size(result) <= 1048576)),
    created_by  bigint      REFERENCES users (id) ON DELETE SET NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT gate_simulations_done CHECK ((status = 'done') = (result IS NOT NULL))
);
CREATE INDEX gate_simulations_project_idx ON gate_simulations (project_id, created_at DESC);

-- J4 : émetteurs OIDC de confiance (CI sans secret). Chaque liaison rattache
-- des revendications (dépôt, ref) à un projet ; aucune liaison, aucun accès.
CREATE TABLE oidc_issuers (
    id          uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    kind        text        NOT NULL CHECK (kind IN ('github', 'gitlab', 'forgejo')),
    issuer      text        NOT NULL UNIQUE CHECK (issuer ~ '^https://[^\s/?#]+(/[^\s?#]*)?$' AND length(issuer) <= 255),
    audience    text        NOT NULL CHECK (length(audience) BETWEEN 1 AND 255),
    forge_id    uuid        REFERENCES forges (id) ON DELETE CASCADE,
    jwks        jsonb       CHECK (jwks IS NULL OR jsonb_typeof(jwks) = 'object'),
    jwks_fetched_at timestamptz,
    enabled     boolean     NOT NULL DEFAULT true,
    created_by  bigint      REFERENCES users (id) ON DELETE SET NULL,
    created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE oidc_bindings (
    id          uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    issuer_id   uuid        NOT NULL REFERENCES oidc_issuers (id) ON DELETE CASCADE,
    project_id  uuid        NOT NULL REFERENCES projects (id) ON DELETE CASCADE,
    repository  text        NOT NULL CHECK (length(repository) BETWEEN 1 AND 255),
    ref_patterns text[]     NOT NULL DEFAULT '{refs/heads/main,refs/tags/*}' CHECK (cardinality(ref_patterns) BETWEEN 1 AND 20),
    scopes      text[]      NOT NULL DEFAULT '{scan:create,scan:read}',
    created_at  timestamptz NOT NULL DEFAULT now(),
    UNIQUE (issuer_id, repository, project_id)
);

-- J2 : PR d'intégration ouvertes par l'appliance (jamais fusionnées par elle),
-- et règle de protection de branche proposée, appliquée après confirmation.
CREATE TABLE integration_requests (
    id           uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id   uuid        NOT NULL REFERENCES projects (id) ON DELETE CASCADE,
    kind         text        NOT NULL CHECK (kind IN ('ci-pr', 'branch-protection')),
    state        text        NOT NULL CHECK (state IN ('proposed', 'open', 'merged', 'closed', 'applied', 'declined', 'error')),
    external_id  text        CHECK (length(external_id) BETWEEN 1 AND 128),
    detail       jsonb       NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(detail) = 'object'),
    decided_by   bigint      REFERENCES users (id) ON DELETE SET NULL,
    created_at   timestamptz NOT NULL DEFAULT now(),
    updated_at   timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT integration_protection_decided CHECK (kind <> 'branch-protection' OR state <> 'applied' OR decided_by IS NOT NULL)
);
CREATE UNIQUE INDEX integration_requests_active ON integration_requests (project_id, kind)
    WHERE state IN ('proposed', 'open');

-- J9 : attestations in-toto signées par la clé de l'appliance, attachées à un
-- artefact (image OCI par empreinte) après un verdict favorable.
CREATE TABLE attestations (
    id              uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id         uuid        NOT NULL REFERENCES scans (id) ON DELETE CASCADE,
    subject_name    text        NOT NULL CHECK (length(subject_name) BETWEEN 1 AND 500),
    subject_digest  text        NOT NULL CHECK (subject_digest ~ '^sha256:[0-9a-f]{64}$'),
    predicate_type  text        NOT NULL CHECK (length(predicate_type) BETWEEN 1 AND 255),
    envelope        jsonb       CHECK (envelope IS NULL OR (jsonb_typeof(envelope) = 'object' AND pg_column_size(envelope) <= 4194304)),
    status          text        NOT NULL CHECK (status IN ('pending', 'signed', 'pushed', 'error')),
    pushed_to       text        CHECK (length(pushed_to) <= 500),
    error           text        CHECK (length(error) <= 1000),
    created_at      timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT attestations_signed CHECK (status IN ('pending', 'error') OR envelope IS NOT NULL),
    UNIQUE (scan_id, subject_digest, predicate_type)
);

-- J11–J13, J16 : cibles de déploiement par projet et exécutions. L'appliance
-- déclenche, propose ou promeut ; elle ne détient jamais d'accès à la production.
CREATE TABLE deploy_targets (
    id           uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id   uuid        NOT NULL REFERENCES projects (id) ON DELETE CASCADE,
    kind         text        NOT NULL CHECK (kind IN ('cd-trigger', 'gitops-pr', 'registry-promotion')),
    environment  text        NOT NULL CHECK (environment ~ '^[a-z0-9][a-z0-9-]{0,39}$'),
    on_trigger   text        NOT NULL DEFAULT 'release' CHECK (on_trigger IN ('release', 'branch')),
    config       jsonb       NOT NULL CHECK (jsonb_typeof(config) = 'object' AND pg_column_size(config) <= 65536),
    credential_id uuid       REFERENCES credentials (id) ON DELETE SET NULL,
    auto_merge   boolean     NOT NULL DEFAULT false,
    auto_merge_by bigint     REFERENCES users (id) ON DELETE SET NULL,
    enabled      boolean     NOT NULL DEFAULT true,
    created_by   bigint      REFERENCES users (id) ON DELETE SET NULL,
    created_at   timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT deploy_auto_merge_gitops CHECK (NOT auto_merge OR (kind = 'gitops-pr' AND auto_merge_by IS NOT NULL)),
    UNIQUE (project_id, kind, environment)
);
CREATE TABLE deployments (
    id            uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    target_id     uuid        NOT NULL REFERENCES deploy_targets (id) ON DELETE CASCADE,
    scan_id       uuid        NOT NULL REFERENCES scans (id) ON DELETE CASCADE,
    status        text        NOT NULL CHECK (status IN ('pending', 'running', 'succeeded', 'failed', 'refused')),
    refused_reason text       CHECK (refused_reason IN ('verdict-not-passed', 'target-disabled', 'project-suspended')),
    external_id   text        CHECK (length(external_id) BETWEEN 1 AND 128),
    external_url  text        CHECK (external_url ~ '^https://' AND length(external_url) <= 500),
    error         text        CHECK (length(error) <= 1000),
    created_at    timestamptz NOT NULL DEFAULT now(),
    finished_at   timestamptz,
    CONSTRAINT deployments_refused CHECK ((status = 'refused') = (refused_reason IS NOT NULL)),
    UNIQUE (target_id, scan_id)
);
CREATE INDEX deployments_scan_idx ON deployments (scan_id);

-- Jetons de CD (Jenkins…) et de registre (J11, J13), chiffrés comme les autres.
ALTER TABLE credentials DROP CONSTRAINT credentials_kind_check;
ALTER TABLE credentials ADD CONSTRAINT credentials_kind_check
    CHECK (kind IN ('token', 'ssh-key', 'ai-token', 'app-key', 'webhook-secret', 'oauth-secret', 'deploy-token', 'registry-token'));

-- I6 (notes de sécurité de release) et I19 (seuils suggérés).
ALTER TABLE ai_tasks DROP CONSTRAINT ai_tasks_subject_type_check;
ALTER TABLE ai_tasks ADD CONSTRAINT ai_tasks_subject_type_check
    CHECK (subject_type IN ('finding', 'scan', 'testbed', 'rule', 'module', 'license', 'appliance', 'exception', 'query', 'release', 'gate'));

-- Signature par le helper root avec la clé de l'appliance : rapport de
-- release (§ 7.3) et enveloppe DSSE d'une attestation (J9).
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
    'validate-ruleset', 'sign-release-report', 'sign-attestation'));
