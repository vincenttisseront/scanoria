-- SPDX-License-Identifier: AGPL-3.0-or-later
-- Copyright (C) 2026 Vincent Tisseront
--
-- Scanoria : schéma initial de la base de la console (itération 0.1).
-- Contrat : docs/ARCHITECTURE.md, section « Base de données ».
-- Le lanceur de migrations exécute chaque fichier dans une transaction et
-- insère lui-même la ligne de schema_migrations (version, nom, empreinte).
-- Aucune extension requise.

-- Suivi des migrations appliquées (créée ici, aussi créée par le lanceur s'il
-- la trouve absente : la définition doit rester identique).
CREATE TABLE IF NOT EXISTS schema_migrations (
    version     integer     PRIMARY KEY CHECK (version > 0),
    name        text        NOT NULL CHECK (name ~ '^[0-9]{3}_[a-z0-9_]+\.sql$'),
    checksum    text        NOT NULL CHECK (checksum ~ '^[0-9a-f]{64}$'),  -- SHA-256 du fichier
    applied_at  timestamptz NOT NULL DEFAULT now()
);

-- Rôles : liste fermée, rang croissant (viewer < operator < admin).
CREATE TABLE roles (
    name  text     PRIMARY KEY CHECK (name IN ('viewer', 'operator', 'admin')),
    rank  smallint NOT NULL UNIQUE CHECK (rank > 0)
);
INSERT INTO roles (name, rank) VALUES ('viewer', 10), ('operator', 20), ('admin', 30);

-- Utilisateurs. 0.1 : comptes locaux seulement (ldap et oidc arrivent en 1.0).
-- password_hash au format PHC : $pbkdf2-sha256$i=<itérations>$<sel b64>$<hash b64>
-- (base64 standard sans remplissage, sel de 16 octets, hash de 32 octets).
CREATE TABLE users (
    id                   bigint      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    username             text        NOT NULL CHECK (username ~ '^[a-z0-9][a-z0-9._-]{0,63}$'),
    display_name         text        CHECK (char_length(display_name) <= 128),
    email                text        CHECK (char_length(email) <= 254 AND email ~ '^[^@[:space:]]+@[^@[:space:]]+$'),
    role                 text        NOT NULL DEFAULT 'viewer' REFERENCES roles (name),
    auth_source          text        NOT NULL DEFAULT 'local' CHECK (auth_source IN ('local')),
    password_hash        text        CHECK (password_hash ~ '^\$pbkdf2-sha256\$i=[0-9]{6,7}\$[A-Za-z0-9+/]{22}\$[A-Za-z0-9+/]{43}$'),
    must_change_password boolean     NOT NULL DEFAULT false,
    locale               text        NOT NULL DEFAULT 'fr' CHECK (locale IN ('fr', 'en')),
    is_active            boolean     NOT NULL DEFAULT true,
    failed_logins        integer     NOT NULL DEFAULT 0 CHECK (failed_logins >= 0),
    locked_until         timestamptz,
    last_login_at        timestamptz,
    password_changed_at  timestamptz,
    created_at           timestamptz NOT NULL DEFAULT now(),
    updated_at           timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT users_local_has_password CHECK (auth_source <> 'local' OR password_hash IS NOT NULL)
);
CREATE UNIQUE INDEX users_username_key ON users (username);

-- Sessions : on ne stocke que le SHA-256 (hex) du jeton remis au navigateur.
CREATE TABLE sessions (
    token_hash    text        PRIMARY KEY CHECK (token_hash ~ '^[0-9a-f]{64}$'),
    user_id       bigint      NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    created_at    timestamptz NOT NULL DEFAULT now(),
    last_seen_at  timestamptz NOT NULL DEFAULT now(),
    expires_at    timestamptz NOT NULL,
    revoked_at    timestamptz,
    ip            inet,
    user_agent    text        CHECK (char_length(user_agent) <= 512),
    CONSTRAINT sessions_expiry_after_creation CHECK (expires_at > created_at)
);
CREATE INDEX sessions_user_id_idx ON sessions (user_id);
CREATE INDEX sessions_expires_at_idx ON sessions (expires_at);

-- Journal d'audit : ajout seul (UPDATE interdit par déclencheur). Une ligne
-- cliquable de la console ouvre « details » dans un panneau latéral.
-- action : <domaine>.<verbe>, ex. auth.login, user.create, system.set-hostname.
-- details ne contient jamais de secret (mot de passe, clé, jeton).
CREATE TABLE audit_log (
    id              bigint      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    occurred_at     timestamptz NOT NULL DEFAULT now(),
    actor_user_id   bigint,              -- identifiant figé, sans clé étrangère : un ON DELETE
                                         -- SET NULL serait un UPDATE, interdit ci-dessous
    actor_username  text,                -- copie figée, survit à la suppression du compte
    actor_type      text        NOT NULL DEFAULT 'user' CHECK (actor_type IN ('user', 'system', 'anonymous')),
    actor_ip        inet,
    action          text        NOT NULL CHECK (action ~ '^[a-z][a-z0-9-]*(\.[a-z0-9-]+)+$'),
    target_type     text        CHECK (target_type ~ '^[a-z][a-z0-9_-]*$'),
    target_id       text        CHECK (char_length(target_id) <= 128),
    outcome         text        NOT NULL CHECK (outcome IN ('success', 'failure', 'denied')),
    request_id      uuid,                -- demande au service root éventuelle
    details         jsonb       NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(details) = 'object')
);
CREATE INDEX audit_log_occurred_at_idx ON audit_log (occurred_at DESC);
CREATE INDEX audit_log_actor_idx ON audit_log (actor_user_id, occurred_at DESC);
CREATE INDEX audit_log_action_idx ON audit_log (action, occurred_at DESC);

CREATE FUNCTION audit_log_forbid_update() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'audit_log is append-only';
END;
$$;
CREATE TRIGGER audit_log_no_update BEFORE UPDATE ON audit_log
    FOR EACH ROW EXECUTE FUNCTION audit_log_forbid_update();

-- Réglages propres à la console (durée de session, langue par défaut…).
-- Les réglages système (nom, réseaux, TLS, politique de mise à jour) vivent
-- dans /etc/scanoria, écrits par scanoria-helper, et se lisent dans state.json.
CREATE TABLE appliance_settings (
    key         text        PRIMARY KEY CHECK (key ~ '^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)*$'),
    value       jsonb       NOT NULL,
    updated_at  timestamptz NOT NULL DEFAULT now(),
    updated_by  bigint      REFERENCES users (id) ON DELETE SET NULL
);
INSERT INTO appliance_settings (key, value) VALUES
    ('auth.session_idle_minutes', '60'::jsonb),
    ('auth.session_max_hours', '12'::jsonb),
    ('auth.lockout_threshold', '5'::jsonb),
    ('auth.lockout_minutes', '15'::jsonb),
    ('ui.default_locale', '"fr"'::jsonb);

-- Demandes déposées pour scanoria-helper, et leur résultat une fois ingéré
-- (y compris les actions d'origine « timer » ou « firstboot » sans demande console).
CREATE TABLE helper_requests (
    id            uuid        PRIMARY KEY,
    type          text        NOT NULL CHECK (type IN (
                      'set-hostname', 'set-admin-networks', 'issue-certificate',
                      'import-certificate', 'check-update', 'apply-update',
                      'rollback-update', 'set-update-policy', 'run-selftest')),
    origin        text        NOT NULL DEFAULT 'console' CHECK (origin IN ('console', 'timer', 'firstboot', 'cli')),
    file_name     text        NOT NULL UNIQUE,
    requested_by  bigint      REFERENCES users (id) ON DELETE SET NULL,
    params        jsonb       NOT NULL DEFAULT '{}'::jsonb,  -- secrets retirés (key_pem…)
    status        text        NOT NULL DEFAULT 'pending'
                              CHECK (status IN ('pending', 'running', 'ok', 'error', 'rejected', 'lost')),
    code          text        CHECK (code ~ '^(OK|E_[A-Z_]+)$'),
    message       text,
    output        jsonb,
    created_at    timestamptz NOT NULL DEFAULT now(),
    finished_at   timestamptz
);
CREATE INDEX helper_requests_status_idx ON helper_requests (status, created_at);

-- Historique des mises à jour et retours arrière de l'appliance.
CREATE TABLE update_history (
    id             bigint      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    action         text        NOT NULL CHECK (action IN ('apply', 'rollback', 'auto-rollback')),
    from_version   text        NOT NULL CHECK (from_version ~ '^[0-9]+\.[0-9]+\.[0-9]+$'),
    to_version     text        NOT NULL CHECK (to_version ~ '^[0-9]+\.[0-9]+\.[0-9]+$'),
    channel        text        CHECK (channel IN ('stable', 'prerelease')),
    source         text        CHECK (source IN ('github', 'upload')),
    status         text        NOT NULL CHECK (status IN ('success', 'failed', 'rolled-back')),
    code           text        CHECK (code ~ '^(OK|E_[A-Z_]+)$'),
    request_id     uuid        REFERENCES helper_requests (id) ON DELETE SET NULL,
    initiated_by   bigint      REFERENCES users (id) ON DELETE SET NULL,
    started_at     timestamptz NOT NULL,
    finished_at    timestamptz,
    details        jsonb       NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(details) = 'object')
);
CREATE INDEX update_history_started_at_idx ON update_history (started_at DESC);
