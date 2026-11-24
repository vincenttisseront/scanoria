-- SPDX-License-Identifier: AGPL-3.0-or-later
-- Copyright (C) 2026 Vincent Tisseront
--
-- Rôle PostgreSQL du service scanoria-ai (CLAUDE.md § 3.5) et ses droits,
-- appliqués par « scanoria-ai-setup prestart » (ExecStartPre=+ de
-- scanoria-ai.service) en superutilisateur postgres, à chaque démarrage :
-- idempotent, et seule source de vérité de ces droits.
--
-- Le service lit ce dont ses tâches ont besoin, n'écrit que dans les tables
-- ai_*, et ne voit dans credentials que la ligne du jeton IA (politique
-- credentials_ai_token_read, migration 004). Connexion par le socket local,
-- authentification peer : l'utilisateur système scanoria-ai.

\set ON_ERROR_STOP on

DO $$BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'scanoria-ai') THEN
        CREATE ROLE "scanoria-ai" LOGIN;
    END IF;
END$$;
ALTER ROLE "scanoria-ai" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS
    NOINHERIT CONNECTION LIMIT 4;

-- Repartir de zéro : un droit retiré de ce fichier disparaît au démarrage suivant.
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM "scanoria-ai";
REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM "scanoria-ai";
GRANT USAGE ON SCHEMA public TO "scanoria-ai";

-- Lecture seule, colonnes utiles seulement.
GRANT SELECT (version) ON schema_migrations TO "scanoria-ai";
GRANT SELECT (key, value) ON appliance_settings TO "scanoria-ai";
GRANT SELECT (id, slug, name, ai_opt_out, archived_at) ON projects TO "scanoria-ai";
GRANT SELECT (id, project_id, number, ref, commit_sha, status, verdict, verdict_details,
              coverage, plan, error, queued_at) ON scans TO "scanoria-ai";
-- 0.4 : status_by, status_at et status_reason servent aux exemples de pré-tri
-- (I24, tris faits par des personnes du MÊME projet seulement).
GRANT SELECT (id, project_id, tool, rule_id, category, severity, native_severity, title, message,
              path, start_line, end_line, cwe, vuln_ids, package, malicious, secret_type, status, snippet,
              status_by, status_at, status_reason)
    ON findings TO "scanoria-ai";
-- 0.4 : résumé (I5) et diagnostic (I15) d'une analyse ; jamais les journaux
-- eux-mêmes (log_path) : l'extrait masqué arrive par ai_tasks.context.
GRANT SELECT (scan_id, finding_id, is_new) ON scan_findings TO "scanoria-ai";
GRANT SELECT (scan_id, module_id, module_version, status, error_class, attempts, duration_ms, peak_memory_mb)
    ON scan_modules TO "scanoria-ai";
GRANT SELECT (id, kind, secret_enc) ON credentials TO "scanoria-ai";

-- Écritures : tables ai_* seulement.
GRANT SELECT ON ai_tasks TO "scanoria-ai";
-- Insertion limitée aux bancs d'essai qu'il se planifie : statut, sortie,
-- projet et contexte prennent leur valeur par défaut (aucune sortie forgée).
GRANT INSERT (kind, subject_type, subject_id, priority) ON ai_tasks TO "scanoria-ai";
-- Mise à jour limitée à l'état d'exécution : ni le sujet, ni le projet, ni la priorité.
GRANT UPDATE (status, output, error, model, model_digest, input_hash, attempts, started_at, finished_at) ON ai_tasks TO "scanoria-ai";
GRANT SELECT, INSERT, DELETE ON ai_cache TO "scanoria-ai";
GRANT SELECT, INSERT ON ai_calls TO "scanoria-ai";
