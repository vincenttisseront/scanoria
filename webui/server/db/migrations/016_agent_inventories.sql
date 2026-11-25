-- SPDX-License-Identifier: AGPL-3.0-or-later
-- Copyright (C) 2026 Vincent Tisseront
--
-- 0.7, chantier F (K7) : inventaire des workflows d'agents d'une analyse,
-- conservé au-delà de la rétention du runner, affiché sur l'analyse et repris
-- par la cartographie de la surface d'attaque (I22, 0.10).

CREATE TABLE agent_inventories (
    scan_id        uuid        PRIMARY KEY REFERENCES scans (id) ON DELETE CASCADE,
    project_id     uuid        NOT NULL REFERENCES projects (id) ON DELETE CASCADE,
    module_version text        NOT NULL CHECK (length(module_version) BETWEEN 1 AND 64),
    frameworks     text[]      NOT NULL DEFAULT '{}'
        CHECK (frameworks <@ ARRAY['langgraph', 'crewai', 'n8n', 'openai-agents', 'autogen']::text[]),
    inventory      jsonb       NOT NULL
        CHECK (jsonb_typeof(inventory) = 'object' AND octet_length(inventory::text) <= 1048576),
    created_at     timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX agent_inventories_project ON agent_inventories (project_id, created_at DESC);
