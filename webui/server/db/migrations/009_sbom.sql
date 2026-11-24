-- SPDX-License-Identifier: AGPL-3.0-or-later
-- Copyright (C) 2026 Vincent Tisseront
--
-- 0.5 : SBOM et composants (F3, F8, H5), renseignement sur les vulnérabilités
-- (H3), recoupement entre outils (F16) et embeddings des résultats (I7).

-- Composants relevés dans le SBOM CycloneDX d'une analyse (Syft). Un composant
-- par (analyse, purl) ; recomparé aux bases sans réanalyse (F3).
CREATE TABLE sbom_components (
    scan_id       uuid        NOT NULL REFERENCES scans (id) ON DELETE CASCADE,
    project_id    uuid        NOT NULL REFERENCES projects (id) ON DELETE CASCADE,
    purl          text        NOT NULL CHECK (length(purl) BETWEEN 5 AND 1024 AND purl LIKE 'pkg:%'),
    ecosystem     text        NOT NULL CHECK (length(ecosystem) BETWEEN 1 AND 64),
    name          text        NOT NULL CHECK (length(name) BETWEEN 1 AND 512),
    version       text        CHECK (length(version) <= 256),
    licenses      text[]      NOT NULL DEFAULT '{}',   -- identifiants ou expressions SPDX
    direct        boolean,                             -- dépendance directe, si connu
    paths         text[]      NOT NULL DEFAULT '{}',   -- fichiers de verrouillage d'origine
    published_at  timestamptz,                         -- date de publication de la version (H5), si connue
    PRIMARY KEY (scan_id, purl)
);
CREATE INDEX sbom_components_lookup_idx ON sbom_components (ecosystem, name, version);
CREATE INDEX sbom_components_project_idx ON sbom_components (project_id, scan_id);

-- F8 : politique de licences. Une politique globale (project_id NULL) et des
-- surcharges par projet ; une licence absente des listes est « à revoir ».
CREATE TABLE license_policies (
    id          uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id  uuid        REFERENCES projects (id) ON DELETE CASCADE,
    license     text        NOT NULL CHECK (length(license) BETWEEN 1 AND 128),
    decision    text        NOT NULL CHECK (decision IN ('allowed', 'review', 'denied')),
    reason      text        CHECK (length(reason) <= 2000),
    updated_by  bigint      REFERENCES users (id) ON DELETE SET NULL,
    updated_at  timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX license_policies_key ON license_policies (COALESCE(project_id, '00000000-0000-0000-0000-000000000000'::uuid), license);

-- H3 : renseignement par vulnérabilité (EPSS de FIRST, catalogue KEV de la
-- CISA), alimenté par des modules feed et lu par le quality gate.
CREATE TABLE vuln_intel (
    vuln_id          text        PRIMARY KEY CHECK (vuln_id ~ '^[A-Za-z][A-Za-z0-9]*-[A-Za-z0-9._:-]{1,120}$'),
    epss             real        CHECK (epss IS NULL OR (epss >= 0 AND epss <= 1)),
    epss_percentile  real        CHECK (epss_percentile IS NULL OR (epss_percentile >= 0 AND epss_percentile <= 1)),
    kev              boolean     NOT NULL DEFAULT false,
    kev_added        date,
    aliases          text[]      NOT NULL DEFAULT '{}',
    updated_at       timestamptz NOT NULL DEFAULT now()
);

-- F16 : un même problème vu par plusieurs outils. La clé de recoupement est
-- calculée à l'ingestion (CVE + composant, ou CWE + emplacement) ; le groupe
-- est l'ensemble des résultats d'un projet qui partagent cette clé.
ALTER TABLE findings ADD COLUMN correlation_key text CHECK (correlation_key IS NULL OR correlation_key ~ '^[0-9a-f]{64}$');
CREATE INDEX findings_correlation_idx ON findings (project_id, correlation_key) WHERE correlation_key IS NOT NULL;

-- I7 : embedding d'un résultat (règle, message, contexte masqué), par modèle.
-- Vecteur en real[] : aucune extension requise ; la similarité est calculée
-- par scanoria-ai sur un ensemble borné.
CREATE TABLE ai_embeddings (
    finding_id    uuid        NOT NULL REFERENCES findings (id) ON DELETE CASCADE,
    model_digest  text        NOT NULL CHECK (length(model_digest) BETWEEN 1 AND 128),
    input_hash    text        NOT NULL CHECK (input_hash ~ '^[0-9a-f]{64}$'),
    vector        real[]      NOT NULL CHECK (cardinality(vector) BETWEEN 8 AND 8192),
    created_at    timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (finding_id, model_digest)
);
