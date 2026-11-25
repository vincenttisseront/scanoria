// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// GET /api/openapi.json : description OpenAPI 3.1 minimale de l'API de la console.

import { defineEventHandler } from 'h3'
import { getConfig } from '../utils/config'
import { getRunningVersion } from '../utils/appliance'
import { PROJECT_OPS, projectSchemas } from '../projects/openapi'
import { VIGILANCE_OPS, vigilanceSchemas } from '../vigilance/openapi'

type Role = 'public' | 'viewer' | 'operator' | 'admin'

interface Op { summary: string, role: Role, body?: string, status?: number, token?: boolean }

const OPS: Record<string, Record<string, Op>> = {
  '/api/health': { get: { summary: 'Console health (status, version, db)', role: 'public' } },
  '/api/about': { get: { summary: 'Version, license and source code link (AGPL-3.0-or-later, section 13)', role: 'public' } },
  '/api/openapi.json': { get: { summary: 'This document', role: 'public' } },
  '/api/auth/login': { post: { summary: 'Local account login; sets the session cookie', role: 'public', body: 'Login' } },
  '/api/auth/logout': { post: { summary: 'Revoke the current session', role: 'viewer' } },
  '/api/auth/session': { get: { summary: 'Current user and CSRF token', role: 'public' } },
  '/api/auth/password': { post: { summary: 'Change own password', role: 'viewer', body: 'ChangePassword' } },
  '/api/account': { patch: { summary: 'Own preferences (locale, display name)', role: 'viewer', body: 'AccountUpdate' } },
  '/api/state': { get: { summary: 'State published by the root service (stale after 3 minutes)', role: 'viewer' } },
  '/api/users': {
    get: { summary: 'List users', role: 'admin' },
    post: { summary: 'Create a local user', role: 'admin', body: 'UserCreate', status: 201 },
  },
  '/api/users/{id}': {
    patch: { summary: 'Update a user (role, active, profile)', role: 'admin', body: 'UserUpdate' },
    delete: { summary: 'Delete a user', role: 'admin' },
  },
  '/api/users/{id}/password': { post: { summary: 'Reset a user password', role: 'admin', body: 'PasswordReset' } },
  '/api/audit': { get: { summary: 'Audit log (paginated, filters: action, outcome, actor)', role: 'operator' } },
  '/api/audit/{id}': { get: { summary: 'Audit entry detail', role: 'operator' } },
  '/api/requests': { get: { summary: 'Recent root service requests', role: 'operator' } },
  '/api/requests/{id}': { get: { summary: 'Root service request status and current step', role: 'viewer' } },
  '/api/system/hostname': { post: { summary: 'Request set-hostname', role: 'admin', body: 'set-hostname', status: 202 } },
  '/api/system/admin-networks': { post: { summary: 'Request set-admin-networks', role: 'admin', body: 'set-admin-networks', status: 202 } },
  '/api/system/selftest': { post: { summary: 'Request run-selftest', role: 'admin', body: 'run-selftest', status: 202 } },
  '/api/system/tls/ca': { get: { summary: 'Download the internal CA certificate (PEM)', role: 'viewer' } },
  '/api/system/tls/issue': { post: { summary: 'Request issue-certificate', role: 'admin', body: 'issue-certificate', status: 202 } },
  '/api/system/tls/import': { post: { summary: 'Request import-certificate', role: 'admin', body: 'import-certificate', status: 202 } },
  '/api/system/updates/check': { post: { summary: 'Request check-update', role: 'admin', body: 'check-update', status: 202 } },
  '/api/system/updates/apply': { post: { summary: 'Request apply-update (github or upload)', role: 'admin', body: 'apply-update', status: 202 } },
  '/api/system/updates/rollback': { post: { summary: 'Request rollback-update (N-1, database restored)', role: 'admin', body: 'rollback-update', status: 202 } },
  '/api/system/updates/policy': { post: { summary: 'Request set-update-policy', role: 'admin', body: 'set-update-policy', status: 202 } },
  '/api/system/updates/history': { get: { summary: 'Update and rollback history', role: 'viewer' } },
  '/api/system/updates/uploads': { post: { summary: 'Start a manual upload of release files', role: 'admin', status: 201 } },
  '/api/system/updates/uploads/{id}/{name}': {
    put: { summary: 'Upload one release file (raw body): release.json, SHA256SUMS, SHA256SUMS.sig, scanoria-X.Y.Z.tar.zst', role: 'admin', status: 201 },
  },
  '/api/system/offline': { get: { summary: 'Offline state: appliance key, trusted keys, exported bundles, schedule, mirror, Dependency-Track sources, history', role: 'operator' } },
  '/api/system/offline/keys': { post: { summary: 'Request trust-key (add a bundle signing key; fingerprint confirmed)', role: 'admin', body: 'trust-key', status: 202 } },
  '/api/system/offline/keys/remove': { post: { summary: 'Request trust-key (remove a bundle signing key)', role: 'admin', body: 'trust-key', status: 202 } },
  '/api/system/offline/export': { post: { summary: 'Request export-bundle (signed offline bundle, or size estimate with dry_run)', role: 'admin', body: 'export-bundle', status: 202 } },
  '/api/system/offline/schedule': { post: { summary: 'Request export-bundle (periodic export settings)', role: 'admin', body: 'export-bundle', status: 202 } },
  '/api/system/offline/uploads': { post: { summary: 'Start the upload of an offline bundle', role: 'admin', status: 201 } },
  '/api/system/offline/uploads/{id}': { put: { summary: 'Upload the bundle archive (raw body, streamed, 64 GiB at most)', role: 'admin', status: 201 } },
  '/api/system/offline/import': { post: { summary: 'Request import-bundle (verified before any change)', role: 'admin', body: 'import-bundle', status: 202 } },
  '/api/system/offline/mirror': { post: { summary: 'Request set-mirror (declare or remove the mirror appliance, F17)', role: 'admin', body: 'set-mirror', status: 202 } },
  '/api/system/offline/bundles/{name}': { get: { summary: 'Download an exported bundle', role: 'admin' } },
  '/api/catalog': { get: { summary: 'Catalog modules, install state, compatibility, packs, dependency graph, recommended selection, operations', role: 'viewer' } },
  '/api/catalog/feeds/refresh': { post: { summary: 'Request refresh-feeds (download the vulnerability databases of installed feeds now)', role: 'admin', body: 'refresh-feeds', status: 202 } },
  '/api/catalog/refresh': { post: { summary: 'Request refresh-catalog (download and verify the signed index)', role: 'admin', body: 'refresh-catalog', status: 202 } },
  '/api/catalog/plan': { post: { summary: 'Install plan without side effect: added dependencies, licenses to accept, resource checks', role: 'viewer', body: 'CatalogPlan' } },
  '/api/catalog/install': { post: { summary: 'Request install-modules for modules or a pack (409 E_PLAN when blocked)', role: 'admin', body: 'CatalogInstall', status: 202 } },
  '/api/catalog/modules/{id}': { get: { summary: 'Module detail: versions, options schema, state, plan, dependents, operations', role: 'viewer' } },
  '/api/catalog/modules/{id}/state': { post: { summary: 'Request set-module-state (enable or disable)', role: 'admin', body: 'ModuleState', status: 202 } },
  '/api/catalog/modules/{id}/update': { post: { summary: 'Request update-module (latest version by default)', role: 'admin', body: 'ModuleUpdate', status: 202 } },
  '/api/catalog/modules/{id}/uninstall': { post: { summary: 'Request uninstall-module (409 E_DEPENDENTS when another module needs it)', role: 'admin', body: 'ModuleUninstall', status: 202 } },
  '/api/catalog/modules/{id}/backup': { post: { summary: 'Request backup-module: database and volumes of a service or runner module (409 E_NOT_PERMANENT otherwise)', role: 'admin', body: 'ModuleBackup', status: 202 } },
  '/api/catalog/modules/{id}/restore': { post: { summary: 'Request restore-module from a listed backup of the installed version (404 E_BACKUP_NOT_FOUND, 409 E_BACKUP_INVALID)', role: 'admin', body: 'ModuleRestore', status: 202 } },
  '/api/catalog/modules/{id}/admin-password': { post: { summary: 'Request reset-service-admin: new random admin password of a service set up by the appliance (SonarQube)', role: 'admin', status: 202 } },
  '/api/catalog/modules/{id}/admin-password/reveal': { post: { summary: 'Admin password of a finished reset-service-admin, returned once to its requester (410 E_GONE afterwards)', role: 'admin', body: 'AdminPasswordReveal' } },
  '/api/ai/status': { get: { summary: 'AI connector (external Ollama): pinned address, models chosen per task and why, testbed, circuit breaker, latency', role: 'operator' } },
  '/api/ai/calls': { get: { summary: 'AI call log (metadata only, never content)', role: 'operator' } },
  '/api/ai/connector': { post: { summary: 'Request set-ai-endpoint: enable or change the Ollama connector (confirmed: true required)', role: 'admin', body: 'AiConnector', status: 202 } },
  '/api/ai/disconnect': { post: { summary: 'Request set-ai-endpoint: remove the connector and close its firewall rule', role: 'admin', status: 202 } },
  '/api/ai/probe': { post: { summary: 'Rediscover the models of the AI server', role: 'admin', status: 202 } },
  '/api/ai/models': { put: { summary: 'Choose the text generation model for all tasks (default), the embedding model (embedding) or a model per task; null goes back to automatic', role: 'admin', body: 'AiModels' } },
  '/api/ai/explain': { post: { summary: 'Interactive AI request: explanation (I2, I9), pre-triage (I3), scan summary (I5), secret type (I14), failure diagnosis (I15), rule translation (I17)', role: 'viewer', body: 'AiExplain', status: 202 } },
  '/api/ai/output': { get: { summary: 'Latest AI output for a finding, a scan or a rule key, marked as AI with model and digest, with the caller\'s feedback', role: 'viewer' } },
  '/api/ai/suggestions': { get: { summary: 'Latest AI pre-triage (I3) or secret type (I14) for up to 200 findings; suggestions only, never a status change', role: 'viewer' } },
  '/api/ai/rule-key': { get: { summary: 'Translation key (tool:version:rule) of a finding\'s rule (I17); null for secrets and opted-out projects', role: 'viewer' } },
  '/api/ai/feedback': { post: { summary: 'Thumbs up/down and optional correction on an AI output (I24); never sent to the model', role: 'viewer', body: 'AiFeedback' } },
  '/api/ai/agreement': { get: { summary: 'AI/human agreement over 90 days per task and model (I24)', role: 'operator' } },
  '/api/ai/diagnosis/proposal': { get: { summary: 'Safe setting proposed for a failed scan (I15), recomputed from facts, never taken from the AI output', role: 'operator' } },
  '/api/ai/diagnosis/apply': { post: { summary: 'Apply the proposed module timeout (409 E_AI_STALE if it changed); audited', role: 'operator', body: 'AiDiagnosisApply' } },
  '/api/ai/similar': { get: { summary: 'Similar findings of the same project (I7, embeddings), with the state of the feature; a suggestion only, never part of the quality gate', role: 'viewer' } },
  '/api/ai/appliance/subjects': { get: { summary: 'Appliance subjects an AI diagnosis can explain now (I16): alerts, last failed self-test, failed updates and modules; empty without connector', role: 'admin' } },
  '/api/ai/appliance/diagnosis': {
    get: { summary: 'Latest AI diagnosis of an appliance subject (I16), marked as AI with model and digest; enabled false without connector', role: 'admin' },
    post: { summary: 'Request the AI diagnosis of an appliance subject (I16): masked, neutralised context of at most 16 KB; proposes one console action, never runs it', role: 'admin', body: 'AiApplianceDiagnosis', status: 202 },
  },
  '/api/ai/license-key': { get: { summary: 'Key (licence|project licence) of the AI explanation of a component licence (I18); null for opted-out projects', role: 'viewer' } },
  '/api/ai/search': {
    get: { summary: 'Natural-language search (I8): connector state, or the structured filters proposed for a phrase (subject_id), revalidated and limited to the caller\'s rights; never SQL', role: 'viewer' },
    post: { summary: 'Translate a phrase into structured filters of the Findings or Components pages (I8); 200 without connector', role: 'viewer', status: 202 },
  },
  '/api/ai/rules': {
    get: { summary: 'Rule generator (I12): connector state, or the rule proposed for a subject with its test on generated positive and negative samples', role: 'operator' },
    post: { summary: 'Generate an Opengrep rule, gitleaks pattern or Checkov policy from a finding, a code sample or a sentence (I12); 200 without connector', role: 'operator', status: 202 },
  },
  '/api/ai/rules/rulesets': { get: { summary: 'Managed rulesets (G4) a generated rule can be saved into, for its engine', role: 'admin' } },
  '/api/ai/rules/test': { post: { summary: 'Test a generated rule in a confined container on its positive and negative samples (I12)', role: 'operator' } },
  '/api/ai/rules/save': { post: { summary: 'Save a tested generated rule as a new ruleset version with origin ai, after explicit admin confirmation (I12); audited', role: 'admin' } },
  '/api/dns': { get: { summary: 'Last DNS check and records to create (<name> and *.<name>)', role: 'viewer' } },
  '/api/dns/check': { post: { summary: 'Request check-dns', role: 'admin', body: 'check-dns', status: 202 } },
  '/api/gates': {
    get: { summary: 'Quality gates with the number of assigned projects', role: 'viewer' },
    post: { summary: 'Create a quality gate by copying the rules of « defaut » (or copy_from)', role: 'admin', body: 'GateCreate', status: 201 },
  },
  '/api/gates/{id}': {
    get: { summary: 'Quality gate: rules, assigned projects, locked rules (H4, G13)', role: 'viewer' },
    patch: { summary: 'Update the rules (GateRules; block_malicious and inconclusive_blocks stay true)', role: 'admin', body: 'GateUpdate' },
    delete: { summary: 'Delete a gate (never the built-in one, never a gate in use)', role: 'admin', status: 204 },
  },
  '/api/gates/{id}/assign': { post: { summary: 'Assign the gate to a project (next scans)', role: 'admin', body: 'GateAssign' } },
  '/api/gates/projects/{id}': { get: { summary: 'CI integration of a project: gate, badge, active tokens', role: 'viewer' } },
  '/api/gates/client': { get: { summary: 'Download the scanoria-scan CI client (POSIX sh, curl, jq)', role: 'public' } },
  '/api/projects/{id}/tokens': {
    get: { summary: 'Project API tokens (prefix and dates, never the value)', role: 'operator' },
    post: { summary: 'Create a project API token scn_…; the value is returned once', role: 'operator', body: 'TokenCreate', status: 201 },
  },
  '/api/projects/{id}/tokens/{token}': { delete: { summary: 'Revoke a project API token', role: 'operator' } },
  '/api/projects/{id}/scans': {
    post: { summary: 'Queue a scan {ref, profile?} → 202 {scan_id, number, url}; API token of the project (trigger api) or operator session', role: 'operator', body: 'ProjectScanCreate', status: 202, token: true },
  },
  '/api/projects/{id}/results': {
    post: { summary: 'Upload external results (J6): raw SARIF 2.1.0 or CycloneDX 1.5/1.6 body, 32 MiB max; query ref, commit, tool, version, category (default sast); creates an external scan, findings marked external, gate evaluated (not a release verdict) → 201 {scan_id, number, module, source, results, new, components, verdict}; 413 too large, 415 unknown format, 422 invalid document {issues}; 429 E_EXTERNAL_BUSY (one upload per project at a time, Retry-After)', role: 'operator', status: 201, token: true },
  },
  '/api/scans/{id}/verdict': {
    get: { summary: 'Scan state, verdict and ordered reasons (VerdictDetails), optional ai_summary (I9); ?locale=fr|en', role: 'viewer', token: true },
  },
  '/api/badges/{name}': { get: { summary: 'Latest verdict badge (appliance scans only, never an external upload), /api/badges/<project slug>.svg (404 unless enabled for the project)', role: 'public' } },
  '/api/badges/projects/{id}': { put: { summary: 'Enable or disable the public badge of a project (disabled by default)', role: 'operator', body: 'BadgeUpdate' } },
  ...PROJECT_OPS,
  ...VIGILANCE_OPS,
  '/api/scans': {
    get: { summary: 'Scan queue (status=active, in worker order) or history (filters: project, status, verdict, trigger; paginated)', role: 'viewer' },
    post: { summary: 'Queue a manual scan {project_id, ref?, profile?}; 200 when merged into an identical queued scan', role: 'operator', body: 'ScanCreate', status: 202 },
  },
  '/api/scans/{id}': { get: { summary: 'Scan detail: status, frozen plan (G11), modules, coverage (G15), queue position, raw verdict', role: 'viewer' } },
  '/api/scans/{id}/cancel': { post: { summary: 'Cancel a queued, dispatched or running scan (409 E_SCAN_STATE when finished)', role: 'operator' } },
  '/api/scans/{id}/retry': { post: { summary: 'Queue a new scan of the same project, ref and profile', role: 'operator', status: 202 } },
  '/api/scans/{id}/replay': { post: { summary: 'Replay identically (G11): same commit and frozen plan', role: 'operator', status: 202 } },
  '/api/scans/{id}/modules/{module}/log': { get: { summary: 'Full module log (text/plain, G20): secrets masked, size bounded, truncation marked; audited', role: 'operator' } },
  '/api/usage/modules': { get: { summary: 'Real usage per installed module (F14) over 30 days and modules unused for N days (query unused_days, default 30); modules required by another are never unused', role: 'viewer' } },
  '/api/usage/modules/{id}': { get: { summary: 'Usage of one installed module (F14): scanner statistics, or memory, CPU and disk series over 7 and 30 days', role: 'viewer' } },
  '/api/health/scans': { get: { summary: 'Scan health per tool over 7 and 30 days (G20): failures by class, timeouts, out of memory, durations; recent failed scans', role: 'viewer' } },
  '/api/findings': { get: { summary: 'Unified findings (filters: project_id, scan_id, tool, severity, category, status, is_new, secret, malicious, q; 0.5: epss_min (0.01, 0.1, 0.5), kev=true, grouped=true for one row per correlation group (F16). grouped defaults to false in the API for backward compatibility; the console sends grouped=true by default. Each item carries epss, epss_percentile (EPSS, FIRST.org), kev, kev_added, correlation_key and group; paginated)', role: 'viewer' } },
  '/api/findings/summary': { get: { summary: 'Open findings per project and severity, secrets to revoke, malicious packages', role: 'viewer' } },
  '/api/findings/{id}': { get: { summary: 'Finding detail (masked snippet, scans where it appears); never a secret value', role: 'viewer' } },
  '/api/findings/{id}/status': { post: { summary: 'Triage a finding (accepted needs reason and end date; refused 409 E_MALICIOUS for a malicious package)', role: 'operator', body: 'FindingStatus' } },
  '/api/findings/{id}/secret': { post: { summary: 'Secret follow-up (to-revoke, revoked, false-positive) with date and author', role: 'operator', body: 'SecretState' } },
  '/api/findings/{id}/group': { get: { summary: 'Group of correlated findings (F16): tools, confirmations (distinct tools), member findings; null without correlation. /api/findings also accepts epss_min, kev and grouped (0.5)', role: 'viewer' } },
  '/api/findings/{id}/group-status': { post: { summary: 'Triage every finding of a correlated group (one audit line per finding; 409 E_MALICIOUS if a member is a malicious package)', role: 'operator', body: 'FindingStatus' } },
  '/api/intel/status': { get: { summary: 'EPSS and KEV import state (H3): CVE count, import date, published database date', role: 'viewer' } },
  '/api/exceptions': {
    get: { summary: 'Project exceptions (query project_id; all=true includes expired and revoked)', role: 'viewer' },
    post: { summary: 'Create a dated exception (at most one year; refused 409 E_MALICIOUS for MAL- advisories)', role: 'operator', body: 'ExceptionCreate', status: 201 },
  },
  '/api/exceptions/{id}': { delete: { summary: 'Revoke an exception (history kept)', role: 'operator' } },
  '/api/severity-maps': {
    get: { summary: 'Severity normalization per module, with origin value', role: 'viewer' },
    patch: { summary: 'Change a normalized severity, or reset it to its origin value (severity null)', role: 'admin', body: 'SeverityMapUpdate' },
  },
  '/api/scans/{id}/agent-inventory': { get: { summary: 'Agent workflow inventory of a scan (K7, Agentic Radar): frameworks, agents, tools, MCP servers; null without one', role: 'viewer' } },
  '/api/scans/{id}/sbom': { get: { summary: 'SBOM components of a scan (contract 14): filters q, ecosystem, license, direct; sort name, ecosystem, version, license, direct; paginated (page, per_page ≤ 200); facets, coverage and Dependency-Track link', role: 'viewer' } },
  '/api/scans/{id}/sbom/export': { get: { summary: 'SBOM of a scan as a CycloneDX 1.6 JSON file, rebuilt from the stored components; audited', role: 'viewer' } },
  // 0.5 (B) : recherche transverse (F3), politique de licences (F8).
  '/api/components': { get: { summary: 'Cross-project component search (F3) in the latest SBOM of each visible project: purl, name, ecosystem, version, version_from/version_to, vuln (aliases included); grouped by project, cursor pagination', role: 'viewer' } },
  '/api/components/export.csv': { get: { summary: 'Same search as /api/components, whole result as CSV (formulas neutralized)', role: 'viewer' } },
  '/api/components/exposures': { get: { summary: 'Projects newly affected by a re-correlation after a database update, over 7 days', role: 'viewer' } },
  '/api/licenses/policy': {
    get: { summary: 'License policy (F8): automatic defaults, global decisions, decisions of a project (query project_id)', role: 'viewer' },
    put: { summary: 'Set a license decision (allowed, review, denied), global or per project; audited with the previous value', role: 'admin' },
  },
  '/api/licenses/policy/{id}': { delete: { summary: 'Remove a license decision (back to the global or default decision); audited', role: 'admin' } },
  '/api/licenses/evaluate': { post: { summary: 'Evaluate an SPDX expression against the policy (OR = best, AND = worst, WITH = base license)', role: 'viewer' } },
  '/api/licenses/scans/{id}': { get: { summary: 'License decision of each SBOM component of a scan, with counts', role: 'viewer' } },
}

const HELPER_BODIES = [
  'set-hostname', 'set-admin-networks', 'issue-certificate', 'import-certificate', 'check-update',
  'apply-update', 'rollback-update', 'set-update-policy', 'run-selftest', 'refresh-catalog', 'check-dns',
  'refresh-feeds',
]

const PLAN_PROPERTIES = {
  modules: {
    type: 'array', minItems: 1, maxItems: 32,
    items: {
      type: 'object', additionalProperties: false, required: ['id'],
      properties: {
        id: { type: 'string', pattern: '^[a-z0-9][a-z0-9-]{1,40}$' },
        version: { type: 'string', description: 'Latest version of the index by default' },
        options: { type: 'object', description: 'Validated against the module options schema; defaults fill the rest' },
      },
    },
  },
  pack: { type: 'string', pattern: '^[a-z0-9][a-z0-9-]{1,40}$' },
}

export default defineEventHandler(async () => {
  const version = await getRunningVersion(getConfig().versionFile)
  const paths: Record<string, Record<string, unknown>> = {}
  for (const [path, ops] of Object.entries(OPS)) {
    paths[path] = {}
    for (const [method, op] of Object.entries(ops)) {
      const params = [...path.matchAll(/\{([a-z]+)\}/g)].map(m => ({ name: m[1], in: 'path', required: true, schema: { type: 'string' } }))
      paths[path]![method] = {
        'summary': op.summary,
        'x-scanoria-role': op.role,
        ...(params.length ? { parameters: params } : {}),
        ...(op.role === 'public' ? { security: [] } : {}),
        ...(op.token ? { security: [{ session: [] }, { apiToken: [] }] } : {}),
        ...(op.body
          ? {
              requestBody: {
                required: true,
                content: {
                  'application/json': {
                    schema: HELPER_BODIES.includes(op.body)
                      ? { description: `params of /usr/share/scanoria/requests/${op.body}.schema.json` }
                      : { $ref: `#/components/schemas/${op.body}` },
                  },
                },
              },
            }
          : {}),
        'responses': {
          [String(op.status ?? 200)]: { description: 'Success' },
          default: { description: 'Error', content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } } },
        },
      }
    }
  }
  return {
    openapi: '3.1.0',
    info: {
      title: 'Scanoria console API',
      version,
      license: { name: 'AGPL-3.0-or-later', identifier: 'AGPL-3.0-or-later' },
      description: 'Session cookie authentication. Every non-GET request needs the X-CSRF-Token header returned by GET /api/auth/session. Roles: viewer < operator < admin.',
    },
    security: [{ session: [] }],
    paths,
    components: {
      securitySchemes: {
        session: { type: 'apiKey', in: 'cookie', name: '__Host-scanoria_session' },
        apiToken: { type: 'http', scheme: 'bearer', description: 'Project API token scn_… (CI routes only: queue a scan, read a verdict)' },
      },
      schemas: {
        AiConnector: {
          type: 'object', additionalProperties: false, required: ['url', 'confirmed'],
          properties: {
            url: { type: 'string', maxLength: 300, pattern: '^https?://' },
            allow_insecure: { type: 'boolean' },
            token: { type: ['string', 'null'], maxLength: 4096 },
            ca_pem: { type: ['string', 'null'], maxLength: 16384 },
            skip_tls_verify: { type: 'boolean', description: 'https only, not with ca_pem: accept the server certificate without verifying it (self-signed). Default: verified' },
            confirmed: { const: true },
          },
        },
        AiModels: {
          type: 'object', additionalProperties: false, required: ['models'],
          properties: { models: { type: 'object', description: 'Keys: default, embedding, or a text generation task kind', additionalProperties: { type: ['string', 'null'], maxLength: 200 } } },
        },
        AiExplain: {
          type: 'object', additionalProperties: false, required: ['kind', 'subject_id'],
          properties: {
            kind: { enum: ['explain-finding', 'explain-verdict', 'triage-finding', 'summarize-scan', 'classify-secret', 'diagnose-scan', 'translate-rule'] },
            subject_id: { type: 'string', maxLength: 400, description: 'Finding or scan UUID; tool:version:rule key for translate-rule' },
            locale: { enum: ['fr', 'en'] },
          },
        },
        AiFeedback: {
          type: 'object', additionalProperties: false, required: ['task_id', 'vote'],
          properties: { task_id: { type: 'string', format: 'uuid' }, vote: { enum: [1, -1] }, correction: { type: ['string', 'null'], minLength: 1, maxLength: 4000 } },
        },
        AiApplianceDiagnosis: {
          type: 'object', additionalProperties: false, required: ['subject_id'],
          properties: {
            subject_id: { type: 'string', maxLength: 200, description: 'alert:update-rollback | alert:tls-expiry | alert:service:<name> | alert:disk:<mount> | selftest:last | update:<n> | install:<module>' },
            locale: { enum: ['fr', 'en'] },
          },
        },
        AiDiagnosisApply: {
          type: 'object', additionalProperties: false, required: ['scan_id', 'module', 'proposed_s'],
          properties: { scan_id: { type: 'string', format: 'uuid' }, module: { type: 'string', pattern: '^[a-z0-9][a-z0-9-]{1,40}$' }, proposed_s: { type: 'integer', minimum: 60, maximum: 86400 } },
        },
        Error: {
          type: 'object',
          properties: {
            statusCode: { type: 'integer' },
            statusMessage: { type: 'string' },
            data: { type: 'object', properties: { code: { type: 'string' } }, required: ['code'] },
          },
        },
        Login: {
          type: 'object', additionalProperties: false, required: ['username', 'password'],
          properties: { username: { type: 'string', maxLength: 64 }, password: { type: 'string', maxLength: 1024 } },
        },
        ChangePassword: {
          type: 'object', additionalProperties: false, required: ['current_password', 'new_password'],
          properties: { current_password: { type: 'string' }, new_password: { type: 'string', minLength: 12, maxLength: 1024 } },
        },
        AccountUpdate: {
          type: 'object', additionalProperties: false,
          properties: { locale: { enum: ['fr', 'en'] }, display_name: { type: ['string', 'null'], maxLength: 128 } },
        },
        UserCreate: {
          type: 'object', additionalProperties: false, required: ['username', 'role', 'password'],
          properties: {
            username: { type: 'string', pattern: '^[a-z0-9][a-z0-9._-]{0,63}$' },
            display_name: { type: ['string', 'null'], maxLength: 128 },
            email: { type: ['string', 'null'], maxLength: 254 },
            role: { enum: ['viewer', 'operator', 'admin'] },
            locale: { enum: ['fr', 'en'] },
            password: { type: 'string', minLength: 12, maxLength: 1024 },
          },
        },
        UserUpdate: {
          type: 'object', additionalProperties: false,
          properties: {
            display_name: { type: ['string', 'null'] }, email: { type: ['string', 'null'] },
            role: { enum: ['viewer', 'operator', 'admin'] }, locale: { enum: ['fr', 'en'] }, is_active: { type: 'boolean' },
          },
        },
        CatalogPlan: {
          type: 'object', additionalProperties: false, description: 'Exactly one of modules or pack',
          properties: PLAN_PROPERTIES,
        },
        CatalogInstall: {
          type: 'object', additionalProperties: false, description: 'Exactly one of modules or pack',
          properties: {
            ...PLAN_PROPERTIES,
            accept_licenses: { type: 'array', maxItems: 32, items: { type: 'string' }, description: 'Modules whose license restrictions are explicitly accepted' },
          },
        },
        ScanCreate: {
          type: 'object', additionalProperties: false, required: ['project_id'],
          properties: {
            project_id: { type: 'string', format: 'uuid' },
            ref: { type: 'string', maxLength: 255, description: 'Default branch of the project when absent' },
            profile: { type: 'string', pattern: '^[a-z0-9][a-z0-9-]{0,62}$', description: 'Project profile when absent' },
          },
        },
        ModuleState: { type: 'object', additionalProperties: false, required: ['enabled'], properties: { enabled: { type: 'boolean' } } },
        ModuleUpdate: { type: 'object', additionalProperties: false, properties: { version: { type: 'string' } } },
        ModuleUninstall: { type: 'object', additionalProperties: false, required: ['keep_data'], properties: { keep_data: { type: 'boolean' } } },
        ModuleBackup: { type: 'object', additionalProperties: false, properties: {} },
        ModuleRestore: { type: 'object', additionalProperties: false, required: ['backup'], properties: { backup: { type: 'string', pattern: '^[0-9]{8}T[0-9]{6}Z(-[0-9])?$' } } },
        AdminPasswordReveal: { type: 'object', additionalProperties: false, required: ['request_id'], properties: { request_id: { type: 'string', format: 'uuid' } } },
        GateCreate: {
          type: 'object', additionalProperties: false, required: ['slug'],
          properties: { slug: { type: 'string', pattern: '^[a-z0-9][a-z0-9-]{0,62}$' }, copy_from: { type: 'string', format: 'uuid' } },
        },
        GateUpdate: {
          type: 'object', additionalProperties: false, required: ['rules'],
          properties: {
            rules: {
              type: 'object', additionalProperties: false,
              properties: {
                new_code_only: { type: 'boolean' },
                max_secrets: { type: 'integer', minimum: 0 },
                vuln_block_from: { enum: ['critical', 'high', 'medium', 'low', 'info', null] },
                sast_block_from: { enum: ['critical', 'high', 'medium', 'low', 'info', null] },
                iac_block_from: { enum: ['critical', 'high', 'medium', 'low', 'info', null] },
                block_malicious: { const: true },
                inconclusive_blocks: { const: true },
              },
            },
          },
        },
        GateAssign: { type: 'object', additionalProperties: false, required: ['project_id'], properties: { project_id: { type: 'string', format: 'uuid' } } },
        TokenCreate: {
          type: 'object', additionalProperties: false, required: ['name'],
          properties: { name: { type: 'string', minLength: 1, maxLength: 100 }, expires_in_days: { type: ['integer', 'null'], minimum: 1, maximum: 3650 } },
        },
        ProjectScanCreate: {
          type: 'object', additionalProperties: false, required: ['ref'],
          properties: { ref: { type: 'string', minLength: 1, maxLength: 255 }, profile: { type: 'string', pattern: '^[a-z0-9][a-z0-9-]{0,62}$' } },
        },
        BadgeUpdate: { type: 'object', additionalProperties: false, required: ['enabled'], properties: { enabled: { type: 'boolean' } } },
        PasswordReset: {
          type: 'object', additionalProperties: false, required: ['password'],
          properties: { password: { type: 'string', minLength: 12, maxLength: 1024 }, must_change_password: { type: 'boolean' } },
        },
        ...projectSchemas(),
        ...vigilanceSchemas(),
        FindingStatus: {
          type: 'object', additionalProperties: false, required: ['status'],
          properties: {
            status: { enum: ['new', 'confirmed', 'false-positive', 'accepted'] },
            reason: { type: 'string', maxLength: 2000, description: 'Required for false-positive and accepted' },
            until: { type: 'string', format: 'date', description: 'Required for accepted, at most one year ahead' },
          },
        },
        SecretState: { type: 'object', additionalProperties: false, required: ['state'], properties: { state: { enum: ['to-revoke', 'revoked', 'false-positive'] } } },
        ExceptionCreate: {
          type: 'object', additionalProperties: false, required: ['project_id', 'kind', 'target', 'reason', 'expires_on'],
          properties: {
            project_id: { type: 'string', format: 'uuid' },
            kind: { enum: ['path', 'rule', 'vuln', 'finding', 'module'] },
            target: { type: 'object', description: 'path {glob, tool?}; rule {rule_id, tool?}; vuln {vuln_id, package?}; finding {finding_id}; module {module_id}' },
            reason: { type: 'string', minLength: 3, maxLength: 2000 },
            expires_on: { type: 'string', format: 'date' },
          },
        },
        SeverityMapUpdate: {
          type: 'object', additionalProperties: false, required: ['module_id', 'native', 'severity'],
          properties: {
            module_id: { type: 'string', pattern: '^[a-z0-9][a-z0-9-]{1,40}$' },
            native: { type: 'string', maxLength: 64 },
            severity: { enum: ['critical', 'high', 'medium', 'low', 'info', null] },
          },
        },
      },
    },
  }
})
