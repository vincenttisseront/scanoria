// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// GET /api/openapi.json : description OpenAPI 3.1 minimale de l'API de la console.

import { defineEventHandler } from 'h3'
import { getConfig } from '../utils/config'
import { getRunningVersion } from '../utils/appliance'

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
  '/api/catalog': { get: { summary: 'Catalog modules, install state, compatibility, packs, dependency graph, recommended selection, operations', role: 'viewer' } },
  '/api/catalog/refresh': { post: { summary: 'Request refresh-catalog (download and verify the signed index)', role: 'admin', body: 'refresh-catalog', status: 202 } },
  '/api/catalog/plan': { post: { summary: 'Install plan without side effect: added dependencies, licenses to accept, resource checks', role: 'viewer', body: 'CatalogPlan' } },
  '/api/catalog/install': { post: { summary: 'Request install-modules for modules or a pack (409 E_PLAN when blocked)', role: 'admin', body: 'CatalogInstall', status: 202 } },
  '/api/catalog/modules/{id}': { get: { summary: 'Module detail: versions, options schema, state, plan, dependents, operations', role: 'viewer' } },
  '/api/catalog/modules/{id}/state': { post: { summary: 'Request set-module-state (enable or disable)', role: 'admin', body: 'ModuleState', status: 202 } },
  '/api/catalog/modules/{id}/update': { post: { summary: 'Request update-module (latest version by default)', role: 'admin', body: 'ModuleUpdate', status: 202 } },
  '/api/catalog/modules/{id}/uninstall': { post: { summary: 'Request uninstall-module (409 E_DEPENDENTS when another module needs it)', role: 'admin', body: 'ModuleUninstall', status: 202 } },
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
    post: { summary: 'Queue a scan {ref, profile?} → 202 {scan_id, number, url}; API token of the project (trigger api) or operator session', role: 'operator', body: 'ScanCreate', status: 202, token: true },
  },
  '/api/scans/{id}/verdict': {
    get: { summary: 'Scan state, verdict and ordered reasons (VerdictDetails), optional ai_summary (I9); ?locale=fr|en', role: 'viewer', token: true },
  },
  '/api/badges/{name}': { get: { summary: 'Latest verdict badge, /api/badges/<project slug>.svg (404 unless enabled for the project)', role: 'public' } },
  '/api/badges/projects/{id}': { put: { summary: 'Enable or disable the public badge of a project (disabled by default)', role: 'operator', body: 'BadgeUpdate' } },
  '/api/findings': { get: { summary: 'Unified findings (filters: project_id, scan_id, tool, severity, category, status, is_new, secret, malicious, q; paginated)', role: 'viewer' } },
  '/api/findings/summary': { get: { summary: 'Open findings per project and severity, secrets to revoke, malicious packages', role: 'viewer' } },
  '/api/findings/{id}': { get: { summary: 'Finding detail (masked snippet, scans where it appears); never a secret value', role: 'viewer' } },
  '/api/findings/{id}/status': { post: { summary: 'Triage a finding (accepted needs reason and end date; refused 409 E_MALICIOUS for a malicious package)', role: 'operator', body: 'FindingStatus' } },
  '/api/findings/{id}/secret': { post: { summary: 'Secret follow-up (to-revoke, revoked, false-positive) with date and author', role: 'operator', body: 'SecretState' } },
  '/api/exceptions': {
    get: { summary: 'Project exceptions (query project_id; all=true includes expired and revoked)', role: 'viewer' },
    post: { summary: 'Create a dated exception (at most one year; refused 409 E_MALICIOUS for MAL- advisories)', role: 'operator', body: 'ExceptionCreate', status: 201 },
  },
  '/api/exceptions/{id}': { delete: { summary: 'Revoke an exception (history kept)', role: 'operator' } },
  '/api/severity-maps': {
    get: { summary: 'Severity normalization per module, with origin value', role: 'viewer' },
    patch: { summary: 'Change a normalized severity, or reset it to its origin value (severity null)', role: 'admin', body: 'SeverityMapUpdate' },
  },
}

const HELPER_BODIES = [
  'set-hostname', 'set-admin-networks', 'issue-certificate', 'import-certificate', 'check-update',
  'apply-update', 'rollback-update', 'set-update-policy', 'run-selftest', 'refresh-catalog', 'check-dns',
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
        ModuleState: { type: 'object', additionalProperties: false, required: ['enabled'], properties: { enabled: { type: 'boolean' } } },
        ModuleUpdate: { type: 'object', additionalProperties: false, properties: { version: { type: 'string' } } },
        ModuleUninstall: { type: 'object', additionalProperties: false, required: ['keep_data'], properties: { keep_data: { type: 'boolean' } } },
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
        ScanCreate: {
          type: 'object', additionalProperties: false, required: ['ref'],
          properties: { ref: { type: 'string', minLength: 1, maxLength: 255 }, profile: { type: 'string', pattern: '^[a-z0-9][a-z0-9-]{0,62}$' } },
        },
        BadgeUpdate: { type: 'object', additionalProperties: false, required: ['enabled'], properties: { enabled: { type: 'boolean' } } },
        PasswordReset: {
          type: 'object', additionalProperties: false, required: ['password'],
          properties: { password: { type: 'string', minLength: 12, maxLength: 1024 }, must_change_password: { type: 'boolean' } },
        },
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
