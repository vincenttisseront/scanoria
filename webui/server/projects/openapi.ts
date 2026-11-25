// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Chemins et schémas OpenAPI des forges et des projets (chantier A), repris
// par server/api/openapi.json.get.ts. Les schémas des corps sont générés
// depuis les schémas zod qui valident réellement les requêtes.

import { z } from 'zod'
import {
  archiveSchema, deleteSchema, forgeCreateSchema, forgeUpdateSchema, hostKeysSchema, projectCreateSchema,
  projectPreviewSchema, projectUpdateSchema,
} from './schemas'

type Role = 'public' | 'viewer' | 'operator' | 'admin'
interface Op { summary: string, role: Role, body?: string, status?: number }

export const PROJECT_OPS: Record<string, Record<string, Op>> = {
  '/api/forges': {
    get: { summary: 'Known forges (token hint only, never the token)', role: 'viewer' },
    post: { summary: 'Add a forge (Forgejo, GitHub, GitLab) with a service account token; access checked immediately, discovery and webhooks started', role: 'admin', body: 'ForgeCreate', status: 201 },
  },
  '/api/forges/{id}': {
    get: { summary: 'Forge and its projects', role: 'viewer' },
    patch: { summary: 'Rename, toggle discovery, replace or remove the token (checked before saving)', role: 'admin', body: 'ForgeUpdate' },
    delete: { summary: 'Remove a forge and its token (409 E_FORGE_IN_USE while projects use it)', role: 'admin' },
  },
  '/api/forges/{id}/discover': { post: { summary: 'Discover repositories now (otherwise hourly)', role: 'operator' } },
  '/api/forges/{id}/webhook': { post: { summary: 'Signed forge webhook (HMAC with the forge secret, replay refused, 1 MiB max); push, pull request, PR comment, installation', role: 'public', status: 202 } },
  '/api/forges/github/manifest': { post: { summary: 'Start the one-click GitHub App creation (J1): manifest and signed state, posted to GitHub by the console', role: 'admin' } },
  '/api/forges/github/convert': { post: { summary: 'GitHub App creation callback: state checked, code exchanged, forge saved; returns the install URL', role: 'admin', status: 201 } },
  '/api/forges/github/install': { post: { summary: 'GitHub App installation callback: installation confirmed with GitHub, repository discovery started', role: 'admin' } },
  '/api/forges/{id}/repos': { get: { summary: 'Repositories reachable with the forge token, with their project if any', role: 'operator' } },
  '/api/projects': {
    get: { summary: 'Projects (?archived=1 for archived ones)', role: 'viewer' },
    post: { summary: 'Add a project: forge repository, free Git URL or uploaded archive; detection, profile, gate and schedule chosen automatically', role: 'operator', body: 'ProjectCreate', status: 201 },
  },
  '/api/projects/preview': { post: { summary: 'Repository detection (F1) before adding it, without saving', role: 'operator', body: 'ProjectPreview' } },
  '/api/projects/ssh-hostkeys': { post: { summary: 'Scan the SSH host keys of a repository URL for confirmation', role: 'operator', body: 'SshHostKeys' } },
  '/api/projects/uploads': { put: { summary: 'Upload a source archive (raw body: zip, tar or tar.gz, 512 MiB max)', role: 'operator', status: 201 } },
  '/api/projects/{id}': {
    get: { summary: 'Project, detection and available profiles and gates', role: 'viewer' },
    patch: { summary: 'Update a project (branches, schedule, profile, gate, AI opt-out, credentials, archive)', role: 'operator', body: 'ProjectUpdate' },
    delete: { summary: 'Delete a project for good (body repeats the slug)', role: 'admin', body: 'ProjectDelete' },
  },
  '/api/projects/{id}/archive': { post: { summary: 'Archive or reactivate a project', role: 'operator', body: 'ProjectArchive' } },
  '/api/projects/{id}/detect': { post: { summary: 'Run the repository detection (F1) again', role: 'operator' } },
  '/api/projects/{id}/branches': { get: { summary: 'Repository branches read from the forge', role: 'viewer' } },
}

const json = (s: z.ZodType) => z.toJSONSchema(s, { io: 'input', unrepresentable: 'any' }) as Record<string, unknown>

export function projectSchemas(): Record<string, Record<string, unknown>> {
  return {
    ForgeCreate: json(forgeCreateSchema),
    ForgeUpdate: json(forgeUpdateSchema),
    ProjectCreate: json(projectCreateSchema),
    ProjectPreview: json(projectPreviewSchema),
    SshHostKeys: json(hostKeysSchema),
    ProjectUpdate: json(projectUpdateSchema),
    ProjectDelete: json(deleteSchema),
    ProjectArchive: json(archiveSchema),
  }
}
