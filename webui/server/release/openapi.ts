// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Chemins et schémas OpenAPI de la gate de release (0.8, chantier A,
// CLAUDE.md § 7), repris par server/api/openapi.json.get.ts.

type Role = 'public' | 'viewer' | 'operator' | 'admin'
interface Op { summary: string, role: Role, body?: string, status?: number, token?: boolean }

export const RELEASE_OPS: Record<string, Record<string, Op>> = {
  '/api/projects/{id}/releases': {
    post: { summary: 'Push mode (§ 7.2): request the release scan of a tag {tag, commit?} → 202 {scan_id, number, url, release_url, existing: false}; the same tag returns its existing scan (200, existing: true), a tag is never analysed twice; commit required when the appliance cannot read the forge; 404 E_RELEASE_TAG, 409 E_RELEASE_COMMIT, E_RELEASE_TAG_MOVED (reported in the audit log), E_RELEASE_MODE', role: 'operator', body: 'ReleaseCreate', status: 202, token: true },
  },
  '/api/releases': { get: { summary: 'Releases of a project (query project), most recent first, with their report status', role: 'viewer' } },
  '/api/releases/{scanId}': { get: { summary: 'Release page: verdict (current and signed), scanoria/release-gate status, report and signature state, F2 comparison with the previous release, forge publications, available files', role: 'viewer' } },
  '/api/releases/{scanId}/compare': { get: { summary: 'F2 comparison with another scan of the same project (query with): introduced, fixed, unchanged, by tool and severity', role: 'viewer' } },
  '/api/releases/{scanId}/{file}': { get: { summary: 'Download report.json (signed envelope, scanoria-signed-release-report/1; project API token or viewer; 409 E_RELEASE_NOT_SIGNED), results.sarif, sbom.cdx.json or notes.md (AI-proposed, unsigned annex)', role: 'viewer', token: true } },
  '/api/releases/client': { get: { summary: 'Download the scanoria-verify client (POSIX sh, openssl): verifies a signed release report offline', role: 'public' } },
  '/api/system/appliance-key': { get: { summary: 'Appliance Ed25519 public key {public_key, fingerprint, pem}: check the fingerprint shown in the console before trusting it', role: 'public' } },
}

export function releaseSchemas() {
  return {
    ReleaseCreate: {
      type: 'object', additionalProperties: false, required: ['tag'],
      properties: { tag: { type: 'string', minLength: 1, maxLength: 255 }, commit: { type: 'string', pattern: '^[0-9a-f]{40,64}$' } },
    },
  }
}
