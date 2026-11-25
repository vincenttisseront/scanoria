// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// K7 (0.7) : inventaire des workflows d'agents relevé par le module
// agentic-radar (runs[0].properties « scanoria/agent-inventory » de son
// SARIF), revalidé, borné et enregistré pour l'analyse (agent_inventories,
// migration 016). Il est affiché sur la page de l'analyse et servira à la
// cartographie de la surface d'attaque (I22) sous forme de métadonnées.
// Le texte vient du dépôt analysé : il est nettoyé et toujours affiché
// comme texte.

import { z } from 'zod'
import type { Queryable } from '../utils/db'
import { sanitizeText } from './sanitize'

export const AGENT_FRAMEWORKS = ['langgraph', 'crewai', 'n8n', 'openai-agents', 'autogen'] as const
export const INVENTORY_PROPERTY = 'scanoria/agent-inventory'
export const INVENTORY_MODULE = 'agentic-radar'
const MAX_BYTES = 1_000_000

const name = z.string().max(300).nullable().optional().transform(v => (v ? sanitizeText(v, 300) || null : null))
const Node = z.object({
  name,
  type: z.string().max(40).nullable().optional().transform(v => v ?? null),
  category: z.string().max(40).nullable().optional().transform(v => v ?? null),
  description: name,
  vulnerabilities: z.array(z.string().max(120)).max(50).default([]).transform(a => a.map(v => sanitizeText(v, 120)).filter(Boolean)),
})
const Workflow = z.object({
  framework: z.enum(AGENT_FRAMEWORKS),
  name,
  nodes: z.array(Node).max(500).default([]),
  edges: z.array(z.object({ start: name, end: name, condition: name })).max(1000).default([]),
  agents: z.array(z.object({
    name,
    llm: name,
    is_guardrail: z.boolean().default(false),
    system_prompt_chars: z.number().int().min(0).max(10_000_000).default(0),
  })).max(500).default([]),
  tools: z.array(Node).max(500).default([]),
  mcp_servers: z.array(Node).max(500).default([]),
})
export const AgentInventory = z.object({
  version: z.literal(1),
  tool_version: z.string().max(40).nullable().optional().transform(v => v ?? null),
  frameworks: z.array(z.enum(AGENT_FRAMEWORKS)).max(5),
  workflows: z.array(Workflow).max(50),
  truncated: z.boolean().default(false),
})
export type AgentInventory = z.infer<typeof AgentInventory>

/** Inventaire revalidé tiré d'un SARIF du module, ou null (absent, invalide, trop gros). */
export function inventoryFromSarif(doc: unknown): AgentInventory | null {
  const runs = (doc as { runs?: unknown })?.runs
  const props = Array.isArray(runs) ? (runs[0] as { properties?: Record<string, unknown> } | undefined)?.properties : undefined
  const raw = props?.[INVENTORY_PROPERTY]
  if (raw === undefined) return null
  const parsed = AgentInventory.safeParse(raw)
  if (!parsed.success) return null
  const inv = { ...parsed.data, frameworks: [...new Set(parsed.data.workflows.map(w => w.framework))].sort() }
  return Buffer.byteLength(JSON.stringify(inv)) <= MAX_BYTES ? inv : null
}

/** Enregistre l'inventaire de l'analyse (un par analyse ; la dernière écriture l'emporte). */
export async function storeAgentInventory(db: Queryable, scan: { id: string, project_id: string }, moduleVersion: string, inv: AgentInventory): Promise<void> {
  await db.query(
    `INSERT INTO agent_inventories (scan_id, project_id, module_version, frameworks, inventory)
     VALUES ($1, $2, $3, $4, $5)
     ON CONFLICT (scan_id) DO UPDATE SET module_version = EXCLUDED.module_version, frameworks = EXCLUDED.frameworks,
       inventory = EXCLUDED.inventory, created_at = now()`,
    [scan.id, scan.project_id, moduleVersion.slice(0, 64) || '?', inv.frameworks, JSON.stringify(inv)],
  )
}

export async function readAgentInventory(db: Queryable, scanId: string) {
  const { rows } = await db.query<{ module_version: string, frameworks: string[], inventory: AgentInventory, created_at: Date }>(
    'SELECT module_version, frameworks, inventory, created_at FROM agent_inventories WHERE scan_id = $1',
    [scanId],
  )
  const r = rows[0]
  return r ? { module_version: r.module_version, frameworks: r.frameworks, inventory: r.inventory, created_at: r.created_at.toISOString() } : null
}
