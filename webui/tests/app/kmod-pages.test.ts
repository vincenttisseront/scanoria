// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// K7 (0.7) sur la page d'une analyse : inventaire des workflows d'agents
// affiché comme texte (frameworks, agents, outils et vulnérabilités, serveurs
// MCP), rien sans inventaire ni en cas d'erreur, en français et en anglais.

import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { enableAutoUnmount } from '@vue/test-utils'
import { bodyText, callsTo, clearBody, mountIn, resetApi, route, setLocale, settle, setUser } from './helpers'
import AgentInventory from '~/components/scans/AgentInventory.vue'

enableAutoUnmount(afterEach)
beforeEach(async () => {
  await setLocale('fr')
  setUser('viewer')
})
afterEach(() => {
  resetApi()
  clearBody()
})

const SCAN = '22222222-2222-4222-8222-222222222222'
const node = (name: string, extra: Record<string, unknown> = {}) => ({ name, type: 'tool', category: null, description: null, vulnerabilities: [], ...extra })
const inventory = (truncated = false) => ({
  module_version: '0.14.2',
  frameworks: ['langgraph'],
  inventory: {
    version: 1, frameworks: ['langgraph'], truncated,
    workflows: [{
      framework: 'langgraph',
      name: 'assistant',
      nodes: [node('agent'), node('tools')],
      edges: [{ start: 'agent', end: 'tools', condition: null }],
      agents: [{ name: 'agent', llm: 'gpt-x', is_guardrail: true, system_prompt_chars: 120 }],
      tools: [node('ShellTool', { category: 'code_interpreter', vulnerabilities: ['Arbitrary Code Execution (ACE)'] })],
      mcp_servers: [node('<b>docs</b>', { type: 'mcp_server' })],
    }],
  },
})

describe('inventaire des agents (K7)', () => {
  it('affiche frameworks, agents, outils vulnérables et serveurs MCP', async () => {
    route('GET', `/api/scans/${SCAN}/agent-inventory`, () => ({ inventory: inventory(true) }))
    const w = await mountIn(AgentInventory, { props: { scanId: SCAN } })
    await settle()
    expect(callsTo('GET', `/api/scans/${SCAN}/agent-inventory`)).toHaveLength(1)
    const text = bodyText()
    expect(text).toContain('Workflows d’agents IA')
    expect(text).toContain('Agentic Radar 0.14.2')
    expect(text).toContain('langgraph')
    expect(text).toContain('agent (gpt-x) · garde-fou')
    expect(text).toContain('ShellTool')
    expect(text).toContain('Arbitrary Code Execution (ACE)')
    expect(text).toContain('Graphe : 2 nœud(s), 1 arête(s).')
    expect(text).toContain('Inventaire tronqué')
    // Texte du dépôt affiché comme texte, jamais comme HTML.
    expect(w.html()).not.toContain('<b>docs</b>')
    expect(text).toContain('<b>docs</b>')
  })

  it('en anglais', async () => {
    await setLocale('en')
    route('GET', `/api/scans/${SCAN}/agent-inventory`, () => ({ inventory: inventory() }))
    await mountIn(AgentInventory, { props: { scanId: SCAN } })
    await settle()
    expect(bodyText()).toContain('AI agent workflows')
    expect(bodyText()).not.toContain('Inventory truncated')
  })

  it('rien sans inventaire, ni en cas d’erreur', async () => {
    route('GET', `/api/scans/${SCAN}/agent-inventory`, () => ({ inventory: null }))
    const w = await mountIn(AgentInventory, { props: { scanId: SCAN } })
    await settle()
    expect(w.find('[data-testid="agent-inventory"]').exists()).toBe(false)
    resetApi()
    route('GET', `/api/scans/${SCAN}/agent-inventory`, () => {
      throw new Error('boom')
    })
    const w2 = await mountIn(AgentInventory, { props: { scanId: SCAN } })
    await settle()
    expect(w2.find('[data-testid="agent-inventory"]').exists()).toBe(false)
  })
})
