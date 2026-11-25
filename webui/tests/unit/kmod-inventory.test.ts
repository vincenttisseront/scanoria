// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// K7 (0.7) : l'inventaire des workflows d'agents porté par le SARIF
// d'agentic-radar est revalidé, borné et nettoyé avant d'être enregistré.

import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'
import { INVENTORY_PROPERTY, inventoryFromSarif } from '../../server/ai/agent-inventory'

const RECORDED = fileURLToPath(new URL('../../../modules/agentic-radar/tests/recorded.sarif', import.meta.url))
const recorded = () => JSON.parse(readFileSync(RECORDED, 'utf8')) as { runs: { properties: Record<string, unknown> }[] }
const wrap = (inv: unknown) => ({ version: '2.1.0', runs: [{ tool: { driver: { name: 'x' } }, results: [], properties: { [INVENTORY_PROPERTY]: inv } }] })

describe('inventaire des agents (K7)', () => {
  it('lit l’inventaire enregistré du banc d’essai', () => {
    const inv = inventoryFromSarif(recorded())!
    expect(inv.frameworks).toEqual(['langgraph'])
    expect(inv.workflows).toHaveLength(1)
    expect(inv.workflows[0]!.tools.some(t => t.vulnerabilities.length > 0)).toBe(true)
  })

  it('absent, invalide ou hors cadre : rien', () => {
    expect(inventoryFromSarif({})).toBeNull()
    expect(inventoryFromSarif(null)).toBeNull()
    expect(inventoryFromSarif({ runs: [{}] })).toBeNull()
    expect(inventoryFromSarif(wrap({ version: 2, frameworks: [], workflows: [] }))).toBeNull()
    expect(inventoryFromSarif(wrap({ version: 1, frameworks: [], workflows: [{ framework: 'inconnu' }] }))).toBeNull()
    expect(inventoryFromSarif(wrap({ version: 1, frameworks: [], workflows: Array.from({ length: 51 }, () => ({ framework: 'n8n' })) }))).toBeNull()
  })

  it('frameworks recalculés et texte du dépôt nettoyé', () => {
    const inv = inventoryFromSarif(wrap({
      version: 1,
      frameworks: ['autogen', 'crewai'],
      workflows: [{ framework: 'crewai', name: '<script>x</script>équipe‮', tools: [{ name: 'shell', vulnerabilities: ['<b>ACE</b>'] }] }],
    }))!
    expect(inv.frameworks).toEqual(['crewai'])
    expect(inv.workflows[0]!.name).not.toMatch(/[<>‮]/)
    expect(inv.workflows[0]!.tools[0]!.vulnerabilities[0]).not.toMatch(/[<>]/)
  })
})
