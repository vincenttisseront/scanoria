// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Aides des tests de la console (environnement Nuxt) : API simulée par des
// points d'accès h3 enregistrés (vraies erreurs { code } comme le serveur),
// session du client, état publié d'exemple, recherche dans le DOM (les
// modales et le panneau latéral sont téléportés dans document.body).

import { flushPromises } from '@vue/test-utils'
import { mountSuspended, registerEndpoint } from '@nuxt/test-utils/runtime'
import { createError, getMethod, getQuery, readBody, type H3Event } from 'h3'
import { defineComponent, h, nextTick } from 'vue'
import type { Role } from '#shared/schemas'
import type { StateResponse } from '~/composables/useApplianceState'

export interface ApiCall {
  method: string
  path: string
  body: unknown
  query: Record<string, unknown>
  csrf: string | undefined
}

type Handler = (event: H3Event, body: unknown) => unknown | Promise<unknown>

const unregister: (() => void)[] = []
export const calls: ApiCall[] = []

/** Enregistre un point d'accès simulé ; chaque appel est consigné dans `calls`. */
export function route(method: string, path: string, handler: Handler): void {
  unregister.push(registerEndpoint(path, {
    method: method as 'GET',
    handler: async (event: H3Event) => {
      const m = getMethod(event)
      const body = m === 'GET' || m === 'DELETE' ? undefined : await readBody(event).catch(() => undefined)
      calls.push({ method: m, path, body, query: getQuery(event), csrf: event.node.req.headers['x-csrf-token'] as string | undefined })
      return handler(event, body)
    },
  }))
}

/** Erreur de l'API au format du serveur (data.code). */
export function apiFail(statusCode: number, code: string): never {
  throw createError({ statusCode, statusMessage: code, data: { code } })
}

export function resetApi(): void {
  while (unregister.length) unregister.pop()!()
  calls.length = 0
}

export function callsTo(method: string, path: string): ApiCall[] {
  return calls.filter(c => c.method === method && c.path === path)
}

export function setUser(role: Role | null, extra: Record<string, unknown> = {}): void {
  const state = useState<Record<string, unknown>>('session')
  state.value = role
    ? {
        loaded: true,
        csrf: 'csrf-test',
        address: '192.0.2.10',
        user: { id: 1, username: 'alice', display_name: 'Alice', role, locale: 'fr', must_change_password: false, ...extra },
      }
    : { loaded: true, user: null, csrf: null, address: null }
}

export async function setLocale(code: 'fr' | 'en'): Promise<void> {
  await useNuxtApp().$i18n.setLocale(code)
}

export async function settle(): Promise<void> {
  for (let i = 0; i < 4; i++) {
    await flushPromises()
    await nextTick()
  }
}

export function bodyText(): string {
  return document.body.textContent?.replace(/\s+/g, ' ') ?? ''
}

export function buttons(label: string): HTMLButtonElement[] {
  return Array.from(document.body.querySelectorAll('button'))
    .filter(b => b.textContent?.replace(/\s+/g, ' ').trim() === label || b.getAttribute('aria-label') === label)
}

export function button(label: string): HTMLButtonElement {
  const found = buttons(label)
  if (!found.length) throw new Error(`bouton introuvable : ${label}`)
  return found[found.length - 1]!
}

export async function click(el: Element): Promise<void> {
  el.dispatchEvent(new MouseEvent('click', { bubbles: true }))
  await settle()
}

/** Monte dans document.body (les recherches du DOM y portent). */
export function mountIn<T>(component: T, options: Parameters<typeof mountSuspended<T>>[1] = {}) {
  return mountSuspended(component, { attachTo: document.body, ...options })
}

/** Ferme les modales restées ouvertes entre deux tests. */
export function clearBody(): void {
  for (const el of Array.from(document.body.children)) {
    if (el.id !== '__nuxt' && el.id !== 'teleports') el.remove()
  }
}

/** Monte un composable dans un composant (useI18n exige un setup). */
export function setupComponent<T>(fn: () => T, holder: { value?: T }) {
  return defineComponent({
    setup() {
      holder.value = fn()
      return () => h('div')
    },
  })
}

export function sampleState(patch: { appliance?: object, update?: object, tls?: object, helper?: object } = {}): StateResponse {
  return {
    available: true,
    console_version: '0.1.0',
    state: {
      generated_at: '2026-11-23T08:00:00Z',
      appliance: {
        fqdn: 'analyse.exemple.test',
        version: '0.1.0',
        previous_version: null,
        firstboot_done: true,
        cpu_count: 4,
        memory_mb: 8192,
        ...patch.appliance,
      },
      helper: { busy: false, current: null, queue_length: 0, ...patch.helper },
      update: {
        channel: 'stable',
        auto_check: true,
        auto_apply: false,
        maintenance_window: null,
        last_check_at: null,
        latest_version: null,
        available: false,
        ...patch.update,
      },
      tls: {
        mode: 'internal',
        subject_alt_names: ['analyse.exemple.test', '*.analyse.exemple.test'],
        not_before: '2026-11-01T00:00:00Z',
        not_after: '2099-01-01T00:00:00Z',
        fingerprint_sha256: 'aabbccdd',
        ca_fingerprint_sha256: '0011',
        ...patch.tls,
      },
      firewall: { loaded: true, admin_networks: ['192.0.2.0/24'] },
      services: { 'scanoria-console': 'active', 'scanoria-helper': 'failed', 'nginx': 'activating' },
      disks: [{ mount: '/', size_mb: 40960, avail_mb: 2048 }],
      selftest: null,
    },
  } as StateResponse
}
