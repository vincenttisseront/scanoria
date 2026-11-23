// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Adresse cliente, limitation des tentatives, filtrage des secrets de l'audit,
// jetons de session et CSRF, état publié, migrations (préparation).

import { mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { normalizeAddress, resolveClientAddress } from '../../server/utils/client-ip'
import { FixedWindowLimiter } from '../../server/utils/ratelimit'
import { redactSecrets } from '../../server/utils/audit'
import { csrfTokenFor, hashToken, isWellFormedToken, newSessionToken, safeEqual } from '../../server/utils/sessions'
import { readPublishedState, sourceUrlFor } from '../../server/utils/appliance'
import { prepareMigrations } from '../../migrate.mjs'
import { loginSchema, userCreateSchema } from '#shared/schemas'

describe('adresse cliente', () => {
  it('normalise et valide', () => {
    expect(normalizeAddress('::ffff:192.0.2.7')).toBe('192.0.2.7')
    expect(normalizeAddress('2001:DB8::1')).toBe('2001:db8::1')
    expect(normalizeAddress('fe80::1%eth0')).toBe('fe80::1')
    expect(normalizeAddress('192.0.2.1;id')).toBeUndefined()
    expect(normalizeAddress('exemple.test')).toBeUndefined()
  })

  it('ne croit X-Real-IP que derrière le proxy local', () => {
    expect(resolveClientAddress('127.0.0.1', '198.51.100.4', true)).toBe('198.51.100.4')
    expect(resolveClientAddress('203.0.113.9', '198.51.100.4', true)).toBe('203.0.113.9')
    expect(resolveClientAddress('127.0.0.1', '198.51.100.4', false)).toBe('127.0.0.1')
    expect(resolveClientAddress('127.0.0.1', 'garbage', true)).toBe('127.0.0.1')
  })
})

describe('limitation des tentatives', () => {
  it('bloque au-delà du maximum puis libère après la fenêtre', () => {
    const l = new FixedWindowLimiter(3, 1000)
    expect([l.hit('a', 0), l.hit('a', 1), l.hit('a', 2), l.hit('a', 3)]).toEqual([true, true, true, false])
    expect(l.hit('b', 3)).toBe(true)
    expect(l.retryAfterSeconds('a', 500)).toBe(1)
    expect(l.hit('a', 1001)).toBe(true)
  })

  it('état bloqué, remise à zéro et nombre de clés borné', () => {
    const l = new FixedWindowLimiter(2, 1000, 2)
    l.hit('a', 0)
    expect(l.isBlocked('a', 0)).toBe(false)
    l.hit('a', 0)
    expect(l.isBlocked('a', 10)).toBe(true)
    expect(l.isBlocked('a', 1000)).toBe(false)
    expect(l.retryAfterSeconds('inconnu')).toBe(0)
    l.reset('a')
    expect(l.isBlocked('a', 10)).toBe(false)
    // table pleine : les entrées expirées sont purgées d'abord…
    l.hit('x', 0)
    l.hit('y', 500)
    l.hit('z', 1200)
    expect(l.retryAfterSeconds('x', 1200)).toBe(0)
    expect(l.retryAfterSeconds('y', 1200)).toBe(1)
    // … puis tout est vidé si aucune n'a expiré
    l.hit('w', 1300)
    expect(l.retryAfterSeconds('y', 1300)).toBe(0)
    expect(l.retryAfterSeconds('w', 1300)).toBe(1)
  })
})

describe('audit sans secret', () => {
  it('retire les champs sensibles, même imbriqués', () => {
    const out = redactSecrets({
      username: 'alice',
      password: 'x',
      nested: { key_pem: 'k', token: 't', ok: 1, list: [{ new_password: 'p', v: 2 }] },
    })
    expect(out).toEqual({ username: 'alice', nested: { ok: 1, list: [{ v: 2 }] } })
  })
})

describe('jetons de session et CSRF', () => {
  it('jeton aléatoire de 32 octets, seule son empreinte est stockée', () => {
    const tok = newSessionToken()
    expect(isWellFormedToken(tok)).toBe(true)
    expect(hashToken(tok)).toMatch(/^[0-9a-f]{64}$/)
    expect(hashToken(tok)).not.toContain(tok)
    expect(isWellFormedToken('short')).toBe(false)
  })

  it('CSRF dérivé du jeton, différent pour chaque session', () => {
    const a = newSessionToken()
    const b = newSessionToken()
    expect(csrfTokenFor(a)).toBe(csrfTokenFor(a))
    expect(csrfTokenFor(a)).not.toBe(csrfTokenFor(b))
    expect(safeEqual(csrfTokenFor(a), csrfTokenFor(a))).toBe(true)
    expect(safeEqual(csrfTokenFor(a), csrfTokenFor(b))).toBe(false)
    expect(safeEqual('a', 'ab')).toBe(false)
  })
})

describe('entrées de l’API', () => {
  it('valide la connexion et la création de compte', () => {
    expect(loginSchema.safeParse({ username: 'admin', password: 'x' }).success).toBe(true)
    expect(loginSchema.safeParse({ username: 'admin', password: 'x', admin: true }).success).toBe(false)
    expect(userCreateSchema.safeParse({ username: 'bob', role: 'viewer', password: 'short' }).success).toBe(false)
    expect(userCreateSchema.safeParse({ username: 'bob', role: 'root', password: 'long-enough-pass' }).success).toBe(false)
    expect(userCreateSchema.safeParse({ username: 'bob', role: 'operator', password: 'long-enough-pass' }).success).toBe(true)
  })
})

describe('état publié et lien source', () => {
  it('signale absent, illisible, périmé ou disponible', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'scanoria-state-'))
    try {
      const file = join(dir, 'state.json')
      expect((await readPublishedState(file)).reason).toBe('missing')
      await writeFile(file, '{bad')
      expect((await readPublishedState(file)).reason).toBe('invalid')
      const now = Date.parse('2026-11-23T08:10:00Z')
      await writeFile(file, JSON.stringify({ version: 1, generated_at: '2026-11-23T08:00:00Z' }))
      expect((await readPublishedState(file, now)).reason).toBe('stale')
      expect((await readPublishedState(file, Date.parse('2026-11-23T08:01:00Z'))).available).toBe(true)
    }
    finally {
      await rm(dir, { recursive: true, force: true })
    }
  })

  it('construit le lien vers le tag de la version installée', () => {
    expect(sourceUrlFor('exemple/scanoria', '0.1.0')).toBe('https://github.com/exemple/scanoria/tree/v0.1.0')
    expect(sourceUrlFor('exemple/../x', '0.1.0')).toBeNull()
    expect(sourceUrlFor(null, '0.1.0')).toBeNull()
  })
})

describe('préparation des migrations', () => {
  it('exige des noms conformes et une numérotation continue', () => {
    expect(prepareMigrations([{ name: '002_b.sql', content: 'b' }, { name: '001_a.sql', content: 'a' }]).map(m => m.version)).toEqual([1, 2])
    expect(() => prepareMigrations([{ name: '001_a.sql', content: '' }, { name: '003_c.sql', content: '' }])).toThrow(/continuous/)
    expect(() => prepareMigrations([{ name: '1_a.sql', content: '' }])).toThrow(/invalid/)
  })
})
