// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Signatures des webhooks (Forgejo, GitHub, GitLab), identifiants de
// livraison et évènements utiles.
import { createHmac, randomBytes } from 'node:crypto'
import { describe, expect, it } from 'vitest'
import { deliveryId, verifyWebhookSignature, webhookEvent } from '../../server/forges/signature'

const secret = randomBytes(32).toString('hex')
const body = Buffer.from(JSON.stringify({ action: 'opened' }))
const hex = (s: string, b: Buffer) => createHmac('sha256', s).update(b).digest('hex')

describe('webhooks : signature à temps constant', () => {
  it('Forgejo (et en-tête Gitea)', () => {
    expect(verifyWebhookSignature('forgejo', { 'x-forgejo-signature': hex(secret, body) }, body, secret)).toBe(true)
    expect(verifyWebhookSignature('forgejo', { 'x-gitea-signature': hex(secret, body).toUpperCase() }, body, secret)).toBe(true)
    expect(verifyWebhookSignature('forgejo', { 'x-forgejo-signature': hex('autre-secret-de-test', body) }, body, secret)).toBe(false)
    expect(verifyWebhookSignature('forgejo', { 'x-forgejo-signature': hex(secret, Buffer.from('{}')) }, body, secret)).toBe(false)
    expect(verifyWebhookSignature('forgejo', {}, body, secret)).toBe(false)
    expect(verifyWebhookSignature('forgejo', { 'x-forgejo-signature': 'abc' }, body, secret)).toBe(false)
  })

  it('GitHub : sha256= obligatoire', () => {
    expect(verifyWebhookSignature('github', { 'x-hub-signature-256': `sha256=${hex(secret, body)}` }, body, secret)).toBe(true)
    expect(verifyWebhookSignature('github', { 'x-hub-signature-256': hex(secret, body) }, body, secret)).toBe(false)
    expect(verifyWebhookSignature('github', { 'x-hub-signature': `sha1=${hex(secret, body)}` }, body, secret)).toBe(false)
  })

  it('GitLab : jeton égal au secret', () => {
    expect(verifyWebhookSignature('gitlab', { 'x-gitlab-token': secret }, body, secret)).toBe(true)
    expect(verifyWebhookSignature('gitlab', { 'x-gitlab-token': `${secret}x` }, body, secret)).toBe(false)
    expect(verifyWebhookSignature('gitlab', { 'x-gitlab-token': ['autre', secret] }, body, secret)).toBe(false)
  })

  it('secret vide ou court : toujours refusé', () => {
    expect(verifyWebhookSignature('forgejo', { 'x-forgejo-signature': hex('', body) }, body, '')).toBe(false)
    expect(verifyWebhookSignature('gitlab', { 'x-gitlab-token': 'court' }, body, 'court')).toBe(false)
  })

  it('identifiant de livraison : présent et bien formé', () => {
    expect(deliveryId('github', { 'x-github-delivery': '72d3162e-cc78-11e3-81ab-4c9367dc0958' })).toBe('72d3162e-cc78-11e3-81ab-4c9367dc0958')
    expect(deliveryId('forgejo', { 'x-gitea-delivery': 'f6266f16-1bf3-46a5-9ea4-602e06ead473' })).not.toBeNull()
    expect(deliveryId('gitlab', { 'idempotency-key': 'a1b2c3d4e5f6' })).toBe('a1b2c3d4e5f6')
    expect(deliveryId('forgejo', {})).toBeNull()
    expect(deliveryId('github', { 'x-github-delivery': 'court' })).toBeNull()
    expect(deliveryId('github', { 'x-github-delivery': '../../etc/passwd-0001' })).toBeNull()
  })

  it('évènements utiles seulement', () => {
    expect(webhookEvent('github', { 'x-github-event': 'pull_request' }).event).toBe('pull_request')
    expect(webhookEvent('github', { 'x-github-event': 'issue_comment' }).event).toBe('comment')
    expect(webhookEvent('github', { 'x-github-event': 'star' }).event).toBeNull()
    expect(webhookEvent('github', { 'x-github-event': '__proto__' }).event).toBeNull()
    expect(webhookEvent('forgejo', { 'x-forgejo-event': 'pull_request_sync' }).event).toBe('pull_request')
    expect(webhookEvent('gitlab', { 'x-gitlab-event': 'Note Hook' }).event).toBe('comment')
    expect(webhookEvent('gitlab', { 'x-gitlab-event': 'Pipeline Hook' }).event).toBeNull()
  })
})
