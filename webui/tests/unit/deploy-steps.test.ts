// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Lecture de l'en-tête Location de Jenkins (0.8, chantier D) : même origine
// seulement, jamais d'exception sur une valeur illisible.

import { describe, expect, it } from 'vitest'
import { jenkinsQueueItem } from '../../server/deploy/steps'

const BASE = 'https://jenkins.exemple.test'

describe('jenkinsQueueItem', () => {
  it('numéro de file lu sur la même origine', () => {
    expect(jenkinsQueueItem(`${BASE}/queue/item/42/`, BASE)?.[1]).toBe('42')
    expect(jenkinsQueueItem('/queue/item/7', BASE)?.[1]).toBe('7')
  })
  it('autre origine, valeur illisible ou absente : null, sans exception', () => {
    expect(jenkinsQueueItem('https://autre.exemple.test/queue/item/42/', BASE)).toBeNull()
    expect(jenkinsQueueItem('https://[::1', BASE)).toBeNull()
    expect(jenkinsQueueItem(null, BASE)).toBeNull()
    expect(jenkinsQueueItem(`${BASE}/job/x/`, BASE)).toBeNull()
  })
})
