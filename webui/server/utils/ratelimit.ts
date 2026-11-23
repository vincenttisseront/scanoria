// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Limitation simple à fenêtre fixe, en mémoire (un seul processus console).
// Complète le verrouillage par compte stocké en base (users.locked_until).

export class FixedWindowLimiter {
  private readonly hits = new Map<string, { count: number, resetAt: number }>()

  constructor(
    private readonly max: number,
    private readonly windowMs: number,
    private readonly maxKeys = 10_000,
  ) {}

  /** Compte une tentative ; renvoie false si la limite est dépassée. */
  hit(key: string, now = Date.now()): boolean {
    const entry = this.hits.get(key)
    if (!entry || entry.resetAt <= now) {
      if (this.hits.size >= this.maxKeys) this.prune(now)
      this.hits.set(key, { count: 1, resetAt: now + this.windowMs })
      return true
    }
    entry.count += 1
    return entry.count <= this.max
  }

  isBlocked(key: string, now = Date.now()): boolean {
    const entry = this.hits.get(key)
    return !!entry && entry.resetAt > now && entry.count >= this.max
  }

  retryAfterSeconds(key: string, now = Date.now()): number {
    const entry = this.hits.get(key)
    return entry ? Math.max(1, Math.ceil((entry.resetAt - now) / 1000)) : 0
  }

  reset(key: string): void {
    this.hits.delete(key)
  }

  private prune(now: number): void {
    for (const [k, v] of this.hits) if (v.resetAt <= now) this.hits.delete(k)
    if (this.hits.size >= this.maxKeys) this.hits.clear()
  }
}

/** Connexions : 20 tentatives par adresse et par tranche de 10 minutes. */
export const loginLimiter = new FixedWindowLimiter(20, 10 * 60_000)
