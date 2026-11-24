// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Jeton porteur facultatif du connecteur IA (CLAUDE.md § 3.5) : chiffré en
// base par le contrat 2 (webui/server/utils/secrets.ts, type « ai-token »).
// La console l'écrit, scanoria-ai le lit ; seule la ligne du jeton IA est
// lisible par le rôle scanoria-ai (politique credentials_ai_token_read).
// Ce module ne contient aucune seconde implémentation du chiffrement : le
// magasin est injecté (setTokenStore). Tant que le contrat 2 n'est pas sur
// main (chantier A), aucun magasin n'est branché : la console refuse un jeton
// (503 E_UNAVAILABLE, champ désactivé sur la page) et le connecteur
// fonctionne sans jeton. À brancher au démarrage de la console et de
// scanoria-ai dès que secrets.ts arrive.

import type { Queryable } from '../utils/db'

export interface TokenStore {
  save: (db: Queryable, value: string, createdBy: number) => Promise<string>
  read: (db: Queryable, credentialId: string) => Promise<string>
}

let store: TokenStore | null = null

export function setTokenStore(s: TokenStore | null): void {
  store = s
}

export function tokenStoreAvailable(): boolean {
  return store !== null
}

export async function saveToken(db: Queryable, value: string, createdBy: number): Promise<string> {
  if (!store) throw new Error('token store unavailable')
  return store.save(db, value, createdBy)
}

export async function readToken(db: Queryable, credentialId: string): Promise<string> {
  if (!store) throw new Error('token store unavailable')
  return store.read(db, credentialId)
}
