// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Modules « service » dont l'appliance gère le compte administrateur
// (provision.py) : lien d'accès et réinitialisation dans la console.

export const MANAGED_ADMIN_MODULES = ['sonarqube', 'dependency-track'] as const

export function managesAdmin(id: string): boolean {
  return (MANAGED_ADMIN_MODULES as readonly string[]).includes(id)
}
