// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Contrat 38 (chantier B) : document VEX de l'analyse, joint au rapport de
// release par son empreinte. Bouchon tant que le chantier B n'est pas
// fusionné : aucun document (« vex »: null dans le rapport). À la fusion de
// B, ce fichier appelle buildVex(db, projectId, { scanId }), range le
// document à côté du rapport (vex.json) et rend { name, sha256, statements }.

import type { Queryable } from '../utils/db'

export interface VexRef { name: string, sha256: string, statements: number }

export async function releaseVex(_db: Queryable, _projectId: string, _scanId: string): Promise<VexRef | null> {
  return null
}
