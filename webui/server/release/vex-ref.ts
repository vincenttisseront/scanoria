// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Contrat 38 (chantier B) : document VEX (OpenVEX 0.2, forme canonique) des
// vulnérabilités vues par l'analyse de release. Rangé à côté du rapport
// (vex.json), téléchargeable et joint à la release de la forge ; le rapport
// signé en porte l'empreinte, ce qui le couvre par la signature.

import type { Queryable } from '../utils/db'
import { buildVex } from '../vex/vex'
import { releasesDir, writeArtifact } from './artifacts'

export interface VexRef { name: string, sha256: string, statements: number }

export async function releaseVex(db: Queryable, projectId: string, scanId: string, dir = releasesDir()): Promise<VexRef> {
  const built = await buildVex(db, projectId, { scanId })
  await writeArtifact(scanId, 'vex.json', built.canonical, dir)
  return { name: 'vex.json', sha256: built.sha256, statements: built.statements.length }
}
