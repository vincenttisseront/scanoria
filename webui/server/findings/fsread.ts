// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Lecture bornée d'un fichier texte : la taille est contrôlée sur le
// descripteur ouvert (fstat), puis la lecture se fait sur ce même descripteur,
// sans fenêtre entre contrôle et lecture. Renvoie null si le fichier dépasse.

import { open } from 'node:fs/promises'

export async function readBoundedText(file: string, maxBytes: number): Promise<string | null> {
  const fh = await open(file, 'r')
  try {
    if ((await fh.stat()).size > maxBytes) return null
    return await fh.readFile('utf8')
  }
  finally {
    await fh.close()
  }
}
