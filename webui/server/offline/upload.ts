// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Téléversement d'un lot hors ligne : un fichier unique, reçu en flux sous
// <uploadsDir>/<upload_id>/bundle.tar, lu ensuite par le helper (import-bundle).

/** Nom attendu par le helper (bundle.UPLOAD_NAME). */
export const BUNDLE_UPLOAD_NAME = 'bundle.tar'
/** Même borne que le helper (bundle.MAX_BUNDLE) : 64 Gio. */
export const BUNDLE_UPLOAD_LIMIT = 64 * 1024 ** 3
