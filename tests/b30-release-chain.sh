#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Vincent Tisseront
#
# b30 — chaîne de signature et de vérification des actifs de release
# (ARCHITECTURE § 6.2), avec des clés Ed25519 jetables : délègue à
# .github/scripts/test-release-chain.sh. Avec SCANORIA_OUT, le lot réellement
# produit par build.sh est signé et vérifié ; sinon, un faux lot.
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
if [[ -n "${SCANORIA_OUT:-}" ]]; then
	exec bash "$ROOT/.github/scripts/test-release-chain.sh" "$SCANORIA_OUT"
fi
exec bash "$ROOT/.github/scripts/test-release-chain.sh"
