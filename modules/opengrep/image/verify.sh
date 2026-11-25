#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Vincent Tisseront
#
# Vérification amont d'Opengrep avant la construction de l'image (lancé par la
# CI depuis modules/opengrep/image/, réseau disponible) : le binaire de la
# release épinglée doit être signé par le workflow de publication du dépôt
# opengrep/opengrep (cosign, signature sans clé, émetteur GitHub Actions), et
# son sha256 égal à celui du Containerfile.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
ver=$(sed -n 's/^ARG OPENGREP_VERSION=//p' Containerfile)
want=$(sed -n 's/^ARG OPENGREP_SHA256=//p' Containerfile)
[[ "$ver" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ && "$want" =~ ^[0-9a-f]{64}$ ]] || { echo "version ou empreinte illisible" >&2; exit 1; }
command -v cosign > /dev/null || { echo "cosign absent" >&2; exit 1; }
w=$(mktemp -d)
trap 'rm -rf "$w"' EXIT
base="https://github.com/opengrep/opengrep/releases/download/$ver"
for f in opengrep_linux_x86 opengrep_linux_x86.sig opengrep_linux_x86.cert; do
	curl --proto '=https' --tlsv1.2 -fsSL --retry 3 -o "$w/$f" "$base/$f"
done
cosign verify-blob \
	--certificate "$w/opengrep_linux_x86.cert" --signature "$w/opengrep_linux_x86.sig" \
	--certificate-identity-regexp '^https://github\.com/opengrep/opengrep/.+' \
	--certificate-oidc-issuer https://token.actions.githubusercontent.com \
	"$w/opengrep_linux_x86"
got=$(sha256sum "$w/opengrep_linux_x86" | cut -d' ' -f1)
echo "opengrep $ver opengrep_linux_x86 sha256=$got"
[[ "$got" == "$want" ]] || { echo "empreinte différente du Containerfile (attendu $want)" >&2; exit 1; }
