#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Vincent Tisseront
#
# Libère de la place sur un runner GitHub standard (ubuntu-latest) avant la
# construction de l'ISO : ISO de base (~4 Gio), paquets, ISO produite, disque
# virtuel du test de démarrage. Supprime des chaînes d'outils préinstallées
# inutiles ici. Sans action tierce.
set -euo pipefail
df -h / | tail -n 1
for d in /usr/share/dotnet /usr/local/lib/android /opt/ghc /usr/local/.ghcup \
	/opt/hostedtoolcache/CodeQL /usr/share/swift /usr/local/share/powershell \
	/usr/local/share/chromium /usr/local/lib/node_modules/@angular; do
	if [[ -d "$d" ]]; then
		sudo rm -rf "$d"
	fi
done
sudo docker image prune --all --force > /dev/null 2>&1 || true
df -h / | tail -n 1
