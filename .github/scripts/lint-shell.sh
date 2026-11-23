#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Vincent Tisseront
#
# ShellCheck sur tous les scripts shell du dépôt : fichiers *.sh et fichiers
# sans extension dont la première ligne désigne sh ou bash (scripts de
# src/rootfs/usr/sbin, assistant de premier démarrage…). Fichiers suivis par
# git (ou non ignorés), hors node_modules.
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$root"

files=()
while IFS= read -r -d '' f; do
	[[ -f "$f" && ! -L "$f" ]] || continue
	case "$f" in
		*/node_modules/*|node_modules/*) continue ;;
		*.sh) files+=("$f"); continue ;;
		*.*) continue ;;
	esac
	if head -n 1 "$f" | grep -Eq '^#!(/usr)?/bin/(env +)?(ba)?sh([[:space:]]|$)'; then
		files+=("$f")
	fi
done < <(git ls-files -z --cached --others --exclude-standard)

[[ ${#files[@]} -gt 0 ]] || { echo "lint-shell: aucun script trouvé" >&2; exit 1; }
printf 'lint-shell: %d scripts\n' "${#files[@]}"
printf '  %s\n' "${files[@]}"
shellcheck --version | sed -n 2p
# -x : suit les « source » ; les directives source-path des scripts guident.
shellcheck -x --severity=style "${files[@]}"
echo "lint-shell: OK"
