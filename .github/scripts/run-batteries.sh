#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Vincent Tisseront
#
# Lance les batteries shell tests/bNN-*.sh « sans root » (les fichiers
# *-live.sh, réservés à une machine de test root, sont exclus), chacune dans
# son propre processus bash, et échoue si l'une échoue.
# Usage : run-batteries.sh [MOTIF]   (défaut : b[0-9][0-9]-*.sh)
# Exemple : run-batteries.sh 'b2[0-9]-*.sh'
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
pattern=${1:-'b[0-9][0-9]-*.sh'}

if [[ "$(id -u)" -eq 0 ]]; then
	echo "run-batteries: refusé en root (batteries sans root)" >&2
	exit 1
fi

shopt -s nullglob
# Le motif est volontairement développé par le shell.
# shellcheck disable=SC2206
scripts=("$root"/tests/$pattern)
failed=()
ran=0
for s in "${scripts[@]}"; do
	case "$s" in *-live.sh) continue ;; esac
	name=$(basename "$s")
	ran=$((ran + 1))
	echo "::group::$name"
	start=$SECONDS
	if bash "$s"; then
		echo "run-batteries: $name OK ($((SECONDS - start)) s)"
	else
		rc=$?
		echo "run-batteries: $name ÉCHEC (code $rc)"
		failed+=("$name")
	fi
	echo "::endgroup::"
done

if [[ "$ran" -eq 0 ]]; then
	echo "run-batteries: aucune batterie pour le motif $pattern"
	exit 0
fi
if [[ ${#failed[@]} -gt 0 ]]; then
	echo "::error::batteries en échec : ${failed[*]}"
	exit 1
fi
echo "run-batteries: $ran batteries OK"
