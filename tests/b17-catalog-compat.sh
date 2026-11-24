#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Vincent Tisseront
#
# b17-catalog-compat — l'index du catalogue construit depuis cette branche est
# accepté par le vérificateur de la dernière version publiée de l'appliance
# (étiquette vX.Y.Z la plus haute). Une appliance installée lit le nouvel index
# avec son propre schéma : un champ qu'elle ne connaît pas ferait rejeter tout
# l'index (E_CHECKSUM) et bloquerait son catalogue. Les modules réservés à une
# version plus récente doivent porter requires.appliance, que l'ancienne
# version refuse proprement à l'installation.
# Sans root. Réseau seulement pour récupérer l'étiquette si elle manque (CI,
# clone superficiel) ; hors CI, l'absence d'étiquette saute le test.
# Dépendances : bash, git, python3 (PyYAML), zstd, tar.

set -euo pipefail
export PYTHONDONTWRITEBYTECODE=1

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
PASS=0
FAIL=0
ok() { PASS=$((PASS + 1)); printf 'ok   %s\n' "$1"; }
ko() { FAIL=$((FAIL + 1)); printf 'FAIL %s\n' "$1"; }

cd "$ROOT"
latest() { git tag -l 'v*' | { grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$' || true; } | sort -V | tail -1; }
TAG=$(latest)
if [[ -z "$TAG" ]]; then
	TAG=$(git ls-remote --tags --refs origin 'v*' 2>/dev/null | sed -n 's#.*refs/tags/##p' |
		grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$' | sort -V | tail -1 || true)
	if [[ -n "$TAG" ]]; then
		git fetch --quiet --depth=1 --no-tags origin "refs/tags/$TAG:refs/tags/$TAG" || TAG=""
	fi
fi
if [[ -z "$TAG" ]]; then
	if [[ -n "${CI:-}" ]]; then
		ko "étiquette de la dernière version publiée introuvable"
		echo "b17-catalog-compat : $PASS ok, $FAIL échec(s)"
		exit 1
	fi
	echo "b17-catalog-compat : aucune étiquette vX.Y.Z, test sauté hors CI"
	exit 0
fi
echo "dernière version publiée : $TAG"

mkdir -p "$TMP/old"
if git archive "$TAG" src/rootfs/usr/lib/scanoria/py src/rootfs/usr/share/scanoria/schemas |
	tar -x -C "$TMP/old"; then
	ok "vérificateur de $TAG extrait"
else
	ko "extraction du vérificateur de $TAG"
fi

if python3 catalog/build.py build --out "$TMP/idx" >"$TMP/build.log" 2>&1; then
	ok "index construit ($(tail -1 "$TMP/build.log"))"
else
	ko "construction de l'index : $(tail -3 "$TMP/build.log")"
fi

if [[ -f "$TMP/idx/catalog-index.json" && -d "$TMP/old/src" ]]; then
	if out=$(python3 -I tests/lib/catalog_compat.py "$TMP/old" "$TAG" "$TMP/idx/catalog-index.json"); then
		ok "$out"
	else
		ko "index refusé par $TAG : $out"
	fi
	# Le test lui-même : un champ inconnu dans requires doit être refusé.
	python3 -I - "$TMP/idx/catalog-index.json" "$TMP/bad.json" <<'PY'
import json, sys
idx = json.load(open(sys.argv[1]))
idx["modules"][0].setdefault("requires", {})["champ_inconnu"] = True
json.dump(idx, open(sys.argv[2], "w"))
PY
	if python3 -I tests/lib/catalog_compat.py "$TMP/old" "$TAG" "$TMP/bad.json" >/dev/null; then
		ko "un index avec un champ inconnu de $TAG devrait être refusé"
	else
		ok "témoin : champ inconnu de $TAG refusé"
	fi
fi

echo "b17-catalog-compat : $PASS ok, $FAIL échec(s)"
[[ $FAIL -eq 0 ]]
