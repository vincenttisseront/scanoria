#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Vincent Tisseront
#
# b10-live — chaque module scanner sur son banc d'essai, en vrai conteneur
# Podman confiné (CLAUDE.md § 6.4) : --network=none, --read-only, sources en
# lecture seule sur /src, /out écrivable, --cap-drop=ALL, no-new-privileges,
# utilisateur 65534, limites mémoire/CPU/PIDs, délai maximal (scan.timeout_s).
# Contrôles : code de sortie dans scan.exit_codes_ok, sortie conforme au schéma
# SARIF 2.1.0 officiel (G2), attentes testbed.expect (F12).
#
# Les bases (feeds) sont préparées AVANT, avec réseau, hors du conteneur
# confiné : trivy-db par l'image Trivy épinglée (--download-db-only), osv-db par
# l'export public OSV (écosystème npm seulement, celui du banc d'essai).
# Lancé par le job CI « modules-testbed-live » (podman rootless du runner).
# Usage : b10-live.sh [ID…]   (défaut : tous les modules scanner)
# Dépendances : podman, curl, python3, python3-yaml, python3-jsonschema, jq.

# shellcheck disable=SC2015
set -euo pipefail
export PYTHONDONTWRITEBYTECODE=1

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
MC="$ROOT/tests/lib/modcheck.py"
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
for t in podman curl python3 jq timeout; do command -v "$t" > /dev/null || { echo "outil manquant : $t" >&2; exit 2; }; done

# Schéma SARIF 2.1.0 officiel (OASIS, dépôt oasis-tcs/sarif-spec), épinglé par
# commit et empreinte (relevés le 2026-11-24).
SARIF_COMMIT=1742a253eb654bf8a4ed7c60eaef7412b2c23553
SARIF_SHA256=c3b4bb2d6093897483348925aaa73af03b3e3f4bd4ca38cef26dcb4212a2682e

PASS=0
FAIL=0
ok() { PASS=$((PASS + 1)); printf 'ok   %s\n' "$1"; }
ko() { FAIL=$((FAIL + 1)); printf 'FAIL %s\n' "$1"; }
yq() { python3 -c 'import json, sys, yaml; print(json.dumps(yaml.safe_load(open(sys.argv[1], encoding="utf-8"))))' "$1"; }

curl --proto '=https' --tlsv1.2 -fsSL --retry 3 -o "$WORK/sarif-schema.json" \
	"https://raw.githubusercontent.com/oasis-tcs/sarif-spec/$SARIF_COMMIT/sarif-2.1/schema/sarif-schema-2.1.0.json"
echo "$SARIF_SHA256  $WORK/sarif-schema.json" | sha256sum --check --strict --quiet

ids=("$@")
if [[ ${#ids[@]} -eq 0 ]]; then
	for f in "$ROOT"/modules/*/module.yaml; do
		[[ "$(yq "$f" | jq -r .type)" == scanner ]] && ids+=("$(basename "$(dirname "$f")")")
	done
fi

# --- Bases (avec réseau, avant les analyses) ---------------------------------------------
prepare_feed() { # id
	local dir="$WORK/feeds/$1"
	[[ -d "$dir" ]] && return 0
	mkdir -p "$dir"
	case "$1" in
		trivy-db)
			local image
			image=$(yq "$ROOT/modules/trivy/module.yaml" | jq -r .image)
			podman pull -q "$image" > /dev/null
			# Préparation seulement (avec réseau, hors analyse) : root du conteneur
			# = utilisateur du runner en podman rootless, pour que les fichiers
			# téléchargés lui appartiennent (lecture par 65534 ensuite, :ro).
			podman run --rm --user=0:0 --env=HOME=/tmp --tmpfs=/tmp -v "$dir:/cache:rw" \
				--entrypoint=trivy "$image" --cache-dir /cache image --download-db-only --no-progress ;;
		osv-db)
			mkdir -p "$dir/osv-scalibr/npm"
			curl --proto '=https' --tlsv1.2 -fsSL --retry 3 -o "$dir/osv-scalibr/npm/all.zip" \
				https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip ;;
		*) echo "feed inconnu de b10-live : $1" >&2; return 1 ;;
	esac
	chmod -R a+rX,go-w "$dir"
	echo "feed prêt : $1 ($(du -sh "$dir" | cut -f1))"
}

for id in "${ids[@]}"; do
	m="$ROOT/modules/$id/module.yaml"
	yq "$m" > "$WORK/$id.json"
	echo "::group::$id"
	for feed in $(jq -r '.requires.feeds[]' "$WORK/$id.json"); do prepare_feed "$feed"; done
	image=$(jq -r .image "$WORK/$id.json")
	podman pull -q "$image" > /dev/null
	# Copie du banc d'essai : lisible par 65534, jamais modifiable (montage :ro).
	src="$WORK/src-$id"
	out="$WORK/out-$id"
	cp -R "$ROOT/modules/$id/$(jq -r .testbed.path "$WORK/$id.json")" "$src"
	chmod -R a+rX,go-w "$src"
	mkdir -p "$out"
	chmod 0777 "$out"
	mapfile -d '' args < <(python3 "$MC" podman "$m" "$src" "$out" "$WORK/feeds")
	echo "podman ${args[*]}"
	rc=0
	timeout "$(jq -r .scan.timeout_s "$WORK/$id.json")" podman "${args[@]}" > "$WORK/$id.log" 2>&1 || rc=$?
	tail -n 20 "$WORK/$id.log"
	if jq -e --argjson rc "$rc" '(.scan.exit_codes_ok // [0]) | index($rc) != null' "$WORK/$id.json" > /dev/null; then
		ok "$id : code de sortie $rc accepté"
	else
		ko "$id : code de sortie $rc hors de scan.exit_codes_ok"
	fi
	sarif="$out/$(basename "$(jq -r .outputs.sarif.path "$WORK/$id.json")")"
	if [[ ! -s "$sarif" ]]; then
		ko "$id : sortie SARIF absente ou vide"
		echo "::endgroup::"
		continue
	fi
	if python3 "$MC" sarif "$WORK/sarif-schema.json" "$sarif"; then ok "$id : SARIF 2.1.0 conforme au schéma officiel"
	else ko "$id : SARIF non conforme"; fi
	if python3 "$MC" expect "$m" "$sarif"; then ok "$id : attentes du banc d'essai satisfaites"
	else ko "$id : attentes du banc d'essai non satisfaites"; jq -c '[.runs[].results[].ruleId]' "$sarif"; fi
	# Aucune valeur de secret dans la sortie (CLAUDE.md § 6.3) : chaque valeur
	# affectée dans le banc d'essai (après « = » ou « : ») est cherchée.
	leaked=0
	while IFS= read -r secret; do
		[[ ${#secret} -ge 20 ]] && grep -qF -- "$secret" "$sarif" && leaked=1
	done < <(grep -rhoE '(=|: *")[A-Za-z0-9_.-]{20,}' "$src" | sed -E 's/^(=|: *")//')
	[[ "$leaked" -eq 0 ]] && ok "$id : aucune valeur de secret dans la sortie" || ko "$id : valeur de secret dans la sortie"
	echo "::endgroup::"
done

printf '\nb10-live : %d réussis, %d échecs\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
