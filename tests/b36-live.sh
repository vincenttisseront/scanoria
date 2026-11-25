#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Vincent Tisseront
#
# b36-live — modules d'analyse du code IA de la 0.7 (chantier F) avec le vrai
# podman (job CI ia-modules-live, machine de test jetable) : agentic-radar
# (K7), mcp-scanner (K5) et skill-scanner (K6) n'ont pas d'image amont ; leur
# image est construite ici depuis modules/<id>/image (même construction que
# tool-images.yml), puis chaque banc d'essai tourne exactement comme sur
# l'appliance (tests/lib/modcheck.py podman) : outil de l'appliance monté en
# lecture seule sur /scanoria, --network=none, --read-only, sources en lecture
# seule, --cap-drop=ALL, no-new-privileges, utilisateur 65534, limites et délai
# du manifeste.
# Cas :
#   - image construite, utilisateur 65534, aucune interface réseau hors lo ;
#   - santé (health.command) ;
#   - banc d'essai : SARIF 2.1.0 valide (schéma OASIS), attentes tenues
#     (testbed.expect), chemins relatifs au dépôt ;
#   - agentic-radar : inventaire présent dans le SARIF ;
#   - skill-scanner : la skill du banc d'essai analysée, aucun échec ;
#   - mêmes résultats que l'enregistrement converti (aucune dérive de l'outil) ;
#   - aucun conteneur laissé, sources intactes.
# Dépendances : bash, python3, python3-yaml, python3-jsonschema, jq, curl, podman.

set -euo pipefail
export PYTHONDONTWRITEBYTECODE=1

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
MC="$ROOT/tests/lib/modcheck.py"
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
for t in podman curl python3 jq timeout sha256sum; do command -v "$t" > /dev/null || { echo "outil manquant : $t" >&2; exit 2; }; done

PASS=0
FAIL=0
ok() { PASS=$((PASS + 1)); printf 'ok   %s\n' "$1"; }
ko() { FAIL=$((FAIL + 1)); printf 'FAIL %s\n' "$1"; }
expect() {
	if [[ "$2" == "$3" ]]; then ok "$1"; else ko "$1 (obtenu « $2 », attendu « $3 »)"; fi
}
yq() { python3 -c 'import json, sys, yaml; print(json.dumps(yaml.safe_load(open(sys.argv[1], encoding="utf-8"))))' "$1"; }

# Schéma SARIF 2.1.0 officiel (OASIS), épinglé par commit et empreinte (comme b10-live).
SARIF_COMMIT=1742a253eb654bf8a4ed7c60eaef7412b2c23553
SARIF_SHA256=c3b4bb2d6093897483348925aaa73af03b3e3f4bd4ca38cef26dcb4212a2682e
curl --proto '=https' --tlsv1.2 -fsSL --retry 3 -o "$WORK/sarif-schema.json" \
	"https://raw.githubusercontent.com/oasis-tcs/sarif-spec/$SARIF_COMMIT/sarif-2.1/schema/sarif-schema-2.1.0.json"
echo "$SARIF_SHA256  $WORK/sarif-schema.json" | sha256sum --check --strict --quiet

rel_sort() { jq -S '[.runs[0].results[] | {ruleId, uri: (.locations[0].physicalLocation.artifactLocation.uri // null)}] | sort_by(.ruleId, .uri) | unique' "$1"; }

for id in agentic-radar mcp-scanner skill-scanner; do
	echo "::group::$id"
	mod="$ROOT/modules/$id"
	yq "$mod/module.yaml" > "$WORK/$id.json"
	version=$(jq -r .version "$WORK/$id.json")
	tag="localhost/scanoria-$id:${version//+/_}"
	epoch=$(git -C "$ROOT" log -1 --format=%ct -- "modules/$id/image" 2> /dev/null || echo 0)

	# --- Image ---------------------------------------------------------------------------------
	if python3 "$MC" containerfile "$mod/image/Containerfile" "$id" > "$WORK/cf.log"; then ok "$id : Containerfile conforme"
	else ko "$id : Containerfile refusé"; sed 's/^/     /' "$WORK/cf.log"; echo "::endgroup::"; continue; fi
	if podman build -q --pull=always --timestamp "$epoch" --build-arg "SOURCE_DATE_EPOCH=$epoch" -t "$tag" "$mod/image" > "$WORK/build.log" 2>&1; then
		ok "$id : image construite"
	else
		ko "$id : construction en échec"; tail -40 "$WORK/build.log" | sed 's/^/     /'; echo "::endgroup::"; continue
	fi
	expect "$id : utilisateur 65534" "$(podman run --rm --network=none --entrypoint id "$tag" -u)" 65534
	expect "$id : étiquette io.scanoria.module" "$(podman image inspect --format '{{ index .Labels "io.scanoria.module" }}' "$tag")" "$id"
	mapfile -t health < <(jq -r '.health.command[]' "$WORK/$id.json")
	if v=$(podman run --rm --network=none --read-only --cap-drop=ALL --security-opt=no-new-privileges --user 65534:65534 \
		--tmpfs /tmp --env HOME=/tmp --entrypoint "${health[0]}" "$tag" "${health[@]:1}" 2> "$WORK/h.log"); then
		expect "$id : santé (version de l'outil)" "$v" "$version"
	else ko "$id : santé en échec"; sed 's/^/     /' "$WORK/h.log"; fi
	# Confinement réseau : aucune interface hors lo dans le conteneur du scanner.
	ifs=$(podman run --rm --network=none --entrypoint python3 "$tag" -I -c 'import socket; print(",".join(sorted(n for _, n in socket.if_nameindex())))')
	expect "$id : aucun réseau (interfaces)" "$ifs" lo

	# --- Banc d'essai, confiné comme sur l'appliance ---------------------------------------------
	src="$WORK/$id-src"
	out="$WORK/$id-out"
	cp -R "$mod/testbed" "$src"
	chmod -R a+rX,go-w "$src"
	mkdir -p "$out"
	chmod 0777 "$out"
	before=$(cd "$src" && find . -type f -exec sha256sum {} + | sort | sha256sum)
	python3 "$MC" podman "$mod/module.yaml" "$src" "$out" "$WORK/feeds" "$tag" > "$WORK/$id.args"
	mapfile -d '' -t args < "$WORK/$id.args"
	args=("${args[0]}" "${args[1]}" "--name=b36-$id-$$" "${args[@]:2}")
	rc=0
	timeout "$(jq -r .scan.timeout_s "$WORK/$id.json")" podman "${args[@]}" > "$WORK/$id.log" 2>&1 || rc=$?
	podman rm -f "b36-$id-$$" > /dev/null 2>&1 || true
	expect "$id : analyse terminée" "$rc" 0
	[[ "$rc" -eq 0 ]] || tail -40 "$WORK/$id.log" | sed 's/^/     /'
	sarif="$out/$(basename "$(jq -r .outputs.sarif.path "$WORK/$id.json")")"
	if [[ -s "$sarif" ]] && python3 "$MC" sarif "$WORK/sarif-schema.json" "$sarif" > "$WORK/s.log" 2>&1; then ok "$id : SARIF 2.1.0 valide (schéma OASIS)"
	else ko "$id : SARIF absent ou invalide"; sed 's/^/     /' "$WORK/s.log" 2> /dev/null || true; echo "::endgroup::"; continue; fi
	if python3 "$MC" expect "$mod/module.yaml" "$sarif" > "$WORK/e.log"; then ok "$id : attentes du banc d'essai"
	else ko "$id : attentes du banc d'essai"; fi
	sed 's/^/     /' "$WORK/e.log"
	expect "$id : chemins relatifs au dépôt" \
		"$(jq -r '[.runs[].results[].locations[]?.physicalLocation.artifactLocation.uri | select(startswith("/") or startswith("file:") or contains(".."))] | length' "$sarif")" 0
	expect "$id : sources intactes" "$(cd "$src" && find . -type f -exec sha256sum {} + | sort | sha256sum)" "$before"
	# Même résultat que l'enregistrement : une dérive de l'outil amont est signalée ici.
	if diff <(rel_sort "$sarif") <(rel_sort "$mod/tests/recorded.sarif") > "$WORK/d.log"; then ok "$id : résultats identiques à l'enregistrement"
	else ko "$id : résultats différents de l'enregistrement"; sed 's/^/     /' "$WORK/d.log" | head -30; fi
	case "$id" in
		agentic-radar)
			expect "$id : inventaire des agents" "$(jq -r '.runs[0].properties["scanoria/agent-inventory"].frameworks | join(",")' "$sarif")" langgraph ;;
		skill-scanner)
			expect "$id : skill analysée, aucun échec" "$(jq -c '.runs[0].properties["scanoria/skills"]' "$sarif")" '{"analysed":1,"failed":[]}' ;;
	esac
	echo "::endgroup::"
done

expect "aucun conteneur laissé" "$(podman ps -a --filter "name=b36-" --format '{{.Names}}' | wc -l)" 0

echo
echo "b36-live : $PASS réussis, $FAIL échoués"
[[ "$FAIL" -eq 0 ]]
