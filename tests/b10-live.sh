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
# Les bases (feeds) sont téléchargées AVANT, avec réseau, hors du conteneur
# confiné, par feeds.py (le code du helper de l'appliance), comme sur une
# appliance neuve : la CI ne pré-remplit plus rien à la place de l'appliance.
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
		# Les scanners reliés à un service (sonar-scanner) ont leur propre batterie (b17-live),
		# ceux de la catégorie sbom (Syft, Grype, dtrack-upload) la leur (b19-live).
		# Un module en attente d'image (image_pending, 0.7) est éprouvé par la batterie -live qui
		# construit son image localement (b36-live pour les modules d'analyse IA).
		[[ "$(yq "$f" | jq -r '.type == "scanner" and (.image_pending != true) and (.scan.network | startswith("service:") | not) and (.categories | index("sbom") | not)')" == true ]] \
			&& ids+=("$(basename "$(dirname "$f")")")
	done
fi

# --- Bases (avec réseau, avant les analyses) ---------------------------------------------
# Téléchargées par le code même de l'appliance (feeds.py, 0.3.4), jamais par un
# outil propre à la CI : une base que l'appliance ne saurait pas obtenir fait
# échouer ce test. Racine de test temporaire ; curl réel.
FEEDROOT="$WORK/root"
mkdir -p "$FEEDROOT/var/lib/scanoria" "$WORK/bin"
ln -s "$(command -v curl)" "$WORK/bin/curl"
prepare_feed() { # id
	[[ -e "$FEEDROOT/var/lib/scanoria/feeds/$1" ]] && return 0
	yq "$ROOT/modules/$1/module.yaml" > "$WORK/feed-$1.json"
	SCANORIA_TEST_ROOT="$FEEDROOT" SCANORIA_TEST_BIN="$WORK/bin" \
		python3 -c 'import json, sys; sys.path.insert(0, sys.argv[1]); from scanoria import feeds
print(feeds.refresh(json.load(open(sys.argv[2])), None, timeout=1500))' \
		"$ROOT/src/rootfs/usr/lib/scanoria/py" "$WORK/feed-$1.json"
	# Podman rootless : 65534 du conteneur n'est pas le groupe 65534 de l'hôte
	# (sur l'appliance, root:65534 en 0640 suffit) ; lecture ouverte ici seulement.
	chmod -R a+rX "$FEEDROOT/var/lib/scanoria/feeds"
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
	python3 "$MC" podman "$m" "$src" "$out" "$FEEDROOT/var/lib/scanoria/feeds" > "$WORK/$id.args" \
		|| { ko "$id : arguments podman non générés"; echo "::endgroup::"; continue; }
	mapfile -d '' args < "$WORK/$id.args"
	# Nom fixe : le conteneur est supprimé même si « timeout » tue le client.
	args=("${args[0]}" "--name=b10-$id-$$" "${args[@]:1}")
	echo "podman ${args[*]}"
	rc=0
	timeout "$(jq -r .scan.timeout_s "$WORK/$id.json")" podman "${args[@]}" > "$WORK/$id.log" 2>&1 || rc=$?
	podman rm -f "b10-$id-$$" > /dev/null 2>&1 || true
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
