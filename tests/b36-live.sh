#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Vincent Tisseront
#
# b36-live — modules d'analyse du code IA de la 0.7 (chantier F) avec le vrai
# podman (job CI ia-modules-live, machine de test root jetable). Aucun n'a
# d'image amont : chaque image est construite ici depuis modules/<id>/image
# (même construction que tool-images.yml).
# 1. Modules hors ligne, agentic-radar (K7), mcp-scanner (K5) et skill-scanner
# (K6) : chaque banc d'essai tourne exactement comme sur l'appliance
# (tests/lib/modcheck.py podman) : outil de l'appliance monté en
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
# 2. Modules par le relais IA, vulnhuntr (K3), mcp-scanner-llm et
# skill-scanner-llm (juges LLM de K5 et K6) : le vrai runner lance chaque banc
# d'essai en --network=none à travers le pont de l'appliance, vers le vrai
# relais de scanoria-ai (contrat 31, comme b35-live) servi en HTTPS avec le
# certificat de la vraie AC interne ; Ollama est un faux en mémoire qui répond
# comme un modèle (webui/tests/live/ia-relay-harness.ts). Cas : analyse « ok »,
# SARIF valide, attentes tenues, mêmes résultats que l'enregistrement, appels
# journalisés au nom du module, aucun outil transmis à Ollama, modèle de
# l'appliance ; projet « aucun envoi à l'IA » : skipped, rien envoyé ; jetons
# et conteneurs retirés.
# Dépendances : bash, python3, python3-yaml, python3-jsonschema, jq, curl,
# openssl, podman, node et webui/node_modules (root).

set -euo pipefail
export PYTHONDONTWRITEBYTECODE=1

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
MC="$ROOT/tests/lib/modcheck.py"
WORK=$(mktemp -d)
RELAY_PID=
cleanup() {
	[[ -n "$RELAY_PID" ]] && kill "$RELAY_PID" 2> /dev/null || true
	podman ps -a --format '{{.Names}}' | grep -E '^(scanoria-scan-|b36-)' | xargs -r podman rm -f > /dev/null 2>&1 || true
	podman secret ls --format '{{.Name}}' | grep '^scanoria-relay-' | xargs -r podman secret rm > /dev/null 2>&1 || true
	rm -rf "$WORK"
}
trap cleanup EXIT
[[ "$(id -u)" -eq 0 ]] || { echo "b36-live : root requis (podman et runner réels)" >&2; exit 2; }
for t in podman curl python3 jq timeout sha256sum openssl node; do command -v "$t" > /dev/null || { echo "outil manquant : $t" >&2; exit 2; }; done

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

# Image du module construite depuis modules/<id>/image, contrôlée (utilisateur,
# étiquette, santé, aucun réseau) ; tag dans $tag. Code 1 si elle n'est pas utilisable.
build_image() { # id
	local id=$1 mod="$ROOT/modules/$1" version epoch health v ifs
	yq "$mod/module.yaml" > "$WORK/$id.json"
	version=$(jq -r .version "$WORK/$id.json")
	tag="localhost/scanoria-$id:${version//+/_}"
	epoch=$(git -C "$ROOT" log -1 --format=%ct -- "modules/$id/image" 2> /dev/null || echo 0)
	if python3 "$MC" containerfile "$mod/image/Containerfile" "$id" > "$WORK/cf.log"; then ok "$id : Containerfile conforme"
	else ko "$id : Containerfile refusé"; sed 's/^/     /' "$WORK/cf.log"; return 1; fi
	if podman build -q --pull=always --timestamp "$epoch" --build-arg "SOURCE_DATE_EPOCH=$epoch" -t "$tag" "$mod/image" > "$WORK/build.log" 2>&1; then
		ok "$id : image construite"
	else
		ko "$id : construction en échec"; tail -40 "$WORK/build.log" | sed 's/^/     /'; return 1
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
}

# --- 1. Modules hors ligne ---------------------------------------------------------------------------
for id in agentic-radar mcp-scanner skill-scanner; do
	echo "::group::$id"
	mod="$ROOT/modules/$id"
	build_image "$id" || { echo "::endgroup::"; continue; }

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

# --- 2. Modules par le relais IA (contrat 31, comme b35-live) ---------------------------------------
RUNNER="$ROOT/src/rootfs/usr/sbin/scanoria-runner"
CA="$ROOT/src/rootfs/usr/sbin/scanoria-ca"
[[ -x "$ROOT/webui/node_modules/.bin/esbuild" ]] || { echo "webui/node_modules absent (npm ci)" >&2; exit 2; }
T="$WORK/root"
STUBS="$WORK/stubs"
SCANS="$T/var/lib/scanoria/scans"
RT="$T/run/scanoria-ai"
TOK_DIR="$T/run/scanoria-relay/tokens"
LIVE="$WORK/live"
N=analyse.exemple.test
TOOLS_T="$T/usr/lib/scanoria/scan-tools"
mkdir -p "$T/etc/scanoria" "$T/var/lib/scanoria/modules" "$T/var/lib/scanoria/uploads" "$T/run/scanoria" "$RT" \
	"$T/proc" "$T/etc/ssl/certs" "$TOOLS_T" "$STUBS" "$LIVE"
chmod 0700 "$RT"
cp /proc/meminfo "$T/proc/meminfo"
grep '^processor' /proc/cpuinfo > "$T/proc/cpuinfo"
cp /etc/ssl/certs/ca-certificates.crt "$T/etc/ssl/certs/ca-certificates.crt"
for t in ai-relay vulnhuntr mcp-scanner skill-scanner; do cp -R "$ROOT/src/rootfs/usr/lib/scanoria/scan-tools/$t" "$TOOLS_T/"; done
find "$TOOLS_T" -name __pycache__ -prune -exec rm -rf {} +
chmod -R a+rX,go-w "$TOOLS_T"
ln -s "$(command -v podman)" "$STUBS/podman"
export SCANORIA_TEST_ROOT="$T" SCANORIA_TEST_BIN="$STUBS"
jq -n --arg f "$N" '{fqdn: $f}' > "$T/etc/scanoria/appliance.json"

SCANORIA_TEST_BIN='' "$CA" init --fqdn "$N" > /dev/null
expect "AC interne : certificat ai-relay émis" "$(SCANORIA_TEST_BIN='' "$CA" issue-relay --fqdn "$N" | jq -r .code)" OK
cp "$T/etc/scanoria/pki/ai-relay/fullchain.pem" "$RT/relay.crt"
cp "$T/etc/scanoria/pki/ai-relay/privkey.pem" "$RT/relay.key"
chmod 0400 "$RT/relay.crt" "$RT/relay.key"
jq -n '{version: 1, enabled: true, url: "https://ollama.exemple.test:11434", scheme: "https", host: "ollama.exemple.test",
	port: 11434, addresses: ["192.0.2.10"], insecure: false, token: false, ca: false, literal: false, pinned_at: "2026-11-25T08:00:00Z"}' > "$RT/ai.json"
(cd "$ROOT/webui" && node_modules/.bin/esbuild tests/live/ia-relay-harness.ts --bundle --platform=node --format=esm --target=node22 \
	--external:pg-native --alias:#shared=./shared --log-level=warning --outfile="$WORK/ia-relay-harness.mjs" \
	"--banner:js=import { createRequire as __r } from 'node:module'; const require = __r(import.meta.url);")
uuid() { python3 -c 'import uuid; print(uuid.uuid4())'; }
OPT_OUT=$(uuid)
PROJ=$(uuid)
RELAY_RUNTIME_DIR="$RT" RELAY_LIVE_DIR="$LIVE" RELAY_TOKEN_DIR="$TOK_DIR" RELAY_OPT_OUT="$OPT_OUT" \
	node "$WORK/ia-relay-harness.mjs" 2>> "$LIVE/relay.err" &
RELAY_PID=$!
for _ in $(seq 100); do [[ -S "$RT/relay.sock" ]] && break; sleep 0.1; done
touch "$LIVE/calls.jsonl" "$LIVE/ollama.jsonl"
if [[ -S "$RT/relay.sock" ]]; then ok "relais en écoute sur le socket du runner"; else ko "relais absent"; cat "$LIVE/relay.err"; exit 1; fi

# Registre des modules installés : manifeste du dépôt, image construite ici.
echo '{"modules": {}, "operations": []}' > "$T/var/lib/scanoria/modules/installed.json"
register() { # id tag
	local reg="$T/var/lib/scanoria/modules/installed.json"
	jq --arg id "$1" --arg img "$2" --slurpfile m "$WORK/$1.json" \
		'.modules[$id] = {manifest: ($m[0] | del(.image_pending) | .image = $img), status: "healthy", enabled: true,
		  options: {}, installed_at: "2026-11-25T08:00:00Z"}' "$reg" > "$reg.new"
	mv "$reg.new" "$reg"
}
job() { # id projet module version testbed
	local up; up=$(uuid)
	mkdir -p "$T/var/lib/scanoria/uploads/$up"
	tar -C "$5" -czf "$T/var/lib/scanoria/uploads/$up/source.tar.gz" .
	jq -cn --arg id "$1" --arg sid "$(uuid)" --arg up "$up" --arg p "$2" --arg m "$3" --arg v "$4" \
		'{schema: 1, id: $id, scan_id: $sid, project_id: $p, created_at: "2026-11-25T10:00:00Z",
		  source: {kind: "archive", upload_id: $up}, modules: [{id: $m, version: $v}]}' > "$SCANS/jobs/incoming/$1.json"
	chmod 0600 "$SCANS/jobs/incoming/$1.json"
	"$RUNNER" --once 2> "$WORK/runner.err" || echo "runner : code $?"
	sed 's/^/     runner: /' "$WORK/runner.err" | tail -n 20
}
mod_of() { jq -c --arg m "$2" '.modules[] | select(.id == $m)' "$SCANS/results/$1/result.json" 2> /dev/null || echo '{}'; }
after() { # libellé
	expect "$1 : jeton retiré" "$(find "$TOK_DIR" -type f 2> /dev/null | wc -l)" 0
	expect "$1 : secret Podman retiré" "$(podman secret ls --format '{{.Name}}' | grep -c '^scanoria-relay-' || true)" 0
	expect "$1 : aucun conteneur laissé" "$(podman ps -a --format '{{.Names}}' | grep -c '^scanoria-scan-' || true)" 0
}
"$RUNNER" --once 2> /dev/null || true   # arborescence

for id in vulnhuntr mcp-scanner-llm skill-scanner-llm; do
	echo "::group::$id"
	mod="$ROOT/modules/$id"
	build_image "$id" || { echo "::endgroup::"; continue; }
	expect "$id : réseau du manifeste = relais IA" "$(jq -r .scan.network "$WORK/$id.json")" ai-relay
	# Le runner n'accepte qu'une image épinglée par empreinte : référence locale par empreinte.
	ref="${tag%:*}@$(podman image inspect --format '{{.Digest}}' "$tag")"
	if podman image exists "$ref"; then ok "$id : image locale joignable par empreinte"; else ko "$id : image locale sans empreinte ($ref)"; fi
	register "$id" "$ref"
	version=$(jq -r .version "$WORK/$id.json")
	src="$WORK/$id-src"
	cp -R "$mod/testbed" "$src"
	calls=$(wc -l < "$LIVE/calls.jsonl" 2> /dev/null || echo 0)
	jid=$(uuid); job "$jid" "$PROJ" "$id" "$version" "$src"
	M=$(mod_of "$jid" "$id")
	expect "$id : analyse ok par le relais" "$(jq -r .status <<< "$M")" ok
	[[ "$(jq -r .status <<< "$M")" == ok ]] || { jq . <<< "$M"; tail -n 40 "$SCANS/results/$jid/"*.log 2> /dev/null || true; tail -n 20 "$LIVE/relay.err"; }
	sarif=$(find "$SCANS/results/$jid" -name '*.sarif' | head -n 1)
	if [[ -n "$sarif" && -s "$sarif" ]] && python3 "$MC" sarif "$WORK/sarif-schema.json" "$sarif" > "$WORK/s.log" 2>&1; then
		ok "$id : SARIF 2.1.0 valide (schéma OASIS)"
		if python3 "$MC" expect "$mod/module.yaml" "$sarif" > "$WORK/e.log"; then ok "$id : attentes du banc d'essai"
		else ko "$id : attentes du banc d'essai"; fi
		sed 's/^/     /' "$WORK/e.log"
		expect "$id : chemins relatifs au dépôt" \
			"$(jq -r '[.runs[].results[].locations[]?.physicalLocation.artifactLocation.uri | select(startswith("/") or startswith("file:") or contains(".."))] | length' "$sarif")" 0
		if diff <(rel_sort "$sarif") <(rel_sort "$mod/tests/recorded.sarif") > "$WORK/d.log"; then ok "$id : résultats identiques à l'enregistrement"
		else ko "$id : résultats différents de l'enregistrement"; sed 's/^/     /' "$WORK/d.log" | head -30; fi
	else
		ko "$id : SARIF absent ou invalide"; sed 's/^/     /' "$WORK/s.log" 2> /dev/null || true
	fi
	new=$(tail -n +"$((calls + 1))" "$LIVE/calls.jsonl" 2> /dev/null || true)
	expect "$id : appels journalisés au nom du module et du projet" \
		"$(jq -s -c --arg p "$PROJ" --arg m "$id" '[length > 0, all(.module == $m and .project == $p and .outcome == "ok")]' <<< "$new")" '[true,true]'
	after "$id"
	echo "::endgroup::"
done
expect "Ollama : aucun outil transmis" "$(jq -s '[.[].keys[] | select(test("tool"))] | length' "$LIVE/ollama.jsonl")" 0
expect "Ollama : modèle de l'appliance seulement" "$(jq -r -s '[.[].model] | unique | join(",")' "$LIVE/ollama.jsonl")" faux-modele:7b

# Projet « aucun envoi à l'IA » : module sauté, rien envoyé.
if [[ -n "${tag:-}" ]]; then
	n=$(wc -l < "$LIVE/ollama.jsonl")
	jid=$(uuid); job "$jid" "$OPT_OUT" vulnhuntr "$(jq -r .version "$WORK/vulnhuntr.json")" "$ROOT/modules/vulnhuntr/testbed"
	expect "aucun envoi à l'IA : vulnhuntr skipped, E_RELAY_OPT_OUT" "$(mod_of "$jid" vulnhuntr | jq -r '.status + " " + .error.code')" "skipped E_RELAY_OPT_OUT"
	expect "aucun envoi à l'IA : rien reçu par Ollama" "$(wc -l < "$LIVE/ollama.jsonl")" "$n"
	after "aucun envoi"
fi

echo
echo "b36-live : $PASS réussis, $FAIL échoués"
[[ "$FAIL" -eq 0 ]]
