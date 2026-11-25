#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Vincent Tisseront
#
# b31-live — modules SAST, IaC et CI (0.7, chantier A) avec le vrai podman (job
# CI sast-live, machine de test root jetable), confinés comme sur l'appliance :
# --network=none, --read-only, sources en lecture seule, --cap-drop=ALL,
# utilisateur 65534, /rules monté en lecture seule. Cas :
#   - image : épinglée par empreinte (podman pull) ou construite depuis
#     modules/<id>/image (opengrep, zizmor, scorecard : verify.sh d'abord) ;
#     version de l'outil égale à celle du manifeste ;
#   - banc d'essai de l'installation (F12) par le code même du helper ;
#   - analyse du banc d'essai par le vrai scanoria-runner : SARIF valide
#     (schéma OASIS), chemins relatifs, aucune valeur de secret ; la sortie
#     est affichée (base64 de gzip) pour tests/recorded.sarif ;
#   - Opengrep avec un jeu de règles G4 : règle du jeu trouvée en plus des
#     règles maison, identifiant non préfixé ; jeu invalide → module en erreur
#     E_RULESET_INVALID (classe input), jamais un résultat vide ;
#   - demande validate-ruleset (helper) : Opengrep, Semgrep, Checkov, KICS,
#     gitleaks, jeux valides acceptés avec les résultats par exemple, jeux
#     invalides refusés par le moteur.
# Dépendances : bash, python3, python3-yaml, python3-jsonschema, jq, curl, zstd, tar, gzip, podman (root).

# shellcheck disable=SC2015,SC2016
set -euo pipefail
export PYTHONDONTWRITEBYTECODE=1

[[ "$(id -u)" -eq 0 ]] || { echo "b31-live : root requis (podman réel)" >&2; exit 2; }
for t in python3 jq curl podman tar zstd gzip base64; do command -v "$t" > /dev/null || { echo "outil manquant : $t" >&2; exit 2; }; done

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
RUNNER="$ROOT/src/rootfs/usr/sbin/scanoria-runner"
HELPER="$ROOT/src/rootfs/usr/sbin/scanoria-helper"
PY="$ROOT/src/rootfs/usr/lib/scanoria/py"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
read -r -a MODS <<< "${B31_MODULES:-opengrep semgrep checkov kics bandit zizmor scorecard}"

PASS=0
FAIL=0
ok() { PASS=$((PASS + 1)); printf 'ok   %s\n' "$1"; }
ko() { FAIL=$((FAIL + 1)); printf 'FAIL %s\n' "$1"; }
expect() {
	if [[ "$2" == "$3" ]]; then ok "$1"; else ko "$1 (obtenu « $2 », attendu « $3 »)"; fi
}
yq() { python3 -c 'import json, sys, yaml; print(json.dumps(yaml.safe_load(open(sys.argv[1], encoding="utf-8"))))' "$1"; }
uuid() { python3 -c 'import uuid; print(uuid.uuid4())'; }

# Schéma SARIF 2.1.0 officiel (OASIS), épinglé par commit et empreinte (comme b29-live).
SARIF_COMMIT=1742a253eb654bf8a4ed7c60eaef7412b2c23553
SARIF_SHA256=c3b4bb2d6093897483348925aaa73af03b3e3f4bd4ca38cef26dcb4212a2682e
curl --proto '=https' --tlsv1.2 -fsSL --retry 3 -o "$TMP/sarif-schema.json" \
	"https://raw.githubusercontent.com/oasis-tcs/sarif-spec/$SARIF_COMMIT/sarif-2.1/schema/sarif-schema-2.1.0.json"
echo "$SARIF_SHA256  $TMP/sarif-schema.json" | sha256sum --check --strict --quiet

# --- Appliance de test : racine préfixée, podman réel ---------------------------------------
T="$TMP/root"
STUBS="$TMP/stubs"
SCANS="$T/var/lib/scanoria/scans"
mkdir -p "$T/var/lib/scanoria/modules" "$T/var/lib/scanoria/uploads" "$T/run/scanoria" "$T/proc" "$T/etc/ssl/certs" \
	"$T/usr/lib/scanoria" "$T"/var/lib/scanoria/requests/{tmp,incoming,work,done,failed} "$T/opt/scanoria/current" "$STUBS"
echo 0.7.0 > "$T/opt/scanoria/current/VERSION"
cp /proc/meminfo "$T/proc/meminfo"
grep '^processor' /proc/cpuinfo > "$T/proc/cpuinfo"
cp -R "$ROOT/src/rootfs/usr/lib/scanoria/scan-tools" "$T/usr/lib/scanoria/"
chmod -R a+rX,go-w "$T/usr"
for t in podman zstd; do ln -s "$(command -v "$t")" "$STUBS/$t"; done
printf '#!/bin/sh\nexit 0\n' > "$STUBS/systemctl"
chmod 0755 "$STUBS/systemctl"
export SCANORIA_TEST_ROOT="$T" SCANORIA_TEST_BIN="$STUBS"

# --- 1. Images ----------------------------------------------------------------------------------
declare -A IMG
for id in "${MODS[@]}"; do
	yq "$ROOT/modules/$id/module.yaml" > "$TMP/$id.json"
	if [[ "$(jq -r '.image_pending // false' "$TMP/$id.json")" == true ]]; then
		if [[ -f "$ROOT/modules/$id/image/verify.sh" ]]; then
			(cd "$ROOT/modules/$id/image" && bash ./verify.sh) > "$TMP/verify.log" 2>&1 && ok "$id : vérification amont (verify.sh)" \
				|| { ko "$id : vérification amont"; sed 's/^/     /' "$TMP/verify.log" | tail -n 5; }
			grep -h 'sha256=' "$TMP/verify.log" || true
		fi
		IMG[$id]="localhost/scanoria-$id:b31"
		if podman build -q --pull=always -t "${IMG[$id]}" "$ROOT/modules/$id/image" > "$TMP/build.log" 2>&1; then ok "$id : image construite"
		else ko "$id : construction de l'image"; tail -n 15 "$TMP/build.log" | sed 's/^/     /'; continue; fi
		# Le registre du test porte l'image locale (l'appliance reçoit l'image publiée, épinglée).
		jq --arg i "${IMG[$id]}" '.image = $i | del(.image_pending)' "$TMP/$id.json" > "$TMP/$id.j" && mv "$TMP/$id.j" "$TMP/$id.json"
	else
		IMG[$id]=$(jq -r .image "$TMP/$id.json")
		[[ "${IMG[$id]}" == *@sha256:* ]] && ok "$id : image épinglée par empreinte" || ko "$id : image non épinglée"
		podman pull -q "${IMG[$id]}" > /dev/null 2>&1 || { ko "$id : image introuvable"; continue; }
	fi
	mapfile -t health < <(jq -r '.health.command[]' "$TMP/$id.json")
	v=$(podman run --rm --network=none --read-only --cap-drop=ALL --security-opt=no-new-privileges --user 65534:65534 \
		--tmpfs /tmp --env HOME=/tmp --entrypoint "${health[0]}" "${IMG[$id]}" "${health[@]:1}" 2>&1 | head -n 3 | tr '\n' ' ' || true)
	echo "     $id : ${health[*]} → $v"
	want=$(jq -r .version "$TMP/$id.json")
	[[ "$v" == *"$want"* ]] && ok "$id : version $want de l'outil" || ko "$id : version de l'outil différente du manifeste ($want)"
done

python3 - "$T/var/lib/scanoria/modules/installed.json" "$TMP" "${MODS[@]}" <<'EOF'
import json, os, sys
path, tmp, ids = sys.argv[1], sys.argv[2], sys.argv[3:]
mods = {}
for i in ids:
    m = json.load(open(os.path.join(tmp, i + ".json")))
    if m.get("image") and "image_pending" not in m:
        mods[i] = {"manifest": m, "status": "healthy", "enabled": True, "options": {}, "installed_at": "2026-11-25T00:00:00Z", "accepted": "none"}
json.dump({"modules": mods, "operations": []}, open(path, "w"))
EOF
"$RUNNER" --once 2> /dev/null || true   # arborescence

# --- 2. Banc d'essai de l'installation (F12) ------------------------------------------------
for id in "${MODS[@]}"; do
	[[ -n "${IMG[$id]:-}" ]] || continue
	tar -C "$ROOT/modules/$id" --format=ustar --owner=0 --group=0 -cf - testbed | zstd -q -o "$TMP/$id-testbed.tar.zst"
	python3 - "$PY" "$TMP/$id.json" "$TMP/$id-testbed.tar.zst" > "$TMP/tb.json" 2> "$TMP/tb.err" <<'EOF' || true
import json, shutil, sys
sys.path.insert(0, sys.argv[1])
from scanoria import testbed
from scanoria.common import Fail
manifest = json.load(open(sys.argv[2]))
testbed.fetch_archive = lambda m, dest: shutil.copyfile(sys.argv[3], dest)
try:
    print(json.dumps(testbed.run(manifest)))
except Fail as f:
    print(json.dumps({"passed": False, "code": f.code, "message": str(f), "extra": getattr(f, "extra", None)}))
EOF
	expect "$id : banc d'essai de l'installation réussi" "$(jq -r .passed "$TMP/tb.json" 2> /dev/null || echo erreur)" true
	jq -c . "$TMP/tb.json" 2> /dev/null | cut -c1-1500 || sed 's/^/     /' "$TMP/tb.err" | tail -n 20
done
expect "bancs d'essai : aucun dossier de travail laissé" "$(find "$T/var/lib/scanoria/modules/work" -mindepth 1 -maxdepth 1 2> /dev/null | wc -l)" 0

# --- 3. Analyse des bancs d'essai par le vrai runner ----------------------------------------
job() { # ID upload-id module [rulesets JSON]
	jq -cn --arg id "$1" --arg sid "$(uuid)" --arg pid "$(uuid)" --arg up "$2" --argjson mod "$(jq -c '{id: .id, version: .version}' "$TMP/$3.json")" \
		--argjson rs "${4:-null}" \
		'{schema: 1, id: $id, scan_id: $sid, project_id: $pid, created_at: "2026-11-25T10:00:00Z", source: {kind: "archive", upload_id: $up},
		  modules: [$mod + (if $rs then {rulesets: $rs} else {} end)], cache: false}'
}
drop() { printf '%s' "$2" > "$SCANS/jobs/incoming/$1.json"; chmod 0600 "$SCANS/jobs/incoming/$1.json"; }
upload() { # dossier → identifiant d'archive
	local up; up=$(uuid)
	mkdir -p "$T/var/lib/scanoria/uploads/$up"
	tar -C "$1" -czf "$T/var/lib/scanoria/uploads/$up/source.tar.gz" .
	echo "$up"
}
scan() { # module dossier [rulesets] → résultat JSON
	local id up; id=$(uuid); up=$(upload "$2")
	drop "$id" "$(job "$id" "$up" "$1" "${3:-}")"
	"$RUNNER" --once 2> "$TMP/runner.err" || echo "     runner : code $?"
	LAST="$SCANS/results/$id"
	cat "$LAST/result.json" 2> /dev/null || echo '{}'
}
mkdir -p "$TMP/recorded"
for id in "${MODS[@]}"; do
	[[ -n "${IMG[$id]:-}" ]] || continue
	R=$(scan "$id" "$ROOT/modules/$id/testbed")
	expect "$id : analyse du banc d'essai par le runner" "$(jq -r '.status + "/" + (.modules[0].status // "?")' <<< "$R")" ok/ok
	[[ "$(jq -r .status <<< "$R")" == ok ]] || { jq -c '.modules[0] | {status, error, exit_code}' <<< "$R"; tail -n 20 "$TMP/runner.err" | sed 's/^/     /'; }
	S="$LAST/$(jq -r '.modules[0].outputs.sarif // "absent"' <<< "$R")"
	if [[ -s "$S" ]]; then
		python3 -c 'import json, sys, jsonschema; jsonschema.validate(json.load(open(sys.argv[1])), json.load(open(sys.argv[2])))' "$S" "$TMP/sarif-schema.json" \
			&& ok "$id : SARIF valide (schéma OASIS 2.1.0)" || ko "$id : SARIF invalide"
		expect "$id : aucun chemin hors des sources" "$(jq -r '[.runs[].results[]?.locations[]?.physicalLocation.artifactLocation.uri // empty | select(startswith("/") or test("(^|/)\\.\\.(/|$)"))] | length' "$S")" 0
		grep -q 'valeur-de-test\|exemple-mot-de-passe' "$S" && ko "$id : valeur d'un secret du banc d'essai recopiée" || ok "$id : aucune valeur de secret recopiée"
		echo "     $id : règles trouvées $(jq -c '[.runs[].results[]?.ruleId] | group_by(.) | map({(.[0]): length}) | add' "$S")"
		cp "$S" "$TMP/recorded/$id.sarif"
		echo "=== recorded $id.sarif (gzip | base64) ==="
		gzip -9n < "$S" | base64 -w 0
		echo
		echo "=== fin $id ==="
	else
		ko "$id : sortie SARIF absente"
	fi
done

# --- 4. Opengrep avec un jeu de règles G4 -------------------------------------------------------
STORE="$SCANS/jobs/rulesets"
mkdir -p "$STORE"
put() { local sha; sha=$(printf '%s' "$1" | sha256sum | cut -d' ' -f1); printf '%s' "$1" > "$STORE/$sha"; chmod 0600 "$STORE/$sha"; echo "$sha"; }
if [[ -n "${IMG[opengrep]:-}" ]]; then
	GOOD=$(put $'rules:\n  - id: interne-print-secret\n    pattern: print(...)\n    message: Sortie standard en production\n    languages: [python]\n    severity: WARNING\n')
	mkdir -p "$TMP/og-src"
	cp -R "$ROOT/modules/opengrep/testbed/." "$TMP/og-src/"
	printf 'def f(x):\n    print(x)\n' > "$TMP/og-src/app/extra.py"
	R=$(scan opengrep "$TMP/og-src" "[{\"slug\": \"interne\", \"engine\": \"opengrep\", \"version\": 2, \"sha256\": \"$GOOD\"}]")
	expect "opengrep + jeu de règles : analyse réussie" "$(jq -r '.status + "/" + (.modules[0].status // "?")' <<< "$R")" ok/ok
	expect "opengrep + jeu de règles : version et empreinte relevées (G11)" "$(jq -c '.modules[0].rulesets' <<< "$R")" "[{\"slug\":\"interne\",\"version\":2,\"sha256\":\"$GOOD\"}]"
	S="$LAST/$(jq -r '.modules[0].outputs.sarif // "absent"' <<< "$R")"
	rules=$(jq -r '[.runs[].results[]?.ruleId] | unique | join(" ")' "$S" 2> /dev/null || true)
	[[ " $rules " == *" interne-print-secret "* ]] && ok "opengrep : règle du jeu trouvée, identifiant non préfixé" || ko "opengrep : règle du jeu absente ($rules)"
	[[ " $rules " == *" scanoria-python-subprocess-shell "* ]] && ok "opengrep : règles maison conservées" || ko "opengrep : règles maison absentes ($rules)"
	BAD=$(put $'rules:\n  - id: casse\n    pattern: print(\n    message: x\n    languages: [python]\n    severity: WARNING\n')
	R=$(scan opengrep "$TMP/og-src" "[{\"slug\": \"casse\", \"engine\": \"opengrep\", \"version\": 1, \"sha256\": \"$BAD\"}]")
	expect "opengrep + jeu invalide : module en erreur E_RULESET_INVALID (input), jamais un résultat vide" \
		"$(jq -r '(.modules[0].status // "?") + " " + (.modules[0].error.code // "?") + " " + (.modules[0].error.class // "?")' <<< "$R")" "error E_RULESET_INVALID input"
fi

# --- 5. Demande validate-ruleset avec le vrai moteur ------------------------------------------
hx() {
	R=$("$HELPER" exec --origin cli --type validate-ruleset --params "$1" 2> "$TMP/helper.err") || true
	[[ -n "$R" ]] || { R='{"code":"NO_OUTPUT"}'; sed 's/^/     /' "$TMP/helper.err" | tail -n 10; }
}
sample() { jq -cn --arg n "$1" --arg c "$2" '{name: $n, content: $c}'; }
validate() { # moteur contenu exemples-JSON → R
	local sha; sha=$(put "$2")
	hx "$(jq -cn --arg e "$1" --arg s "$sha" --argjson x "$3" '{engine: $e, sha256: $s, samples: $x}')"
}
POS=$(sample positif.py $'import os\nos.system("ls " + user)\n')
NEG=$(sample negatif.py $'print("ok")\n')
GREP_RULE=$'rules:\n  - id: candidate-system\n    pattern: os.system(...)\n    message: os.system\n    languages: [python]\n    severity: ERROR\n'
for e in opengrep semgrep; do
	[[ -n "${IMG[$e]:-}" ]] || continue
	validate "$e" "$GREP_RULE" "[$POS, $NEG]"
	expect "validate-ruleset $e : jeu accepté, exemples comptés" "$(jq -c '[.code, .output.ok, .output.samples]' <<< "$R")" \
		'["OK",true,[{"name":"positif.py","matches":1},{"name":"negatif.py","matches":0}]]'
	validate "$e" $'rules:\n  - id: casse\n    pattern: os.system(\n    message: x\n    languages: [python]\n    severity: ERROR\n' "[$POS]"
	expect "validate-ruleset $e : motif invalide refusé par le moteur" "$(jq -c '[.code, .output.ok]' <<< "$R")" '["OK",false]'
	jq -c '.output.errors' <<< "$R" | cut -c1-300
done
if [[ -n "${IMG[checkov]:-}" ]]; then
	TF=$(sample main.tf $'resource "aws_s3_bucket" "b" {\n  bucket = "exemple"\n  acl    = "public-read"\n}\n')
	validate checkov $'metadata:\n  id: CKV2_INT_1\n  name: Ensure S3 buckets are not public\n  category: GENERAL_SECURITY\ndefinition:\n  cond_type: attribute\n  resource_types: [aws_s3_bucket]\n  attribute: acl\n  operator: not_equals\n  value: public-read\n' "[$TF]"
	expect "validate-ruleset checkov : politique acceptée, exemple trouvé" "$(jq -c '[.code, .output.ok, .output.samples]' <<< "$R")" '["OK",true,[{"name":"main.tf","matches":1}]]'
	validate checkov $'metadata:\n  id: CKV2_INT_2\ndefinition:\n  cond_type: nimporte\n' "[$TF]"
	expect "validate-ruleset checkov : politique invalide refusée" "$(jq -c '[.code, .output.ok]' <<< "$R")" '["OK",false]'
fi
if [[ -n "${IMG[kics]:-}" ]]; then
	DF=$(sample Dockerfile $'FROM exemple.test/base:1\nRUN echo ok\n')
	Q=$(jq -cn '{queries: [{id: "interne-run-echo", metadata: {id: "interne-run-echo", queryName: "RUN echo", severity: "LOW", category: "Best Practices", descriptionText: "RUN echo", descriptionUrl: "https://exemple.test/doc", platform: "Dockerfile", descriptionID: "a1b2c3d4", cloudProvider: "common"},
		query: "package Cx\n\nimport data.generic.common as common_lib\n\nCxPolicy[result] {\n\tresource := input.document[i].command[name][_]\n\tresource.Cmd == \"run\"\n\tresult := {\n\t\t\"documentId\": input.document[i].id,\n\t\t\"searchKey\": sprintf(\"FROM={{%s}}.RUN={{%s}}\", [name, resource.Original]),\n\t\t\"issueType\": \"IncorrectValue\",\n\t\t\"keyExpectedValue\": \"no RUN\",\n\t\t\"keyActualValue\": \"RUN\",\n\t}\n}\n"}]}')
	validate kics "$Q" "[$DF]"
	expect "validate-ruleset kics : requête acceptée" "$(jq -c '[.code, .output.ok]' <<< "$R")" '["OK",true]'
	jq -c '.output' <<< "$R" | cut -c1-400
fi

echo
echo "b31-live : $PASS réussis, $FAIL échoués"
[[ "$FAIL" -eq 0 ]]
