#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Vincent Tisseront
#
# b29-live — module modelscan (0.6, K8) avec le vrai podman (job CI
# modelscan-live, machine de test root jetable), exactement comme sur
# l'appliance : image épinglée par empreinte, outil de l'appliance monté en
# lecture seule sur /scanoria (scan.tool), --network=none, --read-only, sources
# en lecture seule, --cap-drop=ALL, no-new-privileges, utilisateur 65534,
# limites et délai du manifeste. Aucune base, rien de pré-rempli.
# Cas :
#   - banc d'essai de l'installation (F12) par le code même du helper
#     (testbed.run) : pickle piégé inerte et couche Lambda Keras trouvés ;
#   - analyse par le vrai scanoria-runner d'une archive piégée (banc d'essai,
#     pickle piégé dans un .pt zippé, lien symbolique vers l'extérieur,
#     node_modules) : tâche réussie, SARIF 2.1.0 valide (schéma OASIS), tous les
#     modèles piégés « critical » (verdict défavorable : voir
#     webui/tests/integration/modelscan-gate.test.ts), modèle sain sans
#     résultat, rien chargé ni exécuté ;
#   - espace de travail supprimé, aucun conteneur laissé ;
#   - outil de l'appliance absent : module en erreur explicite.
# Dépendances : bash, python3, python3-yaml, python3-jsonschema, jq, curl, zstd, tar, podman (root).

# shellcheck disable=SC2015
set -euo pipefail
export PYTHONDONTWRITEBYTECODE=1

[[ "$(id -u)" -eq 0 ]] || { echo "b29-live : root requis (podman réel)" >&2; exit 2; }
for t in python3 jq curl podman tar zstd; do command -v "$t" > /dev/null || { echo "outil manquant : $t" >&2; exit 2; }; done

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
RUNNER="$ROOT/src/rootfs/usr/sbin/scanoria-runner"
PY="$ROOT/src/rootfs/usr/lib/scanoria/py"
MOD="$ROOT/modules/modelscan"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

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
curl --proto '=https' --tlsv1.2 -fsSL --retry 3 -o "$TMP/sarif-schema.json" \
	"https://raw.githubusercontent.com/oasis-tcs/sarif-spec/$SARIF_COMMIT/sarif-2.1/schema/sarif-schema-2.1.0.json"
echo "$SARIF_SHA256  $TMP/sarif-schema.json" | sha256sum --check --strict --quiet

# --- Appliance de test : racine préfixée, podman réel ---------------------------------------
T="$TMP/root"
STUBS="$TMP/stubs"
SCANS="$T/var/lib/scanoria/scans"
mkdir -p "$T/var/lib/scanoria/modules" "$T/var/lib/scanoria/uploads" "$T/run/scanoria" "$T/proc" \
	"$T/etc/ssl/certs" "$T/usr/lib/scanoria" "$STUBS"
cp /proc/meminfo "$T/proc/meminfo"
grep '^processor' /proc/cpuinfo > "$T/proc/cpuinfo"
cp -R "$ROOT/src/rootfs/usr/lib/scanoria/scan-tools" "$T/usr/lib/scanoria/"
chmod -R a+rX,go-w "$T/usr"
for t in podman zstd; do ln -s "$(command -v "$t")" "$STUBS/$t"; done
export SCANORIA_TEST_ROOT="$T" SCANORIA_TEST_BIN="$STUBS"

yq "$MOD/module.yaml" > "$TMP/modelscan.json"
IMAGE=$(jq -r .image "$TMP/modelscan.json")
[[ "$IMAGE" == *@sha256:* ]] && ok "image épinglée par empreinte" || ko "image non épinglée : $IMAGE"
podman pull -q "$IMAGE" > /dev/null
python3 - "$T/var/lib/scanoria/modules/installed.json" "$TMP/modelscan.json" <<'EOF'
import json, sys
path, man = sys.argv[1:3]
m = json.load(open(man))
json.dump({"modules": {"modelscan": {"manifest": m, "status": "healthy", "enabled": True, "options": {}}}, "operations": []}, open(path, "w"))
EOF
"$RUNNER" --once 2> /dev/null || true   # arborescence

# --- 1. Santé et banc d'essai de l'installation (F12) ----------------------------------------
v=$(podman run --rm --network=none --read-only --cap-drop=ALL --security-opt=no-new-privileges --user 65534:65534 \
	--entrypoint '["python3"]' "$IMAGE" -I -c 'import numpy, h5py, tensorflow, sys; print(sys.version_info[:2] >= (3, 10))' 2> "$TMP/health.err" || true)
expect "image : python3 ≥ 3.10, numpy, h5py et TensorFlow présents" "$v" True
[[ "$v" == True ]] || sed 's/^/     /' "$TMP/health.err" | tail -n 5
# Archive du banc d'essai au format du catalogue (catalog/build.py) : « testbed/… » en tar.zst.
tar -C "$MOD" --format=ustar --owner=0 --group=0 -cf - testbed | zstd -q -o "$TMP/testbed.tar.zst"
python3 - "$PY" "$TMP/modelscan.json" "$TMP/testbed.tar.zst" > "$TMP/testbed.json" 2> "$TMP/testbed.err" <<'EOF' || true
import json, shutil, sys
sys.path.insert(0, sys.argv[1])
from scanoria import testbed
from scanoria.common import Fail
manifest = json.load(open(sys.argv[2]))
# Seul le téléchargement depuis la release du catalogue est remplacé par l'archive locale.
testbed.fetch_archive = lambda m, dest: shutil.copyfile(sys.argv[3], dest)
try:
    print(json.dumps(testbed.run(manifest)))
except Fail as f:
    print(json.dumps({"passed": False, "code": f.code, "message": str(f)}))
EOF
expect "banc d'essai de l'installation réussi" "$(jq -r '.passed' "$TMP/testbed.json" 2> /dev/null || echo erreur)" true
jq -c . "$TMP/testbed.json" 2> /dev/null || sed 's/^/     /' "$TMP/testbed.err" | tail -n 20
expect "banc d'essai : aucun dossier de travail laissé" "$(find "$T/var/lib/scanoria/modules/work" -mindepth 1 -maxdepth 1 2> /dev/null | wc -l)" 0

# --- 2. Analyse d'une archive piégée par le vrai runner --------------------------------------
uuid() { python3 -c 'import uuid; print(uuid.uuid4())'; }
job() { # ID upload-id
	jq -cn --arg id "$1" --arg sid "$(uuid)" --arg up "$2" --argjson mod "$(jq -c '{id: .id, version: .version}' "$TMP/modelscan.json")" \
		'{schema: 1, id: $id, scan_id: $sid, created_at: "2026-11-24T10:00:00Z", source: {kind: "archive", upload_id: $up}, modules: [$mod]}'
}
drop() {
	printf '%s' "$2" > "$SCANS/jobs/incoming/$1.json"
	chmod 0600 "$SCANS/jobs/incoming/$1.json"
}
run_runner() {
	"$RUNNER" --once 2> "$TMP/runner.err" || { echo "runner : code $?"; }
	sed 's/^/     runner: /' "$TMP/runner.err" | tail -n 20
}
res() { cat "$SCANS/results/$1/result.json" 2> /dev/null || echo '{}'; }

A="$TMP/arch"
WITNESS=/tmp/scanoria-b29-loaded
rm -f "$WITNESS"
cp -R "$MOD/testbed/." "$A"
mkdir -p "$A/weights" "$A/node_modules/pkg" "$TMP/outside"
# Poids PyTorch (archive zip) qui embarquent le pickle piégé inerte.
python3 - "$A/weights/model.pt" "$MOD/testbed/models/trapped.pkl" <<'EOF'
import sys, zipfile
with zipfile.ZipFile(sys.argv[1], "w") as z:
    z.writestr(zipfile.ZipInfo("archive/data.pkl", date_time=(2026, 1, 1, 0, 0, 0)), open(sys.argv[2], "rb").read())
EOF
# Témoin : pickle qui, chargé, créerait un fichier sur l'hôte ; il ne doit jamais être chargé.
python3 - "$A/models/witness.pkl" "$WITNESS" <<'EOF'
import sys
arg = sys.argv[2].encode()
open(sys.argv[1], "wb").write(b"\x80\x02cpathlib\nPath\nX" + len(arg).to_bytes(4, "little") + arg + b"\x85R.")
EOF
cp "$MOD/testbed/models/trapped.pkl" "$TMP/outside/leak.pkl"
ln -s "$TMP/outside/leak.pkl" "$A/models/link.pkl"
cp "$MOD/testbed/models/trapped.pkl" "$A/node_modules/pkg/model.pkl"
up=$(uuid)
mkdir -p "$T/var/lib/scanoria/uploads/$up"
tar -C "$A" -czf "$T/var/lib/scanoria/uploads/$up/source.tar.gz" .
id=$(uuid)
drop "$id" "$(job "$id" "$up")"
run_runner
R=$(res "$id")
echo "$R" | jq -c '{status, error, modules: [.modules[] | {id, status, error, exit_code, stats, outputs}]}'
expect "tâche réussie, module ok" "$(jq -r '.status + "/" + .modules[0].status' <<< "$R")" ok/ok
expect "empreinte de l'image publiée" "$(jq -r '.modules[0].image_digest' <<< "$R")" "${IMAGE#*@}"
SARIF="$SCANS/results/$id/$(jq -r '.modules[0].outputs.sarif // "absent"' <<< "$R")"
if [[ -s "$SARIF" ]]; then
	ok "sortie publiée ($(jq -r '.modules[0].outputs.sarif' <<< "$R"))"
	if python3 -c 'import json, sys, jsonschema; jsonschema.validate(json.load(open(sys.argv[1])), json.load(open(sys.argv[2])))' "$SARIF" "$TMP/sarif-schema.json"; then
		ok "SARIF valide (schéma OASIS 2.1.0)"
	else
		ko "SARIF invalide"
	fi
	sev() { jq -r --arg p "$1" '[.runs[0].results[] | select(.locations[0].physicalLocation.artifactLocation.uri == $p) | .ruleId + "=" + .properties.severity] | unique | join(",")' "$SARIF"; }
	expect "pickle piégé : critical" "$(sev models/trapped.pkl)" modelscan/pickle-unsafe-op=critical
	expect "couche Lambda Keras : critical" "$(sev models/lambda.keras)" modelscan/keras-lambda=critical
	expect "pickle dans les poids PyTorch : critical" "$(sev weights/model.pt)" modelscan/pytorch-unsafe-op=critical
	expect "modèle sain : aucun résultat" "$(sev models/healthy.pkl)" ""
	jq -c '[.runs[0].results[] | [.ruleId, .locations[0].physicalLocation.artifactLocation.uri, .properties.severity]]' "$SARIF"
	jq -c '.runs[0].invocations[0].toolExecutionNotifications | map(.message.text)' "$SARIF"
	expect "aucun résultat hors des sources" "$(jq -r '[.runs[0].results[].locations[0].physicalLocation.artifactLocation.uri | select(startswith("/") or test("\\.\\."))] | length' "$SARIF")" 0
	expect "aucune erreur de dépendance (TensorFlow et h5py présents)" \
		"$(jq -r '[.runs[0].invocations[0].toolExecutionNotifications[] | select(.descriptor.id == "modelscan/dependency")] | length' "$SARIF")" 0
else
	ko "sortie SARIF absente"
	find "$SCANS/results/$id" -name '*.log' -exec tail -n 30 {} \; 2> /dev/null | sed 's/^/     /' || true
fi
[[ ! -e "$WITNESS" ]] && ok "aucun modèle chargé ni code exécuté" || ko "pickle chargé : code exécuté"
jq -e '.modules[0].stats.duration_ms > 0' <<< "$R" > /dev/null && ok "durée mesurée" || ko "durée non mesurée"
expect "espace de travail supprimé" "$(find "$SCANS/workspaces" -mindepth 1 | wc -l)" 0
expect "aucun conteneur laissé" "$(podman ps -a --format '{{.Names}}' | grep -c '^scanoria-' || true)" 0

# --- 3. Outil de l'appliance absent : jamais lancé sans lui ----------------------------------
mv "$T/usr/lib/scanoria/scan-tools/modelscan" "$TMP/tool-aside"
id=$(uuid)
drop "$id" "$(job "$id" "$up")"
run_runner
R=$(res "$id")
st=$(jq -r '.modules[0].status // "absent"' <<< "$R")
[[ "$st" != ok ]] && ok "outil absent : module non lancé ($st, $(jq -r '.modules[0].error.code // .error.code // "-"' <<< "$R"))" \
	|| ko "outil absent : module lancé quand même"
mv "$TMP/tool-aside" "$T/usr/lib/scanoria/scan-tools/modelscan"
expect "outil absent : aucun conteneur laissé" "$(podman ps -a --format '{{.Names}}' | grep -c '^scanoria-' || true)" 0

echo
echo "b29-live : $PASS réussis, $FAIL échoués"
[[ "$FAIL" -eq 0 ]]
