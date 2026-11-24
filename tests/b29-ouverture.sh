#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Vincent Tisseront
#
# b29-ouverture — module modelscan (0.6, K8), sans root ni conteneur :
# manifeste, sources de ModelScan livrées telles quelles (vendor/SHA256SUMS),
# convertisseur du rapport natif vers SARIF 2.1.0 sur des sorties piégées, et
# analyse réelle du banc d'essai par l'outil de l'appliance (python3 -I, numpy).
# Cas :
#   - manifeste valide (schéma, liens), image épinglée, réseau « none »,
#     catégorie sast, hors sélection conseillée ;
#   - vendor/ identique aux archives PyPI vérifiées (aucune retouche) ;
#   - conversion : sortie identique à l'enregistrement tests/recorded.sarif,
#     gravités (code exécuté au chargement → critical, opérateur TensorFlow de
#     fichiers → high), doublons fusionnés, chemin « .. » écarté, caractères de
#     contrôle et injection d'invite neutralisés, erreurs en notifications
#     (jamais en résultats), empreintes stables, rapport invalide refusé ;
#   - banc d'essai : pickle piégé inerte trouvé, modèle sain sans résultat,
#     rien chargé ni exécuté (pickle témoin qui créerait un fichier) ;
#   - point d'entrée : seulement /src et /out.
# Dépendances : bash, python3 (≥ 3.10), python3-yaml, python3-jsonschema, python3-numpy, jq.

# shellcheck disable=SC2015
set -euo pipefail
export PYTHONDONTWRITEBYTECODE=1

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
DIR="$ROOT/src/rootfs/usr/lib/scanoria/scan-tools/modelscan"
TOOL="$DIR/modelscan_sarif.py"
MOD="$ROOT/modules/modelscan"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
for t in python3 jq sha256sum; do command -v "$t" > /dev/null || { echo "outil manquant : $t" >&2; exit 2; }; done

PASS=0
FAIL=0
ok() { PASS=$((PASS + 1)); printf 'ok   %s\n' "$1"; }
ko() { FAIL=$((FAIL + 1)); printf 'FAIL %s\n' "$1"; }
expect() {
	if [[ "$2" == "$3" ]]; then ok "$1"; else ko "$1 (obtenu « $2 », attendu « $3 »)"; fi
}
yq() { python3 -c 'import json, sys, yaml; print(json.dumps(yaml.safe_load(open(sys.argv[1], encoding="utf-8"))))' "$1"; }
# Outil chargé par son chemin (comme dans le conteneur, python3 -I), fonction appelée sur des dossiers de test.
call() { # fonction arguments…
	(cd "$TMP" && python3 -I -c 'import importlib.util, json, sys
spec = importlib.util.spec_from_file_location("modelscan_sarif", sys.argv[1])
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
fn = sys.argv[2]
if fn == "convert":
    json.dump(m.convert(json.load(open(sys.argv[3]))), sys.stdout, sort_keys=True)
elif fn == "run":
    sys.exit(m.run(*sys.argv[3:]))
elif fn == "main":
    sys.exit(m.main(["modelscan_sarif.py"] + sys.argv[3:]))' "$TOOL" "$@")
}

# --- 1. Manifeste ------------------------------------------------------------------------------
if python3 "$ROOT/tests/lib/modcheck.py" manifest "$MOD/module.yaml" > "$TMP/mc.log" 2>&1; then ok "manifeste valide (schéma)"
else ko "manifeste refusé"; sed 's/^/     /' "$TMP/mc.log"; fi
yq "$MOD/module.yaml" > "$TMP/m.json"
expect "type scanner, catégorie sast" "$(jq -r '.type + "/" + (.categories | join(","))' "$TMP/m.json")" scanner/sast
[[ "$(jq -r .image "$TMP/m.json")" =~ @sha256:[0-9a-f]{64}$ ]] && ok "image épinglée par empreinte" || ko "image non épinglée"
expect "réseau none" "$(jq -r .scan.network "$TMP/m.json")" none
expect "outil de l'appliance monté" "$(jq -r .scan.tool "$TMP/m.json")" modelscan
expect "licence vérifiée" "$(jq -r '.license.spdx + "/" + .license.restrictions' "$TMP/m.json")" Apache-2.0/none
# Contrat 23 (V6) : lancé seulement s'il y a des fichiers de modèles.
applies() { python3 -I -c 'import json, sys
sys.path.insert(0, sys.argv[1])
from scanoria.applicability import applies
print(applies(json.load(open(sys.argv[2])), {}, sys.argv[3:]) or "runs")' "$ROOT/src/rootfs/usr/lib/scanoria/py" "$TMP/m.json" "$@"; }
mapfile -t TB_FILES < <(cd "$MOD/testbed" && find . -type f | sed 's|^\./||')
expect "applies_to : modèles du banc d'essai" "$(applies "${TB_FILES[@]}")" runs
expect "applies_to : extension en majuscules, poids sous weights/" "$(applies a/B.PT)/$(applies weights/x/w.bin)" runs/runs
expect "applies_to : dépôt sans modèle non lancé" "$(applies src/app.py bin/tool.bin README.md)" no-matching-files
grep -E '^export const RECOMMENDED_IDS' "$ROOT/webui/server/utils/catalog.ts" | grep -q "'modelscan'" \
	&& ko "modelscan dans la sélection conseillée" || ok "hors sélection conseillée"

# --- 2. Sources livrées telles quelles --------------------------------------------------------
if (cd "$DIR/vendor" && sha256sum --check --strict --quiet SHA256SUMS); then ok "vendor/ conforme à SHA256SUMS"
else ko "vendor/ modifié"; fi
expect "aucun fichier hors SHA256SUMS" \
	"$(cd "$DIR/vendor" && comm -13 <(awk '{print $2}' SHA256SUMS | sort) <(find modelscan tomlkit -type f ! -name '*.pyc' | LC_ALL=C sort) | wc -l)" 0
grep -qE "^__version__ = ['\"]0\.8\.8['\"]" "$DIR/vendor/modelscan/_version.py" && ok "ModelScan 0.8.8 (version du manifeste)" || ko "version de ModelScan différente du manifeste"

# --- 3. Conversion sur des sorties piégées ----------------------------------------------------
call convert "$MOD/tests/native-sample.json" > "$TMP/conv.sarif"
if diff <(jq -S . "$TMP/conv.sarif") <(jq -S . "$MOD/tests/recorded.sarif") > "$TMP/diff.txt"; then
	ok "conversion identique à l'enregistrement"
else
	ko "conversion différente de l'enregistrement"
	sed 's/^/     /' "$TMP/diff.txt" | head -20
fi
R() { jq -r "$1" "$TMP/conv.sarif"; }
expect "SARIF 2.1.0" "$(R .version)" 2.1.0
expect "résultats : doublon fusionné, « .. » écarté" "$(R '.runs[0].results | length')" 5
expect "pickle : critical" "$(R '[.runs[0].results[] | select(.ruleId == "modelscan/pickle-unsafe-op") | .properties.severity] | unique | join(",")')" critical
expect "PyTorch HIGH de ModelScan : critical (exécuté au chargement)" \
	"$(R '.runs[0].results[] | select(.ruleId == "modelscan/pytorch-unsafe-op") | .properties.severity + "/" + .properties.modelscan_severity')" critical/HIGH
expect "Lambda Keras MEDIUM de ModelScan : critical" \
	"$(R '.runs[0].results[] | select(.ruleId == "modelscan/keras-lambda") | .properties.severity')" critical
expect "opérateur TensorFlow de fichiers : high" \
	"$(R '.runs[0].results[] | select(.ruleId == "modelscan/tensorflow-unsafe-op") | .properties.severity')" high
expect "membre d'archive hors du chemin" \
	"$(R '.runs[0].results[] | select(.ruleId == "modelscan/pytorch-unsafe-op") | .locations[0].physicalLocation.artifactLocation.uri + "|" + .properties.archive_member')" "weights/model.pt|archive/data.pkl"
expect "aucun chemin en « .. »" "$(R '[.runs[0].results[].locations[0].physicalLocation.artifactLocation.uri | select(test("\\.\\."))] | length')" 0
expect "aucun caractère de contrôle" "$(R '[.. | strings | select(explode | any(. < 32 or . == 127))] | length')" 0
expect "injection : gardée dans le texte, jamais comme règle" \
	"$(R '[.runs[0].results[] | select(.ruleId | test("IGNORE"))] | length')" 0
expect "scanner inconnu : règle générique, critical" \
	"$(R '.runs[0].results[] | select(.locations[0].physicalLocation.artifactLocation.uri == "z/ctrl.pkl") | .ruleId + "/" + .properties.severity')" modelscan/unsafe-op/critical
expect "erreurs et constat « .. » écarté en notifications, jamais en résultats" \
	"$(R '.runs[0].invocations[0].toolExecutionNotifications | length')/$(R '[.runs[0].results[] | select(.ruleId | test("dependency|nested"))] | length')" 3/0
expect "fichier non lu : exécution non réussie (G13)" "$(R '.runs[0].invocations[0].executionSuccessful')" false
expect "notifications de niveau error" "$(R '[.runs[0].invocations[0].toolExecutionNotifications[].level] | unique | join(",")')" error
expect "CWE-502 sur le code exécuté au chargement" \
	"$(R '.runs[0].tool.driver.rules[] | select(.id == "modelscan/pickle-unsafe-op") | .properties.tags | index("external/cwe/cwe-502") != null')" true
expect "empreintes uniques et stables" "$(R '[.runs[0].results[].partialFingerprints["modelscan/v1"]] | unique | length')" 5
call convert "$MOD/tests/native-sample.json" | jq -S . > "$TMP/conv2.sarif"
cmp -s <(jq -S . "$TMP/conv.sarif") "$TMP/conv2.sarif" && ok "conversion déterministe" || ko "conversion non déterministe"
echo '[1, 2]' > "$TMP/bad.json"
call convert "$TMP/bad.json" > /dev/null 2>&1 && ko "rapport invalide accepté" || ok "rapport invalide refusé"
echo '{"issues": "x", "errors": 3}' > "$TMP/odd.json"
expect "champs de types inattendus : aucun résultat" "$(call convert "$TMP/odd.json" | jq '.runs[0].results | length')" 0
expect "rapport sans erreur : exécution réussie" "$(call convert "$TMP/odd.json" | jq '.runs[0].invocations[0].executionSuccessful')" true

# --- 4. Banc d'essai, analyse réelle ------------------------------------------------------------
if python3 -I -c 'import numpy' 2> /dev/null; then
	mkdir -p "$TMP/out" "$TMP/src"
	cp -R "$MOD/testbed/." "$TMP/src/"
	# Témoin : pickle qui, chargé, créerait un fichier ; ModelScan ne doit jamais le charger.
	WITNESS="$TMP/witness-loaded"
	python3 - "$TMP/src/models/witness.pkl" "$WITNESS" <<'EOF'
import sys
path, witness = sys.argv[1:3]
arg = witness.encode()
# GLOBAL pathlib.Path, REDUCE(witness) puis appel de touch : n'écrit qu'un fichier vide dans le dossier du test.
data = b"\x80\x02cpathlib\nPath\nX" + len(arg).to_bytes(4, "little") + arg + b"\x85R."
open(path, "wb").write(data)
EOF
	call run "$TMP/src" "$TMP/out/ms.json" "$TMP/out/ms.sarif" > "$TMP/run.log" 2>&1 && ok "analyse du banc d'essai réussie" \
		|| { ko "analyse du banc d'essai en échec"; sed 's/^/     /' "$TMP/run.log" | tail -n 20; }
	if [[ -s "$TMP/out/ms.sarif" ]]; then
		expect "pickle piégé inerte trouvé (critical)" \
			"$(jq -r '[.runs[0].results[] | select(.locations[0].physicalLocation.artifactLocation.uri == "models/trapped.pkl") | .properties.severity] | join(",")' "$TMP/out/ms.sarif")" critical
		expect "modèle sain sans résultat" \
			"$(jq -r '[.runs[0].results[] | select(.locations[0].physicalLocation.artifactLocation.uri == "models/healthy.pkl")] | length' "$TMP/out/ms.sarif")" 0
		jq -e '.summary.scanned.total_scanned >= 2' "$TMP/out/ms.json" > /dev/null && ok "rapport natif écrit" || ko "rapport natif absent"
		if python3 "$ROOT/tests/lib/modcheck.py" expect "$MOD/module.yaml" "$TMP/out/ms.sarif" > "$TMP/exp.log" 2>&1; then
			ko "attentes du banc d'essai satisfaites sans TensorFlow (keras-lambda inattendu)"
		else
			grep -q 'keras-lambda' "$TMP/exp.log" && ok "sans TensorFlow : seule l'attente Keras manque (vérifiée par b29-live)" \
				|| { ko "attentes du banc d'essai"; sed 's/^/     /' "$TMP/exp.log"; }
		fi
	fi
	[[ ! -e "$WITNESS" ]] && ok "aucun modèle chargé ni code exécuté" || ko "pickle chargé : code exécuté"
else
	# Batterie de construction (conteneur sans python3-numpy) : l'analyse réelle est
	# faite par la batterie sans root de la CI (numpy installé) et par b29-live.
	printf 'skip %s\n' "python3-numpy absent : analyse réelle vérifiée par b29-live"
fi

# --- 5. Point d'entrée ----------------------------------------------------------------------------
for args in "/tmp /out/a.json /out/a.sarif" "/src /out/a.json" "/src /etc/a.json /out/a.sarif" "/src /out/a.sarif /out/a.json" "/src /out/../a.json /out/a.sarif"; do
	read -ra argv <<< "$args"
	rc=0; call main "${argv[@]}" > /dev/null 2>&1 || rc=$?
	expect "point d'entrée refusé : $args" "$rc" 2
done

echo
echo "b29-ouverture : $PASS réussis, $FAIL échoués"
[[ "$FAIL" -eq 0 ]]
