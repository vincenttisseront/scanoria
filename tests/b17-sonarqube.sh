#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Vincent Tisseront
#
# b17 — SonarQube Community Build et son scanner (chantier B de la 0.4), sans
# root ni conteneur. Couvre :
#   1. manifestes sonarqube et sonar-scanner (schéma, image épinglée, réseau
#      service:<id>, refs, outil de l'appliance), manifestes hostiles ;
#   2. convertisseur issues/hotspots → SARIF 2.1.0 sur réponses enregistrées :
#      pagination, bornes, champs manquants, texte et chemins hostiles,
#      gravités (impacts puis gravité historique), catégories ;
#   3. orchestration dans le conteneur (sonar_scan.py) contre un faux serveur :
#      attente UP, tâche de calcul, pagination, jeton jamais en argument ;
#   4. runner en mode test : réseau interne du service seul, secret Podman,
#      clé de projet, branche par défaut seulement (skipped, sans G13), service
#      absent ou jeton manquant (missing, G13), jeton masqué partout ;
#   5. mise en service (provision.py) contre le faux serveur : mot de passe
#      admin remplacé, compte et jeton d'analyse, réglages, idempotence,
#      migration de base, reprise, réinitialisation affichée une seule fois ;
#   6. branches et PR (option « branches », plugin de branches) : variantes
#      d'image (compatibilité majeure.mineure, base, fichiers laissés retirés
#      sans suivre de lien), paramètres sonar.branch.name / sonar.pullrequest.*,
#      lecture des résultats filtrée ; runner : SCANORIA_BRANCH seulement si la
#      fonction est active et la référence n'est pas la branche par défaut.
# Dépendances : bash, python3, jq.

# shellcheck disable=SC2016,SC2015
set -euo pipefail
export PYTHONDONTWRITEBYTECODE=1

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
PYLIB="$ROOT/src/rootfs/usr/lib/scanoria/py"
TOOL="$ROOT/src/rootfs/usr/lib/scanoria/scan-tools/sonar"
RUNNER="$ROOT/src/rootfs/usr/sbin/scanoria-runner"
MC="$ROOT/tests/lib/modcheck.py"
FIX="$ROOT/modules/sonar-scanner/tests/api"
TMP=$(mktemp -d)
SRV_PID=
cleanup() {
	[[ -n "$SRV_PID" ]] && kill "$SRV_PID" 2> /dev/null || true
	chmod -R u+rwX "$TMP" 2> /dev/null
	rm -rf "$TMP"
}
trap cleanup EXIT

PASS=0
FAIL=0
ok() { PASS=$((PASS + 1)); printf 'ok   %s\n' "$1"; }
ko() { FAIL=$((FAIL + 1)); printf 'FAIL %s\n' "$1"; }
expect() { # libellé valeur_obtenue valeur_attendue
	if [[ "$2" == "$3" ]]; then ok "$1"; else ko "$1 (obtenu « $2 », attendu « $3 »)"; fi
}
check() { # libellé commande…
	local label=$1
	shift
	if "$@" > "$TMP/check.out" 2>&1; then ok "$label"; else ko "$label"; sed 's/^/     /' "$TMP/check.out" | head -20; fi
}
for t in python3 jq; do command -v "$t" > /dev/null || { echo "outil manquant : $t" >&2; exit 2; }; done
yq() { python3 -c 'import json, sys, yaml; print(json.dumps(yaml.safe_load(open(sys.argv[1], encoding="utf-8"))))' "$1"; }

# --- 1. Manifestes -------------------------------------------------------------------------
check "sonar-scanner : manifeste conforme" python3 "$MC" manifest "$ROOT/modules/sonar-scanner/module.yaml"
check "sonarqube : manifeste conforme" python3 "$MC" manifest "$ROOT/modules/sonarqube/module.yaml"
yq "$ROOT/modules/sonar-scanner/module.yaml" > "$TMP/scanner.json"
yq "$ROOT/modules/sonarqube/module.yaml" > "$TMP/service.json"
expect "sonar-scanner : réseau du service sonarqube seulement" "$(jq -r .scan.network "$TMP/scanner.json")" "service:sonarqube"
expect "sonar-scanner : branche par défaut, sauf fonction active" "$(jq -r .scan.refs "$TMP/scanner.json")" "default-branch"
expect "sonar-scanner : autres branches avec la fonction « branches »" "$(jq -r .scan.refs_feature "$TMP/scanner.json")" "branches"
expect "sonarqube : option « branches » activée par défaut (principe 8)" "$(jq -r .options.properties.branches.default "$TMP/service.json")" true
expect "sonarqube : fonction « branches » déclarée" "$(jq -c .service.features "$TMP/service.json")" '["branches"]'
expect "sonar-scanner : dépend du service (G1)" "$(jq -r '.requires.modules | index("sonarqube") != null' "$TMP/scanner.json")" true
expect "sonar-scanner : catégories qualité et SAST (G7)" "$(jq -c .categories "$TMP/scanner.json")" '["quality","sast"]'
[[ -f "$TOOL/$(jq -r .scan.tool "$TMP/scanner.json" | sed 's/^sonar$/sonar_scan.py/')" ]] \
	&& ok "sonar-scanner : outil de l'appliance présent" || ko "sonar-scanner : outil de l'appliance absent"
for f in scanner service; do
	jq -e '.image | test("@sha256:[0-9a-f]{64}$")' "$TMP/$f.json" > /dev/null && ok "$f : image épinglée par empreinte" || ko "$f : image non épinglée"
	jq -e '.license.spdx | startswith("LGPL-3.0")' "$TMP/$f.json" > /dev/null && ok "$f : licence LGPL-3.0" || ko "$f : licence"
done
expect "sonarqube : libellé DNS" "$(jq -r .hostname "$TMP/service.json")" sonarqube
expect "sonarqube : PostgreSQL" "$(jq -r .needs.postgres "$TMP/service.json")" true
expect "sonarqube : vm.max_map_count ≥ 524288" "$(jq -r '.needs.sysctl["vm.max_map_count"] >= 524288' "$TMP/service.json")" true
expect "sonarqube : ≥ 4 Go de RAM" "$(jq -r '.resources.min_ram_mb >= 4096' "$TMP/service.json")" true
expect "sonarqube : santé api/system/status" "$(jq -r .service.health_path "$TMP/service.json")" /api/system/status
expect "sonarqube : volumes sauvegardés" "$(jq -c '.service.backup | sort' "$TMP/service.json")" '["data","extensions","logs"]'
jq -e '[.service.env | to_entries[] | .value | test("password"; "i")] | any | not' "$TMP/service.json" > /dev/null \
	&& ok "sonarqube : aucun mot de passe dans service.env" || ko "sonarqube : mot de passe dans service.env"
expect "sonarqube : télémétrie coupée" "$(jq -r .service.env.SONAR_TELEMETRY_ENABLE "$TMP/service.json")" false

python3 - "$ROOT" > "$TMP/mut.out" <<'EOF'
import copy, json, sys, yaml
root = sys.argv[1]
sys.path.insert(0, root + "/tests/lib")
import modcheck
v = modcheck.load_schema()
base = yaml.safe_load(open(root + "/modules/sonar-scanner/module.yaml"))
cases = {
    "réseau service:../x": ("network", "service:../x"),
    "réseau service: vide": ("network", "service:"),
    "réseau hôte": ("network", "host"),
    "refs inconnue": ("refs", "all"),
    "refs_feature hostile": ("refs_feature", "../x"),
    "outil ../x": ("tool", "../x"),
    "outil /etc": ("tool", "/etc"),
}
for label, (k, val) in cases.items():
    m = copy.deepcopy(base)
    m["scan"][k] = val
    print("%s\t%s" % (label, "refusé" if modcheck.manifest_errors(m, v) else "accepté"))
EOF
while IFS=$'\t' read -r label verdict; do expect "manifeste hostile : $label" "$verdict" "refusé"; done < "$TMP/mut.out"

# --- 2. Convertisseur ----------------------------------------------------------------------
check "SARIF enregistré = conversion des réponses enregistrées" python3 -I - "$TOOL" "$FIX" "$ROOT/modules/sonar-scanner/tests/recorded.sarif" <<'EOF'
import json, sys
sys.path.insert(0, sys.argv[1])
import sonar_sarif
ld = lambda n: json.load(open("%s/%s-1.json" % (sys.argv[2], n)))
doc = sonar_sarif.convert("scanoria-testbed", [ld("issues")], [ld("hotspots")], [ld("rules")], tool_version="26.11.0.134175")
assert doc == json.load(open(sys.argv[3])), "recorded.sarif différent de la conversion"
EOF
check "attentes du banc d'essai satisfaites par la sortie enregistrée" \
	python3 "$MC" expect "$ROOT/modules/sonar-scanner/module.yaml" "$ROOT/modules/sonar-scanner/tests/recorded.sarif"

python3 -I - "$TOOL" > "$TMP/conv.out" <<'EOF'
import json, sys
sys.path.insert(0, sys.argv[1])
import sonar_sarif as s
K = "scanoria-0123456789ab"
def out(label, cond):
    print("%s\t%s" % (label, "oui" if cond else "non"))
def issue(**kw):
    d = {"key": "AX1", "rule": "python:S100", "component": K + ":src/a.py", "message": "m", "line": 3, "type": "BUG", "severity": "MAJOR"}
    d.update(kw)
    return d
def page(items, comps=None, total=None):
    return {"paging": {"total": total if total is not None else len(items)}, "issues": items,
            "components": comps if comps is not None else [{"key": K + ":src/a.py", "path": "src/a.py"}]}
def results(doc):
    return doc["runs"][0]["results"]
# Gravités.
r = results(s.convert(K, [page([issue(impacts=[{"softwareQuality": "RELIABILITY", "severity": "LOW"}, {"softwareQuality": "SECURITY", "severity": "HIGH"}])])]))[0]
out("impacts : la plus forte gravité (high)", r["properties"]["severity"] == "high")
out("impact SECURITY → catégorie sast", "scanoria-category:sast" in r["properties"]["tags"])
r = results(s.convert(K, [page([issue(severity="BLOCKER")])]))[0]
out("sans impacts : gravité historique (blocker)", r["properties"]["severity"] == "blocker" and r["level"] == "error")
r = results(s.convert(K, [page([issue(severity="WEIRD", type="CODE_SMELL")])]))[0]
out("gravité inconnue → major", r["properties"]["severity"] == "major")
out("code smell → catégorie quality", "scanoria-category:quality" in r["properties"]["tags"])
r = results(s.convert(K, [page([issue(type="VULNERABILITY", impacts=[{"softwareQuality": "SECURITY", "severity": "BLOCKER"}])])]))[0]
out("vulnérabilité blocker", r["properties"]["severity"] == "blocker" and "scanoria-category:sast" in r["properties"]["tags"])
h = s.convert(K, [], [{"hotspots": [{"key": "H1", "ruleKey": "python:S2068", "component": K + ":src/a.py", "message": "pw", "vulnerabilityProbability": "LOW", "securityCategory": "auth", "line": 2}], "components": []}])
r = results(h)[0]
out("hotspot : probabilité → gravité low, catégorie sast", r["properties"]["severity"] == "low" and "scanoria-category:sast" in r["properties"]["tags"])
out("hotspot : chemin déduit de la clé de composant", r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "src/a.py")
out("empreinte partielle = clé SonarQube", r["partialFingerprints"] == {"sonarqube/key/v1": "H1"})
# Pagination et bornes.
pages = [page([issue(key="P%d-%d" % (p, i)) for i in range(500)], total=1200) for p in range(2)] + [page([issue(key="L%d" % i) for i in range(200)], total=1200)]
d = s.convert(K, pages)
out("pagination : 1 200 issues sur 3 pages", len(results(d)) == 1200)
d = s.convert(K, pages, max_results=1000)
info = d["runs"][0]["properties"]["scanoria"]
out("borne : 1 000 résultats gardés, troncature signalée", len(results(d)) == 1000 and info["truncated"] is True and info["total"] == 1200)
c = s.Converter(K)
for p in pages:
    c.add_issues(p)
c.declare_total(12000)
info = c.sarif()["runs"][0]["properties"]["scanoria"]
out("total annoncé par le serveur au-delà du lu : troncature signalée", info["truncated"] is True and info["total"] == 12000 and info["kept"] == 1200)
c = s.Converter(K)
for p in pages:
    c.add_issues(p)
c.declare_total(1200)
out("total annoncé égal au lu : pas de troncature", c.sarif()["runs"][0]["properties"]["scanoria"]["truncated"] is False)
# Champs manquants ou malformés.
d = s.convert(K, [page([{"rule": "python:S1"}, "pas un objet", issue(message=None), issue(rule=None), issue(rule="a b"), issue()])])
info = d["runs"][0]["properties"]["scanoria"]
out("champs manquants : ignorés et comptés", len(results(d)) == 1 and info["skipped"] == 5)
d = s.convert(K, [page([issue(line=None, textRange=None)])])
out("sans ligne : résultat sans région", "region" not in results(d)[0]["locations"][0]["physicalLocation"])
d = s.convert(K, [page([issue(textRange={"startLine": 4, "endLine": 2, "startOffset": -1, "endOffset": "x"})])])
reg = results(d)[0]["locations"][0]["physicalLocation"]["region"]
out("région incohérente : bornée", reg == {"startLine": 4})
out("réponse qui n'est pas un objet : ignorée", results(s.convert(K, ["x", None, 3])) == [])
# Texte et chemins hostiles.
hostile = "<script>alert(1)</script>\x1b[31m\u202eevil\x00" + "A" * 5000
d = s.convert(K, [page([issue(message=hostile, tags=["ok-tag", "Bad Tag", "<x>", 5] + ["t%d" % i for i in range(40)])])])
r = results(d)[0]
out("message : sans caractère de contrôle ni bidi, borné", "\x1b" not in r["message"]["text"] and "\u202e" not in r["message"]["text"] and "\x00" not in r["message"]["text"] and len(r["message"]["text"]) <= 2000)
out("étiquettes : filtrées et bornées", "Bad Tag" not in r["properties"]["tags"] and "<x>" not in r["properties"]["tags"] and len(r["properties"]["tags"]) <= 21)
for p in ("../../etc/passwd", "/etc/passwd", "a/../../b", "c:\\x", "a\x00b"):
    d = s.convert(K, [page([issue(component=K + ":" + p)], comps=[{"key": K + ":" + p, "path": p}])])
    out("chemin hostile écarté : %r" % p, results(d) == [] and d["runs"][0]["properties"]["scanoria"]["outside"] == 1)
d = s.convert(K, [page([issue(component="autre-projet:src/a.py")], comps=[])])
out("composant d'un autre projet : écarté", results(d) == [])
d = s.convert(K, [page([issue()])], rule_pages=[{"rules": [{"key": "python:S100", "name": "Nom\x07 lisible"}, {"key": "inconnue", "name": "x"}]}])
rules = d["runs"][0]["tool"]["driver"]["rules"]
out("noms de règles : seulement les règles vues, nettoyés", [r["name"] for r in rules] == ["Nom lisible"])
json.dumps(d)
out("document sérialisable, version 2.1.0", d["version"] == "2.1.0")
EOF
while IFS=$'\t' read -r label verdict; do expect "convertisseur : $label" "$verdict" "oui"; done < "$TMP/conv.out"

# --- Faux serveur SonarQube ----------------------------------------------------------------
STATE="$TMP/sonar-state.json"
reset_state() { # mot_de_passe_admin [jq supplémentaire]
	jq -n --arg pw "$1" --arg fx "$FIX" '{status: "UP", starting: 0, admin_password: $pw, tokens: {}, users: ["admin"],
		perms: [], settings: {}, visibility: "public", ce: "SUCCESS", fixtures: $fx}' | jq "${2:-.}" > "$STATE"
}
reset_state admin
python3 -I "$ROOT/tests/lib/fake_sonar.py" "$STATE" "$TMP/port" "$TMP/sonar.log" &
SRV_PID=$!
for _ in $(seq 1 50); do [[ -s "$TMP/port" ]] && break; sleep 0.1; done
PORT=$(cat "$TMP/port")
[[ -n "$PORT" ]] && ok "faux serveur SonarQube démarré" || { ko "faux serveur SonarQube"; exit 1; }

# --- 3. Orchestration dans le conteneur (sonar_scan.py) ------------------------------------
SCANTOK="fake_$(head -c 20 /dev/urandom | od -An -tx1 | tr -d ' \n')"
jq --arg t "$SCANTOK" '.tokens[$t] = {login: "scanoria-scan", name: "scanoria-analyses"} | .issues_total = 1100' "$STATE" > "$STATE.n" && mv "$STATE.n" "$STATE"
mkdir -p "$TMP/c/out" "$TMP/c/src" "$TMP/c/secrets"
printf '%s\n' "$SCANTOK" > "$TMP/c/secrets/scan-token"
cat > "$TMP/c/fake-scanner" <<EOF
#!/usr/bin/env python3
import json, os, sys
args = sys.argv[1:]
open("$TMP/c/scanner-args.json", "w").write(json.dumps({"args": args, "token_env": bool(os.environ.get("SONAR_TOKEN")),
    "cache": os.environ.get("SONAR_USER_HOME")}))
if os.path.exists("$TMP/c/scanner-fail"):
    sys.exit(2)
work = [a.split("=", 1)[1] for a in args if a.startswith("-Dsonar.working.directory=")][0]
os.makedirs(work, exist_ok=True)
open(work + "/report-task.txt", "w").write("projectKey=x\nceTaskId=AZtask_01\n")
EOF
chmod 0755 "$TMP/c/fake-scanner"
PKEY="scanoria-$(printf '%012d' 42)"
scan() { # code attendu, libellé, [env supplémentaires…]
	local want=$1 label=$2
	shift 2
	local rc=0
	env SCANORIA_SERVICE_URL="http://127.0.0.1:$PORT" SCANORIA_PROJECT_KEY="$PKEY" \
		SCANORIA_TOKEN_FILE="$TMP/c/secrets/scan-token" SCANORIA_OUT_DIR="$TMP/c/out" SCANORIA_SRC_DIR="$TMP/c/src" \
		SCANORIA_SONAR_SCANNER="$TMP/c/fake-scanner" SCANORIA_BUDGET_S=60 "$@" \
		python3 -I "$TOOL/sonar_scan.py" "$TMP/c/out/result.sarif" > "$TMP/c/stdout" 2> "$TMP/c/stderr" || rc=$?
	expect "sonar_scan : $label (code $want)" "$rc" "$want"
}
scan 0 "analyse complète"
expect "sonar_scan : 1 100 issues paginées + 2 hotspots" "$(jq '.runs[0].results | length' "$TMP/c/out/result.sarif")" 1102
expect "sonar_scan : 3 pages d'issues demandées (500 par page)" "$(grep -c '"p": "api/issues/search"' "$TMP/sonar.log")" 3
jq -e --arg t "$SCANTOK" '.args | map(contains($t)) | any | not' "$TMP/c/scanner-args.json" > /dev/null \
	&& ok "sonar_scan : jeton absent des arguments de sonar-scanner" || ko "sonar_scan : jeton dans les arguments"
expect "sonar_scan : jeton passé par SONAR_TOKEN" "$(jq -r .token_env "$TMP/c/scanner-args.json")" true
jq -e --arg k "-Dsonar.projectKey=$PKEY" '.args | index($k) != null and index("-Dsonar.scm.disabled=true") != null' "$TMP/c/scanner-args.json" > /dev/null \
	&& ok "sonar_scan : clé de projet et SCM coupé" || ko "sonar_scan : arguments inattendus"
jq -e '.args | map(select(startswith("-Dproject.settings="))) | length == 1 and (.[0] | contains("/src") | not)' "$TMP/c/scanner-args.json" > /dev/null \
	&& ok "sonar_scan : sonar-project.properties du dépôt remplacé par un fichier vide hors de /src" || ko "sonar_scan : réglages du dépôt lus"
[[ ! -e "$TMP/c/out/.work" ]] && ok "sonar_scan : répertoire de travail supprimé" || ko "sonar_scan : répertoire de travail laissé"
grep -qF "$SCANTOK" "$TMP/c/stderr" "$TMP/c/stdout" && ko "sonar_scan : jeton dans le journal" || ok "sonar_scan : jeton absent du journal"
rm -f "$TMP/c/out/result.sarif"
jq '.ce = "FAILED"' "$STATE" > "$STATE.n" && mv "$STATE.n" "$STATE"
scan 4 "tâche de calcul en échec"
[[ ! -e "$TMP/c/out/result.sarif" ]] && ok "sonar_scan : aucune sortie partielle" || ko "sonar_scan : sortie partielle"
jq '.ce = "SUCCESS"' "$STATE" > "$STATE.n" && mv "$STATE.n" "$STATE"
touch "$TMP/c/scanner-fail"
scan 4 "sonar-scanner en échec"
rm "$TMP/c/scanner-fail"
scan 2 "clé de projet hostile" SCANORIA_PROJECT_KEY='x;rm -rf /'
scan 2 "adresse du service hostile" SCANORIA_SERVICE_URL='http://evil.exemple.test@127.0.0.1/'
scan 2 "sortie hors de /out" SCANORIA_OUT_DIR="$TMP/c/src"
printf 'pas un jeton !\n' > "$TMP/c/secrets/scan-token"
scan 3 "jeton malformé"
printf '%s\n' "$SCANTOK" > "$TMP/c/secrets/scan-token"
scan 3 "serveur injoignable" SCANORIA_SERVICE_URL="http://127.0.0.1:1"

# Branches et PR : paramètres de sonar-scanner et lecture filtrée.
args_has() { jq -e --arg a "$1" '.args | index($a) != null' "$TMP/c/scanner-args.json" > /dev/null; }
args_none() { jq -e --arg p "$1" '[.args[] | select(startswith($p))] | length == 0' "$TMP/c/scanner-args.json" > /dev/null; }
scan 0 "branche principale : aucun paramètre de branche"
args_none "-Dsonar.branch." && args_none "-Dsonar.pullrequest." && ok "sonar_scan : branche principale sans sonar.branch.* ni sonar.pullrequest.*" || ko "sonar_scan : paramètre de branche inattendu"
: > "$TMP/sonar.log"
scan 0 "branche feature/x" SCANORIA_BRANCH=feature/x
args_has "-Dsonar.branch.name=feature/x" && ok "sonar_scan : sonar.branch.name transmis" || ko "sonar_scan : sonar.branch.name absent"
expect "sonar_scan : issues lues sur la branche" "$(jq -s '[.[] | select(.p == "api/issues/search") | .keys | index("branch") != null] | all and length > 0' "$TMP/sonar.log")" true
expect "sonar_scan : hotspots lus sur la branche" "$(jq -s '[.[] | select(.p == "api/hotspots/search") | .keys | index("branch") != null] | all and length > 0' "$TMP/sonar.log")" true
: > "$TMP/sonar.log"
scan 0 "PR 42" SCANORIA_PR_KEY=42 SCANORIA_PR_BRANCH=feature/y SCANORIA_PR_BASE=main
args_has "-Dsonar.pullrequest.key=42" && args_has "-Dsonar.pullrequest.branch=feature/y" && args_has "-Dsonar.pullrequest.base=main" \
	&& ok "sonar_scan : paramètres sonar.pullrequest.* transmis" || ko "sonar_scan : paramètres de PR absents"
args_none "-Dsonar.branch." && ok "sonar_scan : PR sans sonar.branch.name" || ko "sonar_scan : PR avec sonar.branch.name"
expect "sonar_scan : issues lues sur la PR" "$(jq -s '[.[] | select(.p == "api/issues/search") | .keys | index("pullRequest") != null] | all and length > 0' "$TMP/sonar.log")" true
for b in "-Dsonar.x=1" "a..b" "a b" "x;rm" "feature/" "$(printf 'a\nb')"; do
	scan 2 "branche hostile « $b »" SCANORIA_BRANCH="$b"
done
scan 2 "branche et PR à la fois" SCANORIA_BRANCH=x SCANORIA_PR_KEY=1 SCANORIA_PR_BRANCH=y SCANORIA_PR_BASE=main
scan 2 "PR hostile" SCANORIA_PR_KEY='1 -Dx' SCANORIA_PR_BRANCH=y SCANORIA_PR_BASE=main
scan 2 "PR sans base" SCANORIA_PR_KEY=7 SCANORIA_PR_BRANCH=y

# --- 4. Runner (mode test) -----------------------------------------------------------------
T="$TMP/root"
STUBS="$TMP/stubs"
SCANS="$T/var/lib/scanoria/scans"
SEC="$T/var/lib/scanoria/modules/sonarqube/secrets"
mkdir -p "$T/var/lib/scanoria/modules" "$T/run/scanoria" "$T/proc" "$T/sys/fs/cgroup/fake.scope/container" \
	"$T/etc/ssl/certs" "$T/usr/lib/scanoria/scan-tools/sonar" "$STUBS" "$SEC"
printf 'MemTotal:       16384000 kB\n' > "$T/proc/meminfo"
for i in 0 1 2 3; do printf 'processor\t: %d\n' "$i"; done > "$T/proc/cpuinfo"
echo "52428800" > "$T/sys/fs/cgroup/fake.scope/container/memory.peak"
printf 'usage_usec 1234000\n' > "$T/sys/fs/cgroup/fake.scope/container/cpu.stat"
echo "AC de test" > "$T/etc/ssl/certs/ca-certificates.crt"
cp "$TOOL"/*.py "$T/usr/lib/scanoria/scan-tools/sonar/"
export SCANORIA_TEST_ROOT="$T" SCANORIA_TEST_BIN="$STUBS" SCANORIA_TEST_RESOLVE="forge.exemple.test=192.0.2.10"
unset SCANORIA_TEST_OWNER_UID SCANORIA_SCANS_DIR SCANORIA_RUNNER_STATE
RTOK="fake_$(head -c 20 /dev/urandom | od -An -tx1 | tr -d ' \n')"
printf '%s\n' "$RTOK" > "$SEC/scan-token"
chmod 0600 "$SEC/scan-token"
COMMIT=$(printf 'b17' | sha256sum | cut -c1-40)

cat > "$STUBS/podman" <<EOF
#!/usr/bin/env python3
# Bouchon de podman : journal des arguments, clone et scanner simulés.
import json, os, sys
a = sys.argv[1:]
with open("$TMP/podman.log", "a") as f:
    f.write(json.dumps(a) + "\n")
if a[:2] == ["image", "exists"]:
    sys.exit(0)
if a[:2] == ["network", "exists"]:
    sys.exit(0 if os.path.exists("$TMP/net") else 1)
if a[:2] == ["network", "create"]:
    open("$TMP/net", "w").close(); sys.exit(0)
if a[:2] == ["secret", "create"]:
    # Le jeton est lu dans un fichier : il n'est jamais un argument.
    open("$TMP/secret-content", "w").write(open(a[3]).read())
    open("$TMP/secret-mode", "w").write(oct(os.stat(a[3]).st_mode & 0o777))
    sys.exit(0)
if a[:1] == ["inspect"]:
    fmt = a[a.index("--format") + 1]
    print("/fake.scope" if "Cgroup" in fmt else "false"); sys.exit(0)
if a[:1] != ["run"]:
    sys.exit(0)
vols = {}
for i, x in enumerate(a):
    if x == "--volume":
        host, target, mode = a[i + 1].rsplit(":", 2)
        vols[target] = (host, mode)
ep = json.loads(a[a.index("--entrypoint") + 1])
if ep == ["/bin/sh"]:   # git-fetch
    src = vols["/src"][0]
    os.makedirs(src, exist_ok=True)
    open(src + "/app.py", "w").write("print(1)\n")
    print("commit=$COMMIT")
    sys.exit(0)
open("$TMP/scan-args.json", "w").write(json.dumps(a))
print("analyse avec le jeton $RTOK")
open(vols["/out"][0] + "/result.sarif", "w").write(open("$ROOT/modules/sonar-scanner/tests/recorded.sarif").read())
sys.exit(0)
EOF
cat > "$STUBS/nft" <<'EOF'
#!/bin/sh
cat > /dev/null
exit 0
EOF
chmod 0755 "$STUBS/podman" "$STUBS/nft"

IMG="docker.io/sonarsource/sonar-scanner-cli@sha256:$(printf 'faux' | sha256sum | cut -d' ' -f1)"
SIMG="docker.io/library/sonarqube@sha256:$(printf 'sq' | sha256sum | cut -d' ' -f1)"
GIMG="docker.io/exemple/git@sha256:$(printf 'git' | sha256sum | cut -d' ' -f1)"
registry() { # statut_service actif_service [fonction_active]
	python3 - "$T/var/lib/scanoria/modules/installed.json" "$TMP/scanner.json" "$IMG" "$SIMG" "$GIMG" "$1" "$2" "${3:-}" <<'EOF'
import json, sys
path, scanner, img, simg, gimg, sstatus, senabled, feat = sys.argv[1:9]
sc = json.load(open(scanner))
sc["image"] = img
sc["version"] = "1.0.0"
git = {"id": "git-fetch", "name": "git", "type": "scanner", "version": "1.0.0", "categories": ["system"],
       "license": {"spdx": "MIT", "restrictions": "none"}, "image": gimg,
       "resources": {"min_ram_mb": 256, "min_cpu": 1, "disk_mb": 10},
       "requires": {"modules": [], "feeds": []}, "conflicts": [],
       "options": {"type": "object", "additionalProperties": False, "properties": {}},
       "scan": {"inputs": ["repo"], "network": "none", "timeout_s": 60, "command": ["git"]},
       "outputs": {"sarif": {"path": "/out/r.sarif", "version": "2.1.0"}}}
svc = {"id": "sonarqube", "name": "SonarQube", "type": "service", "version": "26.11.0.134175",
       "categories": ["quality", "sast"], "license": {"spdx": "LGPL-3.0-only", "restrictions": "none"},
       "image": simg, "resources": {"min_ram_mb": 4096, "min_cpu": 2, "disk_mb": 10},
       "requires": {"modules": [], "feeds": []}, "conflicts": [], "hostname": "sonarqube",
       "options": {"type": "object", "additionalProperties": False, "properties": {}},
       "service": {"port": 9000, "health_path": "/api/system/status", "units": [{}]}}
if feat:
    svc["active_variant"] = {"feature": feat, "version": "26.11.0", "option": feat}
reg = {"modules": {
    "sonar-scanner": {"manifest": sc, "status": "healthy", "enabled": True, "options": {}},
    "git-fetch": {"manifest": git, "status": "healthy", "enabled": True, "options": {}},
    "sonarqube": {"manifest": svc, "status": sstatus, "enabled": senabled == "true", "options": {}, "host_port": 18000},
}, "operations": []}
json.dump(reg, open(path, "w"))
EOF
}
uuid() { python3 -c 'import uuid; print(uuid.uuid4())'; }
PROJ=$(uuid)
KEY="scanoria-$(tr -d '-' <<< "$PROJ" | cut -c1-12)"
job() { # id [ref] [default_branch|-] [project|-]
	local ref=${2:-main} db=${3:-main} pr=${4:-$PROJ}
	jq -cn --arg id "$1" --arg sid "$(uuid)" --arg ref "$ref" --arg db "$db" --arg pr "$pr" '
		{schema: 1, id: $id, scan_id: $sid, created_at: "2026-11-24T10:00:00Z",
		 source: ({kind: "git", url: "https://forge.exemple.test/exemple/depot.git", ref: $ref, history: "shallow"}
		          + (if $db == "-" then {} else {default_branch: $db} end)),
		 modules: [{id: "sonar-scanner", version: "1.0.0"}]}
		+ (if $pr == "-" then {} else {project_id: $pr} end)'
}
drop() { mkdir -p "$SCANS/jobs/incoming"; printf '%s' "$2" > "$SCANS/jobs/incoming/$1.json"; chmod 0600 "$SCANS/jobs/incoming/$1.json"; }
run_runner() { "$RUNNER" --once 2> "$TMP/runner.err" || { echo "runner : code $?"; sed 's/^/     /' "$TMP/runner.err"; }; }
res() { cat "$SCANS/results/$1/result.json" 2> /dev/null || echo '{}'; }
mod() { res "$1" | jq -r '.modules[] | select(.id == "sonar-scanner") | .status + "/" + (.error.code // "-")'; }
valid() {
	python3 -I -B -c 'import json, sys; sys.path.insert(0, sys.argv[1]); from scanoria import schema
errs = schema.load("schemas", "scan-result").errors(json.load(open(sys.argv[2])))
print("; ".join(errs[:3])); sys.exit(1 if errs else 0)' "$PYLIB" "$SCANS/results/$1/result.json"
}

registry healthy true
id=$(uuid); drop "$id" "$(job "$id")"; rm -f "$TMP/podman.log"; run_runner
expect "runner : branche par défaut → module ok" "$(mod "$id")" "ok/-"
[[ "$(mod "$id")" == "ok/-" ]] || { res "$id"; cat "$TMP/runner.err"; }
check "runner : résultat conforme au schéma" valid "$id"
jq -r '.[]' "$TMP/scan-args.json" > "$TMP/scan-args.txt"
grep -qx -- "--network=scanoria-mod-sonarqube_scan" "$TMP/scan-args.txt" && ok "runner : réseau interne du service seul" || ko "runner : réseau du service absent"
grep -q -- "--network=none" "$TMP/scan-args.txt" && ko "runner : --network=none laissé" || ok "runner : un seul réseau"
expect "runner : un seul --network" "$(grep -c -- '^--network' "$TMP/scan-args.txt")" 1
grep -qE '^scanoria-scan-[0-9a-f]{16},type=mount,target=scan-token,uid=65534,gid=65534,mode=400$' "$TMP/scan-args.txt" \
	&& ok "runner : jeton par secret Podman monté" || ko "runner : secret Podman absent"
grep -qx "SCANORIA_SERVICE_URL=http://scanoria-mod-sonarqube:9000" "$TMP/scan-args.txt" && ok "runner : adresse du service" || ko "runner : adresse du service"
grep -qx "SCANORIA_PROJECT_KEY=$KEY" "$TMP/scan-args.txt" && ok "runner : clé de projet scanoria-<uuid court>" || ko "runner : clé de projet"
grep -qE ":/scanoria:ro$" "$TMP/scan-args.txt" && ok "runner : outil de l'appliance en lecture seule" || ko "runner : outil non monté"
grep -qx -- "--read-only" "$TMP/scan-args.txt" && grep -qx -- "--cap-drop=ALL" "$TMP/scan-args.txt" \
	&& ok "runner : confinement conservé (lecture seule, aucune capacité)" || ko "runner : confinement perdu"
grep -qF "$RTOK" "$TMP/podman.log" && ko "runner : jeton dans les arguments de podman" || ok "runner : jeton jamais en argument"
expect "runner : secret Podman créé depuis un fichier 0600" "$(cat "$TMP/secret-mode")" "0o600"
expect "runner : contenu du secret = jeton" "$(cat "$TMP/secret-content")" "$RTOK"
grep -q '^\["secret", "rm", "scanoria-scan-' "$TMP/podman.log" && ok "runner : secret Podman retiré" || ko "runner : secret Podman laissé"
compgen -G "$T/run/scanoria/scan-secret-*" > /dev/null && ko "runner : fichier temporaire du jeton laissé" || ok "runner : fichier temporaire du jeton supprimé"
grep -rqF "$RTOK" "$SCANS/results/$id" && ko "runner : jeton dans les résultats ou le journal" || ok "runner : jeton masqué dans le journal du module"

hostile_job() { # libellé id contenu
	drop "$2" "$3"; run_runner
	expect "runner hostile : $1 → E_JOB_INVALID" "$(res "$2" | jq -r .error.code)" E_JOB_INVALID
}
id=$(uuid); hostile_job "branche par défaut --upload-pack" "$id" "$(job "$id" main "--upload-pack=x")"
id=$(uuid); hostile_job "branche par défaut avec .." "$id" "$(job "$id" main "a/../b")"
id=$(uuid); hostile_job "projet non uuid" "$id" "$(job "$id" main main "../../x")"

id=$(uuid); drop "$id" "$(job "$id" feature/x)"; run_runner
expect "runner : autre branche → skipped (E_REF_NOT_DEFAULT)" "$(mod "$id")" "skipped/E_REF_NOT_DEFAULT"
res "$id" | jq -r '.modules[0].error.message' | grep -q "default branch only" && ok "runner : raison « default branch only »" || ko "runner : raison absente"
id=$(uuid); drop "$id" "$(job "$id" refs/heads/main main)"; run_runner
expect "runner : refs/heads/<branche par défaut> → ok" "$(mod "$id")" "ok/-"
id=$(uuid); drop "$id" "$(job "$id" main -)"; run_runner
expect "runner : tâche sans branche par défaut → skipped" "$(mod "$id")" "skipped/E_REF_NOT_DEFAULT"
id=$(uuid); drop "$id" "$(job "$id" main main -)"; run_runner
expect "runner : tâche sans projet → skipped (E_PROJECT_UNKNOWN)" "$(mod "$id")" "skipped/E_PROJECT_UNKNOWN"
check "runner : résultat skipped conforme" valid "$id"

registry healthy false
id=$(uuid); drop "$id" "$(job "$id")"; run_runner
expect "runner : service désactivé → missing (G13)" "$(mod "$id")" "missing/E_SERVICE_MISSING"
registry failed true
id=$(uuid); drop "$id" "$(job "$id")"; run_runner
expect "runner : service en échec → missing" "$(mod "$id")" "missing/E_SERVICE_MISSING"
id=$(uuid); drop "$id" "$(job "$id" develop)"; run_runner
expect "runner : autre branche, service absent → skipped (pas missing)" "$(mod "$id")" "skipped/E_REF_NOT_DEFAULT"
registry healthy true
chmod 0644 "$SEC/scan-token"
id=$(uuid); drop "$id" "$(job "$id")"; run_runner
expect "runner : jeton lisible par d'autres → missing" "$(mod "$id")" "missing/E_SERVICE_TOKEN"
chmod 0600 "$SEC/scan-token"
mv "$SEC/scan-token" "$SEC/ailleurs"; ln -s "$SEC/ailleurs" "$SEC/scan-token"
id=$(uuid); drop "$id" "$(job "$id")"; run_runner
expect "runner : jeton en lien symbolique → missing" "$(mod "$id")" "missing/E_SERVICE_TOKEN"
rm "$SEC/scan-token"
id=$(uuid); drop "$id" "$(job "$id")"; run_runner
expect "runner : jeton absent → missing" "$(mod "$id")" "missing/E_SERVICE_TOKEN"
mv "$SEC/ailleurs" "$SEC/scan-token"
mv "$T/usr/lib/scanoria/scan-tools/sonar" "$T/usr/lib/scanoria/scan-tools/autre"
id=$(uuid); drop "$id" "$(job "$id")"; run_runner
expect "runner : outil de l'appliance absent → missing" "$(mod "$id")" "missing/E_MODULE_INVALID"
mv "$T/usr/lib/scanoria/scan-tools/autre" "$T/usr/lib/scanoria/scan-tools/sonar"

# Branches (fonction « branches » du service) : SCANORIA_BRANCH transmis.
branch_env() { jq -r '.[] | select(startswith("SCANORIA_BRANCH="))' "$TMP/scan-args.json"; }
registry healthy true branches
id=$(uuid); drop "$id" "$(job "$id" feature/x)"; run_runner
expect "runner branches : autre branche → ok" "$(mod "$id")" "ok/-"
expect "runner branches : SCANORIA_BRANCH=feature/x" "$(branch_env)" "SCANORIA_BRANCH=feature/x"
id=$(uuid); drop "$id" "$(job "$id" refs/heads/release/2.0)"; run_runner
expect "runner branches : refs/heads/… raccourci" "$(branch_env)" "SCANORIA_BRANCH=release/2.0"
id=$(uuid); drop "$id" "$(job "$id" refs/tags/v1.2.0)"; run_runner
expect "runner branches : étiquette analysée comme branche" "$(branch_env)" "SCANORIA_BRANCH=v1.2.0"
id=$(uuid); drop "$id" "$(job "$id" main)"; run_runner
expect "runner branches : branche par défaut → ok" "$(mod "$id")" "ok/-"
expect "runner branches : branche par défaut sans SCANORIA_BRANCH" "$(branch_env)" ""
id=$(uuid); drop "$id" "$(job "$id" refs/heads/main main)"; run_runner
expect "runner branches : refs/heads/<défaut> sans SCANORIA_BRANCH" "$(branch_env)" ""
id=$(uuid); drop "$id" "$(job "$id" feature/x -)"; run_runner
expect "runner branches : branche par défaut inconnue → skipped" "$(mod "$id")" "skipped/E_REF_NOT_DEFAULT"
id=$(uuid); drop "$id" "$(job "$id" refs/pull/3/head)"; run_runner
expect "runner branches : référence hors heads/tags → skipped" "$(mod "$id")" "skipped/E_REF_NOT_DEFAULT"
registry healthy true autre
id=$(uuid); drop "$id" "$(job "$id" feature/x)"; run_runner
expect "runner : autre fonction active → skipped" "$(mod "$id")" "skipped/E_REF_NOT_DEFAULT"
res "$id" | jq -r '.modules[0].error.message' | grep -q "branches is not active" && ok "runner : raison « branches is not active »" || ko "runner : raison absente"
registry healthy true

# Variantes d'image (helper) : compatibilité, manifeste effectif, fichiers laissés.
cat > "$TMP/variant.py" <<'EOF'
import copy
IMG = "docker.io/mc1arke/sonarqube-with-community-branch-plugin@sha256:" + "a" * 64
def with_variant(base, **kw):
    m = copy.deepcopy(base)
    v = {"feature": "branches", "option": "branches", "image": IMG, "version": "26.11.0",
         "base_version": m["version"],
         "license": {"spdx": "LGPL-3.0-only", "url": "https://exemple.test/l", "verified_at": "2026-11-24"},
         "upstream": {"source": "https://exemple.test/s"},
         "leaves": [{"volume": "extensions", "dir": "plugins", "prefix": "sonarqube-community-branch-plugin"}]}
    v.update(kw)
    m["service"]["variants"] = [v]
    return m
EOF
check "variantes : choix, compatibilité, manifeste effectif" python3 -I - "$PYLIB" "$TMP/service.json" "$TMP" <<'EOF'
import json, sys
sys.path.insert(0, sys.argv[1])
sys.path.insert(0, sys.argv[3])
from scanoria import variants
from scanoria.common import Fail
from variant import IMG, with_variant
base = json.load(open(sys.argv[2]))
assert base["service"]["variants"] == [], "aucune variante sans plugin compatible publié"
st = variants.features(base, {"branches": True})["branches"]
assert st["active"] is False and st["code"] == "unavailable", st
assert variants.features(base, {"branches": False})["branches"]["code"] == "disabled"
assert variants.effective(base, {"branches": True})["image"] == base["image"]
m = with_variant(base)
e = variants.effective(m, {"branches": True})
assert e["image"] == IMG and e["active_variant"]["feature"] == "branches", e.get("active_variant")
assert variants.active_features(e) == {"branches"}
assert variants.features(m, {"branches": True})["branches"] == {"active": True, "version": "26.11.0", "code": None, "reason": None}
off = variants.effective(m, {"branches": False})
assert off["image"] == base["image"] and "active_variant" not in off and variants.active_features(off) == set()
assert m["image"] == base["image"], "manifeste du catalogue modifié"
# Plugin d'une autre majeure.mineure : image officielle gardée, raison donnée.
old = with_variant(base, version="26.10.0")
assert variants.effective(old, {"branches": True})["image"] == base["image"]
assert variants.features(old, {"branches": True})["branches"]["code"] == "incompatible"
# Image construite sur un autre SonarQube : écartée de même.
assert variants.effective(with_variant(base, base_version="26.10.0.133078"), {"branches": True})["image"] == base["image"]
for label, kw in {"image non épinglée": {"image": "docker.io/mc1arke/x:latest"},
                  "fonction non déclarée": {"feature": "autre", "option": "autre"},
                  "option différente": {"option": "autre"},
                  "volume inconnu": {"leaves": [{"volume": "etc", "dir": "plugins", "prefix": "abcdef"}]},
                  "répertoire ..": {"leaves": [{"volume": "extensions", "dir": "..", "prefix": "abcdef"}]},
                  "répertoire avec /": {"leaves": [{"volume": "extensions", "dir": "a/b", "prefix": "abcdef"}]}}.items():
    try:
        variants.declared(with_variant(base, **kw))
    except Fail:
        continue
    raise SystemExit("variante hostile acceptée : " + label)
EOF
check "variantes : catalogue refusé si la variante est incompatible" python3 -I - "$ROOT" "$TMP/service.json" "$TMP" <<'EOF'
import json, sys
sys.path.insert(0, sys.argv[1] + "/catalog")
sys.path.insert(0, sys.argv[3])
import build
from variant import with_variant
base = json.load(open(sys.argv[2]))
build.check_variants(with_variant(base))
for kw in ({"version": "26.10.0"}, {"base_version": "26.10.0.133078"}):
    try:
        build.check_variants(with_variant(base, **kw))
    except build.BuildError:
        continue
    raise SystemExit("variante incompatible acceptée : %r" % kw)
EOF

# Fichiers d'une variante inactive : retirés du volume, sans suivre de lien.
cp "$STUBS/podman" "$TMP/podman.stub"
cat > "$STUBS/podman" <<'EOF'
#!/bin/sh
[ "$1 $2" = "volume inspect" ] && { echo "/vol"; exit 0; }
exit 1
EOF
chmod 0755 "$STUBS/podman"
mkdir -p "$T/vol/plugins" "$TMP/ailleurs"
printf jar > "$T/vol/plugins/sonarqube-community-branch-plugin-26.11.0.jar"
printf autre > "$T/vol/plugins/sonar-autre-plugin.jar"
printf cible > "$TMP/ailleurs/sonarqube-community-branch-plugin-cible"
ln -s "$TMP/ailleurs/sonarqube-community-branch-plugin-cible" "$T/vol/plugins/sonarqube-community-branch-plugin-lien.jar"
check "variantes : fichiers d'une variante inactive retirés, liens non suivis" python3 -I - "$PYLIB" "$TMP/service.json" "$TMP" "$T" <<'EOF'
import json, os, sys
sys.path.insert(0, sys.argv[1])
sys.path.insert(0, sys.argv[3])
from scanoria import variants
from variant import with_variant
m = with_variant(json.load(open(sys.argv[2])))
T, TMP = sys.argv[4], sys.argv[3]
assert variants.remove_leaves(variants.effective(m, {"branches": True})) == [], "variante active : rien à retirer"
assert os.path.exists(T + "/vol/plugins/sonarqube-community-branch-plugin-26.11.0.jar")
removed = sorted(variants.remove_leaves(variants.effective(m, {"branches": False})))
assert removed == ["plugins/sonarqube-community-branch-plugin-26.11.0.jar",
                   "plugins/sonarqube-community-branch-plugin-lien.jar"], removed
assert os.path.exists(T + "/vol/plugins/sonar-autre-plugin.jar"), "autre plugin retiré"
assert os.path.exists(TMP + "/ailleurs/sonarqube-community-branch-plugin-cible"), "cible du lien retirée"
EOF
rm -rf "$T/vol/plugins" && ln -s "$TMP/ailleurs" "$T/vol/plugins"
check "variantes : répertoire du volume en lien symbolique jamais suivi" python3 -I - "$PYLIB" "$TMP/service.json" "$TMP" <<'EOF'
import json, os, sys
sys.path.insert(0, sys.argv[1])
sys.path.insert(0, sys.argv[3])
from scanoria import variants
from scanoria.common import Fail
from variant import with_variant
m = with_variant(json.load(open(sys.argv[2])))
try:
    variants.remove_leaves(m)
except Fail:
    pass
assert os.path.exists(sys.argv[3] + "/ailleurs/sonarqube-community-branch-plugin-cible"), "lien suivi"
EOF
rm -rf "$T/vol" "$TMP/ailleurs"
cp "$TMP/podman.stub" "$STUBS/podman"

# --- 5. Mise en service (provision.py) -----------------------------------------------------
reset_state admin '.starting = 3'
prov() { # sortie JSON d'un appel Python
	python3 -I -B - "$PYLIB" "$PORT" "$@" <<'EOF'
import json, sys
sys.path.insert(0, sys.argv[1])
from scanoria import provision
from scanoria.common import Fail
port, what = int(sys.argv[2]), sys.argv[3]
m = {"id": "sonarqube", "type": "service"}
try:
    if what == "run":
        print(json.dumps(provision.run(m, {"host_port": port, "timeout": 20, "phase": "install"})))
    elif what == "other":
        print(json.dumps(provision.run({"id": "dtrack"}, {"host_port": port})))
    elif what == "reset":
        class C:
            params = {"id": sys.argv[4]}
            req = {"id": sys.argv[5]}
            def left(self):
                return 60
        print(json.dumps(provision.act_reset_service_admin(C())))
except Fail as f:
    print(json.dumps({"code": f.code, "message": f.message}))
EOF
}
expect "provision : sans effet pour un autre module" "$(prov other)" null
out=$(prov run)
expect "provision : SonarQube prêt après STARTING" "$(jq -r .version <<< "$out")" 26.11.0.134175
ADMIN_PW=$(cat "$SEC/admin-password")
[[ "$ADMIN_PW" != admin ]] && jq -e --arg p "$ADMIN_PW" '.admin_password == $p' "$STATE" > /dev/null \
	&& ok "provision : mot de passe admin par défaut remplacé" || ko "provision : mot de passe admin"
expect "provision : fichier admin-password 0600" "$(stat -c %a "$SEC/admin-password")" 600
[[ ! -e "$SEC/admin-password.new" ]] && ok "provision : aucun fichier provisoire laissé" || ko "provision : fichier provisoire laissé"
expect "provision : utilisateur d'analyse créé" "$(jq -r '.users | index("scanoria-scan") != null' "$STATE")" true
expect "provision : droits analyse et création de projets" "$(jq -c '[.perms[] | select(.[0] == "scanoria-scan") | .[1]] | sort' "$STATE")" '["provisioning","scan"]'
TOK=$(tr -d '\n' < "$SEC/scan-token")
jq -e --arg t "$TOK" '.tokens[$t].login == "scanoria-scan"' "$STATE" > /dev/null && ok "provision : jeton d'analyse écrit" || ko "provision : jeton d'analyse"
expect "provision : fichier scan-token 0600" "$(stat -c %a "$SEC/scan-token")" 600
expect "provision : authentification forcée" "$(jq -r '.settings["sonar.forceAuthentication"]' "$STATE")" true
expect "provision : projets privés par défaut" "$(jq -r .visibility "$STATE")" private
grep -q '"password"' "$TMP/sonar.log" && ko "provision : mot de passe journalisé par le faux serveur" || ok "provision : aucune valeur de mot de passe journalisée"
out=$(prov run)
expect "provision : idempotente (jeton gardé)" "$(jq -r .token_renewed <<< "$out")/$(jq -r .generated "$STATE")" "false/1"
# Mot de passe admin changé à la main dans SonarQube : sans conséquence tant que le jeton vaut.
jq '.admin_password = "Change-a-la-main-1"' "$STATE" > "$STATE.n" && mv "$STATE.n" "$STATE"
expect "provision : admin changé à la main, jeton valide → admin_known false" "$(prov run | jq -r .admin_known)" false
jq '.tokens = {}' "$STATE" > "$STATE.n" && mv "$STATE.n" "$STATE"
expect "provision : admin inconnu et jeton révoqué → E_SONAR_ADMIN" "$(prov run | jq -r .code)" E_SONAR_ADMIN
jq --arg p "$ADMIN_PW" '.admin_password = $p' "$STATE" > "$STATE.n" && mv "$STATE.n" "$STATE"
expect "provision : jeton révoqué → renouvelé" "$(prov run | jq -r .token_renewed)" true
# Reprise après un arrêt entre le changement de mot de passe et le remplacement du fichier.
REPRISE="Sq#$(od -An -N12 -tx1 /dev/urandom | tr -d ' \n')9reprise"
printf '%s\n' "$REPRISE" > "$SEC/admin-password.new"; chmod 0600 "$SEC/admin-password.new"
jq --arg p "$REPRISE" '.admin_password = $p' "$STATE" > "$STATE.n" && mv "$STATE.n" "$STATE"
prov run > /dev/null
expect "provision : reprise du changement interrompu" "$(cat "$SEC/admin-password")" "$REPRISE"
jq '.status = "DB_MIGRATION_NEEDED"' "$STATE" > "$STATE.n" && mv "$STATE.n" "$STATE"
prov run > /dev/null
expect "provision : migration de base lancée après mise à jour" "$(jq -r .migrated "$STATE")" true
jq '.status = "DOWN"' "$STATE" > "$STATE.n" && mv "$STATE.n" "$STATE"
expect "provision : service DOWN → E_SONAR_UNAVAILABLE" "$(prov run | jq -r .code)" E_SONAR_UNAVAILABLE
jq '.status = "UP"' "$STATE" > "$STATE.n" && mv "$STATE.n" "$STATE"

# Réinitialisation (demande reset-service-admin) : registre avec le service à l'écoute du faux serveur.
python3 - "$T/var/lib/scanoria/modules/installed.json" "$PORT" <<'EOF'
import json, sys
p, port = sys.argv[1], int(sys.argv[2])
reg = json.load(open(p))
reg["modules"]["sonarqube"]["host_port"] = port
json.dump(reg, open(p, "w"))
EOF
RID=$(uuid)
OLD=$(cat "$SEC/admin-password")
out=$(prov reset sonarqube "$RID")
expect "réinitialisation : sortie sans mot de passe" "$(jq -c . <<< "$out")" '{"id":"sonarqube","login":"admin","oneshot":true}'
NEWPW=$(jq -r .password "$T/run/scanoria/oneshot/$RID.json")
[[ "$NEWPW" != "$OLD" ]] && jq -e --arg p "$NEWPW" '.admin_password == $p' "$STATE" > /dev/null \
	&& ok "réinitialisation : nouveau mot de passe actif" || ko "réinitialisation : mot de passe inchangé"
expect "réinitialisation : appliance à jour" "$(cat "$SEC/admin-password")" "$NEWPW"
expect "réinitialisation : dépôt unique 0640" "$(stat -c %a "$T/run/scanoria/oneshot/$RID.json")" 640
expect "réinitialisation : module sans compte géré → E_PRECONDITION" "$(prov reset dtrack "$(uuid)" | jq -r .code)" E_PRECONDITION
expect "réinitialisation : id de demande hostile → E_INVALID_PARAM" "$(prov reset sonarqube "../../etc/x" | jq -r .code)" E_INVALID_PARAM
touch -d '-3 minutes' "$T/run/scanoria/oneshot/$RID.json"
RID2=$(uuid)
prov reset sonarqube "$RID2" > /dev/null
[[ ! -e "$T/run/scanoria/oneshot/$RID.json" ]] && ok "réinitialisation : dépôts de plus de 2 minutes effacés" || ko "réinitialisation : dépôt périmé laissé"
[[ -e "$T/run/scanoria/oneshot/$RID2.json" ]] && ok "réinitialisation : dépôt récent gardé pour la console" || ko "réinitialisation : dépôt récent effacé"
grep -q 'provision.purge_oneshot()' "$PYLIB/scanoria/helper.py" \
	&& ok "helper : purge des dépôts échus à chaque passage" || ko "helper : purge absente de cmd_run"

# Sauvegarde : mot de passe admin et jeton suivent la base (restauration cohérente).
python3 -I -B - "$PYLIB" "$TMP/bk" > "$TMP/bk.out" <<'EOF'
import os, sys
sys.path.insert(0, sys.argv[1])
from scanoria import backup, services
from scanoria.common import Fail
d = sys.argv[2]
os.makedirs(d, mode=0o700)
def out(label, cond):
    print(("ok   " if cond else "FAIL ") + label)
adm, tok = services.secret_path("sonarqube", "admin-password"), services.secret_path("sonarqube", "scan-token")
before = (open(adm).read(), open(tok).read())
backup.save_secrets("sonarqube", d)
names = sorted(os.listdir(d))
out("sauvegarde : secrets de mise en service copiés", names == ["secret-admin-password", "secret-scan-token"])
out("sauvegarde : copies 0600", all(oct(os.stat(os.path.join(d, n)).st_mode & 0o777) == "0o600" for n in names))
out("sauvegarde : noms acceptés par le manifeste", all(backup.FILE_RE.match(n) for n in names))
out("sauvegarde : db-password jamais copié", not os.path.exists(os.path.join(d, "secret-db-password")))
for path in (adm, tok):
    with open(path, "w") as f:
        f.write("valeur-posterieure-a-la-sauvegarde\n")
backup.restore_secrets("sonarqube", d, set(names))
out("restauration : secrets de la sauvegarde remis", (open(adm).read(), open(tok).read()) == before)
out("restauration : 0600", oct(os.stat(adm).st_mode & 0o777) == "0o600")
open(os.path.join(d, "secret-db-password"), "w").write("x\n")
try:
    backup.restore_secrets("sonarqube", d, {"secret-db-password"})
    out("restauration : secret inattendu refusé", False)
except Fail as e:
    out("restauration : secret inattendu refusé", e.code == "E_BACKUP_INVALID")
backup.restore_secrets("sonarqube", d, {"db.dump"})
out("restauration d'une sauvegarde sans secrets : secrets en place gardés", open(adm).read() == before[0])
EOF
while IFS= read -r line; do
	case "$line" in "ok   "*) ok "${line#ok   }" ;; *) ko "${line#FAIL }" ;; esac
done < "$TMP/bk.out"
[[ -s "$TMP/bk.out" ]] || ko "sauvegarde : contrôles Python non exécutés"

python3 -I -B - "$PYLIB" > "$TMP/req.out" <<'EOF'
import sys
sys.path.insert(0, sys.argv[1])
from scanoria import schema
v = schema.load("requests", "reset-service-admin")
base = {"version": 1, "id": "0b0b0b0b-0b0b-4b0b-8b0b-0b0b0b0b0b0b", "type": "reset-service-admin",
        "created_at": "2026-11-24T10:00:00Z", "requested_by": {"user_id": 1, "username": "admin"}}
print("valide\t%s" % ("oui" if v.valid(dict(base, params={"id": "sonarqube"})) else "non"))
for label, params in (("id ../x", {"id": "../x"}), ("champ en trop", {"id": "sonarqube", "password": "x"}),
                      ("id absent", {}), ("id majuscule", {"id": "Sonar"})):
    print("%s\t%s" % (label, "non" if v.valid(dict(base, params=params)) else "oui"))
EOF
while IFS=$'\t' read -r label verdict; do expect "demande reset-service-admin : $label" "$verdict" "oui"; done < "$TMP/req.out"

echo
echo "b17-sonarqube : $PASS réussis, $FAIL échoués"
[[ $FAIL -eq 0 ]]
