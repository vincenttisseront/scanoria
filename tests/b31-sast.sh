#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Vincent Tisseront
#
# b31-sast — modules SAST, IaC et CI et jeux de règles G4 (0.7, chantier A),
# sans root ni conteneur. Cas :
#   - manifestes valides (schéma), réseau « none », image épinglée par
#     empreinte ou construite (image/Containerfile : FROM @sha256, USER 65534,
#     binaire vérifié par sha256sum, dépendances Python par empreinte) ;
#   - règles maison Opengrep (AGPL) : identifiants « scanoria- », métadonnées ;
#   - enveloppe sast_run.py : SARIF reproduit à l'identique (Bandit, Scorecard),
#     chemins hors de /src écartés, extraits et messages des règles de secrets
#     masqués, règles invalides → code 3, aucune règle → code 4, moteur appelé
#     depuis un répertoire de travail (identifiants non préfixés), politiques
#     Checkov découpées, seuil Scorecard ;
#   - jeux de règles côté runner (rulesets.py) : références hostiles (slug,
#     moteur, empreinte, lien, propriétaire, taille), [extend] gitleaks, KICS
#     dépliés, un seul jeu pour gitleaks, Semgrep sans jeu → « skipped » ;
#   - demande validate-ruleset : schéma (hostiles), module absent, contenu
#     absent ou altéré, règles refusées par le moteur, exemples comptés, et
#     montages (/src, /out, /rules en lecture seule, réseau none) ;
#   - registres : type et codes déclarés partout (helper, console, schémas).
# Dépendances : bash, python3 (≥ 3.10), python3-yaml, python3-jsonschema, jq.

# shellcheck disable=SC2016
set -euo pipefail
export PYTHONDONTWRITEBYTECODE=1

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
PYLIB="$ROOT/src/rootfs/usr/lib/scanoria/py"
SAST="$ROOT/src/rootfs/usr/lib/scanoria/scan-tools/sast"
HELPER="$ROOT/src/rootfs/usr/sbin/scanoria-helper"
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
MODS=(opengrep semgrep checkov kics bandit zizmor scorecard)

# --- 1. Manifestes et images ------------------------------------------------------------------
for id in "${MODS[@]}" gitleaks; do
	if python3 "$ROOT/tests/lib/modcheck.py" manifest "$ROOT/modules/$id/module.yaml" > "$TMP/mc.log" 2>&1; then ok "$id : manifeste valide (schéma)"
	else ko "$id : manifeste refusé"; sed 's/^/     /' "$TMP/mc.log"; fi
done
python3 -I - "$ROOT" "${MODS[@]}" > "$TMP/man.txt" <<-'EOF'
	import os, re, sys, yaml
	root = sys.argv[1]
	for mid in sys.argv[2:]:
	    m = yaml.safe_load(open(os.path.join(root, "modules", mid, "module.yaml"), encoding="utf-8"))
	    scan = m["scan"]
	    pending = m.get("image_pending") is True
	    img = m.get("image") or ""
	    good_img = (pending and not img) or bool(re.search(r"@sha256:[0-9a-f]{64}$", img))
	    cf = os.path.join(root, "modules", mid, "image", "Containerfile")
	    print(mid, scan.get("network"), "img-ok" if good_img else "img-KO", "built" if pending else "upstream",
	          "cf" if os.path.isfile(cf) else "nocf", "testbed" if os.path.isdir(os.path.join(root, "modules", mid, "testbed")) else "notestbed")
	EOF
while read -r id net img kind cf tb; do
	expect "$id : réseau none, image épinglée, banc d'essai" "$net $img $tb" "none img-ok testbed"
	if [[ "$kind" == built ]]; then expect "$id : image construite depuis image/Containerfile" "$cf" cf; fi
done < "$TMP/man.txt"
for cf in "$ROOT"/modules/{opengrep,zizmor,scorecard}/image/Containerfile; do
	id=$(basename "$(dirname "$(dirname "$cf")")")
	froms=$(grep -cE '^FROM ' "$cf"); pinned=$(grep -cE '^FROM [^ ]+@sha256:[0-9a-f]{64}( AS [a-z]+)?$' "$cf")
	expect "$id : chaque FROM épinglé par empreinte" "$pinned" "$froms"
	expect "$id : utilisateur final 65534" "$(grep -E '^USER ' "$cf" | tail -1)" "USER 65534:65534"
	grep -q 'ARG SOURCE_DATE_EPOCH' "$cf" && ok "$id : SOURCE_DATE_EPOCH" || ko "$id : SOURCE_DATE_EPOCH absent"
	grep -q 'org.opencontainers.image.licenses' "$cf" && ok "$id : étiquettes OCI" || ko "$id : étiquettes OCI absentes"
done
grep -q 'sha256sum -c' "$ROOT/modules/opengrep/image/Containerfile" && ok "opengrep : binaire vérifié par sha256sum" || ko "opengrep : binaire non vérifié"
grep -q 'cosign verify-blob' "$ROOT/modules/opengrep/image/verify.sh" && ok "opengrep : signature cosign vérifiée avant construction" || ko "opengrep : verify.sh sans cosign"
grep -qE '^zizmor==[0-9.]+ --hash=sha256:[0-9a-f]{64}$' "$ROOT/modules/zizmor/image/requirements.lock" && grep -q -- '--require-hashes' "$ROOT/modules/zizmor/image/Containerfile" \
	&& ok "zizmor : dépendance Python installée par empreinte" || ko "zizmor : requirements.lock sans empreinte"

# --- 2. Règles maison Opengrep ----------------------------------------------------------------
R=$(python3 -I - "$SAST/rules/opengrep/scanoria-base.yaml" <<-'EOF'
	import sys, yaml
	rules = yaml.safe_load(open(sys.argv[1], encoding="utf-8"))["rules"]
	bad = [r.get("id") for r in rules if not str(r.get("id", "")).startswith("scanoria-")
	       or not (r.get("metadata") or {}).get("cwe") or r.get("severity") not in ("ERROR", "WARNING", "INFO")]
	print(len(rules), len({r["id"] for r in rules}), len(bad))
	EOF
)
read -r n uniq bad <<< "$R"
expect "règles maison : identifiants uniques" "$uniq" "$n"
expect "règles maison : préfixe scanoria-, CWE et gravité" "$bad" 0
head -3 "$SAST/rules/opengrep/scanoria-base.yaml" | grep -q 'AGPL-3.0-or-later' && ok "règles maison : en-tête SPDX AGPL" || ko "règles maison : en-tête SPDX absent"

# --- 3. Enveloppe sast_run.py -----------------------------------------------------------------
for spec in "bandit:" "scorecard:--min-score=4"; do
	id=${spec%%:*}; opt=${spec#*:}
	# shellcheck disable=SC2086
	python3 -I "$ROOT/tests/lib/sast_convert.py" "$id" "$ROOT/modules/$id/tests/native.json" "$TMP/$id.sarif" $opt
	if cmp -s "$TMP/$id.sarif" "$ROOT/modules/$id/tests/converted.sarif"; then ok "$id : conversion identique à tests/converted.sarif"
	else ko "$id : conversion différente de tests/converted.sarif (relancer tests/lib/sast_convert.py)"; fi
done
grep -q 'valeur-de-test' "$ROOT/modules/bandit/tests/converted.sarif" && ko "bandit : valeur d'un mot de passe recopiée" || ok "bandit : valeur d'un mot de passe jamais recopiée (extrait ni message)"

# Fonctions de l'enveloppe, chemins /src, /out, /rules redirigés vers des dossiers de test.
cat > "$TMP/st.py" <<-'EOF'
	import importlib.util, json, os, sys
	spec = importlib.util.spec_from_file_location("sast_run", sys.argv[1])
	s = importlib.util.module_from_spec(spec)
	spec.loader.exec_module(s)
	t = sys.argv[2]
	s.SRC, s.OUT, s.RULES = t + "/src", t + "/out", t + "/rules"
	s.GREP_WORK, s.CHECKOV_WORK = t + "/work", t + "/ckwork"
	for d in ("src", "out", "rules"):
	    os.makedirs(os.path.join(t, d), exist_ok=True)
	def rc(fn, *a):
	    try:
	        fn(*a)
	        return 0
	    except s.ToolError as e:
	        return e.code
	exec(sys.argv[3])
	EOF
st() { rm -rf "$TMP/w"; mkdir -p "$TMP/w"; python3 -I "$TMP/st.py" "$SAST/sast_run.py" "$TMP/w" "$1"; }

R=$(st '
doc = {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "x", "rules": [
  {"id": "generic.secrets.api-key", "shortDescription": {"text": "API key in code"}},
  {"id": "python.eval", "properties": {"tags": ["CWE-95"]}},
  {"id": "custom.cred", "properties": {"tags": ["CWE-798: Use of Hard-coded Credentials"]}}]}},
  "originalUriBaseIds": {"SRC": {"uri": "file:///src/"}},
  "results": [
  {"ruleId": "generic.secrets.api-key", "message": {"text": "found key AKIA-valeur-piege"},
   "locations": [{"physicalLocation": {"artifactLocation": {"uri": "file:///src/app/conf.py", "uriBaseId": "SRC"}, "region": {"startLine": 3, "snippet": {"text": "KEY=valeur-piege"}}}}],
   "fixes": [{"description": {"text": "remove valeur-piege"}}]},
  {"ruleId": "python.eval", "message": {"text": "eval"},
   "locations": [{"physicalLocation": {"artifactLocation": {"uri": "/src/./app/x.py"}, "region": {"startLine": 1, "snippet": {"text": "a" * 5000}}}}]},
  {"ruleId": "custom.cred", "message": {"text": "password valeur-piege"},
   "locations": [{"physicalLocation": {"artifactLocation": {"uri": "../../etc/passwd"}, "region": {"startLine": 1, "snippet": {"text": "valeur-piege"}}}}]}]}]}
out = s.tidy_sarif(doc, "x")
r = out["runs"][0]["results"]
print(json.dumps([
  r[0]["locations"][0]["physicalLocation"]["artifactLocation"],
  r[1]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
  len(r[1]["locations"][0]["physicalLocation"]["region"]["snippet"]["text"]),
  "uri" in r[2]["locations"][0]["physicalLocation"]["artifactLocation"],
  "valeur-piege" in json.dumps(out), "fixes" in r[0], r[0]["message"]["text"], r[2]["message"]["text"],
  "originalUriBaseIds" in out["runs"][0], out["runs"][0]["properties"]["scanoria"]["wrapper"]]))
')
expect "SARIF : chemin relatif à /src, uriBaseId retiré" "$(jq -c '.[0]' <<< "$R")" '{"uri":"app/conf.py"}'
expect "SARIF : chemin « /src/./ » normalisé" "$(jq -r '.[1]' <<< "$R")" app/x.py
expect "SARIF : extrait borné à 400 caractères" "$(jq -r '.[2]' <<< "$R")" 400
expect "SARIF : chemin « .. » écarté" "$(jq -r '.[3]' <<< "$R")" false
expect "SARIF : valeur d'un secret jamais recopiée (extrait, message, correction)" "$(jq -r '.[4]' <<< "$R") $(jq -r '.[5]' <<< "$R")" "false false"
expect "SARIF : message d'une règle de secret remplacé par sa description" "$(jq -r '.[6]' <<< "$R")" "API key in code"
expect "SARIF : CWE-798 reconnu comme règle de secret" "$(jq -r '.[7]' <<< "$R")" "Possible hardcoded secret (custom.cred)"
expect "SARIF : propriétés de l'enveloppe" "$(jq -r '.[8]' <<< "$R") $(jq -r '.[9]' <<< "$R")" "false sast_run"

# Faux moteur : journalise ses arguments et son répertoire, écrit une sortie selon le cas.
cat > "$TMP/fakegrep" <<-'EOF'
	#!/usr/bin/env python3
	import json, os, sys
	a = sys.argv[1:]
	json.dump({"argv": a, "cwd": os.getcwd(), "files": sorted(os.listdir("."))}, open(os.environ["FAKE_LOG"], "w"))
	mode = os.environ.get("FAKE_MODE", "ok")
	if mode != "ok":
	    sys.exit(int(mode))
	out = a[a.index("--sarif-output") + 1]
	json.dump({"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "fake", "rules": [{"id": "interne-eval"}]}},
	           "results": [{"ruleId": "interne-eval", "message": {"text": "eval"}, "locations": [{"physicalLocation":
	           {"artifactLocation": {"uri": "/src/app.py"}, "region": {"startLine": 1}}}]}]}]}, open(out, "w"))
	sys.exit(1)
	EOF
chmod 0755 "$TMP/fakegrep"
export SCANORIA_OPENGREP_BIN="$TMP/fakegrep" SCANORIA_SEMGREP_BIN="$TMP/fakegrep" FAKE_LOG="$TMP/fake.json"
GREP_SETUP='
os.makedirs(s.RULES + "/interne"); open(s.RULES + "/interne/rules.yaml", "w").write("rules: []\n")
os.makedirs(s.RULES + "/Mauvais"); open(s.RULES + "/Mauvais/rules.yaml", "w").write("rules: []\n")
os.symlink("/etc", s.RULES + "/lien")
'
R=$(st "$GREP_SETUP"'
print(rc(s.run_grep, "opengrep", []), json.load(open(s.OUT + "/opengrep.sarif"))["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"])')
expect "opengrep : résultats (code 1) acceptés, chemin relatif" "$R" "0 app.py"
expect "opengrep : jeux montés et règles maison, depuis le répertoire de travail" \
	"$(jq -c '[.files, .cwd == ($w + "/work"), (.argv | index("--config") != null), (.argv | index("--metrics") == null), .argv[-1] == ($w + "/src")]' --arg w "$TMP/w" "$TMP/fake.json")" \
	'[["interne.yaml","scanoria-base.yaml"],true,true,true,true]'
R=$(st "$GREP_SETUP"'print(rc(s.run_grep, "opengrep", ["--builtin=false"]))')
expect "opengrep : option builtin_rules=false, règles maison retirées" "$R $(jq -c .files "$TMP/fake.json")" '0 ["interne.yaml"]'
R=$(st 'print(rc(s.run_grep, "opengrep", ["--builtin=false"]))')
expect "opengrep : aucune règle → code 4" "$R" 4
R=$(st "$GREP_SETUP"'print(rc(s.run_grep, "semgrep", []))')
expect "semgrep : jeux montés seulement, métriques coupées, règles OSS" "$R $(jq -c '[.files, (.argv | index("--metrics") != null), (.argv | index("--oss-only") != null)]' "$TMP/fake.json")" \
	'0 [["interne.yaml"],true,true]'
R=$(st 'print(rc(s.run_grep, "semgrep", []))')
expect "semgrep sans jeu (banc d'essai) : règles maison à défaut" "$R $(jq -c .files "$TMP/fake.json")" '0 ["scanoria-base.yaml"]'
for code in 2 7; do
	R=$(FAKE_MODE=$code st "$GREP_SETUP"'print(rc(s.run_grep, "opengrep", []))')
	expect "opengrep : sortie $code avec un jeu de règles → règles invalides (code 3)" "$R" 3
done
R=$(FAKE_MODE=2 st 'print(rc(s.run_grep, "opengrep", []))')
expect "opengrep : sortie 2 sur les seules règles maison → échec de l'outil (code 2)" "$R" 2
R=$(SCANORIA_OPENGREP_BIN=/nonexistent st "$GREP_SETUP"'print(rc(s.run_grep, "opengrep", []))')
expect "opengrep : binaire absent → échec de l'outil (code 2)" "$R" 2

if python3 -c 'import yaml' 2> /dev/null; then
	R=$(st '
os.makedirs(s.RULES + "/pol")
open(s.RULES + "/pol/policies.yaml", "w").write("- metadata: {id: CKV2_INT_1, name: a}\n  definition: {cond_type: attribute, resource_types: [aws_s3_bucket], attribute: acl, operator: not_equals, value: public-read}\n- metadata: {id: CKV2_INT_2, name: b}\n  definition: {and: []}\n")
dirs, ids = s.checkov_external_dirs(s.CHECKOV_WORK)
print(json.dumps([ids, sorted(os.listdir(dirs[0]))]))')
	expect "checkov : politiques découpées une par fichier" "$R" '[["CKV2_INT_1", "CKV2_INT_2"], ["policy-000.yaml", "policy-001.yaml"]]'
	for bad in '"!!python/object/apply:os.system [id]"' '"- metadata: {name: sans-id}\n  definition: {}"' '"a: [1"' '"- 42"'; do
		R=$(st "
os.makedirs(s.RULES + '/pol'); open(s.RULES + '/pol/policies.yaml', 'w').write($bad)
print(rc(s.checkov_external_dirs, s.CHECKOV_WORK))")
		expect "checkov : politique hostile ou invalide → règles invalides (code 3) : $bad" "$R" 3
	done
fi

R=$(st '
rep = json.load(open(sys.argv[4]))
for v in ("4", "3.2", "0"):
    d = s.convert_scorecard(rep, float(v))
    print(v, d["runs"][0]["results"][0]["ruleId"])
print(rc(s.parse_min_score, ["--min-score=11"]), rc(s.parse_min_score, ["--min-score=abc"]), s.parse_min_score([]))
print(rc(s.convert_scorecard, {"checks": "x"}, 4.0), rc(s.convert_bandit, {"results": None}))' "$ROOT/modules/scorecard/tests/native.json")
expect "scorecard : seuil 4, score 3.2 → résultat de seuil en tête" "$(sed -n 1p <<< "$R")" "4 scorecard/score-below-threshold"
expect "scorecard : seuil égal au score → pas de résultat de seuil" "$(sed -n 2p <<< "$R")" "3.2 scorecard/Token-Permissions"
expect "scorecard : seuil hors bornes refusé, défaut 4" "$(sed -n 4p <<< "$R")" "2 2 4.0"
expect "rapports natifs malformés refusés (code 2)" "$(sed -n 5p <<< "$R")" "2 2"

# --- 4. Jeux de règles côté runner (rulesets.py) ------------------------------------------------
export SCANORIA_TEST_ROOT="$TMP/root"
mkdir -p "$TMP/root"
RS=$(python3 -I - "$PYLIB" <<-'EOF'
	import hashlib, json, os, sys
	sys.path.insert(0, sys.argv[1])
	from scanoria import rulesets as rs
	from scanoria.common import Fail
	base = os.environ["SCANORIA_TEST_ROOT"] + "/scans"
	store = rs.store_dir(base)
	os.makedirs(store, exist_ok=True)
	def put(data):
	    sha = hashlib.sha256(data).hexdigest()
	    p = os.path.join(store, sha)
	    if not os.path.exists(p):
	        open(p, "wb").write(data)
	    return sha
	def man(engine, **kw):
	    spec = dict({"engine": engine, "mount": "/rules"}, **kw)
	    return {"id": engine, "scan": {"rulesets": spec}}
	def ref(slug, engine, data, version=1):
	    return {"slug": slug, "engine": engine, "version": version, "sha256": put(data)}
	def code(fn, *a):
	    try:
	        fn(*a)
	        return "OK"
	    except Fail as f:
	        return f.code
	og = b"rules:\n  - id: interne\n"
	out = {}
	out["ok"] = code(rs.load, {"rulesets": [ref("interne", "opengrep", og)]}, man("opengrep"), base)
	out["no-spec"] = code(rs.load, {"rulesets": [ref("interne", "opengrep", og)]}, {"id": "bandit", "scan": {}}, base)
	for i, bad in enumerate([{"slug": "../x"}, {"slug": "scanoria-base"}, {"slug": "Maj"}, {"engine": "semgrep"},
	                         {"sha256": "z" * 64}, {"version": 0}, {"version": True}]):
	    r = dict(ref("interne", "opengrep", og), **bad)
	    out["hostile-%d" % i] = code(rs.load, {"rulesets": [r]}, man("opengrep"), base)
	out["dup"] = code(rs.load, {"rulesets": [ref("a", "opengrep", og), ref("a", "opengrep", og)]}, man("opengrep"), base)
	out["missing"] = code(rs.load, {"rulesets": [{"slug": "a", "engine": "opengrep", "version": 1, "sha256": "e" * 64}]}, man("opengrep"), base)
	# Contenu altéré après coup : l'empreinte ne correspond plus.
	sha = put(b"rules: []\n")
	open(os.path.join(store, sha), "wb").write(b"rules: [x]\n")
	out["tampered"] = code(rs.load, {"rulesets": [{"slug": "a", "engine": "opengrep", "version": 1, "sha256": sha}]}, man("opengrep"), base)
	# Lien symbolique et lien physique dans la file.
	target = os.path.join(base, "cible")
	open(target, "wb").write(og)
	lsha = hashlib.sha256(og + b"#l\n").hexdigest()
	os.symlink(target, os.path.join(store, lsha))
	out["symlink"] = code(rs.load, {"rulesets": [{"slug": "a", "engine": "opengrep", "version": 1, "sha256": lsha}]}, man("opengrep"), base)
	hsha = put(og + b"#h\n")
	os.link(os.path.join(store, hsha), os.path.join(base, "second-lien"))
	out["hardlink"] = code(rs.load, {"rulesets": [{"slug": "a", "engine": "opengrep", "version": 1, "sha256": hsha}]}, man("opengrep"), base)
	big = b"rules:\n" + b"#" * (1 << 20)
	out["big"] = code(rs.load, {"rulesets": [ref("a", "opengrep", big)]}, man("opengrep"), base)
	out["nul"] = code(rs.load, {"rulesets": [ref("a", "opengrep", b"rules: []\n\x00")]}, man("opengrep"), base)
	out["gl-extend"] = code(rs.load, {"rulesets": [ref("g", "gitleaks", b'[extend]\npath = "/etc/gitleaks.toml"\n')]}, man("gitleaks", env="GITLEAKS_CONFIG"), base)
	gl = b'[extend]\nuseDefault = true\n'
	out["gl-two"] = code(rs.load, {"rulesets": [ref("g1", "gitleaks", gl), ref("g2", "gitleaks", gl + b"#2\n")]}, man("gitleaks", env="GITLEAKS_CONFIG"), base)
	loaded = rs.load({"rulesets": [ref("g1", "gitleaks", gl)]}, man("gitleaks", env="GITLEAKS_CONFIG"), base)
	out["gl-env"] = rs.env_of(man("gitleaks", env="GITLEAKS_CONFIG"), loaded)
	q = {"id": "interne-1", "metadata": {"id": "interne-1", "severity": "HIGH"}, "query": "package Cx\n"}
	for name, doc in (("kics-badid", {"queries": [dict(q, id="../x")]}), ("kics-extra", {"queries": [q], "x": 1}),
	                  ("kics-empty", {"queries": []}), ("kics-many", {"queries": [dict(q, id="q%d" % i) for i in range(501)]}),
	                  ("kics-dup", {"queries": [q, q]})):
	    out[name] = code(rs.load, {"rulesets": [ref("k", "kics", json.dumps(doc).encode())]}, man("kics"), base)
	out["kics-notjson"] = code(rs.load, {"rulesets": [ref("k", "kics", b"{")]}, man("kics"), base)
	k = rs.load({"rulesets": [ref("k", "kics", json.dumps({"queries": [q]}).encode())]}, man("kics"), base)
	dest = os.environ["SCANORIA_TEST_ROOT"] + "/staged"
	rs.stage(k + rs.load({"rulesets": [ref("o", "opengrep", og)]}, man("opengrep"), base), dest)
	files = []
	for r_, ds, fs in os.walk(dest):
	    for f in fs:
	        p = os.path.join(r_, f)
	        files.append("%s:%o" % (os.path.relpath(p, dest), os.stat(p).st_mode & 0o777))
	out["staged"] = sorted(files)
	out["digest"] = rs.digest_of(k)[0]["slug"]
	print(json.dumps(out))
	EOF
)
expect "jeu de règles valide chargé" "$(jq -r .ok <<< "$RS")" OK
expect "jeu pour un module qui n'en lit pas : refusé" "$(jq -r '."no-spec"' <<< "$RS")" E_RULESET_INVALID
expect "références hostiles (slug .., réservé, majuscules, moteur, empreinte, version)" \
	"$(jq -r '[."hostile-0", ."hostile-1", ."hostile-2", ."hostile-3", ."hostile-4", ."hostile-5", ."hostile-6"] | unique | join(",")' <<< "$RS")" E_RULESET_INVALID
expect "slug en double refusé" "$(jq -r .dup <<< "$RS")" E_RULESET_INVALID
expect "contenu absent de la file" "$(jq -r .missing <<< "$RS")" E_RULESET_MISSING
expect "contenu altéré (empreinte) refusé" "$(jq -r .tampered <<< "$RS")" E_RULESET_INVALID
expect "lien symbolique et lien physique dans la file refusés" "$(jq -r '.symlink + " " + .hardlink' <<< "$RS")" "E_RULESET_INVALID E_RULESET_INVALID"
expect "contenu de plus d'1 Mio ou avec octet nul refusé" "$(jq -r '.big + " " + .nul' <<< "$RS")" "E_RULESET_INVALID E_RULESET_INVALID"
expect "gitleaks : [extend] vers un fichier refusé" "$(jq -r '."gl-extend"' <<< "$RS")" E_RULESET_INVALID
expect "gitleaks : un seul jeu (GITLEAKS_CONFIG)" "$(jq -r '."gl-two"' <<< "$RS") $(jq -c '."gl-env"' <<< "$RS")" \
	'E_RULESET_INVALID {"GITLEAKS_CONFIG":"/rules/g1/gitleaks.toml"}'
expect "KICS : identifiant .., clé inconnue, liste vide ou trop longue, doublon, JSON invalide" \
	"$(jq -r '[."kics-badid", ."kics-extra", ."kics-empty", ."kics-many", ."kics-dup", ."kics-notjson"] | unique | join(",")' <<< "$RS")" E_RULESET_INVALID
expect "montage : KICS dépliés en requêtes, fichiers 0644" "$(jq -c .staged <<< "$RS")" \
	'["k/interne-1/metadata.json:644","k/interne-1/query.rego:644","o/rules.yaml:644"]'

R=$(python3 -I - "$PYLIB" <<-'EOF'
	import json, sys
	sys.path.insert(0, sys.argv[1])
	from scanoria import runner
	m = {"id": "semgrep", "version": "1.0.0", "scan": {"rulesets": {"engine": "semgrep", "mount": "/rules", "required": True}}}
	skip, rsets = runner.plan_rulesets({"id": "semgrep", "version": "1.0.0"}, m, "semgrep", "1.0.0")
	print(json.dumps([skip["status"], skip["error"]["code"], skip["error"]["class"], rsets]))
	m2 = {"id": "opengrep", "version": "1.0.0", "scan": {"rulesets": {"engine": "opengrep", "mount": "/rules"}}}
	skip, rsets = runner.plan_rulesets({"id": "opengrep", "rulesets": [{"slug": "a", "engine": "opengrep", "version": 1, "sha256": "e" * 64}]}, m2, "opengrep", "1.0.0")
	print(json.dumps([skip["status"], skip["error"]["code"], skip["error"]["class"]]))
	EOF
)
expect "runner : Semgrep sans jeu → ignoré (skipped, input)" "$(sed -n 1p <<< "$R")" '["skipped", "E_RULESET_NONE", "input", null]'
expect "runner : jeu absent de la file → erreur de classe input, jamais un résultat vide" "$(sed -n 2p <<< "$R")" '["error", "E_RULESET_MISSING", "input"]'

# --- 5. Demande validate-ruleset (helper, podman bouchon) ---------------------------------------
T="$TMP/hroot"
STUBS="$TMP/stubs"
CALLS="$TMP/calls.log"
mkdir -p "$T"/var/lib/scanoria/requests/{tmp,incoming,work,done,failed} "$T/var/lib/scanoria/modules" "$T/var/lib/scanoria/scans/jobs/rulesets" \
	"$T/var/lib/scanoria/console" "$T/run/scanoria" "$T/etc/scanoria" "$T/opt/scanoria/current" "$STUBS"
echo 0.7.0 > "$T/opt/scanoria/current/VERSION"
: > "$CALLS"
export SCANORIA_TEST_ROOT="$T" SCANORIA_TEST_BIN="$STUBS"
# podman : journalise ; « run » écrit dans /out un SARIF avec un résultat par fichier
# de /src qui contient « eval(», et sort en 3 si les règles contiennent « INVALIDE ».
cat > "$STUBS/podman" <<-'EOF'
	#!/usr/bin/env python3
	import json, os, sys
	a = sys.argv[1:]
	open(os.environ["CALLS"], "a").write(json.dumps(["podman"] + a) + "\n")
	if not a or a[0] != "run":
	    sys.exit(0)
	vols = {}
	for i, x in enumerate(a):
	    if x == "--volume":
	        host, target, mode = a[i + 1].rsplit(":", 2)
	        vols[target] = host
	rules = "".join(open(os.path.join(r, f)).read() for r, _, fs in os.walk(vols["/rules"]) for f in fs)
	if "INVALIDE" in rules:
	    sys.stderr.write("invalid rule at line 2\n")
	    sys.exit(3)
	res = [{"ruleId": "candidate", "message": {"text": "x"}, "locations": [{"physicalLocation": {"artifactLocation": {"uri": "/src/" + f}}}]}
	       for f in sorted(os.listdir(vols["/src"])) if "eval(" in open(os.path.join(vols["/src"], f)).read()]
	json.dump({"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "fake"}}, "results": res}]},
	          open(os.path.join(vols["/out"], os.environ.get("FAKE_OUT", "opengrep.sarif")), "w"))
	EOF
chmod 0755 "$STUBS/podman"
printf '#!/bin/sh\nexit 0\n' > "$STUBS/systemctl"
chmod 0755 "$STUBS/systemctl"
export CALLS
hx() {
	R=$("$HELPER" exec --origin cli --type validate-ruleset --params "$1" 2> "$TMP/helper.err") || true
	[[ -n "$R" ]] || { R='{"code":"NO_OUTPUT"}'; sed 's/^/     /' "$TMP/helper.err"; }
}
SHA=$(printf 'e%.0s' {1..64})
for bad in '{}' '{"engine": "bandit", "sha256": "'"$SHA"'"}' '{"engine": "opengrep", "sha256": "E'"${SHA:1}"'"}' \
	'{"engine": "opengrep", "sha256": "'"$SHA"'", "samples": [{"name": "../x", "content": ""}]}' \
	'{"engine": "opengrep", "sha256": "'"$SHA"'", "samples": [{"name": "a.py", "content": "", "path": "/etc"}]}' \
	'{"engine": "opengrep", "sha256": "'"$SHA"'", "extra": 1}'; do
	hx "$bad"
	expect "validate-ruleset hostile refusée : $bad" "$(jq -r .code <<< "$R")" E_SCHEMA
done
hx "{\"engine\": \"opengrep\", \"sha256\": \"$SHA\", \"samples\": $(python3 -c 'import json; print(json.dumps([{"name": "s%d.py" % i, "content": ""} for i in range(11)]))')}"
expect "validate-ruleset : plus de 10 exemples refusés" "$(jq -r .code <<< "$R")" E_SCHEMA
hx "{\"engine\": \"opengrep\", \"sha256\": \"$SHA\", \"samples\": [{\"name\": \"a.py\", \"content\": \"$(printf 'x%.0s' {1..8200})\"}]}"
expect "validate-ruleset : exemple de plus de 8 Kio refusé" "$(jq -r .code <<< "$R")" E_SCHEMA
hx "{\"engine\": \"opengrep\", \"sha256\": \"$SHA\"}"
expect "validate-ruleset : module du moteur non installé" "$(jq -r .code <<< "$R")" E_RULESET_ENGINE_MISSING

python3 -I - "$PYLIB" "$ROOT/modules/opengrep/module.yaml" <<-'EOF'
	import sys, yaml
	sys.path.insert(0, sys.argv[1])
	from scanoria import common, modules
	m = yaml.safe_load(open(sys.argv[2], encoding="utf-8"))
	m.pop("image_pending", None)
	m["image"] = "ghcr.io/exemple/opengrep@sha256:" + "a" * 64
	reg = modules.load_registry()
	reg["modules"]["opengrep"] = {"manifest": m, "status": "healthy", "enabled": True, "installed_at": "2026-11-25T00:00:00Z",
	                              "options": {}, "accepted": "none"}
	common.write_json(modules.REGISTRY, reg, 0o600, group_scanoria=False)
	EOF
STORE="$T/var/lib/scanoria/scans/jobs/rulesets"
put() { local sha; sha=$(printf '%s' "$1" | sha256sum | cut -d' ' -f1); printf '%s' "$1" > "$STORE/$sha"; chmod 0600 "$STORE/$sha"; echo "$sha"; }
hx "{\"engine\": \"opengrep\", \"sha256\": \"$SHA\"}"
expect "validate-ruleset : contenu absent → refus motivé, sans lancer le moteur" "$(jq -c '[.code, .output.ok, (.output.errors[0] | test("missing"))]' <<< "$R") $(grep -c '"run"' "$CALLS" || true)" '["OK",false,true] 0'
GOOD=$(put $'rules:\n  - id: candidate\n    pattern: eval(...)\n')
hx "{\"engine\": \"opengrep\", \"sha256\": \"$GOOD\", \"samples\": [{\"name\": \"positif.py\", \"content\": \"eval(x)\\n\"}, {\"name\": \"negatif.py\", \"content\": \"print(x)\\n\"}]}"
expect "validate-ruleset : règles acceptées, résultats par exemple" "$(jq -c '[.code, .output.ok, .output.module, .output.samples]' <<< "$R")" \
	'["OK",true,"opengrep",[{"name":"positif.py","matches":1},{"name":"negatif.py","matches":0}]]'
RUN=$(grep '"run"' "$CALLS" | tail -1)
expect "validate-ruleset : conteneur sans réseau, lecture seule, /rules et /src en lecture seule" \
	"$(jq -r '[(index("--network=none") != null), (index("--read-only") != null), (index("--cap-drop=ALL") != null),
	  ([.[] | select(test(":/rules:ro$"))] | length), ([.[] | select(test(":/src:ro$"))] | length), (index("--builtin=false") != null)] | map(tostring) | join(" ")' <<< "$RUN")" \
	"true true true 1 1 true"
BAD=$(put $'rules:\n  - id: INVALIDE\n')
hx "{\"engine\": \"opengrep\", \"sha256\": \"$BAD\"}"
expect "validate-ruleset : règles refusées par le moteur (code 3)" "$(jq -c '[.code, .output.ok, (.output.errors[0] | test("invalid rule"))]' <<< "$R")" '["OK",false,true]'
NOKEY=$(put $'foo: 1\n')
hx "{\"engine\": \"opengrep\", \"sha256\": \"$NOKEY\"}"
expect "validate-ruleset : contrôle statique refait par le helper" "$(jq -c '[.code, .output.ok]' <<< "$R")" '["OK",false]'
FAKE_OUT=autre.sarif hx "{\"engine\": \"opengrep\", \"sha256\": \"$GOOD\"}"
expect "validate-ruleset : sortie absente → refus motivé (jamais un succès vide)" "$(jq -c '[.code, .output.ok]' <<< "$R")" '["OK",false]'
LEFT=$(find "$T/var/lib/scanoria/modules/work" -mindepth 1 -maxdepth 1 2> /dev/null | wc -l)
expect "validate-ruleset : répertoire de travail supprimé" "$LEFT" 0

# --- 6. Registres -------------------------------------------------------------------------------
R=$(python3 -I - "$PYLIB" "$ROOT" <<-'EOF'
	import json, os, re, sys
	sys.path.insert(0, sys.argv[1])
	from scanoria import common, helper
	root = sys.argv[2]
	codes = ["E_RULESET_INVALID", "E_RULESET_MISSING", "E_RULESET_NONE", "E_RULESET_ENGINE_MISSING"]
	shared = open(os.path.join(root, "webui/shared/schemas.ts"), encoding="utf-8").read()
	result = json.load(open(os.path.join(root, "src/rootfs/usr/share/scanoria/requests/result.schema.json")))
	fr = open(os.path.join(root, "webui/i18n/locales/fr.ts"), encoding="utf-8").read()
	print("validate-ruleset" in common.REQUEST_TYPES, "validate-ruleset" in helper.ACTIONS, "validate-ruleset" in helper.TIMEOUTS,
	      "'validate-ruleset'" in shared, os.path.isfile(os.path.join(root, "src/rootfs/usr/share/scanoria/requests/validate-ruleset.schema.json")),
	      all(c in common.ALL_CODES for c in codes), all(("'%s'" % c) in shared for c in codes),
	      all(c in json.dumps(result) for c in codes), all(("%s:" % c) in fr for c in codes))
	EOF
)
expect "registres : type validate-ruleset et codes E_RULESET_* déclarés partout" "$R" "True True True True True True True True True"

echo
echo "b31-sast : $PASS réussis, $FAIL échoués"
[[ "$FAIL" -eq 0 ]]
