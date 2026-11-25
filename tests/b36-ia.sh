#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Vincent Tisseront
#
# b36-ia — modules d'analyse du code IA de la 0.7 (chantier F) sans root ni
# conteneur : agentic-radar (K7), mcp-scanner (K5), skill-scanner (K6).
# Les convertisseurs de l'appliance (scan.tool, src/rootfs/…/scan-tools) sont
# rejoués sur des sorties enregistrées des vrais outils, sans les outils :
#   - manifestes valides, réseau « none », outil de l'appliance, applies_to,
#     image en attente de publication ou épinglée par empreinte ;
#   - Containerfile conformes (base épinglée, dépendances à empreintes,
#     utilisateur 65534, étiquettes) ;
#   - agentic-radar : graphe enregistré → SARIF identique à l'enregistrement,
#     inventaire borné (taille des invites seulement, jamais leur texte) ;
#   - skill-scanner : fusion des SARIF par skill → chemins relatifs au dépôt,
#     aucun chemin absolu du conteneur, rien hors du dépôt ;
#   - mcp-scanner : découverte des outils, invites et serveurs MCP du banc
#     d'essai, conversion avec un analyseur factice, variables d'API retirées ;
#   - entrées hostiles : liens symboliques vers l'extérieur, fichiers énormes,
#     chemins « .. » ou absolus dans un SARIF amont, JSON invalide ;
#   - aucun appel réseau prévu (VirusTotal, API Cisco, OSV.dev, OpenAI) ;
#   - attentes du banc d'essai (testbed.expect) tenues par les enregistrements.
# La vraie exécution dans les images confinées est dans tests/b36-live.sh.
# Dépendances : bash, python3, python3-yaml, python3-jsonschema, jq.

set -euo pipefail
export PYTHONDONTWRITEBYTECODE=1

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
TOOLS="$ROOT/src/rootfs/usr/lib/scanoria/scan-tools"
MODCHECK="$ROOT/tests/lib/modcheck.py"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
for t in python3 jq; do command -v "$t" > /dev/null || { echo "outil manquant : $t" >&2; exit 2; }; done

PASS=0
FAIL=0
ok() { PASS=$((PASS + 1)); printf 'ok   %s\n' "$1"; }
ko() { FAIL=$((FAIL + 1)); printf 'FAIL %s\n' "$1"; }
expect() {
	if [[ "$2" == "$3" ]]; then ok "$1"; else ko "$1 (obtenu « $2 », attendu « $3 »)"; fi
}
yq() { python3 -c 'import json, sys, yaml; print(json.dumps(yaml.safe_load(open(sys.argv[1], encoding="utf-8"))))' "$1"; }
# Fonction d'un convertisseur chargé par son chemin (python3 -I, comme dans le conteneur).
pycall() { # outil code-python arguments…
	local tool=$1 code=$2
	shift 2
	(cd "$TMP" && python3 -I -c 'import importlib.util, json, sys
spec = importlib.util.spec_from_file_location("conv", sys.argv[1])
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
args = sys.argv[2:]
'"$code" "$tool" "$@")
}

MODS=(agentic-radar mcp-scanner skill-scanner vulnhuntr mcp-scanner-llm skill-scanner-llm)
RADAR="$TOOLS/agentic-radar/radar_sarif.py"
MCP="$TOOLS/mcp-scanner/mcp_sarif.py"
SKILL="$TOOLS/skill-scanner/skill_sarif.py"

# --- 1. Manifestes et images -------------------------------------------------------------------
for m in "${MODS[@]}"; do
	dir="$ROOT/modules/$m"
	if python3 "$MODCHECK" manifest "$dir/module.yaml" > "$TMP/mc.log" 2>&1; then ok "$m : manifeste valide"
	else ko "$m : manifeste refusé"; sed 's/^/     /' "$TMP/mc.log"; fi
	if python3 "$MODCHECK" containerfile "$dir/image/Containerfile" "$m" > "$TMP/cf.log" 2>&1; then ok "$m : Containerfile conforme"
	else ko "$m : Containerfile refusé"; sed 's/^/     /' "$TMP/cf.log"; fi
	yq "$dir/module.yaml" > "$TMP/$m.json"
	tool=${m%-llm}
	if [[ "$m" == "$tool" && "$m" != vulnhuntr ]]; then
		expect "$m : aucun réseau" "$(jq -r .scan.network "$TMP/$m.json")" none
	else
		# Modules par le relais IA : conteneur toujours en --network=none, pont vers le seul relais.
		expect "$m : relais IA seulement" "$(jq -r .scan.network "$TMP/$m.json")" ai-relay
	fi
	expect "$m : outil de l'appliance" "$(jq -r .scan.tool "$TMP/$m.json")" "$tool"
	expect "$m : lancé selon le contenu (applies_to)" "$(jq -r '.scan.applies_to.paths | length > 0' "$TMP/$m.json")" true
	img=$(jq -r '.image // ""' "$TMP/$m.json")
	if [[ "$(jq -r '.image_pending // false' "$TMP/$m.json")" == true && -z "$img" ]] || [[ "$img" == *@sha256:* ]]; then
		ok "$m : image en attente ou épinglée par empreinte"
	else ko "$m : image non épinglée ($img)"; fi
	if [[ "$m" == vulnhuntr ]]; then lic=AGPL-3.0-only; else lic=Apache-2.0; fi
	expect "$m : licence $lic vérifiée" "$(jq -r .license.spdx "$TMP/$m.json")" "$lic"
	n=$(grep -c ' --hash=sha256:' "$dir/image/requirements.lock" || true)
	if [[ "$n" -gt 10 ]]; then ok "$m : dépendances à empreintes ($n)"; else ko "$m : requirements.lock sans empreintes"; fi
	# Aucun service tiers en ligne : ni clé, ni option qui l'appellerait.
	if grep -nE 'VIRUSTOTAL_API_KEY=|MCP_SCANNER_API_KEY=|"--use-(osv|virustotal|aidefense)"|api\.openai\.com' \
		"$dir/module.yaml" "$TOOLS/$tool/"*.py > "$TMP/net.log"; then
		ko "$m : appel d'un service en ligne prévu"; sed 's/^/     /' "$TMP/net.log"
	else ok "$m : aucun service en ligne prévu"; fi
done

# Mode hors ligne de skill-scanner : ni juge LLM ni OSV.dev (le juge est le module skill-scanner-llm).
expect "skill-scanner : mode hors ligne sans juge LLM" \
	"$(grep -E '^OFFLINE_FLAGS' "$TOOLS/skill-scanner/skill_sarif.py" | grep -cE 'use-(llm|osv)')" 0

# --- 2. agentic-radar (K7) ---------------------------------------------------------------------
RAD="$ROOT/modules/agentic-radar"
(cd "$RAD/testbed" && python3 -I "$RADAR" --convert < "$RAD/tests/recorded-graphs.json" > "$TMP/radar.sarif")
expect "radar : SARIF identique à l'enregistrement" \
	"$(jq -S . "$TMP/radar.sarif" | sha256sum | cut -c1-64)" "$(jq -S . "$RAD/tests/recorded.sarif" | sha256sum | cut -c1-64)"
if python3 "$MODCHECK" expect "$RAD/module.yaml" "$TMP/radar.sarif" > "$TMP/exp.log"; then ok "radar : attentes du banc d'essai"
else ko "radar : attentes du banc d'essai"; sed 's/^/     /' "$TMP/exp.log"; fi
inv='.runs[0].properties["scanoria/agent-inventory"]'
expect "radar : inventaire version 1" "$(jq -r "$inv.version" "$TMP/radar.sarif")" 1
expect "radar : frameworks" "$(jq -c "$inv.frameworks" "$TMP/radar.sarif")" '["langgraph"]'
expect "radar : outil shell relevé" "$(jq -r "[$inv.workflows[].tools[].name] | index(\"Shell (bash)\") != null" "$TMP/radar.sarif")" true
expect "radar : outil maison relevé" "$(jq -r "[$inv.workflows[].tools[].name] | index(\"lookup\") != null" "$TMP/radar.sarif")" true
expect "radar : emplacements relatifs au dépôt seulement" \
	"$(jq -r '[.runs[0].results[].locations[]?.physicalLocation.artifactLocation.uri | select(startswith("/") or contains(".."))] | length' "$TMP/radar.sarif")" 0
# Invite système d'un agent : seule sa longueur sort (jamais son texte).
python3 - "$RAD/tests/recorded-graphs.json" "$TMP/graphs-prompt.json" <<'EOF'
import json, sys
g = json.load(open(sys.argv[1]))
def walk(o):
    if isinstance(o, dict):
        for k in list(o):
            if k == "system_prompt":
                o[k] = "CANARY-PROMPT-7171 " * 20
            walk(o[k])
    elif isinstance(o, list):
        for v in o:
            walk(v)
walk(g)
# Agent ajouté s'il n'y en a aucun : la consigne doit quand même disparaître.
for w in (g if isinstance(g, list) else [g]):
    if isinstance(w, dict):
        w.setdefault("agents", []).append({"name": "a", "llm": "m", "system_prompt": "CANARY-PROMPT-7171", "is_guardrail": False})
json.dump(g, open(sys.argv[2], "w"))
EOF
(cd "$RAD/testbed" && python3 -I "$RADAR" --convert < "$TMP/graphs-prompt.json" > "$TMP/radar-p.sarif")
if grep -q CANARY-PROMPT "$TMP/radar-p.sarif"; then ko "radar : texte d'invite système sorti"; else ok "radar : invites système jamais recopiées"; fi
# Lien symbolique vers l'extérieur et fichier énorme : jamais lus pour localiser un outil.
mkdir -p "$TMP/hostile/src"
printf 'ShellTool = 1\n' > "$TMP/outside.py"
ln -s "$TMP/outside.py" "$TMP/hostile/src/lien.py"
python3 -c 'import sys; open(sys.argv[1], "w").write("ShellTool\n" + "x" * 6_000_000)' "$TMP/hostile/src/gros.py"
expect "radar : liens et fichiers énormes jamais lus" "$(pycall "$RADAR" 'print(json.dumps(m.locate(args[0], ["ShellTool"])))' "$TMP/hostile/src")" '{}'
printf 'x = 1\nShellTool = 2\n' > "$TMP/hostile/src/vrai.py"
expect "radar : localisation dans un fichier ordinaire" \
	"$(pycall "$RADAR" 'print(json.dumps(m.locate(args[0], ["ShellTool"])["ShellTool"][:2]))' "$TMP/hostile/src")" '["vrai.py", 2]'
rc=0; python3 -I "$RADAR" > /dev/null 2>&1 || rc=$?
expect "radar : arguments manquants refusés" "$rc" 2
printf '{' > "$TMP/bad.json"
rc=0; (cd "$RAD/testbed" && python3 -I "$RADAR" --convert < "$TMP/bad.json" > "$TMP/x.sarif" 2> /dev/null) || rc=$?
if [[ "$rc" -ne 0 && ! -s "$TMP/x.sarif" ]]; then ok "radar : graphe invalide refusé, aucune sortie"; else ko "radar : graphe invalide accepté"; fi

# --- 3. skill-scanner (K6) ---------------------------------------------------------------------
SKM="$ROOT/modules/skill-scanner"
jq -n --slurpfile r "$SKM/tests/upstream-rapport.sarif" '{"skills/rapport": $r[0]}' | python3 -I "$SKILL" --merge > "$TMP/skill.sarif"
expect "skill : fusion identique à l'enregistrement" \
	"$(jq -S . "$TMP/skill.sarif" | sha256sum | cut -c1-64)" "$(jq -S . "$SKM/tests/recorded.sarif" | sha256sum | cut -c1-64)"
if python3 "$MODCHECK" expect "$SKM/module.yaml" "$TMP/skill.sarif" > "$TMP/exp.log"; then ok "skill : attentes du banc d'essai"
else ko "skill : attentes du banc d'essai"; sed 's/^/     /' "$TMP/exp.log"; fi
expect "skill : chemins relatifs au dépôt" \
	"$(jq -r '[.runs[0].results[].locations[]?.physicalLocation.artifactLocation.uri | select(startswith("/") or startswith("file:") or contains(".."))] | length' "$TMP/skill.sarif")" 0
if expect "skill : emplacements des constats" \
	"$(jq -r '[.runs[0].results[].locations[]?.physicalLocation.artifactLocation.uri] | unique | join(" ")' "$TMP/skill.sarif")" \
	"skills/rapport/SKILL.md skills/rapport/scripts/build.py"
grep -q '"/src/' "$TMP/skill.sarif"; then ko "skill : chemin absolu du conteneur"; else ok "skill : aucun chemin absolu du conteneur"; fi
expect "skill : skills analysées" "$(jq -c '.runs[0].properties["scanoria/skills"]' "$TMP/skill.sarif")" '{"analysed":1,"failed":[]}'
# SARIF amont hostile : chemins hors du dépôt écartés, document invalide compté en échec.
jq '.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri = "../../../etc/passwd"
  | .runs[0].results[1].locations[0].physicalLocation.artifactLocation.uri = "file:///etc/shadow"
  | .runs[0].results[2].locations[0].physicalLocation.artifactLocation.uri = "/root/.ssh/id_ed25519"' \
	"$SKM/tests/upstream-rapport.sarif" > "$TMP/hostile.sarif"
jq -n --slurpfile r "$TMP/hostile.sarif" '{"skills/rapport": $r[0], "skills/autre": "{"}' | python3 -I "$SKILL" --merge > "$TMP/skill-h.sarif" 2> /dev/null || true
if grep -qE 'etc/passwd|etc/shadow|id_ed25519' "$TMP/skill-h.sarif"; then ko "skill : chemin hors du dépôt recopié"; else ok "skill : chemins hors du dépôt écartés"; fi
expect "skill : SARIF amont invalide compté en échec" "$(jq -c '.runs[0].properties["scanoria/skills"].failed' "$TMP/skill-h.sarif")" '["skills/autre"]'
# Découverte : SKILL.md en lien symbolique ignoré, dossiers exclus.
mkdir -p "$TMP/sk/a" "$TMP/sk/b" "$TMP/sk/node_modules/c"
printf '# a\n' > "$TMP/sk/a/SKILL.md"
ln -s "$TMP/outside.py" "$TMP/sk/b/SKILL.md"
printf '# c\n' > "$TMP/sk/node_modules/c/SKILL.md"
expect "skill : découverte (liens et node_modules ignorés)" \
	"$(pycall "$SKILL" 'print(json.dumps(m.skills(args[0])))' "$TMP/sk")" '["a"]'
expect "skill : banc d'essai découvert" "$(pycall "$SKILL" 'print(json.dumps(m.skills(args[0])))' "$SKM/testbed")" '["skills/rapport"]'

# --- 4. mcp-scanner (K5) -----------------------------------------------------------------------
MCM="$ROOT/modules/mcp-scanner"
expect "mcp : éléments découverts dans le banc d'essai" \
	"$(pycall "$MCP" 'print(" ".join(sorted(i["kind"] + ":" + i["name"] for i in m.discover(args[0]))))' "$MCM/testbed")" \
	"server:fichiers server:notes tool:add_numbers tool:format_text tool:weather"
# Configuration de serveur : seuls les noms des variables d'environnement sortent, jamais leurs valeurs.
mkdir -p "$TMP/mc"
python3 - "$TMP/mc/.mcp.json" <<'EOF'
import json, secrets, sys
tok = "tok_" + secrets.token_hex(16)
json.dump({"mcpServers": {"interne": {"command": "node", "args": ["srv.js"], "env": {"API_TOKEN": tok}}}}, open(sys.argv[1], "w"))
open(sys.argv[1] + ".tok", "w").write(tok)
EOF
pycall "$MCP" 'print(json.dumps(m.discover(args[0])))' "$TMP/mc" > "$TMP/mc.items"
if grep -qF "$(cat "$TMP/mc/.mcp.json.tok")" "$TMP/mc.items"; then ko "mcp : valeur d'une variable d'environnement recopiée"; else ok "mcp : valeurs des variables jamais recopiées"; fi
if grep -q API_TOKEN "$TMP/mc.items"; then ok "mcp : noms des variables relevés"; else ko "mcp : noms des variables absents"; fi
# Conversion avec un analyseur factice (règles YARA simulées), sans l'outil.
pycall "$MCP" '
class F:
    def __init__(s, rule, sev):
        s.details = {"raw_response": {"rule": rule, "description": "desc " + rule, "threat_type": "t"}}
        s.severity = sev
        s.threat_category = "SECURITY"
class A:
    async def analyze(s, content, ctx):
        out = []
        if "ignore" in content.lower():
            out.append(F("prompt_injection", "HIGH"))
        if "http" in content.lower():
            out.append(F("data_exfiltration", "MEDIUM"))
        return out
items = m.discover(args[0])
json.dump(m.sarif(m.scan(items, A()), "0.0.0"), open(args[1], "w"))' "$MCM/testbed" "$TMP/mcp.sarif"
expect "mcp : SARIF 2.1.0" "$(jq -r .version "$TMP/mcp.sarif")" 2.1.0
expect "mcp : identifiants de règles préfixés" "$(jq -r '[.runs[0].results[].ruleId | select(startswith("mcp-scanner/") | not)] | length' "$TMP/mcp.sarif")" 0
expect "mcp : chaque résultat localisé dans le dépôt" \
	"$(jq -r '[.runs[0].results[] | .locations[0].physicalLocation | select(.artifactLocation.uri | startswith("/") or contains("..")) ] | length' "$TMP/mcp.sarif")" 0
if [[ "$(jq -r '.runs[0].results | length' "$TMP/mcp.sarif")" -gt 0 ]]; then ok "mcp : constats convertis"; else ko "mcp : aucun constat converti"; fi
expect "mcp : empreintes stables" "$(jq -r '[.runs[0].results[].partialFingerprints["mcpScanner/v1"] | length == 64] | all' "$TMP/mcp.sarif")" true
if python3 "$MODCHECK" expect "$MCM/module.yaml" "$MCM/tests/recorded.sarif" > "$TMP/exp.log"; then ok "mcp : attentes du banc d'essai (enregistrement)"
else ko "mcp : attentes du banc d'essai (enregistrement)"; sed 's/^/     /' "$TMP/exp.log"; fi
# Entrées hostiles : lien vers l'extérieur, fichier énorme, JSON invalide, Python invalide.
mkdir -p "$TMP/mh"
python3 -c 'import json, sys; json.dump({"tools": [{"name": "dehors", "description": "x"}]}, open(sys.argv[1], "w"))' "$TMP/dehors.json"
ln -s "$TMP/dehors.json" "$TMP/mh/lien.json"
python3 -c 'import json, sys; json.dump({"tools": [{"name": "gros", "description": "x" * 3_000_000}]}, open(sys.argv[1], "w"))' "$TMP/mh/gros.json"
printf '{"tools": [' > "$TMP/mh/casse.json"
printf 'def f(:\n' > "$TMP/mh/casse.py"
expect "mcp : entrées hostiles ignorées" "$(pycall "$MCP" 'print(len(m.discover(args[0])))' "$TMP/mh")" 0
rc=0; python3 -I "$MCP" > /dev/null 2>&1 || rc=$?
expect "mcp : arguments manquants refusés" "$rc" 2
for t in "$RADAR" "$MCP" "$SKILL" "$TOOLS/vulnhuntr/vulnhuntr_sarif.py"; do
	rc=0; python3 -I "$t" "$TMP" /out/x.sarif > /dev/null 2>&1 || rc=$?
	expect "$(basename "$t") : sources hors de /src refusées" "$rc" 2
	for o in /tmp/x.sarif /out/../x.sarif "/out/a b.sarif" /out/x.txt; do
		rc=0; python3 -I "$t" /src "$o" > /dev/null 2>&1 || rc=$?
		expect "$(basename "$t") : sortie « $o » refusée" "$rc" 2
	done
done

# --- 5. Vulnhuntr (K3, relais IA) -------------------------------------------------------------
VH="$TOOLS/vulnhuntr/vulnhuntr_sarif.py"
VHM="$ROOT/modules/vulnhuntr"
# Sources amont livrées non modifiées : chaque fichier listé et aucun ajouté.
if (cd "$TOOLS/vulnhuntr/vendor" && sha256sum --check --strict --quiet SHA256SUMS) > "$TMP/sums.log" 2>&1; then ok "vulnhuntr : sources amont intactes"
else ko "vulnhuntr : sources amont modifiées"; sed 's/^/     /' "$TMP/sums.log"; fi
expect "vulnhuntr : aucun fichier amont ajouté" \
	"$(cd "$TOOLS/vulnhuntr/vendor" && find vulnhuntr licenses -type f | sort | tr '\n' ' ')" \
	"$(awk '{print $2}' "$TOOLS/vulnhuntr/vendor/SHA256SUMS" | sort | tr '\n' ' ')"
sed "s#@REPO@#$VHM/testbed#g" "$VHM/tests/recorded.log" > "$TMP/vh.log"
(cd "$VHM/testbed" && python3 -I "$VH" --convert < "$TMP/vh.log" > "$TMP/vh.sarif")
expect "vulnhuntr : journal enregistré → SARIF identique" \
	"$(jq -S . "$TMP/vh.sarif" | sha256sum | cut -c1-64)" "$(jq -S . "$VHM/tests/recorded.sarif" | sha256sum | cut -c1-64)"
if python3 "$MODCHECK" expect "$VHM/module.yaml" "$TMP/vh.sarif" > "$TMP/exp.log"; then ok "vulnhuntr : attentes du banc d'essai"
else ko "vulnhuntr : attentes du banc d'essai"; sed 's/^/     /' "$TMP/exp.log"; fi
(cd "$VHM/testbed" && python3 -I "$VH" --convert 10 < "$TMP/vh.log" > "$TMP/vh10.sarif")
expect "vulnhuntr : seuil de confiance appliqué" "$(jq '.runs[0].results | length' "$TMP/vh10.sarif")" 0
# Ligne retrouvée par la citation de code du rapport ; chemins hors du dépôt et lignes invalides écartés.
python3 - "$TMP/vh.log" "$TMP/vh-h.log" <<'PY'
import json, sys
out = []
for line in open(sys.argv[1]):
    ev = json.loads(line)
    rep = ev.get("secondary_analysis_report")
    if rep and "RCE" in json.dumps(rep):
        rep["context_code"] = [{"name": "ping", "reason": "r", "code_line": 'subprocess.check_output("ping -c 1 " + host, shell=True)'}]
    out.append(json.dumps(ev))
rep = {"scratchpad": "", "analysis": "x", "poc": "", "confidence_score": 10, "vulnerability_types": ["LFI"], "context_code": []}
out += ["{pas du json", json.dumps({"event": "Performing initial analysis", "file": "../../etc/passwd"}),
        json.dumps({"event": "Initial analysis complete", "report": rep}),
        json.dumps({"event": "Performing initial analysis", "file": "/etc/shadow"}),
        json.dumps({"event": "Initial analysis complete", "report": rep})]
open(sys.argv[2], "w").write("\n".join(out) + "\n")
PY
(cd "$VHM/testbed" && python3 -I "$VH" --convert < "$TMP/vh-h.log" > "$TMP/vh-h.sarif")
expect "vulnhuntr : ligne retrouvée par la citation du rapport" \
	"$(jq -r '.runs[0].results[] | select(.ruleId == "vulnhuntr/rce") | .locations[0].physicalLocation.region.startLine' "$TMP/vh-h.sarif")" \
	"$(grep -n 'shell=True' "$VHM/testbed/app.py" | cut -d: -f1)"
expect "vulnhuntr : chemins hors du dépôt écartés" "$(jq -r '[.runs[0].results[].ruleId] | sort | join(" ")' "$TMP/vh-h.sarif")" "vulnhuntr/rce vulnhuntr/ssrf"
# Copie de travail : fichiers Python réguliers seulement, liens et dépendances ignorés.
mkdir -p "$TMP/vsrc/pkg" "$TMP/vsrc/node_modules/x" "$TMP/vwork"
printf 'x = 1\n' > "$TMP/vsrc/pkg/a.py"
printf 'y = 2\n' > "$TMP/vsrc/node_modules/x/b.py"
ln -s "$TMP/outside.py" "$TMP/vsrc/pkg/lien.py"
python3 -c 'import sys; open(sys.argv[1], "w").write("#" * 600_000)' "$TMP/vsrc/gros.py"
printf '# R\n' > "$TMP/vsrc/README.md"
ln -s "$TMP/outside.py" "$TMP/vsrc/README.rst"
expect "vulnhuntr : copie de travail bornée" \
	"$(pycall "$VH" 'print(m.copy_tree(args[0], args[1])); import os; print(" ".join(sorted(os.path.relpath(os.path.join(r, f), args[1]) for r, _, fs in os.walk(args[1]) for f in fs)))' "$TMP/vsrc" "$TMP/vwork" | tr '\n' '|')" \
	"1|README.md pkg/a.py|"
rc=0; env -u OPENAI_BASE_URL -u OPENAI_API_KEY python3 -I "$VH" /src /out/vx.sarif > /dev/null 2>&1 || rc=$?
expect "vulnhuntr : sans relais, panne d'infrastructure" "$rc" 3
rc=0; python3 -I "$VH" /src /out/vx.sarif 11 > /dev/null 2>&1 || rc=$?
expect "vulnhuntr : seuil invalide refusé" "$rc" 2
if grep -nE 'ANTHROPIC_API_KEY=|api\.anthropic\.com' "$VHM/module.yaml" "$VH" > /dev/null; then ko "vulnhuntr : autre fournisseur prévu"; else ok "vulnhuntr : relais seulement"; fi

# --- 6. Juges LLM (K5, K6, relais IA) ---------------------------------------------------------
SKL="$ROOT/modules/skill-scanner-llm"
jq -n --slurpfile r "$SKL/tests/upstream-rapport.sarif" '{"skills/rapport": $r[0]}' | python3 -I "$SKILL" --llm --merge > "$TMP/skl.sarif"
expect "skill-llm : fusion identique à l'enregistrement" \
	"$(jq -S . "$TMP/skl.sarif" | sha256sum | cut -c1-64)" "$(jq -S . "$SKL/tests/recorded.sarif" | sha256sum | cut -c1-64)"
expect "skill-llm : constats du juge seulement" \
	"$(jq -r '[.runs[0].results[].ruleId | select(startswith("skill-scanner-llm/llm_") | not)] | length' "$TMP/skl.sarif")" 0
if python3 "$MODCHECK" expect "$SKL/module.yaml" "$TMP/skl.sarif" > "$TMP/exp.log"; then ok "skill-llm : attentes du banc d'essai"
else ko "skill-llm : attentes du banc d'essai"; sed 's/^/     /' "$TMP/exp.log"; fi
jq '.runs[0].results += [{"ruleId": "LLM_ANALYSIS_FAILED", "level": "note", "message": {"text": "x"}}]' "$SKL/tests/upstream-rapport.sarif" > "$TMP/skl-f.sarif"
jq -n --slurpfile r "$TMP/skl-f.sarif" '{"skills/rapport": $r[0]}' | python3 -I "$SKILL" --llm --merge > "$TMP/skl-f.out"
expect "skill-llm : juge en échec compté en échec" "$(jq -c '.runs[0].properties["scanoria/skills"]' "$TMP/skl-f.out")" '{"analysed":0,"failed":["skills/rapport"]}'
rc=0; env -u OPENAI_BASE_URL -u OPENAI_API_KEY python3 -I "$SKILL" --llm /src /out/sx.sarif > /dev/null 2>&1 || rc=$?
expect "skill-llm : sans relais, panne d'infrastructure" "$rc" 3
expect "skill-llm : environnement du juge limité au relais" \
	"$(OPENAI_BASE_URL=https://ai-relay.exemple.test:8443/v1 OPENAI_API_KEY=k VIRUSTOTAL_API_KEY=v ANTHROPIC_API_KEY=a SKILL_SCANNER_LLM_PROVIDER=x \
		pycall "$SKILL" 'e = m.llm_env(); print(e["SKILL_SCANNER_LLM_BASE_URL"], e["SKILL_SCANNER_LLM_MODEL"], sorted(k for k in e if k.startswith(("VIRUSTOTAL", "ANTHROPIC", "OPENAI_", "SKILL_SCANNER_LLM_PROVIDER"))))')" \
	"https://ai-relay.exemple.test:8443/v1 scanoria []"
pycall "$MCP" '
class F:
    def __init__(s, cat, details, sev="HIGH"):
        s.details, s.severity, s.threat_category = details, sev, cat
class A:
    def __init__(s, fail=False):
        s.fail, s.seen = fail, []
    async def analyze(s, content, ctx):
        s.seen.append(json.loads(content))
        if s.fail:
            return [F("ANALYZER INFRASTRUCTURE", {"error_type": "InternalServerError"}, "INFO")]
        if "collect" in content.lower() or "ssh" in content.lower():
            return [F("PROMPT INJECTION", {"threat_type": "PROMPT INJECTION", "evidence": "prompt injection detected", "raw_response": {"threat_analysis": {}}})]
        return []
items = m.discover(args[0])
a = A()
json.dump(m.sarif(m.scan(items, a, True), "0.0.0", True), open(args[1], "w"))
json.dump(a.seen, open(args[2], "w"))
try:
    m.scan(items, A(True), True)
    print("no-raise")
except RuntimeError:
    print("raised")' "$MCM/testbed" "$TMP/mcl.sarif" "$TMP/mcl.seen" > "$TMP/mcl.out"
expect "mcp-llm : panne signalée par l'amont = erreur, jamais un constat" "$(cat "$TMP/mcl.out")" raised
expect "mcp-llm : identifiants de règles" "$(jq -r '[.runs[0].results[].ruleId] | unique | join(" ")' "$TMP/mcl.sarif")" "mcp-scanner-llm/prompt-injection"
expect "mcp-llm : une définition par élément, paramètres en objets" \
	"$(jq -r '[length, (map(.parameters | to_entries | map(.value | type == "object") | all) | all)] | join(" ")' "$TMP/mcl.seen")" "5 true"
expect "mcp-llm : noms des variables d'environnement seulement" "$(jq -r '[.[] | select(.name == "notes") | .parameters | keys[]] | join(",")' "$TMP/mcl.seen")" NOTES_TOKEN
rc=0; env -u OPENAI_BASE_URL -u OPENAI_API_KEY python3 -I "$MCP" --llm /src /out/mx.sarif > /dev/null 2>&1 || rc=$?
expect "mcp-llm : sans relais, panne d'infrastructure" "$rc" 3

echo
echo "b36-ia : $PASS réussis, $FAIL échoués"
[[ "$FAIL" -eq 0 ]]
