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

MODS=(agentic-radar mcp-scanner skill-scanner)
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
	expect "$m : aucun réseau" "$(jq -r .scan.network "$TMP/$m.json")" none
	expect "$m : outil de l'appliance" "$(jq -r .scan.tool "$TMP/$m.json")" "$m"
	expect "$m : lancé selon le contenu (applies_to)" "$(jq -r '.scan.applies_to.paths | length > 0' "$TMP/$m.json")" true
	img=$(jq -r '.image // ""' "$TMP/$m.json")
	if [[ "$(jq -r '.image_pending // false' "$TMP/$m.json")" == true && -z "$img" ]] || [[ "$img" == *@sha256:* ]]; then
		ok "$m : image en attente ou épinglée par empreinte"
	else ko "$m : image non épinglée ($img)"; fi
	expect "$m : licence Apache-2.0 vérifiée" "$(jq -r .license.spdx "$TMP/$m.json")" Apache-2.0
	n=$(grep -c ' --hash=sha256:' "$dir/image/requirements.lock" || true)
	if [[ "$n" -gt 10 ]]; then ok "$m : dépendances à empreintes ($n)"; else ko "$m : requirements.lock sans empreintes"; fi
	# Aucun service tiers en ligne : ni clé, ni option qui l'appellerait.
	if grep -nE 'VIRUSTOTAL_API_KEY=|MCP_SCANNER_API_KEY=|"--use-(osv|virustotal|aidefense|llm)"|api\.openai\.com' \
		"$dir/module.yaml" "$TOOLS/$m/"*.py > "$TMP/net.log"; then
		ko "$m : appel d'un service en ligne prévu"; sed 's/^/     /' "$TMP/net.log"
	else ok "$m : aucun service en ligne prévu"; fi
done

# --- 2. agentic-radar (K7) ---------------------------------------------------------------------
RAD="$ROOT/modules/agentic-radar"
python3 -I "$RADAR" --convert "$RAD/tests/recorded-graphs.json" "$RAD/testbed" "$TMP/radar.sarif" > /dev/null
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
python3 -I "$RADAR" --convert "$TMP/graphs-prompt.json" "$RAD/testbed" "$TMP/radar-p.sarif" > /dev/null
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
rc=0; python3 -I "$RADAR" --convert "$TMP/bad.json" "$RAD/testbed" "$TMP/x.sarif" > /dev/null 2>&1 || rc=$?
if [[ "$rc" -ne 0 && ! -s "$TMP/x.sarif" ]]; then ok "radar : graphe invalide refusé, aucune sortie"; else ko "radar : graphe invalide accepté"; fi

# --- 3. skill-scanner (K6) ---------------------------------------------------------------------
SKM="$ROOT/modules/skill-scanner"
python3 -I "$SKILL" --merge /src "$TMP/skill.sarif" "skills/rapport=$SKM/tests/upstream-rapport.sarif" > /dev/null
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
python3 -I "$SKILL" --merge /src "$TMP/skill-h.sarif" "skills/rapport=$TMP/hostile.sarif" "skills/autre=$TMP/bad.json" > /dev/null 2>&1 || true
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

echo
echo "b36-ia : $PASS réussis, $FAIL échoués"
[[ "$FAIL" -eq 0 ]]
