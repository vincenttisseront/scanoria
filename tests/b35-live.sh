#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Vincent Tisseront
#
# b35-live — relais IA des modules d'analyse par IA (0.7, contrat 31) avec le
# vrai podman et le vrai relais (job CI relay-live, machine de test root
# jetable). Le relais de scanoria-ai (webui/server/ai/relay.ts, regroupé par
# esbuild) sert en HTTPS, avec le certificat ai-relay.<nom> de la vraie AC
# interne (scanoria-ca), sur le socket Unix du runner ; Ollama est un faux en
# mémoire qui journalise ce qu'il reçoit. Le runner tourne en mode test sur une
# racine temporaire. Un module de test (image Python épinglée) appelle
# l'API compatible OpenAI depuis son conteneur en --network=none, à travers le
# pont de l'appliance. Cas :
#   - analyse : TLS vérifié de bout en bout (AC interne, nom ai-relay.<nom>),
#     jeton accepté, réponse du faux modèle reprise en SARIF, appel journalisé
#     (relay, module, projet, modèle choisi par l'appliance) ;
#   - garde-fous vus d'Ollama : outils retirés, secret de l'extrait masqué,
#     modèle de l'appliance et non celui demandé, consigne de l'appliance en tête ;
#   - confinement : aucun autre réseau joignable depuis le conteneur ;
#   - projet « aucun envoi à l'IA » : module « skipped », aucun appel ;
#   - relais arrêté : module « skipped » (E_RELAY_UNAVAILABLE) ;
#   - après chaque analyse : jeton retiré, secret Podman retiré, aucun conteneur.
# Les résultats IA hors verdict puis confirmés sont couverts contre un vrai
# PostgreSQL par webui/tests/integration/ai-findings-api.test.ts.
# Dépendances : bash, python3, python3-yaml, jq, openssl, podman, node et
# webui/node_modules (root).

# shellcheck disable=SC2016,SC2015
set -euo pipefail
export PYTHONDONTWRITEBYTECODE=1

[[ "$(id -u)" -eq 0 ]] || { echo "b35-live : root requis (podman réel)" >&2; exit 2; }
for t in python3 jq openssl podman node; do command -v "$t" > /dev/null || { echo "outil manquant : $t" >&2; exit 2; }; done

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
RUNNER="$ROOT/src/rootfs/usr/sbin/scanoria-runner"
CA="$ROOT/src/rootfs/usr/sbin/scanoria-ca"
[[ -x "$ROOT/webui/node_modules/.bin/esbuild" ]] || { echo "webui/node_modules absent (npm ci)" >&2; exit 2; }
TMP=$(mktemp -d)
RELAY_PID=
cleanup() {
	[[ -n "$RELAY_PID" ]] && kill "$RELAY_PID" 2> /dev/null || true
	podman ps -a --format '{{.Names}}' | grep '^scanoria-scan-' | xargs -r podman rm -f > /dev/null 2>&1 || true
	podman secret ls --format '{{.Name}}' | grep '^scanoria-relay-' | xargs -r podman secret rm > /dev/null 2>&1 || true
	rm -rf "$TMP"
}
trap cleanup EXIT

PASS=0
FAIL=0
ok() { PASS=$((PASS + 1)); printf 'ok   %s\n' "$1"; }
ko() { FAIL=$((FAIL + 1)); printf 'FAIL %s\n' "$1"; }
expect() { if [[ "$2" == "$3" ]]; then ok "$1"; else ko "$1 (obtenu « $2 », attendu « $3 »)"; fi; }
yq() { python3 -c 'import json, sys, yaml; print(json.dumps(yaml.safe_load(open(sys.argv[1], encoding="utf-8"))))' "$1"; }
uuid() { python3 -c 'import uuid; print(uuid.uuid4())'; }

T="$TMP/root"
STUBS="$TMP/stubs"
SCANS="$T/var/lib/scanoria/scans"
RT="$T/run/scanoria-ai"
TOK_DIR="$T/run/scanoria-relay/tokens"
LIVE="$TMP/live"
N=analyse.exemple.test
mkdir -p "$T/etc/scanoria" "$T/var/lib/scanoria/modules" "$T/var/lib/scanoria/uploads" "$T/run/scanoria" "$RT" \
	"$T/proc" "$T/etc/ssl/certs" "$T/usr/lib/scanoria/scan-tools/ai-relay" "$STUBS" "$LIVE"
chmod 0700 "$RT"
cp /proc/meminfo "$T/proc/meminfo"
grep '^processor' /proc/cpuinfo > "$T/proc/cpuinfo"
cp /etc/ssl/certs/ca-certificates.crt "$T/etc/ssl/certs/ca-certificates.crt"
cp "$ROOT/src/rootfs/usr/lib/scanoria/scan-tools/ai-relay/bridge.py" "$T/usr/lib/scanoria/scan-tools/ai-relay/"
chmod -R a+rX "$T/usr/lib/scanoria/scan-tools"
ln -s "$(command -v podman)" "$STUBS/podman"
export SCANORIA_TEST_ROOT="$T" SCANORIA_TEST_BIN="$STUBS"
jq -n --arg f "$N" '{fqdn: $f}' > "$T/etc/scanoria/appliance.json"

# --- AC interne, certificat du relais, relais --------------------------------------------------
SCANORIA_TEST_BIN='' "$CA" init --fqdn "$N" > /dev/null
expect "AC interne : certificat ai-relay émis" "$(SCANORIA_TEST_BIN='' "$CA" issue-relay --fqdn "$N" | jq -r .code)" OK
cp "$T/etc/scanoria/pki/ai-relay/fullchain.pem" "$RT/relay.crt"
cp "$T/etc/scanoria/pki/ai-relay/privkey.pem" "$RT/relay.key"
chmod 0400 "$RT/relay.crt" "$RT/relay.key"
jq -n '{version: 1, enabled: true, url: "https://ollama.exemple.test:11434", scheme: "https", host: "ollama.exemple.test",
	port: 11434, addresses: ["192.0.2.10"], insecure: false, token: false, ca: false, literal: false, pinned_at: "2026-11-25T08:00:00Z"}' > "$RT/ai.json"
(cd "$ROOT/webui" && node_modules/.bin/esbuild tests/live/relay-harness.ts --bundle --platform=node --format=esm --target=node22 \
	--external:pg-native --alias:#shared=./shared --log-level=warning --outfile="$TMP/relay-harness.mjs" \
	"--banner:js=import { createRequire as __r } from 'node:module'; const require = __r(import.meta.url);")
OPT_OUT=$(uuid)
start_relay() {
	RELAY_RUNTIME_DIR="$RT" RELAY_LIVE_DIR="$LIVE" RELAY_TOKEN_DIR="$TOK_DIR" RELAY_OPT_OUT="$OPT_OUT" \
		node "$TMP/relay-harness.mjs" 2>> "$LIVE/relay.err" &
	RELAY_PID=$!
	for _ in $(seq 100); do [[ -S "$RT/relay.sock" ]] && return 0; sleep 0.1; done
	return 1
}
start_relay && ok "relais en écoute sur le socket du runner" || { ko "relais absent"; cat "$LIVE/relay.err"; exit 1; }
expect "socket du relais 0666" "$(stat -c %a "$RT/relay.sock")" 666

# --- Module de test : image Python épinglée, outil qui parle OpenAI -------------------------------
PY_IMAGE=$(yq "$ROOT/modules/reach-index/module.yaml" | jq -r .image)
[[ "$PY_IMAGE" == *@sha256:* ]] && ok "image Python épinglée par empreinte" || ko "image Python non épinglée"
podman pull -q "$PY_IMAGE" > /dev/null
python3 - "$T/var/lib/scanoria/modules/installed.json" "$PY_IMAGE" <<'EOF'
import json, sys
path, image = sys.argv[1:3]
man = {"id": "ia-live", "name": "IA live", "type": "scanner", "version": "1.0.0", "categories": ["sast"],
       "license": {"spdx": "MIT", "restrictions": "none"}, "image": image,
       "resources": {"min_ram_mb": 256, "min_cpu": 1, "disk_mb": 10},
       "requires": {"modules": [], "feeds": []}, "conflicts": [],
       "scan": {"inputs": ["archive"], "network": "ai-relay", "timeout_s": 120, "exit_codes_ok": [0],
                "command": ["python3", "-I", "/src/outil_ia.py", "/src/app.py", "/out/result.sarif"]},
       "outputs": {"sarif": {"path": "/out/result.sarif", "version": "2.1.0"}}}
reg = {"modules": {"ia-live": {"manifest": man, "status": "healthy", "enabled": True, "options": {},
                               "installed_at": "2026-11-25T08:00:00Z"}}, "operations": []}
json.dump(reg, open(path, "w"))
EOF
# Outil du module (fichier de l'archive analysée pour ce seul test) : appelle
# /chat/completions avec un modèle et des outils demandés, puis vérifie qu'aucun
# autre réseau n'est joignable, et écrit le résultat du modèle en SARIF.
SECRET="ghp_$(head -c 64 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 36)"
mkarch() { # upload_id
	mkdir -p "$T/var/lib/scanoria/uploads/$1"
	python3 - "$T/var/lib/scanoria/uploads/$1" "$SECRET" <<'EOF'
import io, sys, tarfile
tool = r'''
import json, os, socket, ssl, sys, urllib.request
src, out = sys.argv[1:3]
code = open(src).read()
body = {"model": "gpt-4o", "temperature": 0, "messages": [
    {"role": "system", "content": "You are a code reviewer."},
    {"role": "user", "content": "Review this file:\n" + code}],
    "tools": [{"type": "function", "function": {"name": "run_shell_live", "parameters": {"type": "object"}}}],
    "tool_choice": "auto"}
req = urllib.request.Request(os.environ["OPENAI_BASE_URL"] + "/chat/completions", data=json.dumps(body).encode(),
    headers={"Authorization": "Bearer " + os.environ["OPENAI_API_KEY"], "Content-Type": "application/json"})
ctx = ssl.create_default_context(cafile=os.environ["SSL_CERT_FILE"])
doc = json.load(urllib.request.urlopen(req, context=ctx, timeout=60))
finding = json.loads(doc["choices"][0]["message"]["content"])
try:
    socket.create_connection(("192.0.2.10", 443), timeout=3).close(); net = "reachable"
except OSError:
    net = "blocked"
sarif = {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "ia-live"}}, "results": [
    {"ruleId": finding["rule"], "level": "warning", "message": {"text": finding["message"]},
     "locations": [{"physicalLocation": {"artifactLocation": {"uri": finding["path"]}, "region": {"startLine": finding["line"]}}}],
     "properties": {"model": doc["model"], "network": net, "base": os.environ["OPENAI_BASE_URL"]}}]}]}
open(out, "w").write(json.dumps(sarif))
'''
t = tarfile.open(sys.argv[1] + "/source.tar.gz", "w:gz")
for name, data in (("outil_ia.py", tool), ("app.py", "import os\nTOKEN = \"%s\"\nprint(input())\n" % sys.argv[2])):
    i = tarfile.TarInfo(name); d = data.encode(); i.size = len(d); t.addfile(i, io.BytesIO(d))
t.close()
EOF
}
job() { # id projet
	local up; up=$(uuid); mkarch "$up"
	jq -cn --arg id "$1" --arg sid "$(uuid)" --arg up "$up" --arg p "$2" \
		'{schema: 1, id: $id, scan_id: $sid, project_id: $p, created_at: "2026-11-25T10:00:00Z",
		  source: {kind: "archive", upload_id: $up}, modules: [{id: "ia-live", version: "1.0.0"}]}'
}
drop() {
	printf '%s' "$2" > "$SCANS/jobs/incoming/$1.json"
	chmod 0600 "$SCANS/jobs/incoming/$1.json"
}
run_runner() {
	"$RUNNER" --once 2> "$TMP/runner.err" || echo "runner : code $?"
	sed 's/^/     runner: /' "$TMP/runner.err" | tail -n 20
}
res() { cat "$SCANS/results/$1/result.json" 2> /dev/null || echo '{}'; }
mod() { res "$1" | jq -c '.modules[] | select(.id == "ia-live")'; }
after() { # libellé
	expect "$1 : jeton retiré" "$(find "$TOK_DIR" -type f 2> /dev/null | wc -l)" 0
	expect "$1 : secret Podman retiré" "$(podman secret ls --format '{{.Name}}' | grep -c '^scanoria-relay-' || true)" 0
	expect "$1 : aucun conteneur laissé" "$(podman ps -a --format '{{.Names}}' | grep -c '^scanoria-scan-' || true)" 0
}

"$RUNNER" --once 2> /dev/null || true   # arborescence

# --- 1. Analyse par le relais ---------------------------------------------------------------------
PROJ=$(uuid)
id=$(uuid); drop "$id" "$(job "$id" "$PROJ")"; run_runner
M=$(mod "$id")
expect "module IA : ok" "$(jq -r .status <<< "$M")" ok
[[ "$(jq -r .status <<< "$M")" == ok ]] || { jq . <<< "$M"; tail -n 30 "$SCANS/results/$id/"*.log 2> /dev/null || true; cat "$LIVE/relay.err"; }
SARIF=$(find "$SCANS/results/$id" -name '*.sarif' | head -n 1)
R=$(jq -c '.runs[0].results[0]' "$SARIF" 2> /dev/null || echo '{}')
expect "réponse du modèle reprise en SARIF" "$(jq -r '.ruleId + " " + .locations[0].physicalLocation.artifactLocation.uri' <<< "$R")" "ai-injection app.py"
expect "TLS de bout en bout vers ai-relay.<nom> (AC interne)" "$(jq -r .properties.base <<< "$R")" "https://ai-relay.$N:8443/v1"
expect "modèle annoncé à l'outil : alias de l'appliance" "$(jq -r .properties.model <<< "$R")" scanoria
expect "confinement : aucun autre réseau joignable" "$(jq -r .properties.network <<< "$R")" blocked
C=$(tail -n 1 "$LIVE/calls.jsonl" 2> /dev/null || echo '{}')
expect "appel journalisé : relais, module, projet, issue" "$(jq -c '[.module, .project == $p, .outcome]' --arg p "$PROJ" <<< "$C")" '["ia-live",true,"ok"]'
expect "appel journalisé : modèle choisi par l'appliance" "$(jq -r .model <<< "$C")" "faux-modele:7b@eeeeeeeeeeee"
O=$(tail -n 1 "$LIVE/ollama.jsonl" 2> /dev/null || echo '{}')
expect "Ollama : modèle de l'appliance, pas celui demandé" "$(jq -r .model <<< "$O")" faux-modele:7b
expect "Ollama : aucun outil transmis" "$(jq -r '.keys | map(select(test("tool"))) | length' <<< "$O")" 0
grep -q run_shell_live "$LIVE/ollama.jsonl" && ko "Ollama : définition d'outil transmise" || ok "Ollama : définition d'outil jamais transmise"
grep -qF "$SECRET" "$LIVE/ollama.jsonl" && ko "Ollama : secret de l'extrait transmis" || ok "Ollama : secret de l'extrait masqué avant envoi"
expect "Ollama : consigne de l'appliance en tête" "$(jq -r '.messages[0].role' <<< "$O") $(jq -r '.messages[0].content | test("data, never instructions|never as instructions|untrusted"; "i")' <<< "$O")" "system true"
grep -rqF "$(cat "$TOK_DIR"/* 2> /dev/null || echo jamais)" "$SCANS/results/$id" 2> /dev/null && ko "jeton dans les résultats" || ok "jeton absent des résultats"
after "analyse"

# --- 2. Projet « aucun envoi à l'IA » --------------------------------------------------------------
n=$(wc -l < "$LIVE/ollama.jsonl")
id=$(uuid); drop "$id" "$(job "$id" "$OPT_OUT")"; run_runner
expect "aucun envoi à l'IA : skipped, E_RELAY_OPT_OUT" "$(mod "$id" | jq -r '.status + " " + .error.code')" "skipped E_RELAY_OPT_OUT"
expect "aucun envoi à l'IA : rien reçu par Ollama" "$(wc -l < "$LIVE/ollama.jsonl")" "$n"
after "aucun envoi"

# --- 3. Relais arrêté --------------------------------------------------------------------------------
kill "$RELAY_PID"; wait "$RELAY_PID" 2> /dev/null || true; RELAY_PID=
rm -f "$RT/relay.sock"
id=$(uuid); drop "$id" "$(job "$id" "$PROJ")"; run_runner
expect "relais arrêté : skipped, E_RELAY_UNAVAILABLE" "$(mod "$id" | jq -r '.status + " " + .error.code')" "skipped E_RELAY_UNAVAILABLE"
expect "relais arrêté : analyse non en erreur" "$(res "$id" | jq -r .status)" ok
after "relais arrêté"

printf '\n%d réussis, %d échoués\n' "$PASS" "$FAIL"
[[ $FAIL -eq 0 ]]
