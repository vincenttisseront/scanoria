#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Vincent Tisseront
#
# b35 — relais IA des modules d'analyse par IA (0.7, contrat 31 ; CLAUDE.md
# § 3.5, K1–K10), sans root. Couvre :
#   - certificat ai-relay.<nom> émis par l'AC interne (scanoria-ca issue-relay),
#     contraint par ses nameConstraints ;
#   - schéma de manifeste : scan.network ai-relay et scan.relay_python ;
#   - jetons éphémères : droits du répertoire et des fichiers, purge des jetons
#     expirés, illisibles ou temporaires ;
#   - vérification préalable du runner contre un faux relais HTTPS sur socket
#     Unix (certificat de l'AC interne) : prêt, « aucun envoi à l'IA » (403),
#     jeton refusé (401), indisponible (503), socket absent, AC absente, nom TLS
#     faux ;
#   - runner en mode test (podman en bouchon) : --network=none conservé, jeton
#     jamais en argument ni dans le journal ou result.json, secret Podman monté
#     puis retiré, montages en lecture seule, commande sous le pont, jeton lié
#     au projet, à l'analyse et au module, retiré après le module ; module
#     « skipped » sans relais ou pour un projet « aucun envoi à l'IA » ; aucune
#     réutilisation de résultat (V4) ; manifeste à relay_python invalide refusé ;
#   - pont : relaie octet par octet vers le socket, passe le jeton par
#     OPENAI_API_KEY seulement, rend le code de sortie de l'outil ;
#   - I23 : un module d'IA qui échoue à son canari est désactivé, pas un autre.
# Dépendances : bash, python3, jq, openssl.

# shellcheck disable=SC2016,SC2015
set -euo pipefail
export PYTHONDONTWRITEBYTECODE=1

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
RUNNER="$ROOT/src/rootfs/usr/sbin/scanoria-runner"
CA="$ROOT/src/rootfs/usr/sbin/scanoria-ca"
PYLIB="$ROOT/src/rootfs/usr/lib/scanoria/py"
BRIDGE="$ROOT/src/rootfs/usr/lib/scanoria/scan-tools/ai-relay/bridge.py"
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
expect() { if [[ "$2" == "$3" ]]; then ok "$1"; else ko "$1 (obtenu « $2 », attendu « $3 »)"; fi; }
for t in python3 jq openssl; do command -v "$t" > /dev/null || { echo "outil manquant : $t" >&2; exit 2; }; done

T="$TMP/root"
STUBS="$TMP/stubs"
SCANS="$T/var/lib/scanoria/scans"
N=analyse.exemple.test
H="ai-relay.$N"
mkdir -p "$T/etc/scanoria" "$T/var/lib/scanoria/modules" "$T/var/lib/scanoria/uploads" "$T/run/scanoria" \
	"$T/run/scanoria-ai" "$T/proc" "$T/sys/fs/cgroup/fake.scope/container" "$T/etc/ssl/certs" \
	"$T/usr/lib/scanoria/scan-tools/ai-relay" "$STUBS"
chmod 0700 "$T/run/scanoria-ai"
export SCANORIA_TEST_ROOT="$T" SCANORIA_TEST_BIN="$STUBS"
unset SCANORIA_TEST_OWNER_UID SCANORIA_SCANS_DIR SCANORIA_RUNNER_STATE
printf 'MemTotal:       16384000 kB\n' > "$T/proc/meminfo"
for i in 0 1 2 3; do printf 'processor\t: %d\n' "$i"; done > "$T/proc/cpuinfo"
echo "52428800" > "$T/sys/fs/cgroup/fake.scope/container/memory.peak"
printf 'usage_usec 1234000\nuser_usec 1000000\n' > "$T/sys/fs/cgroup/fake.scope/container/cpu.stat"
echo "AC de test" > "$T/etc/ssl/certs/ca-certificates.crt"
jq -n --arg f "$N" '{fqdn: $f}' > "$T/etc/scanoria/appliance.json"
cp "$BRIDGE" "$T/usr/lib/scanoria/scan-tools/ai-relay/bridge.py"
uuid() { python3 -c 'import uuid; print(uuid.uuid4())'; }
py() { python3 -I -B -c "import sys; sys.path.insert(0, '$PYLIB'); $1" "${@:2}"; }

# --- 1. Certificat du relais par l'AC interne -----------------------------------------------
ca() { SCANORIA_TEST_BIN='' "$CA" "$@" 2> "$TMP/ca.err" || true; }
expect "AC interne : init" "$(ca init --fqdn "$N" | jq -r .code)" OK
out=$(ca issue-relay --fqdn "$N")
expect "issue-relay → OK, émis" "$(jq -r '"\(.code) \(.output.issued)"' <<< "$out")" "OK true"
RC="$T/etc/scanoria/pki/ai-relay"
openssl x509 -in "$RC/fullchain.pem" -noout -text > "$TMP/relay.txt"
grep -q "DNS:$H" "$TMP/relay.txt" && ok "certificat : SAN DNS:$H" || ko "certificat : SAN"
grep -q 'TLS Web Server Authentication' "$TMP/relay.txt" && ok "certificat : serverAuth" || ko "certificat : EKU"
openssl verify -x509_strict -CAfile "$T/var/lib/scanoria/public/scanoria-ca.crt" "$RC/fullchain.pem" > /dev/null 2>&1 \
	&& ok "certificat : vérifié par l'AC publique (nameConstraints)" || ko "certificat : non vérifié par l'AC"
expect "certificat : clé privée 0600" "$(stat -c %a "$RC/privkey.pem")" 600
expect "issue-relay sans force, valide → non réémis" "$(ca issue-relay --fqdn "$N" | jq -r .output.issued)" false
expect "issue-relay pour un autre nom → E_PRECONDITION" "$(ca issue-relay --fqdn autre.exemple.test | jq -r .code)" E_PRECONDITION

# --- 2. Schéma du manifeste ------------------------------------------------------------------
schema_check() { # manifeste-json → erreurs (vide = valide)
	py 'import json
from scanoria import schema
v = schema.Validator(json.load(open(sys.argv[1] + "/catalog/schema/module.schema.json")))
print("; ".join(v.errors(json.loads(sys.argv[2]))))' "$ROOT" "$1"
}
IMG="ghcr.io/exemple/ia@sha256:$(printf 'ia' | sha256sum | cut -d' ' -f1)"
manifest() { # relay_python
	jq -cn --arg img "$IMG" --arg py "$1" '{id: "ia-faux", name: "IA faux", type: "scanner", version: "1.0.0",
		categories: ["sast"], license: {spdx: "MIT", url: "https://exemple.test/licence", restrictions: "none"},
		upstream: {homepage: "https://exemple.test", source: "https://exemple.test/src"}, image: $img,
		resources: {min_ram_mb: 256, min_cpu: 1, disk_mb: 10}, hostname: null,
		needs: {feeds: [], sysctl: {}, postgres: false},
		scan: ({inputs: ["repo", "archive"], network: "ai-relay", timeout_s: 60,
			command: ["ia", "/src", "/out/result.sarif"], outputs: {sarif: "/out/result.sarif"}}
			+ (if $py == "" then {} else {relay_python: $py} end)),
		service: null, health: {command: ["ia", "--version"]}, upgrade: {policy: "on-demand"}}'
}
errs=$(schema_check "$(manifest "")")
[[ "$errs" != *network* && "$errs" != *relay* ]] && ok "schéma : network ai-relay accepté" || ko "schéma : ai-relay refusé ($errs)"
errs=$(schema_check "$(manifest /usr/local/bin/python3.12)")
[[ "$errs" != *relay_python* ]] && ok "schéma : relay_python absolu accepté" || ko "schéma : relay_python refusé ($errs)"
errs=$(schema_check "$(manifest 'python3; id')")
[[ "$errs" == *relay_python* ]] && ok "schéma : relay_python piégé refusé" || ko "schéma : relay_python piégé accepté"
errs=$(schema_check "$(manifest "" | jq -c '.scan.network = "host"')")
[[ "$errs" == *network* ]] && ok "schéma : network host refusé" || ko "schéma : network host accepté"
expect "python_of : « .. » refusé" "$(py 'from scanoria import airelay
try:
    airelay.python_of({"scan": {"relay_python": "/opt/../bin/python3"}}); print("accepté")
except airelay.Unavailable as u:
    print(u.code)')" E_MODULE_INVALID
expect "wrap_command : sous le pont, en mode isolé" "$(py 'import json
from scanoria import airelay
print(json.dumps(airelay.wrap_command({"scan": {}}, ["pr-agent", "review"])))')" '["python3", "-I", "/scanoria-relay/bridge.py", "--", "pr-agent", "review"]'

# --- 3. Jetons éphémères ---------------------------------------------------------------------
TOK_DIR="$T/run/scanoria-relay/tokens"
py 'import time
from scanoria import airelay
p = airelay.write_token("scr_essai", {"v": 1, "purpose": "scan", "module_id": "ia-faux", "project_id": None, "scan_id": None, "expires_at": int(time.time()) + 600})
print(p)' > "$TMP/tokpath"
expect "jeton : répertoire 0750" "$(stat -c %a "$TOK_DIR")" 750
expect "jeton : parent 0750" "$(stat -c %a "$(dirname "$TOK_DIR")")" 750
expect "jeton : fichier 0640" "$(stat -c %a "$(cat "$TMP/tokpath")")" 640
expect "jeton : nommé par son empreinte, jamais en clair" "$(basename "$(cat "$TMP/tokpath")")" "$(printf 'scr_essai' | sha256sum | cut -d' ' -f1).json"
grep -q scr_essai "$TOK_DIR"/*.json && ko "jeton : valeur écrite sur disque" || ok "jeton : valeur jamais écrite sur disque"
echo '{"expires_at": 1}' > "$TOK_DIR/$(printf 'vieux' | sha256sum | cut -d' ' -f1).json"
echo 'pas du JSON' > "$TOK_DIR/$(printf 'casse' | sha256sum | cut -d' ' -f1).json"
touch "$TOK_DIR/x.json.tmp-0000" "$TOK_DIR/autre.txt"
expect "purge : expiré et illisible retirés" "$(py 'from scanoria import airelay; print(airelay.purge_tokens())')" 2
expect "purge : jeton valide et fichier étranger gardés, temporaire retiré" "$(find "$TOK_DIR" -type f -printf '%f\n' | sed 's/^[0-9a-f]\{64\}\.json$/jeton/' | sort | tr '\n' ' ')" "autre.txt jeton "
rm -f "$TOK_DIR"/*

# --- 4. Faux relais : HTTPS sur socket Unix, certificat de l'AC interne -----------------------
SOCK="$T/run/scanoria-ai/relay.sock"
SCEN="$TMP/relay-scenario"
echo ready > "$SCEN"
cat > "$TMP/fake-relay.py" <<'EOF'
import hashlib, json, os, socket, ssl, sys, threading
sock, cert, key, tokdir, scen, log = sys.argv[1:7]
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(cert, key)
try:
    os.unlink(sock)
except OSError:
    pass
srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
srv.bind(sock)
os.chmod(sock, 0o666)
srv.listen(16)

def reply(s, status, doc):
    body = json.dumps(doc).encode()
    s.sendall(b"HTTP/1.1 %d X\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n" % (status, len(body)) + body)

def handle(raw):
    try:
        with ctx.wrap_socket(raw, server_side=True) as s:
            data = b""
            while b"\r\n\r\n" not in data:
                chunk = s.recv(4096)
                if not chunk:
                    return
                data += chunk
            lines = data.split(b"\r\n\r\n")[0].decode().split("\r\n")
            hdr = {l.split(":", 1)[0].lower(): l.split(":", 1)[1].strip() for l in lines[1:] if ":" in l}
            tok = hdr.get("authorization", "")[7:]
            path = os.path.join(tokdir, hashlib.sha256(tok.encode()).hexdigest() + ".json")
            rec = json.load(open(path)) if os.path.isfile(path) else None
            with open(log, "a") as f:
                f.write(json.dumps({"line": lines[0], "host": hdr.get("host"), "token": rec}) + "\n")
            mode = open(scen).read().strip()
            if rec is None:
                return reply(s, 401, {"error": {"code": "invalid_token"}})
            if mode == "optout":
                return reply(s, 403, {"error": {"code": "ai_opt_out"}})
            if mode == "down":
                return reply(s, 503, {"error": {"code": "circuit_open"}})
            reply(s, 200, {"ready": True, "model": "qwen-test:7b@cccccccccccc"})
    except (OSError, ssl.SSLError):
        pass

while True:
    c, _ = srv.accept()
    threading.Thread(target=handle, args=(c,), daemon=True).start()
EOF
python3 -I "$TMP/fake-relay.py" "$SOCK" "$RC/fullchain.pem" "$RC/privkey.pem" "$TOK_DIR" "$SCEN" "$TMP/relay.log" &
SRV_PID=$!
for _ in $(seq 50); do [[ -S "$SOCK" ]] && break; sleep 0.1; done
[[ -S "$SOCK" ]] && ok "faux relais en écoute" || { ko "faux relais absent"; exit 1; }

check() { # [hôte] → modèle ou code
	py 'import time
from scanoria import airelay
tok = "scr_" + "c" * 40
host = sys.argv[1] if len(sys.argv) > 1 and sys.argv[1] else airelay.relay_host()
path = airelay.write_token(tok, {"v": 1, "purpose": "scan", "module_id": "ia-faux", "project_id": None, "scan_id": None, "expires_at": int(time.time()) + 60})
try:
    print(airelay.check(tok, host, timeout=5))
except airelay.Unavailable as u:
    print(u.code)
    sys.stderr.write(u.message + "\n")
finally:
    __import__("os").unlink(path)' "${1:-}"
}
expect "vérification : prêt, modèle rendu" "$(check)" "qwen-test:7b@cccccccccccc"
expect "vérification : Host et ligne de requête" "$(tail -n 1 "$TMP/relay.log" | jq -r '.line + " " + .host')" "GET /v1/relay/check HTTP/1.1 $H"
echo optout > "$SCEN"
expect "vérification : projet « aucun envoi à l'IA » → E_RELAY_OPT_OUT" "$(check)" E_RELAY_OPT_OUT
echo down > "$SCEN"
expect "vérification : disjoncteur ouvert → E_RELAY_UNAVAILABLE" "$(check)" E_RELAY_UNAVAILABLE
echo ready > "$SCEN"
expect "vérification : jeton inconnu → E_RELAY_TOKEN" "$(py 'from scanoria import airelay
try:
    airelay.check("scr_inconnu", airelay.relay_host(), timeout=5)
except airelay.Unavailable as u:
    print(u.code)')" E_RELAY_TOKEN
expect "vérification : nom TLS faux → E_RELAY_UNAVAILABLE (certificat refusé)" "$(check "ollama.$N")" E_RELAY_UNAVAILABLE
mv "$T/var/lib/scanoria/public/scanoria-ca.crt" "$TMP/ca.bak"
expect "vérification : AC absente → E_RELAY_UNAVAILABLE" "$(check)" E_RELAY_UNAVAILABLE
mv "$TMP/ca.bak" "$T/var/lib/scanoria/public/scanoria-ca.crt"
mkdir -p "$TMP/vide"
expect "relay_host : sans nom d'appliance → E_RELAY_UNAVAILABLE" "$(SCANORIA_TEST_ROOT="$TMP/vide" py 'from scanoria import airelay
try:
    airelay.relay_host()
except airelay.Unavailable as u:
    print(u.code)')" E_RELAY_UNAVAILABLE

# --- 5. Runner : module relié au relais -------------------------------------------------------
cat > "$STUBS/podman" <<EOF
#!/usr/bin/env python3
# Bouchon de podman : journal des arguments, secrets et scanner simulés.
import json, os, sys
a = sys.argv[1:]
with open("$TMP/podman.log", "a") as f:
    f.write(json.dumps(a) + "\n")
if a[:2] == ["image", "exists"]:
    sys.exit(0)
if a[:2] == ["secret", "create"]:
    open("$TMP/secret-value", "w").write(open(a[3]).read())
    open("$TMP/secrets", "a").write(a[2] + "\n"); sys.exit(0)
if a[:2] == ["secret", "rm"]:
    open("$TMP/secrets-rm", "a").write(a[2] + "\n"); sys.exit(0)
if a[:2] == ["secret", "ls"]:
    print("scanoria-relay-0123456789abcdef\nautre-secret"); sys.exit(0)
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
toks = sorted(os.listdir("$T/run/scanoria-relay/tokens"))
open("$TMP/run-state", "w").write(json.dumps({"vols": vols, "tokens": [json.load(open("$T/run/scanoria-relay/tokens/" + t)) for t in toks],
    "hosts": open(vols["/etc/hosts"][0]).read() if "/etc/hosts" in vols else None}))
print("jeton vu par l'outil : " + open("$TMP/secret-value").read())
if os.path.exists("$TMP/tool-fails"):
    print("upstream_error 502 from the relay"); sys.exit(1)
out = vols["/out"][0]
open(out + "/result.sarif", "w").write(json.dumps({"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "ia"}}, "results": [{"ruleId": "ai-1", "message": {"text": "m"}}]}]}))
sys.exit(0)
EOF
cat > "$STUBS/nft" <<'EOF'
#!/bin/sh
exit 0
EOF
chmod 0755 "$STUBS/podman" "$STUBS/nft"

python3 - "$T/var/lib/scanoria/modules/installed.json" "$(manifest "")" <<'EOF'
import json, sys
path, man = sys.argv[1], json.loads(sys.argv[2])
man.update({"requires": {"modules": [], "feeds": []}, "conflicts": [],
            "outputs": {"sarif": {"path": "/out/result.sarif", "version": "2.1.0"}}})
man["scan"].pop("outputs", None)
man["scan"]["exit_codes_ok"] = [0]
bad = json.loads(json.dumps(man)); bad["id"] = "ia-casse"; bad["scan"]["relay_python"] = "python3; id"
e = {"status": "healthy", "enabled": True, "options": {}, "installed_at": "2026-11-25T08:00:00Z"}
reg = {"modules": {"ia-faux": dict(e, manifest=man), "ia-casse": dict(e, manifest=bad)}, "operations": []}
json.dump(reg, open(path, "w"))
EOF
PROJ=$(uuid)
mkarch() {
	mkdir -p "$T/var/lib/scanoria/uploads/$1"
	python3 -c 'import io, sys, tarfile
t = tarfile.open(sys.argv[1] + "/source.tar.gz", "w:gz")
i = tarfile.TarInfo("app.py"); d = b"print(1)\n"; i.size = len(d); t.addfile(i, io.BytesIO(d)); t.close()' "$T/var/lib/scanoria/uploads/$1"
}
job() { # id modules [project]
	local up; up=$(uuid); mkarch "$up"
	jq -cn --arg id "$1" --arg sid "$SCAN_ID" --arg up "$up" --argjson mods "$2" --arg p "${3-$PROJ}" \
		'{schema: 1, id: $id, scan_id: $sid, created_at: "2026-11-25T10:00:00Z", source: {kind: "archive", upload_id: $up}, modules: $mods}
		 + (if $p == "" then {} else {project_id: $p} end)'
}
drop() {
	printf '%s' "$2" > "$SCANS/jobs/incoming/$1.json"
	chmod 0600 "$SCANS/jobs/incoming/$1.json"
}
run_runner() { "$RUNNER" --once 2> "$TMP/runner.err" || { echo "runner : code $?"; sed 's/^/     /' "$TMP/runner.err"; }; }
res() { cat "$SCANS/results/$1/result.json" 2> /dev/null || echo '{}'; }
mod() { res "$1" | jq -c --arg m "$2" '.modules[] | select(.id == $m)'; }

run_runner   # arborescence ; secrets orphelins du relais retirés au démarrage
expect "démarrage : secret orphelin du relais retiré, pas les autres" "$(cat "$TMP/secrets-rm" 2> /dev/null)" scanoria-relay-0123456789abcdef
: > "$TMP/secrets-rm"
SCAN_ID=$(uuid)
id=$(uuid); drop "$id" "$(job "$id" '[{"id": "ia-faux", "version": "1.0.0"}]')"; : > "$TMP/podman.log"; run_runner
M=$(mod "$id" ia-faux)
expect "module IA : ok, une sortie SARIF" "$(jq -r '.status + " " + (.outputs | keys | join(","))' <<< "$M")" "ok sarif"
expect "module IA : marqué ai_relay pour la console" "$(jq -r .ai_relay <<< "$M")" true
RUN=$(grep '^\["run"' "$TMP/podman.log" | tail -n 1)
expect "conteneur : --network=none conservé, aucun autre réseau" "$(jq -c '[.[] | select(startswith("--network"))]' <<< "$RUN")" '["--network=none"]'
expect "conteneur : secret Podman du jeton monté pour l'utilisateur 65534" \
	"$(jq -r '. as $a | [range(length)] | map(select($a[.] == "--secret") | $a[. + 1]) | .[0] | sub("^scanoria-relay-[0-9a-f]{16}"; "S")' <<< "$RUN")" \
	"S,type=mount,target=relay-token,uid=65534,gid=65534,mode=400"
expect "conteneur : montages du relais en lecture seule" \
	"$(jq -r '.vols | to_entries | map(select(.key | test("relay|hosts"))) | map(.key + ":" + .value[1]) | sort | join(" ")' "$TMP/run-state")" \
	"/etc/hosts:ro /run/scanoria-relay/ca.pem:ro /run/scanoria-relay/relay.sock:ro /scanoria-relay:ro"
expect "conteneur : socket du relais monté" "$(jq -r '.vols["/run/scanoria-relay/relay.sock"][0]' "$TMP/run-state")" "$SOCK"
expect "conteneur : /etc/hosts désigne la boucle locale pour le relais" "$(jq -r .hosts "$TMP/run-state" | head -n 1)" "$(printf '127.0.0.1\tlocalhost %s' "$H")"
expect "conteneur : commande sous le pont" "$(jq -c '. as $a | (index("--entrypoint")) as $i | [$a[$i + 1]] + $a[$i + 3:$i + 6]' <<< "$RUN")" \
	'["[\"python3\"]","-I","/scanoria-relay/bridge.py","--"]'
expect "conteneur : base OpenAI vers le relais en HTTPS" "$(jq -r '.[] | select(startswith("OPENAI_BASE_URL="))' <<< "$RUN")" "OPENAI_BASE_URL=https://$H:8443/v1"
expect "conteneur : modèle choisi par l'appliance (alias)" "$(jq -r '.[] | select(startswith("SCANORIA_AI_MODEL="))' <<< "$RUN")" "SCANORIA_AI_MODEL=scanoria"
TOKV=$(cat "$TMP/secret-value")
[[ "$TOKV" =~ ^scr_[A-Za-z0-9_-]{64}$ ]] && ok "jeton : forme scr_ et 48 octets aléatoires" || ko "jeton : forme ($TOKV)"
grep -qF "$TOKV" "$TMP/podman.log" && ko "jeton : présent dans les arguments de podman" || ok "jeton : jamais dans les arguments de podman"
grep -rqF "$TOKV" "$SCANS/results/$id" && ko "jeton : présent dans le journal ou result.json" || ok "jeton : masqué dans le journal et absent de result.json"
expect "jeton : lié au projet, à l'analyse et au module" "$(jq -c '.tokens[0] | [.purpose, .module_id, .project_id == $p, .scan_id == $s]' --arg p "$PROJ" --arg s "$SCAN_ID" "$TMP/run-state")" '["scan","ia-faux",true,true]'
expect "jeton : expire après le délai du module" "$(jq -r '.tokens[0].expires_at - now | floor | . > 60 and . < 1000' "$TMP/run-state")" true
expect "jeton : retiré après le module" "$(find "$TOK_DIR" -type f | wc -l)" 0
grep -qxF "$(cat "$TMP/secrets")" "$TMP/secrets-rm" && ok "secret Podman : retiré après le module" || ko "secret Podman : laissé"
[[ -z "$(find "$SCANS/workspaces" -name relay-hosts)" ]] && ok "fichier hosts retiré" || ko "fichier hosts laissé"
expect "relais : vérifié une fois avec le jeton du module" "$(jq -c 'select(.token.module_id == "ia-faux") | .line' "$TMP/relay.log" | tail -n 1)" '"GET /v1/relay/check HTTP/1.1"'
expect "aucune réutilisation de résultat (V4)" "$(jq -r '.cache_key // "aucune" | tostring' <<< "$M") $(jq -r '.reused // false' <<< "$M")" "aucune false"
expect "result.json conforme au schéma" "$(py 'import json
from scanoria import schema
print(len(schema.load("schemas", "scan-result").errors(json.load(open(sys.argv[1])))))' "$SCANS/results/$id/result.json")" 0

touch "$TMP/tool-fails"
id=$(uuid); drop "$id" "$(job "$id" '[{"id": "ia-faux", "version": "1.0.0"}]')"; run_runner
M=$(mod "$id" ia-faux)
expect "outil IA en erreur (relais 502) : skipped, jamais non concluant (§ 3.5)" "$(jq -r '.status + " " + .error.code' <<< "$M")" "skipped E_TOOL_EXIT"
expect "outil IA en erreur : cause lisible" "$(jq -r '.error.message | startswith("AI module, outside the verdict")' <<< "$M")" true
expect "outil IA en erreur : jeton retiré" "$(find "$TOK_DIR" -type f | wc -l)" 0
rm -f "$TMP/tool-fails"

echo optout > "$SCEN"
id=$(uuid); drop "$id" "$(job "$id" '[{"id": "ia-faux", "version": "1.0.0"}]')"; : > "$TMP/podman.log"; run_runner
M=$(mod "$id" ia-faux)
expect "projet « aucun envoi à l'IA » : skipped, E_RELAY_OPT_OUT" "$(jq -r '.status + " " + .error.code' <<< "$M")" "skipped E_RELAY_OPT_OUT"
grep -q '^\["run"' "$TMP/podman.log" && ko "aucun envoi : conteneur lancé" || ok "aucun envoi : aucun conteneur lancé"
expect "aucun envoi : analyse non en erreur (G13 hors IA)" "$(res "$id" | jq -r .status)" ok
echo ready > "$SCEN"

kill "$SRV_PID"; wait "$SRV_PID" 2> /dev/null || true; SRV_PID=; rm -f "$SOCK"
id=$(uuid); drop "$id" "$(job "$id" '[{"id": "ia-faux", "version": "1.0.0"}]')"; run_runner
expect "sans relais : skipped, E_RELAY_UNAVAILABLE" "$(mod "$id" ia-faux | jq -r '.status + " " + .error.code')" "skipped E_RELAY_UNAVAILABLE"
expect "sans relais : aucun jeton laissé" "$(find "$TOK_DIR" -type f | wc -l)" 0

id=$(uuid); drop "$id" "$(job "$id" '[{"id": "ia-faux", "version": "1.0.0"}]' "")"; run_runner
expect "sans projet : skipped, E_PROJECT_UNKNOWN" "$(mod "$id" ia-faux | jq -r '.status + " " + .error.code')" "skipped E_PROJECT_UNKNOWN"

id=$(uuid); drop "$id" "$(job "$id" '[{"id": "ia-casse", "version": "1.0.0"}]')"; run_runner
expect "relay_python piégé : module refusé" "$(mod "$id" ia-casse | jq -r '.status')" missing

# --- 6. Pont : octets relayés, jeton par OPENAI_API_KEY, code de sortie ------------------------
B="$TMP/bridge"
mkdir -p "$B"
cat > "$B/echo-sock.py" <<'EOF'
import os, socket, sys
p = sys.argv[1]
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.bind(p); s.listen(4)
while True:
    c, _ = s.accept()
    d = b""
    while not d.endswith(b"\n"):
        x = c.recv(1024)
        if not x:
            break
        d += x
    c.sendall(b"echo:" + d); c.close()
EOF
cat > "$B/tool.py" <<'EOF'
import os, socket, sys, time
port = int(sys.argv[2])
for _ in range(50):
    try:
        s = socket.create_connection(("127.0.0.1", port), timeout=2); break
    except OSError:
        time.sleep(0.1)
s.sendall(b"bonjour\n")
r = s.recv(1024)
print(r.decode().strip())
print("key=" + ("ok" if os.environ.get("OPENAI_API_KEY") == "scr_pont" else "absent"))
print("port-env=" + ("present" if "SCANORIA_RELAY_PORT" in os.environ else "absent"))
sys.exit(int(sys.argv[1]))
EOF
printf 'scr_pont\n' > "$B/token"
BPORT=$(python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])')
python3 -I "$B/echo-sock.py" "$B/relay.sock" &
ECHO_PID=$!
SRV_PID=$ECHO_PID
for _ in $(seq 50); do [[ -S "$B/relay.sock" ]] && break; sleep 0.1; done
bridge() { # code-de-sortie-de-l-outil
	SCANORIA_RELAY_PORT=$BPORT python3 -I -B -c 'import runpy, sys
g = runpy.run_path(sys.argv[1], run_name="bridge")
g["main"].__globals__.update(SOCKET=sys.argv[2], TOKEN=sys.argv[3])
sys.exit(g["main"](["bridge.py", "--", sys.executable, "-I", sys.argv[4], sys.argv[5], sys.argv[6]]))' "$BRIDGE" "$B/relay.sock" "$B/token" "$B/tool.py" "$1" "$BPORT"
}
set +e
out=$(bridge 0); rc=$?
set -e
expect "pont : octets relayés vers le socket" "$(sed -n 1p <<< "$out")" "echo:bonjour"
expect "pont : jeton passé par OPENAI_API_KEY" "$(sed -n 2p <<< "$out")" "key=ok"
expect "pont : SCANORIA_RELAY_PORT retiré de l'environnement de l'outil" "$(sed -n 3p <<< "$out")" "port-env=absent"
expect "pont : code 0 rendu" "$rc" 0
set +e
bridge 3 > /dev/null; rc=$?
set -e
expect "pont : code de sortie de l'outil rendu (3)" "$rc" 3
set +e
python3 -I -B -c 'import runpy, sys
g = runpy.run_path(sys.argv[1], run_name="bridge")
g["main"].__globals__.update(TOKEN=sys.argv[2])
sys.exit(g["main"](["bridge.py", "--", "true"]))' "$BRIDGE" "$B/absent" 2> "$B/err"; rc=$?
set -e
expect "pont : jeton absent → 70, outil non lancé" "$rc $(cat "$B/err")" "70 ai-relay bridge: relay token missing"
set +e
python3 -I -B "$BRIDGE" true 2> /dev/null; rc=$?
set -e
expect "pont : usage sans « -- » → 70" "$rc" 70
kill "$ECHO_PID" 2> /dev/null || true

# --- 7. I23 : désactivation automatique d'un module d'IA au canari ------------------------------
expect "canari : module d'IA désactivé après deux échecs de suite, jamais un autre" "$(py 'import json
from scanoria import modules, vigilance
reg = modules.load_registry()
reg["modules"]["sans-ia"] = json.loads(json.dumps(reg["modules"]["ia-faux"]))
reg["modules"]["sans-ia"]["manifest"]["id"] = "sans-ia"
reg["modules"]["sans-ia"]["manifest"]["scan"]["network"] = "none"
modules.save_registry(reg)
print(vigilance.disable_failed_ai_modules(["ia-faux", "sans-ia"]))
print(vigilance.disable_failed_ai_modules([], ["ia-faux"]))
print(vigilance.disable_failed_ai_modules(["ia-faux"]))
print(vigilance.disable_failed_ai_modules(["ia-faux", "sans-ia"]))
reg = modules.load_registry()
print(reg["modules"]["ia-faux"]["enabled"], reg["modules"]["ia-faux"]["status"], reg["modules"]["sans-ia"]["enabled"])' 2> /dev/null | tr '\n' ' ')" "[] [] [] ['ia-faux'] False disabled True "

printf '\n%d réussis, %d échoués\n' "$PASS" "$FAIL"
[[ $FAIL -eq 0 ]]
