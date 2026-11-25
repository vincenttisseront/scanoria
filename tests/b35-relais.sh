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
expect "wrap_command : sous le pont, en mode isolé, sans la commande en argument" "$(py 'import json
from scanoria import airelay
print(json.dumps(airelay.wrap_command({"scan": {}})))')" '["python3", "-I", "/scanoria-relay/bridge.py"]'
expect "command_doc : commande vide, NUL ou non-chaîne refusée" "$(py 'from scanoria import airelay
for c in ([], [""], ["ia", "a\0b"], ["ia", 3], "ia"):
    try:
        airelay.command_doc(c); print("accepté")
    except airelay.Unavailable as u:
        print(u.code)' | sort -u)" E_MODULE_INVALID

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
    "hosts": open(vols["/etc/hosts"][0]).read() if "/etc/hosts" in vols else None,
    "modes": {k: oct(os.stat(v[0]).st_mode & 0o777) for k, v in vols.items() if k in ("/etc/hosts", "/run/scanoria-relay/command.json")},
    "command": json.load(open(vols["/run/scanoria-relay/command.json"][0])) if "/run/scanoria-relay/command.json" in vols else None}))
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
	"/etc/hosts:ro /run/scanoria-relay/ca.pem:ro /run/scanoria-relay/command.json:ro /run/scanoria-relay/relay.sock:ro /scanoria-relay:ro"
expect "conteneur : socket du relais monté" "$(jq -r '.vols["/run/scanoria-relay/relay.sock"][0]' "$TMP/run-state")" "$SOCK"
expect "conteneur : /etc/hosts désigne la boucle locale pour le relais" "$(jq -r .hosts "$TMP/run-state" | head -n 1)" "$(printf '127.0.0.1\tlocalhost %s' "$H")"
expect "conteneur : commande sous le pont, sans argument" "$(jq -c '. as $a | (index("--entrypoint")) as $i | [$a[$i + 1]] + $a[$i + 3:]' <<< "$RUN")" \
	'["[\"python3\"]","-I","/scanoria-relay/bridge.py"]'
expect "conteneur : commande de l'outil remise au pont par un fichier" "$(jq -c .command "$TMP/run-state")" '["ia","/src","/out/result.sarif"]'
expect "conteneur : hosts et commande en 0400 (utilisateur du conteneur seul)" "$(jq -r '.modes | [.["/etc/hosts"], .["/run/scanoria-relay/command.json"]] | join(" ")' "$TMP/run-state")" "0o400 0o400"
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
[[ -z "$(find "$SCANS/workspaces" -name 'relay-hosts' -o -name 'relay-command.json')" ]] && ok "fichiers hosts et commande retirés" || ko "fichier hosts ou commande laissé"
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
import json
json.dump([sys.executable, "-I", sys.argv[4], sys.argv[5], sys.argv[6]], open(sys.argv[7], "w"))
g["main"].__globals__.update(SOCKET=sys.argv[2], TOKEN=sys.argv[3], COMMAND=sys.argv[7])
sys.exit(g["main"](["bridge.py"]))' "$BRIDGE" "$B/relay.sock" "$B/token" "$B/tool.py" "$1" "$BPORT" "$B/command.json"
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
g["main"].__globals__.update(TOKEN=sys.argv[2], COMMAND=sys.argv[3])
sys.exit(g["main"](["bridge.py"]))' "$BRIDGE" "$B/absent" "$B/command.json" 2> "$B/err"; rc=$?
set -e
expect "pont : jeton absent → 70, outil non lancé" "$rc $(cat "$B/err")" "70 ai-relay bridge: relay token missing"
for bad in '[]' '[""]' '"true"' '["true", 3]' '{' ; do
	printf '%s' "$bad" > "$B/bad-command.json"
	set +e
	python3 -I -B -c 'import runpy, sys
g = runpy.run_path(sys.argv[1], run_name="bridge")
g["main"].__globals__.update(TOKEN=sys.argv[2], COMMAND=sys.argv[3])
sys.exit(g["main"](["bridge.py"]))' "$BRIDGE" "$B/token" "$B/bad-command.json" 2> "$B/err"; rc=$?
	set -e
	expect "pont : commande invalide ($bad) → 70, outil non lancé" "$rc $(cat "$B/err")" "70 ai-relay bridge: tool command missing or invalid"
done
set +e
python3 -I -B "$BRIDGE" true 2> /dev/null; rc=$?
set -e
expect "pont : commande en argument refusée → 70" "$rc" 70
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

# --- 8. K2 PR-Agent et K4 Fraim : diff de la PR, convertisseurs, outils ---------------------------
# 8.1 Runner : scan.pr_diff hors PR (archive, aucun commit de base).
python3 - "$T/var/lib/scanoria/modules/installed.json" <<'EOF'
import json, sys
reg = json.load(open(sys.argv[1]))
for mid, mode in (("ia-diff", "required"), ("ia-diff-opt", "optional")):
    e = json.loads(json.dumps(reg["modules"]["ia-faux"]))
    e["manifest"]["id"] = mid
    e["manifest"]["scan"]["pr_diff"] = mode
    e.update(enabled=True, status="healthy")
    reg["modules"][mid] = e
json.dump(reg, open(sys.argv[1], "w"))
EOF
id=$(uuid); drop "$id" "$(job "$id" '[{"id": "ia-diff", "version": "1.0.0"}, {"id": "ia-diff-opt", "version": "1.0.0"}]')"
: > "$TMP/podman.log"; run_runner
expect "pr_diff required hors PR : skipped, avec sa raison" "$(mod "$id" ia-diff | jq -r '.status + " " + .error.code + " " + .error.class + " " + .error.message')" \
	"skipped E_PR_DIFF_UNAVAILABLE input not a pull request analysis: module not run"
# Le relais de l'essai est arrêté (section 5) : le module optionnel va jusqu'à la vérification du relais.
expect "pr_diff optional hors PR : jamais écarté pour le diff, aucun /pr.diff" "$(mod "$id" ia-diff-opt | jq -r '.status + " " + .error.code') $(grep -c '/pr.diff' "$TMP/podman.log")" "skipped E_RELAY_UNAVAILABLE 0"
expect "pr_diff : raison si la base manque ou si le diff est trop gros" "$(py 'from scanoria import runner
b = "a" * 40
print(runner.pr_diff_reason({"pr_base": b}, None)); print(runner.pr_diff_reason({"pr_base": b}, "too-large"))
print(runner.pr_base({"pr_base": "-x"}), runner.prdiff_mode({"scan": {"pr_diff": "toujours"}}))' | tr '\n' '|')" \
	"the base commit of the pull request could not be fetched: module not run|the pull request diff exceeds 4 MiB: module not run|None None|"
expect "pr_diff : jamais mis en cache (V4)" "$(py 'from scanoria import resultcache
m = {"id": "x", "image": "r/x@sha256:" + "0" * 64, "scan": {"network": "none", "pr_diff": "optional"}}
m2 = dict(m, scan={"network": "none"})
args = ({"cache": True, "source": {"kind": "git"}}, {"history": False, "command": ["x"]}, [], "t" * 40, None, False)
print(resultcache.key_for(args[0], m, *args[1:]), resultcache.key_for(args[0], m2, *args[1:]) is not None)')" "None True"

# 8.2 Diff de la PR calculé par fetch.FETCH_SCRIPT, avec le vrai git (chemins du conteneur remplacés).
G="$TMP/git"; mkdir -p "$G/forge" "$G/tt"
(
	set -e
	git init -q -b main "$G/forge/depot" && cd "$G/forge/depot"
	git config user.email essai@exemple.test && git config user.name essai
	echo un > base.txt && printf '*.txt diff=piege\n' > .gitattributes && git add -A && git commit -qm base
	git checkout -q -b pr && echo deux >> base.txt && echo 'print(1)' > app.py && git add -A && git commit -qm pr
	# Base qui a avancé depuis l'ouverture de la PR (divergence) ; historique sans lien.
	git checkout -q -b avance main && echo 'propre à main' > main.txt && git add -A && git commit -qm avance
	git checkout -q --orphan orphelin && git rm -rqf . && echo seul > seul.txt && git add -A && git commit -qm orphelin
) > /dev/null
BASE=$(git -C "$G/forge/depot" rev-parse main); HEAD_C=$(git -C "$G/forge/depot" rev-parse pr)
AVANCE=$(git -C "$G/forge/depot" rev-parse avance); ORPHELIN=$(git -C "$G/forge/depot" rev-parse orphelin)
cat > "$TMP/fetch-harness.py" <<'EOF'
import json, os, subprocess, sys
sys.path.insert(0, sys.argv[1])
from scanoria import fetch
tt, mirror, src, prd, url, ref, want, base, limit = sys.argv[2:11]
script = (fetch.FETCH_SCRIPT.replace("-gt %d" % fetch.PR_DIFF_MAX_BYTES, "-gt " + limit)
          .replace("head -c %d" % (fetch.PR_DIFF_MAX_BYTES + 1), "head -c %d" % (int(limit) + 1)))
for i, cpath in enumerate(("/tmp/", "/mirror", "/src", "/git", "/pr/")):
    script = script.replace(cpath, "\x00%d\x00" % i)
for i, real in enumerate((tt + "/", mirror, src, src + "-git", prd + "/")):
    script = script.replace("\x00%d\x00" % i, real)
env, _ = fetch.git_env(None)
n = int(env["GIT_CONFIG_COUNT"])
# Pilote de diff piégé du dépôt (.gitattributes) : jamais lancé (--no-ext-diff, --no-textconv).
extra = {"protocol.file.allow": "always", "diff.piege.command": "touch " + tt + "/piege-diff",
         "diff.piege.textconv": "touch " + tt + "/piege-textconv"}
for i, (k, v) in enumerate(extra.items()):
    env["GIT_CONFIG_KEY_%d" % (n + i)], env["GIT_CONFIG_VALUE_%d" % (n + i)] = k, v
env.update({"GIT_CONFIG_COUNT": str(n + len(extra)), "PATH": os.environ["PATH"], "HOME": tt})
os.makedirs(src, exist_ok=True); os.makedirs(prd, exist_ok=True)
subprocess.run(["git", "init", "-q", "--bare", mirror], check=True)
r = subprocess.run(["/bin/sh", "-c", script, "git-fetch", url, ref, want, "shallow", "k" * 16, base],
                   env=env, capture_output=True, text=True)
print(json.dumps({"rc": r.returncode, "out": r.stdout, "err": r.stderr[-2000:]}))
EOF
prfetch() { # base limite
	rm -rf "$G/m" "$G/s" "$G/s-git" "$G/p"
	python3 -I -B "$TMP/fetch-harness.py" "$PYLIB" "$G/tt" "$G/m" "$G/s" "$G/p" "file://$G/forge/depot" pr "$HEAD_C" "$1" "$2"
}
R=$(prfetch "$BASE" 4194304)
expect "diff de PR : récupération réussie, base récupérée à son tour" "$(jq -r .rc <<< "$R") $(jq -r .out <<< "$R" | grep -c '^scanoria=pr-diff$')" "0 1"
grep -q '^+++ b/app.py$' "$G/p/pr.diff" && grep -q '^+deux$' "$G/p/pr.diff" && ok "diff de PR : base → tête, fichiers ajoutés et modifiés" || ko "diff de PR : contenu inattendu"
[[ ! -e "$G/tt/piege-diff" && ! -e "$G/tt/piege-textconv" ]] && ok "diff de PR : pilote de diff du dépôt jamais lancé" || ko "diff de PR : pilote de diff lancé"
R=$(prfetch "$BASE" 10)
expect "diff de PR trop gros : non transmis" "$(jq -r .out <<< "$R" | grep -c '^scanoria=pr-diff-too-large$') $([[ -e "$G/p/pr.diff" || -e "$G/p/pr.diff.tmp" ]] && echo laissé || echo absent)" "1 absent"
R=$(prfetch "$AVANCE" 4194304)
expect "diff de PR, base divergente en clone superficiel : historique approfondi, point de divergence trouvé" "$(jq -r .rc <<< "$R") $(jq -r .out <<< "$R" | grep -c '^scanoria=pr-diff$')" "0 1"
grep -q '^+++ b/app.py$' "$G/p/pr.diff" && ! grep -q 'main.txt' "$G/p/pr.diff" && ok "diff de PR : seulement les changements de la PR, jamais l'inverse de ceux de la base" || ko "diff de PR : base divergente mal traitée"
R=$(prfetch "$ORPHELIN" 4194304)
expect "base sans ancêtre commun : récupération réussie, aucun diff" "$(jq -r .rc <<< "$R") $(jq -r .out <<< "$R" | grep -c '^scanoria=pr-no-merge-base$') $([[ -e "$G/p/pr.diff" ]] && echo laissé || echo absent)" "0 1 absent"
R=$(prfetch "$(printf 'b%.0s' {1..40})" 4194304)
expect "base introuvable : récupération réussie quand même, sans diff" "$(jq -r .rc <<< "$R") $(jq -r .out <<< "$R" | grep -c '^scanoria=pr-base-missing$')" "0 1"
R=$(prfetch "" 4194304)
expect "hors PR : aucun diff calculé" "$(jq -r .out <<< "$R" | grep -c '^scanoria=pr-')" 0

# 8.3 Convertisseurs (sorties enregistrées et entrées piégées).
PA="$ROOT/src/rootfs/usr/lib/scanoria/scan-tools/pr-agent/pragent_scan.py"
FR="$ROOT/src/rootfs/usr/lib/scanoria/scan-tools/fraim/fraim_scan.py"
expect "PR-Agent : sortie native → SARIF enregistré" "$(python3 -I -B -c 'import json, runpy, sys
g = runpy.run_path(sys.argv[1]); d = sys.argv[2]
doc = g["convert"](json.load(open(d + "/tests/native-review.json")), json.load(open(d + "/tests/native-describe.json")),
                   g["diff_files"](open(d + "/testbed/pr.diff").read()))
print(doc == json.load(open(d + "/tests/recorded.sarif")))' "$PA" "$ROOT/modules/pr-agent")" True
expect "PR-Agent : chemins piégés écartés, textes nettoyés, 50 points au plus, « No » sans préoccupation" "$(python3 -I -B -c 'import json, runpy, sys
g = runpy.run_path(sys.argv[1])
issues = [{"relevant_file": p, "issue_header": "h\x00\x07", "issue_content": "c" * 9000, "start_line": 9, "end_line": 2}
          for p in ("../etc/passwd", "/etc/passwd", "a/./b.py", "hors-diff.py", "b/app.py")] + [{"relevant_file": "app.py", "issue_header": "x", "start_line": "4"}] * 60
doc = g["convert"]({"review": {"key_issues_to_review": issues, "security_concerns": "No", "score": 500,
                               "estimated_effort_to_review_[1-5]": "3, because"}}, {"type": ["Bug fix", 3], "title": "t"}, {"app.py"})
r = doc["runs"][0]
locs = [x.get("locations", [{}])[0].get("physicalLocation", {}).get("artifactLocation", {}).get("uri") for x in r["results"][:6]]
print(len(r["results"]), locs, r["results"][0]["message"]["text"][:3], len(r["results"][0]["message"]["text"]) <= 4100,
      r["results"][4]["locations"][0]["physicalLocation"]["region"], [x["ruleId"] for x in r["results"]].count("pr-agent/security-concern"),
      r["properties"]["scanoria/pr-agent"])' "$PA")" \
	"50 [None, None, None, None, 'app.py', 'app.py'] h : True {'startLine': 9} 0 {'version': '1.0.0', 'effort': 3, 'description': {'title': 't', 'type': 'Bug fix'}}"
cat > "$TMP/quoted.diff" <<'EOF'
+++ "b/r\303\251sum\303\251 \"x\".py"
+++ b/simple.py
+++ /dev/null
EOF
expect "PR-Agent : chemins cités par git reconnus, aucun chemin accepté sans en-tête de fichier" "$(python3 -I -B -c 'import runpy, sys
g = runpy.run_path(sys.argv[1])
print(sorted(g["diff_files"](open(sys.argv[2], encoding="utf-8").read())), g["clean_path"]("app.py", set()))' "$PA" "$TMP/quoted.diff")" \
	"['résumé \"x\".py', 'simple.py'] None"
expect "Fraim : sortie native → SARIF enregistré" "$(python3 -I -B -c 'import json, runpy, sys
g = runpy.run_path(sys.argv[1]); d = sys.argv[2]
res, rules = g["convert"]([tuple(x) for x in json.load(open(d + "/tests/native-results.json"))], "/src")
doc = g["document"](res, rules, {"version": g["VERSION"], "workflows": ["code", "iac", "risk_flagger"], "failed": [],
                                 "llm_calls": {"ok": 4, "failed": 0}, "partial": False, "pr_risk": g["risk_level"](res)})
print(doc == json.load(open(d + "/tests/recorded.sarif")))' "$FR" "$ROOT/modules/fraim")" True
expect "Fraim : chemins hors des sources écartés, gravité bornée, indicateur de risque" "$(python3 -I -B -c 'import runpy, sys
g = runpy.run_path(sys.argv[1])
loc = lambda u: [{"physicalLocation": {"artifactLocation": {"uri": u}, "region": {"startLine": 0, "endLine": -1}}}]
found = [("code", {"level": "bizarre", "message": {"text": "m\x00"}, "locations": loc("file:///src/a.py") + loc("/autre/b.py") + loc("../c.py"),
                   "properties": {"type": "T", "confidence": 99}}),
         ("risk_flagger", {"level": "error", "message": {"text": "r"}, "properties": {"risk_type": "Database Changes", "risk_severity": "critical"}}),
         ("risk_flagger", {"level": "note", "message": {"text": "r2"}, "properties": {"risk_type": "X", "risk_severity": "énorme"}}), "pas un dict"]
res, rules = g["convert"](found, "/src")
print([r["ruleId"] for r in res], res[0]["level"], res[0]["properties"], res[0]["locations"], res[0]["message"]["text"],
      [r["properties"]["severity"] for r in res], g["risk_level"](res), [r["id"] for r in rules])' "$FR")" \
	"['fraim/code', 'fraim/risk-flagger', 'fraim/risk-flagger'] warning {'severity': 'medium', 'tags': ['ai', 'code'], 'type': 'T'} [{'physicalLocation': {'artifactLocation': {'uri': 'a.py'}}}] T : m ['medium', 'critical', 'low'] critical ['fraim/code', 'fraim/risk-flagger']"

# 8.4 Outils lancés de bout en bout, avec des paquets pr_agent, fraim et litellm de substitution.
STUB="$TMP/stubs-py"; mkdir -p "$STUB/pr_agent" "$STUB/fraim/core/workflows" "$STUB/fraim/workflows/code" "$STUB/fraim/workflows/iac" "$STUB/fraim/inputs" "$STUB/litellm"
touch "$STUB/pr_agent/__init__.py" "$STUB/fraim/__init__.py" "$STUB/fraim/core/__init__.py" "$STUB/fraim/core/workflows/__init__.py" \
	"$STUB/fraim/workflows/__init__.py" "$STUB/fraim/workflows/code/__init__.py" "$STUB/fraim/workflows/iac/__init__.py" "$STUB/fraim/inputs/__init__.py"
cat > "$STUB/pr_agent/cli.py" <<'EOF'
import json, os
def run(inargs):
    # Substitut de pr_agent.cli.run : rend la réponse préparée de la commande, note l'environnement.
    with open(os.environ["ESSAI_LOG"], "a") as f:
        f.write(json.dumps({"args": inargs, "model": os.environ.get("CONFIG__MODEL"), "key": os.environ.get("OPENAI__KEY"),
                            "base": os.environ.get("OPENAI__API_BASE"), "extra": os.environ.get("PR_AGENT_EXTRA_CONFIG_URL"),
                            "cwd": os.getcwd()}) + "\n")
    cmd, out = inargs[-1], inargs[inargs.index("--json-output") + 1]
    src = os.environ.get("ESSAI_" + cmd.upper())
    if src == "raise":
        raise RuntimeError("relay down")
    if src:
        with open(src) as i, open(out, "w") as o:
            o.write(i.read())
EOF
cat > "$STUB/litellm/__init__.py" <<'EOF'
import os
async def acompletion(**kw):
    if os.environ.get("ESSAI_LLM") == "down":
        raise ConnectionError("relay down")
    return {"ok": True}
EOF
cat > "$STUB/fraim/workflows/code/workflow.py" <<'EOF'
FILE_PATTERNS = ["*.py"]
EOF
cat > "$STUB/fraim/workflows/iac/workflow.py" <<'EOF'
FILE_PATTERNS = ["*.tf"]
EOF
cat > "$STUB/fraim/inputs/git_diff.py" <<'EOF'
class GitDiff:
    def _git_repo(self):
        raise RuntimeError("git must not run in the container")
    def _git_diff(self, repo):
        raise RuntimeError("git must not run in the container")
EOF
cat > "$STUB/fraim/core/workflows/discovery.py" <<'EOF'
import dataclasses, json, os
import litellm
from fraim.inputs.git_diff import GitDiff

@dataclasses.dataclass
class Opts:
    location: str = "."
    model: str = ""
    temperature: float = 0
    confidence: int = 7
    output: str = ""
    max_concurrent_chunks: int = 5
    globs: list | None = None
    diff: bool = False
    pr_url: str = ""
    approver: str = ""
    slack_webhook_url: str = ""
    no_gh_comment: bool = False

class R:
    def __init__(self, d): self.d = d
    def model_dump(self, **kw): return self.d

def make(name):
    class W:
        @classmethod
        def options(cls): return Opts
        def __init__(self, args): self.args = args
        async def run(self):
            with open(os.environ["ESSAI_LOG"], "a") as f:
                f.write(json.dumps({"workflow": name, "args": dataclasses.asdict(self.args)}) + "\n")
            if os.environ.get("ESSAI_FAIL") == name:
                raise RuntimeError("boom")
            try:
                await litellm.acompletion(model=self.args.model)
            except ConnectionError:
                return []      # Fraim saute le morceau en silence
            diff = None
            if self.args.diff:
                g = GitDiff(); diff = g._git_diff(g._git_repo())
            return [R({"message": {"text": name + (" diff=%d" % len(diff) if diff else "")}, "level": "error",
                       "locations": [{"physicalLocation": {"artifactLocation": {"uri": self.args.location + "/app.py"},
                                                           "region": {"startLine": 1, "endLine": 1}}}],
                       "properties": {"type": "T", "risk_type": "Database Changes", "risk_severity": "high", "confidence": 8}})]
    return W

def discover_workflows():
    return {n: make(n) for n in ("code", "iac", "risk_flagger")}
EOF
ESS="$TMP/essai-k"; mkdir -p "$ESS"
tool() { # outil args… (environnement de l'essai déjà posé)
	PYTHONPATH="$STUB" TMPDIR="$ESS" SCANORIA_OUT_DIR="$ESS" ESSAI_LOG="$ESS/log.jsonl" python3 -B "$@" 2> "$ESS/err"
}
cp "$ROOT/modules/pr-agent/tests/native-review.json" "$ESS/review.json"; cp "$ROOT/modules/pr-agent/tests/native-describe.json" "$ESS/describe.json"
: > "$ESS/log.jsonl"; set +e
SCANORIA_PR_DIFF="$ROOT/modules/pr-agent/testbed/pr.diff" OPENAI_BASE_URL=https://ai-relay.exemple.test:8443/v1 OPENAI_API_KEY=scr_essai \
	PR_AGENT_EXTRA_CONFIG_URL=https://config.exemple.test/x.toml ESSAI_REVIEW="$ESS/review.json" ESSAI_DESCRIBE="$ESS/describe.json" \
	tool "$PA" "$ESS/pa.sarif"; rc=$?; set -e
expect "PR-Agent : review et describe sur le diff seul, SARIF écrit" "$rc $(jq -c '[.runs[0].results[].ruleId]' "$ESS/pa.sarif" 2> /dev/null)" '0 ["pr-agent/key-issue","pr-agent/security-concern"]'
expect "PR-Agent : modèle de l'appliance par le relais, jeton du pont, aucune configuration distante" \
	"$(jq -sc '[.[] | [.args[0], .args[-1], .model, .key, .base, .extra, (.cwd | startswith($e))]]' --arg e "$ESS/pr-agent-" "$ESS/log.jsonl")" \
	'[["--diff-file","review","openai/scanoria","scr_essai","https://ai-relay.exemple.test:8443/v1",null,true],["--diff-file","describe","openai/scanoria","scr_essai","https://ai-relay.exemple.test:8443/v1",null,true]]'
set +e
SCANORIA_PR_DIFF="$ESS/absent.diff" tool "$PA" "$ESS/pa2.sarif"; rc1=$?
SCANORIA_PR_DIFF="$ROOT/modules/pr-agent/testbed/pr.diff" ESSAI_REVIEW=raise ESSAI_DESCRIBE="$ESS/describe.json" tool "$PA" "$ESS/pa2.sarif"; rc2=$?
tool "$PA"; rc3=$?
set -e
expect "PR-Agent : sans diff ou sans revue → 3 (skipped), usage → 2, aucun SARIF" "$rc1 $rc2 $rc3 $([[ -e "$ESS/pa2.sarif" ]] && echo écrit || echo absent)" "3 3 2 absent"
set +e; tool "$PA" "$TMP/ailleurs.sarif"; ra=$?; tool "$PA" "$ESS/../x.sarif"; rb=$?; tool "$FR" "$ESS/src" "$ESS/x.json"; rc=$?; set -e
expect "PR-Agent, Fraim : sortie hors du répertoire de sortie, remontée ou mauvais nom refusée (usage)" "$ra $rb $rc" "2 2 2"
mkdir -p "$ESS/src" && printf 'app.py\ninfra/main.tf\n../hors.py\n' > "$ESS/changed.txt"
: > "$ESS/log.jsonl"; set +e
SCANORIA_PR_DIFF="$ROOT/modules/fraim/testbed/pr.diff" SCANORIA_CHANGED_FILES="$ESS/changed.txt" GITHUB_TOKEN=ghp_essai \
	tool "$FR" "$ESS/src" "$ESS/fr.sarif"; rc=$?; set -e
expect "Fraim : code, iac et risk_flagger, SARIF écrit, indicateur de risque" "$rc $(jq -c '[.runs[0].results[].ruleId], .runs[0].properties["scanoria/fraim"].pr_risk' "$ESS/fr.sarif" | tr '\n' ' ')" \
	'0 ["fraim/code","fraim/iac","fraim/risk-flagger"] "high" '
expect "Fraim : fichiers modifiés seulement, diff lu dans le fichier, aucune URL de PR ni webhook" \
	"$(jq -sc '[.[] | [.workflow, .args.globs, .args.diff, .args.pr_url, .args.slack_webhook_url, .args.no_gh_comment, .args.model]]' "$ESS/log.jsonl")" \
	'[["code",["app.py"],false,"","",false,"openai/scanoria"],["iac",["infra/main.tf"],false,"","",false,"openai/scanoria"],["risk_flagger",null,true,"","",true,"openai/scanoria"]]'
expect "Fraim : chemins relatifs aux sources" "$(jq -r '[.runs[0].results[].locations[0].physicalLocation.artifactLocation.uri] | unique | join(",")' "$ESS/fr.sarif")" app.py
printf 'README.md\n' > "$ESS/changed.txt"; : > "$ESS/log.jsonl"; set +e
SCANORIA_CHANGED_FILES="$ESS/changed.txt" tool "$FR" "$ESS/src" "$ESS/fr2.sarif"; rc1=$?
set -e
expect "Fraim : PR sans fichier concerné → rien à analyser, module écarté (3), aucun workflow" "$rc1 $([[ -e "$ESS/fr2.sarif" ]] && echo écrit || echo absent) $(wc -l < "$ESS/log.jsonl")" "3 absent 0"
set +e
ESSAI_LLM=down tool "$FR" "$ESS/src" "$ESS/fr3.sarif"; rc2=$?
set -e
expect "Fraim : relais injoignable → 3 (skipped), jamais « aucun résultat »" "$rc2 $([[ -e "$ESS/fr3.sarif" ]] && echo écrit || echo absent) $(cat "$ESS/err")" \
	"3 absent fraim: every call to the AI relay failed"
set +e
ESSAI_FAIL=code tool "$FR" "$ESS/src" "$ESS/fr4.sarif"; rc3=$?
set -e
expect "Fraim : un workflow en échec n'empêche pas les autres" "$rc3 $(jq -c '.runs[0].properties["scanoria/fraim"] | [.workflows, .failed]' "$ESS/fr4.sarif")" '0 [["iac"],["code"]]'

printf '\n%d réussis, %d échoués\n' "$PASS" "$FAIL"
[[ $FAIL -eq 0 ]]
