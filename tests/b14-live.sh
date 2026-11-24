#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Vincent Tisseront
#
# b14-live — scanoria-runner avec le vrai podman et le vrai nftables (job CI
# runner-live, machine de test root jetable). Le runner tourne en mode test sur
# une racine temporaire ; podman et nft sont les vrais.
# Cas :
#   - dépôt Git servi en HTTPS par un petit serveur local (git http-backend,
#     certificat d'une AC de test, authentification par jeton) : clone dans le
#     conteneur git-fetch sur le réseau scanoria-fetch, règle nftables posée
#     puis retirée, historique complet ; gitleaks trouve un faux secret qui
#     n'existe plus que dans l'historique ; SARIF publié et valide ;
#   - jeton absent des résultats ; espace de travail supprimé ; aucun conteneur
#     laissé ;
#   - réseau coupé pour le scanner (une sonde ne joint pas le serveur) ;
#   - réseau de récupération fermé hors des autorisations du runner ;
#   - archive téléversée analysée par gitleaks.
# Les faux secrets sont tirés au hasard à l'exécution (jamais dans le dépôt).
# Dépendances : bash, python3, python3-yaml, jq, openssl, git, curl, podman, nft (root).

# shellcheck disable=SC2016,SC2015
set -euo pipefail
export PYTHONDONTWRITEBYTECODE=1

[[ "$(id -u)" -eq 0 ]] || { echo "b14-live : root requis (podman et nftables réels)" >&2; exit 2; }
for t in python3 jq openssl git curl podman nft; do command -v "$t" > /dev/null || { echo "outil manquant : $t" >&2; exit 2; }; done

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
RUNNER="$ROOT/src/rootfs/usr/sbin/scanoria-runner"
TMP=$(mktemp -d)
SERVER_PID=
cleanup() {
	[[ -n "$SERVER_PID" ]] && kill "$SERVER_PID" 2> /dev/null || true
	nft delete table inet scanoria_fetch 2> /dev/null || true
	podman network rm -f scanoria-fetch > /dev/null 2>&1 || true
	rm -rf "$TMP"
}
trap cleanup EXIT

PASS=0
FAIL=0
ok() { PASS=$((PASS + 1)); printf 'ok   %s\n' "$1"; }
ko() { FAIL=$((FAIL + 1)); printf 'FAIL %s\n' "$1"; }
expect() {
	if [[ "$2" == "$3" ]]; then ok "$1"; else ko "$1 (obtenu « $2 », attendu « $3 »)"; fi
}
yq() { python3 -c 'import json, sys, yaml; print(json.dumps(yaml.safe_load(open(sys.argv[1], encoding="utf-8"))))' "$1"; }

T="$TMP/root"
STUBS="$TMP/stubs"
SCANS="$T/var/lib/scanoria/scans"
mkdir -p "$T/var/lib/scanoria/modules" "$T/var/lib/scanoria/uploads" "$T/run/scanoria" "$T/proc" \
	"$T/etc/ssl/certs" "$STUBS"
cp /proc/meminfo "$T/proc/meminfo"
grep '^processor' /proc/cpuinfo > "$T/proc/cpuinfo"
ln -s "$(command -v podman)" "$STUBS/podman"
ln -s "$(command -v nft)" "$STUBS/nft"
export SCANORIA_TEST_ROOT="$T" SCANORIA_TEST_BIN="$STUBS"
HOST_IP=$(ip -4 route get 192.0.2.1 | sed -n 's/.* src \([0-9.]*\).*/\1/p')
[[ -n "$HOST_IP" ]] || { echo "adresse de l'hôte introuvable" >&2; exit 2; }
export SCANORIA_TEST_RESOLVE="forge.exemple.test=$HOST_IP"
PORT=8443
echo "hôte de test : $HOST_IP:$PORT"

# --- Images et registre des modules -------------------------------------------------------
yq "$ROOT/modules/git-fetch/module.yaml" > "$TMP/git-fetch.json"
yq "$ROOT/modules/gitleaks/module.yaml" > "$TMP/gitleaks.json"
for m in git-fetch gitleaks; do podman pull -q "$(jq -r .image "$TMP/$m.json")" > /dev/null; done
GIT_IMAGE=$(jq -r .image "$TMP/git-fetch.json")
# Sonde : un « scanner » qui tente de joindre le serveur ; code 3 si le réseau est coupé.
jq --arg ip "$HOST_IP" --arg port "$PORT" '.id = "sonde" | .categories = ["lint"] | .requires.modules = []
	| .scan = {inputs: ["repo", "archive"], network: "none", timeout_s: 60, exit_codes_ok: [0],
	           command: ["/bin/sh", "-c", ("if wget -q -T 5 -O /dev/null --no-check-certificate https://" + $ip + ":" + $port + "/ 2>/tmp/e || grep -q \"401\\|403\" /tmp/e; then exit 0; else exit 3; fi"), "sonde", "/out/result.sarif"],
	           env: {}}' "$TMP/git-fetch.json" > "$TMP/sonde.json"
python3 - "$T/var/lib/scanoria/modules/installed.json" "$TMP" <<'EOF'
import json, sys
path, tmp = sys.argv[1:3]
reg = {"modules": {}, "operations": []}
for mid in ("git-fetch", "gitleaks", "sonde"):
    m = json.load(open("%s/%s.json" % (tmp, mid)))
    opts = {k: p["default"] for k, p in (m.get("options") or {}).get("properties", {}).items()}
    reg["modules"][mid] = {"manifest": m, "status": "healthy", "enabled": True, "options": opts}
json.dump(reg, open(path, "w"))
EOF

# --- Forge de test : dépôt servi en HTTPS ----------------------------------------------------
TOKEN="scn_$(head -c 64 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 40)"
FAKE="AKIA$(head -c 64 /dev/urandom | base32 | tr -dc 'A-Z2-7' | head -c 16)"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 1 \
	-subj "/CN=forge.exemple.test" -addext "subjectAltName=DNS:forge.exemple.test" \
	-keyout "$TMP/forge.key" -out "$TMP/forge.crt" 2> /dev/null
cp "$TMP/forge.crt" "$T/etc/ssl/certs/ca-certificates.crt"
W="$TMP/work"
git init -q -b main "$W"
git -C "$W" config user.name Scanoria
git -C "$W" config user.email b14@exemple.test
printf 'aws_access_key_id = %s\n' "$FAKE" > "$W/config.ini"
echo "# Dépôt de test" > "$W/README.md"
git -C "$W" add -A && git -C "$W" commit -qm "ajout de la configuration"
git -C "$W" rm -q config.ini && git -C "$W" commit -qm "retrait de la clé"
mkdir -p "$TMP/srv"
git clone -q --bare "$W" "$TMP/srv/depot.git"
COMMIT=$(git -C "$W" rev-parse HEAD)
cat > "$TMP/server.py" <<'EOF'
import base64, http.server, os, ssl, subprocess, sys
root, port, cert, key, token = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4], sys.argv[5]
want = "Basic " + base64.b64encode(("oauth2:" + token).encode()).decode()
class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        sys.stderr.write("forge: " + (fmt % args) + "\n")
    def do_GET(self):
        self.cgi()
    def do_POST(self):
        self.cgi()
    def cgi(self):
        if self.headers.get("Authorization", "") != want:
            self.send_response(401)
            self.send_header("WWW-Authenticate", 'Basic realm="forge"')
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        path, _, qs = self.path.partition("?")
        n = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(n) if n else b""
        env = {"GIT_PROJECT_ROOT": root, "GIT_HTTP_EXPORT_ALL": "1", "PATH_INFO": path, "QUERY_STRING": qs,
               "REQUEST_METHOD": self.command, "CONTENT_TYPE": self.headers.get("Content-Type", ""),
               "CONTENT_LENGTH": str(len(body)), "REMOTE_USER": "oauth2", "PATH": os.environ["PATH"]}
        if self.headers.get("Content-Encoding"):
            env["HTTP_CONTENT_ENCODING"] = self.headers["Content-Encoding"]
        if self.headers.get("Git-Protocol"):
            env["GIT_PROTOCOL"] = self.headers["Git-Protocol"]
        out = subprocess.run(["git", "http-backend"], input=body, env=env, capture_output=True).stdout
        sep = b"\r\n\r\n" if b"\r\n\r\n" in out else b"\n\n"
        head, _, rest = out.partition(sep)
        status, hdrs = 200, []
        for line in head.replace(b"\r\n", b"\n").split(b"\n"):
            k, _, v = line.decode().partition(":")
            if k.lower() == "status":
                status = int(v.strip().split()[0])
            elif k:
                hdrs.append((k, v.strip()))
        self.send_response(status)
        for k, v in hdrs:
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(rest)))
        self.end_headers()
        self.wfile.write(rest)
srv = http.server.ThreadingHTTPServer(("0.0.0.0", port), H)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(cert, key)
srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
srv.serve_forever()
EOF
python3 "$TMP/server.py" "$TMP/srv" "$PORT" "$TMP/forge.crt" "$TMP/forge.key" "$TOKEN" 2> "$TMP/server.log" &
SERVER_PID=$!
sleep 1
code=$(curl -s --cacert "$TMP/forge.crt" --resolve "forge.exemple.test:$PORT:$HOST_IP" -o /dev/null -w '%{http_code}' \
	"https://forge.exemple.test:$PORT/depot.git/info/refs?service=git-upload-pack" || true)
if [[ "$code" == 401 ]]; then ok "forge de test : HTTPS en service, authentification exigée"
else ko "forge de test : réponse $code"; cat "$TMP/server.log"; fi

# --- Outils --------------------------------------------------------------------------------
uuid() { python3 -c 'import uuid; print(uuid.uuid4())'; }
job() { # ID source-json modules-json
	jq -cn --arg id "$1" --arg sid "$(uuid)" --argjson src "$2" --argjson mods "$3" \
		'{schema: 1, id: $id, scan_id: $sid, created_at: "2026-11-24T10:00:00Z", source: $src, modules: $mods}'
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
GL=$(jq -c '{id: .id, version: .version}' "$TMP/gitleaks.json")
SRC=$(jq -cn --arg t "$TOKEN" --arg port "$PORT" \
	'{kind: "git", url: ("https://forge.exemple.test:" + $port + "/depot.git"), ref: "main", history: "shallow", credential: {kind: "token", token: $t}}')

"$RUNNER" --once 2> /dev/null || true   # arborescence

# --- 1. Dépôt Git : clone confiné + gitleaks sur l'historique --------------------------------
id=$(uuid)
drop "$id" "$(job "$id" "$SRC" "[$GL]")"
run_runner
R=$(res "$id")
echo "$R" | jq -c '{status, error, source, modules: [.modules[] | {id, status, error, stats, outputs}]}'
expect "git : tâche réussie" "$(jq -r .status <<< "$R")" ok
expect "git : commit cloné" "$(jq -r .source.commit <<< "$R")" "$COMMIT"
expect "git : historique complet (gitleaks history: full)" "$(jq -r .source.history <<< "$R")" full
expect "git : gitleaks ok" "$(jq -r '.modules[0].status' <<< "$R")" ok
SARIF="$SCANS/results/$id/$(jq -r '.modules[0].outputs.sarif' <<< "$R")"
if [[ -s "$SARIF" ]] && jq -e '[.runs[].results[] | select(.ruleId == "aws-access-token")] | length >= 1' "$SARIF" > /dev/null; then
	ok "git : faux secret trouvé dans l'historique (aws-access-token)"
else
	ko "git : faux secret non trouvé dans l'historique"
	sed 's/^/     /' "$SCANS/results/$id/gitleaks/module.log" 2> /dev/null | tail -n 20
fi
grep -rqF -- "$FAKE" "$SCANS/results/$id" && ko "git : valeur du faux secret publiée" || ok "git : valeur du faux secret absente des résultats (--redact)"
grep -rqF -- "$TOKEN" "$SCANS/results/$id" && ko "git : jeton dans les résultats" || ok "git : jeton absent des résultats"
jq -e '.modules[0].stats.duration_ms > 0' <<< "$R" > /dev/null && ok "git : durée mesurée" || ko "git : durée non mesurée"
jq -e '.modules[0].stats.peak_memory_mb >= 0' <<< "$R" > /dev/null && ok "git : mémoire mesurée (cgroup)" \
	|| echo "     (pic mémoire non relevé : cgroup indisponible sur cette machine)"
expect "git : espace de travail supprimé" "$(find "$SCANS/workspaces" -mindepth 1 | wc -l)" 0
expect "git : aucun conteneur laissé" "$(podman ps -a --format '{{.Names}}' | grep -c '^scanoria-' || true)" 0
expect "nftables : autorisation retirée après le clone" \
	"$( (nft -j list set inet scanoria_fetch allow4 || echo '{"nftables": []}') | jq '[.nftables[] | select(.set) | .set.elem // [] | length] | add // "table absente"')" 0
nft list table inet scanoria_fetch 2>&1 | sed 's/^/     /' || true

# --- 2. Jeton faux : authentification refusée --------------------------------------------
id=$(uuid)
drop "$id" "$(job "$id" "$(jq -c '.credential.token = "scn_faux"' <<< "$SRC")" "[$GL]")"
run_runner
expect "jeton refusé : E_SOURCE_AUTH (input)" "$(res "$id" | jq -r '.error.code + "/" + .error.class')" "E_SOURCE_AUTH/input"

# --- 3. Réseau coupé pour le scanner ------------------------------------------------------
id=$(uuid)
drop "$id" "$(job "$id" "$SRC" '[{"id": "sonde", "version": "2.54.1"}]')"
run_runner
expect "scanner : aucun accès réseau (la sonde ne joint pas la forge)" \
	"$(res "$id" | jq -r '.modules[0] | .status + "/" + (.exit_code | tostring)')" "error/3"

# --- 4. Réseau de récupération fermé hors autorisation -------------------------------------
rc=0
podman run --rm --network scanoria-fetch --ip 10.89.250.251 --dns=none --cap-drop=ALL --user 65534:65534 \
	--entrypoint '["/bin/sh"]' "$GIT_IMAGE" -c "wget -q -T 5 -O /dev/null --no-check-certificate https://$HOST_IP:$PORT/ 2> /tmp/e || grep -q '401' /tmp/e" \
	> /dev/null 2>&1 || rc=$?
[[ "$rc" -ne 0 ]] && ok "réseau scanoria-fetch : forge injoignable sans autorisation du runner" \
	|| ko "réseau scanoria-fetch : forge joignable sans autorisation"

# --- 5. Archive téléversée ----------------------------------------------------------------
up=$(uuid)
mkdir -p "$T/var/lib/scanoria/uploads/$up" "$TMP/arch"
printf 'aws_access_key_id = %s\n' "$FAKE" > "$TMP/arch/config.ini"
tar -C "$TMP/arch" -czf "$T/var/lib/scanoria/uploads/$up/source.tar.gz" .
id=$(uuid)
drop "$id" "$(job "$id" "{\"kind\": \"archive\", \"upload_id\": \"$up\"}" "[$GL]")"
run_runner
R=$(res "$id")
expect "archive : gitleaks ok" "$(jq -r '.status + "/" + .modules[0].status + "/" + .source.history' <<< "$R")" ok/ok/none
SARIF="$SCANS/results/$id/$(jq -r '.modules[0].outputs.sarif' <<< "$R")"
jq -e '[.runs[].results[] | select(.ruleId == "aws-access-token")] | length >= 1' "$SARIF" > /dev/null 2>&1 \
	&& ok "archive : faux secret trouvé" || ko "archive : faux secret non trouvé"
expect "archive : espace de travail supprimé" "$(find "$SCANS/workspaces" -mindepth 1 | wc -l)" 0

echo
echo "b14-live : $PASS réussis, $FAIL échoués"
[[ "$FAIL" -eq 0 ]]
