#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Vincent Tisseront
#
# b27-live — délais d'exécution de la 0.6 (chantier C) avec le vrai podman, le
# vrai nftables et le vrai git de l'image git-fetch (job CI execution-live,
# machine de test root jetable). Le runner tourne en mode test sur une racine
# temporaire, avec la mémoire réelle de la machine (/proc/meminfo copié).
# Cas :
#   - V2 : deux analyses successives du même projet ; la première crée le
#     miroir, la seconde ne récupère que les nouveaux objets ; une analyse d'un
#     commit déjà présent ne contacte pas la forge ; gitleaks lit l'historique
#     par les alternates du miroir (monté en lecture seule) ;
#   - V9 : sources en tmpfs, démonté en fin d'analyse ;
#   - V7 : mise à jour d'une base pendant une analyse : l'analyse en cours
#     garde sa version, la suivante prend la nouvelle ;
#   - V1 : image supprimée → erreur infra E_IMAGE_MISSING, puis reprise après
#     prefetch-images.
# Chronométrage : durées des récupérations imprimées dans le journal du job.
# Dépendances : bash, python3, python3-yaml, jq, openssl, git, curl, podman, nft (root).

# shellcheck disable=SC2016,SC2015
set -euo pipefail
export PYTHONDONTWRITEBYTECODE=1

[[ "$(id -u)" -eq 0 ]] || { echo "b27-live : root requis (podman, nftables et tmpfs réels)" >&2; exit 2; }
for t in python3 jq openssl git curl podman nft findmnt; do command -v "$t" > /dev/null || { echo "outil manquant : $t" >&2; exit 2; }; done

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
RUNNER="$ROOT/src/rootfs/usr/sbin/scanoria-runner"
PYLIB="$ROOT/src/rootfs/usr/lib/scanoria/py"
TMP=$(mktemp -d)
SERVER_PID=
cleanup() {
	[[ -n "$SERVER_PID" ]] && kill "$SERVER_PID" 2> /dev/null || true
	findmnt -rn -o TARGET | grep -F "$TMP/" | sort -r | xargs -r -n1 umount -l 2> /dev/null || true
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
now_ms() { date +%s%3N; }

T="$TMP/root"
STUBS="$TMP/stubs"
SCANS="$T/var/lib/scanoria/scans"
MIRRORS="$T/var/lib/scanoria/git-mirrors"
mkdir -p "$T/var/lib/scanoria/modules" "$T/var/lib/scanoria/catalog" "$T/run/scanoria" "$T/proc" "$T/etc/ssl/certs" "$STUBS"
cp /proc/meminfo "$T/proc/meminfo"
grep '^processor' /proc/cpuinfo > "$T/proc/cpuinfo"
for c in podman nft mount umount; do ln -s "$(command -v "$c")" "$STUBS/$c"; done
export SCANORIA_TEST_ROOT="$T" SCANORIA_TEST_BIN="$STUBS"
HOST_IP=$(ip -4 route get 192.0.2.1 | sed -n 's/.* src \([0-9.]*\).*/\1/p')
[[ -n "$HOST_IP" ]] || { echo "adresse de l'hôte introuvable" >&2; exit 2; }
export SCANORIA_TEST_RESOLVE="forge.exemple.test=$HOST_IP"
PORT=8444
echo "hôte de test : $HOST_IP:$PORT ; $(grep MemAvailable /proc/meminfo)"

# --- Images et registre des modules -------------------------------------------------------
yq "$ROOT/modules/git-fetch/module.yaml" > "$TMP/git-fetch.json"
yq "$ROOT/modules/gitleaks/module.yaml" > "$TMP/gitleaks.json"
for m in git-fetch gitleaks; do podman pull -q "$(jq -r .image "$TMP/$m.json")" > /dev/null; done
GL_IMAGE=$(jq -r .image "$TMP/gitleaks.json")
# Lecteur de base : lit /feeds/demo-db/version au début et à la fin (après une
# pause pendant laquelle le test remplace la base), et l'écrit dans le SARIF.
jq '.id = "lecteur-base" | .categories = ["sca"] | .requires.modules = [] | .requires.feeds = ["demo-db"]
	| .scan = {inputs: ["repo"], network: "none", timeout_s: 120, exit_codes_ok: [0], env: {},
	           command: ["/bin/sh", "-c", "a=$(cat /feeds/demo-db/version); sleep 12; b=$(cat /feeds/demo-db/version); printf \"{\\\"version\\\":\\\"2.1.0\\\",\\\"runs\\\":[{\\\"tool\\\":{\\\"driver\\\":{\\\"name\\\":\\\"lb\\\"}},\\\"results\\\":[{\\\"ruleId\\\":\\\"v-%s-%s\\\",\\\"message\\\":{\\\"text\\\":\\\"x\\\"}}]}]}\" \"$a\" \"$b\" > /out/result.sarif", "lecteur", "/src"]}' \
	"$TMP/git-fetch.json" > "$TMP/lecteur-base.json"
python3 - "$T/var/lib/scanoria/modules/installed.json" "$TMP" <<'EOF'
import json, sys
path, tmp = sys.argv[1:3]
reg = {"modules": {}, "operations": []}
for mid in ("git-fetch", "gitleaks", "lecteur-base"):
    m = json.load(open("%s/%s.json" % (tmp, mid)))
    opts = {k: p["default"] for k, p in (m.get("options") or {}).get("properties", {}).items()}
    reg["modules"][mid] = {"manifest": m, "status": "healthy", "enabled": True, "options": opts}
json.dump(reg, open(path, "w"))
EOF
# Index du catalogue installé (prefetch-images ne lit que les modules installés ici).
jq -n '{version: 12, modules: []}' > "$T/var/lib/scanoria/catalog/catalog-index.json"

# --- Forge de test : même serveur HTTPS que b14-live ----------------------------------------
TOKEN="scn_$(head -c 64 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 40)"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 1 \
	-subj "/CN=forge.exemple.test" -addext "subjectAltName=DNS:forge.exemple.test" \
	-keyout "$TMP/forge.key" -out "$TMP/forge.crt" 2> /dev/null
cp "$TMP/forge.crt" "$T/etc/ssl/certs/ca-certificates.crt"
sed -n "/^cat > \"\$TMP\/server.py\" <<'EOF'\$/,/^EOF\$/p" "$ROOT/tests/b14-live.sh" | sed '1d;$d' > "$TMP/server.py"
[[ -s "$TMP/server.py" ]] && ok "forge de test : serveur repris de b14-live" || ko "forge de test : serveur introuvable dans b14-live"
W="$TMP/work"
git init -q -b main "$W"
git -C "$W" config user.name Scanoria
git -C "$W" config user.email b27@exemple.test
for i in $(seq 1 300); do head -c 2048 /dev/urandom | base64 > "$W/f$i.txt"; done
mkdir -p "$W/node_modules/dep" && echo 'module.exports = 1' > "$W/node_modules/dep/index.js"
git -C "$W" add -A && git -C "$W" commit -qm "dépôt initial"
mkdir -p "$TMP/srv"
git clone -q --bare "$W" "$TMP/srv/depot.git"
python3 "$TMP/server.py" "$TMP/srv" "$PORT" "$TMP/forge.crt" "$TMP/forge.key" "$TOKEN" 2> "$TMP/server.log" &
SERVER_PID=$!
sleep 1

uuid() { python3 -c 'import uuid; print(uuid.uuid4())'; }
PROJ=$(uuid)
SRC=$(jq -cn --arg t "$TOKEN" --arg port "$PORT" \
	'{kind: "git", url: ("https://forge.exemple.test:" + $port + "/depot.git"), ref: "main", history: "shallow", credential: {kind: "token", token: $t}}')
job() { # ID modules-json [commit]
	jq -cn --arg id "$1" --arg sid "$(uuid)" --arg pid "$PROJ" --argjson src "$SRC" --argjson mods "$2" --arg c "${3:-}" \
		'{schema: 1, id: $id, scan_id: $sid, project_id: $pid, created_at: "2026-11-24T10:00:00Z",
		  source: ($src + (if $c == "" then {} else {commit: $c} end)), modules: $mods}'
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
objects() { git --git-dir="$MIRRORS/$PROJ.git" count-objects -v | awk '/^(count|in-pack):/ {s += $2} END {print s + 0}'; }
GL=$(jq -c '{id: .id, version: .version}' "$TMP/gitleaks.json")
LB=$(jq -c '{id: .id, version: .version}' "$TMP/lecteur-base.json")

"$RUNNER" --once 2> /dev/null || true   # arborescence

# --- 1. V2 et V9 : première analyse, miroir créé, sources en mémoire ------------------------
id=$(uuid)
drop "$id" "$(job "$id" "[$GL]")"
t0=$(now_ms); run_runner; t1=$(now_ms)
R=$(res "$id")
echo "$R" | jq -c '{status, error, source: (.source | del(.skipped)), modules: [.modules[] | {id, status, error, stats}]}'
expect "première analyse : réussie" "$(jq -r '.status + "/" + .modules[0].status' <<< "$R")" ok/ok
expect "première analyse : miroir créé" "$(jq -r .source.mirror <<< "$R")" created
expect "première analyse : sources en mémoire" "$(jq -r .source.workdir <<< "$R")" tmpfs
expect "première analyse : node_modules exclu" "$(jq -r '[.source.excluded[] | select(.pattern == "**/node_modules/**") | .count] | add' <<< "$R")" 1
expect "première analyse : historique complet lu par gitleaks" "$(jq -r .source.history <<< "$R")" full
[[ -f "$MIRRORS/$PROJ.git/HEAD" && ! -f "$MIRRORS/$PROJ.git/shallow" ]] && ok "miroir : dépôt nu complet" || ko "miroir : absent ou superficiel"
expect "tmpfs : démonté en fin d'analyse" "$(findmnt -rn -o TARGET | grep -cF "$SCANS/workspaces/" || true)" 0
expect "espace de travail supprimé" "$(find "$SCANS/workspaces" -mindepth 1 | wc -l)" 0
first=$(objects)
echo "chronométrage : première analyse (clone complet) $((t1 - t0)) ms, $first objets dans le miroir"

# Nouveau commit sur la forge : la seconde analyse ne récupère que les nouveaux objets.
echo "modifié" > "$W/f1.txt"
git -C "$W" commit -qam "petite modification"
git -C "$W" push -q "$TMP/srv/depot.git" main
C2=$(git -C "$W" rev-parse HEAD)
id=$(uuid)
drop "$id" "$(job "$id" "[$GL]")"
t0=$(now_ms); run_runner; t1=$(now_ms)
R=$(res "$id")
expect "seconde analyse : réussie sur le nouveau commit" "$(jq -r '.status + "/" + .source.commit' <<< "$R")" "ok/$C2"
expect "seconde analyse : miroir mis à jour" "$(jq -r .source.mirror <<< "$R")" fetched
second=$(objects)
[[ $((second - first)) -le 5 ]] && ok "seconde analyse : $((second - first)) objet(s) récupéré(s) sur $first" || ko "seconde analyse : $((second - first)) objets récupérés"
echo "chronométrage : seconde analyse (nouveaux objets seulement) $((t1 - t0)) ms"

# Commit déjà présent : la forge n'est pas contactée (serveur arrêté).
kill "$SERVER_PID"; wait "$SERVER_PID" 2> /dev/null || true; SERVER_PID=
id=$(uuid)
drop "$id" "$(job "$id" "[$GL]" "$C2")"
t0=$(now_ms); run_runner; t1=$(now_ms)
R=$(res "$id")
expect "commit présent : réussi forge arrêtée" "$(jq -r '.status + "/" + .source.mirror' <<< "$R")" ok/hit
echo "chronométrage : analyse d'un commit déjà présent $((t1 - t0)) ms"

# --- 2. V7 : base remplacée pendant une analyse ------------------------------------------
python3 -I -B - "$PYLIB" <<'EOF'
import os, sys
sys.path.insert(0, sys.argv[1])
from scanoria import feeds
feeds._dirs()
d = os.path.join(feeds.store_dir("demo-db"), "20261124T010000Z-00000001")
os.makedirs(d)
open(d + "/version", "w").write("un")
feeds._readable(d)
feeds.swap("demo-db", d)
EOF
id=$(uuid)
drop "$id" "$(job "$id" "[$LB]" "$C2")"
"$RUNNER" --once 2> "$TMP/runner-v7.err" &
RPID=$!
for _ in $(seq 1 60); do
	podman ps --format '{{.Names}}' | grep -q '^scanoria-scan-' && break
	sleep 0.5
done
sleep 2
python3 -I -B - "$PYLIB" <<'EOF'
import os, sys
sys.path.insert(0, sys.argv[1])
from scanoria import feeds
for n, v in (("20261124T020000Z-00000002", "deux"), ("20261124T030000Z-00000003", "trois")):
    d = os.path.join(feeds.store_dir("demo-db"), n)
    os.makedirs(d)
    open(d + "/version", "w").write(v)
    feeds._readable(d)
    feeds.prune("demo-db", feeds.swap("demo-db", d))
EOF
wait "$RPID" || true
R=$(res "$id")
SARIF="$SCANS/results/$id/$(jq -r '.modules[0].outputs.sarif' <<< "$R")"
expect "base remplacée en cours d'analyse : l'analyse garde sa version" "$(jq -r '.runs[0].results[0].ruleId' "$SARIF" 2> /dev/null)" v-un-un
expect "base : date de la version épinglée enregistrée" "$(jq -r '.modules[0].feeds[0].updated_at' <<< "$R")" 2026-11-24T01:00:00Z
expect "base : version montée enregistrée (G11)" "$(jq -r '.modules[0].feeds[0].revision' <<< "$R")" 20261124T010000Z-00000001
expect "base : bail rendu en fin d'analyse" "$(find "$T/var/lib/scanoria/feeds/.store/demo-db/.leases" -type f 2> /dev/null | wc -l)" 0
id=$(uuid)
drop "$id" "$(job "$id" "[$LB]" "$C2")"
run_runner
SARIF="$SCANS/results/$id/$(jq -r '.modules[0].outputs.sarif' "$SCANS/results/$id/result.json")"
expect "analyse suivante : nouvelle version" "$(jq -r '.runs[0].results[0].ruleId' "$SARIF" 2> /dev/null)" v-trois-trois

# --- 3. V1 : image supprimée, erreur infra, puis reprise après prefetch-images ----------------
podman rmi -f "$GL_IMAGE" > /dev/null
id=$(uuid)
drop "$id" "$(job "$id" "[$GL]" "$C2")"
run_runner
expect "image supprimée : E_IMAGE_MISSING (infra)" "$(res "$id" | jq -r '.modules[0].error.code + "/" + .modules[0].error.class')" E_IMAGE_MISSING/infra
out=$(python3 -I -B - "$PYLIB" <<'EOF'
import json, sys
sys.path.insert(0, sys.argv[1])
from scanoria import prefetch
class C:
    params = {}
    def left(self): return 900
print(json.dumps(prefetch.act_prefetch_images(C())))
EOF
)
echo "     prefetch-images : $out"
expect "prefetch-images : image de gitleaks récupérée" "$(jq -r '[.pulled[].module] | join(",")' <<< "$out")" gitleaks
podman image exists "$GL_IMAGE" && ok "prefetch-images : image présente sous son empreinte" || ko "prefetch-images : image toujours absente"
id=$(uuid)
drop "$id" "$(job "$id" "[$GL]" "$C2")"
run_runner
expect "reprise après prefetch-images : analyse réussie" "$(res "$id" | jq -r '.status + "/" + .modules[0].status')" ok/ok
expect "aucun conteneur laissé" "$(podman ps -a --format '{{.Names}}' | grep -c '^scanoria-' || true)" 0

echo
echo "b27-live : $PASS réussis, $FAIL échoués"
[[ "$FAIL" -eq 0 ]]
