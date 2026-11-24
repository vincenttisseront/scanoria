#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Vincent Tisseront
#
# Batterie de mesure des délais (0.6, CLAUDE.md § 15 V1–V10), sur une machine
# de test root jetable (workflow bench.yml) :
#   1. appliance de test vide (racine préfixée, vrai podman) ; modules du profil
#      « complet » sans service permanent installés PAR LE HELPER depuis l'index
#      réel du dépôt : gitleaks, OSV-Scanner, Trivy, Syft, Grype, reach-index,
#      bases téléchargées depuis leurs vraies sources (rien de pré-rempli) ;
#   2. l'appliance de référence est imposée : 2 vCPU / 4 Go vus par le runner
#      (/proc de la racine de test) et appliqués aux conteneurs par systemd
#      (machine.slice : CPUQuota=200 %, MemoryMax=4G) ;
#   3. trois dépôts générés de façon déterministe (gen.py : petit, moyen, gros)
#      analysés par le vrai runner, outils longs d'abord (ordre du plan V5),
#      deux fois : à froid, puis avec le cache de résultats rempli (V4, release
#      d'un commit déjà analysé) ;
#   4. mesures.json (durée totale et par outil) et rapport comparé à
#      baseline.json (compare.py : régression > 15 % signalée, non bloquante).
# Usage : run.sh <répertoire de sortie>
# Dépendances : bash, python3, python3-yaml, jq, openssl, zstd, tar, curl, podman, systemd.

# shellcheck disable=SC2016
set -euo pipefail
export PYTHONDONTWRITEBYTECODE=1

[[ "$(id -u)" -eq 0 ]] || { echo "bench : root requis (podman réel)" >&2; exit 2; }
for t in python3 jq openssl zstd tar curl podman systemctl; do
	command -v "$t" > /dev/null || { echo "outil manquant : $t" >&2; exit 2; }
done
OUT=$(realpath -m "${1:?usage : run.sh <répertoire de sortie>}")
mkdir -p "$OUT"
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
HELPER="$ROOT/src/rootfs/usr/sbin/scanoria-helper"
RUNNER="$ROOT/src/rootfs/usr/sbin/scanoria-runner"
BENCH="$ROOT/tests/bench"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
echo "Machine : $(nproc) vCPU, $(awk '/MemTotal/ {printf "%d Mo", $2/1024}' /proc/meminfo) ; mesure bornée à 2 vCPU / 4 Go"

# --- 1. Appliance de test -------------------------------------------------------------------
T="$TMP/root"
STUBS="$TMP/stubs"
REL="$TMP/rel/catalog-v1"
mkdir -p "$T"/var/lib/scanoria/requests/{tmp,incoming,work,done,failed} "$T/var/lib/scanoria/uploads" "$T/run/scanoria" \
	"$T/etc/scanoria" "$T/opt/scanoria/current" "$T/proc" "$T/usr/lib/scanoria" "$STUBS" "$REL"
export SCANORIA_TEST_ROOT="$T" SCANORIA_TEST_BIN="$STUBS" SCANORIA_TEST_HEALTH_TIMEOUT=900
export SCANORIA_RESULT_CACHE="$TMP/result-cache"
cat "$ROOT/VERSION" > "$T/opt/scanoria/current/VERSION"
cp /proc/meminfo "$T/proc/meminfo" && grep '^processor' /proc/cpuinfo > "$T/proc/cpuinfo"
cp -R "$ROOT/src/rootfs/usr/lib/scanoria/scan-tools" "$T/usr/lib/scanoria/"
chmod -R a+rX,go-w "$T/usr"
echo '{"repo": "exemple/scanoria"}' > "$T/etc/scanoria/catalog.json"
openssl genpkey -algorithm ed25519 -out "$TMP/sign.key" 2> /dev/null
openssl pkey -in "$TMP/sign.key" -pubout -out "$T/etc/scanoria/update-pubkey.pem"
python3 -I "$ROOT/catalog/build.py" build --version 1 --out "$REL" > /dev/null
openssl pkeyutl -sign -inkey "$TMP/sign.key" -rawin -in "$REL/SHA256SUMS" -out "$REL/SHA256SUMS.sig"
echo '[{"tag_name": "catalog-v1", "name": "Catalogue Scanoria 1", "draft": false, "prerelease": false}]' > "$TMP/api.json"
ln -s "$(command -v podman)" "$STUBS/podman"
ln -s "$(command -v nft 2> /dev/null || echo /bin/true)" "$STUBS/nft"
CURL=$(command -v curl)
cat > "$STUBS/curl" <<-EOF
	#!/usr/bin/env python3
	import os, shutil, sys
	a = sys.argv[1:]
	url = a[-1]
	if url.startswith(("https://api.github.com/repos/exemple/", "https://github.com/exemple/")):
	    out = a[a.index("--output") + 1] if "--output" in a else None
	    wo = a[a.index("--write-out") + 1] if "--write-out" in a else ""
	    code, src = 404, None
	    if url == "https://api.github.com/repos/exemple/scanoria/releases?per_page=30":
	        code, src = 200, "$TMP/api.json"
	    elif url.startswith("https://github.com/exemple/scanoria/releases/download/"):
	        p = "$TMP/rel/" + url.split("/releases/download/", 1)[1]
	        if os.path.isfile(p):
	            code, src = 200, p
	    if out and src:
	        shutil.copyfile(src, out)
	    sys.stdout.write(wo.replace("%{http_code}", str(code)).replace("%{redirect_url}", ""))
	    sys.exit(0)
	os.execv("$CURL", ["curl"] + a)
EOF
printf '#!/bin/bash\nexit 0\n' > "$STUBS/scanoria-state"
chmod 0755 "$STUBS/curl" "$STUBS/scanoria-state"

hx() {
	R=$("$HELPER" exec --origin cli --type "$1" --params "$2" 2> "$TMP/helper.err") || true
	echo "--- $1 : $(jq -c '{code, message}' <<< "${R:-{\}}")"
	[[ "$(jq -r .code <<< "${R:-{\}}")" == OK ]] || { sed 's/^/     /' "$TMP/helper.err" | tail -n 40; exit 1; }
}
ver() { jq -r --arg id "$1" '[.modules[] | select(.id == $id)][0].version' "$REL/catalog-index.json"; }
MODULES=(gitleaks osv-scanner trivy syft grype reach-index)
hx refresh-catalog '{}'
start=$SECONDS
hx install-modules "$(for m in "${MODULES[@]}"; do jq -cn --arg id "$m" --arg v "$(ver "$m")" '{id: $id, version: $v, options: {}}'; done \
	| jq -cs '{modules: ., accept_licenses: []}')"
echo "installation (images et bases réelles) : $((SECONDS - start)) s"

# --- 2. Appliance de référence : 2 vCPU / 4 Go ----------------------------------------------
printf 'MemTotal:        4096000 kB\n' > "$T/proc/meminfo"
printf 'processor\t: 0\nprocessor\t: 1\n' > "$T/proc/cpuinfo"
systemctl set-property --runtime machine.slice CPUQuota=200% MemoryMax=4G
trap 'systemctl set-property --runtime machine.slice CPUQuota= MemoryMax=infinity || true; rm -rf "$TMP"' EXIT

# --- 3. Mesures -----------------------------------------------------------------------------
SCANS="$T/var/lib/scanoria/scans"
uuid() { python3 -c 'import uuid; print(uuid.uuid4())'; }
# Ordre du plan (V5) : outils longs d'abord, Syft avant Grype (graphe V3), comme order.ts sans historique.
ORDER='[{"id": "trivy"}, {"id": "syft"}, {"id": "grype", "after": ["syft"]}, {"id": "osv-scanner"}, {"id": "gitleaks"}, {"id": "reach-index"}]'
JOBMODS=$(jq -c --argjson v "$(for m in "${MODULES[@]}"; do jq -cn --arg id "$m" --arg v "$(ver "$m")" '{($id): $v}'; done | jq -cs add)" \
	'map(. + {version: $v[.id]})' <<< "$ORDER")
measure() { # dépôt passage
	local up id t0 t1 rdir
	up=$(uuid)
	id=$(uuid)
	mkdir -p "$T/var/lib/scanoria/uploads/$up" "$SCANS/jobs/incoming"
	cp "$TMP/$1.tar.gz" "$T/var/lib/scanoria/uploads/$up/source.tar.gz"
	jq -cn --arg id "$id" --arg sid "$(uuid)" --arg up "$up" --argjson mods "$JOBMODS" \
		'{schema: 1, id: $id, scan_id: $sid, created_at: "2026-11-24T10:00:00Z", source: {kind: "archive", upload_id: $up}, modules: $mods, cache: true}' \
		> "$SCANS/jobs/incoming/$id.json"
	chmod 0600 "$SCANS/jobs/incoming/$id.json"
	t0=$(date +%s%3N)
	"$RUNNER" --once 2> "$TMP/runner.err" || { sed 's/^/     /' "$TMP/runner.err"; exit 1; }
	t1=$(date +%s%3N)
	rdir="$SCANS/results/$id"
	jq -c --arg r "$1" --arg p "$2" --argjson total $((t1 - t0)) '{repo: $r, pass: $p, total_ms: $total,
		status: .status, modules: (.modules | map({(.id): (.stats.duration_ms // 0)}) | add),
		statuses: (.modules | map({(.id): .status}) | add), reused: ([.modules[] | select(.reused_from)] | length)}' \
		"$rdir/result.json" | tee -a "$TMP/raw.jsonl"
	if [[ "$2" == cold ]]; then
		echo "rangées dans le cache : $(python3 -I "$BENCH/store.py" "$rdir" "$SCANORIA_RESULT_CACHE")"
	fi
}
for repo in small medium large; do
	python3 -I "$BENCH/gen.py" "$TMP/$repo" "$repo"
	tar -C "$TMP/$repo" -czf "$TMP/$repo.tar.gz" .
	echo "::group::$repo ($(find "$TMP/$repo" -type f | wc -l) fichiers)"
	measure "$repo" cold
	measure "$repo" warm
	echo "::endgroup::"
done

# --- 4. Résultats ---------------------------------------------------------------------------
jq -s --arg at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --arg commit "${GITHUB_SHA:-local}" \
	'{version: 1, measured_at: $at, commit: $commit, machine: "2 vCPU / 4 Go",
	  repos: (group_by(.repo) | map({(.[0].repo): (map({(.pass): {total_ms, modules, statuses, reused}}) | add)}) | add)}' \
	"$TMP/raw.jsonl" > "$OUT/mesures.json"
python3 -I "$BENCH/compare.py" "$OUT/mesures.json" "$BENCH/baseline.json" "$OUT/rapport.md" | tee "$OUT/regression.txt"
cat "$OUT/rapport.md"
bad=$(jq -r '[.repos[][] | .statuses | to_entries[] | select(.value != "ok" and .value != "not-applicable") | .key] | unique | join(" ")' "$OUT/mesures.json")
if [[ -n "$bad" ]]; then
	echo "::error::modules en échec pendant la mesure : $bad"
	exit 1
fi
