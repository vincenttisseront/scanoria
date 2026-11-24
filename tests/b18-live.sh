#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Vincent Tisseront
#
# b18-live — le test qui aurait attrapé le code 127 de la 0.3.3 : installation
# réelle d'OSV-Scanner et de Trivy PAR LE HELPER, à partir de bases vides,
# comme sur une appliance neuve (job CI feeds-live, machine de test root
# jetable). Le helper tourne en mode test sur une racine temporaire, mais
# podman est le vrai et les bases sont téléchargées par feeds.py depuis leurs
# vraies sources (export OSV, registre OCI de trivy-db) : rien n'est
# pré-rempli par la CI. L'index du catalogue est construit depuis modules/ par
# catalog/build.py et signé par une clé de test jetable ; seules les URL des
# releases du catalogue sont servies depuis le disque.
# Cas : installation (feeds téléchargés avant les bancs d'essai, bancs d'essai
# réussis), état publié (âge et taille des bases), refresh-feeds (bascule,
# deux versions gardées au plus), désinstallation (bases retirées).
# Dépendances : bash, python3, python3-yaml, jq, openssl, zstd, tar, curl, podman (root).

# shellcheck disable=SC2016
set -euo pipefail
export PYTHONDONTWRITEBYTECODE=1

[[ "$(id -u)" -eq 0 ]] || { echo "b18-live : root requis (podman réel)" >&2; exit 2; }
for t in python3 jq openssl zstd tar curl podman; do command -v "$t" > /dev/null || { echo "outil manquant : $t" >&2; exit 2; }; done

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
HELPER="$ROOT/src/rootfs/usr/sbin/scanoria-helper"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

PASS=0
FAIL=0
ok() { PASS=$((PASS + 1)); printf 'ok   %s\n' "$1"; }
ko() { FAIL=$((FAIL + 1)); printf 'FAIL %s\n' "$1"; }
expect() {
	if [[ "$2" == "$3" ]]; then ok "$1"; else ko "$1 (obtenu « $2 », attendu « $3 »)"; fi
}

T="$TMP/root"
STUBS="$TMP/stubs"
REL="$TMP/rel/catalog-v1"
mkdir -p "$T"/var/lib/scanoria/requests/{tmp,incoming,work,done,failed} "$T/run/scanoria" "$T/etc/scanoria" \
	"$T/opt/scanoria/current" "$STUBS" "$REL"
export SCANORIA_TEST_ROOT="$T" SCANORIA_TEST_BIN="$STUBS"
echo 0.3.4 > "$T/opt/scanoria/current/VERSION"
mkdir -p "$T/proc" && cp /proc/meminfo "$T/proc/meminfo" && grep '^processor' /proc/cpuinfo > "$T/proc/cpuinfo"
echo '{"repo": "exemple/scanoria"}' > "$T/etc/scanoria/catalog.json"
openssl genpkey -algorithm ed25519 -out "$TMP/sign.key" 2> /dev/null
openssl pkey -in "$TMP/sign.key" -pubout -out "$T/etc/scanoria/update-pubkey.pem"

# Index réel du dépôt (modules/), signé par la clé de test.
python3 -I "$ROOT/catalog/build.py" build --version 1 --out "$REL"
openssl pkeyutl -sign -inkey "$TMP/sign.key" -rawin -in "$REL/SHA256SUMS" -out "$REL/SHA256SUMS.sig"
echo '[{"tag_name": "catalog-v1", "name": "Catalogue Scanoria 1", "draft": false, "prerelease": false}]' > "$TMP/api.json"

ln -s "$(command -v podman)" "$STUBS/podman"
# curl : releases du catalogue servies depuis le disque ; tout le reste (les
# bases) part vers le vrai curl, donc vers les vraies sources.
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
	sed 's/^/     /' "$TMP/helper.err" | tail -n 40
}
STATE="$T/var/lib/scanoria/modules/state.json"
FEEDS="$T/var/lib/scanoria/feeds"
ver() { jq -r --arg id "$1" '[.modules[] | select(.id == $id)][0].version' "$REL/catalog-index.json"; }
mstate() { jq -r --arg id "$1" '[.modules[] | select(.id == $id)][0] | if . == null then "absent" else .status + "/" + (.enabled|tostring) end' "$STATE"; }
fstate() { jq -r --arg id "$1" '[.feeds[] | select(.id == $id)][0] | .status + "/" + (.updated_at != null | tostring)' "$STATE"; }

hx refresh-catalog '{}'
expect "refresh-catalog (index réel signé par la clé de test)" "$(jq -r .code <<< "$R")" OK

# Bases absentes, comme sur la VM : l'installation doit les télécharger.
expect "aucune base avant l'installation" "$(find "$FEEDS" -mindepth 1 2> /dev/null | wc -l)" 0
INST=$(jq -cn --arg o "$(ver osv-scanner)" --arg t "$(ver trivy)" \
	'{modules: [{id: "osv-scanner", version: $o, options: {}}, {id: "trivy", version: $t, options: {}}], accept_licenses: []}')
start=$SECONDS
hx install-modules "$INST"
echo "durée de l'installation : $((SECONDS - start)) s"
expect "install osv-scanner + trivy par le helper" "$(jq -r .code <<< "$R")" OK
for id in osv-db trivy-db osv-scanner trivy; do
	expect "$id sain et activé" "$(mstate "$id")" healthy/true
done
for id in osv-scanner trivy; do
	expect "$id : banc d'essai réussi" "$(jq -r --arg id "$id" '.modules[] | select(.id == $id) | .testbed.passed' "$STATE")" true
done
expect "osv-db : base téléchargée (npm)" "$([[ -s "$FEEDS/osv-db/osv-scalibr/npm/all.zip" ]] && echo oui)" oui
expect "trivy-db : base téléchargée" "$([[ -s "$FEEDS/trivy-db/db/trivy.db" && -s "$FEEDS/trivy-db/db/metadata.json" ]] && echo oui)" oui
expect "osv-db : âge publié" "$(fstate osv-db)" ok/true
expect "trivy-db : âge publié" "$(fstate trivy-db)" ok/true
expect "bases lisibles par le groupe 65534 seulement (0640)" "$(stat -c %a:%g "$FEEDS/trivy-db/db/trivy.db")" 640:65534
expect "aucun conteneur laissé" "$(podman ps -a --format '{{.Names}}' | grep -c '^scanoria-run-' || true)" 0
jq '.feeds' "$STATE"

before=$(readlink "$FEEDS/trivy-db")
hx refresh-feeds '{"ids": ["trivy-db"]}'
expect "refresh-feeds trivy-db" "$(jq -r .code <<< "$R")" OK
expect "refresh-feeds : bascule vers une nouvelle version" "$([[ "$(readlink "$FEEDS/trivy-db")" != "$before" ]] && echo oui)" oui
expect "refresh-feeds : version précédente gardée" "$([[ -d "$FEEDS/$before" ]] && echo oui)" oui

hx uninstall-module '{"id": "trivy", "keep_data": false}'
hx uninstall-module '{"id": "trivy-db", "keep_data": false}'
expect "désinstallation de trivy-db" "$(jq -r .code <<< "$R")" OK
expect "base trivy-db retirée" "$(if [[ -e "$FEEDS/trivy-db" || -e "$FEEDS/.store/trivy-db" ]]; then echo reste; else echo retirée; fi)" retirée

echo
echo "b18-live : $PASS réussis, $FAIL échoués"
[[ "$FAIL" -eq 0 ]]
