#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Vincent Tisseront
#
# b18 — téléchargement des bases de vulnérabilités par le helper (feeds.py,
# 0.3.4), sans root. Mode test (SCANORIA_TEST_ROOT) ; curl est le vrai, qui
# fait confiance à une AC jetable, face à un faux serveur HTTPS local
# (tests/lib/fakefeeds.py) : export OSV par écosystème et registre OCI avec
# jeton anonyme et redirection du blob.
# Couvre : disposition attendue par OSV-Scanner et Trivy, droits (0644/0755),
# bascule atomique par lien et conservation de la version précédente, base
# antérieure (répertoire réel vide) remplacée, empreinte fausse, taille
# différente, archive piégée (lien, « .. », fichier en trop, metadata absent),
# échec réseau qui garde la base précédente, écosystème « .. » refusé, proxy
# lu dans /etc/environment, base vide signalée (E_FEED_UNAVAILABLE, jamais 127).
# Dépendances : bash, python3, curl, openssl, jq.

set -euo pipefail
export PYTHONDONTWRITEBYTECODE=1

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
PYLIB="$ROOT/src/rootfs/usr/lib/scanoria/py"
FAKE="$ROOT/tests/lib/fakefeeds.py"
TMP=$(mktemp -d)
SRV_PID=""
cleanup() {
	if [[ -n "$SRV_PID" ]]; then kill "$SRV_PID" 2> /dev/null || true; fi
	rm -rf "$TMP"
}
trap cleanup EXIT
for t in python3 curl openssl jq; do command -v "$t" > /dev/null || { echo "outil manquant : $t" >&2; exit 2; }; done

PASS=0
FAIL=0
ok() { PASS=$((PASS + 1)); printf 'ok   %s\n' "$1"; }
ko() { FAIL=$((FAIL + 1)); printf 'FAIL %s\n' "$1"; }
expect() {
	if [[ "$2" == "$3" ]]; then ok "$1"; else ko "$1 (obtenu « $2 », attendu « $3 »)"; fi
}

T="$TMP/root"
STUBS="$TMP/stubs"
SRV="$TMP/srv"
mkdir -p "$T/var/lib/scanoria" "$T/etc" "$STUBS" "$SRV/osv/npm" "$SRV/osv/PyPI"
export SCANORIA_TEST_ROOT="$T" SCANORIA_TEST_BIN="$STUBS"

# AC et certificat jetables pour 127.0.0.1 ; curl réel qui leur fait confiance.
openssl req -x509 -newkey ed25519 -nodes -days 1 -subj "/CN=b18" -addext "subjectAltName=IP:127.0.0.1" \
	-keyout "$TMP/srv.key" -out "$TMP/srv.pem" 2> /dev/null
CURL=$(command -v curl)
cat > "$STUBS/curl" <<-EOF
	#!/bin/bash
	printf '%s\n' "\$*" >> "$TMP/curl.log"
	printf '%s\n' "\$(env | grep -i '^https_proxy=' || true)" >> "$TMP/curl.env"
	exec "$CURL" --cacert "$TMP/srv.pem" --noproxy 127.0.0.1 "\$@"
EOF
chmod 0755 "$STUBS/curl"

python3 "$FAKE" serve "$TMP/srv.pem" "$TMP/srv.key" "$TMP/port" "$SRV" &
SRV_PID=$!
for _ in $(seq 50); do [[ -s "$TMP/port" ]] && break; sleep 0.1; done
PORT=$(cat "$TMP/port")
HOST="127.0.0.1:$PORT"

mkzip() { python3 -c 'import sys, zipfile; z = zipfile.ZipFile(sys.argv[1], "w"); z.writestr("OSV-1.json", sys.argv[2]); z.close()' "$1" "$2"; }
mkzip "$SRV/osv/npm/all.zip" '{"id": "OSV-1"}'
mkzip "$SRV/osv/PyPI/all.zip" '{"id": "OSV-2"}'

# manifest LAYER_MODE [jq] : couche trivy-db et manifeste OCI qui la décrit
manifest() {
	python3 "$FAKE" layer "$SRV/blob" "$1"
	local sha size
	sha=$(sha256sum "$SRV/blob" | cut -d' ' -f1)
	size=$(stat -c %s "$SRV/blob")
	jq -cn --arg d "sha256:$sha" --argjson s "$size" '{schemaVersion: 2, mediaType: "application/vnd.oci.image.manifest.v1+json",
		layers: [{mediaType: "application/vnd.aquasec.trivy.db.layer.v1.tar+gzip", digest: $d, size: $s}]} | '"${2:-.}" > "$SRV/manifest.json"
}

OSV=$(jq -cn --arg ref "https://$HOST/osv/{ecosystem}/all.zip" '{id: "osv-db", type: "feed", resources: {disk_mb: 1},
	options: {properties: {ecosystems: {default: ["npm", "PyPI"]}}}, feed: {source: {kind: "https", ref: $ref}}}')
TDB=$(jq -cn --arg ref "$HOST/aquasec/trivy-db:2" '{id: "trivy-db", type: "feed", resources: {disk_mb: 1},
	feed: {source: {kind: "oci", ref: $ref}}}')
SCANNER='{"id": "trivy", "type": "scanner", "requires": {"feeds": ["trivy-db"]}}'

# refresh MANIFESTE [OPTIONS] : code de résultat (OK ou code Fail) dans $R
refresh() {
	R=$(python3 - "$1" "${2:-null}" <<-'PY' 2> "$TMP/err" || true
		import json, sys
		sys.path.insert(0, __import__("os").environ["PYLIB"])
		from scanoria import feeds
		from scanoria.common import Fail
		try:
		    feeds.refresh(json.loads(sys.argv[1]), json.loads(sys.argv[2]), timeout=120)
		    print("OK")
		except Fail as f:
		    print(f.code + " " + f.message)
	PY
	)
}
export PYLIB
FEEDS="$T/var/lib/scanoria/feeds"
status() { jq -r ".$2" "$FEEDS/.store/$1/status.json"; }
versions() { find "$FEEDS/.store/$1" -mindepth 1 -maxdepth 1 -type d -regextype posix-extended -regex '.*/[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}' | wc -l; }
mode() { stat -c %a "$1"; }

# --- OSV par écosystème -------------------------------------------------------
# Base antérieure à la 0.3.4 : répertoire réel vide, créé par l'installation.
mkdir -p "$FEEDS/osv-db"
refresh "$OSV"
expect "osv-db : téléchargement" "${R%% *}" OK
expect "osv-db : disposition OSV-Scanner (npm)" "$(test -f "$FEEDS/osv-db/osv-scalibr/npm/all.zip" && echo oui)" oui
expect "osv-db : disposition OSV-Scanner (PyPI)" "$(test -f "$FEEDS/osv-db/osv-scalibr/PyPI/all.zip" && echo oui)" oui
expect "osv-db : ancien répertoire remplacé par un lien" "$(test -L "$FEEDS/osv-db" && echo lien)" lien
expect "osv-db : fichiers 0644" "$(mode "$FEEDS/osv-db/osv-scalibr/npm/all.zip")" 644
expect "osv-db : répertoires 0755" "$(mode "$FEEDS/osv-db/osv-scalibr/npm")/$(mode "$FEEDS/osv-db/")" 755/755
expect "osv-db : état ok" "$(status osv-db status)" ok
expect "osv-db : aucun répertoire de travail laissé" "$(find "$FEEDS/.store/osv-db" -maxdepth 1 -name '.tmp-*' | wc -l)" 0
first=$(readlink "$FEEDS/osv-db")

refresh "$OSV" '{"ecosystems": ["npm"]}'
expect "osv-db : option ecosystems appliquée" "${R%% *}/$(ls "$FEEDS/osv-db/osv-scalibr")" OK/npm
second=$(readlink "$FEEDS/osv-db")
expect "osv-db : bascule vers une nouvelle version" "$([[ "$first" != "$second" ]] && echo oui)" oui
refresh "$OSV"
expect "osv-db : deux versions gardées au plus (active et précédente)" "$(versions osv-db)" 2
expect "osv-db : ancienne base « legacy » retirée" "$(find "$FEEDS/.store/osv-db" -maxdepth 1 -name 'legacy-*' | wc -l)" 0

refresh "$OSV" '{"ecosystems": [".."]}'
expect "osv-db : écosystème « .. » refusé" "${R%% *}" E_INVALID_PARAM
refresh "$OSV" '{"ecosystems": ["Absent"]}'
expect "osv-db : écosystème inconnu → E_FEED_UNAVAILABLE" "${R%% *}" E_FEED_UNAVAILABLE
expect "osv-db : message qui dit quoi faire" "$(grep -c "check access to 127.0.0.1" <<< "$R")" 1
expect "osv-db : base précédente gardée (stale)" "$(status osv-db status)/$(test -f "$FEEDS/osv-db/osv-scalibr/npm/all.zip" && echo présente)" stale/présente
printf 'pas un zip' > "$SRV/osv/PyPI/all.zip"
refresh "$OSV"
expect "osv-db : archive qui n'est pas un zip refusée" "${R%% *}/$(grep -c 'not a zip' <<< "$R")" E_FEED_UNAVAILABLE/1
mkzip "$SRV/osv/PyPI/all.zip" '{"id": "OSV-2"}'
echo down > "$SRV/mode"
refresh "$OSV"
expect "osv-db : serveur en panne → base gardée" "${R%% *}/$(test -f "$FEEDS/osv-db/osv-scalibr/npm/all.zip" && echo présente)" E_FEED_UNAVAILABLE/présente
rm "$SRV/mode"

# --- trivy-db par registre OCI ------------------------------------------------
python3 - "$SCANNER" <<-'PY' > "$TMP/ready" 2>&1 || true
	import json, os, sys
	sys.path.insert(0, os.environ["PYLIB"])
	from scanoria import feeds
	from scanoria.common import Fail
	try:
	    feeds.require_ready(json.loads(sys.argv[1]))
	    print("OK")
	except Fail as f:
	    print(f.code)
PY
expect "base vide : E_FEED_UNAVAILABLE avant le scanner (jamais 127)" "$(cat "$TMP/ready")" E_FEED_UNAVAILABLE

manifest ok
refresh "$TDB"
expect "trivy-db : jeton anonyme, manifeste, couche" "${R%% *}" OK
expect "trivy-db : disposition trivy --cache-dir" "$(find "$FEEDS/trivy-db/db/" -mindepth 1 -printf '%f\n' | sort | tr '\n' ' ')" "metadata.json trivy.db "
expect "trivy-db : DownloadedAt posé" "$(jq -r '.DownloadedAt != null and .Version == 2' "$FEEDS/trivy-db/db/metadata.json")" true
expect "trivy-db : fichiers 0644" "$(mode "$FEEDS/trivy-db/db/trivy.db")" 644
expect "trivy-db : jeton jamais dans l'argv de curl" "$(grep -c 'jeton-anonyme' "$TMP/curl.log" || true)" 0
expect "trivy-db : jeton supprimé après usage" "$(find "$FEEDS/.store/trivy-db" -name 'auth.header' | wc -l)" 0
good=$(readlink "$FEEDS/trivy-db")
sum=$(sha256sum "$FEEDS/trivy-db/db/trivy.db" | cut -d' ' -f1)

bad() { # libellé mode_couche [jq] motif
	manifest "$2" "${3:-.}"
	refresh "$TDB"
	expect "trivy-db : $1" "${R%% *}/$(grep -c -- "$4" <<< "$R")" E_FEED_UNAVAILABLE/1
	expect "trivy-db : $1 → base précédente intacte" "$(readlink "$FEEDS/trivy-db")/$(sha256sum "$FEEDS/trivy-db/db/trivy.db" | cut -d' ' -f1)" "$good/$sum"
}
bad "empreinte fausse" ok '.layers[0].digest = "sha256:" + ("0" * 64)' "digest mismatch"
bad "taille annoncée plus petite" ok '.layers[0].size -= 10' "larger than allowed\|unexpected size"
bad "lien symbolique dans l'archive" symlink . "unexpected entry"
bad "chemin « .. » dans l'archive" dotdot . "unexpected entry"
bad "fichier en trop" extra . "unexpected entry"
bad "metadata.json absent" nometa . "lacks metadata.json"
bad "index d'images non pris en charge" ok '{schemaVersion: 2, manifests: []}' "image index"
expect "trivy-db : état stale après échec" "$(status trivy-db status)" stale
expect "trivy-db : aucun extrait hors de la base" "$(find "$TMP" -name 'evade.db' | wc -l)" 0
manifest ok
refresh "$TDB"
expect "trivy-db : nouvelle base après correction" "${R%% *}/$(status trivy-db status)" OK/ok

# --- Proxy ----------------------------------------------------------------------
: > "$TMP/curl.env"
printf 'PATH="/usr/bin"\nhttps_proxy="http://192.0.2.10:3128"\nno_proxy=localhost,127.0.0.1\n' > "$T/etc/environment"
refresh "$OSV" '{"ecosystems": ["npm"]}'
expect "proxy de /etc/environment transmis à curl" "$(grep -c '^https_proxy=http://192.0.2.10:3128$' "$TMP/curl.env")" 1
printf 'https_proxy="http://x;rm -rf /"\n' > "$T/etc/environment"
: > "$TMP/curl.env"
refresh "$OSV" '{"ecosystems": ["npm"]}'
expect "proxy invalide ignoré" "$(grep -c 'https_proxy=' "$TMP/curl.env")" 0

# --- Retrait --------------------------------------------------------------------
python3 -c 'import os, sys; sys.path.insert(0, os.environ["PYLIB"]); from scanoria import feeds; feeds.remove("trivy-db")'
expect "retrait : lien et versions supprimés" "$(test -e "$FEEDS/trivy-db" -o -e "$FEEDS/.store/trivy-db" && echo reste || echo vide)" vide

echo
echo "b18 : $PASS réussis, $FAIL échoués"
[[ "$FAIL" -eq 0 ]]
