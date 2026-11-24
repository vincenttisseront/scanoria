#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Vincent Tisseront
#
# b23 — bases EPSS et KEV (0.5, H3) téléchargées par le helper (feeds.py) et
# exportées pour la console (contrat 17), sans root. Mode test
# (SCANORIA_TEST_ROOT) ; curl est le vrai, qui fait confiance à une AC jetable,
# face à un faux serveur HTTPS local qui sert un répertoire.
# Couvre : CSV EPSS et JSON KEV valides, export jsonl.gz (une ligne par CVE),
# droits du fichier exporté (0640, répertoire 0750), écriture atomique (aucun
# fichier temporaire laissé, inode remplacé), fichiers piégés refusés (taille,
# colonnes manquantes, valeurs hors bornes, nan, CVE invalide, doublon, nombre
# annoncé faux, date invalide, document qui n'est pas un objet), base et export
# précédents gardés après un refus, base qui rétrécit refusée, export retiré à
# la désinstallation, manifestes du dépôt conformes (export déclaré).
# « --live » (job CI feeds-live) : rien de faux, les manifestes du dépôt sont
# téléchargés depuis leurs vraies sources, sur une racine vide, comme sur une
# appliance neuve (leçon de la 0.4 : aucune base pré-remplie).
# Dépendances : bash, python3, curl, openssl, jq, gzip (et python3-yaml en --live).

set -euo pipefail
export PYTHONDONTWRITEBYTECODE=1

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
PYLIB="$ROOT/src/rootfs/usr/lib/scanoria/py"
TMP=$(mktemp -d)
SRV_PID=""
cleanup() {
	if [[ -n "$SRV_PID" ]]; then kill "$SRV_PID" 2> /dev/null || true; fi
	rm -rf "$TMP"
}
trap cleanup EXIT
for t in python3 curl openssl jq gzip; do command -v "$t" > /dev/null || { echo "outil manquant : $t" >&2; exit 2; }; done

PASS=0
FAIL=0
ok() { PASS=$((PASS + 1)); printf 'ok   %s\n' "$1"; }
ko() { FAIL=$((FAIL + 1)); printf 'FAIL %s\n' "$1"; }
expect() {
	if [[ "$2" == "$3" ]]; then ok "$1"; else ko "$1 (obtenu « $2 », attendu « $3 »)"; fi
}

if [[ "${1:-}" == "--live" ]]; then
	T="$TMP/root"
	mkdir -p "$T/var/lib/scanoria" "$T/etc" "$TMP/live-bin"
	# En mode test, une commande absente de SCANORIA_TEST_BIN est un bouchon : le vrai curl y est placé.
	ln -s "$(command -v curl)" "$TMP/live-bin/curl"
	export SCANORIA_TEST_ROOT="$T" SCANORIA_TEST_BIN="$TMP/live-bin" PYLIB
	for id in epss kev; do
		# Journal (essais, repli sur le miroir) à part : seul le résultat est comparé.
		R=$(python3 - "$ROOT/modules/$id/module.yaml" <<-'PY' 2> "$TMP/$id.err" || true
			import os, sys, yaml
			sys.path.insert(0, os.environ["PYLIB"])
			from scanoria import feeds
			from scanoria.common import Fail
			try:
			    st = feeds.refresh(yaml.safe_load(open(sys.argv[1])), None, timeout=600)
			    print("OK", st["status"])
			except Fail as f:
			    print(f.code + " " + f.message)
		PY
		)
		expect "$id (vraie source) : téléchargement, validation et export" "$R" "OK ok"
		[[ "$R" == "OK ok" ]] || cat "$TMP/$id.err" >&2
		n=$( (gzip -dc "$T/var/lib/scanoria/feeds-export/$id.jsonl.gz" 2> /dev/null || true) | wc -l)
		if [[ $n -ge 1000 ]]; then ok "$id (vraie source) : $n CVE exportées"; else ko "$id (vraie source) : $n CVE exportées (≥ 1000 attendues)"; fi
		jq -c '{source, details}' "$T/var/lib/scanoria/feeds/.store/$id/status.json" 2> /dev/null || true
	done
	echo "b23 --live : $PASS réussis, $FAIL échoués"
	[[ $FAIL -eq 0 ]]
	exit
fi

T="$TMP/root"
STUBS="$TMP/stubs"
SRV="$TMP/srv"
mkdir -p "$T/var/lib/scanoria" "$T/etc" "$STUBS" "$SRV"
export SCANORIA_TEST_ROOT="$T" SCANORIA_TEST_BIN="$STUBS" PYLIB

openssl req -x509 -newkey ed25519 -nodes -days 1 -subj "/CN=b23" -addext "subjectAltName=IP:127.0.0.1" \
	-keyout "$TMP/srv.key" -out "$TMP/srv.pem" 2> /dev/null
CURL=$(command -v curl)
cat > "$STUBS/curl" <<-EOF
	#!/bin/bash
	exec "$CURL" --cacert "$TMP/srv.pem" --noproxy 127.0.0.1 "\$@"
EOF
chmod 0755 "$STUBS/curl"

# Faux serveur : sert SRV ; le fichier SRV/mode à « down » rend 500 partout.
cat > "$TMP/serve.py" <<-'PY'
	import http.server, os, ssl, sys
	cert, key, portfile, base = sys.argv[1:5]
	class H(http.server.BaseHTTPRequestHandler):
	    def log_message(self, *a):
	        pass
	    def do_GET(self):
	        mode = os.path.join(base, "mode")
	        if os.path.exists(mode) and open(mode).read().strip() == "down":
	            self.send_response(500); self.send_header("Content-Length", "0"); self.end_headers(); return
	        path = os.path.join(base, os.path.basename(self.path.split("?")[0]))
	        try:
	            data = open(path, "rb").read()
	        except OSError:
	            self.send_response(404); self.send_header("Content-Length", "0"); self.end_headers(); return
	        self.send_response(200); self.send_header("Content-Length", str(len(data))); self.end_headers()
	        self.wfile.write(data)
	srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
	srv.handle_error = lambda *a: None
	ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain(cert, key)
	srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
	open(portfile + ".tmp", "w").write(str(srv.server_address[1])); os.rename(portfile + ".tmp", portfile)
	srv.serve_forever()
PY
python3 "$TMP/serve.py" "$TMP/srv.pem" "$TMP/srv.key" "$TMP/port" "$SRV" &
SRV_PID=$!
for _ in $(seq 50); do [[ -s "$TMP/port" ]] && break; sleep 0.1; done
HOST="127.0.0.1:$(cat "$TMP/port")"

EPSS=$(jq -cn --arg ref "https://$HOST/epss.csv.gz" '{id: "epss", type: "feed", resources: {disk_mb: 1},
	feed: {format: "epss-csv", source: {kind: "https", ref: $ref}, export: {format: "jsonl.gz"}}}')
KEV=$(jq -cn --arg ref "https://$HOST/kev.json" '{id: "kev", type: "feed", resources: {disk_mb: 1},
	feed: {format: "kev-json", source: {kind: "https", ref: $ref}, export: {format: "jsonl.gz"}}}')

# refresh MANIFESTE : code de résultat (OK ou code Fail et message) dans $R
refresh() {
	R=$(python3 - "$1" <<-'PY' 2> "$TMP/err" || true
		import json, os, sys
		sys.path.insert(0, os.environ["PYLIB"])
		from scanoria import feeds
		from scanoria.common import Fail
		try:
		    feeds.refresh(json.loads(sys.argv[1]), None, timeout=120)
		    print("OK")
		except Fail as f:
		    print(f.code + " " + f.message)
	PY
	)
}
EXPORT="$T/var/lib/scanoria/feeds-export"
lines() { gzip -dc "$EXPORT/$1.jsonl.gz" | wc -l; }
mode() { stat -c %a "$1"; }
# epss LIGNES... : fichier CSV compressé servi
epss() {
	{ printf '#model_version:v2025.03.14,score_date:2026-11-24T00:00:00+0000\n'; printf '%s\n' "$@"; } | gzip -c > "$SRV/epss.csv.gz"
}
GOOD_EPSS=('cve,epss,percentile' 'CVE-2026-0001,0.97000,0.99900' 'CVE-2026-0002,0.00043,0.12000' 'CVE-2026-0003,4e-05,0.01000' 'CVE-2026-0004,0.5,0.8')

# --- EPSS ---------------------------------------------------------------------
epss "${GOOD_EPSS[@]}"
refresh "$EPSS"
expect "epss : téléchargement et validation" "${R%% *}" OK
expect "epss : export écrit, une ligne par CVE" "$(lines epss)" 4
expect "epss : ligne normalisée" "$(gzip -dc "$EXPORT/epss.jsonl.gz" | head -1 | jq -c .)" '{"vuln_id":"CVE-2026-0001","epss":0.97,"epss_percentile":0.999}'
expect "epss : exposant décimal accepté" "$(gzip -dc "$EXPORT/epss.jsonl.gz" | jq -r 'select(.vuln_id == "CVE-2026-0003") | .epss == 0.00004')" true
expect "epss : fichier exporté 0640" "$(mode "$EXPORT/epss.jsonl.gz")" 640
expect "epss : répertoire d'export 0750" "$(mode "$EXPORT")" 750
expect "epss : aucun fichier temporaire laissé" "$(find "$EXPORT" -name '.*' | wc -l)" 0
expect "epss : export identique à la base active" "$(cmp -s "$EXPORT/epss.jsonl.gz" "$T/var/lib/scanoria/feeds/epss/export.jsonl.gz" && echo oui)" oui
expect "epss : date du modèle relevée" "$(jq -r '.details.score_date + " " + (.details.rows | tostring)' "$T/var/lib/scanoria/feeds/.store/epss/status.json")" "2026-11-24 4"
ino=$(stat -c %i "$EXPORT/epss.jsonl.gz")
sum=$(sha256sum "$EXPORT/epss.jsonl.gz" | cut -d' ' -f1)
epss "${GOOD_EPSS[@]}" CVE-2026-0005,0.1,0.5
refresh "$EPSS"
expect "epss : nouvel export par rename(2) (inode remplacé)" "${R%% *}/$([[ "$(stat -c %i "$EXPORT/epss.jsonl.gz")" != "$ino" ]] && echo nouveau)" OK/nouveau
sum=$(sha256sum "$EXPORT/epss.jsonl.gz" | cut -d' ' -f1)

bad_epss() { # libellé motif lignes...
	local label=$1 pattern=$2
	shift 2
	epss "$@"
	refresh "$EPSS"
	expect "epss : $label refusé" "${R%% *}/$(grep -c -- "$pattern" <<< "$R")" E_FEED_UNAVAILABLE/1
	expect "epss : $label → export précédent intact" "$(sha256sum "$EXPORT/epss.jsonl.gz" | cut -d' ' -f1)" "$sum"
}
bad_epss "colonne percentile manquante" "lacks cve, epss or percentile" cve,epss CVE-2026-0001,0.5
bad_epss "colonnes en moins sur une ligne" "columns instead of" cve,epss,percentile CVE-2026-0001,0.5
bad_epss "score hors bornes" "epss out of range" cve,epss,percentile CVE-2026-0001,1.5,0.5
bad_epss "percentile négatif" "invalid percentile value" cve,epss,percentile CVE-2026-0001,0.5,-0.1
bad_epss "score nan" "invalid epss value" cve,epss,percentile CVE-2026-0001,nan,0.5
bad_epss "CVE invalide" "invalid CVE identifier" cve,epss,percentile "CVE-26-1;rm,0.5,0.5"
bad_epss "doublon" "duplicate CVE-2026-0001" cve,epss,percentile CVE-2026-0001,0.5,0.5 CVE-2026-0001,0.4,0.4
bad_epss "fichier sans score" "has no scores" cve,epss,percentile
bad_epss "base qui rétrécit brutalement" "1 entries instead of 5" cve,epss,percentile CVE-2026-0001,0.5,0.5
printf 'pas du gzip' > "$SRV/epss.csv.gz"
refresh "$EPSS"
expect "epss : fichier qui n'est pas du gzip refusé" "${R%% *}/$(grep -c 'unreadable' <<< "$R")" E_FEED_UNAVAILABLE/1
python3 -c 'import gzip, sys; f = gzip.open(sys.argv[1], "wb"); f.write(b"cve,epss,percentile\n" + b"x" * 8192 + b"\n"); f.close()' "$SRV/epss.csv.gz"
refresh "$EPSS"
expect "epss : ligne démesurée refusée" "${R%% *}/$(grep -c 'too long' <<< "$R")" E_FEED_UNAVAILABLE/1
head -c $((65 << 20)) /dev/zero > "$SRV/epss.csv.gz"
refresh "$EPSS"
expect "epss : téléchargement plus gros que permis refusé" "${R%% *}/$(grep -c 'larger than allowed' <<< "$R")" E_FEED_UNAVAILABLE/1
rm -f "$SRV/epss.csv.gz"
expect "epss : état stale, base précédente gardée" "$(jq -r .status "$T/var/lib/scanoria/feeds/.store/epss/status.json")/$(lines epss)" stale/5

# --- KEV ----------------------------------------------------------------------
kev() { jq -cn "$1" > "$SRV/kev.json"; }
kev '{title: "KEV", catalogVersion: "2026.11.24", count: 3, vulnerabilities: [
	{cveID: "CVE-2026-0001", dateAdded: "2026-11-01"}, {cveID: "CVE-2026-0007", dateAdded: "2026-11-20"},
	{cveID: "cve-2026-0001", dateAdded: "2026-10-01"}]}'
refresh "$KEV"
expect "kev : téléchargement et validation" "${R%% *}" OK
expect "kev : doublon fusionné, première date d'ajout gardée" "$(gzip -dc "$EXPORT/kev.jsonl.gz" | jq -sc .)" \
	'[{"vuln_id":"CVE-2026-0001","kev":true,"kev_added":"2026-10-01"},{"vuln_id":"CVE-2026-0007","kev":true,"kev_added":"2026-11-20"}]'
expect "kev : fichier exporté 0640" "$(mode "$EXPORT/kev.jsonl.gz")" 640
expect "kev : version du catalogue relevée" "$(jq -r .details.catalog_version "$T/var/lib/scanoria/feeds/.store/kev/status.json")" 2026.11.24
sum=$(sha256sum "$EXPORT/kev.jsonl.gz" | cut -d' ' -f1)
bad_kev() { # libellé motif document
	kev "$3"
	refresh "$KEV"
	expect "kev : $1 refusé" "${R%% *}/$(grep -c -- "$2" <<< "$R")" E_FEED_UNAVAILABLE/1
	expect "kev : $1 → export précédent intact" "$(sha256sum "$EXPORT/kev.jsonl.gz" | cut -d' ' -f1)" "$sum"
}
bad_kev "nombre annoncé faux" "announces 5 entries" '{count: 5, vulnerabilities: [{cveID: "CVE-2026-0001", dateAdded: "2026-11-01"}]}'
bad_kev "date d'ajout invalide" "invalid dateAdded" '{vulnerabilities: [{cveID: "CVE-2026-0001", dateAdded: "2026-02-30"}]}'
bad_kev "CVE invalide" "invalid CVE identifier" '{vulnerabilities: [{cveID: "../../etc", dateAdded: "2026-11-01"}]}'
bad_kev "CVE d'un type inattendu" "invalid CVE identifier" '{vulnerabilities: [{cveID: 5, dateAdded: "2026-11-01"}]}'
bad_kev "entrée qui n'est pas un objet" "is not an object" '{vulnerabilities: ["CVE-2026-0001"]}'
bad_kev "liste absente" "no vulnerability list" '[1, 2]'
bad_kev "liste vide" "unexpected number of entries" '{vulnerabilities: []}'
printf '{"vulnerabilities": [' > "$SRV/kev.json"
refresh "$KEV"
expect "kev : JSON tronqué refusé" "${R%% *}/$(grep -c 'not valid JSON' <<< "$R")" E_FEED_UNAVAILABLE/1
echo down > "$SRV/mode"
refresh "$KEV"
expect "kev : serveur en panne → export précédent gardé" "${R%% *}/$(sha256sum "$EXPORT/kev.jsonl.gz" | cut -d' ' -f1)" "E_FEED_UNAVAILABLE/$sum"
rm "$SRV/mode"

# --- Export : échec d'écriture, déclaration, retrait ---------------------------
kev '{vulnerabilities: [{cveID: "CVE-2026-0001", dateAdded: "2026-11-01"}, {cveID: "CVE-2026-0007", dateAdded: "2026-11-20"}]}'
chmod 0500 "$EXPORT"
refresh "$KEV"
chmod 0750 "$EXPORT"
if [[ $(id -u) -eq 0 ]]; then
	ok "kev : export impossible (ignoré en root, qui écrit malgré les droits)"
else
	expect "kev : export impossible → E_EXPORT_FAILED, base active" "${R%% *}/$(jq -r .status "$T/var/lib/scanoria/feeds/.store/kev/status.json")" E_EXPORT_FAILED/ok
fi
R=$(python3 - <<-'PY' 2>&1 || true
	import os, sys
	sys.path.insert(0, os.environ["PYLIB"])
	from scanoria import feeds
	from scanoria.common import Fail
	try:
	    feeds.export_format({"id": "x", "feed": {"export": {"format": "csv"}}})
	    print("OK")
	except Fail as f:
	    print(f.code)
PY
)
expect "export d'un format inconnu refusé" "$R" E_PRECONDITION
python3 - <<-'PY'
	import os, sys
	sys.path.insert(0, os.environ["PYLIB"])
	from scanoria import feeds
	feeds.remove("kev")
PY
expect "kev : export retiré à la désinstallation" "$([[ -e "$EXPORT/kev.jsonl.gz" ]] && echo présent || echo absent)/$([[ -e "$EXPORT/epss.jsonl.gz" ]] && echo epss)" absent/epss

# --- Manifestes du dépôt ------------------------------------------------------
for id in epss kev; do
	got=$(python3 -c 'import json, sys, yaml; m = yaml.safe_load(open(sys.argv[1])); f = m["feed"]
print(m["type"], f["source"]["kind"], f["export"]["format"], m["requires"]["appliance"], m["license"]["restrictions"])' \
		"$ROOT/modules/$id/module.yaml")
	expect "manifeste $id : feed https exporté, réservé à la 0.5, sans restriction" "$got" "feed https jsonl.gz >=0.5.0 none"
done
expect "sélection conseillée : epss et kev proposés" \
	"$(grep -c "'epss', 'kev'" "$ROOT/webui/server/utils/catalog.ts")" 1

echo "b23 : $PASS réussis, $FAIL échoués"
[[ $FAIL -eq 0 ]]
