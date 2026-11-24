#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Vincent Tisseront
#
# b22 — demande « package-dates » du helper (H5, quarantaine), sans root.
# Mode test (SCANORIA_TEST_ROOT) ; curl est le vrai, qui ne fait confiance
# qu'à une AC jetable ; les registres sont de faux registres HTTPS locaux
# (tests/lib/fakeregistry.py), un préfixe par écosystème.
# Cas : dates des 8 écosystèmes, réponses piégées (taille, JSON invalide,
# redirection hors du registre, délai, date mal formée), purl hostiles,
# cache (date définitive, absence gardée un jour), mode sans réseau (tout
# null, la demande réussit), schéma de la demande.
# Dépendances : bash, python3, curl, openssl, jq.

# shellcheck disable=SC2016
set -euo pipefail
export PYTHONDONTWRITEBYTECODE=1

for t in python3 curl openssl jq; do command -v "$t" > /dev/null || { echo "outil manquant : $t" >&2; exit 2; }; done

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
PYLIB="$ROOT/src/rootfs/usr/lib/scanoria/py"
HELPER="$ROOT/src/rootfs/usr/sbin/scanoria-helper"
TMP=$(mktemp -d)
SRV_PID=
cleanup() {
	[[ -n "$SRV_PID" ]] && kill "$SRV_PID" 2> /dev/null || true
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

T="$TMP/root"
STUBS="$TMP/stubs"
mkdir -p "$T"/var/lib/scanoria/requests/{tmp,incoming,work,done,failed} "$T/run/scanoria" "$T/etc" "$STUBS"
chmod 0700 "$T/var/lib/scanoria/requests/incoming" "$T/var/lib/scanoria/requests/work"
export SCANORIA_TEST_ROOT="$T" SCANORIA_TEST_BIN="$STUBS"

openssl req -x509 -newkey ed25519 -nodes -days 1 -subj "/CN=b22" -addext "subjectAltName=IP:127.0.0.1" \
	-keyout "$TMP/srv.key" -out "$TMP/srv.pem" 2> /dev/null
CURL=$(command -v curl)
cat > "$STUBS/curl" <<-EOF
	#!/bin/bash
	printf '%s\n' "\$*" >> "$TMP/curl.log"
	exec "$CURL" --cacert "$TMP/srv.pem" --noproxy 127.0.0.1 "\$@"
EOF
chmod 0755 "$STUBS/curl"

python3 "$ROOT/tests/lib/fakeregistry.py" serve "$TMP/srv.pem" "$TMP/srv.key" "$TMP/port" "$TMP/requests.log" &
SRV_PID=$!
for _ in $(seq 50); do [[ -s "$TMP/port" ]] && break; sleep 0.1; done
PORT=$(cat "$TMP/port")
export SCANORIA_TEST_PKGDATES_BASE="https://127.0.0.1:$PORT"

# lookup PURL… : {dates, stats} en JSON
lookup() {
	python3 -I -B - "$PYLIB" "$@" <<-'EOF'
	import json, sys
	sys.path.insert(0, sys.argv[1])
	from scanoria import pkgdates
	dates, stats = pkgdates.lookup(sys.argv[2:], 120)
	print(json.dumps({"dates": dates, "stats": stats}))
	EOF
}
date_of() { jq -r --arg p "$1" '.dates[$p] // "null"' <<< "$R"; }

# --- 1. Huit écosystèmes ---------------------------------------------------------------------
R=$(lookup "pkg:npm/bon@1.0.0" "pkg:npm/%40exemple/outil@2.0.0" "pkg:pypi/bon@1.0.0" "pkg:cargo/bon@1.0.0" \
	"pkg:golang/github.com/Exemple/bon@v1.0.0" "pkg:maven/org.exemple/bon@1.0.0" "pkg:gem/bon@1.0.0" \
	"pkg:nuget/Bon@1.0.0" "pkg:composer/exemple/bon@1.0.0")
expect "npm : date de la version" "$(date_of pkg:npm/bon@1.0.0)" 2026-11-20T08:00:00Z
expect "npm à portée : @exemple/outil" "$(date_of pkg:npm/%40exemple/outil@2.0.0)" 2026-11-23T10:00:00Z
expect "PyPI : premier fichier publié" "$(date_of pkg:pypi/bon@1.0.0)" 2026-11-21T09:00:00Z
expect "crates.io : created_at" "$(date_of pkg:cargo/bon@1.0.0)" 2026-11-19T07:00:00Z
expect "proxy Go : chemin encodé (!exemple)" "$(date_of pkg:golang/github.com/Exemple/bon@v1.0.0)" 2026-11-18T06:00:00Z
expect "Maven Central : horodatage en ms" "$(date_of pkg:maven/org.exemple/bon@1.0.0)" 2025-11-20T08:00:00Z
expect "RubyGems : version ruby" "$(date_of pkg:gem/bon@1.0.0)" 2026-11-17T05:00:00Z
expect "NuGet : identifiant en minuscules" "$(date_of pkg:nuget/Bon@1.0.0)" 2026-11-16T04:00:00Z
expect "Packagist : version préfixée v" "$(date_of pkg:composer/exemple/bon@1.0.0)" 2026-11-15T03:00:00Z
expect "statistiques : 9 cherchés" "$(jq -r .stats.looked_up <<< "$R")" 9

# --- 2. Réponses piégées ---------------------------------------------------------------------
R=$(lookup "pkg:npm/geant@1.0.0" "pkg:npm/casse@1.0.0" "pkg:npm/ailleurs@1.0.0" "pkg:npm/datebizarre@1.0.0" "pkg:npm/inconnu@1.0.0")
for p in geant casse ailleurs datebizarre inconnu; do
	expect "piège npm « $p » : null" "$(date_of "pkg:npm/$p@1.0.0")" null
done
expect "redirection jamais suivie (aucune requête vers l'autre hôte)" "$(grep -c '192.0.2.1' "$TMP/curl.log" || true)" 0
grep -q -- '--max-redirs 0' "$TMP/curl.log" && ok "curl : --max-redirs 0" || ko "curl : redirections permises"
grep -q -- '--proto =https' "$TMP/curl.log" && ok "curl : HTTPS seul" || ko "curl : protocole non restreint"
R=$(lookup "pkg:npm/lent@1.0.0")
expect "délai dépassé : null" "$(date_of pkg:npm/lent@1.0.0)" null

# --- 3. purl hostiles ------------------------------------------------------------------------
: > "$TMP/requests.log"
R=$(lookup "pkg:npm/../../etc/passwd@1" "pkg:npm/a%2F..%2F..@1" "pkg:deb/debian/bash@5.2" "pkg:npm/sans-version" \
	"pkg:npm/x@1%0a" "pkg:pypi/a/b@1" 'pkg:npm/%00nul@1' "pkg:npm/bon@1.0.0;rm")
expect "purl hostiles : tous null" "$(jq -r '[.dates[]] | map(select(. != null)) | length' <<< "$R")" 0
expect "purl hostiles : aucun registre interrogé" "$(wc -l < "$TMP/requests.log" | tr -d ' ')" 0
expect "purl hostiles : comptés non pris en charge" "$(jq -r .stats.unsupported <<< "$R")" 8

# --- 4. Cache --------------------------------------------------------------------------------
: > "$TMP/requests.log"
R=$(lookup "pkg:npm/bon@1.0.0" "pkg:npm/inconnu@1.0.0")
expect "cache : date et absence servies sans requête" "$(wc -l < "$TMP/requests.log" | tr -d ' ')/$(jq -r .stats.cached <<< "$R")" 0/2
expect "cache : date gardée" "$(date_of pkg:npm/bon@1.0.0)" 2026-11-20T08:00:00Z
expect "cache : répertoire 0700" "$(stat -c %a "$T/var/lib/scanoria/cache/package-dates")" 700
f=$(ls "$T/var/lib/scanoria/cache/package-dates" | head -1)
expect "cache : fichiers 0600" "$(stat -c %a "$T/var/lib/scanoria/cache/package-dates/$f")" 600
# Une absence de plus d'un jour est cherchée de nouveau ; une date ne l'est jamais.
python3 -I -B - "$PYLIB" <<-'EOF'
import json, os, sys
sys.path.insert(0, sys.argv[1])
from scanoria import pkgdates
p = pkgdates._cache_path("pkg:npm/inconnu@1.0.0")
o = json.load(open(p)); o["checked_at"] -= 2 * 86400; json.dump(o, open(p, "w"))
EOF
: > "$TMP/requests.log"
R=$(lookup "pkg:npm/bon@1.0.0" "pkg:npm/inconnu@1.0.0")
expect "cache : absence échue cherchée de nouveau" "$(grep -c inconnu "$TMP/requests.log" || true)/$(grep -c '/npm/bon' "$TMP/requests.log" || true)" 1/0
# Fichier de cache piégé (autre purl, lien symbolique) : ignoré.
python3 -I -B - "$PYLIB" <<-'EOF'
import json, os, sys
sys.path.insert(0, sys.argv[1])
from scanoria import pkgdates
json.dump({"purl": "pkg:npm/autre@1", "published_at": "2000-01-01T00:00:00Z"}, open(pkgdates._cache_path("pkg:cargo/bon@1.0.0"), "w"))
p = pkgdates._cache_path("pkg:gem/bon@1.0.0"); os.unlink(p); os.symlink("/etc/hostname", p)
EOF
R=$(lookup "pkg:cargo/bon@1.0.0" "pkg:gem/bon@1.0.0")
expect "cache piégé : ignoré, date du registre" "$(date_of pkg:cargo/bon@1.0.0)/$(date_of pkg:gem/bon@1.0.0)" 2026-11-19T07:00:00Z/2026-11-17T05:00:00Z

# --- 5. Sans réseau --------------------------------------------------------------------------
kill "$SRV_PID"; wait "$SRV_PID" 2> /dev/null || true; SRV_PID=
R=$(lookup "pkg:npm/neuf1@1.0.0" "pkg:npm/neuf2@1.0.0" "pkg:npm/neuf3@1.0.0" "pkg:npm/neuf4@1.0.0" "pkg:npm/neuf5@1.0.0" "pkg:npm/bon@1.0.0")
expect "hors ligne : tout null sauf le cache" "$(jq -c '[.dates[]] | map(select(. != null))' <<< "$R")" '["2026-11-20T08:00:00Z"]'
expect "hors ligne : signalé" "$(jq -r .stats.offline <<< "$R")" true
expect "hors ligne : erreurs réseau jamais mises en cache" "$(python3 -I -B -c 'import os, sys; sys.path.insert(0, sys.argv[1]); from scanoria import pkgdates; print(os.path.exists(pkgdates._cache_path("pkg:npm/neuf1@1.0.0")))' "$PYLIB")" False

# --- 6. Demande au helper : schéma et résultat -----------------------------------------------
hx() {
	R=$("$HELPER" exec --origin cli --type package-dates --params "$1" 2> "$TMP/helper.err") || true
	[[ -n "$R" ]] || { R='{"code":"NO_OUTPUT"}'; sed 's/^/     /' "$TMP/helper.err"; }
}
hx '{"purls": ["pkg:npm/bon@1.0.0", "pkg:npm/neuf1@1.0.0"]}'
expect "helper : demande réussie même hors ligne" "$(jq -r .code <<< "$R")" OK
expect "helper : sortie {dates}" "$(jq -c '.output.dates | [.["pkg:npm/bon@1.0.0"], .["pkg:npm/neuf1@1.0.0"]]' <<< "$R")" '["2026-11-20T08:00:00Z",null]'
for bad in '{}' '{"purls": []}' '{"purls": ["npm/bon@1"]}' '{"purls": ["pkg:npm/a b@1"]}' \
	'{"purls": ["pkg:npm/x@1", "pkg:npm/x@1"]}' '{"purls": ["pkg:npm/x@1"], "force": true}'; do
	hx "$bad"
	expect "helper : demande hostile refusée $(cut -c1-40 <<< "$bad")" "$(jq -r .code <<< "$R")" E_SCHEMA
done
big=$(python3 -c 'import json; print(json.dumps({"purls": ["pkg:npm/p%d@1.0.0" % i for i in range(2001)]}))')
hx "$big"
expect "helper : plus de 2 000 purl refusés" "$(jq -r .code <<< "$R")" E_SCHEMA

echo
echo "b22 : $PASS réussis, $FAIL échoués"
[[ "$FAIL" -eq 0 ]]
