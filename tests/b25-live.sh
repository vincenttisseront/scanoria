#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Vincent Tisseront
#
# b25-live — lot hors ligne réel (0.6, chantier A, job CI bundle-live, machine
# de test root jetable). Deux appliances en mode test sur des racines
# temporaires, avec le vrai podman, le vrai skopeo et le vrai openssl :
#   A (connectée) : index réel du dépôt (catalog/build.py, signé par une clé
#     jetable), export de gitleaks et de la base osv-db, téléchargées depuis
#     leurs vraies sources (registre de l'image, export OSV) ;
#   B (hors ligne) : chaque demande au helper tourne dans un espace de noms
#     réseau vide (unshare --net), donc sans aucun accès, comme une appliance
#     isolée. B fait confiance à la clé de A, importe le lot, installe
#     gitleaks depuis l'image importée (aucun pull), son banc d'essai réussit,
#     puis la base osv-db importée est gardée à l'installation du feed.
#   Miroir des bases servi à Dependency-Track en HTTPS : certificat feeds.<nom>
#     de l'AC interne, magasin Java construit par le keytool de la vraie image
#     de Dependency-Track, site nginx rendu par routing et servi par le vrai
#     nginx ; le JVM de cette image, avec ce magasin monté en lecture seule,
#     accepte le miroir et refuse un autre nom ou le magasin d'origine.
# Dépendances : bash, python3, python3-yaml, jq, openssl, zstd, tar, curl,
# podman, skopeo, unshare, nginx, javac (root).

# shellcheck disable=SC2016
set -euo pipefail
export PYTHONDONTWRITEBYTECODE=1

[[ "$(id -u)" -eq 0 ]] || { echo "b25-live : root requis (podman réel)" >&2; exit 2; }
for t in python3 jq openssl zstd tar curl podman skopeo unshare nginx javac; do
	command -v "$t" > /dev/null || { echo "outil manquant : $t" >&2; exit 2; }
done

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
HELPER="$ROOT/src/rootfs/usr/sbin/scanoria-helper"
TMP=$(mktemp -d)
NGX_PID=""
cleanup() {
	[[ -n "$NGX_PID" ]] && kill "$NGX_PID" 2> /dev/null
	podman secret rm scanoria-test-truststore > /dev/null 2>&1 || true
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

STUBS="$TMP/stubs"
REL="$TMP/rel/catalog-v1"
mkdir -p "$STUBS" "$REL"
openssl genpkey -algorithm ed25519 -out "$TMP/sign.key" 2> /dev/null
openssl pkey -in "$TMP/sign.key" -pubout -out "$TMP/sign.pub"
python3 -I "$ROOT/catalog/build.py" build --version 1 --out "$REL"
openssl pkeyutl -sign -inkey "$TMP/sign.key" -rawin -in "$REL/SHA256SUMS" -out "$REL/SHA256SUMS.sig"
echo '[{"tag_name": "catalog-v1", "name": "Catalogue Scanoria 1", "draft": false, "prerelease": false}]' > "$TMP/api.json"

ln -s "$(command -v podman)" "$STUBS/podman"
ln -s "$(command -v skopeo)" "$STUBS/skopeo"
# curl : releases du catalogue servies depuis le disque ; tout le reste part
# vers le vrai curl (vraies sources pour A, aucun réseau pour B).
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
export SCANORIA_TEST_BIN="$STUBS"

mkroot() {
	local r=$1
	mkdir -p "$r"/var/lib/scanoria/requests/{tmp,incoming,work,done,failed} "$r/run/scanoria" "$r/etc/scanoria" \
		"$r/opt/scanoria/current" "$r/proc" "$r/var/lib/scanoria/uploads"
	echo 0.6.0 > "$r/opt/scanoria/current/VERSION"
	cp /proc/meminfo "$r/proc/meminfo"
	grep '^processor' /proc/cpuinfo > "$r/proc/cpuinfo"
	echo '{"repo": "exemple/scanoria"}' > "$r/etc/scanoria/catalog.json"
	echo '{"fqdn": "analyse.exemple.test"}' > "$r/etc/scanoria/appliance.json"
	cp "$TMP/sign.pub" "$r/etc/scanoria/update-pubkey.pem"
}
A="$TMP/a"
B="$TMP/b"
mkroot "$A"
mkroot "$B"

# hx RACINE TYPE PARAMS [--offline] : demande au helper ; résultat dans $R
hx() {
	local pre=()
	[[ "${4:-}" == --offline ]] && pre=(unshare --net --)
	R=$(SCANORIA_TEST_ROOT="$1" "${pre[@]}" "$HELPER" exec --origin cli --type "$2" --params "$3" 2> "$TMP/helper.err") || true
	echo "--- $2 : $(jq -c '{code, message}' <<< "${R:-{\}}")"
	sed 's/^/     /' "$TMP/helper.err" | tail -n 30
}
code() { jq -r .code <<< "$R"; }
out() { jq -r ".output$1" <<< "$R"; }
ver() { jq -r --arg id "$1" '[.modules[] | select(.id == $id)][0].version' "$REL/catalog-index.json"; }
img() { jq -r --arg id "$1" '[.modules[] | select(.id == $id)][0].image' "$REL/catalog-index.json"; }
STATE="$B/var/lib/scanoria/modules/state.json"
mstate() { jq -r --arg id "$1" '[.modules[] | select(.id == $id)][0] | if . == null then "absent" else .status + "/" + (.enabled|tostring) end' "$STATE"; }

# Le réseau de B est vraiment coupé.
if unshare --net -- "$CURL" -fsS --max-time 5 -o /dev/null https://github.com 2> /dev/null; then
	ko "espace de noms réseau vide : Internet joignable"
else
	ok "espace de noms réseau vide : aucun accès"
fi

# --- A : appliance connectée ------------------------------------------------------
hx "$A" refresh-catalog '{}'
expect "A : catalogue réel installé" "$(code)" OK
GL_IMG=$(img gitleaks)
# L'image ne doit venir que du lot : retirée du stockage de podman avant tout.
podman rmi -f "$GL_IMG" "$(img git-fetch)" > /dev/null 2>&1 || true
start=$SECONDS
hx "$A" export-bundle '{"modules": ["gitleaks", "osv-db"]}'
echo "durée de l'export : $((SECONDS - start)) s, taille : $(out .size_bytes) octets"
expect "A : export" "$(code)" OK
# gitleaks requiert git-fetch (G1) : le lot porte les deux images et les deux bancs d'essai.
expect "A : contenu du lot" "$(out '.images | sort | join(",")')/$(out '.feeds | join(",")')/$(out .testbeds)" git-fetch,gitleaks/osv-db/2
BUNDLE="$A/var/lib/scanoria/bundles/$(out .name)"
expect "A : lot signé par sa clé" "$(out .signer_fingerprint)" "$(jq -r .appliance_key.fingerprint "$A/var/lib/scanoria/offline/status.json")"
expect "A : export sans pull dans podman" "$(podman image exists "$GL_IMG" && echo présente || echo absente)" absente
A_PUB=$(jq -r .appliance_key.public_key "$A/var/lib/scanoria/offline/status.json")
A_FP=$(jq -r .appliance_key.fingerprint "$A/var/lib/scanoria/offline/status.json")
FEED_AT=$(tar -xOf "$BUNDLE" manifest.json | jq -r '.feeds[0].updated_at')

# --- B : appliance hors ligne -------------------------------------------------------
hx "$B" trust-key '{"action": "add", "public_key": "'"$A_PUB"'", "fingerprint": "'"$A_FP"'"}' --offline
expect "B : clé de A ajoutée au magasin" "$(code)" OK
id=$(python3 -c 'import uuid; print(uuid.uuid4())')
mkdir -p "$B/var/lib/scanoria/uploads/$id"
cp "$BUNDLE" "$B/var/lib/scanoria/uploads/$id/bundle.tar"
start=$SECONDS
hx "$B" import-bundle '{"upload_id": "'"$id"'"}' --offline
echo "durée de l'import : $((SECONDS - start)) s"
expect "B : import hors ligne" "$(code)" OK
expect "B : index du catalogue installé" "$(out .catalog.installed)/$(jq -r .version "$B/var/lib/scanoria/catalog/catalog-index.json")" true/1
expect "B : images chargées par leur empreinte" "$(podman image exists "$GL_IMG" && podman image exists "$(img git-fetch)" && echo présentes || echo absentes)" présentes
expect "B : base osv-db, date d'origine gardée" "$(jq -r .updated_at "$B/var/lib/scanoria/feeds/.store/osv-db/status.json")" "$FEED_AT"
expect "B : téléversement supprimé" "$([[ -e "$B/var/lib/scanoria/uploads/$id" ]] && echo reste || echo supprimé)" supprimé

INST=$(jq -cn --arg v "$(ver gitleaks)" '{modules: [{id: "gitleaks", version: $v, options: {}}], accept_licenses: []}')
hx "$B" install-modules "$INST" --offline
expect "B : gitleaks installé hors ligne" "$(code)" OK
expect "B : gitleaks sain et activé" "$(mstate gitleaks)" healthy/true
expect "B : banc d'essai réussi" "$(jq -r '.modules[] | select(.id == "gitleaks") | .testbed.passed' "$STATE")" true
INST=$(jq -cn --arg v "$(ver osv-db)" '{modules: [{id: "osv-db", version: $v, options: {}}], accept_licenses: []}')
hx "$B" install-modules "$INST" --offline
expect "B : feed osv-db installé avec la base importée" "$(code)/$(mstate osv-db)" OK/healthy/true
expect "B : base importée gardée (pas de téléchargement)" "$(jq -r .updated_at "$B/var/lib/scanoria/feeds/.store/osv-db/status.json")" "$FEED_AT"
expect "aucun conteneur laissé" "$(podman ps -a --format '{{.Names}}' | grep -c '^scanoria-' || true)" 0

# --- Miroir des bases en HTTPS pour Dependency-Track ------------------------------------
FQDN=analyse.exemple.test
DT_IMG=$(img dependency-track)
podman pull -q "$DT_IMG" > /dev/null
SCANORIA_TEST_ROOT="$B" "$ROOT/src/rootfs/usr/sbin/scanoria-ca" init --fqdn "$FQDN" > /dev/null
py() { SCANORIA_TEST_ROOT="$B" PYTHONPATH="$ROOT/src/rootfs/usr/lib/scanoria/py" python3 -c "$1" "${@:2}"; }
TS=$(py '
import json, sys
from scanoria import dtmirror
m = [x for x in json.load(open(sys.argv[1]))["modules"] if x["id"] == "dependency-track"][0]
tls = dtmirror.ensure_tls()
print(json.dumps({"sans": tls["subject_alt_names"], "built": dtmirror.build_truststore(m),
                  "again": dtmirror.build_truststore(m), "again_tls": dtmirror.ensure_tls()["issued"]}))' "$REL/catalog-index.json")
expect "certificat feeds.<nom> de l'AC interne" "$(jq -c .sans <<< "$TS")" "[\"feeds.$FQDN\"]"
expect "certificat vérifié par l'AC interne" \
	"$(openssl verify -CAfile "$B/etc/scanoria/pki/ca/ca.crt" "$B/etc/scanoria/pki/feeds/fullchain.pem" > /dev/null && echo oui || echo non)" oui
expect "magasin Java construit, puis gardé (AC et image inchangées)" "$(jq -r '"\(.built)/\(.again)/\(.again_tls)"' <<< "$TS")" true/false/false
STORE="$B/var/lib/scanoria/modules/dependency-track/secrets/truststore"
JH=$(jq -r .java_home "$STORE.json")
expect "magasin Java : fichier root 0600" "$(stat -c %a "$STORE")" 600
podman secret rm scanoria-test-truststore > /dev/null 2>&1 || true
podman secret create scanoria-test-truststore "$STORE" > /dev/null

# Site nginx rendu par routing (chemins ramenés sous la racine de test), servi par le vrai nginx.
NGX="$TMP/nginx"
mkdir -p "$NGX/logs" "$B/var/lib/scanoria-feeds-mirror/osv/npm"
echo ok > "$B/var/lib/scanoria-feeds-mirror/osv/npm/modified_id.csv"
site() { # réseau autorisé
	py 'import sys
from scanoria import routing
sys.stdout.write(routing._render("feeds-mirror.conf.tmpl", "analyse.exemple.test", "", port="9790", allow=sys.argv[1]))' "$1" \
		| sed -e "s#/etc/scanoria/pki/#$B/etc/scanoria/pki/#" -e "s#/var/lib/scanoria-feeds-mirror#$B/var/lib/scanoria-feeds-mirror#"
}
ngx_start() { # réseau autorisé
	[[ -n "$NGX_PID" ]] && kill "$NGX_PID" 2> /dev/null && sleep 1
	site "$1" > "$NGX/site.conf"
	printf 'user root;\nworker_processes 1;\nerror_log %s/logs/error.log;\npid %s/nginx.pid;\nevents {}\nhttp {\naccess_log off;\ninclude %s/site.conf;\n}\n' \
		"$NGX" "$NGX" "$NGX" > "$NGX/nginx.conf"
	nginx -t -q -p "$NGX" -c "$NGX/nginx.conf" || ko "nginx -t sur le site rendu"
	nginx -p "$NGX" -c "$NGX/nginx.conf" -g 'daemon off;' &
	NGX_PID=$!
	for _ in $(seq 1 20); do (exec 3<> /dev/tcp/127.0.0.1/9790) 2> /dev/null && break; sleep 0.5; done
}
# probe URL [--sans-magasin] : JVM de l'image de Dependency-Track, sans privilège, en lecture
# seule (sonde compilée ici : l'image n'a pas de compilateur).
mkdir -p "$TMP/probe"
env -u JAVA_TOOL_OPTIONS -u _JAVA_OPTIONS javac -nowarn --release 17 -d "$TMP/probe" "$ROOT/tests/lib/TlsProbe.java"
chmod -R a+rX "$TMP/probe"
probe() {
	local trust=(--secret "scanoria-test-truststore,type=mount,target=$JH/lib/security/cacerts,mode=0444")
	[[ "${2:-}" == --sans-magasin ]] && trust=()
	podman run --rm --network=host --read-only --cap-drop=ALL --security-opt=no-new-privileges \
		--add-host "feeds.$FQDN:127.0.0.1" "${trust[@]}" -v "$TMP/probe:/probe:ro" \
		--entrypoint java "$DT_IMG" -cp /probe TlsProbe "$1" 2> /dev/null | tail -n 1
}
URL="https://feeds.$FQDN:9790/osv/npm/modified_id.csv"
ngx_start 127.0.0.1/32
expect "JVM de Dependency-Track + magasin monté : miroir HTTPS accepté" "$(probe "$URL")" 200
expect "JVM sans le magasin de l'appliance : certificat refusé" "$(probe "$URL" --sans-magasin)" untrusted
expect "autre nom que feeds.<nom> : refusé" "$(probe "https://127.0.0.1:9790/osv/npm/modified_id.csv")" untrusted
ngx_start 10.90.3.0/24
expect "réseau autre que celui de Dependency-Track : refusé par nginx" "$(probe "$URL")" 403
expect "aucun HTTP en clair sur le port du miroir" \
	"$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:9790/osv/npm/modified_id.csv")" 400

echo
echo "b25-live : $PASS réussis, $FAIL échoués"
[[ "$FAIL" -eq 0 ]]
