#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Vincent Tisseront
#
# b03 — AC interne et certificats (ARCHITECTURE § 7), sans root : scanoria-ca
# tourne en mode test (SCANORIA_TEST_ROOT) avec le vrai openssl, nginx et
# systemctl étant remplacés par des bouchons. Vérifie :
#   - profil de l'AC (ECDSA P-256, CA:TRUE pathlen:0, contrainte de nom) et
#     son effet réel (un certificat pour un autre nom ne se vérifie pas) ;
#   - certificat serveur : SAN <nom> et *.<nom>, serverAuth, 397 jours,
#     clé 0600, lien active, copie publique de l'AC ;
#   - pas de réémission inutile, réémission forcée, renouvellement à moins de
#     30 jours, nouvelle AC à chaque changement de nom (ancienne archivée) ;
#   - import : cas valide (RSA 2048 + chaîne) et refus (clé ne correspondant
#     pas, noms incomplets ou piégés, expiré, pas encore valide, valide moins
#     d'un jour, clé chiffrée, RSA 1024, Ed25519, P-521, deux certificats,
#     PEM illisible), l'état précédent restant actif ;
#   - si root et nginx présents : « nginx -t » sur le site généré.
# Dépendances : bash, openssl (≥ 3.0), jq.

# shellcheck disable=SC2016,SC2015
set -euo pipefail
shopt -s lastpipe

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
CA="$ROOT/src/rootfs/usr/sbin/scanoria-ca"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

PASS=0
FAIL=0
ok() { PASS=$((PASS + 1)); printf 'ok   %s\n' "$1"; }
ko() { FAIL=$((FAIL + 1)); printf 'FAIL %s\n' "$1"; }
expect() { if [[ "$2" == "$3" ]]; then ok "$1"; else ko "$1 (obtenu « $2 », attendu « $3 »)"; fi; }
for t in openssl jq; do command -v "$t" > /dev/null || { echo "outil manquant : $t" >&2; exit 2; }; done

T="$TMP/root"
X="$TMP/ext"
mkdir -p "$T/etc/scanoria" "$T/var/lib/scanoria" "$X"
export SCANORIA_TEST_ROOT="$T"
unset SCANORIA_TEST_BIN
N=analyse.exemple.test
PKI="$T/etc/scanoria/pki"

ca() { "$CA" "$@" 2> "$TMP/ca.err" || true; }
code() { jq -r .code <<< "$1" 2> /dev/null || echo "?"; }
text() { openssl x509 -in "$1" -noout -text; }
fp() { openssl x509 -in "$1" -noout -fingerprint -sha256 | cut -d= -f2; }
active() { readlink "$PKI/active" 2> /dev/null || echo none; }

# --- 1. AC interne ----------------------------------------------------------------
out=$(ca init --fqdn "$N")
expect "init → OK" "$(code "$out")" OK
C="$PKI/ca/ca.crt"
text "$C" > "$TMP/ca.txt"
grep -q 'ASN1 OID: prime256v1' "$TMP/ca.txt" && ok "AC : ECDSA P-256" || ko "AC : courbe"
grep -A1 'Basic Constraints: critical' "$TMP/ca.txt" | grep -q 'CA:TRUE, pathlen:0' && ok "AC : CA:TRUE, pathlen:0, critique" || ko "AC : basicConstraints"
grep -A1 'Key Usage: critical' "$TMP/ca.txt" | grep -q 'Certificate Sign, CRL Sign' && ok "AC : keyCertSign, cRLSign" || ko "AC : keyUsage"
grep -A2 'Name Constraints: critical' "$TMP/ca.txt" | grep -q "DNS:$N" && ok "AC : nameConstraints DNS:$N" || ko "AC : nameConstraints"
grep -q 'IP:0.0.0.0/0.0.0.0' "$TMP/ca.txt" && grep -q 'IP:0:0:0:0:0:0:0:0/0:0:0:0:0:0:0:0' "$TMP/ca.txt" \
	&& ok "AC : adresses IP exclues" || ko "AC : exclusions IP"
expect "AC : sujet" "$(openssl x509 -in "$C" -noout -subject -nameopt RFC2253)" "subject=CN=Scanoria CA $N"
expect "AC : clé privée 0600" "$(stat -c %a "$PKI/ca/ca.key")" 600
expect "AC : copie publique identique" "$(cmp -s "$C" "$T/var/lib/scanoria/public/scanoria-ca.crt" && echo same)" same
expect "AC : copie pour nginx identique" "$(cmp -s "$C" "$T/etc/nginx/scanoria/scanoria-ca.crt" && echo same)" same
expect "AC : empreinte annoncée" "$(jq -r .output.ca_fingerprint_sha256 <<< "$out")" "$(fp "$C" | tr -d : | tr 'A-F' 'a-f')"

# --- 2. Certificat serveur ---------------------------------------------------------------
out=$(ca issue --fqdn "$N")
expect "issue → OK, émis" "$(jq -r '"\(.code) \(.output.issued)"' <<< "$out")" "OK true"
L="$PKI/internal/fullchain.pem"
text "$L" > "$TMP/leaf.txt"
expect "certificat : SAN exacts" "$(jq -c .output.subject_alt_names <<< "$out")" "[\"$N\",\"*.$N\"]"
grep -A1 'Subject Alternative Name' "$TMP/leaf.txt" | grep -q "DNS:$N, DNS:\*.$N" && ok "certificat : SAN (openssl)" || ko "certificat : SAN"
grep -A1 'Extended Key Usage' "$TMP/leaf.txt" | grep -q 'TLS Web Server Authentication' && ok "certificat : serverAuth" || ko "certificat : EKU"
grep -q 'CA:FALSE' "$TMP/leaf.txt" && ok "certificat : CA:FALSE" || ko "certificat : basicConstraints"
grep -q 'ASN1 OID: prime256v1' "$TMP/leaf.txt" && ok "certificat : ECDSA P-256" || ko "certificat : courbe"
nb=$(date -u -d "$(openssl x509 -in "$L" -noout -startdate | cut -d= -f2)" +%s)
na=$(date -u -d "$(openssl x509 -in "$L" -noout -enddate | cut -d= -f2)" +%s)
expect "certificat : 397 jours" "$(( (na - nb) / 86400 ))" 397
serial=$(openssl x509 -in "$L" -noout -serial | cut -d= -f2)
[[ ${#serial} -ge 30 ]] && ok "certificat : numéro de série aléatoire ≥ 120 bits" || ko "certificat : numéro de série court ($serial)"
openssl verify -x509_strict -CAfile "$C" "$L" > /dev/null 2>&1 && ok "certificat : vérifié par l'AC" || ko "certificat : vérification"
for h in "$N" "www.$N"; do
	openssl x509 -in "$L" -noout -checkhost "$h" | grep -q 'does match' && ok "certificat : couvre $h" || ko "certificat : $h"
done
openssl x509 -in "$L" -noout -checkhost "a.b.$N" | grep -q 'does NOT match' && ok "certificat : ne couvre pas a.b.$N" || ko "joker sur deux niveaux"
expect "certificat : clé 0600" "$(stat -c %a "$PKI/internal/privkey.pem")" 600
expect "lien active → internal" "$(active)" internal
expect "tls.json : internal" "$(jq -r .mode "$T/etc/scanoria/tls.json")" internal
expect "status : mode et empreinte" "$(code "$(ca status)") $(jq -r .output.mode <<< "$(ca status)")" "OK internal"
if find "$TMP" -name '*.json' -newer "$C" -exec grep -l 'PRIVATE KEY' {} + 2> /dev/null | grep -q .; then
	ko "aucune clé dans les sorties JSON"
else
	ok "aucune clé dans les sorties JSON"
fi
grep -q 'PRIVATE KEY' <<< "$out$(ca status)" && ko "clé dans la sortie" || ok "aucune clé sur la sortie standard"

# La contrainte de nom est effective : l'AC ne peut pas signer un autre nom.
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$X/o.key" 2> /dev/null
openssl req -new -key "$X/o.key" -subj "/CN=autre.exemple.test" -out "$X/o.csr"
printf 'subjectAltName = DNS:autre.exemple.test\n' > "$X/o.ext"
openssl x509 -req -in "$X/o.csr" -CA "$C" -CAkey "$PKI/ca/ca.key" -days 30 -extfile "$X/o.ext" -out "$X/o.crt" 2> /dev/null
openssl verify -CAfile "$C" "$X/o.crt" > /dev/null 2>&1 && ko "contrainte de nom inopérante" || ok "contrainte de nom : autre.exemple.test refusé"

# --- 3. Réémission, renouvellement, changement de nom -----------------------------------------
f1=$(fp "$L")
expect "issue sans force, certificat valide → non réémis" "$(jq -r '"\(.code) \(.output.issued)"' <<< "$(ca issue --fqdn "$N")")" "OK false"
expect "empreinte inchangée" "$(fp "$L")" "$f1"
expect "issue --force → réémis" "$(jq -r '.output.issued' <<< "$(ca issue --fqdn "$N" --force)")" true
[[ "$(fp "$L")" != "$f1" ]] && ok "issue --force : nouveau certificat" || ko "issue --force : même certificat"
# Certificat à 10 jours de l'échéance : renouvelé sans --force.
printf 'subjectAltName = DNS:%s,DNS:*.%s\n' "$N" "$N" > "$X/s.ext"
openssl req -new -key "$PKI/internal/privkey.pem" -subj "/CN=$N" -out "$X/s.csr"
openssl x509 -req -in "$X/s.csr" -CA "$C" -CAkey "$PKI/ca/ca.key" -days 10 -extfile "$X/s.ext" -out "$L" 2> /dev/null
expect "certificat à < 30 jours → renouvelé" "$(jq -r '.output.issued' <<< "$(ca issue --fqdn "$N")")" true
na=$(date -u -d "$(openssl x509 -in "$L" -noout -enddate | cut -d= -f2)" +%s)
[[ $(( (na - $(date -u +%s)) / 86400 )) -ge 396 ]] && ok "renouvellement : 397 jours" || ko "renouvellement : durée"
expect "issue pour un autre nom que l'AC → E_PRECONDITION" "$(code "$(ca issue --fqdn "autre.exemple.test")")" E_PRECONDITION
expect "init : nom invalide → E_INVALID_PARAM" "$(code "$(ca init --fqdn 'x.exemple.test;id')")" E_INVALID_PARAM
expect "init : nom avec saut de ligne → E_INVALID_PARAM" "$(code "$(ca init --fqdn $'x.exemple.test\nCN = y')")" E_INVALID_PARAM
N2=scan.exemple.test
oldca=$(fp "$C")
expect "changement de nom : nouvelle AC" "$(code "$(ca init --fqdn "$N2")")" OK
[[ "$(fp "$C")" != "$oldca" ]] && ok "changement de nom : AC différente" || ko "changement de nom : même AC"
expect "changement de nom : ancienne AC archivée" "$(find "$PKI/ca/archive" -name ca.crt | wc -l)" 1
expect "changement de nom : certificat réémis sans --force" "$(jq -r '.output.issued' <<< "$(ca issue --fqdn "$N2")")" true
expect "changement de nom : SAN" "$(jq -c .output.subject_alt_names <<< "$(ca status)")" "[\"$N2\",\"*.$N2\"]"
N=$N2

# --- 4. Import ----------------------------------------------------------------------------------
# AC externe de test et certificats émis avec des dates choisies (openssl ca).
mkdir -p "$X/db/new"
: > "$X/db/index.txt"
echo 1000 > "$X/db/serial"
openssl req -x509 -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout "$X/extca.key" \
	-subj "/CN=Test external CA" -days 30 -out "$X/extca.crt" 2> /dev/null
cat > "$X/ca.cnf" <<-EOF
	[ca]
	default_ca = c
	[c]
	database = $X/db/index.txt
	new_certs_dir = $X/db/new
	serial = $X/db/serial
	default_md = sha256
	policy = p
	unique_subject = no
	copy_extensions = none
	[p]
	commonName = supplied
	[e]
	basicConstraints = CA:FALSE
	extendedKeyUsage = serverAuth
	subjectAltName = \${ENV::SANS}
EOF
# ext_cert SORTIE CLÉ SANS DÉBUT FIN (dates AAAAMMJJHHMMSSZ)
ext_cert() {
	openssl req -new -key "$2" -subj "/CN=$N" -out "$X/r.csr"
	SANS=$3 openssl ca -batch -notext -config "$X/ca.cnf" -cert "$X/extca.crt" -keyfile "$X/extca.key" \
		-in "$X/r.csr" -out "$1" -extensions e -startdate "$4" -enddate "$5" 2> "$TMP/openssl-ca.err" \
		|| { cat "$TMP/openssl-ca.err" >&2; return 1; }
}
d() { date -u -d "$1" +%Y%m%d%H%M%SZ; }
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$X/rsa.key" 2> /dev/null
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 -out "$X/p384.key" 2> /dev/null
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:1024 -out "$X/rsa1024.key" 2> /dev/null
openssl genpkey -algorithm ED25519 -out "$X/ed.key" 2> /dev/null
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-521 -out "$X/p521.key" 2> /dev/null
openssl genrsa -traditional -aes256 -passout pass:secret -out "$X/enc.key" 2048 2> /dev/null
SANS_OK="DNS:$N,DNS:*.$N"
ext_cert "$X/good.crt" "$X/rsa.key" "$SANS_OK" "$(d '-1 day')" "$(d '+20 days')"

imp() { # certificat clé [chaîne]
	local args=(import --fqdn "$N" --cert "$1" --key "$2")
	[[ -z "${3:-}" ]] || args+=(--chain "$3")
	code "$(ca "${args[@]}")"
}
refused() { # libellé code_attendu certificat clé
	expect "$1" "$(imp "$3" "$4")" "$2"
	expect "$1 : état précédent conservé" "$(active) $(jq -r .mode "$T/etc/scanoria/tls.json")" "internal internal"
}
cp "$X/rsa.key" "$X/rsa-copy.key"
refused "clé ne correspondant pas → E_CERT_KEY_MISMATCH" E_CERT_KEY_MISMATCH "$X/good.crt" "$X/p384.key"
ext_cert "$X/nowild.crt" "$X/rsa.key" "DNS:$N" "$(d '-1 day')" "$(d '+20 days')"
refused "sans *.<nom> → E_CERT_NAMES" E_CERT_NAMES "$X/nowild.crt" "$X/rsa.key"
ext_cert "$X/onlywild.crt" "$X/rsa.key" "DNS:*.$N" "$(d '-1 day')" "$(d '+20 days')"
refused "sans <nom> → E_CERT_NAMES" E_CERT_NAMES "$X/onlywild.crt" "$X/rsa.key"
ext_cert "$X/other.crt" "$X/rsa.key" "DNS:autre.exemple.test,DNS:*.autre.exemple.test" "$(d '-1 day')" "$(d '+20 days')"
refused "autre nom → E_CERT_NAMES" E_CERT_NAMES "$X/other.crt" "$X/rsa.key"
ext_cert "$X/parentwild.crt" "$X/rsa.key" "DNS:$N,DNS:*.exemple.test" "$(d '-1 day')" "$(d '+20 days')"
refused "joker du domaine parent → E_CERT_NAMES" E_CERT_NAMES "$X/parentwild.crt" "$X/rsa.key"
if ext_cert "$X/comma.crt" "$X/rsa.key" "DNS:*.$N,DNS:\"x.test, DNS:$N\"" "$(d '-1 day')" "$(d '+20 days')" 2> /dev/null; then
	refused "nom piégé « x.test, DNS:<nom> » → E_CERT_NAMES" E_CERT_NAMES "$X/comma.crt" "$X/rsa.key"
fi
ext_cert "$X/expired.crt" "$X/rsa.key" "$SANS_OK" "$(d '-60 days')" "$(d '-1 day')"
refused "certificat expiré → E_CERT_EXPIRED" E_CERT_EXPIRED "$X/expired.crt" "$X/rsa.key"
ext_cert "$X/future.crt" "$X/rsa.key" "$SANS_OK" "$(d '+2 days')" "$(d '+40 days')"
refused "certificat pas encore valide → E_CERT_EXPIRED" E_CERT_EXPIRED "$X/future.crt" "$X/rsa.key"
ext_cert "$X/short.crt" "$X/rsa.key" "$SANS_OK" "$(d '-1 day')" "$(d '+12 hours')"
refused "valide moins d'un jour → E_CERT_EXPIRED" E_CERT_EXPIRED "$X/short.crt" "$X/rsa.key"
refused "clé chiffrée → E_CERT_INVALID" E_CERT_INVALID "$X/good.crt" "$X/enc.key"
for k in rsa1024 ed p521; do
	ext_cert "$X/$k.crt" "$X/$k.key" "$SANS_OK" "$(d '-1 day')" "$(d '+20 days')"
	refused "clé $k refusée → E_CERT_INVALID" E_CERT_INVALID "$X/$k.crt" "$X/$k.key"
done
cat "$X/good.crt" "$X/good.crt" > "$X/two.crt"
refused "deux certificats dans cert_pem → E_CERT_INVALID" E_CERT_INVALID "$X/two.crt" "$X/rsa.key"
printf -- '-----BEGIN CERTIFICATE-----\nQUFBQQ==\n-----END CERTIFICATE-----\n' > "$X/garbage.crt"
refused "PEM illisible → E_CERT_INVALID" E_CERT_INVALID "$X/garbage.crt" "$X/rsa.key"
printf 'not a key\n' > "$X/bad.key"
refused "clé illisible → E_CERT_INVALID" E_CERT_INVALID "$X/good.crt" "$X/bad.key"

expect "import valide (RSA 2048 + chaîne) → OK" "$(imp "$X/good.crt" "$X/rsa.key" "$X/extca.crt")" OK
expect "import : lien active → imported, tls.json" "$(active) $(jq -r .mode "$T/etc/scanoria/tls.json")" "imported imported"
expect "import : fullchain = certificat + chaîne" "$(grep -c 'BEGIN CERTIFICATE' "$PKI/imported/fullchain.pem")" 2
expect "import : clé 0600, PKCS#8" "$(stat -c %a "$PKI/imported/privkey.pem") $(head -n 1 "$PKI/imported/privkey.pem")" "600 -----BEGIN PRIVATE KEY-----"
expect "import ECDSA P-384 → OK" "$(ext_cert "$X/p384.crt" "$X/p384.key" "$SANS_OK" "$(d '-1 day')" "$(d '+20 days')" && imp "$X/p384.crt" "$X/p384.key")" OK
expect "issue sans force après import → retour au mode interne" \
	"$(code "$(ca issue --fqdn "$N")") $(active) $(jq -r .mode "$T/etc/scanoria/tls.json")" "OK internal internal"

# --- 5. nginx -t sur le site généré (root et nginx seulement) ----------------------------------
if [[ $EUID -eq 0 ]] && command -v nginx > /dev/null; then
	mkdir -p "$TMP/ng/scanoria.d"
	sed -e "s/@FQDN@/$N/g" -e "s#/etc/scanoria/#$T/etc/scanoria/#g" -e "s#/etc/nginx/scanoria/#$T/etc/nginx/scanoria/#g" \
		-e "s#/etc/nginx/scanoria.d/#$TMP/ng/scanoria.d/#" "$ROOT/src/rootfs/usr/share/scanoria/nginx/scanoria.conf.tmpl" > "$TMP/ng/site.conf"
	[[ -e /proc/net/if_inet6 ]] || sed -i '/listen \[::\]/d' "$TMP/ng/site.conf"
	cat > "$TMP/ng/nginx.conf" <<-EOF
		pid $TMP/ng/nginx.pid;
		error_log stderr;
		events {}
		http {
			include /etc/nginx/mime.types;
			access_log off;
			ssl_protocols TLSv1 TLSv1.1 TLSv1.2 TLSv1.3;
			ssl_prefer_server_ciphers on;
			include $TMP/ng/site.conf;
		}
	EOF
	nginx -t -q -c "$TMP/ng/nginx.conf" 2> "$TMP/ng/err" && ok "nginx -t : site généré valide" \
		|| { ko "nginx -t : site généré"; sed 's/^/     /' "$TMP/ng/err"; }
else
	echo "skip nginx -t (root et nginx requis)"
fi

echo
echo "b03 : $PASS réussi(s), $FAIL échec(s)"
[[ $FAIL -eq 0 ]]
