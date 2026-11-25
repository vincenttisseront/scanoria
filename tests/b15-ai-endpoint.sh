#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Vincent Tisseront
#
# b15 — connecteur IA (CLAUDE.md § 3.5, chantier F de la 0.3), sans root :
# demande set-ai-endpoint du helper et scanoria-ai-setup en mode test
# (SCANORIA_TEST_ROOT) ; nft, systemctl, ip, resolvectl, runuser et curl sont
# des bouchons. Couvre : adresses mal formées, http sans allow_insecure, jeton
# sans https, adresses interdites (bouclage, lien local, multidiffusion,
# non spécifiée, IPv4 encapsulée, adresse de l'appliance), nom qui résout vers
# le bouclage (même parmi d'autres adresses), nom qui ne résout pas, AC
# invalide ou contenant une clé privée, épinglage et règle nftables limitée à
# l'UID de scanoria-ai, échec de nft et retour à la configuration précédente,
# changement de résolution signalé sans élargir la règle, règle retirée,
# serveur candidat ollama.<domaine>, préparation du service (rôle PostgreSQL,
# fichiers copiés), contrôle selftest ai.alive.
# Dépendances : bash, python3, jq, openssl.

# Les motifs jq et les programmes Python sont volontairement entre apostrophes.
# shellcheck disable=SC2016,SC2015
set -euo pipefail
export PYTHONDONTWRITEBYTECODE=1

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
PY="$ROOT/src/rootfs/usr/lib/scanoria/py"
HELPER="$ROOT/src/rootfs/usr/sbin/scanoria-helper"
SETUP="$ROOT/src/rootfs/usr/sbin/scanoria-ai-setup"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

PASS=0
FAIL=0
ok() { PASS=$((PASS + 1)); printf 'ok   %s\n' "$1"; }
ko() { FAIL=$((FAIL + 1)); printf 'FAIL %s\n' "$1"; }
expect() { if [[ "$2" == "$3" ]]; then ok "$1"; else ko "$1 (obtenu « $2 », attendu « $3 »)"; fi; }
for t in python3 jq openssl; do command -v "$t" > /dev/null || { echo "outil manquant : $t" >&2; exit 2; }; done

T="$TMP/root"
STUBS="$TMP/stubs"
CALLS="$TMP/calls.log"
mkdir -p "$T"/var/lib/scanoria/requests/{tmp,incoming,work,done,failed} "$T/run/scanoria" \
	"$T/etc/scanoria/nftables" "$T/var/lib/scanoria/console" "$T/var/lib/scanoria/selftest" "$STUBS" "$TMP/dns"
export SCANORIA_TEST_ROOT="$T" SCANORIA_TEST_BIN="$STUBS" SCANORIA_TEST_AI_UID=64990
unset SCANORIA_TEST_OWNER_UID SCANORIA_TEST_NOW

log_call() { printf 'jq -cn --arg c %s %s >> "%s"\n' "$1" "'[\$c] + \$ARGS.positional' --args -- \"\$@\"" "$CALLS"; }
# nft : code de sortie lu dans $TMP/nft-rc (-c) et $TMP/nft-load-rc (-f), 0 par défaut.
cat > "$STUBS/nft" <<-EOF
	#!/bin/bash
	$(log_call nft)
	if [[ "\$1" == -c ]]; then exit "\$(cat "$TMP/nft-rc" 2> /dev/null || echo 0)"; fi
	exit "\$(cat "$TMP/nft-load-rc" 2> /dev/null || echo 0)"
EOF
cat > "$STUBS/systemctl" <<-EOF
	#!/bin/bash
	$(log_call systemctl)
	[[ "\$1" == is-active ]] && exit "\$(cat "$TMP/active-rc" 2> /dev/null || echo 0)"
	exit 0
EOF
cat > "$STUBS/runuser" <<-EOF
	#!/bin/bash
	$(log_call runuser)
	exit "\$(cat "$TMP/psql-rc" 2> /dev/null || echo 0)"
EOF
# ip : adresse de l'appliance dans $TMP/ip4.
cat > "$STUBS/ip" <<-EOF
	#!/bin/bash
	if [[ "\$2" == addr ]]; then
		[[ -e "$TMP/ipaddr-fail" ]] && exit 2
		printf '[{"ifname":"lo","addr_info":[{"local":"127.0.0.1"}]},{"ifname":"eth0","addr_info":[{"local":"%s"}]},{"ifname":"eth1","addr_info":[{"local":"203.0.113.250"},{"local":"fe80::1"}]}]\n' "\$(cat "$TMP/ip4" 2> /dev/null)"
		exit 0
	fi
	f="$TMP/ip4"; [[ "\$2" == -6 ]] && f="$TMP/ip6"
	[[ -s "\$f" ]] || exit 2
	printf '[{"dst":"%s","prefsrc":"%s"}]\n' "\$5" "\$(cat "\$f")"
EOF
# resolvectl : réponses dans $TMP/dns/<nom>.<type>.
cat > "$STUBS/resolvectl" <<-EOF
	#!/bin/bash
	$(log_call resolvectl)
	name=\${!#}; type=\${*: -2:1}
	if [[ -f "$TMP/dns/\$name.\$type" ]]; then cat "$TMP/dns/\$name.\$type"
	else echo "\$name: resource record not found" >&2; exit 1; fi
EOF
# curl : réponse de /api/version dans $TMP/curl-<schéma> (absent = échec).
cat > "$STUBS/curl" <<-EOF
	#!/bin/bash
	$(log_call curl)
	url=\${!#}; f="$TMP/curl-\${url%%:*}"
	[[ -f "\$f" ]] || exit 7
	cat "\$f"
EOF
printf '#!/bin/bash\nexit 0\n' > "$STUBS/scanoria-state"
chmod 0755 "$STUBS"/*
echo 192.0.2.5 > "$TMP/ip4"
: > "$CALLS"

dns() { # nom type adresse...
	local n=$1 t=$2; shift 2
	: > "$TMP/dns/$n.$t"
	for a in "$@"; do printf '%s IN %s %s  -- link: eth0\n' "$n" "$t" "$a" >> "$TMP/dns/$n.$t"; done
}
hx() { # PARAMS : demande set-ai-endpoint, résultat dans $R
	R=$("$HELPER" exec --origin cli --type set-ai-endpoint --params "$1" 2> "$TMP/helper.err") || true
	[[ -n "$R" ]] || { R='{"code":"NO_OUTPUT"}'; sed 's/^/     /' "$TMP/helper.err"; }
}
code() { jq -r .code <<< "$R"; }
CONF="$T/etc/scanoria/ai.json"
NFT="$T/etc/scanoria/nftables/ai.nft"
STATUS="$T/run/scanoria/ai-status.json"
conf_hash() { cat "$CONF" "$NFT" 2> /dev/null | sha256sum | cut -c1-16; }
valid() { # schéma fichier
	python3 -I -c '
import sys
sys.path.insert(0, sys.argv[1])
from scanoria import common, schema
d = common.load_json_file(sys.argv[3], 1 << 20)
errs = schema.load("schemas", sys.argv[2]).errors(d)
print("ok" if not errs else errs[:3])' "$PY" "$1" "$2"
}

# --- 1. Adresses refusées avant toute résolution ----------------------------------------
for p in '{"enabled": true}' \
	'{"enabled": true, "url": "ftp://ollama.exemple.test"}' \
	'{"enabled": true, "url": "https://user@ollama.exemple.test"}' \
	'{"enabled": true, "url": "https://ollama.exemple.test/api"}' \
	'{"enabled": true, "url": "https://ollama.exemple.test?x=1"}' \
	'{"enabled": true, "url": "https://OLLAMA.exemple.test"}' \
	'{"enabled": true, "url": "https://ollama.exemple.test", "model": "x"}' \
	'{"enabled": false, "url": "https://ollama.exemple.test"}' \
	'{"enabled": true, "url": "https://ollama.exemple.test", "ca_pem": "-----BEGIN CERTIFICATE-----\nAAAA"}' \
	'{"enabled": true, "url": "https://[2001:db8::10:11434"}'; do
	hx "$p"
	expect "refusé par le schéma : $p" "$(code)" E_SCHEMA
done
for p in '{"enabled": true, "url": "http://ollama.exemple.test:11434"}' \
	'{"enabled": true, "url": "http://ollama.exemple.test:11434", "allow_insecure": true, "token": true}' \
	'{"enabled": true, "url": "https://ollama.exemple.test:99999"}' \
	'{"enabled": true, "url": "https://ollama:11434"}' \
	'{"enabled": true, "url": "https://ollama..exemple.test"}' \
	'{"enabled": true, "url": "https://[192.0.2.10]:11434"}' \
	'{"enabled": true, "url": "https://192.000.002.010:11434"}'; do
	hx "$p"
	expect "E_AI_URL : $p" "$(code)" E_AI_URL
done
[[ ! -e "$CONF" && ! -e "$NFT" ]] && ok "rien d'écrit après un refus" || ko "fichiers écrits malgré un refus"
grep -q '"resolvectl"' "$CALLS" && ko "résolution lancée pour une adresse refusée" || ok "aucune résolution pour une adresse refusée"

# --- 2. Adresses interdites --------------------------------------------------------------
for u in http://127.0.0.1:11434 http://127.8.9.1:11434 http://169.254.1.1:11434 http://224.0.0.1:11434 \
	http://0.0.0.0:11434 http://0.1.2.3:11434 http://240.0.0.1:11434 'http://[::1]:11434' \
	'http://[fe80::1]:11434' 'http://[ff02::1]:11434' 'http://[::ffff:127.0.0.1]:11434' \
	'http://[2002:7f00:1::1]:11434' 'http://[2001:0:4136:e378:8000:63bf:3fff:fdd2]:11434' \
	http://203.0.113.250:11434 http://192.0.2.5:11434; do
	hx "{\"enabled\": true, \"url\": \"$u\", \"allow_insecure\": true}"
	expect "adresse interdite : $u" "$(code)" E_AI_FORBIDDEN_ADDRESS
done
expect "adresse de l'appliance : motif" "$(jq -r .output.reason <<< "$R")" appliance
dns loop.exemple.test A 127.0.0.1
hx '{"enabled": true, "url": "https://loop.exemple.test:11434"}'
expect "nom qui résout vers le bouclage" "$(code)" E_AI_FORBIDDEN_ADDRESS
dns mixed.exemple.test A 192.0.2.10 127.0.0.1
hx '{"enabled": true, "url": "https://mixed.exemple.test:11434"}'
expect "une seule adresse interdite suffit" "$(code)" E_AI_FORBIDDEN_ADDRESS
dns v6loop.exemple.test AAAA ::1
dns v6loop.exemple.test A 192.0.2.10
hx '{"enabled": true, "url": "https://v6loop.exemple.test:11434"}'
expect "bouclage IPv6 parmi des IPv4 valides" "$(code)" E_AI_FORBIDDEN_ADDRESS
hx '{"enabled": true, "url": "https://absent.exemple.test:11434"}'
expect "nom qui ne résout pas" "$(code)" E_AI_UNRESOLVED
dns other-if.exemple.test A 203.0.113.250
hx '{"enabled": true, "url": "https://other-if.exemple.test:11434"}'
expect "adresse d'une autre interface de l'appliance" "$(jq -r .output.reason <<< "$R")" appliance
dns ok-if.exemple.test A 192.0.2.10
touch "$TMP/ipaddr-fail"
hx '{"enabled": true, "url": "https://ok-if.exemple.test:11434"}'
expect "adresses locales illisibles : refus (échec fermé)" "$(code)" E_INTERNAL
rm -f "$TMP/ipaddr-fail"
[[ ! -e "$CONF" ]] && ok "rien d'épinglé après un refus d'adresse" || ko "ai.json écrit malgré un refus"

# --- 3. AC ---------------------------------------------------------------------------------
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout "$TMP/ca.key" -out "$TMP/ca.pem" \
	-subj "/CN=AC de test" -days 1 2> /dev/null
dns ollama.exemple.test A 192.0.2.10
dns ollama.exemple.test AAAA 2001:db8::10
p=$(jq -cn --rawfile ca "$TMP/ca.pem" '{enabled: true, url: "http://ollama.exemple.test:11434", allow_insecure: true, ca_pem: $ca}')
hx "$p"
expect "AC refusée en http" "$(code)" E_AI_URL
p=$(jq -cn --rawfile ca "$TMP/ca.pem" --rawfile k "$TMP/ca.key" '{enabled: true, url: "https://ollama.exemple.test:11434", ca_pem: ($ca + $k)}')
hx "$p"
expect "AC contenant une clé privée" "$(code)" E_AI_CA
p=$(jq -cn '{enabled: true, url: "https://ollama.exemple.test:11434", ca_pem: ("-----BEGIN CERTIFICATE-----\n" + ("QUJD" * 20) + "\n-----END CERTIFICATE-----\n")}')
hx "$p"
expect "AC illisible" "$(code)" E_AI_CA
hx '{"enabled": true, "url": "http://ollama.exemple.test:11434", "allow_insecure": true, "skip_tls_verify": true}'
expect "vérification désactivée refusée en http (schéma)" "$(code)" E_SCHEMA
p=$(jq -cn --rawfile ca "$TMP/ca.pem" '{enabled: true, url: "https://ollama.exemple.test:11434", ca_pem: $ca, skip_tls_verify: true}')
hx "$p"
expect "vérification désactivée refusée avec une AC (schéma)" "$(code)" E_SCHEMA
hx '{"enabled": false, "skip_tls_verify": true}'
expect "skip_tls_verify sans connecteur : refusé par le schéma" "$(code)" E_SCHEMA

# --- 4. Épinglage ----------------------------------------------------------------------------
: > "$CALLS"
p=$(jq -cn --rawfile ca "$TMP/ca.pem" '{enabled: true, url: "https://ollama.exemple.test:11434", token: true, ca_pem: $ca}')
hx "$p"
expect "connecteur activé" "$(code)" OK
expect "adresses épinglées (IPv4 puis IPv6)" "$(jq -c .addresses "$CONF")" '["192.0.2.10","2001:db8::10"]'
expect "ai.json conforme au schéma" "$(valid ai-endpoint "$CONF")" ok
expect "ai.json : 0640" "$(stat -c %a "$CONF")" 640
expect "AC enregistrée" "$(cmp -s "$TMP/ca.pem" "$T/etc/scanoria/ai-ca.pem" && echo oui)" oui
grep -qxF $'\t\tmeta skuid 64990 ip daddr { 192.0.2.10 } tcp dport 11434 accept' "$NFT" \
	&& ok "nft : sortie IPv4 vers l'adresse et le port épinglés, pour l'UID de scanoria-ai" || ko "nft : règle IPv4"
grep -qxF $'\t\tmeta skuid 64990 ip6 daddr { 2001:db8::10 } tcp dport 11434 accept' "$NFT" \
	&& ok "nft : sortie IPv6" || ko "nft : règle IPv6"
expect "nft : tout le reste refusé pour cet UID, en dernier" "$(grep -v '^[[:space:]]*}' "$NFT" | tail -1)" $'\t\tmeta skuid 64990 counter reject'
expect "nft : aucune règle sans skuid" "$(grep -c 'accept$' "$NFT")" "$(grep -c 'meta skuid 64990 .* accept$' "$NFT")"
grep -q '^delete table inet scanoria_ai$' "$NFT" && ! grep -q 'flush ruleset' "$NFT" \
	&& ok "nft : seule la table inet scanoria_ai est remplacée" || ko "nft : table"
expect "nft -c avant nft -f" "$(jq -r 'select(.[0] == "nft") | .[1]' "$CALLS" | tr '\n' ' ')" "-c -f "
grep -qF '["systemctl","restart","scanoria-ai.service"]' "$CALLS" && ok "scanoria-ai redémarré" || ko "scanoria-ai non redémarré"
expect "ai-status.json après activation" "$(valid ai-status "$STATUS")" ok
grep -q '"token"\|secret' <<< "$(jq -c .output <<< "$R" | jq -c 'del(.token)')" && ko "secret dans la sortie" || ok "aucun secret dans la sortie"
expect "certificat vérifié par défaut" "$(jq -r .tls_verify "$CONF")" true

# --- 4 bis. Vérification du certificat désactivée (certificat autosigné) --------------------
hx '{"enabled": true, "url": "https://ollama.exemple.test:11434", "skip_tls_verify": true}'
expect "connecteur activé sans vérification" "$(code)" OK
expect "ai.json : tls_verify false" "$(jq -r .tls_verify "$CONF")" false
expect "sortie : tls_verify false" "$(jq -r .output.tls_verify <<< "$R")" false
expect "ai.json sans vérification conforme au schéma" "$(valid ai-endpoint "$CONF")" ok
[[ ! -e "$T/etc/scanoria/ai-ca.pem" ]] && ok "aucune AC gardée sans vérification" || ko "AC gardée sans vérification"
jq 'del(.tls_verify)' "$CONF" > "$TMP/old-ai.json"
expect "ai.json antérieur (sans tls_verify) toujours conforme" "$(valid ai-endpoint "$TMP/old-ai.json")" ok
p=$(jq -cn --rawfile ca "$TMP/ca.pem" '{enabled: true, url: "https://ollama.exemple.test:11434", token: true, ca_pem: $ca}')
hx "$p"
expect "retour à la vérification avec AC" "$(code)" OK
expect "ai.json : tls_verify true" "$(jq -r .tls_verify "$CONF")" true

# --- 5. Échec de nft : configuration précédente rétablie ---------------------------------
before=$(conf_hash)
dns other.exemple.test A 198.51.100.7
echo 1 > "$TMP/nft-rc"
hx '{"enabled": true, "url": "https://other.exemple.test:11434"}'
expect "nft -c en échec → E_INTERNAL" "$(code)" E_INTERNAL
expect "configuration précédente rétablie" "$(conf_hash)" "$before"
rm -f "$TMP/nft-rc"
echo 1 > "$TMP/nft-load-rc"
hx '{"enabled": true, "url": "https://other.exemple.test:11434"}'
expect "nft -f en échec → E_INTERNAL" "$(code)" E_INTERNAL
expect "adresses précédentes toujours épinglées" "$(jq -c .addresses "$CONF")" '["192.0.2.10","2001:db8::10"]'
rm -f "$TMP/nft-load-rc"

# --- 6. Changement de résolution : signalé, jamais appliqué --------------------------------
before=$(conf_hash)
dns ollama.exemple.test A 203.0.113.50
"$SETUP" check > "$TMP/check.json" 2> "$TMP/check.err" || ko "scanoria-ai-setup check : code de sortie"
expect "changement signalé" "$(jq -r .resolution.changed "$STATUS")" true
expect "nouvelle résolution relevée" "$(jq -c .resolution.current "$STATUS")" '["203.0.113.50","2001:db8::10"]'
expect "règle et épinglage inchangés" "$(conf_hash)" "$before"
expect "ai-status.json conforme au schéma" "$(valid ai-status "$STATUS")" ok
dns ollama.exemple.test A 127.0.0.1
"$SETUP" check > /dev/null 2>&1 || true
expect "rebond vers le bouclage : signalé comme erreur" "$(jq -r .resolution.error "$STATUS")" E_AI_FORBIDDEN_ADDRESS
expect "rebond vers le bouclage : règle inchangée" "$(conf_hash)" "$before"
dns ollama.exemple.test A 192.0.2.10
"$SETUP" check > /dev/null 2>&1 || true
expect "résolution revenue : plus de changement" "$(jq -r .resolution.changed "$STATUS")" false

# --- 7. Préparation du service ---------------------------------------------------------------
printf 'cle-de-test-32-octets-0123456789' > "$T/var/lib/scanoria/console/ai-token.key"
printf 'cle-des-forges-32-octets-0123456' > "$T/var/lib/scanoria/console/secret.key"
: > "$CALLS"
"$SETUP" prestart > "$TMP/pre.json" 2> "$TMP/pre.err" || ko "prestart : code de sortie"
expect "prestart : fichiers copiés (jeton et AC configurés)" "$(jq -c .files "$TMP/pre.json")" '["ai-token.key","ai.json","ca.pem"]'
expect "prestart : fichiers 0400" "$(stat -c %a "$T/run/scanoria-ai/ai.json")" 400
# Clé du jeton remplacée par un lien (vers la clé des forges) ou de taille fausse : jamais copiée.
mv "$T/var/lib/scanoria/console/ai-token.key" "$TMP/ai-token.key"
ln -s "$T/var/lib/scanoria/console/secret.key" "$T/var/lib/scanoria/console/ai-token.key"
"$SETUP" prestart > "$TMP/pre-link.json" 2> /dev/null || true
expect "prestart : clé du jeton en lien symbolique refusée" "$(jq -c .files "$TMP/pre-link.json")" '["ai.json","ca.pem"]'
rm -f "$T/var/lib/scanoria/console/ai-token.key"
printf 'trop-courte' > "$T/var/lib/scanoria/console/ai-token.key"
"$SETUP" prestart > "$TMP/pre-link.json" 2> /dev/null || true
expect "prestart : clé du jeton de taille fausse refusée" "$(jq -c .files "$TMP/pre-link.json")" '["ai.json","ca.pem"]'
mv -f "$TMP/ai-token.key" "$T/var/lib/scanoria/console/ai-token.key"
grep -q 'ai-grants.sql' "$CALLS" && jq -e 'select(.[0] == "runuser") | .[1:4] == ["-u", "postgres", "--"]' "$CALLS" > /dev/null \
	&& ok "prestart : rôle et droits appliqués en postgres" || ko "prestart : psql"
grep -q '"nft","-f"' "$CALLS" && ok "prestart : table nftables rechargée" || ko "prestart : nft"
echo 1 > "$TMP/psql-rc"
"$SETUP" prestart > /dev/null 2>&1 && ko "prestart : échec de psql ignoré" || ok "prestart : échec de psql → service non démarré"
rm -f "$TMP/psql-rc"
grep -q '^GRANT .* ON credentials' "$ROOT/src/rootfs/usr/share/scanoria/sql/ai-grants.sql" \
	&& grep -qE '^GRANT (SELECT, INSERT, UPDATE|SELECT, INSERT, DELETE|SELECT, INSERT) ON ai_' "$ROOT/src/rootfs/usr/share/scanoria/sql/ai-grants.sql" \
	&& ! grep -E '^GRANT [A-Z, ]*(INSERT|UPDATE|DELETE)' "$ROOT/src/rootfs/usr/share/scanoria/sql/ai-grants.sql" | grep -qv ' ON ai_' \
	&& ok "ai-grants.sql : écritures limitées aux tables ai_*" || ko "ai-grants.sql : écriture hors ai_*"

# --- 8. selftest ai.alive ----------------------------------------------------------------------
st() { python3 -I -c '
import sys, json
sys.path.insert(0, sys.argv[1])
from scanoria import selftest
r = selftest.Report(); selftest.check_ai(r)
print(json.dumps([c["status"] for c in r.checks if c["id"] == "ai.alive"]))' "$PY"; }
expect "ai.alive : service actif" "$(st)" '["pass"]'
echo 3 > "$TMP/active-rc"
expect "ai.alive : service arrêté → avertissement" "$(st)" '["warn"]'
rm -f "$TMP/active-rc"

# --- 9. Retrait du connecteur ------------------------------------------------------------------
: > "$CALLS"
hx '{"enabled": false}'
expect "connecteur retiré" "$(code)" OK
expect "ai.json : inactif" "$(jq -cS . "$CONF")" '{"enabled":false,"version":1}'
expect "nft : plus aucune sortie autorisée" "$(grep -c 'accept$' "$NFT")" 0
grep -qxF $'\t\tmeta skuid 64990 counter reject' "$NFT" && ok "nft : refus conservé pour scanoria-ai" || ko "nft : refus absent"
grep -qF '["systemctl","try-restart","scanoria-ai.service"]' "$CALLS" && ok "scanoria-ai relancé au repos" || ko "scanoria-ai non relancé"
expect "ai.alive : absent sans connecteur" "$(st)" '[]'
"$SETUP" prestart > "$TMP/pre.json" 2> /dev/null || ko "prestart sans connecteur"
expect "prestart sans connecteur : seule la configuration est copiée" "$(jq -c .files "$TMP/pre.json")" '["ai.json"]'
[[ ! -e "$T/run/scanoria-ai/ai-token.key" ]] && ok "clé du jeton IA retirée du service" || ko "clé du jeton IA restée"
[[ ! -e "$T/run/scanoria-ai/secret.key" ]] && ok "clé des secrets jamais copiée" || ko "clé des secrets copiée"
printf '{"version":1,"enabled":true,"url":"x"}' > "$CONF"
"$SETUP" prestart > "$TMP/pre.json" 2> /dev/null || true
expect "ai.json incohérent : traité comme inactif (échec fermé)" "$(jq -r .enabled "$TMP/pre.json")" false

# --- 10. Serveur candidat ------------------------------------------------------------------------
printf '{"version":1,"enabled":false}' > "$CONF"
printf '{"fqdn": "analyse.exemple.test"}\n' > "$T/etc/scanoria/appliance.json"
"$SETUP" check > /dev/null 2>&1 || true
expect "sans réponse : aucun candidat" "$(jq -c .candidate "$STATUS")" null
printf '{"version":"0.12.3"}' > "$TMP/curl-http"
"$SETUP" check > /dev/null 2>&1 || true
expect "candidat ollama.<domaine> en http" "$(jq -c '[.candidate.url, .candidate.version, .candidate.insecure]' "$STATUS")" \
	'["http://ollama.exemple.test:11434","0.12.3",true]'
grep -q -- '--resolve","ollama.exemple.test:11434:192.0.2.10"' "$CALLS" && ok "candidat : adresse épinglée pour curl" || ko "candidat : --resolve"
printf '{"version":"0.12.3"}' > "$TMP/curl-https"
"$SETUP" check > /dev/null 2>&1 || true
expect "candidat : https préféré" "$(jq -r .candidate.url "$STATUS")" "https://ollama.exemple.test:11434"
printf '{"version":"<script>"}' > "$TMP/curl-https"
printf '{"version":"<script>"}' > "$TMP/curl-http"
"$SETUP" check > /dev/null 2>&1 || true
expect "candidat : version hostile ignorée" "$(jq -c .candidate "$STATUS")" null
dns ollama.exemple.test A 127.0.0.1
printf '{"version":"0.12.3"}' > "$TMP/curl-http"
"$SETUP" check > /dev/null 2>&1 || true
expect "candidat qui résout vers le bouclage : ignoré" "$(jq -c .candidate "$STATUS")" null
"$SETUP" bogus > /dev/null 2>&1 && ko "commande inconnue acceptée" || ok "commande inconnue refusée"

printf '\n%d réussis, %d échoués\n' "$PASS" "$FAIL"
[[ $FAIL -eq 0 ]]
