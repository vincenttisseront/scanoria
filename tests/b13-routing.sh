#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Vincent Tisseront
#
# b13 — aiguillage des modules par nom et vérification DNS (chantier D, 0.2),
# sans root : scanoria.routing et la demande check-dns tournent en mode test
# (SCANORIA_TEST_ROOT) ; nginx, systemctl, ip et resolvectl sont des bouchons.
# Couvre : sites générés pour 0, 1 et N services, service désactivé, nom
# inconnu, libellés, identifiants et ports hostiles (rien n'est écrit),
# « nginx -t » en échec puis retour à l'ancienne configuration, liens
# symboliques plantés, resynchronisation après changement de nom, check-dns
# (résolution simulée, joker par sonde aléatoire, schéma de status.json),
# contrôle selftest routing.sites. Si root et nginx présents : « nginx -t »
# réel sur les sites générés, inclus dans le site de la console.
# Dépendances : bash, python3, jq.

# Les motifs jq et les programmes Python sont volontairement entre apostrophes.
# shellcheck disable=SC2016,SC2015
set -euo pipefail
export PYTHONDONTWRITEBYTECODE=1

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
PY="$ROOT/src/rootfs/usr/lib/scanoria/py"
HELPER="$ROOT/src/rootfs/usr/sbin/scanoria-helper"
SELFTEST="$ROOT/src/rootfs/usr/sbin/scanoria-selftest"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

PASS=0
FAIL=0
ok() { PASS=$((PASS + 1)); printf 'ok   %s\n' "$1"; }
ko() { FAIL=$((FAIL + 1)); printf 'FAIL %s\n' "$1"; }
expect() { if [[ "$2" == "$3" ]]; then ok "$1"; else ko "$1 (obtenu « $2 », attendu « $3 »)"; fi; }
for t in python3 jq; do command -v "$t" > /dev/null || { echo "outil manquant : $t" >&2; exit 2; }; done

T="$TMP/root"
STUBS="$TMP/stubs"
D="$T/etc/nginx/scanoria.d"
N=analyse.exemple.test
mkdir -p "$T"/var/lib/scanoria/requests/{tmp,incoming,work,done,failed} "$T/run/scanoria" \
	"$T/etc/scanoria" "$T/var/lib/scanoria/modules" "$STUBS"
export SCANORIA_TEST_ROOT="$T" SCANORIA_TEST_BIN="$STUBS"
unset SCANORIA_TEST_OWNER_UID SCANORIA_TEST_NOW

# Bouchons. nginx : code de sortie lu dans $TMP/nginx-rc (0 par défaut).
cat > "$STUBS/nginx" <<-EOF
	#!/bin/bash
	echo "nginx \$*" >> "$TMP/calls.log"
	exit "\$(cat "$TMP/nginx-rc" 2> /dev/null || echo 0)"
EOF
cat > "$STUBS/systemctl" <<-EOF
	#!/bin/bash
	echo "systemctl \$*" >> "$TMP/calls.log"
EOF
# ip : adresses de l'appliance lues dans $TMP/ip4 et $TMP/ip6 (absent = pas de route).
cat > "$STUBS/ip" <<-EOF
	#!/bin/bash
	f="$TMP/ip4"; [[ "\$2" == -6 ]] && f="$TMP/ip6"
	[[ -s "\$f" ]] || exit 2
	printf '[{"dst":"%s","prefsrc":"%s"}]\n' "\$5" "\$(cat "\$f")"
EOF
# resolvectl : réponses dans $TMP/dns/<nom>.<type> (sortie brute), joker dans $TMP/dns/wild.<type>.
cat > "$STUBS/resolvectl" <<-EOF
	#!/bin/bash
	echo "resolvectl \$*" >> "$TMP/calls.log"
	name=\${!#}; type=\${*: -2:1}
	if [[ -f "$TMP/dns/\$name.\$type" ]]; then cat "$TMP/dns/\$name.\$type"
	elif [[ "\$name" == scanoria-probe-*.$N && -f "$TMP/dns/wild.\$type" ]]; then
		sed "s/^\\*/\$name/" "$TMP/dns/wild.\$type"
	else echo "\$name: resource record not found" >&2; exit 1; fi
EOF
printf '#!/bin/bash\nexit 0\n' > "$STUBS/scanoria-state"
chmod 0755 "$STUBS"/*
mkdir -p "$TMP/dns"
: > "$TMP/calls.log"

# Appel Python : rt 'code' → imprime le résultat ou « FAIL <code> »
rt() {
	python3 -I -B - "$PY" "$@" <<-'EOF'
		import json, sys
		sys.path.insert(0, sys.argv[1])
		from scanoria import routing, common
		args = sys.argv[2:]
		try:
		    res = eval(args[0], {"routing": routing, "json": json, "a": args[1:]})
		    print(json.dumps(res, sort_keys=True))
		except common.Fail as e:
		    print("FAIL " + e.code)
	EOF
}
svc() { printf '{"id":"%s","hostname":"%s","port":%s,"enabled":%s}' "$1" "$2" "$3" "$4"; }
tree_hash() { (cd "$D" 2> /dev/null && find . -mindepth 1 -printf '%p %y %l\n' | sort && cat ./* 2> /dev/null) | sha256sum | cut -c1-16; }
listing() { find "$D" -mindepth 1 -printf '%f\n' | LC_ALL=C sort | tr '\n' ' '; }
set_name() { printf '{"fqdn": "%s"}\n' "$1" > "$T/etc/scanoria/appliance.json"; }

# --- 1. Sites générés ---------------------------------------------------------------------
expect "sans nom d'appliance → E_PRECONDITION" "$(rt 'routing.apply(None, [])')" "FAIL E_PRECONDITION"
set_name "$N"
expect "0 service : aucune route" "$(rt 'routing.apply(None, [])')" "[]"
expect "0 service : seul le site joker est écrit" "$(listing)" "00-catchall.conf "
grep -q "server_name \"~^(?<scanoria_label>\[a-z0-9\]\[a-z0-9-\]\*)\\\\.analyse\\\\.exemple\\\\.test\$\";" "$D/00-catchall.conf" \
	&& ok "joker : nom en expression régulière, points échappés" || ko "joker : server_name"
grep -qF "return 302 https://$N/modules/unavailable?m=\$scanoria_label;" "$D/00-catchall.conf" \
	&& ok "nom inconnu → page « module indisponible »" || ko "nom inconnu : redirection"
grep -qF "return 301 https://\$scanoria_http_label.$N\$request_uri;" "$D/00-catchall.conf" \
	&& ok "port 80 : redirection vers le même nom en HTTPS" || ko "port 80 : redirection"
grep -q '^nginx -t -q$' "$TMP/calls.log" && grep -q 'systemctl try-reload-or-restart nginx.service' "$TMP/calls.log" \
	&& ok "nginx -t puis rechargement" || ko "nginx -t / rechargement"
grep -q 'systemctl start --no-block scanoria-dns-check.service' "$TMP/calls.log" \
	&& ok "contrôle DNS lancé après le routage" || ko "contrôle DNS non lancé"
expect "sites.json : nom et liste" "$(jq -c '[.fqdn, .services]' "$T/var/lib/scanoria/routing/sites.json")" "[\"$N\",[]]"

out=$(rt 'routing.apply(None, [json.loads(a[0])])' "$(svc sonarqube sonarqube 18001 true)")
expect "1 service : route rendue" "$out" "[{\"hostname\": \"sonarqube.$N\", \"id\": \"sonarqube\", \"url\": \"https://sonarqube.$N/\"}]"
f="$D/module-sonarqube.conf"
grep -qF "server_name sonarqube.$N;" "$f" && ok "1 service : server_name <libellé>.<nom>" || ko "1 service : server_name"
grep -qF "proxy_pass http://127.0.0.1:18001;" "$f" && ok "1 service : proxy vers 127.0.0.1:<port>" || ko "1 service : proxy_pass"
grep -qF "ssl_certificate /etc/scanoria/pki/active/fullchain.pem;" "$f" && ok "1 service : certificat générique" || ko "1 service : certificat"
for h in Strict-Transport-Security X-Content-Type-Options Referrer-Policy X-Frame-Options Permissions-Policy; do
	grep -q "add_header $h " "$f" || { ko "1 service : en-tête $h absent"; continue; }
done
ok "1 service : en-têtes de sécurité"
expect "1 service : aucun « @ » de gabarit restant" "$(grep -c '@[A-Z_]*@' "$f" || true)" 0
expect "1 service : fichier 0644" "$(stat -c %a "$f")" 644

L=$(printf '[%s,%s,%s]' "$(svc sonarqube sonarqube 18001 true)" "$(svc dtrack dtrack 18002 false)" "$(svc defectdojo defectdojo 18003 true)")
out=$(rt 'routing.apply(None, json.loads(a[0]))' "$L")
expect "N services : routes des seuls actifs" "$(jq -r '[.[].id] | join(" ")' <<< "$out")" "defectdojo sonarqube"
expect "N services : un fichier par service + joker" "$(listing)" "00-catchall.conf module-defectdojo.conf module-dtrack.conf module-sonarqube.conf "
grep -qF "return 302 https://$N/modules/unavailable?m=dtrack;" "$D/module-dtrack.conf" \
	&& ! grep -q proxy_pass "$D/module-dtrack.conf" && ok "service désactivé → redirection, aucun proxy" || ko "service désactivé"
echo 'server { listen 8080; }' > "$D/local.conf"
rt 'routing.apply(None, [json.loads(a[0])])' "$(svc sonarqube sonarqube 18001 true)" > /dev/null
expect "service retiré : son site disparaît" "$(listing)" "00-catchall.conf local.conf module-sonarqube.conf "
rm -f "$D/local.conf"

# --- 2. Entrées hostiles : rien n'est écrit -----------------------------------------------
before=$(tree_hash)
: > "$TMP/calls.log"
hostile() { # libellé json
	expect "hostile : $1 → E_INVALID_PARAM" "$(rt 'routing.apply(None, json.loads(a[0]))' "$2")" "FAIL E_INVALID_PARAM"
}
for lab in '..' 'a..b' 'Sonar' 'sonar_qube' "$(printf 'a%.0s' {1..64})" 'a;b' 'a}' 'a{' 'a b' '-a' 'a-' '' 'a.b' 'é' 'a$host' 'a\nb'; do
	hostile "libellé « $lab »" "[$(jq -cn --arg h "$lab" '{id: "m", hostname: $h, port: 18001, enabled: true}')]"
done
for id in '../x' 'X' 'a/b' 'a;' '' 'a.conf' "$(printf 'b%.0s' {1..65})"; do
	hostile "id « $id »" "[$(jq -cn --arg i "$id" '{id: $i, hostname: "m", port: 18001, enabled: true}')]"
done
for port in 0 80 1023 3000 5432 65536 '"18001"' true 18001.5 null; do
	hostile "port $port" "[$(svc m m "$port" true)]"
done
hostile "enabled non booléen" "[$(svc m m 18001 '"yes"')]"
hostile "champ inconnu" '[{"id":"m","hostname":"m","port":18001,"enabled":true,"extra":"x"}]'
hostile "champ manquant" '[{"id":"m","hostname":"m","port":18001}]'
hostile "libellé en double" "[$(svc a m 18001 true),$(svc b m 18002 true)]"
hostile "id en double" "[$(svc a m 18001 true),$(svc a n 18002 true)]"
hostile "port actif en double" "[$(svc a m 18001 true),$(svc b n 18001 true)]"
hostile "liste attendue" '{"id":"m"}'
long=$(printf 'c%.0s' {1..60}).$(printf 'd%.0s' {1..60}).$(printf 'e%.0s' {1..60}).$(printf 'f%.0s' {1..60}).test
set_name "$long"
hostile "nom complet > 253 caractères" "[$(svc m mmmmmmmmmmmmmmmmmmmm 18001 true)]"
set_name "$N"
expect "hostile : sites inchangés" "$(tree_hash)" "$before"
expect "hostile : nginx jamais appelé" "$(grep -c '^nginx' "$TMP/calls.log" || true)" 0
expect "fqdn hostile en argument → E_INVALID_PARAM" "$(rt 'routing.apply("a;b.test", [])')" "FAIL E_INVALID_PARAM"

# --- 3. nginx -t en échec : retour arrière --------------------------------------------------
before=$(tree_hash)
sites_before=$(sha256sum < "$T/var/lib/scanoria/routing/sites.json")
: > "$TMP/calls.log"
echo 1 > "$TMP/nginx-rc"
expect "nginx -t en échec → E_INTERNAL" "$(rt 'routing.apply(None, json.loads(a[0]))' "$L")" "FAIL E_INTERNAL"
expect "nginx -t en échec : sites d'avant remis à l'identique" "$(tree_hash)" "$before"
expect "nginx -t en échec : sites.json inchangé" "$(sha256sum < "$T/var/lib/scanoria/routing/sites.json")" "$sites_before"
expect "nginx -t en échec : aucun rechargement" "$(grep -c 'reload' "$TMP/calls.log" || true)" 0
rm -f "$TMP/nginx-rc"

# --- 4. Liens symboliques plantés ----------------------------------------------------------------
echo 'intact' > "$TMP/target"
ln -sf "$TMP/target" "$D/module-sonarqube.conf"
ln -s "$TMP/target" "$D/module-ghost.conf"
rt 'routing.apply(None, [json.loads(a[0])])' "$(svc sonarqube sonarqube 18001 true)" > /dev/null
expect "lien planté : cible intacte" "$(cat "$TMP/target")" intact
[[ -f "$D/module-sonarqube.conf" && ! -L "$D/module-sonarqube.conf" && ! -e "$D/module-ghost.conf" ]] \
	&& ok "lien planté : remplacé par un fichier régulier, lien orphelin retiré" || ko "lien planté"

# --- 5. Changement de nom : resynchronisation ------------------------------------------------------
expect "resync sans changement → rien à faire" "$(rt 'routing.resync()')" false
set_name "audit.exemple.test"
expect "resync après changement de nom → régénéré" "$(rt 'routing.resync()')" true
grep -qF "server_name sonarqube.audit.exemple.test;" "$D/module-sonarqube.conf" \
	&& ok "resync : sites au nouveau nom (port conservé)" || ko "resync : nouveau nom"
grep -qF "proxy_pass http://127.0.0.1:18001;" "$D/module-sonarqube.conf" && ok "resync : port repris de sites.json" || ko "resync : port"
set_name "$N"
rt 'routing.resync()' > /dev/null

# --- 6. check-dns ----------------------------------------------------------------------------------
echo 192.0.2.10 > "$TMP/ip4"
echo 2001:db8::10 > "$TMP/ip6"
printf '%s IN A 192.0.2.10   -- link: eth0\n' "$N" > "$TMP/dns/$N.A"
printf '%s IN AAAA 2001:db8::10   -- link: eth0\n' "$N" > "$TMP/dns/$N.AAAA"
printf '* IN A 192.0.2.10\n' > "$TMP/dns/wild.A"
# AAAA du joker : mauvaise adresse ; sonarqube.<nom> : réponse piégée.
printf '* IN AAAA 2001:db8::99\n' > "$TMP/dns/wild.AAAA"
printf 'sonarqube.%s IN CNAME x.%s\nx IN A 198.51.100.7\nx IN A 2001:db8::10\ngarbage; rm -rf /\nx IN A 999.1.1.1\n' "$N" "$N" \
	> "$TMP/dns/sonarqube.$N.A"
: > "$TMP/calls.log"
res=$("$HELPER" exec --origin cli --type check-dns --params '{}' 2> "$TMP/h.err" || true)
expect "check-dns : code OK" "$(jq -r .code <<< "$res")" OK
S="$T/var/lib/scanoria/dns/status.json"
python3 -I -B -c 'import json, sys
sys.path.insert(0, sys.argv[1])
from scanoria import schema
assert schema.load("schemas", "dns-status").valid(json.load(open(sys.argv[2])))' "$PY" "$S" \
	&& ok "status.json conforme à dns-status.schema.json" || ko "status.json : schéma"
expect "status.json : nom de l'appliance" "$(jq -r .fqdn "$S")" "$N"
expect "status.json : noms vérifiés" "$(jq -r '[.records[] | .name + "/" + .type] | join(" ")' "$S")" \
	"$N/A $N/AAAA *.$N/A *.$N/AAAA sonarqube.$N/A sonarqube.$N/AAAA"
expect "appliance A et AAAA : ok" "$(jq -r "[.records[] | select(.name == \"$N\") | .ok] | join(\" \")" "$S")" "true true"
expect "joker A ok, AAAA faux (autre adresse)" "$(jq -r '[.records[] | select(.name | startswith("*.")) | "\(.ok):\(.resolved | join(","))"] | join(" ")' "$S")" \
	"true:192.0.2.10 false:2001:db8::99"
expect "réponse piégée : seules les adresses valides de la bonne famille" \
	"$(jq -r '.records[] | select(.name | startswith("sonarqube")) | select(.type == "A") | "\(.ok) \(.resolved | join(","))"' "$S")" \
	"false 198.51.100.7"
expect "attendu : adresses de l'appliance" "$(jq -r '[.records[0,1].expected] | join(" ")' "$S")" "192.0.2.10 2001:db8::10"
grep -q "resolvectl query --legend=no --synthesize=no --cache=no -p dns -t A scanoria-probe-[0-9a-f]\{12\}.$N$" "$TMP/calls.log" \
	&& ok "joker : nom de sonde aléatoire, sans /etc/hosts ni cache" || ko "joker : sonde"
expect "check-dns : sortie (noms non résolus)" "$(jq -c '[.output.ok, .output.not_resolved]' <<< "$res")" "[false,[\"*.$N\",\"sonarqube.$N\"]]"
expect "status.json : 0640" "$(stat -c %a "$S")" 640

rm -f "$TMP/ip6"
"$HELPER" exec --origin cli --type check-dns --params '{}' > /dev/null 2>&1 || true
expect "sans IPv6 : A seulement" "$(jq -r '[.records[].type] | unique | join(" ")' "$S")" "A"
rm -f "$TMP/ip4"
"$HELPER" exec --origin cli --type check-dns --params '{}' > /dev/null 2>&1 || true
expect "sans adresse : expected null, ok faux" "$(jq -r '[.records[] | "\(.expected)/\(.ok)"] | unique | join(" ")' "$S")" "null/false"
echo 192.0.2.10 > "$TMP/ip4"

res=$("$HELPER" exec --origin cli --type check-dns --params '{"force": true}' 2> /dev/null || true)
expect "check-dns : paramètre inconnu → E_SCHEMA" "$(jq -r .code <<< "$res")" E_SCHEMA
set_name "audit.exemple.test"
res=$("$HELPER" exec --origin cli --type check-dns --params '{}' 2> /dev/null || true)
expect "check-dns après changement de nom : sites resynchronisés" "$(jq -r .output.routing_resynced <<< "$res")" true
grep -qF "server_name sonarqube.audit.exemple.test;" "$D/module-sonarqube.conf" && ok "check-dns : sites au nouveau nom" || ko "check-dns : resync"
echo 1 > "$TMP/nginx-rc"
set_name "$N"
res=$("$HELPER" exec --origin cli --type check-dns --params '{}' 2> /dev/null || true)
expect "check-dns, nginx refuse les sites → E_INTERNAL, DNS écrit quand même" \
	"$(jq -r .code <<< "$res") $(jq -r .fqdn "$S")" "E_INTERNAL $N"
rm -f "$TMP/nginx-rc"
rt 'routing.resync()' > /dev/null
rm "$T/etc/scanoria/appliance.json"
res=$("$HELPER" exec --origin cli --type check-dns --params '{}' 2> /dev/null || true)
expect "check-dns sans nom → E_PRECONDITION, status fqdn null" "$(jq -r .code <<< "$res") $(jq -r '.fqdn, (.records | length)' "$S" | tr '\n' ' ')" \
	"E_PRECONDITION null 0 "
set_name "$N"

# --- 7. selftest routing.sites --------------------------------------------------------------------
st_routing() { "$SELFTEST" --json --quick 2> /dev/null | jq -r '.checks[] | select(.id == "routing.sites") | .status'; }
jq -n --arg n "$N" '{modules: [{id: "sonarqube", type: "service", status: "healthy", enabled: true,
	route: {hostname: ("sonarqube." + $n), url: ("https://sonarqube." + $n + "/")}},
	{id: "gitleaks", type: "scanner", status: "healthy", enabled: true, route: null}], operations: []}' \
	> "$T/var/lib/scanoria/modules/state.json"
expect "selftest routing.sites : cohérent → pass" "$(st_routing)" pass
cp "$D/module-sonarqube.conf" "$D/module-oldtool.conf"
expect "selftest : site d'un module non installé → fail" "$(st_routing)" fail
rm "$D/module-oldtool.conf"
jq '.modules += [{id: "dtrack", type: "service", status: "healthy", enabled: true,
	route: {hostname: "dtrack", url: "https://dtrack/"}}]' "$T/var/lib/scanoria/modules/state.json" > "$TMP/s.json"
mv "$TMP/s.json" "$T/var/lib/scanoria/modules/state.json"
expect "selftest : module routé sans site → fail" "$(st_routing)" fail
rt 'routing.apply(None, json.loads(a[0]))' "[$(svc sonarqube sonarqube 18001 true),$(svc dtrack dtrack 18002 true)]" > /dev/null
expect "selftest : après apply → pass" "$(st_routing)" pass
sed -i "s/$N/autre.exemple.test/" "$D/module-dtrack.conf"
expect "selftest : site généré pour un autre nom → fail" "$(st_routing)" fail
rt 'routing.apply(None, json.loads(a[0]))' "[$(svc sonarqube sonarqube 18001 true),$(svc dtrack dtrack 18002 true)]" > /dev/null
echo 'not json' > "$T/var/lib/scanoria/modules/state.json"
expect "selftest : state.json illisible → fail" "$(st_routing)" fail
rm "$T/var/lib/scanoria/modules/state.json"
expect "selftest : aucun module, sites du joker seul → fail (sites de modules restants)" "$(st_routing)" fail
rt 'routing.apply(None, [])' > /dev/null
expect "selftest : aucun module installé → pass" "$(st_routing)" pass

# --- 8. nginx -t réel (root et nginx seulement) --------------------------------------------------------
if [[ $EUID -eq 0 ]] && command -v nginx > /dev/null; then
	rt 'routing.apply(None, json.loads(a[0]))' "$L" > /dev/null
	G="$TMP/ng"
	mkdir -p "$G/pki" "$G/scanoria.d"
	openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 2 -subj "/CN=$N" \
		-addext "subjectAltName=DNS:$N,DNS:*.$N" -keyout "$G/pki/privkey.pem" -out "$G/pki/fullchain.pem" 2> /dev/null
	for f in "$D"/*.conf; do sed "s#/etc/scanoria/pki/active/#$G/pki/#g" "$f" > "$G/scanoria.d/$(basename "$f")"; done
	sed -e "s/@FQDN@/$N/g" -e "s#/etc/scanoria/pki/active/#$G/pki/#g" -e "s#/etc/nginx/scanoria/#$G/#g" \
		-e "s#/etc/nginx/scanoria.d/#$G/scanoria.d/#" "$ROOT/src/rootfs/usr/share/scanoria/nginx/scanoria.conf.tmpl" > "$G/site.conf"
	[[ -e /proc/net/if_inet6 ]] || sed -i '/listen \[::\]/d' "$G/site.conf"
	cat > "$G/nginx.conf" <<-EOF
		pid $G/nginx.pid;
		error_log stderr;
		events {}
		http {
			include /etc/nginx/mime.types;
			access_log off;
			include $G/site.conf;
		}
	EOF
	nginx -t -q -c "$G/nginx.conf" 2> "$G/err" && ok "nginx -t réel : site de la console + sites des modules" \
		|| { ko "nginx -t réel"; sed 's/^/     /' "$G/err"; }
else
	echo "skip nginx -t réel (root et nginx requis)"
fi

echo
echo "b13 : $PASS réussi(s), $FAIL échec(s)"
[[ $FAIL -eq 0 ]]
