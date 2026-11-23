#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Vincent Tisseront
#
# b01 — scanoria-helper face à des demandes hostiles, sans root : le helper
# tourne en mode test (SCANORIA_TEST_ROOT) sur une arborescence temporaire,
# les commandes qu'il appelle (scanoria-ca, scanoria-firewall…) sont des
# bouchons qui journalisent leurs arguments. Couvre ARCHITECTURE § 5.4–5.6 :
# noms, liens symboliques et physiques, FIFO, répertoires, propriétaire,
# taille, JSON piégé, type inconnu, schéma, injections (fqdn, CIDR, PEM),
# identifiants, fraîcheur, doublons, anti-verrouillage, exec, ordre FIFO, et
# conformité de chaque résultat à result.schema.json.
# Dépendances : bash, python3, jq.

# Les « bash -c '…' » et les motifs jq sont volontairement entre apostrophes.
# shellcheck disable=SC2016,SC2015
set -euo pipefail
shopt -s lastpipe
export PYTHONDONTWRITEBYTECODE=1

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
HELPER="$ROOT/src/rootfs/usr/sbin/scanoria-helper"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

PASS=0
FAIL=0
ok() { PASS=$((PASS + 1)); printf 'ok   %s\n' "$1"; }
ko() { FAIL=$((FAIL + 1)); printf 'FAIL %s\n' "$1"; }
expect() { # libellé valeur_obtenue valeur_attendue
	if [[ "$2" == "$3" ]]; then ok "$1"; else ko "$1 (obtenu « $2 », attendu « $3 »)"; fi
}
for t in python3 jq; do command -v "$t" > /dev/null || { echo "outil manquant : $t" >&2; exit 2; }; done

T="$TMP/root"
Q="$T/var/lib/scanoria/requests"
STUBS="$TMP/stubs"
mkdir -p "$Q"/{tmp,incoming,work,done,failed} "$T/run/scanoria" "$T/etc/scanoria" "$STUBS"
chmod 0700 "$Q/incoming" "$Q/work"
export SCANORIA_TEST_ROOT="$T" SCANORIA_TEST_BIN="$STUBS"
unset SCANORIA_TEST_OWNER_UID SCANORIA_TEST_NOW

# Bouchons : journalisent leurs arguments (un tableau JSON par appel) et
# répondent au protocole {code, message, output}.
for c in scanoria-ca scanoria-firewall scanoria-selfupdate; do
	cat > "$STUBS/$c" <<-EOF
		#!/bin/bash
		jq -cn --arg c "$c" '[\$c] + \$ARGS.positional' --args -- "\$@" >> "$TMP/calls.log"
		echo '{"code":"OK","message":"stub","output":{"loaded":true}}'
	EOF
done
printf '#!/bin/bash\nexit 0\n' > "$STUBS/scanoria-state"
cat > "$STUBS/scanoria-selftest" <<-'EOF'
	#!/bin/bash
	echo '{"version":1,"appliance_version":"0.1.0","started_at":"2026-11-23T08:00:00Z","finished_at":"2026-11-23T08:00:01Z","status":"pass","checks":[]}'
EOF
chmod 0755 "$STUBS"/*
: > "$TMP/calls.log"

uuid() { cat /proc/sys/kernel/random/uuid; }
EPOCH=$(date -u +%s)
NAME_TS=$(date -u -d "@$EPOCH" +%Y%m%dT%H%M%SZ)
CREATED=$(date -u -d "@$EPOCH" +%Y-%m-%dT%H:%M:%SZ)

# Enveloppe valide : req TYPE PARAMS_JSON [ID] [CREATED_AT] [ADRESSE]
req() {
	jq -cn --arg type "$1" --argjson params "$2" --arg id "${3:-$(uuid)}" \
		--arg created "${4:-$CREATED}" --arg addr "${5:-}" \
		'{version: 1, id: $id, type: $type, created_at: $created,
		  requested_by: ({user_id: 1, username: "admin"} + (if $addr == "" then {} else {address: $addr} end)),
		  params: $params}'
}
# Dépose une demande : put NOM [contenu sur l'entrée standard]
put() { cat > "$Q/incoming/$1"; }
name_for() { printf '%s-%s.json' "${2:-$NAME_TS}" "$1"; }
run_helper() { "$HELPER" run 2> "$TMP/helper.err" || { ko "scanoria-helper run (code $?)"; sed 's/^/     /' "$TMP/helper.err"; }; }
# Résultat d'une demande : code (done/ ou failed/)
code_of() {
	local f
	for f in "$Q/done/$1" "$Q/failed/$1"; do
		if [[ -f "$f" ]]; then jq -r '.code' "$f"; return; fi
	done
	echo "absent"
}
# Soumet une demande et rend son code : submit LIBELLÉ CODE_ATTENDU NOM (contenu sur stdin)
submit() {
	put "$3"
	run_helper
	expect "$1" "$(code_of "$3")" "$2"
}
# Contenu JSON valide pour un type, avec un id donné
valid() { req "$1" "$2" "$3"; }

# --- 1. Demandes valides ------------------------------------------------------
id=$(uuid); n=$(name_for "$id")
valid set-hostname '{"fqdn": "analyse.exemple.test"}' "$id" | submit "set-hostname valide → OK" OK "$n"
expect "set-hostname : résultat dans done/" "$(jq -r '.status + " " + .origin + " " + .id' "$Q/done/$n")" "ok console $id"
expect "set-hostname : appliance.json écrit" "$(jq -r .fqdn "$T/etc/scanoria/appliance.json")" analyse.exemple.test
grep -qF '["scanoria-ca","init","--fqdn","analyse.exemple.test"]' "$TMP/calls.log" \
	&& ok "set-hostname : scanoria-ca init reçoit le nom en un seul argument" || ko "set-hostname : appel scanoria-ca init"
grep -q 'server_name analyse.exemple.test;' "$T/etc/nginx/sites-available/scanoria.conf" \
	&& ok "set-hostname : site nginx généré" || ko "set-hostname : site nginx"
grep -qF '["nginx","-t","-q"]' "$T/test-commands.log" && ok "set-hostname : nginx -t avant rechargement" || ko "nginx -t"
grep -q '^127.0.1.1 analyse.exemple.test analyse$' "$T/etc/hosts" && ok "set-hostname : /etc/hosts" || ko "/etc/hosts"

id=$(uuid); n=$(name_for "$id")
valid set-admin-networks '{"networks": ["192.0.2.0/24", "2001:db8::/32"]}' "$id" | submit "set-admin-networks valide → OK" OK "$n"
expect "set-admin-networks : configuration écrite" "$(jq -c .networks "$T/etc/scanoria/admin-networks.json")" '["192.0.2.0/24","2001:db8::/32"]'

# --- 2. Noms de fichier ---------------------------------------------------------
before=$(find "$Q/failed" -name 'invalid-*' | wc -l)
for bad in "evil.json" "20261123T080000Z-$(uuid | tr 'a-f' 'A-F').json" "$(name_for "$(uuid)").bak" \
	"$(name_for "$(uuid)" | sed 's/T/t/')" $'line\nbreak.json' ".hidden.json" "20261123T080000Z-not-a-uuid.json"; do
	printf '{}' > "$Q/incoming/$bad"
done
run_helper
after=$(find "$Q/failed" -name 'invalid-*' | wc -l)
expect "noms non conformes → 7 résultats invalid-*" "$((after - before))" 7
expect "noms non conformes : code E_INVALID_NAME, id null" \
	"$(jq -r 'select(.code == "E_INVALID_NAME") | "\(.id) \(.status)"' "$Q"/failed/invalid-*.json | sort -u)" "null rejected"

# --- 3. Fichiers piégés -----------------------------------------------------------
echo 'secret' > "$TMP/target"
n=$(name_for "$(uuid)"); ln -s "$TMP/target" "$Q/incoming/$n"; run_helper
expect "lien symbolique → E_NOT_REGULAR_FILE" "$(code_of "$n")" E_NOT_REGULAR_FILE
expect "lien symbolique : cible intacte" "$(cat "$TMP/target")" secret
id=$(uuid); n=$(name_for "$id"); valid run-selftest '{}' "$id" > "$TMP/hl.json"; ln "$TMP/hl.json" "$Q/incoming/$n"; run_helper
expect "lien physique → E_NOT_REGULAR_FILE" "$(code_of "$n")" E_NOT_REGULAR_FILE
n=$(name_for "$(uuid)"); mkfifo "$Q/incoming/$n"
if timeout 20 "$HELPER" run 2>> "$TMP/helper.err"; then ok "FIFO : pas de blocage"; else ko "FIFO : blocage ou erreur"; fi
expect "FIFO → E_NOT_REGULAR_FILE" "$(code_of "$n")" E_NOT_REGULAR_FILE
n=$(name_for "$(uuid)"); mkdir -p "$Q/incoming/$n/sub"; run_helper
expect "répertoire → E_NOT_REGULAR_FILE" "$(code_of "$n")" E_NOT_REGULAR_FILE
id=$(uuid); n=$(name_for "$id")
valid run-selftest '{}' "$id" | put "$n"
SCANORIA_TEST_OWNER_UID=$(( $(id -u) + 4242 )) "$HELPER" run 2>> "$TMP/helper.err"
expect "propriétaire inattendu → E_BAD_OWNER" "$(code_of "$n")" E_BAD_OWNER
n=$(name_for "$(uuid)")
python3 -c 'import sys; sys.stdout.write("{\"pad\": \"" + "A" * (129 * 1024) + "\"}")' | submit "plus de 128 Kio → E_TOO_LARGE" E_TOO_LARGE "$n"
expect "file vide après traitement (incoming/)" "$(find "$Q/incoming" -mindepth 1 | wc -l)" 0
expect "copie de travail supprimée (work/)" "$(find "$Q/work" -mindepth 1 | wc -l)" 0

# --- 4. JSON piégé ------------------------------------------------------------------
j() { n=$(name_for "$(uuid)"); printf '%s' "$2" | submit "$1" "${3:-E_INVALID_JSON}" "$n"; }
j "JSON invalide → E_INVALID_JSON" '{"version": 1,'
j "clé dupliquée → E_INVALID_JSON" '{"type": "run-selftest", "type": "set-hostname"}'
j "NaN → E_INVALID_JSON" '{"version": NaN}'
j "UTF-8 invalide → E_INVALID_JSON" $'{"x": "\xff\xfe"}'
j "BOM → E_INVALID_JSON" $'\xef\xbb\xbf{}'
j "demi-paire de substitution → E_INVALID_JSON" '{"x": "\ud800"}'
j "imbrication profonde → E_INVALID_JSON" "$(python3 -c 'print("[" * 60000 + "]" * 60000)')"
j "tableau au lieu d'objet → E_SCHEMA" '[1, 2]' E_SCHEMA
j "type inconnu → E_UNKNOWN_TYPE" "$(req reboot '{}')" E_UNKNOWN_TYPE
j "type avec chemin → E_UNKNOWN_TYPE" "$(req '../../../etc/passwd' '{}')" E_UNKNOWN_TYPE
j "type « __proto__ » → E_UNKNOWN_TYPE" "$(req '__proto__' '{}')" E_UNKNOWN_TYPE

# --- 5. Schéma et injections ----------------------------------------------------------
s() { # libellé type params code [id]
	local id=${5:-$(uuid)}
	n=$(name_for "$id"); req "$2" "$3" "$id" | submit "$1" "$4" "$n"
}
: > "$TMP/calls.log"
s "fqdn avec ; → E_SCHEMA" set-hostname '{"fqdn": "analyse.exemple.test; rm -rf /"}' E_SCHEMA
s "fqdn avec \$( ) → E_SCHEMA" set-hostname '{"fqdn": "$(id).exemple.test"}' E_SCHEMA
s "fqdn avec saut de ligne final → E_SCHEMA" set-hostname '{"fqdn": "analyse.exemple.test\n"}' E_SCHEMA
s "fqdn avec saut de ligne et option → E_SCHEMA" set-hostname '{"fqdn": "analyse.exemple.test\n--force"}' E_SCHEMA
s "fqdn en majuscules → E_SCHEMA" set-hostname '{"fqdn": "Analyse.Exemple.Test"}' E_SCHEMA
s "fqdn commençant par - → E_SCHEMA" set-hostname '{"fqdn": "-analyse.exemple.test"}' E_SCHEMA
s "fqdn joker → E_SCHEMA" set-hostname '{"fqdn": "*.exemple.test"}' E_SCHEMA
s "fqdn à une étiquette → E_SCHEMA" set-hostname '{"fqdn": "analyse"}' E_SCHEMA
s "fqdn trop court → E_SCHEMA" set-hostname '{"fqdn": "a.b"}' E_SCHEMA
s "paramètre en trop → E_SCHEMA" set-hostname '{"fqdn": "analyse.exemple.test", "x": 1}' E_SCHEMA
s "paramètre manquant → E_SCHEMA" set-hostname '{}' E_SCHEMA
s "booléen à la place d'un entier → E_SCHEMA" set-update-policy '{"channel": "stable", "auto_check": 1, "auto_apply": false, "maintenance_window": null}' E_SCHEMA
s "auto_apply sans fenêtre → E_SCHEMA" set-update-policy '{"channel": "stable", "auto_check": true, "auto_apply": true, "maintenance_window": null}' E_SCHEMA
s "CIDR avec commande nft → E_SCHEMA" set-admin-networks '{"networks": ["192.0.2.0/24; flush ruleset"]}' E_SCHEMA
s "CIDR avec accolade → E_SCHEMA" set-admin-networks '{"networks": ["192.0.2.0/24 }"]}' E_SCHEMA
s "CIDR IPv6 en majuscules → E_SCHEMA" set-admin-networks '{"networks": ["2001:DB8::/32"]}' E_SCHEMA
s "CIDR en double → E_SCHEMA" set-admin-networks '{"networks": ["192.0.2.0/24", "192.0.2.0/24"]}' E_SCHEMA
s "CIDR non canonique (bits d'hôte) → E_INVALID_PARAM" set-admin-networks '{"networks": ["192.0.2.1/24"]}' E_INVALID_PARAM
s "CIDR IPv6 non canonique → E_INVALID_PARAM" set-admin-networks '{"networks": ["2001:0db8::/32"]}' E_INVALID_PARAM
s "CIDR IPv6 « ::: » → E_INVALID_PARAM" set-admin-networks '{"networks": [":::/64"]}' E_INVALID_PARAM
s "version avec suffixe → E_SCHEMA" apply-update '{"source": "github", "version": "1.2.3-rc1"}' E_SCHEMA
s "version avec option → E_SCHEMA" apply-update '{"source": "github", "version": "--help"}' E_SCHEMA
s "upload_id avec chemin → E_SCHEMA" apply-update '{"source": "upload", "upload_id": "../../../../etc"}' E_SCHEMA
s "source inconnue → E_SCHEMA" apply-update '{"source": "file", "version": "1.2.3"}' E_SCHEMA
# En-têtes de clé privée factices construits à l'exécution : aucune clé, même
# fausse, n'apparaît en clair dans le dépôt (gitleaks, check-repo).
PKB="-----BEGIN PRIVATE"" KEY-----"
PKE="-----END PRIVATE"" KEY-----"
s "PEM avec en-tête inattendu → E_SCHEMA" import-certificate "$(jq -nc --arg k "$PKB"$'\n' '{cert_pem: "x-----BEGIN CERTIFICATE-----\n", key_pem: $k}')" E_SCHEMA
s "PEM avec contenu hors base64 → E_CERT_INVALID" import-certificate "$(jq -nc --arg k "$PKB"$'\nAAAA\n'"$PKE"$'\n' '{cert_pem: "-----BEGIN CERTIFICATE-----\n$(id)`id`\n-----END CERTIFICATE-----\n", key_pem: $k}')" E_CERT_INVALID
expect "aucune commande lancée pour une demande refusée" "$(wc -l < "$TMP/calls.log")" 0

# Enveloppe
s2() { n=$(name_for "${3:-$(uuid)}" "${4:-}"); printf '%s' "$2" | submit "$1" "${5:-E_SCHEMA}" "$n"; }
id=$(uuid)
s2 "champ d'enveloppe en trop → E_SCHEMA" "$(req run-selftest '{}' "$id" | jq -c '. + {extra: 1}')" "$id"
id=$(uuid)
s2 "version 2 → E_SCHEMA" "$(req run-selftest '{}' "$id" | jq -c '.version = 2')" "$id"
id=$(uuid)
s2 "user_id booléen → E_SCHEMA" "$(req run-selftest '{}' "$id" | jq -c '.requested_by.user_id = true')" "$id"
id=$(uuid)
s2 "nom d'utilisateur avec espace → E_SCHEMA" "$(req run-selftest '{}' "$id" | jq -c '.requested_by.username = "a b"')" "$id"
id=$(uuid)
s2 "user_id 0 réservé à system → E_INVALID_PARAM" "$(req run-selftest '{}' "$id" | jq -c '.requested_by.user_id = 0')" "$id" "" E_INVALID_PARAM
id=$(uuid)
s2 "id ≠ nom du fichier → E_ID_MISMATCH" "$(req run-selftest '{}' "$(uuid)")" "$id" "" E_ID_MISMATCH
id=$(uuid)
s2 "horodatage du nom ≠ created_at → E_ID_MISMATCH" "$(req run-selftest '{}' "$id")" "$id" "20200101T000000Z" E_ID_MISMATCH
id=$(uuid); old=$((EPOCH - 2 * 86400))
s2 "demande de plus de 24 h → E_STALE" \
	"$(req run-selftest '{}' "$id" "$(date -u -d "@$old" +%Y-%m-%dT%H:%M:%SZ)")" "$id" "$(date -u -d "@$old" +%Y%m%dT%H%M%SZ)" E_STALE
id=$(uuid); fut=$((EPOCH + 3600))
s2 "demande dans le futur → E_STALE" \
	"$(req run-selftest '{}' "$id" "$(date -u -d "@$fut" +%Y-%m-%dT%H:%M:%SZ)")" "$id" "$(date -u -d "@$fut" +%Y%m%dT%H%M%SZ)" E_STALE

# --- 6. Doublon : le résultat d'origine n'est jamais écrasé -------------------------
id=$(uuid); n=$(name_for "$id")
valid run-selftest '{"quick": true}' "$id" | submit "run-selftest valide → OK" OK "$n"
first=$(sha256sum "$Q/done/$n")
before=$(find "$Q/failed" -name 'invalid-*' | wc -l)
valid run-selftest '{"quick": true}' "$id" | put "$n"
run_helper
expect "doublon : résultat d'origine intact" "$(sha256sum "$Q/done/$n")" "$first"
expect "doublon : résultat séparé, id null, E_DUPLICATE_ID" \
	"$(jq -r 'select(.code == "E_DUPLICATE_ID") | "\(.id)"' "$Q"/failed/invalid-*.json | sort -u)" null
expect "doublon : un seul nouveau résultat" "$(( $(find "$Q/failed" -name 'invalid-*' | wc -l) - before ))" 1

# --- 7. Anti-verrouillage ---------------------------------------------------------------
s3() { local id; id=$(uuid); n=$(name_for "$id"); req set-admin-networks "$2" "$id" "$CREATED" "$3" | submit "$1" "$4" "$n"; }
s3 "adresse hors des réseaux → E_LOCKOUT" '{"networks": ["198.51.100.0/24"]}' 192.0.2.10 E_LOCKOUT
s3 "adresse IPv4 encapsulée couverte → OK" '{"networks": ["192.0.2.0/24"]}' ::ffff:192.0.2.10 OK
s3 "adresse IPv6 couverte → OK" '{"networks": ["2001:db8::/32"]}' 2001:db8::10 OK
s3 "allow_self_lockout → OK" '{"networks": ["198.51.100.0/24"], "allow_self_lockout": true}' 192.0.2.10 OK
expect "E_LOCKOUT : configuration inchangée par le refus" "$(jq -c .networks "$T/etc/scanoria/admin-networks.json")" '["198.51.100.0/24"]'

# --- 8. Import de certificat : aucun secret ni fichier résiduel --------------------------
: > "$TMP/calls.log"
id=$(uuid); n=$(name_for "$id")
req import-certificate '{"cert_pem": "-----BEGIN CERTIFICATE-----\nQUFBQQ==\n-----END CERTIFICATE-----\n", "key_pem": "-----BEGIN PRIVATE KEY-----\nU0VDUkVUS0VZTUFURVJJQUw=\n-----END PRIVATE KEY-----\n"}' "$id" \
	| submit "import-certificate (bouchon) → OK" OK "$n"
if grep -q 'U0VDUkVUS0VZTUFURVJJQUw\|PRIVATE KEY' "$Q/done/$n" "$TMP/calls.log"; then
	ko "import : clé présente dans le résultat ou les arguments"
else
	ok "import : clé absente du résultat et des arguments"
fi
expect "import : fichiers temporaires supprimés" "$(find "$T/run/scanoria" -name 'import-*' | wc -l)" 0
expect "import : clé passée par fichier" "$(jq -r '.[0:2] | join(" ")' "$TMP/calls.log")" "scanoria-ca import"

# --- 9. Ordre FIFO ---------------------------------------------------------------------
: > "$TMP/calls.log"
a=$(uuid); b=$(uuid)
t1=$(date -u -d "@$((EPOCH - 2))" +%Y%m%dT%H%M%SZ); c1=$(date -u -d "@$((EPOCH - 2))" +%Y-%m-%dT%H:%M:%SZ)
req check-update '{"channel": "prerelease"}' "$b" | put "$(name_for "$b")"
req check-update '{"channel": "stable"}' "$a" "$c1" | put "$(name_for "$a" "$t1")"
run_helper
expect "FIFO : ordre lexical des noms" "$(jq -r '.[-1]' "$TMP/calls.log" | paste -sd ' ')" "stable prerelease"

# --- 10. exec (premier démarrage, timers, ligne de commande) ------------------------------
out=$("$HELPER" exec --origin cli --type set-update-policy \
	--params '{"channel": "prerelease", "auto_check": true, "auto_apply": true, "maintenance_window": {"days": ["sun"], "start": "02:00", "duration_minutes": 120}}' 2>> "$TMP/helper.err") || true
expect "exec : résultat JSON sur la sortie standard" "$(jq -r '"\(.code) \(.origin)"' <<< "$out")" "OK cli"
expect "exec : update.json écrit" "$(jq -r .channel "$T/etc/scanoria/update.json")" prerelease
expect "exec : résultat aussi dans done/" "$(find "$Q/done" -name "*-$(jq -r .id <<< "$out").json" | wc -l)" 1
rc=0; out=$("$HELPER" exec --origin cli --type set-hostname --params '{"fqdn": "x.exemple.test; id"}' 2>> "$TMP/helper.err") || rc=$?
expect "exec : injection refusée (E_SCHEMA, code 1)" "$(jq -r .code <<< "$out") $rc" "E_SCHEMA 1"
rc=0; "$HELPER" exec --origin console --type set-hostname --params '{}' > /dev/null 2>&1 || rc=$?
expect "exec : origine « console » refusée (usage)" "$rc" 2
rc=0; "$HELPER" exec --origin cli --type reboot --params '{}' > /dev/null 2>&1 || rc=$?
expect "exec : type inconnu refusé (usage)" "$rc" 2

# --- 10 bis. Mise à jour planifiée : vérification fraîche, canal, version abandonnée --------
# Bouchon de scanoria-selfupdate : « check » écrit check.json depuis $TMP/check.json
# (ou échoue si ce fichier manque) ; « apply » est seulement journalisé.
cp "$STUBS/scanoria-selfupdate" "$TMP/selfupdate.orig"
cat > "$STUBS/scanoria-selfupdate" <<-EOF
	#!/bin/bash
	jq -cn '["scanoria-selfupdate"] + \$ARGS.positional' --args -- "\$@" >> "$TMP/calls.log"
	if [[ \$1 == check ]]; then
		[[ -f "$TMP/check.json" ]] || { echo '{"code":"E_NETWORK","message":"stub","output":{}}'; exit 1; }
		mkdir -p "$T/var/lib/scanoria/updates"
		jq --arg now "\$(date -u +%Y-%m-%dT%H:%M:%SZ)" '.checked_at = \$now' "$TMP/check.json" > "$T/var/lib/scanoria/updates/check.json"
	fi
	echo '{"code":"OK","message":"stub","output":{}}'
EOF
chmod 0755 "$STUBS/scanoria-selfupdate"
mkdir -p "$T/opt/scanoria/releases/0.1.0" "$T/var/lib/scanoria/updates"
echo 0.1.0 > "$T/opt/scanoria/releases/0.1.0/VERSION"
ln -sfn releases/0.1.0 "$T/opt/scanoria/current"
pol() {
	jq -n --arg c "$1" '{channel: $c, auto_check: true, auto_apply: true,
		maintenance_window: {days: ["mon","tue","wed","thu","fri","sat","sun"], start: "00:00", duration_minutes: 1440}}' \
		> "$T/etc/scanoria/update.json"
}
chk() {
	jq -n --arg c "$1" --arg v "$2" '{checked_at: "2000-01-01T00:00:00Z", channel: $c, code: "OK",
		latest_version: $v, available: true, notes_md: null, published_at: null, source_url: null}' > "$TMP/check.json"
}
# Lance le timer update-apply ; rend les versions passées à « apply ».
sched() {
	: > "$TMP/calls.log"
	rm -f "$T/var/lib/scanoria/updates/auto-apply.json"
	"$HELPER" scheduled update-apply > /dev/null 2>> "$TMP/helper.err" || true
	jq -r 'select(.[1] == "apply") | .[3]' "$TMP/calls.log" | paste -sd ' '
}
pol stable; chk stable 0.2.0
expect "update-apply : version appliquée" "$(sched)" "0.2.0"
expect "update-apply : vérification relancée juste avant" "$(jq -r '.[1]' "$TMP/calls.log" | paste -sd ' ')" "check apply"
pol stable; chk prerelease 0.2.0
expect "update-apply : résultat d'un autre canal → rien" "$(sched)" ""
pol stable; rm -f "$TMP/check.json"
echo '{"checked_at":"2026-01-01T00:00:00Z","channel":"stable","code":"OK","latest_version":"0.2.0","available":true}' \
	> "$T/var/lib/scanoria/updates/check.json"
expect "update-apply : vérification en échec → ancien check.json ignoré" "$(sched)" ""
pol stable; chk stable 0.2.0
echo '{"version":"0.2.0","at":"2026-01-01T00:00:00Z"}' > "$T/var/lib/scanoria/updates/skip-version.json"
expect "update-apply : version abandonnée par un retour N-1 → rien" "$(sched)" ""
chk stable 0.3.0
expect "update-apply : version plus récente que l'abandonnée → appliquée" "$(sched)" "0.3.0"
rm -f "$T/var/lib/scanoria/updates/skip-version.json"
"$HELPER" exec --origin cli --type set-update-policy \
	--params '{"channel": "stable", "auto_check": true, "auto_apply": false, "maintenance_window": null}' > /dev/null 2>> "$TMP/helper.err" || true
[[ -f "$T/var/lib/scanoria/updates/check.json" ]] && ok "set-update-policy : même canal, check.json gardé" || ko "check.json effacé à tort"
"$HELPER" exec --origin cli --type set-update-policy \
	--params '{"channel": "prerelease", "auto_check": true, "auto_apply": false, "maintenance_window": null}' > /dev/null 2>> "$TMP/helper.err" || true
[[ ! -e "$T/var/lib/scanoria/updates/check.json" ]] && ok "set-update-policy : changement de canal, check.json effacé" || ko "check.json gardé après changement de canal"
dl=$(python3 -I -B - "$ROOT/src/rootfs/usr/lib/scanoria/py" <<-'EOF'
	import sys, time
	sys.path.insert(0, sys.argv[1])
	from scanoria import helper
	t = helper.TIMEOUTS["apply-update"]
	c = helper.Ctx({"params": {}}, time.monotonic() + t)
	d = int(helper.update_env(c)["SCANORIA_UPDATE_DEADLINE"]) - int(time.time())
	print("ok" if t >= 3300 and t - 320 <= d <= t - 300 else d)
EOF
)
expect "apply-update : 3300 s et échéance transmise à scanoria-selfupdate" "$dl" ok
cp "$TMP/selfupdate.orig" "$STUBS/scanoria-selfupdate"

# --- 10 ter. Analyse PEM en temps linéaire ----------------------------------------------------
pem=$(python3 -I -B - "$ROOT/src/rootfs/usr/lib/scanoria/py" <<-'EOF'
	import sys, time
	sys.path.insert(0, sys.argv[1])
	from scanoria import helper
	B, E = "-----BEGIN CERTIFICATE-----\n", "-----END CERTIFICATE-----\n"
	good = B + "QUFBQQ==\n" + E
	t = time.monotonic()
	slow = [helper.pem_ok(B + "QUFB\n" + (E + B) * 270 + "!"),
	        helper.pem_ok(B + "QUFB\n" + (E + B) * 15 + "!"),
	        helper.pem_ok(B + "QUFB\n" * 1999 + "!")]
	dt = time.monotonic() - t
	cases = [helper.pem_ok(good), helper.pem_ok(good + "\n" + good), helper.pem_ok(good.replace("\n", "\r\n")),
	         helper.pem_ok(B + "Proc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,00FF\n\nQUFB\n" + E),
	         not helper.pem_ok(B + "-QUFB\n" + E), not helper.pem_ok(B + E),
	         not helper.pem_ok(B + "QUFB\n-----END RSA PUBLIC KEY-----\n"), not helper.pem_ok(good * 17),
	         not helper.pem_ok("x" + good), not helper.pem_ok(good + "x"), not any(slow), dt < 1]
	print(" ".join("1" if c else "0" for c in cases))
EOF
)
expect "PEM : analyse correcte et linéaire (entrée pathologique < 1 s)" "$pem" "1 1 1 1 1 1 1 1 1 1 1 1"

# --- 11. Conformité des résultats -----------------------------------------------------------
bad=$(python3 -I -B - "$ROOT/src/rootfs/usr/lib/scanoria/py" "$Q" <<-'EOF'
	import glob, json, os, sys
	sys.path.insert(0, sys.argv[1])
	from scanoria import schema
	v = schema.load("requests", "result")
	bad = 0
	for f in glob.glob(os.path.join(sys.argv[2], "*", "*.json")):
	    with open(f, "rb") as fh:
	        data = fh.read()
	    res = json.loads(data)
	    if not v.valid(res) or b"PRIVATE KEY" in data:
	        bad += 1
	        print(f, v.errors(res), file=sys.stderr)
	print(bad)
EOF
)
expect "tous les résultats sont conformes à result.schema.json" "$bad" 0
expect "statut rejected ⇔ code de forme" \
	"$(jq -r 'select((.status == "rejected") != (.code | test("^E_(INVALID_NAME|NOT_REGULAR_FILE|BAD_OWNER|TOO_LARGE|INVALID_JSON|UNKNOWN_TYPE|SCHEMA|ID_MISMATCH|DUPLICATE_ID|STALE|INVALID_PARAM)$"))) | .id' "$Q"/done/*.json "$Q"/failed/*.json | wc -l)" 0

echo
echo "b01 : $PASS réussi(s), $FAIL échec(s)"
[[ $FAIL -eq 0 ]]
