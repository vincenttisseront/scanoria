#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Vincent Tisseront
#
# b04 — socle système (src/rootfs), contrôles statiques et fumée sans root :
#   - en-têtes SPDX, fins de ligne LF, préfixes autorisés (§ 3.3) ;
#   - shellcheck et bash -n (scripts du lot et tests b2x), syntaxe Python ;
#   - unités systemd (systemd-analyze verify si disponible) ;
#   - pare-feu : règles générées (IPv4, IPv6, ensembles vides), refus d'une
#     configuration invalide, « nft -c » si root et nft présents ;
#   - scanoria-state et scanoria-selftest en mode test : sortie conforme aux
#     schémas, codes de sortie (0 pass/warn, 1 fail, 2 usage).
# Dépendances : bash, python3, jq, ShellCheck (pip install shellcheck-py).

# shellcheck disable=SC2016,SC2015
set -euo pipefail
shopt -s lastpipe
export PYTHONDONTWRITEBYTECODE=1

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
RF="$ROOT/src/rootfs"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

PASS=0
FAIL=0
ok() { PASS=$((PASS + 1)); printf 'ok   %s\n' "$1"; }
ko() { FAIL=$((FAIL + 1)); printf 'FAIL %s\n' "$1"; }
expect() { if [[ "$2" == "$3" ]]; then ok "$1"; else ko "$1 (obtenu « $2 », attendu « $3 »)"; fi; }
check() {
	local label=$1
	shift
	if "$@" > "$TMP/last.log" 2>&1; then ok "$label"; else ko "$label"; sed 's/^/     /' "$TMP/last.log" | head -n 30; fi
}
for t in python3 jq shellcheck; do command -v "$t" > /dev/null || { echo "outil manquant : $t" >&2; exit 2; }; done

# Fichiers du lot (hors premier démarrage, lot C, et schémas JSON de l'architecte).
mapfile -t FILES < <(cd "$ROOT" && find src/rootfs -type f ! -path '*/firstboot/*' ! -name '*.schema.json' \
	! -path '*/__pycache__/*' ! -name 'update.json' | LC_ALL=C sort)
FILES+=(tests/b01-helper-hostile.sh tests/b02-update-signature.sh tests/b03-ca.sh tests/b04-system-static.sh)

# --- 1. Fichiers ----------------------------------------------------------------------
missing=()
for f in "${FILES[@]}"; do
	grep -q 'SPDX-License-Identifier: AGPL-3.0-or-later' "$ROOT/$f" && grep -q 'Copyright (C) 2026 Vincent Tisseront' "$ROOT/$f" \
		|| missing+=("$f")
done
expect "en-tête SPDX et copyright dans chaque fichier" "${missing[*]:-}" ""
crlf=$(cd "$ROOT" && grep -l $'\r' "${FILES[@]}" || true)
expect "fins de ligne LF" "$crlf" ""
bad=$(cd "$RF" && find . -type f ! -path '*/__pycache__/*' | sed 's#^\./##' \
	| grep -Ev '^usr/(sbin/scanoria-[a-z0-9][a-z0-9-]*|lib/scanoria/.+|share/scanoria/.+|lib/systemd/system/scanoria-[A-Za-z0-9@._-]+|lib/sysusers\.d/scanoria\.conf|lib/tmpfiles\.d/scanoria\.conf)$' || true)
expect "src/rootfs : préfixes autorisés seulement (§ 3.3)" "$bad" ""
expect "src/rootfs : aucun lien symbolique" "$(find "$RF" -type l | wc -l)" 0
expect "aucune clé privée dans src/rootfs" "$(grep -rl -- '-----BEGIN [A-Z ]*PRIVATE KEY-----' "$RF" | wc -l)" 0
expect "update-pubkey.pem n'est pas déployé par une mise à jour" "$(find "$RF" -name 'update-pubkey.pem' | wc -l)" 0
for c in scanoria-helper scanoria-ca scanoria-firewall scanoria-selfupdate scanoria-state scanoria-selftest; do
	[[ -x "$RF/usr/sbin/$c" ]] && ok "commande exécutable : $c" || ko "commande absente ou non exécutable : $c"
done

# --- 2. Syntaxe ----------------------------------------------------------------------------
SH=()
for f in "${FILES[@]}"; do
	if head -n 1 "$ROOT/$f" | grep -q '^#!.*bash' || grep -q '^# shellcheck shell=bash' "$ROOT/$f"; then SH+=("$f"); fi
done
for f in "${SH[@]}"; do check "bash -n $f" bash -n "$ROOT/$f"; done
check "shellcheck (${#SH[@]} scripts)" bash -c 'cd "$1" && shift && shellcheck -x -P SCRIPTDIR "$@"' _ "$ROOT" "${SH[@]}"
mapfile -t PY < <(find "$RF/usr/lib/scanoria/py" -name '*.py')
check "syntaxe Python (${#PY[@]} fichiers)" python3 -I -B -c 'import ast, sys
for f in sys.argv[1:]:
    ast.parse(open(f, encoding="utf-8").read(), f)' "${PY[@]}"
check "schémas chargés par le validateur (mots-clés pris en charge)" python3 -I -B -c 'import sys, os, glob
sys.path.insert(0, sys.argv[1])
from scanoria import schema
for kind in ("requests", "schemas"):
    for f in glob.glob(os.path.join(sys.argv[2], kind, "*.schema.json")):
        schema.load(kind, os.path.basename(f)[:-len(".schema.json")])' "$RF/usr/lib/scanoria/py" "$RF/usr/share/scanoria"
check "valeurs par défaut : update.json conforme" python3 -I -B -c 'import json, sys
d = json.load(open(sys.argv[1]))
assert d == {"channel": "stable", "auto_check": True, "auto_apply": False, "maintenance_window": None}' \
	"$RF/usr/share/scanoria/defaults/update.json"
if command -v systemd-analyze > /dev/null; then
	# Seules les erreurs de syntaxe comptent (les binaires ne sont pas installés ici).
	systemd-analyze verify --man=no "$RF"/usr/lib/systemd/system/scanoria-* 2>&1 \
		| grep -v 'is not executable: No such file or directory' \
		| grep -F "$RF/" > "$TMP/sa.log" || true
	# (seuls les messages qui portent sur nos unités : systemd-analyze vérifie
	# aussi les unités dont elles dépendent, celles de l'hôte de test)
	expect "unités systemd (systemd-analyze verify)" "$(cat "$TMP/sa.log")" ""
fi
grep -q '^NoNewPrivileges=yes' "$RF/usr/lib/systemd/system/scanoria-console.service" \
	&& grep -q '^ProtectSystem=strict' "$RF/usr/lib/systemd/system/scanoria-console.service" \
	&& grep -q '^User=scanoria' "$RF/usr/lib/systemd/system/scanoria-console.service" \
	&& ok "console : utilisateur scanoria, durcissement" || ko "console : durcissement"
W="$RF/usr/lib/systemd/system/scanoria-worker.service"
grep -q '^NoNewPrivileges=yes' "$W" && grep -q '^ProtectSystem=strict' "$W" && grep -q '^User=scanoria' "$W" \
	&& grep -q '^PartOf=scanoria-console.service' "$W" && grep -q '^IPAddressDeny=any' "$W" \
	&& grep -q '^Wants=scanoria-worker.service' "$RF/usr/lib/systemd/system/scanoria-console.service" \
	&& ok "worker : utilisateur scanoria, durcissement, lié à la console" || ko "worker : durcissement"

# --- 3. Pare-feu --------------------------------------------------------------------------
T="$TMP/root"
mkdir -p "$T/etc/scanoria" "$T/run/scanoria" "$T/var/lib/scanoria/requests/incoming"
export SCANORIA_TEST_ROOT="$T"
unset SCANORIA_TEST_BIN SCANORIA_TEST_OWNER_UID
FW="$RF/usr/sbin/scanoria-firewall"
fw_render() { # configuration JSON -> fichier de règles
	printf '%s' "$1" > "$T/etc/scanoria/admin-networks.json"
	"$FW" render > "$2" 2> /dev/null
}
fw_render '{"networks": ["192.0.2.0/24", "198.51.100.7/32", "2001:db8::/32"]}' "$TMP/r1.nft"
grep -q 'elements = { 192.0.2.0/24, 198.51.100.7/32 }' "$TMP/r1.nft" && ok "pare-feu : ensemble admin4" || ko "pare-feu : admin4"
grep -q 'elements = { 2001:db8::/32 }' "$TMP/r1.nft" && ok "pare-feu : ensemble admin6" || ko "pare-feu : admin6"
grep -q 'policy drop;' "$TMP/r1.nft" && grep -q 'tcp dport { 22, 80, 443 }' "$TMP/r1.nft" \
	&& ok "pare-feu : politique drop, 22/80/443 depuis les réseaux d'administration" || ko "pare-feu : règles"
grep -v '^#' "$TMP/r1.nft" | grep -q 'flush ruleset' && ko "pare-feu : flush ruleset interdit" || ok "pare-feu : jamais de flush ruleset"
fw_render '{"networks": ["192.0.2.0/24"]}' "$TMP/r2.nft"
expect "pare-feu : IPv4 seule → pas d'éléments IPv6" "$(grep -c 'elements' "$TMP/r2.nft")" 1
for badconf in '{"networks": []}' '{"networks": ["192.0.2.1/24"]}' '{"networks": ["192.0.2.0/24; flush ruleset"]}' \
	'{"networks": ["192.0.2.0/24"], "x": 1}' 'not json'; do
	if fw_render "$badconf" "$TMP/bad.nft"; then ko "pare-feu : configuration refusée : $badconf"; else ok "pare-feu : configuration refusée : $badconf"; fi
done
printf '%s' '{"networks": ["192.0.2.1/24"]}' > "$T/etc/scanoria/admin-networks.json"
out=$("$FW" apply 2> /dev/null || true)
expect "pare-feu : apply avec configuration invalide → E_INVALID_PARAM" "$(jq -r .code <<< "$out")" E_INVALID_PARAM
out=$("$FW" apply --boot 2> /dev/null || true)
expect "pare-feu : démarrage avec configuration invalide → table aux ensembles vides" \
	"$(jq -r .code <<< "$out") $(grep -c elements "$T/etc/scanoria/nftables/scanoria.nft")" "OK 0"
rm -f "$T/etc/scanoria/admin-networks.json"
out=$("$FW" apply --boot 2> /dev/null || true)
expect "pare-feu : démarrage sans configuration → rien chargé" "$(jq -r '"\(.code) \(.output.loaded)"' <<< "$out")" "OK false"
if [[ $EUID -eq 0 ]] && command -v nft > /dev/null; then
	for f in "$TMP/r1.nft" "$TMP/r2.nft" "$T/etc/scanoria/nftables/scanoria.nft"; do
		check "nft -c $(basename "$f")" nft -c -f "$f"
	done
else
	echo "skip nft -c (root et nft requis)"
fi

# --- 4. scanoria-state et scanoria-selftest en mode test ------------------------------------
printf '{"networks": ["192.0.2.0/24"]}' > "$T/etc/scanoria/admin-networks.json"
printf '{"fqdn": "analyse.exemple.test"}' > "$T/etc/scanoria/appliance.json"
check "scanoria-state : état conforme au schéma" "$RF/usr/sbin/scanoria-state"
check "state.json : valide (jq)" jq -e '.version == 1 and .appliance.fqdn == "analyse.exemple.test" and (.helper.busy | not)' "$T/run/scanoria/state.json"
rc=0; "$RF/usr/sbin/scanoria-selftest" --json --quick > "$TMP/st.json" 2> "$TMP/st.err" || rc=$?
expect "selftest sur une appliance vide : fail, code 1" "$(jq -r .status "$TMP/st.json" 2> /dev/null) $rc" "fail 1"
check "selftest : rapport conforme au schéma" python3 -I -B -c 'import json, sys
sys.path.insert(0, sys.argv[1])
from scanoria import schema
assert schema.load("schemas", "selftest").valid(json.load(open(sys.argv[2])))' "$RF/usr/lib/scanoria/py" "$TMP/st.json"
ids=$(jq -r '[.checks[].id] | join(" ")' "$TMP/st.json")
for id in version.files layout.release perms.paths pubkey.present services.postgresql services.nginx \
	services.console services.helper-path worker.alive db.connect db.migrations console.health tls.cert-valid \
	tls.cert-names tls.key-match tls.ca-present firewall.loaded requests.queue disk.free; do
	[[ " $ids " == *" $id "* ]] && ok "selftest --quick : $id" || ko "selftest --quick : $id absent"
done
"$RF/usr/sbin/scanoria-selftest" --json > "$TMP/st2.json" 2> /dev/null || true
expect "selftest complet : dns.resolve, time.sync, hardware.floor" \
	"$(jq -r '[.checks[].id | select(. == "dns.resolve" or . == "time.sync" or . == "hardware.floor")] | length' "$TMP/st2.json")" 3
rc=0; "$RF/usr/sbin/scanoria-selftest" --bogus > /dev/null 2>&1 || rc=$?
expect "selftest : option inconnue → code 2" "$rc" 2

# Premier démarrage : aucune unité ordonnée après multi-user.target (cloud-final),
# sinon cycle avec getty@tty1 et multi-user.target, et l'assistant ne part pas.
fb="$ROOT/src/rootfs/usr/lib/systemd/system/scanoria-firstboot.service"
refuse_cycle() { grep -E '^(After|Wants|Requires)=' "$fb" | grep -qE 'cloud-final|multi-user\.target|graphical\.target'; }
if refuse_cycle; then ko "scanoria-firstboot.service : ordonnée après multi-user.target (cycle)"; else ok "scanoria-firstboot.service : sans cycle avec multi-user.target"; fi

echo
echo "b04 : $PASS réussi(s), $FAIL échec(s)"
[[ $FAIL -eq 0 ]]
