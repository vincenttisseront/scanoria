#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Vincent Tisseront
#
# b37 — gate de release (0.8, chantier A, CLAUDE.md § 7.3), sans root.
# 1. Demande sign-release-report au vrai helper (mode test, file de demandes) :
#    rapport valide signé par la clé de l'appliance (créée une fois, 0600),
#    puis demandes hostiles : empreinte fausse, schéma inconnu, autre scan_id,
#    forme non canonique (espaces, clés non triées, nombre non entier, clé en
#    double), base64 non strict, contenu trop gros, autre type au-delà de
#    128 Kio refusé avant tout décodage, paramètres en trop. Clé privée jamais
#    dans un résultat.
# 2. scanoria-verify (sh POSIX, openssl) sur l'enveloppe produite comme la
#    console : rapport valide ; octet modifié ; empreinte et contenu échangés ;
#    signature d'un autre rapport ; autre clé ; commit différent ; --fetch-key
#    sans empreinte refusé ; verdict non favorable avec --require-passed.
# 3. Forme canonique stable : deux sérialisations Python indépendantes
#    (et l'ordre d'insertion des clés) donnent les mêmes octets.
# Dépendances : bash, python3, jq, openssl.

# shellcheck disable=SC2015
set -euo pipefail
export PYTHONDONTWRITEBYTECODE=1

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
HELPER="$ROOT/src/rootfs/usr/sbin/scanoria-helper"
VERIFY="$ROOT/src/rootfs/usr/share/scanoria/client/scanoria-verify"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
for t in python3 jq openssl; do command -v "$t" > /dev/null || { echo "outil manquant : $t" >&2; exit 2; }; done

PASS=0
FAIL=0
ok() { PASS=$((PASS + 1)); printf 'ok   %s\n' "$1"; }
ko() { FAIL=$((FAIL + 1)); printf 'FAIL %s\n' "$1"; }
expect() {
	if [[ "$2" == "$3" ]]; then ok "$1"; else ko "$1 (obtenu « $2 », attendu « $3 »)"; fi
}

T="$TMP/root"
Q="$T/var/lib/scanoria/requests"
STUBS="$TMP/stubs"
mkdir -p "$Q"/{tmp,incoming,work,done,failed} "$T/run/scanoria" "$T/etc/scanoria" "$STUBS"
chmod 0700 "$Q/incoming" "$Q/work"
printf '#!/bin/bash\nexit 0\n' > "$STUBS/scanoria-state"
chmod 0755 "$STUBS"/*
export SCANORIA_TEST_ROOT="$T" SCANORIA_TEST_BIN="$STUBS"
unset SCANORIA_TEST_OWNER_UID SCANORIA_TEST_NOW

uuid() { python3 -c 'import uuid; print(uuid.uuid4())'; }
NAME_TS=$(date -u +%Y%m%dT%H%M%SZ)
CREATED=$(date -u +%Y-%m-%dT%H:%M:%SZ)
run_helper() { "$HELPER" run 2> "$TMP/helper.err" || { ko "scanoria-helper run (code $?)"; sed 's/^/     /' "$TMP/helper.err"; }; }
result() { # NOM → fichier de résultat
	local f
	for f in "$Q/done/$1" "$Q/failed/$1"; do [[ -f "$f" ]] && { echo "$f"; return; }; done
	echo /dev/null
}
# canon FICHIER_JSON → octets canoniques (comme canonical.ts et release.py)
canon() { python3 -c 'import json, sys; sys.stdout.buffer.write(json.dumps(json.load(open(sys.argv[1])), sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode())' "$1"; }
b64() { openssl base64 -A -in "$1"; }
sha() { openssl dgst -sha256 -r "$1" | cut -c1-64; }

# sign NOM_DE_LIBELLÉ CODE_ATTENDU FICHIER_CONTENU SCAN_ID [SHA] [KIND] [EXTRA_JSON] [TYPE]
# Dépose la demande dans la file, lance le helper, vérifie le code ; résultat dans $RES.
sign() {
	local label=$1 want=$2 content=$3 scan=$4 digest=${5:-} kind=${6:-release-report} extra=${7:-'{}'} type=${8:-sign-release-report}
	local id name
	id=$(uuid)
	name="$NAME_TS-$id.json"
	[[ -n "$digest" ]] || digest=$(sha "$content")
	b64 "$content" > "$TMP/content.b64"
	jq -cn --arg id "$id" --arg created "$CREATED" --arg scan "$scan" --arg sha "$digest" --arg kind "$kind" \
		--rawfile c "$TMP/content.b64" --arg type "$type" --argjson extra "$extra" \
		'{version: 1, id: $id, type: $type, created_at: $created, requested_by: {user_id: 0, username: "system"},
		  params: ({scan_id: $scan, sha256: $sha, kind: $kind, content_b64: $c} + $extra)}' > "$Q/incoming/$name"
	run_helper
	RES=$(result "$name")
	expect "$label" "$(jq -r .code "$RES" 2> /dev/null || echo absent)" "$want"
}

SCAN=$(uuid)
COMMIT=$(printf 'c0ffee%.0s' 1 2 3 4 5 6 7 | cut -c1-40)
cat > "$TMP/report.json" <<-EOF
	{"schema": "scanoria-release-report/1", "scan_id": "$SCAN", "tag": "v1.2.0", "commit_sha": "$COMMIT",
	 "verdict": {"value": "passed", "reasons": []}, "project": {"slug": "demo", "name": "Démo é"},
	 "findings": {"total": 3, "by_tool": {"gitleaks": 1}}, "comparison": null}
EOF
canon "$TMP/report.json" > "$TMP/report.canon"

# === 1. Demande valide ===========================================================
sign "rapport canonique valide → OK" OK "$TMP/report.canon" "$SCAN"
expect "sortie : empreinte et analyse" "$(jq -r '.output.sha256 == "'"$(sha "$TMP/report.canon")"'" and .output.scan_id == "'"$SCAN"'"' "$RES")" true
SIG=$(jq -r .output.signature "$RES")
FP=$(jq -r .output.key_fingerprint "$RES")
KEY="$T/etc/scanoria/keys/appliance.ed25519"
expect "clé de l'appliance 0600" "$(stat -c %a "$KEY")" 600
expect "clé privée jamais dans un résultat" "$(grep -rl 'PRIVATE KEY' "$Q/done" "$Q/failed" 2> /dev/null | wc -l)" 0
openssl pkey -in "$KEY" -pubout -out "$TMP/appliance.pem" 2> /dev/null
expect "empreinte = SHA-256 de la clé publique brute" "$FP" "$(openssl pkey -pubin -in "$TMP/appliance.pem" -outform DER | tail -c 32 | openssl dgst -sha256 -r | cut -c1-64)"
expect "params.content_b64 jamais recopié dans le résultat" "$(jq -r '.. | strings | select(length > 4096)' "$RES" | wc -l)" 0
REC="$T/var/lib/scanoria/release/signed/$SCAN.json"
expect "relevé root du rapport signé (0600, répertoire 0700)" "$(stat -c %a "$REC") $(stat -c %a "$(dirname "$REC")")" "600 700"
expect "relevé : analyse, empreinte, commit, tag, verdict, clé" \
	"$(jq -r '[.scan_id, .report_sha256, .commit_sha, .tag, .verdict, .key_fingerprint] | join(" ")' "$REC")" \
	"$SCAN $(sha "$TMP/report.canon") $COMMIT v1.2.0 passed $FP"

# === 2. Demandes hostiles ========================================================
rm -f "$REC"
sign "empreinte qui ne correspond pas → E_SIGN_DIGEST" E_SIGN_DIGEST "$TMP/report.canon" "$SCAN" "$(printf '%064d' 0)"
sign "autre scan_id que la demande → E_SIGN_SCAN" E_SIGN_SCAN "$TMP/report.canon" "$(uuid)"
jq -c '.schema = "scanoria-attestation/1"' "$TMP/report.json" > "$TMP/x.json"; canon "$TMP/x.json" > "$TMP/x.canon"
sign "schéma de rapport inconnu → E_SIGN_SCHEMA" E_SIGN_SCHEMA "$TMP/x.canon" "$SCAN"
sign "kind inconnu → refusé par le schéma" E_SCHEMA "$TMP/report.canon" "$SCAN" "" attestation
jq '.' "$TMP/report.json" > "$TMP/x.pretty"
sign "JSON avec espaces (non canonique) → E_SIGN_CANONICAL" E_SIGN_CANONICAL "$TMP/x.pretty" "$SCAN"
python3 -c 'import json, sys; d = json.load(open(sys.argv[1])); sys.stdout.write(json.dumps(dict(reversed(list(d.items()))), separators=(",", ":"), ensure_ascii=False))' "$TMP/report.json" > "$TMP/x.unsorted"
sign "clés non triées → E_SIGN_CANONICAL" E_SIGN_CANONICAL "$TMP/x.unsorted" "$SCAN"
jq -c '.findings.total = 1.5' "$TMP/report.json" > "$TMP/x.json"; canon "$TMP/x.json" > "$TMP/x.float"
sign "nombre non entier → E_SIGN_CANONICAL" E_SIGN_CANONICAL "$TMP/x.float" "$SCAN"
sed 's/^{/{"commit_sha":"'"$(printf '%040d' 0)"'",/' "$TMP/report.canon" > "$TMP/x.dup"
sign "clé en double (deux commits) → E_SIGN_CANONICAL" E_SIGN_CANONICAL "$TMP/x.dup" "$SCAN"
printf '[1,2]' > "$TMP/x.array"
sign "contenu qui n'est pas un objet → E_SIGN_CANONICAL" E_SIGN_CANONICAL "$TMP/x.array" "$SCAN"
expect "demandes refusées : aucun relevé écrit" "$(find "$T/var/lib/scanoria/release/signed" -type f | wc -l)" 0

# base64 non strict : remplissage retiré (le schéma de la demande ou release.py refuse)
id=$(uuid); name="$NAME_TS-$id.json"
jq -cn --arg id "$id" --arg created "$CREATED" --arg scan "$SCAN" --arg sha "$(sha "$TMP/report.canon")" --arg c "$(b64 "$TMP/report.canon" | tr -d '=')A" \
	'{version: 1, id: $id, type: "sign-release-report", created_at: $created, requested_by: {user_id: 0, username: "system"},
	  params: {scan_id: $scan, sha256: $sha, kind: "release-report", content_b64: $c}}' > "$Q/incoming/$name"
run_helper
c=$(jq -r .code "$(result "$name")")
[[ "$c" == E_SIGN_ENCODING || "$c" == E_SCHEMA ]] && ok "base64 non strict → refusé ($c)" || ko "base64 non strict (obtenu $c)"

# Contenu de plus de 4 Mio (mais demande sous 6 Mio) : refusé, jamais signé.
python3 - "$TMP/report.json" "$TMP/x.big" <<-'EOF'
	import json, sys
	d = json.load(open(sys.argv[1]))
	d["padding"] = "x" * (4 * 1024 * 1024 + 10)
	open(sys.argv[2], "w").write(json.dumps(d, sort_keys=True, separators=(",", ":"), ensure_ascii=False))
EOF
sign "contenu au-delà de 4 Mio → refusé par le schéma (maxLength)" E_SCHEMA "$TMP/x.big" "$SCAN"
expect "contenu trop gros : jamais signé" "$(jq -r '.output.signature // "aucune"' "$RES")" aucune

# Un autre type ne profite jamais de la limite de 6 Mio : refusé avant tout décodage.
head -c 200000 /dev/zero | tr '\0' 'a' > "$TMP/x.pad"
id=$(uuid); name="$NAME_TS-$id.json"
jq -cn --arg id "$id" --arg created "$CREATED" --rawfile pad "$TMP/x.pad" \
	'{version: 1, id: $id, type: "set-hostname", created_at: $created, requested_by: {user_id: 1, username: "admin"},
	  params: {fqdn: "analyse.exemple.test"}, padding: $pad}' > "$Q/incoming/$name"
run_helper
expect "autre type au-delà de 128 Kio → E_TOO_LARGE" "$(jq -r .code "$(result "$name")")" E_TOO_LARGE
id=$(uuid); name="$NAME_TS-$id.json"
{ printf '{"padding":"'; cat "$TMP/x.pad"; printf '","type":"sign-release-report","version":1}'; } > "$Q/incoming/$name"
run_helper
expect "type sign-release-report caché après 512 octets → E_TOO_LARGE" "$(jq -r .code "$(result "$name")")" E_TOO_LARGE
sign "paramètre inconnu → E_SCHEMA" E_SCHEMA "$TMP/report.canon" "$SCAN" "" release-report '{"key_path": "/etc/scanoria/keys/appliance.ed25519"}'
expect "aucune demande laissée dans incoming/" "$(find "$Q/incoming" -mindepth 1 | wc -l)" 0

# === 3. scanoria-verify ==========================================================
# envelope FICHIER_CANON SIGNATURE FP → enveloppe comme la console (sign.ts signedEnvelope)
envelope() {
	python3 - "$1" "$2" "$3" <<-'EOF'
		import base64, hashlib, json, sys
		raw = open(sys.argv[1], "rb").read()
		env = {"schema": "scanoria-signed-release-report/1", "payload_type": "application/vnd.scanoria.release-report+json",
		       "payload": base64.b64encode(raw).decode(), "payload_sha256": hashlib.sha256(raw).hexdigest(),
		       "signature": sys.argv[2], "key_fingerprint": sys.argv[3], "signed_at": "2026-11-25T10:00:00Z"}
		sys.stdout.write(json.dumps(env, sort_keys=True, separators=(",", ":")) + "\n")
	EOF
}
verify() { sh "$VERIFY" "$@" > "$TMP/verify.out" 2>&1; echo $?; }
envelope "$TMP/report.canon" "$SIG" "$FP" > "$TMP/env.json"
expect "rapport valide → 0" "$(verify "$TMP/env.json" --key "$TMP/appliance.pem")" 0
expect "commit identique → 0" "$(verify "$TMP/env.json" --key "$TMP/appliance.pem" --commit "$COMMIT")" 0
expect "commit abrégé identique → 0" "$(verify "$TMP/env.json" --key "$TMP/appliance.pem" --commit "${COMMIT:0:12}")" 0
expect "commit différent → 2" "$(verify "$TMP/env.json" --key "$TMP/appliance.pem" --commit "$(printf '%040d' 1)")" 2
expect "verdict favorable avec --require-passed → 0" "$(verify "$TMP/env.json" --key "$TMP/appliance.pem" --require-passed)" 0
expect "empreinte de clé attendue → 0" "$(verify "$TMP/env.json" --key "$TMP/appliance.pem" --key-fingerprint "$FP")" 0
expect "empreinte de clé attendue différente → 1" "$(verify "$TMP/env.json" --key "$TMP/appliance.pem" --key-fingerprint "$(printf '%064d' 2)")" 1

# Un octet du contenu signé modifié (empreinte recalculée pour passer le premier contrôle).
sed 's/"passed"/"passeD"/' "$TMP/report.canon" > "$TMP/x.tamper"
envelope "$TMP/x.tamper" "$SIG" "$FP" > "$TMP/env.bad"
expect "octet modifié (empreinte recalculée) → 1 (signature)" "$(verify "$TMP/env.bad" --key "$TMP/appliance.pem")" 1
grep -q 'signature invalide' "$TMP/verify.out" && ok "message : signature invalide" || ko "message de signature"
# Octet modifié sans recalcul de l'empreinte.
python3 - "$TMP/env.json" "$TMP/env.bad" <<-'EOF'
	import base64, json, sys
	e = json.load(open(sys.argv[1])); raw = bytearray(base64.b64decode(e["payload"])); raw[10] ^= 1
	e["payload"] = base64.b64encode(bytes(raw)).decode()
	open(sys.argv[2], "w").write(json.dumps(e, sort_keys=True, separators=(",", ":")) + "\n")
EOF
expect "octet modifié → 1 (empreinte)" "$(verify "$TMP/env.bad" --key "$TMP/appliance.pem")" 1
# Clés de l'enveloppe échangées (empreinte à la place de la signature).
jq -c '{payload, payload_sha256: .key_fingerprint, key_fingerprint: .payload_sha256, signature, schema, payload_type, signed_at}' "$TMP/env.json" > "$TMP/env.bad"
expect "empreintes échangées → 1" "$(verify "$TMP/env.bad" --key "$TMP/appliance.pem")" 1
# Signature d'un autre rapport.
jq -c '.tag = "v9.9.9"' "$TMP/report.json" > "$TMP/x.json"; canon "$TMP/x.json" > "$TMP/other.canon"
sign "deuxième rapport signé → OK" OK "$TMP/other.canon" "$SCAN"
envelope "$TMP/report.canon" "$(jq -r .output.signature "$RES")" "$FP" > "$TMP/env.bad"
expect "signature d'un autre rapport → 1" "$(verify "$TMP/env.bad" --key "$TMP/appliance.pem")" 1
# Une autre clé : rapport refusé.
openssl genpkey -algorithm ed25519 -out "$TMP/other.key" 2> /dev/null
openssl pkey -in "$TMP/other.key" -pubout -out "$TMP/other.pem"
expect "autre clé → 1" "$(verify "$TMP/env.json" --key "$TMP/other.pem")" 1
# Signé par une autre clé qui se déclare comme celle de l'appliance.
openssl pkeyutl -sign -inkey "$TMP/other.key" -rawin -in "$TMP/report.canon" -out "$TMP/other.sig"
envelope "$TMP/report.canon" "$(openssl base64 -A -in "$TMP/other.sig")" "$FP" > "$TMP/env.bad"
expect "signature d'une autre clé, empreinte usurpée → 1" "$(verify "$TMP/env.bad" --key "$TMP/appliance.pem")" 1
# Enveloppe piégée : champ en double, plusieurs lignes, schéma inconnu.
sed 's/^{/{"signature":"AAAA",/' "$TMP/env.json" > "$TMP/env.bad"
expect "champ en double → 1" "$(verify "$TMP/env.bad" --key "$TMP/appliance.pem")" 1
{ cat "$TMP/env.json"; cat "$TMP/env.json"; } > "$TMP/env.bad"
expect "enveloppe sur plusieurs lignes → 1" "$(verify "$TMP/env.bad" --key "$TMP/appliance.pem")" 1
sed 's#scanoria-signed-release-report/1#scanoria-signed-release-report/2#' "$TMP/env.json" > "$TMP/env.bad"
expect "schéma d'enveloppe inconnu → 1" "$(verify "$TMP/env.bad" --key "$TMP/appliance.pem")" 1
# Rapport signé qui porte deux commits : refusé (le helper ne le signerait pas, mais la clé d'un tiers oui).
python3 - "$TMP/report.canon" "$TMP/x.two" <<-'EOF'
	import sys
	raw = open(sys.argv[1], "rb").read()
	open(sys.argv[2], "wb").write(raw.replace(b'"comparison":null', b'"comparison":{"commit_sha":"' + b"1" * 40 + b'"}'))
EOF
openssl pkeyutl -sign -inkey "$TMP/other.key" -rawin -in "$TMP/x.two" -out "$TMP/x.two.sig"
envelope "$TMP/x.two" "$(openssl base64 -A -in "$TMP/x.two.sig")" "$(openssl pkey -pubin -in "$TMP/other.pem" -outform DER | tail -c 32 | openssl dgst -sha256 -r | cut -c1-64)" > "$TMP/env.bad"
expect "commit ambigu → 1" "$(verify "$TMP/env.bad" --key "$TMP/other.pem")" 1
# Verdict défavorable et --require-passed.
jq -c '.verdict.value = "failed"' "$TMP/report.json" > "$TMP/x.json"; canon "$TMP/x.json" > "$TMP/failed.canon"
sign "rapport défavorable signé → OK" OK "$TMP/failed.canon" "$SCAN"
envelope "$TMP/failed.canon" "$(jq -r .output.signature "$RES")" "$FP" > "$TMP/env.failed"
expect "verdict défavorable sans --require-passed → 0" "$(verify "$TMP/env.failed" --key "$TMP/appliance.pem")" 0
expect "verdict défavorable avec --require-passed → 4" "$(verify "$TMP/env.failed" --key "$TMP/appliance.pem" --require-passed)" 4
# Utilisation.
expect "--fetch-key sans --key-fingerprint → 3" "$(verify "$TMP/env.json" --fetch-key https://analyse.exemple.test/api/system/appliance-key)" 3
expect "--fetch-key en http:// → 3" "$(verify "$TMP/env.json" --fetch-key "http""://analyse.exemple.test/k" --key-fingerprint "$FP")" 3
expect "sans clé → 3" "$(verify "$TMP/env.json")" 3
expect "clé qui n'est pas Ed25519 → 3" "$(openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 2> /dev/null | openssl pkey -pubout > "$TMP/ec.pem"; verify "$TMP/env.json" --key "$TMP/ec.pem")" 3
expect "rapport absent → 3" "$(verify "$TMP/absent.json" --key "$TMP/appliance.pem")" 3
expect "attestation sans scanoria-verify-attestation → 3" "$(cp "$VERIFY" "$TMP/sv"; sh "$TMP/sv" attestation x > /dev/null 2>&1; echo $?)" 3
if command -v dash > /dev/null; then
	expect "sh POSIX strict (dash) → 0" "$(dash "$VERIFY" "$TMP/env.json" --key "$TMP/appliance.pem" --quiet > /dev/null 2>&1; echo $?)" 0
fi

# === 4. Forme canonique stable ===================================================
python3 - "$TMP/report.json" > "$TMP/canon2" <<-'EOF'
	import json, sys
	d = json.load(open(sys.argv[1]))
	def rebuild(v):
	    if isinstance(v, dict):
	        return {k: rebuild(v[k]) for k in sorted(v, reverse=True)}
	    if isinstance(v, list):
	        return [rebuild(x) for x in v]
	    return v
	sys.path.insert(0, sys.argv[0].rsplit("/", 1)[0])
	sys.stdout.buffer.write(json.dumps(rebuild(d), sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode())
EOF
expect "ordre d'insertion sans effet" "$(sha "$TMP/canon2")" "$(sha "$TMP/report.canon")"
expect "canonical_bytes du helper identique" "$(python3 -c 'import json, sys, hashlib; sys.path.insert(0, sys.argv[2]); from scanoria import release; print(hashlib.sha256(release.canonical_bytes(json.load(open(sys.argv[1])))).hexdigest())' "$TMP/report.json" "$ROOT/src/rootfs/usr/lib/scanoria/py")" "$(sha "$TMP/report.canon")"
grep -q 'Démo é' "$TMP/report.canon" && ok "UTF-8 non échappé (comme canonical.ts)" || ko "UTF-8 non échappé"

echo
echo "b37-release : $PASS réussis, $FAIL échoués"
[[ "$FAIL" -eq 0 ]]
