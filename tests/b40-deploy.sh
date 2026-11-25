#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Vincent Tisseront
#
# b40 — attestations de déploiement (0.8, J9), sans root : demande
# sign-attestation du helper en mode test (SCANORIA_TEST_ROOT) face à des
# déclarations hostiles (forme, JSON non canonique, nombres flottants, sujet
# multiple ou piégé, analyse ou verdict différent, empreinte fausse, taille,
# base64), signature valide vérifiée par openssl avec la clé publique de
# l'appliance, clé privée jamais rendue ; puis scanoria-verify-attestation
# sur une enveloppe (valide, signature d'une autre clé, sujet ou verdict
# changé) et exemples d'admission présents.
# Dépendances : bash, python3, jq, openssl.

# Les motifs jq et les programmes Python sont volontairement entre apostrophes.
# shellcheck disable=SC2016,SC2015
set -euo pipefail
export PYTHONDONTWRITEBYTECODE=1

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
HELPER="$ROOT/src/rootfs/usr/sbin/scanoria-helper"
VERIFY="$ROOT/src/rootfs/usr/share/scanoria/client/scanoria-verify-attestation"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

PASS=0
FAIL=0
ok() { PASS=$((PASS + 1)); printf 'ok   %s\n' "$1"; }
ko() { FAIL=$((FAIL + 1)); printf 'FAIL %s\n' "$1"; }
expect() { # libellé obtenu attendu
	if [[ "$2" == "$3" ]]; then ok "$1"; else ko "$1 (obtenu « $2 », attendu « $3 »)"; fi
}
for t in python3 jq openssl; do command -v "$t" > /dev/null || { echo "outil manquant : $t" >&2; exit 2; }; done

T="$TMP/root"
mkdir -p "$T"/var/lib/scanoria/requests/{tmp,incoming,work,done,failed} "$T/run/scanoria" "$T/etc/scanoria"
chmod 0700 "$T/var/lib/scanoria/requests/incoming" "$T/var/lib/scanoria/requests/work"
echo '{"fqdn": "analyse.exemple.test"}' > "$T/etc/scanoria/appliance.json"
export SCANORIA_TEST_ROOT="$T"

SCAN=0b6f9c2e-1d3a-4c5b-8e7f-9a0b1c2d3e4f
DIGEST=$(printf 'image de test' | sha256sum | cut -d' ' -f1)
PRED=https://github.com/vincenttisseront/scanoria/attestation/release-verdict/v1

# statement [MODIFICATION_PYTHON] : déclaration canonique (sur stdout), éventuellement piégée.
statement() {
	SCAN="$SCAN" DIGEST="$DIGEST" PRED="$PRED" python3 -I -c '
import json, os, sys
st = {"_type": "https://in-toto.io/Statement/v1",
      "subject": [{"name": "registre.exemple.test/valide/app", "digest": {"sha256": os.environ["DIGEST"]}}],
      "predicateType": os.environ["PRED"],
      "predicate": {"scan_id": os.environ["SCAN"], "project_id": "5f0c3a4e-2b1d-4c6e-9f8a-7b6c5d4e3f2a", "verdict": "passed",
                    "commit_sha": "a" * 40, "ref": "refs/tags/v1.2.0", "tag": "v1.2.0", "report_sha256": "c" * 64,
                    "report_url": "https://analyse.exemple.test/scans/" + os.environ["SCAN"], "evaluated_at": "2026-11-25T10:00:00Z"}}
raw = None
exec(sys.argv[1] if len(sys.argv) > 1 else "")
sys.stdout.buffer.write(raw if raw is not None else json.dumps(st, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode())
' "${1:-}"
}
# sign FICHIER [SHA256] [SCAN_ID] : demande sign-attestation ; résultat JSON dans $R
sign() {
	local sum=${2:-$(sha256sum "$1" | cut -d' ' -f1)}
	local params
	params=$(jq -cn --arg s "${3:-$SCAN}" --arg h "$sum" --rawfile c <(base64 -w0 "$1") '{scan_id: $s, kind: "attestation", sha256: $h, content_b64: $c}')
	R=$("$HELPER" exec --origin cli --type sign-attestation --params "$params" 2> "$TMP/helper.err") || true
	[[ -n "$R" ]] || { R='{"code":"NO_OUTPUT"}'; sed 's/^/     /' "$TMP/helper.err"; }
}
code() { jq -r .code <<< "$R"; }
# hostile LIBELLÉ CODE_ATTENDU MODIFICATION_PYTHON
hostile() {
	statement "$3" > "$TMP/st.json"
	sign "$TMP/st.json"
	expect "$1" "$(code)" "$2"
}

# === 1. Signature valide ===========================================================
statement > "$TMP/ok.json"
sign "$TMP/ok.json"
expect "déclaration valide → OK" "$(code)" OK
KEY="$T/etc/scanoria/keys/appliance.ed25519"
expect "clé de l'appliance créée, 0600" "$(stat -c %a "$KEY" 2> /dev/null)" 600
grep -q 'PRIVATE KEY' <<< "$R" && ko "clé privée rendue" || ok "clé privée jamais rendue"
expect "résultat : sujet et type de charge" "$(jq -r '.output | .subject_digest + " " + .payload_type' <<< "$R")" "sha256:$DIGEST application/vnd.in-toto+json"
openssl pkey -in "$KEY" -pubout -out "$TMP/pub.pem" 2> /dev/null
python3 -I -c '
import sys
t = b"application/vnd.in-toto+json"; p = open(sys.argv[1], "rb").read()
sys.stdout.buffer.write(b"DSSEv1 %d %s %d %s" % (len(t), t, len(p), p))' "$TMP/ok.json" > "$TMP/pae"
jq -r .output.signature <<< "$R" | base64 -d > "$TMP/sig"
openssl pkeyutl -verify -pubin -inkey "$TMP/pub.pem" -rawin -in "$TMP/pae" -sigfile "$TMP/sig" > /dev/null 2>&1 \
	&& ok "signature Ed25519 de la PAE DSSE vérifiée par openssl" || ko "signature de la PAE"
FP=$(openssl pkey -pubin -in "$TMP/pub.pem" -outform DER 2> /dev/null | tail -c 32 | sha256sum | cut -d' ' -f1)
expect "empreinte de clé = SHA-256 de la clé publique brute" "$(jq -r .output.key_fingerprint <<< "$R")" "$FP"
jq -n --rawfile p <(base64 -w0 "$TMP/ok.json") --arg s "$(jq -r .output.signature <<< "$R")" --arg k "$FP" \
	'{payloadType: "application/vnd.in-toto+json", payload: $p, signatures: [{keyid: $k, sig: $s}]}' > "$TMP/env.json"

# === 2. Déclarations hostiles ======================================================
hostile "JSON non canonique (espaces)" E_ATTEST_CANONICAL 'raw = json.dumps(st, sort_keys=True, indent=1).encode()'
hostile "JSON non canonique (clés non triées)" E_ATTEST_CANONICAL 'raw = json.dumps(st, separators=(",", ":")).encode()'
hostile "nombre flottant refusé" E_ATTEST_CANONICAL 'st["predicate"]["x"] = 1.5'
hostile "clé en double" E_ATTEST_CANONICAL 'raw = b"{\"_type\":\"a\",\"_type\":\"b\"}"'
hostile "JSON illisible" E_ATTEST_CANONICAL 'raw = b"{pas du json"'
hostile "clé inattendue à la racine" E_ATTEST_STATEMENT 'st["extra"] = 1'
hostile "type de déclaration autre" E_ATTEST_STATEMENT 'st["_type"] = "https://in-toto.io/Statement/v0.1"'
hostile "type de prédicat autre" E_ATTEST_STATEMENT 'st["predicateType"] = "https://slsa.dev/provenance/v1"'
hostile "clé de prédicat inconnue" E_ATTEST_STATEMENT 'st["predicate"]["approved_by"] = "ia"'
hostile "deux sujets" E_ATTEST_SUBJECT 'st["subject"].append(st["subject"][0])'
hostile "sujet sans empreinte sha256" E_ATTEST_SUBJECT 'st["subject"][0]["digest"] = {"sha512": "0" * 128}'
hostile "nom de sujet avec .." E_ATTEST_SUBJECT 'st["subject"][0]["name"] = "registre.exemple.test/../app"'
hostile "nom de sujet avec retour à la ligne" E_ATTEST_SUBJECT 'st["subject"][0]["name"] = "registre.exemple.test/app\nx"'
hostile "analyse différente de la demande" E_ATTEST_SCAN 'st["predicate"]["scan_id"] = "11111111-1111-4111-8111-111111111111"'
hostile "verdict non favorable" E_ATTEST_VERDICT 'st["predicate"]["verdict"] = "failed"'
hostile "verdict non concluant" E_ATTEST_VERDICT 'st["predicate"]["verdict"] = "inconclusive"'
hostile "commit invalide" E_ATTEST_STATEMENT 'st["predicate"]["commit_sha"] = "HEAD"'
hostile "lien de rapport non HTTPS" E_ATTEST_STATEMENT 'st["predicate"]["report_url"] = "javascript:alert(1)"'
hostile "date invalide" E_ATTEST_STATEMENT 'st["predicate"]["evaluated_at"] = "hier"'

sign "$TMP/ok.json" "$(printf '%064d' 0)"
expect "empreinte annoncée fausse" "$(code)" E_ATTEST_DIGEST
sign "$TMP/ok.json" "" "11111111-1111-4111-8111-111111111111"
expect "scan_id de la demande différent" "$(code)" E_ATTEST_SCAN
head -c 70000 /dev/zero | tr '\0' 'a' > "$TMP/big.json"
sign "$TMP/big.json"
[[ "$(code)" == E_* ]] && ok "contenu de plus de 64 Kio refusé ($(code))" || ko "contenu de plus de 64 Kio ($(code))"
R=$("$HELPER" exec --origin cli --type sign-attestation --params "$(jq -cn --arg s "$SCAN" '{scan_id: $s, kind: "attestation", sha256: ("0" * 64), content_b64: "@@@@"}')" 2> /dev/null) || true
[[ "$(code)" == E_* && "$(code)" != OK ]] && ok "base64 invalide refusé ($(code))" || ko "base64 invalide ($(code))"
R=$("$HELPER" exec --origin cli --type sign-attestation --params "$(jq -cn --arg s "$SCAN" '{scan_id: $s, kind: "report", sha256: ("0" * 64), content_b64: "e30="}')" 2> /dev/null) || true
[[ "$(code)" == E_* ]] && ok "kind autre que attestation refusé ($(code))" || ko "kind ($(code))"
R=$("$HELPER" exec --origin cli --type sign-attestation --params "$(jq -cn --arg s "$SCAN" '{scan_id: $s, kind: "attestation", sha256: ("0" * 64), content_b64: "e30=", key: "/etc/shadow"}')" 2> /dev/null) || true
[[ "$(code)" == E_* ]] && ok "paramètre en trop refusé ($(code))" || ko "paramètre en trop ($(code))"

# === 3. scanoria-verify-attestation (enveloppe locale) =============================
out=$("$VERIFY" "registre.exemple.test/valide/app@sha256:$DIGEST" --key "$TMP/pub.pem" --envelope "$TMP/env.json") && rc=0 || rc=$?
expect "vérification : enveloppe valide → 0" "$rc/$(jq -r .verified <<< "$out")/$(jq -r .tag <<< "$out")" "0/true/v1.2.0"
jq -n --rawfile pem "$TMP/pub.pem" '{public_key: "x", fingerprint: "y", pem: $pem}' > "$TMP/appliance-key.json"
"$VERIFY" "registre.exemple.test/valide/app@sha256:$DIGEST" --key "$TMP/appliance-key.json" --envelope "$TMP/env.json" > /dev/null && rc=0 || rc=$?
expect "vérification : clé lue dans la réponse appliance-key" "$rc" 0
openssl genpkey -algorithm ed25519 -out "$TMP/autre.key" 2> /dev/null
openssl pkey -in "$TMP/autre.key" -pubout -out "$TMP/autre.pem" 2> /dev/null
"$VERIFY" "registre.exemple.test/valide/app@sha256:$DIGEST" --key "$TMP/autre.pem" --envelope "$TMP/env.json" > /dev/null && rc=0 || rc=$?
expect "vérification : autre clé → 1" "$rc" 1
"$VERIFY" "registre.exemple.test/valide/app@sha256:$(printf '%064d' 1)" --key "$TMP/pub.pem" --envelope "$TMP/env.json" > /dev/null && rc=0 || rc=$?
expect "vérification : autre image → 1" "$rc" 1
statement 'st["predicate"]["verdict"] = "failed"' > "$TMP/bad.json"
jq --rawfile p <(base64 -w0 "$TMP/bad.json") '.payload = $p' "$TMP/env.json" > "$TMP/env-bad.json"
"$VERIFY" "registre.exemple.test/valide/app@sha256:$DIGEST" --key "$TMP/pub.pem" --envelope "$TMP/env-bad.json" > /dev/null && rc=0 || rc=$?
expect "vérification : charge utile changée après signature → 1" "$rc" 1
"$VERIFY" "registre.exemple.test/../app@sha256:$DIGEST" --key "$TMP/pub.pem" --envelope "$TMP/env.json" > /dev/null 2>&1 && rc=0 || rc=$?
expect "vérification : image piégée → 2" "$rc" 2
"$VERIFY" "registre.exemple.test/valide/app@sha256:$DIGEST" > /dev/null 2>&1 && rc=0 || rc=$?
expect "vérification : sans clé → 2" "$rc" 2

# === 4. Exemples d'admission =======================================================
ADM="$ROOT/docs/exemples/admission"
grep -q "$PRED" "$ADM/scanoria-attestation.yaml" && ok "politique Kyverno : type de prédicat Scanoria" || ko "politique Kyverno : type de prédicat"
grep -q 'BEGIN PUBLIC KEY' "$ADM/scanoria-attestation.yaml" && ok "politique Kyverno : clé publique d'exemple" || ko "politique Kyverno : clé"
grep -h 'image:' "$ADM"/*.yaml | grep -qv '@sha256:[0-9a-f]\{64\}' && ko "exemple d'admission : image non épinglée" || ok "exemples d'admission : images épinglées ou absentes"

printf '\nb40-deploy : %d ok, %d échec(s)\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
