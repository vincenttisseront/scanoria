#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Vincent Tisseront
#
# Cohérences du dépôt vérifiées à chaque CI :
#   - VERSION = webui/VERSION = version de webui/package.json, format X.Y.Z ;
#   - CHANGELOG.md contient une section « ## X.Y.Z » non vide ;
#   - update-pubkey.pem est une clé publique Ed25519 dont l'empreinte (DER)
#     est celle épinglée dans src/iso/build.env ;
#   - aucune clé privée suivie par git (en-tête suivi d'un corps base64) ;
#   - toutes les actions des workflows sont épinglées par SHA de 40 caractères.
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$root"
fail=0
ko() { echo "check-repo: ERREUR : $*" >&2; fail=1; }

v=$(tr -d '[:space:]' < VERSION)
[[ "$v" =~ ^(0|[1-9][0-9]{0,3})\.(0|[1-9][0-9]{0,3})\.(0|[1-9][0-9]{0,3})$ ]] || ko "VERSION invalide : $v"
[[ "$(tr -d '[:space:]' < webui/VERSION)" == "$v" ]] || ko "webui/VERSION ≠ VERSION ($v)"
pv=$(jq -r .version webui/package.json)
[[ "$pv" == "$v" ]] || ko "webui/package.json ($pv) ≠ VERSION ($v)"

section=$(awk -v v="$v" '/^## / { if (inside) exit; if ($2 == v) { inside = 1; next } } inside && NF { n++ } END { print n + 0 }' CHANGELOG.md)
[[ "$section" -gt 0 ]] || ko "CHANGELOG.md : section « ## $v » absente ou vide"

pinned=$(sed -n 's/^UPDATE_PUBKEY_SHA256=\([0-9a-f]\{64\}\)$/\1/p' src/iso/build.env)
if ! openssl pkey -pubin -in update-pubkey.pem -noout -text 2>/dev/null | grep -q '^ED25519 Public-Key'; then
	ko "update-pubkey.pem n'est pas une clé publique Ed25519"
else
	got=$(openssl pkey -pubin -in update-pubkey.pem -outform DER | sha256sum | cut -d' ' -f1)
	[[ -n "$pinned" && "$got" == "$pinned" ]] || ko "empreinte de update-pubkey.pem ($got) ≠ build.env ($pinned)"
fi

# Même motif strict que build.sh et b21 : un en-tête suivi d'un vrai corps
# base64 (au moins 40 caractères sur la ligne suivante). Les en-têtes seuls
# (données d'essai, texte d'aide de la console) ne sont pas des clés.
if git ls-files -z | python3 -I -B -c '
import re, sys
pat = re.compile(rb"-----BEGIN ([A-Z0-9]+ )*PRIVATE KEY-----\r?\n[A-Za-z0-9+/=]{40,}")
found = 0
for name in sys.stdin.buffer.read().split(b"\0"):
    if not name:
        continue
    try:
        with open(name, "rb") as f:
            data = f.read()
    except (IsADirectoryError, FileNotFoundError):
        continue
    if pat.search(data):
        print(name.decode("utf-8", "replace"))
        found = 1
sys.exit(found)
'; then :; else
	ko "clé privée suivie par git (fichiers ci-dessus)"
fi

while IFS= read -r line; do
	ko "action non épinglée par SHA : $line"
done < <(grep -rhoE '^[[:space:]-]*uses:[[:space:]]*[^[:space:]#]+' .github/workflows \
	| sed -E 's/^[[:space:]-]*uses:[[:space:]]*//' \
	| grep -vE '^\./' | grep -vE '@[0-9a-f]{40}$' || true)

[[ "$fail" -eq 0 ]] || exit 1
echo "check-repo: OK (version $v)"
