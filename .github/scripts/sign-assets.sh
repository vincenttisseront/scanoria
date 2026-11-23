#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Vincent Tisseront
#
# Signe des fichiers avec la clé Ed25519 de publication (ARCHITECTURE § 6.2) :
# pour chaque FICHIER, FICHIER.sig = signature brute de 64 octets
# (openssl pkeyutl -sign -rawin). Usage :
#   SIGNING_KEY_PEM="$(…)" sign-assets.sh CLÉ_PUBLIQUE.pem FICHIER…
# La clé privée n'arrive QUE par la variable SIGNING_KEY_PEM (jamais en
# argument) ; elle est écrite le temps de la signature dans un fichier 0600 du
# répertoire temporaire du runner, puis effacée. Avant de signer, le script
# vérifie que la clé privée correspond à la clé publique versionnée ; après,
# il vérifie chaque signature avec cette clé publique.
set -euo pipefail
umask 077

die() { echo "sign-assets: ERREUR : $*" >&2; exit 1; }

[[ $# -ge 2 ]] || die "usage : sign-assets.sh CLÉ_PUBLIQUE.pem FICHIER…"
pub=$1
shift
[[ -n "${SIGNING_KEY_PEM:-}" ]] || die "SIGNING_KEY_PEM vide (secret UPDATE_SIGNING_KEY absent ?)"
[[ -f "$pub" ]] || die "clé publique absente : $pub"

tmp=$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/sign.XXXXXX")
cleanup() {
	if [[ -f "$tmp/signing.key" ]]; then
		shred -u "$tmp/signing.key" 2>/dev/null || rm -f "$tmp/signing.key"
	fi
	rm -rf "$tmp"
}
trap cleanup EXIT
key="$tmp/signing.key"
printf '%s\n' "$SIGNING_KEY_PEM" > "$key"
unset SIGNING_KEY_PEM

openssl pkey -in "$key" -noout -text 2>/dev/null | grep -q '^ED25519 Private-Key' \
	|| die "la clé de signature n'est pas une clé privée Ed25519"
want=$(openssl pkey -pubin -in "$pub" -outform DER | sha256sum | cut -d' ' -f1)
got=$(openssl pkey -in "$key" -pubout -outform DER | sha256sum | cut -d' ' -f1)
[[ "$want" == "$got" ]] || die "la clé de signature ne correspond pas à $pub"

for f in "$@"; do
	[[ -f "$f" && ! -L "$f" ]] || die "fichier à signer absent : $f"
	rm -f "$f.sig"
	openssl pkeyutl -sign -inkey "$key" -rawin -in "$f" -out "$f.sig"
	[[ "$(stat -c %s "$f.sig")" -eq 64 ]] || die "signature de $f : taille inattendue"
	openssl pkeyutl -verify -pubin -inkey "$pub" -rawin -in "$f" -sigfile "$f.sig" > /dev/null \
		|| die "signature de $f non vérifiée par $pub"
	chmod 0644 "$f.sig"
	echo "sign-assets: $(basename "$f").sig (vérifiée avec $(basename "$pub"))"
done
