#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Vincent Tisseront
#
# Test de la chaîne de signature et de vérification des releases, avec des
# clés Ed25519 JETABLES générées à l'exécution dans un répertoire temporaire
# (jamais versionnées, jamais la clé de publication) :
#   test-release-chain.sh [RÉPERTOIRE_DU_LOT]
# Sans argument, un faux lot (archive, release.json, SHA256SUMS) est fabriqué ;
# avec un argument, le lot produit par « build.sh --bundle » est copié et
# utilisé. Cas valides puis hostiles (signature, empreintes, lignes en trop,
# mauvaise version, mauvaise clé, ISO en morceaux altérée).
set -euo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
PASS=0 FAIL=0
ok() { PASS=$((PASS + 1)); echo "ok   $1"; }
ko() { FAIL=$((FAIL + 1)); echo "FAIL $1"; }
expect_ok() { local l=$1; shift; if "$@" > "$tmp/log" 2>&1; then ok "$l"; else ko "$l"; sed 's/^/     /' "$tmp/log"; fi; }
expect_ko() { local l=$1; shift; if "$@" > "$tmp/log" 2>&1; then ko "$l (accepté à tort)"; else ok "$l"; fi; }

# --- Clés jetables ----------------------------------------------------------------
openssl genpkey -algorithm ed25519 -out "$tmp/test.key" 2>/dev/null
openssl pkey -in "$tmp/test.key" -pubout -out "$tmp/test.pub"
openssl genpkey -algorithm ed25519 -out "$tmp/other.key" 2>/dev/null
openssl pkey -in "$tmp/other.key" -pubout -out "$tmp/other.pub"
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$tmp/ec.key" 2>/dev/null

# --- Lot ------------------------------------------------------------------------
lot="$tmp/lot"
mkdir -p "$lot"
if [[ $# -ge 1 ]]; then
	src=$1
	version=$(jq -r .release "$src/release.json")
	cp "$src/release.json" "$src/SHA256SUMS" "$src/scanoria-$version.tar.zst" "$lot/"
else
	version=0.0.1
	mkdir -p "$tmp/stage/scanoria-$version"
	echo "$version" > "$tmp/stage/scanoria-$version/VERSION"
	tar -C "$tmp/stage" -cf - "scanoria-$version" | zstd -q -o "$lot/scanoria-$version.tar.zst"
	sha=$(sha256sum "$lot/scanoria-$version.tar.zst" | cut -d' ' -f1)
	size=$(stat -c %s "$lot/scanoria-$version.tar.zst")
	jq -n --arg v "$version" --arg sha "$sha" --argjson size "$size" \
		'{version: 1, name: "scanoria", release: $v, tag: ("v" + $v),
		  commit: "0123456789abcdef0123456789abcdef01234567", built_at: "2026-01-01T00:00:00Z",
		  archive: ("scanoria-" + $v + ".tar.zst"), archive_sha256: $sha, archive_size: $size,
		  min_upgrade_from: "0.0.1", node_major: 22, notes_md: "### Test\n- essai"}' > "$lot/release.json"
	(cd "$lot" && sha256sum release.json "scanoria-$version.tar.zst" > SHA256SUMS)
fi

sign() { # clé fichier…
	local k=$1
	shift
	SIGNING_KEY_PEM=$(cat "$k") bash "$here/sign-assets.sh" "$tmp/test.pub" "$@"
}
verify() { bash "$here/verify-release-assets.sh" "$@"; }
fresh() { # copie de travail du lot signé
	rm -rf "$tmp/w" && cp -a "$lot" "$tmp/w"
}

# --- Cas valides ------------------------------------------------------------------
expect_ok "signature avec la clé jetable" sign "$tmp/test.key" "$lot/SHA256SUMS"
expect_ok "signature brute de 64 octets" test "$(stat -c %s "$lot/SHA256SUMS.sig")" -eq 64
expect_ok "vérification du lot signé" verify "$lot" "$version" "$tmp/test.pub"
expect_ok "vérification sans archive (SHA256SUMS seul)" verify "$lot" "$version" "$tmp/test.pub" --no-archive
expect_ok "vérification par la commande de l'appliance" \
	openssl pkeyutl -verify -pubin -inkey "$tmp/test.pub" -rawin -in "$lot/SHA256SUMS" -sigfile "$lot/SHA256SUMS.sig"

# --- Signature refusée --------------------------------------------------------------
fresh
expect_ko "clé privée ≠ clé publique versionnée" sign "$tmp/other.key" "$tmp/w/SHA256SUMS"
expect_ko "clé non Ed25519" sign "$tmp/ec.key" "$tmp/w/SHA256SUMS"
expect_ko "clé vide" env SIGNING_KEY_PEM= bash "$here/sign-assets.sh" "$tmp/test.pub" "$tmp/w/SHA256SUMS"
# Le secret ne doit jamais rester sur disque.
# Le bash -c reçoit sa commande entre apostrophes : voulu.
# shellcheck disable=SC2016
expect_ok "aucune clé laissée dans le répertoire temporaire" \
	bash -c '! find "${RUNNER_TEMP:-${TMPDIR:-/tmp}}" -maxdepth 2 -name signing.key 2>/dev/null | grep -q .'

# --- Vérification refusée -----------------------------------------------------------
expect_ko "autre clé publique" verify "$lot" "$version" "$tmp/other.pub"
fresh; printf 'x' >> "$tmp/w/SHA256SUMS"
expect_ko "SHA256SUMS modifié après signature" verify "$tmp/w" "$version" "$tmp/test.pub"
fresh; head -c 63 "$lot/SHA256SUMS.sig" > "$tmp/w/SHA256SUMS.sig"
expect_ko "signature tronquée (63 octets)" verify "$tmp/w" "$version" "$tmp/test.pub"
fresh; rm "$tmp/w/SHA256SUMS.sig"
expect_ko "signature absente" verify "$tmp/w" "$version" "$tmp/test.pub"
fresh; printf 'x' >> "$tmp/w/scanoria-$version.tar.zst"
expect_ko "archive modifiée" verify "$tmp/w" "$version" "$tmp/test.pub"
fresh; jq '.notes_md = "modifié"' "$lot/release.json" > "$tmp/w/release.json"
expect_ko "release.json modifié" verify "$tmp/w" "$version" "$tmp/test.pub"
fresh; rm -f "$tmp/w/SHA256SUMS.sig"
echo "0000000000000000000000000000000000000000000000000000000000000000  autre.txt" >> "$tmp/w/SHA256SUMS"
sign "$tmp/test.key" "$tmp/w/SHA256SUMS" > /dev/null
expect_ko "troisième ligne dans SHA256SUMS (même signée)" verify "$tmp/w" "$version" "$tmp/test.pub"
fresh; ln -sf release.json "$tmp/w/lien.json"; rm "$tmp/w/release.json"; ln -s lien.json "$tmp/w/release.json"
expect_ko "release.json en lien symbolique" verify "$tmp/w" "$version" "$tmp/test.pub"
expect_ko "version demandée différente" verify "$lot" "9.9.9" "$tmp/test.pub"
expect_ko "version mal formée" verify "$lot" "1.0" "$tmp/test.pub"

# --- ISO en morceaux --------------------------------------------------------------
iso="scanoria-$version-amd64.iso"
head -c 300000 /dev/urandom > "$lot/$iso"
expect_ok "découpage de l'ISO" env ISO_PART_SIZE=100k bash "$here/split-iso.sh" "$lot" "$version"
expect_ok "trois morceaux" test "$(find "$lot" -name "$iso.part*" | wc -l)" -eq 3
expect_ok "signature des empreintes de l'ISO" sign "$tmp/test.key" "$lot/$iso.SHA256SUMS"
rm "$lot/$iso"
expect_ok "vérification de l'ISO en morceaux (sans l'ISO entière)" verify "$lot" "$version" "$tmp/test.pub" --iso
fresh; printf 'x' >> "$tmp/w/$iso.part01"
expect_ko "morceau modifié" verify "$tmp/w" "$version" "$tmp/test.pub" --iso
fresh; rm "$tmp/w/$iso.part02"
expect_ko "morceau manquant" verify "$tmp/w" "$version" "$tmp/test.pub" --iso
fresh; rm "$tmp/w/$iso.SHA256SUMS.sig"
expect_ko "empreintes de l'ISO non signées" verify "$tmp/w" "$version" "$tmp/test.pub" --iso

echo "test-release-chain: $PASS ok, $FAIL échec(s)"
[[ "$FAIL" -eq 0 ]]
