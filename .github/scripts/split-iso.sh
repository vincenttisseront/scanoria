#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Vincent Tisseront
#
# Découpe l'ISO en morceaux de moins de 2 Gio (limite d'un actif de release
# GitHub) et écrit leurs empreintes :
#   split-iso.sh RÉPERTOIRE X.Y.Z
# Produit dans RÉPERTOIRE : scanoria-X.Y.Z-amd64.iso.part00, .part01, … et
# scanoria-X.Y.Z-amd64.iso.SHA256SUMS (ISO entière + chaque morceau), à signer
# ensuite (sign-assets.sh). Taille d'un morceau : ISO_PART_SIZE (défaut 1900M).
set -euo pipefail

die() { echo "split-iso: ERREUR : $*" >&2; exit 1; }
[[ $# -eq 2 ]] || die "usage : split-iso.sh RÉPERTOIRE X.Y.Z"
dir=$1 version=$2
[[ "$version" =~ ^[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4}$ ]] || die "version invalide : $version"
iso="scanoria-$version-amd64.iso"
cd "$dir"
[[ -f "$iso" && ! -L "$iso" ]] || die "$iso absent de $dir"
rm -f "$iso".part[0-9][0-9] "$iso.SHA256SUMS" "$iso.SHA256SUMS.sig"
split -b "${ISO_PART_SIZE:-1900M}" -d -a 2 "$iso" "$iso.part"
mapfile -t parts < <(find . -maxdepth 1 -type f -name "$iso.part[0-9][0-9]" -printf '%f\n' | LC_ALL=C sort)
[[ ${#parts[@]} -ge 1 && ${#parts[@]} -le 99 ]] || die "nombre de morceaux inattendu"
sha256sum "$iso" "${parts[@]}" > "$iso.SHA256SUMS"
echo "split-iso: ${#parts[@]} morceau(x), $iso.SHA256SUMS"
