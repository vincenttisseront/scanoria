#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Vincent Tisseront
#
# Vérifie les actifs d'une release (ARCHITECTURE § 6.2), comme le fera
# l'appliance, avant publication, après publication et avant promotion :
#   verify-release-assets.sh RÉPERTOIRE X.Y.Z CLÉ_PUBLIQUE.pem [--iso] [--no-archive]
#
#  - SHA256SUMS : ≤ 4 Kio, exactement deux lignes « <hex>  release.json » et
#    « <hex>  scanoria-X.Y.Z.tar.zst » ; SHA256SUMS.sig : 64 octets, signature
#    Ed25519 valide pour la clé publique donnée ;
#  - release.json : ≤ 128 Kio, empreinte conforme, champs cohérents (version,
#    tag, archive, taille, empreinte, notes non vides) ;
#  - archive : empreinte conforme (sauf --no-archive : SHA256SUMS seulement) ;
#  - --iso : scanoria-X.Y.Z-amd64.iso.SHA256SUMS signé (.sig), morceaux
#    .partNN présents et conformes, concaténation = empreinte de l'ISO entière.
set -euo pipefail

die() { echo "verify-release-assets: ERREUR : $*" >&2; exit 1; }

[[ $# -ge 3 ]] || die "usage : verify-release-assets.sh RÉPERTOIRE X.Y.Z CLÉ_PUBLIQUE.pem [--iso] [--no-archive]"
dir=$1 version=$2 pub=$3
shift 3
want_iso=0 check_archive=1
for o in "$@"; do
	case "$o" in
		--iso) want_iso=1 ;;
		--no-archive) check_archive=0 ;;
		*) die "option inconnue : $o" ;;
	esac
done
[[ "$version" =~ ^(0|[1-9][0-9]{0,3})\.(0|[1-9][0-9]{0,3})\.(0|[1-9][0-9]{0,3})$ ]] || die "version invalide : $version"
[[ -d "$dir" ]] || die "répertoire absent : $dir"
[[ -f "$pub" ]] || die "clé publique absente : $pub"
openssl pkey -pubin -in "$pub" -noout -text 2>/dev/null | grep -q '^ED25519 Public-Key' \
	|| die "$pub n'est pas une clé publique Ed25519"

archive="scanoria-$version.tar.zst"
esc_version=${version//./\\.}

regular() { [[ -f "$1" && ! -L "$1" ]]; }
size() { stat -c %s "$1"; }

verify_sig() { # fichier
	regular "$1.sig" || die "$(basename "$1").sig absent"
	[[ "$(size "$1.sig")" -eq 64 ]] || die "$(basename "$1").sig : 64 octets attendus"
	openssl pkeyutl -verify -pubin -inkey "$pub" -rawin -in "$1" -sigfile "$1.sig" > /dev/null 2>&1 \
		|| die "signature de $(basename "$1") invalide"
}

# --- SHA256SUMS ---------------------------------------------------------------
sums="$dir/SHA256SUMS"
regular "$sums" || die "SHA256SUMS absent"
[[ "$(size "$sums")" -le 4096 ]] || die "SHA256SUMS > 4 Kio"
verify_sig "$sums"
[[ "$(wc -l < "$sums")" -eq 2 ]] || die "SHA256SUMS : exactement deux lignes attendues"
grep -Eq "^[0-9a-f]{64}  release\\.json\$" "$sums" || die "SHA256SUMS : ligne release.json absente ou mal formée"
grep -Eq "^[0-9a-f]{64}  scanoria-$esc_version\\.tar\\.zst\$" "$sums" || die "SHA256SUMS : ligne $archive absente ou mal formée"
[[ "$(grep -Ec "^[0-9a-f]{64}  (release\\.json|scanoria-$esc_version\\.tar\\.zst)\$" "$sums")" -eq 2 ]] \
	|| die "SHA256SUMS : lignes inattendues"

# --- release.json ---------------------------------------------------------------
rj="$dir/release.json"
regular "$rj" || die "release.json absent"
[[ "$(size "$rj")" -le 131072 ]] || die "release.json > 128 Kio"
want=$(awk '$2 == "release.json" { print $1 }' "$sums")
[[ "$(sha256sum "$rj" | cut -d' ' -f1)" == "$want" ]] || die "empreinte de release.json non conforme"
want_archive=$(awk -v a="$archive" '$2 == a { print $1 }' "$sums")
jq -e --arg v "$version" --arg a "$archive" --arg sha "$want_archive" '
	.version == 1 and .name == "scanoria" and .release == $v and .tag == ("v" + $v)
	and .archive == $a and .archive_sha256 == $sha
	and (.archive_size | type == "number" and . > 0 and . <= 1073741824)
	and (.commit | test("^[0-9a-f]{40}$"))
	and (.built_at | test("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$"))
	and (.min_upgrade_from | test("^[0-9]+\\.[0-9]+\\.[0-9]+$"))
	and (.node_major | type == "number" and . >= 22)
	and (.notes_md | type == "string" and length > 0 and length <= 65536)
' "$rj" > /dev/null || die "release.json : champs incohérents avec la version $version"
min_from=$(jq -r .min_upgrade_from "$rj")
[[ "$(printf '%s\n%s\n' "$min_from" "$version" | sort -V | head -n 1)" == "$min_from" ]] \
	|| die "release.json : min_upgrade_from ($min_from) > $version"

# --- Archive ----------------------------------------------------------------------
if [[ "$check_archive" -eq 1 ]]; then
	regular "$dir/$archive" || die "$archive absent"
	[[ "$(size "$dir/$archive")" -eq "$(jq -r .archive_size "$rj")" ]] || die "$archive : taille ≠ release.json"
	(cd "$dir" && sha256sum --check --strict --quiet SHA256SUMS) || die "empreintes de SHA256SUMS non conformes"
fi

# --- ISO en morceaux ------------------------------------------------------------
if [[ "$want_iso" -eq 1 ]]; then
	iso="scanoria-$version-amd64.iso"
	isums="$dir/$iso.SHA256SUMS"
	regular "$isums" || die "$iso.SHA256SUMS absent"
	[[ "$(size "$isums")" -le 8192 ]] || die "$iso.SHA256SUMS > 8 Kio"
	verify_sig "$isums"
	bad=$(grep -Evc "^[0-9a-f]{64}  scanoria-$esc_version-amd64\\.iso(\\.part[0-9]{2})?\$" "$isums" || true)
	[[ "$bad" -eq 0 ]] || die "$iso.SHA256SUMS : lignes mal formées"
	full=$(awk -v n="$iso" '$2 == n { print $1 }' "$isums")
	[[ "$full" =~ ^[0-9a-f]{64}$ ]] || die "$iso.SHA256SUMS : empreinte de l'ISO entière absente"
	mapfile -t parts < <(awk '$2 ~ /\.part[0-9][0-9]$/ { print $2 }' "$isums" | LC_ALL=C sort)
	[[ ${#parts[@]} -ge 1 ]] || die "$iso.SHA256SUMS : aucun morceau"
	for i in "${!parts[@]}"; do
		[[ "${parts[$i]}" == "$(printf '%s.part%02d' "$iso" "$i")" ]] || die "morceaux non consécutifs"
		regular "$dir/${parts[$i]}" || die "${parts[$i]} absent"
		[[ "$(size "$dir/${parts[$i]}")" -lt 2147483648 ]] || die "${parts[$i]} ≥ 2 Gio"
	done
	(cd "$dir" && grep -E '\.part[0-9]{2}$' "$(basename "$isums")" | sha256sum --check --strict --quiet) \
		|| die "empreintes des morceaux non conformes"
	got=$( (cd "$dir" && cat "${parts[@]}") | sha256sum | cut -d' ' -f1)
	[[ "$got" == "$full" ]] || die "concaténation des morceaux ≠ empreinte de l'ISO"
fi

echo "verify-release-assets: OK ($version$([[ "$want_iso" -eq 1 ]] && echo ', ISO comprise'))"
