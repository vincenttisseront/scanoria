#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Vincent Tisseront
#
# Construction de l'appliance Scanoria, toujours dans un conteneur
# ubuntu:24.04 neuf (docker ou podman), jamais sur la machine hôte.
#
#   ./build.sh --stage   arborescence du lot dans out/stage/scanoria-X.Y.Z/
#   ./build.sh --bundle  lot de mise à jour : out/scanoria-X.Y.Z.tar.zst,
#                        out/release.json, out/SHA256SUMS (NON signé : la
#                        signature SHA256SUMS.sig est faite par la CI)
#   ./build.sh --iso     lot + ISO d'installation : out/scanoria-X.Y.Z-amd64.iso
#
# Options :
#   --repo PROPRIÉTAIRE/DÉPÔT  source des mises à jour (update-source.json) ;
#                              défaut : $GITHUB_REPOSITORY, puis le dépôt GitHub
#                              du remote « origin »
#   --out RÉPERTOIRE           sortie (défaut : out/ à la racine du dépôt)
#   --engine docker|podman     moteur de conteneurs (défaut : détecté)
#   -h, --help                 cette aide
#
# Variables : BUILD_IMAGE (image de construction, défaut dans src/iso/build.env),
# SOURCE_DATE_EPOCH (défaut : date du dernier commit), SCANORIA_COMMIT
# (défaut : git rev-parse HEAD), SCANORIA_REUSE_BUNDLE=1 (--iso seulement :
# reprend le lot déjà présent dans la sortie, SHA256SUMS[.sig] compris, au lieu
# de le reconstruire).
#
# Usage interne : --in-container (appelé par ce script ou make-iso.ps1 dans le
# conteneur). Le fichier peut aussi être « sourcé » par les tests : seules les
# fonctions sont alors définies.
set -euo pipefail

SCANORIA_ROOT_DEFAULT=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

# Préfixes que rootfs/ a le droit de contenir (ARCHITECTURE § 3.3).
readonly ROOTFS_ALLOWED_RE='^usr/(sbin/scanoria-[a-z0-9][a-z0-9-]*|lib/scanoria/.+|share/scanoria/.+|lib/systemd/system/scanoria-[A-Za-z0-9@._-]+|lib/sysusers\.d/scanoria\.conf|lib/tmpfiles\.d/scanoria\.conf)$'
readonly ROOTFS_DIRS_RE='^(usr|usr/sbin|usr/lib|usr/share|usr/lib/systemd|usr/lib/systemd/system|usr/lib/sysusers\.d|usr/lib/tmpfiles\.d|usr/lib/scanoria(/.+)?|usr/share/scanoria(/.+)?)$'
readonly SEMVER_RE='^(0|[1-9][0-9]{0,3})\.(0|[1-9][0-9]{0,3})\.(0|[1-9][0-9]{0,3})$'
readonly REPO_RE='^[A-Za-z0-9-]{1,39}/[A-Za-z0-9._-]{1,100}$'

log() { printf '\033[1m[build]\033[0m %s\n' "$*" >&2; }
die() { printf '\033[1;31m[build] ERREUR :\033[0m %s\n' "$*" >&2; exit 1; }

usage() { sed -n '4,30p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; }

# Lit une variable KEY=VALEUR d'un fichier .env sans l'exécuter.
env_get() { # fichier clé
	local v
	v=$(sed -n "s/^$2=\\(.*\\)\$/\\1/p" "$1" | tail -n 1)
	[[ -n "$v" ]] || die "$2 absent de $1"
	printf '%s' "$v"
}

# --------------------------------------------------------------------------
# Fonctions pures (testées sans root par tests/b20-iso-static.sh)
# --------------------------------------------------------------------------

# Vérifie un ISO téléchargé : la ligne de SHA256SUMS et le fichier doivent tous
# deux correspondre à l'empreinte épinglée.
verify_iso_checksum() { # iso sha256sums nom empreinte_épinglée
	local iso=$1 sums=$2 name=$3 pinned=$4 listed actual
	[[ "$pinned" =~ ^[0-9a-f]{64}$ ]] || { log "empreinte épinglée invalide"; return 1; }
	[[ -f "$iso" ]] || { log "ISO absente : $iso"; return 1; }
	listed=$(awk -v n="$name" '{f=$2; sub(/^\*/, "", f)} f == n && NF == 2 {print $1}' "$sums")
	if [[ $(printf '%s' "$listed" | grep -c '') -ne 1 ]]; then
		log "SHA256SUMS ne contient pas exactement une ligne pour $name"
		return 1
	fi
	if [[ "$listed" != "$pinned" ]]; then
		log "SHA256SUMS ($listed) ≠ empreinte épinglée ($pinned)"
		return 1
	fi
	actual=$(sha256sum "$iso" | cut -d' ' -f1)
	if [[ "$actual" != "$pinned" ]]; then
		log "empreinte de l'ISO ($actual) ≠ empreinte épinglée ($pinned)"
		return 1
	fi
}

# Vérifie la signature GPG de SHA256SUMS avec la clé versionnée, dont
# l'empreinte doit être celle épinglée.
verify_sums_signature() { # sums sums.gpg clé.asc empreinte
	local sums=$1 sig=$2 key=$3 fpr=$4 tmp got
	tmp=$(mktemp -d)
	GNUPGHOME="$tmp" gpg --batch --quiet --import "$key" 2>/dev/null
	got=$(GNUPGHOME="$tmp" gpg --batch --with-colons --fingerprint 2>/dev/null \
		| awk -F: '$1 == "fpr" {print $10; exit}')
	if [[ "$got" != "$fpr" ]]; then
		rm -rf "$tmp"
		log "clé GPG inattendue ($got ≠ $fpr)"
		return 1
	fi
	GNUPGHOME="$tmp" gpg --batch --quiet --export "$fpr" > "$tmp/keyring.gpg"
	if ! gpgv --quiet --keyring "$tmp/keyring.gpg" "$sig" "$sums" 2>/dev/null; then
		rm -rf "$tmp"
		log "signature GPG de SHA256SUMS invalide"
		return 1
	fi
	rm -rf "$tmp"
}

# Section d'une version dans CHANGELOG.md (sans la ligne de titre).
changelog_section() { # CHANGELOG.md version
	awk -v v="$2" '
		/^## / { if (inside) exit; if ($2 == v) { inside = 1; next } }
		inside { print }
	' "$1" | sed -e :a -e '/^\n*$/{$d;N;ba' -e '}' | sed '/./,$!d'
}

# Refuse tout fichier qui ressemble à une clé privée ou à un conteneur de clés.
check_no_private_keys() { # répertoire
	local found
	found=$(find "$1" -type f \( -name '*.key' -o -name '*.key.*' -o -name 'signing.*' \
		-o -name '*.p12' -o -name '*.pfx' -o -name '.env' -o -name '.env.*' \) -print)
	if [[ -n "$found" ]]; then
		log "fichier de clé ou de secret refusé : $found"
		return 1
	fi
	found=$(find "$1" -type f -size -4M -print0 | xargs -0 -r python3 -I -c '
import re, sys
pat = re.compile(rb"-----BEGIN ([A-Z0-9]+ )*PRIVATE KEY-----\r?\n[A-Za-z0-9+/=]{40,}")
for p in sys.argv[1:]:
    with open(p, "rb") as f:
        if pat.search(f.read()):
            print(p)
')
	if [[ -n "$found" ]]; then
		log "clé privée trouvée : $found"
		return 1
	fi
}

# Contrôle rootfs/ : fichiers réguliers et répertoires seulement, sous les
# préfixes autorisés, noms simples, aucun lien physique multiple.
validate_rootfs() { # répertoire rootfs
	local root=$1 bad=0 rel type
	[[ -d "$root" ]] || { log "rootfs absent : $root"; return 1; }
	while IFS= read -r -d '' p; do
		rel=${p#"$root"/}
		[[ "$p" == "$root" ]] && continue
		if [[ ! "$rel" =~ ^[A-Za-z0-9._@+/-]+$ || "$rel" == *..* || "$rel" == */./* ]]; then
			log "rootfs : nom refusé : $rel"; bad=1; continue
		fi
		type=$(stat -c '%F' "$p")
		case "$type" in
			directory)
				[[ "$rel" =~ $ROOTFS_DIRS_RE ]] || { log "rootfs : répertoire hors préfixes : $rel"; bad=1; } ;;
			'regular file'|'regular empty file')
				[[ "$rel" =~ $ROOTFS_ALLOWED_RE ]] || { log "rootfs : fichier hors préfixes : $rel"; bad=1; }
				[[ $(stat -c '%h' "$p") -eq 1 ]] || { log "rootfs : lien physique refusé : $rel"; bad=1; } ;;
			*)
				log "rootfs : type refusé ($type) : $rel"; bad=1 ;;
		esac
	done < <(find "$root" -print0)
	return "$bad"
}

# Droits normalisés : répertoires 0755, fichiers 0644, exécutables 0755.
normalize_modes() { # répertoire
	find "$1" -type d -exec chmod 0755 {} +
	find "$1" -type f -perm /111 -exec chmod 0755 {} +
	find "$1" -type f ! -perm /111 -exec chmod 0644 {} +
}

# Assemble l'arborescence du lot (ARCHITECTURE § 6.3).
#   srcroot      racine du dépôt (VERSION, LICENSE, CHANGELOG.md, src/rootfs…)
#   webui_output sortie Nitro (.output : server/index.mjs, public/, nitro.json)
#   dest         répertoire parent (le lot est créé dans dest/scanoria-X.Y.Z)
assemble_stage() { # srcroot webui_output dest repo
	local src=$1 output=$2 dest=$3 repo=$4 version stage migrate f
	version=$(tr -d '[:space:]' < "$src/VERSION")
	[[ "$version" =~ $SEMVER_RE ]] || { log "VERSION invalide : $version"; return 1; }
	[[ "$(tr -d '[:space:]' < "$src/webui/VERSION")" == "$version" ]] \
		|| { log "webui/VERSION ≠ VERSION"; return 1; }
	[[ "$repo" =~ $REPO_RE ]] || { log "dépôt invalide : $repo"; return 1; }
	[[ -f "$output/server/index.mjs" ]] || { log "sortie de la console absente : $output/server/index.mjs"; return 1; }
	if [[ -f "$output/migrate.mjs" ]]; then
		migrate="$output/migrate.mjs"
	elif [[ -f "$src/webui/migrate.mjs" ]]; then
		migrate="$src/webui/migrate.mjs"
	else
		log "webui/migrate.mjs absent"; return 1
	fi
	compgen -G "$src/webui/server/db/migrations/[0-9][0-9][0-9]_*.sql" > /dev/null \
		|| { log "aucune migration dans webui/server/db/migrations"; return 1; }

	stage="$dest/scanoria-$version"
	rm -rf "$stage"
	mkdir -p "$stage/webui/migrations" "$stage/rootfs"
	printf '%s\n' "$version" > "$stage/VERSION"
	for f in LICENSE CHANGELOG.md; do
		[[ -f "$src/$f" ]] || { log "$f absent"; return 1; }
		cp "$src/$f" "$stage/$f"
	done
	if [[ -f "$src/OPEN-SOURCE.md" ]]; then
		cp "$src/OPEN-SOURCE.md" "$stage/OPEN-SOURCE.md"
	else
		log "AVERTISSEMENT : OPEN-SOURCE.md absent du dépôt, absent du lot"
	fi
	# Console : copie sans lien symbolique (cp -L déréférence, find vérifie).
	cp -RL "$output/." "$stage/webui/"
	rm -f "$stage/webui/migrate.mjs"
	cp "$migrate" "$stage/webui/migrate.mjs"
	printf '%s\n' "$version" > "$stage/webui/VERSION"
	cp "$src"/webui/server/db/migrations/[0-9][0-9][0-9]_*.sql "$stage/webui/migrations/"

	# Système : copie de src/rootfs, contrôlée avant tout ajout.
	cp -R --no-dereference "$src/src/rootfs/." "$stage/rootfs/"
	validate_rootfs "$stage/rootfs" || return 1
	mkdir -p "$stage/rootfs/usr/share/scanoria"
	jq -n --arg repo "$repo" '{repo: $repo}' > "$stage/rootfs/usr/share/scanoria/update-source.json"
	if [[ -f "$stage/webui/console.cdx.json" ]]; then
		mkdir -p "$stage/rootfs/usr/share/scanoria/sbom"
		mv "$stage/webui/console.cdx.json" "$stage/rootfs/usr/share/scanoria/sbom/console.cdx.json"
	fi
	# Liste des fichiers déployés (chemins absolus sur l'appliance), MANIFEST compris.
	(
		cd "$stage/rootfs"
		{ find . -type f ! -path ./usr/share/scanoria/MANIFEST -printf '/%P\n'
		  echo /usr/share/scanoria/MANIFEST; } | LC_ALL=C sort
	) > "$stage/MANIFEST.tmp"
	mv "$stage/MANIFEST.tmp" "$stage/rootfs/usr/share/scanoria/MANIFEST"
	validate_rootfs "$stage/rootfs" || return 1

	if [[ -n "$(find "$stage" -type l -print -quit)" ]] \
		|| [[ -n "$(find "$stage" ! -type f ! -type d -print -quit)" ]]; then
		log "lien ou fichier spécial dans le lot"; return 1
	fi
	check_no_private_keys "$stage" || return 1
	normalize_modes "$stage"
	printf '%s\n' "$stage"
}

# Archive du lot + release.json + SHA256SUMS (non signé).
make_bundle() { # stage_dir outdir commit epoch min_upgrade_from node_major
	local stage=$1 out=$2 commit=$3 epoch=$4 min_from=$5 node_major=$6
	local version name archive size sha notes built
	name=$(basename "$stage")
	version=${name#scanoria-}
	[[ "$version" =~ $SEMVER_RE ]] || { log "lot mal nommé : $name"; return 1; }
	[[ "$commit" =~ ^[0-9a-f]{40}$ ]] || { log "commit invalide : $commit"; return 1; }
	[[ "$epoch" =~ ^[0-9]+$ ]] || { log "SOURCE_DATE_EPOCH invalide"; return 1; }
	[[ "$min_from" =~ $SEMVER_RE ]] || { log "MIN_UPGRADE_FROM invalide"; return 1; }
	[[ "$node_major" =~ ^[0-9]+$ && "$node_major" -ge 22 ]] || { log "node_major invalide"; return 1; }
	if [[ "$(printf '%s\n%s\n' "$min_from" "$version" | sort -V | head -n 1)" != "$min_from" ]]; then
		log "MIN_UPGRADE_FROM ($min_from) > version ($version)"; return 1
	fi
	mkdir -p "$out"
	archive="scanoria-$version.tar.zst"
	rm -f "$out/$archive" "$out/release.json" "$out/SHA256SUMS" "$out/SHA256SUMS.sig"
	LC_ALL=C tar --sort=name --format=gnu --mtime="@$epoch" \
		--owner=0 --group=0 --numeric-owner --no-acls --no-xattrs --no-selinux \
		-C "$(dirname "$stage")" -cf - "$name" \
		| zstd -q -19 -T1 -o "$out/$archive"
	size=$(stat -c '%s' "$out/$archive")
	[[ "$size" -le 1073741824 ]] || { log "archive > 1 Gio"; return 1; }
	sha=$(sha256sum "$out/$archive" | cut -d' ' -f1)
	notes=$(changelog_section "$stage/CHANGELOG.md" "$version")
	[[ -n "$notes" ]] || { log "aucune section $version dans CHANGELOG.md"; return 1; }
	[[ ${#notes} -le 65536 ]] || { log "section du CHANGELOG > 65536 caractères"; return 1; }
	built=$(date -u -d "@$epoch" +%Y-%m-%dT%H:%M:%SZ)
	jq -n --arg release "$version" --arg commit "$commit" --arg built "$built" \
		--arg archive "$archive" --arg sha "$sha" --argjson size "$size" \
		--arg min "$min_from" --argjson node "$node_major" --arg notes "$notes" \
		'{version: 1, name: "scanoria", release: $release, tag: ("v" + $release),
		  commit: $commit, built_at: $built, archive: $archive,
		  archive_sha256: $sha, archive_size: $size, min_upgrade_from: $min,
		  node_major: $node, notes_md: $notes}' > "$out/release.json"
	(cd "$out" && sha256sum release.json "$archive" > SHA256SUMS)
	log "lot : $out/$archive ($size octets), release.json, SHA256SUMS (non signé)"
}

# --------------------------------------------------------------------------
# Étapes exécutées dans le conteneur
# --------------------------------------------------------------------------

apt_install() {
	DEBIAN_FRONTEND=noninteractive apt-get install -y -q --no-install-recommends "$@" > /dev/null
}

fetch() { # url fichier
	curl --fail --location --silent --show-error --proto '=https' --tlsv1.2 \
		--retry 3 --retry-delay 5 -o "$2.part" "$1"
	mv -f "$2.part" "$2"
}

install_node() { # src cache
	local env="$1/src/iso/node-release.env" version tarball base sha listed
	version=$(env_get "$env" NODE_VERSION)
	tarball=$(env_get "$env" NODE_TARBALL)
	base=$(env_get "$env" NODE_BASE_URL)
	sha=$(env_get "$env" NODE_SHA256)
	mkdir -p "$2/node"
	fetch "$base/SHASUMS256.txt" "$2/node/SHASUMS256.txt"
	listed=$(awk -v n="$tarball" '$2 == n {print $1}' "$2/node/SHASUMS256.txt")
	[[ "$listed" == "$sha" ]] || die "Node : SHASUMS256.txt ($listed) ≠ empreinte épinglée ($sha)"
	if [[ ! -f "$2/node/$tarball" ]] || [[ "$(sha256sum "$2/node/$tarball" | cut -d' ' -f1)" != "$sha" ]]; then
		log "téléchargement de Node.js $version"
		fetch "$base/$tarball" "$2/node/$tarball"
	fi
	[[ "$(sha256sum "$2/node/$tarball" | cut -d' ' -f1)" == "$sha" ]] || die "Node : empreinte du fichier invalide"
	rm -rf /opt/node && mkdir -p /opt/node
	tar -xJf "$2/node/$tarball" -C /opt/node --strip-components=1 --no-same-owner
	export PATH="/opt/node/bin:$PATH"
	[[ "$(node --version)" == "v$version" ]] || die "Node : version inattendue"
}

build_webui() { # work
	log "construction de la console (npm ci, npm run build)"
	[[ -f "$1/webui/package.json" ]] || die "webui/package.json absent"
	(
		cd "$1/webui"
		# Sans scripts d'installation des dépendances ; préparation Nuxt explicite.
		npm ci --ignore-scripts --no-audit --no-fund --loglevel=error
		npm run postinstall
		npm run build
	)
	[[ -f "$1/webui/.output/server/index.mjs" ]] || die "la construction n'a pas produit webui/.output"
}

# F19 (0.6) : SBOM CycloneDX de la console (dépendances de production, lues
# dans package-lock.json), livré dans le lot signé sous
# /usr/share/scanoria/sbom/console.cdx.json. Rendu déterministe : horodatage
# = SOURCE_DATE_EPOCH, numéro de série dérivé du contenu. Un échec n'arrête
# pas la construction : l'appliance signale alors un trou de couverture.
console_sbom() { # work
	local out="$1/webui/.output/console.cdx.json" raw serial built
	raw=$(cd "$1/webui" && npm sbom --sbom-format=cyclonedx --omit=dev --package-lock-only 2> /dev/null) \
		|| { log "AVERTISSEMENT : SBOM de la console non produit (npm sbom)"; return 0; }
	built=$(date -u -d "@${SOURCE_DATE_EPOCH:-0}" +%Y-%m-%dT%H:%M:%SZ)
	serial=$(jq -cS 'del(.serialNumber, .metadata.timestamp)' <<< "$raw" | sha256sum | cut -c1-32)
	serial="${serial:0:8}-${serial:8:4}-5${serial:13:3}-a${serial:17:3}-${serial:20:12}"
	jq --arg s "urn:uuid:$serial" --arg t "$built" '.serialNumber = $s | .metadata.timestamp = $t' <<< "$raw" > "$out" \
		|| { log "AVERTISSEMENT : SBOM de la console illisible"; rm -f "$out"; }
}

check_pubkey() { # src
	local want got
	want=$(env_get "$1/src/iso/build.env" UPDATE_PUBKEY_SHA256)
	got=$(openssl pkey -pubin -in "$1/update-pubkey.pem" -outform DER | sha256sum | cut -d' ' -f1)
	[[ "$got" == "$want" ]] || die "update-pubkey.pem ($got) ≠ empreinte épinglée ($want)"
	openssl pkey -pubin -in "$1/update-pubkey.pem" -noout -text 2>/dev/null | grep -q 'ED25519' \
		|| die "update-pubkey.pem n'est pas une clé Ed25519"
}

fetch_ubuntu_iso() { # src cache → chemin de l'ISO vérifiée
	local env="$1/src/iso/ubuntu-release.env" name base sha key fpr dir
	name=$(env_get "$env" UBUNTU_ISO_NAME)
	base=$(env_get "$env" UBUNTU_ISO_BASE_URL)
	sha=$(env_get "$env" UBUNTU_ISO_SHA256)
	key="$1/src/iso/$(env_get "$env" UBUNTU_GPG_KEY_FILE)"
	fpr=$(env_get "$env" UBUNTU_GPG_FPR)
	dir="$2/ubuntu"
	mkdir -p "$dir"
	fetch "$base/SHA256SUMS" "$dir/SHA256SUMS"
	fetch "$base/SHA256SUMS.gpg" "$dir/SHA256SUMS.gpg"
	verify_sums_signature "$dir/SHA256SUMS" "$dir/SHA256SUMS.gpg" "$key" "$fpr" \
		|| die "SHA256SUMS officiel non vérifié"
	if ! verify_iso_checksum "$dir/$name" "$dir/SHA256SUMS" "$name" "$sha" 2>/dev/null; then
		log "téléchargement de l'ISO de base ($name)"
		curl --fail --location --silent --show-error --proto '=https' --tlsv1.2 \
			--retry 3 --retry-delay 10 -C - -o "$dir/$name.part" "$base/$name" \
			|| { rm -f "$dir/$name.part"; die "téléchargement de l'ISO impossible"; }
		mv -f "$dir/$name.part" "$dir/$name"
	fi
	verify_iso_checksum "$dir/$name" "$dir/SHA256SUMS" "$name" "$sha" \
		|| { rm -f "$dir/$name"; die "ISO de base non conforme (supprimée)"; }
	printf '%s\n' "$dir/$name"
}

build_pool() { # src pool
	local pool=$2 pkgs closure
	mapfile -t pkgs < <(grep -Ev '^[[:space:]]*(#|$)' "$1/src/iso/packages.list")
	log "dépôt hors ligne : ${pkgs[*]}"
	# Fermeture complète des dépendances (bibliothèques de base comprises), pour
	# que l'installation ne dépende pas des versions présentes sur le support.
	mapfile -t closure < <(apt-cache depends --recurse --no-recommends --no-suggests \
		--no-conflicts --no-breaks --no-replaces --no-enhances "${pkgs[@]}" \
		| grep -E '^[a-z0-9]' | sed 's/:any$//' | LC_ALL=C sort -u)
	rm -rf "$pool" && mkdir -p "$pool"
	chown _apt "$pool" 2>/dev/null || true
	(cd "$pool" && apt-get download -q "${closure[@]}" > /dev/null)
	(
		cd "$pool"
		apt-ftparchive packages . > Packages
		gzip -9n -k Packages
		apt-ftparchive release . > Release
	)
	log "dépôt hors ligne : $(find "$pool" -name '*.deb' | wc -l) paquets, $(du -sh "$pool" | cut -f1)"
}

build_iso() { # src work out cache version bundle_dir
	local src=$1 work=$2 out=$3 cache=$4 version=$5 bundle=$6
	local base_iso overlay env tarball iso_out f
	base_iso=$(fetch_ubuntu_iso "$src" "$cache")
	overlay="$work/overlay"
	rm -rf "$overlay"
	mkdir -p "$overlay/nocloud" "$overlay/boot/grub" "$overlay/scanoria/node" "$overlay/scanoria/bundle"
	for f in "$src"/src/iso/autoinstall/{user-data,meta-data}; do
		cp "$f" "$overlay/nocloud/"
	done
	: > "$overlay/nocloud/vendor-data"
	cp "$src/src/iso/grub/grub.cfg" "$overlay/boot/grub/grub.cfg"
	cp "$src/src/iso/scripts/check-hardware.sh" "$src/src/iso/scripts/late-install.sh" \
		"$src/src/iso/packages.list" "$overlay/scanoria/"
	cp "$src/update-pubkey.pem" "$overlay/scanoria/update-pubkey.pem"
	env="$src/src/iso/node-release.env"
	tarball=$(env_get "$env" NODE_TARBALL)
	cp "$cache/node/$tarball" "$overlay/scanoria/node/"
	cp "$bundle/scanoria-$version.tar.zst" "$bundle/release.json" "$bundle/SHA256SUMS" \
		"$overlay/scanoria/bundle/"
	if [[ -f "$bundle/SHA256SUMS.sig" ]]; then
		cp "$bundle/SHA256SUMS.sig" "$overlay/scanoria/bundle/"
	fi
	printf 'SCANORIA_VERSION=%s\nNODE_TARBALL=%s\n' "$version" "$tarball" > "$overlay/scanoria/iso.env"
	build_pool "$src" "$overlay/scanoria/pool"
	(cd "$overlay/scanoria" && find . -type f -printf '%P\n' \
		| LC_ALL=C sort | xargs -d '\n' sha256sum) > "$work/media.sha256"
	mv "$work/media.sha256" "$overlay/scanoria/SHA256SUMS"
	check_no_private_keys "$overlay" || die "clé privée dans l'ISO"

	# Le noyau et l'initrd référencés par grub.cfg doivent exister.
	for f in /casper/vmlinuz /casper/initrd; do
		xorriso -indev "$base_iso" -find "$f" 2>/dev/null | grep -qx "'$f'" \
			|| die "$f absent de l'ISO de base : adapter src/iso/grub/grub.cfg"
	done
	iso_out="$out/scanoria-$version-amd64.iso"
	rm -f "$iso_out" "$iso_out.sha256"
	log "assemblage de l'ISO (xorriso, amorçage BIOS et UEFI d'origine rejoué)"
	if ! xorriso -abort_on FAILURE -return_with SORRY 32 \
		-indev "$base_iso" -outdev "$iso_out" \
		-map "$overlay/nocloud" /nocloud \
		-map "$overlay/scanoria" /scanoria \
		-map "$overlay/boot/grub/grub.cfg" /boot/grub/grub.cfg \
		-boot_image any replay > "$work/xorriso.log" 2>&1; then
		tail -n 30 "$work/xorriso.log" >&2
		rm -f "$iso_out"
		die "xorriso a échoué"
	fi
	[[ -s "$iso_out" ]] || die "xorriso n'a pas produit l'ISO"
	(cd "$out" && sha256sum "$(basename "$iso_out")" > "$(basename "$iso_out").sha256")
	log "ISO : $iso_out ($(du -h "$iso_out" | cut -f1))"
}

in_container() { # mode
	local mode=$1 src=/src out=/out cache work version stage commit epoch repo min_from node_major
	[[ -f "$src/VERSION" ]] || die "dépôt non monté sur /src"
	cache="$out/cache"
	work=$(mktemp -d /tmp/scanoria-build.XXXXXX)
	mkdir -p "$out" "$cache"
	repo=${SCANORIA_REPO:?SCANORIA_REPO absent}
	commit=${SCANORIA_COMMIT:?SCANORIA_COMMIT absent}
	epoch=${SOURCE_DATE_EPOCH:?SOURCE_DATE_EPOCH absent}
	export SOURCE_DATE_EPOCH

	log "paquets de construction"
	export DEBIAN_FRONTEND=noninteractive
	apt-get update -q > /dev/null
	apt_install ca-certificates curl xz-utils zstd jq python3 openssl gnupg gpgv
	if [[ "$mode" == iso ]]; then
		apt_install xorriso apt-utils
	fi

	check_pubkey "$src"
	# Copie de travail : le dépôt reste en lecture seule.
	mkdir -p "$work/src"
	tar -C "$src" --exclude=./out --exclude=./.git --exclude=./node_modules \
		--exclude=./webui/node_modules --exclude=./webui/.output --exclude=./webui/.nuxt \
		-cf - . | tar -C "$work/src" -xf -
	install_node "$work/src" "$cache"
	version=$(tr -d '[:space:]' < "$work/src/VERSION")
	if [[ "$mode" == iso && "${SCANORIA_REUSE_BUNDLE:-0}" == 1 ]]; then
		# ISO construite autour d'un lot existant (par exemple les actifs signés
		# d'une release), sans le reconstruire.
		(cd "$out" && sha256sum --check --quiet --strict SHA256SUMS) \
			|| die "lot existant de $out non conforme à SHA256SUMS"
		[[ -f "$out/scanoria-$version.tar.zst" ]] || die "scanoria-$version.tar.zst absent de $out"
		log "réutilisation du lot existant $out/scanoria-$version.tar.zst"
		build_iso "$work/src" "$work" "$out" "$cache" "$version" "$out"
	else
		build_webui "$work/src"
		console_sbom "$work/src"
		stage=$(assemble_stage "$work/src" "$work/src/webui/.output" "$work/stage" "$repo") \
			|| die "assemblage du lot refusé"
		if [[ "$mode" == stage ]]; then
			rm -rf "$out/stage" && mkdir -p "$out/stage"
			cp -a "$stage" "$out/stage/"
			log "arborescence : $out/stage/$(basename "$stage")"
		else
			min_from=$(env_get "$work/src/src/iso/build.env" MIN_UPGRADE_FROM)
			node_major=$(env_get "$work/src/src/iso/node-release.env" NODE_VERSION)
			node_major=${node_major%%.*}
			make_bundle "$stage" "$out" "$commit" "$epoch" "$min_from" "$node_major"
			if [[ "$mode" == iso ]]; then
				build_iso "$work/src" "$work" "$out" "$cache" "$version" "$out"
			fi
		fi
	fi
	if [[ -n "${HOST_UID:-}" && -n "${HOST_GID:-}" ]]; then
		chown -R "$HOST_UID:$HOST_GID" "$out"
	fi
	rm -rf "$work"
}

# --------------------------------------------------------------------------
# Lanceur (machine hôte)
# --------------------------------------------------------------------------

detect_repo() { # racine
	local url
	if [[ -n "${GITHUB_REPOSITORY:-}" ]]; then
		printf '%s' "$GITHUB_REPOSITORY"; return
	fi
	url=$(git -C "$1" remote get-url origin 2>/dev/null || true)
	url=${url%.git}
	if [[ "$url" =~ github\.com[:/]([A-Za-z0-9-]+/[A-Za-z0-9._-]+)$ ]]; then
		printf '%s' "${BASH_REMATCH[1]}"
	fi
}

detect_engine() {
	if command -v docker > /dev/null 2>&1 && docker info > /dev/null 2>&1; then
		echo docker
	elif command -v podman > /dev/null 2>&1; then
		echo podman
	else
		die "ni docker ni podman disponible"
	fi
}

main() {
	local mode="" repo="" out="" engine="" inside=0 root image commit epoch
	local -a run_args
	root=$SCANORIA_ROOT_DEFAULT
	while [[ $# -gt 0 ]]; do
		case "$1" in
			--iso|--bundle|--stage)
				[[ -z "$mode" ]] || die "un seul mode à la fois"
				mode=${1#--} ;;
			--repo) repo=${2:?--repo attend une valeur}; shift ;;
			--out) out=${2:?--out attend une valeur}; shift ;;
			--engine) engine=${2:?--engine attend une valeur}; shift ;;
			--in-container) inside=1 ;;
			-h|--help) usage; exit 0 ;;
			*) usage >&2; die "option inconnue : $1" ;;
		esac
		shift
	done
	[[ -n "$mode" ]] || { usage >&2; die "mode attendu : --iso, --bundle ou --stage"; }

	if [[ "$inside" -eq 1 ]]; then
		in_container "$mode"
		return
	fi

	repo=${repo:-$(detect_repo "$root")}
	[[ "$repo" =~ $REPO_RE ]] || die "dépôt source des mises à jour inconnu : --repo PROPRIÉTAIRE/DÉPÔT"
	commit=${SCANORIA_COMMIT:-${GITHUB_SHA:-$(git -C "$root" rev-parse HEAD 2>/dev/null || true)}}
	[[ "$commit" =~ ^[0-9a-f]{40}$ ]] || die "commit inconnu (SCANORIA_COMMIT)"
	if [[ -n "$(git -C "$root" status --porcelain 2>/dev/null || true)" ]]; then
		log "AVERTISSEMENT : copie de travail modifiée ; release.json citera $commit"
	fi
	epoch=${SOURCE_DATE_EPOCH:-$(git -C "$root" log -1 --format=%ct 2>/dev/null || true)}
	[[ "$epoch" =~ ^[0-9]+$ ]] || die "SOURCE_DATE_EPOCH inconnu"
	out=${out:-$root/out}
	mkdir -p "$out"
	out=$(cd "$out" && pwd)
	image=${BUILD_IMAGE:-$(env_get "$root/src/iso/build.env" BUILD_IMAGE)}
	engine=${engine:-$(detect_engine)}
	[[ "$engine" == docker || "$engine" == podman ]] || die "moteur inconnu : $engine"

	run_args=(run --rm --pull=always --security-opt label=disable
		-v "$root:/src:ro" -v "$out:/out"
		-e "SCANORIA_REPO=$repo" -e "SCANORIA_COMMIT=$commit" -e "SOURCE_DATE_EPOCH=$epoch"
		-e "SCANORIA_REUSE_BUNDLE=${SCANORIA_REUSE_BUNDLE:-0}")
	if [[ "$engine" == docker ]]; then
		run_args+=(-e "HOST_UID=$(id -u)" -e "HOST_GID=$(id -g)")
	fi
	if [[ -t 1 ]]; then
		run_args+=(-t)
	fi
	log "$mode : $engine, image $image, dépôt $repo, sortie $out"
	"$engine" "${run_args[@]}" "$image" bash /src/build.sh --in-container "--$mode"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
	main "$@"
fi
