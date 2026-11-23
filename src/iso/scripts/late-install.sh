#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Vincent Tisseront
#
# Fin d'installation (autoinstall, late-commands) : lancé dans l'environnement
# de l'installateur, le système installé étant monté sur /target et le support
# sur /cdrom. Étapes :
#   1. contrôle d'intégrité des fichiers ajoutés au support (SHA256SUMS) ;
#   2. paquets de l'appliance depuis le dépôt local du support (hors ligne) ;
#   3. Node.js dans /opt/scanoria/node ;
#   4. clé publique épinglée dans /etc/scanoria/update-pubkey.pem ;
#   5. lot de l'appliance : scanoria-selfupdate install-local ;
#   6. assistant de premier démarrage activé, présentation neutre du système.
# Aucun service n'est démarré ici (chroot) : le premier démarrage s'en charge.
set -euo pipefail

SRC=${SCANORIA_ISO_SRC:-/cdrom/scanoria}
T=${SCANORIA_TARGET:-/target}
LOG="$T/var/log/scanoria-install.log"

log() {
	printf 'scanoria-install: %s\n' "$*"
	printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" >> "$LOG" 2>/dev/null || true
}
die() {
	log "ERREUR / ERROR: $*"
	exit 1
}
# Une erreur imprévue (set -e) nomme sa ligne et sa commande dans le journal.
trap 'log "ERREUR / ERROR: ligne $LINENO : $BASH_COMMAND"' ERR
# Sortie recopiée sur le port série quand il existe : seul journal lisible
# d'une installation automatisée (tests de démarrage, hyperviseurs).
if [[ -w /dev/ttyS0 ]] && stty -F /dev/ttyS0 > /dev/null 2>&1; then
	exec > >(tee -a /dev/ttyS0 2> /dev/null) 2>&1
fi
in_target() {
	curtin in-target --target="$T" -- "$@"
}

[[ -d "$SRC" && -d "$T" ]] || die "support ou cible absent / medium or target missing"
install -d -m 0755 "$T/var/log"
: > "$LOG"
chmod 0600 "$LOG"

# --- 0. Métadonnées du support (écrites par build.sh) ------------------------
[[ -f "$SRC/iso.env" ]] || die "iso.env absent"
SCANORIA_VERSION=$(sed -n 's/^SCANORIA_VERSION=\([0-9.]*\)$/\1/p' "$SRC/iso.env")
NODE_TARBALL=$(sed -n 's/^NODE_TARBALL=\(node-v[0-9.]*-linux-x64\.tar\.xz\)$/\1/p' "$SRC/iso.env")
[[ "$SCANORIA_VERSION" =~ ^[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4}$ ]] || die "SCANORIA_VERSION invalide"
[[ -n "$NODE_TARBALL" ]] || die "NODE_TARBALL invalide"
log "appliance $SCANORIA_VERSION"

# --- 1. Intégrité du support ------------------------------------------------
log "contrôle du support / checking medium"
(cd "$SRC" && sha256sum --check --quiet --strict SHA256SUMS) || die "support corrompu / corrupted medium"

# --- 2. Paquets depuis le dépôt local ---------------------------------------
log "paquets hors ligne / offline packages"
POOL=/var/cache/scanoria/pool
install -d -m 0755 "$T$POOL"
cp -a "$SRC/pool/." "$T$POOL/"
# Liste de sources dédiée : n'altère pas la configuration apt normale. Le dépôt
# local est marqué trusted : chaque paquet a été vérifié par apt (signature de
# l'archive) lors de la construction, et le support est vérifié ci-dessus.
printf 'deb [trusted=yes] file:%s ./\n' "$POOL" > "$T/etc/apt/scanoria-local.list"
APT_OPTS=(-o Dir::Etc::SourceList=/etc/apt/scanoria-local.list
	-o Dir::Etc::SourceParts=- -o APT::Get::List-Cleanup=0)
mapfile -t PACKAGES < <(grep -Ev '^[[:space:]]*(#|$)' "$SRC/packages.list")
for p in "${PACKAGES[@]}"; do
	[[ "$p" =~ ^[a-z0-9][a-z0-9.+-]+$ ]] || die "nom de paquet invalide : $p"
done
in_target apt-get "${APT_OPTS[@]}" update
in_target env DEBIAN_FRONTEND=noninteractive LANG=en_US.UTF-8 LC_ALL=en_US.UTF-8 \
	apt-get "${APT_OPTS[@]}" install -y --no-install-recommends "${PACKAGES[@]}"
rm -f "$T/etc/apt/scanoria-local.list"
rm -rf "${T:?}$POOL"

# PostgreSQL : socket Unix seul (ARCHITECTURE § 4).
PGCONF="$T/etc/postgresql/16/main/conf.d"
[[ -d "$PGCONF" ]] || die "configuration PostgreSQL 16 absente"
printf '%s\n' "# Scanoria : socket Unix seul" "listen_addresses = ''" > "$PGCONF/scanoria.conf"
chmod 0644 "$PGCONF/scanoria.conf"

# --- 3. Node.js --------------------------------------------------------------
log "Node.js"
install -d -m 0755 "$T/opt/scanoria" "$T/opt/scanoria/node"
tar -xJf "$SRC/node/$NODE_TARBALL" -C "$T/opt/scanoria/node" --strip-components=1 \
	--no-same-owner --no-same-permissions
chown -R 0:0 "$T/opt/scanoria/node"
chmod -R go-w "$T/opt/scanoria/node"
in_target /opt/scanoria/node/bin/node --version >> "$LOG"

# --- 4. Clé publique épinglée -----------------------------------------------
log "clé publique / public key"
install -d -m 0750 -o 0 -g 0 "$T/etc/scanoria"
install -m 0644 -o 0 -g 0 "$SRC/update-pubkey.pem" "$T/etc/scanoria/update-pubkey.pem"

# --- 5. Lot de l'appliance ----------------------------------------------------
log "lot de l'appliance / appliance bundle"
B=/var/cache/scanoria/bundle
install -d -m 0700 "$T$B" "$T$B/assets"
cp -a "$SRC/bundle/." "$T$B/assets/"
ARCHIVE="scanoria-$SCANORIA_VERSION.tar.zst"
[[ -f "$T$B/assets/$ARCHIVE" ]] || die "$ARCHIVE absent"
# Le programme d'installation vient du lot lui-même : extraction temporaire,
# puis install-local, qui refait l'extraction contrôlée (règles § 6.3) depuis
# le répertoire des actifs (archive, release.json, SHA256SUMS[, .sig]).
install -d -m 0700 "$T$B/boot"
in_target tar --zstd -xf "$B/assets/$ARCHIVE" -C "$B/boot" --no-same-owner \
	"scanoria-$SCANORIA_VERSION/rootfs"
in_target bash "$B/boot/scanoria-$SCANORIA_VERSION/rootfs/usr/sbin/scanoria-selfupdate" \
	install-local "$B/assets"
[[ -L "$T/opt/scanoria/current" ]] || die "install-local n'a pas créé /opt/scanoria/current"
rm -rf "${T:?}$B"

# --- 6. Premier démarrage et présentation ------------------------------------
log "assistant de premier démarrage / first boot assistant"
[[ -x "$T/usr/sbin/scanoria-firstboot" ]] || die "assistant de premier démarrage absent"
[[ -f "$T/usr/lib/systemd/system/scanoria-firstboot.service" ]] \
	|| die "unité scanoria-firstboot.service absente"
in_target systemctl enable scanoria-firstboot.service

# Le système ne propose jamais de changer de version de base (nouvelle ISO).
if [[ -f "$T/etc/update-manager/release-upgrades" ]]; then
	sed -i 's/^Prompt=.*/Prompt=never/' "$T/etc/update-manager/release-upgrades"
fi
# Présentation : l'appliance, pas la distribution.
printf 'Scanoria appliance %s \\n \\l\n\n' "$SCANORIA_VERSION" > "$T/etc/issue"
printf 'Scanoria appliance %s\n' "$SCANORIA_VERSION" > "$T/etc/issue.net"
if [[ -f "$T/etc/default/motd-news" ]]; then
	sed -i 's/^ENABLED=.*/ENABLED=0/' "$T/etc/default/motd-news"
fi
for f in 10-help-text 50-motd-news 91-release-upgrade; do
	if [[ -f "$T/etc/update-motd.d/$f" ]]; then
		chmod -x "$T/etc/update-motd.d/$f"
	fi
done
install -d -m 0755 "$T/etc/default/grub.d"
printf '%s\n' 'GRUB_DISTRIBUTOR="Scanoria"' > "$T/etc/default/grub.d/90-scanoria.cfg"
in_target update-grub

log "installation terminée / installation complete"
