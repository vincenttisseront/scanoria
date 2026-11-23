#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Vincent Tisseront
#
# Test de démarrage de l'ISO (docs/TESTING.md, « Test de démarrage ») :
#   iso-boot-test.sh ISO RÉPERTOIRE_DE_TRAVAIL
#
# 1. Installation : QEMU/KVM (2 vCPU, 6 Gio, disque virtuel de 48 Go) démarre
#    l'ISO ; l'entrée par défaut lance l'autoinstall, qui éteint la machine à
#    la fin. Délai : ISO_INSTALL_TIMEOUT (défaut 3600 s).
# 2. Premier démarrage sans intervention : la machine redémarre sur le disque
#    avec un fichier de réponses passé par fw_cfg
#    (opt/scanoria/unattended.json), réservé aux hyperviseurs QEMU. L'assistant
#    l'applique et écrit sur le port série (ttyS0) les marqueurs :
#       SCANORIA-SELFTEST-JSON <rapport scanoria-selftest --json en base64, une ligne>
#       SCANORIA-SELFTEST-EXIT <code de sortie>
#       SCANORIA-FIRSTBOOT-END ok|error
#    Délai : ISO_FIRSTBOOT_TIMEOUT (défaut 2400 s).
# 3. Vérifications : code 0 (pass ou warn), rapport JSON lisible, aucune
#    vérification « fail » ; /api/health de la console répond via nginx
#    (port 443 redirigé) avec la version attendue.
#
# Réseau virtuel en plage de documentation RFC 5737 (192.0.2.0/24), nom
# d'exemple analyse.exemple.test. Mots de passe générés à l'exécution, jamais
# affichés ni conservés. Journaux (série, captures d'écran) dans
# RÉPERTOIRE_DE_TRAVAIL/logs, à publier comme artefact.
set -euo pipefail
umask 077

die() {
	echo "::error::iso-boot-test: $*" >&2
	dump_diagnostics
	exit 1
}
# Les artefacts ne sont pas toujours lisibles par qui diagnostique : les fins
# des journaux série et les dernières captures (PNG en base64, une ligne
# chacune, marqueur SCANORIA-SCREENSHOT) vont aussi dans le journal du job.
# Aucun secret à l'écran : les mots de passe ne passent que par fw_cfg.
dump_diagnostics() {
	local f
	for f in "${work:-/nonexistent}"/logs/*-serial.log; do
		[[ -s "$f" ]] || continue
		echo "::group::$(basename "$f") (200 dernières lignes)"
		tail -n 200 "$f" | tr -d '\r' | sed 's/\x1b\[[0-9;?]*[A-Za-z]//g'
		echo "::endgroup::"
	done
	echo "::group::captures d'écran (base64)"
	find "${work:-/nonexistent}/logs" -maxdepth 1 -name '*.png' -printf '%T@ %p\n' 2> /dev/null \
		| sort -n | tail -n 3 | while read -r _ f; do
		echo "SCANORIA-SCREENSHOT $(basename "$f") $(base64 -w0 "$f")"
	done
	echo "::endgroup::"
}
log() { echo "iso-boot-test: $*"; }

[[ $# -eq 2 ]] || die "usage : iso-boot-test.sh ISO RÉPERTOIRE_DE_TRAVAIL"
iso=$(realpath "$1")
work=$2
[[ -f "$iso" ]] || die "ISO absente : $iso"
[[ -c /dev/kvm && -w /dev/kvm ]] || die "/dev/kvm absent ou non accessible"
command -v qemu-system-x86_64 > /dev/null || die "qemu-system-x86_64 absent"
command -v socat > /dev/null || die "socat absent"

version=$(basename "$iso" | sed -n 's/^scanoria-\([0-9]*\.[0-9]*\.[0-9]*\)-amd64\.iso$/\1/p')
[[ -n "$version" ]] || die "nom d'ISO inattendu : $(basename "$iso")"
fqdn=analyse.exemple.test
mkdir -p "$work/logs"
work=$(realpath "$work")
disk="$work/disk.qcow2"
mon="$work/monitor.sock"
answers="$work/unattended.json"
pidfile="$work/qemu.pid"
https_port=${ISO_HTTPS_PORT:-8443}

stop_vm() {
	if vm_running; then
		kill "$(cat "$pidfile")" 2> /dev/null || true
		sleep 2
		kill -9 "$(cat "$pidfile")" 2> /dev/null || true
	fi
	rm -f "$pidfile"
}
cleanup() {
	stop_vm
	rm -f "$answers" "$disk" "$mon"
}
trap cleanup EXIT

vm_running() { [[ -f "$pidfile" ]] && kill -0 "$(cat "$pidfile")" 2> /dev/null; }
monitor() { printf '%s\n' "$1" | socat - "UNIX-CONNECT:$mon" > /dev/null 2>&1 || true; }
screenshot() { # nom
	monitor "screendump $work/logs/$1.ppm"
	sleep 1
	if command -v pnmtopng > /dev/null && [[ -f "$work/logs/$1.ppm" ]]; then
		pnmtopng "$work/logs/$1.ppm" > "$work/logs/$1.png" 2> /dev/null && rm -f "$work/logs/$1.ppm"
	fi
}

# Les virgules appartiennent aux options de QEMU.
# shellcheck disable=SC2054
qemu_base=(qemu-system-x86_64 -name scanoria-test -machine q35,accel=kvm -cpu host
	-smp 2 -m 6144 -display none -vga std
	-drive "file=$disk,if=virtio,format=qcow2,cache=unsafe"
	-netdev "user,id=n0,net=192.0.2.0/24,host=192.0.2.2,dhcpstart=192.0.2.15,dns=192.0.2.3,hostfwd=tcp:127.0.0.1:$https_port-:443"
	-device virtio-net-pci,netdev=n0
	-monitor "unix:$mon,server,nowait"
	-daemonize -pidfile "$pidfile")

wait_vm_exit() { # délai étiquette [journal série à surveiller]
	local deadline=$((SECONDS + $1)) n=0
	while vm_running; do
		# L'installateur en erreur attend une touche : inutile d'attendre le délai.
		if [[ -n "${3:-}" ]] && grep -qE 'An error occurred|install_fail' "$3" 2> /dev/null; then
			screenshot "$2-error"
			return 2
		fi
		if [[ $SECONDS -ge $deadline ]]; then
			screenshot "$2-timeout"
			return 1
		fi
		sleep 20
		n=$((n + 1))
		# Une capture toutes les 5 minutes, pour le diagnostic.
		if ((n % 15 == 0)); then screenshot "$2-$((n / 3))min"; fi
	done
	return 0
}

# --- 1. Installation ----------------------------------------------------------
qemu-img create -q -f qcow2 "$disk" 48G
log "installation (autoinstall) de $(basename "$iso")"
"${qemu_base[@]}" -cdrom "$iso" -boot order=d \
	-serial "file:$work/logs/install-serial.log"
start=$SECONDS
rc=0
wait_vm_exit "${ISO_INSTALL_TIMEOUT:-3600}" install "$work/logs/install-serial.log" || rc=$?
[[ $rc -ne 2 ]] || die "l'installateur signale une erreur"
[[ $rc -eq 0 ]] || die "installation non terminée dans le délai"
log "installation terminée en $(((SECONDS - start) / 60)) min (machine éteinte)"

# --- 2. Premier démarrage sans intervention -----------------------------------
admin_pw=$(openssl rand -base64 24 | tr -d '/+=' | head -c 24)
sys_pw=$(openssl rand -base64 24 | tr -d '/+=' | head -c 24)
jq -n --arg fqdn "$fqdn" --arg a "$admin_pw" --arg s "$sys_pw" '{
	version: 1, language: "en", keyboard: "us", timezone: "Etc/UTC",
	network: { mode: "dhcp" }, fqdn: $fqdn,
	admin_password: $a, sysadmin_password: $s,
	admin_networks: ["192.0.2.0/24"],
	report: "serial", poweroff: false }' > "$answers"
unset admin_pw sys_pw
serial="$work/logs/firstboot-serial.log"
: > "$serial"
log "premier démarrage sans intervention"
"${qemu_base[@]}" -boot order=c \
	-fw_cfg "name=opt/scanoria/unattended.json,file=$answers" \
	-serial "file:$serial"
deadline=$((SECONDS + ${ISO_FIRSTBOOT_TIMEOUT:-2400}))
until grep -q '^SCANORIA-FIRSTBOOT-END ' "$serial" 2> /dev/null; do
	if ! vm_running; then
		die "la machine s'est arrêtée avant la fin du premier démarrage"
	fi
	if [[ $SECONDS -ge $deadline ]]; then
		screenshot firstboot-timeout
		die "premier démarrage non terminé dans le délai (marqueur SCANORIA-FIRSTBOOT-END absent)"
	fi
	sleep 15
done
rm -f "$answers"
screenshot firstboot-end

# --- 3. Vérifications ---------------------------------------------------------
fail=0
end=$(sed -n 's/^SCANORIA-FIRSTBOOT-END \([a-z]*\).*$/\1/p' "$serial" | tail -n 1)
rc=$(sed -n 's/^SCANORIA-SELFTEST-EXIT \([0-9]*\).*$/\1/p' "$serial" | tail -n 1)
sed -n 's/^SCANORIA-SELFTEST-JSON \([A-Za-z0-9+/=]*\).*$/\1/p' "$serial" | tail -n 1 \
	| base64 -d > "$work/logs/selftest.json" 2> /dev/null || true
log "premier démarrage : ${end:-?} ; scanoria-selftest : code ${rc:-?}"
[[ "$end" == ok ]] || { echo "::error::premier démarrage en erreur"; fail=1; }
[[ "$rc" == 0 ]] || { echo "::error::scanoria-selftest a rendu le code ${rc:-?}"; fail=1; }
if jq -e '.checks | type == "array"' "$work/logs/selftest.json" > /dev/null 2>&1; then
	jq -r '.checks[] | "  \(.status)\t\(.id)\t\(.message // "")"' "$work/logs/selftest.json"
	status=$(jq -r .status "$work/logs/selftest.json")
	[[ "$status" == pass || "$status" == warn ]] || { echo "::error::selftest : statut $status"; fail=1; }
	nfail=$(jq '[.checks[] | select(.status == "fail")] | length' "$work/logs/selftest.json")
	[[ "$nfail" -eq 0 ]] || { echo "::error::selftest : $nfail vérification(s) en échec"; fail=1; }
	appv=$(jq -r .appliance_version "$work/logs/selftest.json")
	[[ "$appv" == "$version" ]] || { echo "::error::selftest : version $appv ≠ $version"; fail=1; }
else
	echo "::error::rapport scanoria-selftest absent ou illisible"
	fail=1
fi

# La console répond par nginx. Le certificat de l'AC interne est contrôlé par
# selftest (tls.*) ; ici seuls la réponse et la version comptent.
health=$(curl -sk --max-time 20 --resolve "$fqdn:$https_port:127.0.0.1" \
	"https://$fqdn:$https_port/api/health" || true)
printf '%s\n' "$health" > "$work/logs/health.json"
if jq -e --arg v "$version" '.status == "ok" and .version == $v and .db == "ok"' <<< "$health" > /dev/null 2>&1; then
	log "/api/health : $health"
else
	echo "::error::/api/health inattendu : ${health:-(aucune réponse)}"
	fail=1
fi

monitor system_powerdown
wait_vm_exit 180 powerdown || true
[[ "$fail" -eq 0 ]] || exit 1
log "OK : ISO installée, premier démarrage et scanoria-selftest réussis"
