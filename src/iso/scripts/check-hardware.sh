#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Vincent Tisseront
#
# Plancher matériel D6 de l'appliance (console seule) : 2 vCPU, 4 Go de RAM,
# 40 Go de disque. Lancé par autoinstall (early-commands) avant toute écriture
# sur le disque ; sort en 1 avec un message en français et en anglais si la
# machine est en dessous.
#
# Seuils :
# - RAM : MemTotal >= 3 670 016 kio (3,5 Gio). Une machine de 4 Go voit moins
#   que 4 Gio dans MemTotal (mémoire réservée par le noyau et le micrologiciel).
# - Disque : plus grand disque >= 40 000 000 000 octets (40 Go).
# Les variables SCANORIA_HW_* ne servent qu'aux tests (tests/b20-iso-static.sh).
set -eu

MIN_CPUS=2
MIN_MEM_KB=3670016
MIN_DISK_BYTES=40000000000

cpus="${SCANORIA_HW_CPUS:-$(nproc 2>/dev/null || echo 0)}"
mem_kb="${SCANORIA_HW_MEM_KB:-$(awk '/^MemTotal:/ {print $2}' /proc/meminfo 2>/dev/null || echo 0)}"
if [ -n "${SCANORIA_HW_DISK_BYTES:-}" ]; then
	disk_bytes="$SCANORIA_HW_DISK_BYTES"
else
	# Plus grand disque (hors supports amovibles, CD et disques en mémoire).
	disk_bytes="$(lsblk -b -d -n -o SIZE,TYPE,RM 2>/dev/null \
		| awk '$2 == "disk" && $3 == "0" && $1 > max {max = $1} END {print max + 0}')"
fi

case "$cpus$mem_kb$disk_bytes" in
	*[!0-9]*|'') cpus=0 ;;
esac

ok=1
msg=""
if [ "$cpus" -lt "$MIN_CPUS" ]; then
	ok=0
	msg="${msg}  - processeurs / CPUs : $cpus (minimum $MIN_CPUS)
"
fi
if [ "$mem_kb" -lt "$MIN_MEM_KB" ]; then
	ok=0
	msg="${msg}  - mémoire / memory : $((mem_kb / 1024)) Mio/MiB (minimum 4 Go/GB)
"
fi
if [ "$disk_bytes" -lt "$MIN_DISK_BYTES" ]; then
	ok=0
	msg="${msg}  - disque / disk : $((disk_bytes / 1000000000)) Go/GB (minimum 40 Go/GB)
"
fi

if [ "$ok" -eq 1 ]; then
	echo "scanoria: plancher matériel respecté / hardware floor met ($cpus vCPU, $((mem_kb / 1024)) MiB, $((disk_bytes / 1000000000)) GB)"
	exit 0
fi

text="
==============================================================================
 Installation refusée : la machine est en dessous du minimum de l'appliance.
 Installation refused: this machine is below the appliance minimum.

$msg
 Minimum : 2 vCPU, 4 Go de RAM, 40 Go de disque.
 Minimum: 2 vCPU, 4 GB RAM, 40 GB disk.
 Aucun disque n'a été modifié. / No disk has been modified.
==============================================================================
"
printf '%s\n' "$text" >&2
if [ -z "${SCANORIA_HW_CPUS:-}${SCANORIA_HW_MEM_KB:-}${SCANORIA_HW_DISK_BYTES:-}" ]; then
	for tty in /dev/console /dev/tty1; do
		[ -w "$tty" ] && printf '%s\n' "$text" > "$tty" 2>/dev/null || true
	done
	sleep 30
fi
exit 1
