# shellcheck shell=bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Vincent Tisseront
#
# Fonctions communes des commandes root écrites en bash (scanoria-ca,
# scanoria-firewall). À « sourcer » après « set -euo pipefail ».
#
# Mode test (sans root) : SCANORIA_TEST_ROOT=<répertoire absolu> préfixe les
# chemins de l'appliance ; les commandes système à effet (nginx, systemctl,
# nft, chown) sont remplacées par une ligne dans <racine>/test-commands.log,
# sauf si SCANORIA_TEST_BIN fournit un bouchon du même nom.

R=${SCANORIA_TEST_ROOT:-}
if [[ -n "$R" ]]; then
	if [[ "$R" != /* || ! -d "$R" ]]; then
		echo "scanoria: SCANORIA_TEST_ROOT must be an existing absolute directory" >&2
		exit 2
	fi
	R=$(readlink -f "$R")
fi
export LC_ALL=C.UTF-8
umask 077

ETC="$R/etc/scanoria"
# shellcheck disable=SC2034 # utilisés par les scripts qui sourcent ce fichier
VARLIB="$R/var/lib/scanoria"
# shellcheck disable=SC2034
PKI="$ETC/pki"
# shellcheck disable=SC2034 # utilisé par les scripts qui sourcent ce fichier
SHARE=$(readlink -f "$(dirname "${BASH_SOURCE[0]}")/../../../share/scanoria")
# shellcheck disable=SC2034
FQDN_RE='^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]([a-z0-9-]{0,61}[a-z0-9])?$'

log() { printf 'scanoria: %s\n' "$*" >&2; }

is_test() { [[ -n "$R" ]]; }

# Réponse au protocole {code, message, output} sur la sortie standard, puis
# sortie (0 si OK). output : objet JSON (défaut {}).
emit() { # code message [output_json]
	local out=${3:-}
	[[ -n "$out" ]] || out='{}'
	jq -cn --arg c "$1" --arg m "$2" --argjson o "$out" '{code: $c, message: $m, output: $o}'
	[[ "$1" == OK ]] && exit 0
	exit 1
}

# Commande système à effet ; bouchon en mode test.
sys() { # commande arguments…
	if is_test; then
		if [[ -n "${SCANORIA_TEST_BIN:-}" && -x "$SCANORIA_TEST_BIN/$1" ]]; then
			"$SCANORIA_TEST_BIN/$1" "${@:2}"
			return
		fi
		jq -cn '$ARGS.positional' --args -- "$@" >> "$R/test-commands.log"
		return 0
	fi
	"$@"
}

# Propriétaire et droits (propriétaire ignoré en mode test).
own() { # propriétaire:groupe mode chemin…
	local o=$1 m=$2
	shift 2
	chmod "$m" "$@"
	is_test || chown "$o" "$@"
}

valid_fqdn() { # nom
	[[ ${#1} -ge 4 && ${#1} -le 253 && "$1" =~ $FQDN_RE ]]
}

# Écriture atomique d'un fichier (contenu sur l'entrée standard).
atomic_write() { # propriétaire:groupe mode chemin
	local tmp
	tmp=$(mktemp "$(dirname "$3")/.$(basename "$3").XXXXXX")
	cat > "$tmp"
	own "$1" "$2" "$tmp"
	sync -- "$tmp" 2>/dev/null || true
	mv -f -- "$tmp" "$3"
}

# Date openssl (« Nov 23 08:00:00 2027 GMT ») en RFC 3339 UTC.
to_iso() { date -u -d "$1" +%Y-%m-%dT%H:%M:%SZ; }
to_epoch() { date -u -d "$1" +%s; }
