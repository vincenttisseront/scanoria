#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Vincent Tisseront
#
# Installe les outils de la CI demandés (gitleaks, actionlint, osv-scanner,
# ShellCheck, zizmor) dans un répertoire, après vérification de l'empreinte épinglée
# dans .github/tools.env. Usage : install-tools.sh RÉPERTOIRE OUTIL…
set -euo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
env_file="$here/../tools.env"

get() { # clé
	local v
	v=$(sed -n "s/^$1=\\([A-Za-z0-9.]*\\)\$/\\1/p" "$env_file" | tail -n 1)
	[[ -n "$v" ]] || { echo "install-tools: $1 absent de tools.env" >&2; exit 1; }
	printf '%s' "$v"
}

fetch() { # url fichier empreinte
	curl --proto '=https' --tlsv1.2 -fsSL --retry 3 -o "$2" "$1"
	echo "$3  $2" | sha256sum --check --strict --quiet \
		|| { echo "install-tools: empreinte invalide pour $1" >&2; exit 1; }
}

[[ $# -ge 2 ]] || { echo "usage : $0 RÉPERTOIRE OUTIL…" >&2; exit 2; }
dest=$1
shift
mkdir -p "$dest"
dl=$(mktemp -d)
trap 'rm -rf "$dl"' EXIT

for tool in "$@"; do
	case "$tool" in
		gitleaks)
			v=$(get GITLEAKS_VERSION)
			fetch "https://github.com/gitleaks/gitleaks/releases/download/v$v/gitleaks_${v}_linux_x64.tar.gz" \
				"$dl/gitleaks.tgz" "$(get GITLEAKS_SHA256)"
			tar -xzf "$dl/gitleaks.tgz" -C "$dest" gitleaks ;;
		actionlint)
			v=$(get ACTIONLINT_VERSION)
			fetch "https://github.com/rhysd/actionlint/releases/download/v$v/actionlint_${v}_linux_amd64.tar.gz" \
				"$dl/actionlint.tgz" "$(get ACTIONLINT_SHA256)"
			tar -xzf "$dl/actionlint.tgz" -C "$dest" actionlint ;;
		osv-scanner)
			v=$(get OSV_SCANNER_VERSION)
			fetch "https://github.com/google/osv-scanner/releases/download/v$v/osv-scanner_linux_amd64" \
				"$dl/osv-scanner" "$(get OSV_SCANNER_SHA256)"
			install -m 0755 "$dl/osv-scanner" "$dest/osv-scanner" ;;
		shellcheck)
			# Environnement virtuel : le Python du système est « externally managed ».
			python3 -m venv "$dest/.venv-shellcheck"
			"$dest/.venv-shellcheck/bin/pip" install --quiet --disable-pip-version-check \
				"shellcheck-py==$(get SHELLCHECK_PY_VERSION)"
			ln -sf "$dest/.venv-shellcheck/bin/shellcheck" "$dest/shellcheck" ;;
		zizmor)
			python3 -m venv "$dest/.venv-zizmor"
			"$dest/.venv-zizmor/bin/pip" install --quiet --disable-pip-version-check \
				"zizmor==$(get ZIZMOR_VERSION)"
			ln -sf "$dest/.venv-zizmor/bin/zizmor" "$dest/zizmor" ;;
		*) echo "install-tools: outil inconnu : $tool" >&2; exit 2 ;;
	esac
	echo "install-tools: $tool installé"
done
