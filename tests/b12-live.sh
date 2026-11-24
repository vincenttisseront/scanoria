#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Vincent Tisseront
#
# b12-live — installation réelle d'un scanner avec podman (job CI modules-live,
# machine de test root jetable). Le helper tourne en mode test sur une racine
# temporaire, mais podman est le vrai : image tirée par empreinte, santé et banc
# d'essai lancés en conteneurs confinés (§ 6.4). L'index du catalogue est signé
# par une clé de test générée à la volée et servi depuis le disque (bouchon
# curl) ; systemctl, sysctl et runuser restent des bouchons.
# Cas : banc d'essai sans résultat attendu (retour arrière, image retirée),
# installation de gitleaks (faux secret généré à l'exécution, jamais dans le
# dépôt), désinstallation.
# Dépendances : bash, python3, jq, openssl, zstd, tar, podman (root).

# shellcheck disable=SC2016
set -euo pipefail
export PYTHONDONTWRITEBYTECODE=1

[[ "$(id -u)" -eq 0 ]] || { echo "b12-live : root requis (podman réel)" >&2; exit 2; }
for t in python3 jq openssl zstd tar podman; do command -v "$t" > /dev/null || { echo "outil manquant : $t" >&2; exit 2; }; done

# gitleaks, relevé en amont le 2026-11-24 (ghcr.io/gitleaks/gitleaks, tag v8.30.1, licence MIT).
GITLEAKS_IMAGE="ghcr.io/gitleaks/gitleaks:v8.30.1@sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f"

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
HELPER="$ROOT/src/rootfs/usr/sbin/scanoria-helper"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

PASS=0
FAIL=0
ok() { PASS=$((PASS + 1)); printf 'ok   %s\n' "$1"; }
ko() { FAIL=$((FAIL + 1)); printf 'FAIL %s\n' "$1"; }
expect() {
	if [[ "$2" == "$3" ]]; then ok "$1"; else ko "$1 (obtenu « $2 », attendu « $3 »)"; fi
}

T="$TMP/root"
STUBS="$TMP/stubs"
REL="$TMP/rel/catalog-v1"
mkdir -p "$T"/var/lib/scanoria/requests/{tmp,incoming,work,done,failed} "$T/run/scanoria" "$T/etc/scanoria" \
	"$T/opt/scanoria/current" "$T/usr/share/scanoria/schemas" "$STUBS" "$REL"
export SCANORIA_TEST_ROOT="$T" SCANORIA_TEST_BIN="$STUBS"
echo 0.2.0 > "$T/opt/scanoria/current/VERSION"
mkdir -p "$T/proc" && cp /proc/meminfo "$T/proc/meminfo" && grep '^processor' /proc/cpuinfo > "$T/proc/cpuinfo"
echo '{"repo": "exemple/scanoria"}' > "$T/etc/scanoria/catalog.json"
echo '{"type": "object", "required": ["schema", "version", "modules", "packs"]}' \
	> "$T/usr/share/scanoria/schemas/catalog-index.schema.json"
openssl genpkey -algorithm ed25519 -out "$TMP/sign.key" 2> /dev/null
openssl pkey -in "$TMP/sign.key" -pubout -out "$T/etc/scanoria/update-pubkey.pem"

ln -s "$(command -v podman)" "$STUBS/podman"
cat > "$STUBS/curl" <<-EOF
	#!/usr/bin/env python3
	import os, shutil, sys
	a = sys.argv[1:]
	out = a[a.index("--output") + 1] if "--output" in a else None
	wo = a[a.index("--write-out") + 1] if "--write-out" in a else ""
	url, code, src = a[-1], 404, None
	if url == "https://api.github.com/repos/exemple/scanoria/releases?per_page=30":
	    code, src = 200, "$TMP/api.json"
	elif url.startswith("https://github.com/exemple/scanoria/releases/download/"):
	    p = "$TMP/rel/" + url.split("/releases/download/", 1)[1]
	    if os.path.isfile(p):
	        code, src = 200, p
	if out and src:
	    shutil.copyfile(src, out)
	sys.stdout.write(wo.replace("%{http_code}", str(code)).replace("%{redirect_url}", ""))
EOF
printf '#!/bin/bash\nexit 0\n' > "$STUBS/scanoria-state"
chmod 0755 "$STUBS/curl" "$STUBS/scanoria-state"

# Bancs d'essai : un faux identifiant de clé d'accès, de forme reconnaissable,
# tiré au hasard à l'exécution (jamais écrit dans le dépôt), et un dépôt sain.
mkdir -p "$TMP/tb-secret/testbed" "$TMP/tb-clean/testbed"
FAKE="AKIA$(head -c 64 /dev/urandom | base32 | tr -dc 'A-Z2-7' | head -c 16)"
printf 'aws_access_key_id = %s\n' "$FAKE" > "$TMP/tb-secret/testbed/config.ini"
echo "aucun secret ici" > "$TMP/tb-clean/testbed/README"
for k in secret clean; do
	tar -C "$TMP/tb-$k" --format=ustar --owner=0 --group=0 -cf - testbed | zstd -q -o "$REL/testbed-gitleaks-$k-8.30.1.tar.zst"
done

entry() { # id
	jq -cn --arg id "$1" --arg img "$GITLEAKS_IMAGE" --arg sha "$(sha256sum "$REL/testbed-$1-8.30.1.tar.zst" | cut -d' ' -f1)" '
		{id: $id, name: "gitleaks", version: "8.30.1", type: "scanner", categories: ["secrets"],
		 license: {spdx: "MIT", url: "https://github.com/gitleaks/gitleaks/blob/master/LICENSE", restrictions: "none"},
		 upstream: {homepage: "https://gitleaks.io", source: "https://github.com/gitleaks/gitleaks"},
		 image: $img, resources: {min_ram_mb: 256, min_cpu: 1, disk_mb: 200}, hostname: null,
		 needs: {sysctl: {}, postgres: false}, requires: {modules: [], feeds: []}, conflicts: [],
		 options: {type: "object", additionalProperties: false, properties: {}},
		 scan: {inputs: ["repo"], timeout_s: 300, network: "none", exit_codes_ok: [0, 1],
		        command: ["gitleaks", "dir", "/src", "--no-banner", "--report-format", "sarif",
		                  "--report-path", "/out/result.sarif", "--exit-code", "1"]},
		 outputs: {sarif: {path: "/out/result.sarif", version: "2.1.0"}},
		 health: {command: ["gitleaks", "version"]}, upgrade: {policy: "on-demand"},
		 testbed: {path: "testbed/", expect: [{rule: "aws-access-token", category: "secrets", min: 1}]},
		 testbed_archive: ("testbed-" + $id + "-8.30.1.tar.zst"), testbed_sha256: $sha}'
}
jq -n --argjson a "$(entry gitleaks-clean)" --argjson b "$(entry gitleaks-secret)" \
	'{schema: 1, version: 1, generated_at: "2026-11-24T00:00:00Z", modules: [$a, $b], packs: []}' > "$REL/catalog-index.json"
(cd "$REL" && sha256sum catalog-index.json testbed-*.tar.zst > SHA256SUMS)
openssl pkeyutl -sign -inkey "$TMP/sign.key" -rawin -in "$REL/SHA256SUMS" -out "$REL/SHA256SUMS.sig"
echo '[{"tag_name": "catalog-v1", "name": "Catalogue Scanoria 1", "draft": false, "prerelease": false}]' > "$TMP/api.json"

hx() {
	R=$("$HELPER" exec --origin cli --type "$1" --params "$2" 2> "$TMP/helper.err") || true
	echo "--- $1 : $(jq -c '{code, message}' <<< "${R:-{\}}")"
	sed 's/^/     /' "$TMP/helper.err"
}
STATE="$T/var/lib/scanoria/modules/state.json"
inst() { jq -cn --arg id "$1" '{modules: [{id: $id, version: "8.30.1", options: {}}], accept_licenses: []}'; }

podman rmi --ignore "$GITLEAKS_IMAGE" > /dev/null 2>&1 || true
hx refresh-catalog '{}'
expect "refresh-catalog (index signé par la clé de test)" "$(jq -r .code <<< "$R")" OK

hx install-modules "$(inst gitleaks-clean)"
expect "banc d'essai sans résultat attendu : refus" "$(jq -r .code <<< "$R")" E_TESTBED
expect "retour arrière : module absent" "$(jq '[.modules[] | select(.id == "gitleaks-clean")] | length' "$STATE")" 0
expect "retour arrière : image retirée" "$(podman image exists "$GITLEAKS_IMAGE" && echo présente || echo retirée)" retirée

hx install-modules "$(inst gitleaks-secret)"
expect "install gitleaks réel" "$(jq -r .code <<< "$R")" OK
expect "gitleaks sain et activé" "$(jq -r '.modules[] | select(.id == "gitleaks-secret") | .status + "/" + (.enabled|tostring)' "$STATE")" healthy/true
expect "banc d'essai : faux secret détecté" "$(jq -r '.modules[] | select(.id == "gitleaks-secret") | .testbed.details[0].found >= 1' "$STATE")" true
expect "image présente, épinglée par empreinte" "$(podman image exists "$GITLEAKS_IMAGE" && echo oui)" oui
expect "aucun conteneur laissé" "$(podman ps -a --format '{{.Image}}' | grep -c gitleaks || true)" 0
expect "répertoire de travail supprimé" "$(find "$T/var/lib/scanoria/modules/work" -mindepth 1 2> /dev/null | wc -l)" 0
jq '.modules' "$STATE"

hx uninstall-module '{"id": "gitleaks-secret", "keep_data": false}'
expect "uninstall gitleaks" "$(jq -r .code <<< "$R")" OK
expect "image retirée à la désinstallation" "$(podman image exists "$GITLEAKS_IMAGE" && echo présente || echo retirée)" retirée

echo
echo "b12-live : $PASS réussis, $FAIL échoués"
[[ "$FAIL" -eq 0 ]]
