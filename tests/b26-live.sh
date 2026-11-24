#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Vincent Tisseront
#
# b26-live — vigilance de l'appliance (0.6, chantier B) avec le vrai podman
# (job CI vigilance-live, machine de test root jetable). Le helper et le runner
# tournent en mode test sur une racine temporaire ; podman est le vrai, l'index
# du catalogue est signé par une clé de test générée à la volée (comme b12-live).
# Cas :
#   - canari (G14) d'un gitleaks installé : réussi, puis échec simulé (attendu
#     inatteignable) signalé E_CANARY_FAILED, module toujours sain et actif ;
#   - essai (F13) de la version candidate de gitleaks : image tirée par
#     empreinte, santé, image retenue ; 3 analyses d'essai par le vrai runner
#     avec la candidate (empreinte publiée), une version non retenue refusée
#     en erreur d'infrastructure (G12) ;
#   - version figée (G6) par un projet : gardée à l'adoption ;
#   - adoption : update-module normal vers la candidate, ancienne image gardée
#     (figée) puis retirée une fois libérée, image adoptée jamais retirée.
# Dépendances : bash, python3, jq, openssl, zstd, tar, podman (root).

# shellcheck disable=SC2016
set -euo pipefail
export PYTHONDONTWRITEBYTECODE=1

[[ "$(id -u)" -eq 0 ]] || { echo "b26-live : root requis (podman réel)" >&2; exit 2; }
for t in python3 jq openssl zstd tar podman; do command -v "$t" > /dev/null || { echo "outil manquant : $t" >&2; exit 2; }; done

# gitleaks v8.30.0 et v8.30.1, relevés en amont le 2026-11-24 (ghcr.io/gitleaks/gitleaks, licence MIT).
OLD_IMAGE="ghcr.io/gitleaks/gitleaks@sha256:691af3c7c5a48b16f187ce3446d5f194838f91238f27270ed36eef6359a574d9"
NEW_IMAGE="ghcr.io/gitleaks/gitleaks@sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f"

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
HELPER="$ROOT/src/rootfs/usr/sbin/scanoria-helper"
RUNNER="$ROOT/src/rootfs/usr/sbin/scanoria-runner"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

PASS=0
FAIL=0
ok() { PASS=$((PASS + 1)); printf 'ok   %s\n' "$1"; }
ko() { FAIL=$((FAIL + 1)); printf 'FAIL %s\n' "$1"; }
expect() {
	if [[ "$2" == "$3" ]]; then ok "$1"; else ko "$1 (obtenu « $2 », attendu « $3 »)"; fi
}
present() { podman image exists "$1" && echo présente || echo retirée; }

T="$TMP/root"
STUBS="$TMP/stubs"
REL="$TMP/rel/catalog-v1"
SCANS="$T/var/lib/scanoria/scans"
mkdir -p "$T"/var/lib/scanoria/requests/{tmp,incoming,work,done,failed} "$T/var/lib/scanoria/console" "$T/var/lib/scanoria/uploads" \
	"$T/run/scanoria" "$T/etc/scanoria" "$T/opt/scanoria/current" "$T/usr/share/scanoria/schemas" "$STUBS" "$REL"
export SCANORIA_TEST_ROOT="$T" SCANORIA_TEST_BIN="$STUBS"
echo 0.6.0 > "$T/opt/scanoria/current/VERSION"
mkdir -p "$T/proc" && cp /proc/meminfo "$T/proc/meminfo" && grep '^processor' /proc/cpuinfo > "$T/proc/cpuinfo"
echo '{"repo": "exemple/scanoria"}' > "$T/etc/scanoria/catalog.json"
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
for c in systemctl sysctl runuser scanoria-state; do printf '#!/bin/bash\nexit 0\n' > "$STUBS/$c"; done
chmod 0755 "$STUBS"/*

# Banc d'essai : un faux identifiant de clé d'accès tiré au hasard à l'exécution
# (jamais écrit dans le dépôt) ; gitleaks 8.30 exige une configuration dans la source.
mkdir -p "$TMP/tb/testbed"
FAKE="AKIA$(head -c 64 /dev/urandom | base32 | tr -dc 'A-Z2-7' | head -c 16)"
printf 'aws_access_key_id = %s\n' "$FAKE" > "$TMP/tb/testbed/config.ini"
printf '[extend]\nuseDefault = true\n' > "$TMP/tb/testbed/.gitleaks.toml"
tar -C "$TMP/tb" --format=ustar --owner=0 --group=0 -cf - testbed | zstd -q -o "$REL/testbed-gitleaks-8.30.0.tar.zst"
# Nom imposé par catalogverify : testbed-<id>-<version>.tar.zst, un par version.
cp "$REL/testbed-gitleaks-8.30.0.tar.zst" "$REL/testbed-gitleaks-8.30.1.tar.zst"
TB_SHA=$(sha256sum "$REL/testbed-gitleaks-8.30.0.tar.zst" | cut -d' ' -f1)

entry() { # version image
	jq -cn --arg v "$1" --arg img "$2" --arg sha "$TB_SHA" '
		{id: "gitleaks", name: "gitleaks", version: $v, type: "scanner", categories: ["secrets"],
		 license: {spdx: "MIT", url: "https://github.com/gitleaks/gitleaks/blob/master/LICENSE", restrictions: "none"},
		 upstream: {homepage: "https://gitleaks.io", source: "https://github.com/gitleaks/gitleaks"},
		 image: $img, resources: {min_ram_mb: 256, min_cpu: 1, disk_mb: 200}, hostname: null,
		 needs: {sysctl: {}, postgres: false}, requires: {modules: [], feeds: []}, conflicts: [],
		 options: {type: "object", additionalProperties: false, properties: {}},
		 scan: {inputs: ["repo", "archive"], timeout_s: 300, network: "none", exit_codes_ok: [0, 1],
		        command: ["gitleaks", "dir", "/src", "--no-banner", "--report-format", "sarif",
		                  "--report-path", "/out/result.sarif", "--exit-code", "1"]},
		 outputs: {sarif: {path: "/out/result.sarif", version: "2.1.0"}},
		 health: {command: ["gitleaks", "version"]}, upgrade: {policy: "on-demand"},
		 testbed: {path: "testbed/", expect: [{rule: "aws-access-token", category: "secrets", min: 1}]},
		 testbed_archive: ("testbed-gitleaks-" + $v + ".tar.zst"), testbed_sha256: $sha}'
}
jq -n --argjson a "$(entry 8.30.0 "$OLD_IMAGE")" --argjson b "$(entry 8.30.1 "$NEW_IMAGE")" \
	'{schema: 1, version: 1, generated_at: "2026-11-24T00:00:00Z", modules: [$a, $b], packs: []}' > "$REL/catalog-index.json"
(cd "$REL" && sha256sum catalog-index.json testbed-*.tar.zst > SHA256SUMS)
openssl pkeyutl -sign -inkey "$TMP/sign.key" -rawin -in "$REL/SHA256SUMS" -out "$REL/SHA256SUMS.sig"
echo '[{"tag_name": "catalog-v1", "name": "Catalogue Scanoria 1", "draft": false, "prerelease": false}]' > "$TMP/api.json"

hx() {
	R=$("$HELPER" exec --origin cli --type "$1" --params "$2" 2> "$TMP/helper.err") || true
	echo "--- $1 : $(jq -c '{code, message}' <<< "${R:-{\}}")"
	sed 's/^/     /' "$TMP/helper.err" | tail -n 20
}
REG="$T/var/lib/scanoria/modules/installed.json"
STATE="$T/var/lib/scanoria/modules/state.json"
VSTATE="$T/var/lib/scanoria/vigilance/state.json"
PINS="$T/var/lib/scanoria/console/pins.json"
gl() { jq -r ".modules[] | select(.id == \"gitleaks\") | $1" "$STATE"; }

podman rmi --ignore "$OLD_IMAGE" "$NEW_IMAGE" > /dev/null 2>&1 || true
hx refresh-catalog '{}'
expect "refresh-catalog (index signé par la clé de test)" "$(jq -r .code <<< "$R")" OK
hx install-modules '{"modules": [{"id": "gitleaks", "version": "8.30.0", "options": {}}], "accept_licenses": []}'
expect "gitleaks 8.30.0 installé" "$(jq -r .code <<< "$R")/$(gl '.version + "/" + .status')" OK/8.30.0/healthy

# --- 1. Canari (G14) : réussite, puis échec simulé -------------------------------------------
hx run-canaries '{}'
expect "canari : réussi" "$(jq -r .code <<< "$R")/$(jq -r '.output.canaries[0].ok' <<< "$R")" OK/true
expect "canari : faux secret détecté" "$(jq -r '.output.canaries[0].details.expect[0].found >= 1' <<< "$R")" true
cp "$REG" "$TMP/installed.ok"
jq '.modules.gitleaks.manifest.testbed.expect[0].min = 999' "$TMP/installed.ok" > "$REG"
chmod 0600 "$REG"
hx run-canaries '{"ids": ["gitleaks"]}'
expect "canari : échec signalé" "$(jq -r .code <<< "$R")" E_CANARY_FAILED
expect "canari : attendu manquant détaillé" "$(jq -c '.output.canaries[0].details.expect[0] | [.min, .ok]' <<< "$R")" '[999,false]'
expect "canari : module jamais désactivé" "$(jq -r '.modules.gitleaks | .status + "/" + (.enabled | tostring)' "$REG")" healthy/true
cp "$TMP/installed.ok" "$REG"
chmod 0600 "$REG"
expect "canari : aucun conteneur laissé" "$(podman ps -a --format '{{.Image}}' | grep -c gitleaks || true)" 0

# --- 2. Essai (F13) de la candidate 8.30.1 ---------------------------------------------------
TRIAL=$(python3 -c 'import uuid; print(uuid.uuid4())')
hx start-trial "{\"module\": \"gitleaks\", \"version\": \"8.30.1\", \"trial_id\": \"$TRIAL\"}"
expect "start-trial : réussi" "$(jq -r .code <<< "$R")" OK
expect "start-trial : empreinte de l'index" "$(jq -r .output.image_digest <<< "$R")" "${NEW_IMAGE#*@}"
expect "candidate tirée par empreinte" "$(present "$NEW_IMAGE")" présente
expect "candidate retenue (état publié)" "$(jq -c '[.retained[] | [.version, .kind, .trial_id]]' "$VSTATE")" "[[\"8.30.1\",\"trial\",\"$TRIAL\"]]"
expect "version installée inchangée" "$(gl .version)" 8.30.0

# 3 analyses d'essai par le vrai runner (tâches marquées trial, version et empreinte de la candidate).
uuid() { python3 -c 'import uuid; print(uuid.uuid4())'; }
job() { # ID upload VERSION DIGEST
	jq -cn --arg id "$1" --arg sid "$(uuid)" --arg up "$2" --arg v "$3" --arg d "$4" \
		'{schema: 1, id: $id, scan_id: $sid, created_at: "2026-11-24T10:00:00Z", trial: true,
		  source: {kind: "archive", upload_id: $up}, modules: [{id: "gitleaks", version: $v, image_digest: $d}]}'
}
run_job() { # job JSON → result.json
	local id
	id=$(jq -r .id <<< "$1")
	printf '%s' "$1" > "$SCANS/jobs/incoming/$id.json"
	chmod 0600 "$SCANS/jobs/incoming/$id.json"
	"$RUNNER" --once 2> "$TMP/runner.err" || echo "runner : code $?" >&2
	sed 's/^/     runner: /' "$TMP/runner.err" | tail -n 10 >&2
	cat "$SCANS/results/$id/result.json" 2> /dev/null || echo '{}'
}
"$RUNNER" --once 2> /dev/null || true   # arborescence
for i in 1 2 3; do
	up=$(uuid)
	mkdir -p "$TMP/src$i" "$T/var/lib/scanoria/uploads/$up"
	printf '[extend]\nuseDefault = true\n' > "$TMP/src$i/.gitleaks.toml"
	printf 'aws_access_key_id = AKIA%s\n' "$(head -c 64 /dev/urandom | base32 | tr -dc 'A-Z2-7' | head -c 16)" > "$TMP/src$i/app$i.ini"
	tar -C "$TMP/src$i" -czf "$T/var/lib/scanoria/uploads/$up/source.tar.gz" .
	echo "$up" >> "$TMP/uploads"
	R=$(run_job "$(job "$(uuid)" "$up" 8.30.1 "${NEW_IMAGE#*@}")")
	expect "essai $i : candidate lancée" "$(jq -r '.modules[0] | .status + " " + .version + " " + .image_digest' <<< "$R")" "ok 8.30.1 ${NEW_IMAGE#*@}"
	expect "essai $i : résultat produit" "$(jq -r '.modules[0].outputs.sarif != null' <<< "$R")" true
done
up=$(head -1 "$TMP/uploads")
R=$(run_job "$(job "$(uuid)" "$up" 8.29.1 "sha256:$(printf '0%.0s' {1..64})")")
expect "version jamais retenue : missing, classe infra (G12)" "$(jq -r '.modules[0] | .status + "/" + (.error.class // .error_class // "?")' <<< "$R")" missing/infra
expect "essais : aucun conteneur laissé" "$(podman ps -a --format '{{.Names}}' | grep -c '^scanoria-' || true)" 0

# --- 3. Version figée (G6) puis adoption -----------------------------------------------------
echo "{\"version\": 1, \"pins\": [{\"module\": \"gitleaks\", \"version\": \"8.30.0\", \"image_digest\": \"${OLD_IMAGE#*@}\"}]}" > "$PINS"
hx update-module '{"id": "gitleaks", "version": "8.30.1"}'
expect "adoption : mise à jour normale réussie" "$(jq -r .code <<< "$R")/$(gl '.version + "/" + .status')" OK/8.30.1/healthy
expect "adoption : enregistrement d'essai libéré" "$(jq -c '[.retained[] | [.version, .kind]]' "$VSTATE")" '[["8.30.0","pin"]]'
expect "adoption : image figée 8.30.0 gardée" "$(present "$OLD_IMAGE")" présente
R=$(run_job "$(job "$(uuid)" "$up" 8.30.0 "${OLD_IMAGE#*@}")")
expect "version figée : lancée après la mise à jour" "$(jq -r '.modules[0] | .status + " " + .version' <<< "$R")" "ok 8.30.0"

echo '{"version": 1, "pins": []}' > "$PINS"
hx run-canaries '{}'
expect "canari de la version adoptée" "$(jq -r .code <<< "$R")/$(jq -r '.output.canaries[0].version' <<< "$R")" OK/8.30.1
expect "version libérée : image 8.30.0 retirée" "$(present "$OLD_IMAGE")" retirée
expect "image adoptée jamais retirée" "$(present "$NEW_IMAGE")" présente
expect "plus aucune image retenue" "$(jq -r '.retained | length' "$VSTATE")" 0

hx uninstall-module '{"id": "gitleaks", "keep_data": false}'
expect "désinstallation" "$(jq -r .code <<< "$R")" OK
podman rmi --ignore "$OLD_IMAGE" "$NEW_IMAGE" > /dev/null 2>&1 || true

echo
echo "b26-live : $PASS réussis, $FAIL échoués"
[[ "$FAIL" -eq 0 ]]
