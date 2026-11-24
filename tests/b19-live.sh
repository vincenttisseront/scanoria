#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Vincent Tisseront
#
# b19-live — SBOM de la 0.5 sur une appliance neuve (job CI sbom-live, machine
# de test root jetable). Le helper et le runner tournent en mode test sur une
# racine temporaire, mais podman, systemd (Quadlet), PostgreSQL 16 et les
# sources réelles sont les vrais ; rien n'est pré-rempli :
#   1. Syft et Grype installés PAR LE HELPER depuis l'index réel du dépôt
#      (catalog/build.py, signé par une clé jetable), dépendances résolues
#      (git-fetch, grype-db) ; base grype-db téléchargée depuis Anchore et
#      préparée par « grype db import » confiné ; bancs d'essai réussis ;
#   2. Dependency-Track réel installé par le helper (PostgreSQL, Quadlet),
#      mis en service (mot de passe admin remplacé, équipe et clé d'API), puis
#      dtrack-upload dont le banc d'essai envoie un SBOM au vrai service ;
#   3. analyse complète d'une archive par le runner : Syft, puis Grype sur le
#      SBOM (vulnérabilité connue trouvée hors ligne), puis dtrack-upload ; le
#      SBOM arrive dans Dependency-Track (projet scanoria-<uuid court>) ;
#   4. la console ingère les sorties réelles (tests/integration/sbom-live) :
#      sbom_components rempli, lien vers le projet Dependency-Track ;
#   5. désinstallation sans conservation : base, volumes, unités retirés.
# Dépendances : bash, python3, python3-yaml, jq, openssl, zstd, tar, curl,
# podman, systemd, postgresql-16, node et webui/node_modules (root).

# shellcheck disable=SC2016,SC2015
set -euo pipefail
export PYTHONDONTWRITEBYTECODE=1

[[ "$(id -u)" -eq 0 ]] || { echo "b19-live : root requis" >&2; exit 2; }
for t in python3 jq openssl zstd tar curl podman systemctl systemd-run node; do
	command -v "$t" > /dev/null || { echo "outil manquant : $t" >&2; exit 2; }
done
[[ -d /etc/postgresql/16/main ]] || { echo "PostgreSQL 16 absent" >&2; exit 2; }

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
HELPER="$ROOT/src/rootfs/usr/sbin/scanoria-helper"
RUNNER="$ROOT/src/rootfs/usr/sbin/scanoria-runner"
TMP=$(mktemp -d)
UNIT=scanoria-mod-dependency-track
cleanup() {
	systemctl stop "$UNIT.service" > /dev/null 2>&1 || true
	rm -f /etc/containers/systemd/"$UNIT"*
	systemctl daemon-reload || true
	podman volume rm --force "${UNIT}_data" > /dev/null 2>&1 || true
	podman secret rm "$UNIT-db-password" > /dev/null 2>&1 || true
	rm -rf "$TMP"
}
trap cleanup EXIT

PASS=0
FAIL=0
ok() { PASS=$((PASS + 1)); printf 'ok   %s\n' "$1"; }
ko() { FAIL=$((FAIL + 1)); printf 'FAIL %s\n' "$1"; }
expect() { if [[ "$2" == "$3" ]]; then ok "$1"; else ko "$1 (obtenu « $2 », attendu « $3 »)"; fi; }
echo "Machine : $(nproc) vCPU, $(awk '/MemTotal/ {printf "%d Mo", $2/1024}' /proc/meminfo) de RAM, $(df -h --output=avail / | tail -n 1) libres"

# --- Appliance de test --------------------------------------------------------------------
T="$TMP/root"
STUBS="$TMP/stubs"
REL="$TMP/rel/catalog-v1"
mkdir -p "$T"/var/lib/scanoria/requests/{tmp,incoming,work,done,failed} "$T/var/lib/scanoria/uploads" "$T/run/scanoria" \
	"$T/etc/scanoria" "$T/etc/containers" "$T/opt/scanoria/current" "$T/proc" "$T/var/lib" "$T/usr/lib/scanoria" \
	"$T/etc/ssl/certs" "$STUBS" "$REL" /etc/containers/systemd
ln -s /etc/containers/systemd "$T/etc/containers/systemd"
ln -s /etc/postgresql "$T/etc/postgresql"
ln -s /sys "$T/sys"
ln -s /var/lib/containers "$T/var/lib/containers"
cp /etc/ssl/certs/ca-certificates.crt "$T/etc/ssl/certs/"
cp -R "$ROOT/src/rootfs/usr/lib/scanoria/scan-tools" "$T/usr/lib/scanoria/"
chmod -R a+rX,go-w "$T/usr"
export SCANORIA_TEST_ROOT="$T" SCANORIA_TEST_BIN="$STUBS" SCANORIA_TEST_HEALTH_TIMEOUT=900
echo 0.5.0 > "$T/opt/scanoria/current/VERSION"
cp /proc/meminfo "$T/proc/meminfo" && grep '^processor' /proc/cpuinfo > "$T/proc/cpuinfo"
echo '{"repo": "exemple/scanoria"}' > "$T/etc/scanoria/catalog.json"
echo '{"fqdn": "analyse.exemple.test"}' > "$T/etc/scanoria/appliance.json"
openssl genpkey -algorithm ed25519 -out "$TMP/sign.key" 2> /dev/null
openssl pkey -in "$TMP/sign.key" -pubout -out "$T/etc/scanoria/update-pubkey.pem"
python3 -I "$ROOT/catalog/build.py" build --version 1 --out "$REL"
openssl pkeyutl -sign -inkey "$TMP/sign.key" -rawin -in "$REL/SHA256SUMS" -out "$REL/SHA256SUMS.sig"
echo '[{"tag_name": "catalog-v1", "name": "Catalogue Scanoria 1", "draft": false, "prerelease": false}]' > "$TMP/api.json"

for c in podman sysctl runuser nft; do ln -s "$(command -v "$c")" "$STUBS/$c"; done
cat > "$STUBS/systemctl" <<-EOF
	#!/bin/bash
	case " \$* " in *" nginx.service "*|*" scanoria-dns-check."*) exit 0 ;; esac
	exec $(command -v systemctl) "\$@"
EOF
# curl : releases du catalogue servies depuis le disque ; tout le reste (base
# Grype d'Anchore, service local) part vers le vrai curl, donc les vraies sources.
CURL=$(command -v curl)
cat > "$STUBS/curl" <<-EOF
	#!/usr/bin/env python3
	import os, shutil, sys
	a = sys.argv[1:]
	url = a[-1]
	if url.startswith(("https://api.github.com/repos/exemple/", "https://github.com/exemple/")):
	    out = a[a.index("--output") + 1] if "--output" in a else None
	    wo = a[a.index("--write-out") + 1] if "--write-out" in a else ""
	    code, src = 404, None
	    if url == "https://api.github.com/repos/exemple/scanoria/releases?per_page=30":
	        code, src = 200, "$TMP/api.json"
	    elif url.startswith("https://github.com/exemple/scanoria/releases/download/"):
	        p = "$TMP/rel/" + url.split("/releases/download/", 1)[1]
	        if os.path.isfile(p):
	            code, src = 200, p
	    if out and src:
	        shutil.copyfile(src, out)
	    sys.stdout.write(wo.replace("%{http_code}", str(code)).replace("%{redirect_url}", ""))
	    sys.exit(0)
	os.execv("$CURL", ["curl"] + a)
EOF
printf '#!/bin/bash\nexit 0\n' > "$STUBS/scanoria-state"
printf '#!/bin/bash\nexit 0\n' > "$STUBS/nginx"
chmod 0755 "$STUBS/systemctl" "$STUBS/curl" "$STUBS/scanoria-state" "$STUBS/nginx"
systemctl start postgresql.service

hx() {
	R=$("$HELPER" exec --origin cli --type "$1" --params "$2" 2> "$TMP/helper.err") || true
	echo "--- $1 : $(jq -c '{code, message}' <<< "${R:-{\}}")"
	sed 's/^/     /' "$TMP/helper.err" | tail -n 40
}
code() { jq -r .code <<< "$R"; }
STATE="$T/var/lib/scanoria/modules/state.json"
FEEDS="$T/var/lib/scanoria/feeds"
SEC="$T/var/lib/scanoria/modules/dependency-track/secrets"
ver() { jq -r --arg id "$1" '[.modules[] | select(.id == $id)][0].version' "$REL/catalog-index.json"; }
mstate() { jq -r --arg id "$1" '[.modules[] | select(.id == $id)][0] | if . == null then "absent" else .status + "/" + (.enabled|tostring) end' "$STATE"; }
testbed() { jq -r --arg id "$1" '.modules[] | select(.id == $id) | .testbed.passed' "$STATE"; }
diag() {
	systemctl status "$UNIT.service" --no-pager -l 2>&1 | tail -n 20 || true
	podman logs --tail 60 "$UNIT" 2>&1 || true
}

hx refresh-catalog '{}'
expect "refresh-catalog (index réel signé par la clé de test)" "$(code)" OK

# --- 1. Syft et Grype, depuis une appliance vide -------------------------------------------
expect "aucune base avant l'installation" "$(find "$FEEDS" -mindepth 1 2> /dev/null | wc -l)" 0
start=$SECONDS
hx install-modules "$(jq -cn --arg s "$(ver syft)" --arg g "$(ver grype)" \
	'{modules: [{id: "syft", version: $s, options: {}}, {id: "grype", version: $g, options: {}}], accept_licenses: []}')"
echo "durée de l'installation de Syft et Grype : $((SECONDS - start)) s"
expect "install syft + grype par le helper" "$(code)" OK
for id in git-fetch grype-db syft grype; do expect "$id sain et activé" "$(mstate "$id")" healthy/true; done
for id in syft grype; do
	expect "$id : banc d'essai réussi" "$(testbed "$id")" true
	[[ "$(testbed "$id")" == true ]] || jq -c --arg id "$id" '.modules[] | select(.id == $id) | .testbed' "$STATE"
done
[[ -s "$FEEDS/grype-db/6/vulnerability.db" && -s "$FEEDS/grype-db/6/import.json" ]] \
	&& ok "grype-db : base téléchargée et préparée (6/vulnerability.db, 6/import.json)" || ko "grype-db : base absente"
jq -e '.digest | startswith("xxh64:")' "$FEEDS/grype-db/6/import.json" > /dev/null && ok "grype-db : import.json avec empreinte xxh64" || ko "grype-db : import.json"
expect "grype-db : âge publié" "$(jq -r '[.feeds[] | select(.id == "grype-db")][0] | .status + "/" + (.updated_at != null | tostring)' "$STATE")" ok/true
expect "grype-db : lisible par le groupe 65534 seulement (0640)" "$(stat -c %a:%g "$FEEDS/grype-db/6/vulnerability.db")" 640:65534
du -sh "$(readlink -f "$FEEDS/grype-db")" || true

# --- 2. Dependency-Track réel --------------------------------------------------------------
echo "::group::Dependency-Track"
start=$SECONDS
hx install-modules "$(jq -cn --arg d "$(ver dependency-track)" --arg u "$(ver dtrack-upload)" \
	'{modules: [{id: "dependency-track", version: $d, options: {}}, {id: "dtrack-upload", version: $u, options: {}}], accept_licenses: []}')"
echo "durée de l'installation de Dependency-Track : $((SECONDS - start)) s ; mémoire : $(podman stats --no-stream --format '{{.MemUsage}}' "$UNIT" 2> /dev/null || echo '?')"
[[ "$(code)" == OK ]] || diag
echo "::endgroup::"
expect "install dependency-track + dtrack-upload par le helper" "$(code)" OK
for id in dependency-track dtrack-upload; do expect "$id sain et activé" "$(mstate "$id")" healthy/true; done
expect "dtrack-upload : banc d'essai réussi (SBOM envoyé au vrai service)" "$(testbed dtrack-upload)" true
expect "unité Quadlet active" "$(systemctl is-active "$UNIT.service")" active
expect "base PostgreSQL du module" "$(runuser -u postgres -- psql -X -A -t -c "SELECT count(*) FROM pg_database WHERE datname = 'mod_dependency_track'")" 1
PORT=$(jq -r '.modules["dependency-track"].host_port' "$T/var/lib/scanoria/modules/installed.json")
API="http://127.0.0.1:$PORT"
expect "fichiers de secrets 0600" "$(stat -c %a "$SEC/admin-password" "$SEC/scan-token" | sort -u)" 600
login() { curl -s -o "$TMP/login.out" -w '%{http_code}' --data-urlencode username=admin --data-urlencode "password=$1" "$API/api/v1/user/login"; }
expect "admin/admin refusé (mot de passe par défaut remplacé)" "$(login admin)" 401
expect "admin : mot de passe de l'appliance accepté" "$(login "$(cat "$SEC/admin-password")")" 200
JWT=$(cat "$TMP/login.out")
KEYH="X-Api-Key: $(cat "$SEC/scan-token")"
expect "clé d'analyse : portefeuille lisible" "$(curl -s -o /dev/null -w '%{http_code}' -H "$KEYH" "$API/api/v1/project?pageSize=1")" 200
expect "clé d'analyse : pas d'administration des utilisateurs" "$(curl -s -o /dev/null -w '%{http_code}' -H "$KEYH" "$API/api/v1/user/managed")" 403
expect "équipe d'analyse : droits minimaux" \
	"$(curl -s -H "Authorization: Bearer $JWT" "$API/api/v1/team" | jq -r '.[] | select(.name == "Scanoria (analyses)") | [.permissions[].name] | sort | join(",")')" \
	"BOM_UPLOAD,PROJECT_CREATION_UPLOAD,VIEW_PORTFOLIO"
expect "banc d'essai : projet scanoria-testbed dans Dependency-Track" \
	"$(curl -s -H "$KEYH" "$API/api/v1/project/lookup?name=scanoria-testbed&version=testbed" | jq -r .name)" scanoria-testbed

# --- 3. Analyse complète d'une archive ------------------------------------------------------
SCANS="$T/var/lib/scanoria/scans"
up=$(python3 -c 'import uuid; print(uuid.uuid4())')
PROJ=$(python3 -c 'import uuid; print(uuid.uuid4())')
PKEY="scanoria-$(tr -d '-' <<< "$PROJ" | cut -c1-12)"
mkdir -p "$TMP/arch" "$T/var/lib/scanoria/uploads/$up"
cp "$ROOT/modules/grype/testbed/package-lock.json" "$ROOT/modules/grype/testbed/package.json" "$TMP/arch/"
cp "$ROOT/modules/syft/testbed/requirements.txt" "$ROOT/modules/syft/testbed/go.mod" "$ROOT/modules/syft/testbed/go.sum" "$TMP/arch/"
tar -C "$TMP/arch" -czf "$T/var/lib/scanoria/uploads/$up/source.tar.gz" .
id=$(python3 -c 'import uuid; print(uuid.uuid4())')
mkdir -p "$SCANS/jobs/incoming"
jq -cn --arg id "$id" --arg sid "$(python3 -c 'import uuid; print(uuid.uuid4())')" --arg up "$up" --arg pr "$PROJ" \
	--arg g "$(ver grype)" --arg u "$(ver dtrack-upload)" --arg s "$(ver syft)" '
	{schema: 1, id: $id, scan_id: $sid, project_id: $pr, created_at: "2026-11-24T10:00:00Z",
	 source: {kind: "archive", upload_id: $up},
	 modules: [{id: "grype", version: $g}, {id: "dtrack-upload", version: $u}, {id: "syft", version: $s}]}' > "$SCANS/jobs/incoming/$id.json"
chmod 0600 "$SCANS/jobs/incoming/$id.json"
start=$SECONDS
"$RUNNER" --once 2> "$TMP/runner.err" || { echo "runner : code $?"; tail -n 30 "$TMP/runner.err"; }
echo "durée de l'analyse : $((SECONDS - start)) s"
RES="$SCANS/results/$id"
R=$(cat "$RES/result.json" 2> /dev/null || echo '{}')
expect "analyse : statut ok" "$(jq -r .status <<< "$R")" ok
expect "analyse : trois modules réussis (ordre de la tâche gardé)" \
	"$(jq -r '[.modules[] | .id + "=" + .status] | join(" ")' <<< "$R")" "grype=ok dtrack-upload=ok syft=ok"
[[ "$(jq -r '[.modules[].status] | unique | join(",")' <<< "$R")" == ok ]] || { jq -c '.modules[] | {id, status, error}' <<< "$R"; for f in "$RES"/*/module.log; do echo "== $f"; tail -n 20 "$f"; done; }
SBOM="$RES/$(jq -r '.modules[] | select(.id == "syft") | .outputs.cyclonedx' <<< "$R")"
SARIF="$RES/$(jq -r '.modules[] | select(.id == "grype") | .outputs.sarif' <<< "$R")"
DT="$RES/$(jq -r '.modules[] | select(.id == "dtrack-upload") | .outputs.cyclonedx' <<< "$R")"
expect "Syft : un composant par écosystème" "$(jq -r '[.components[].name] | map(select(. == "minimist" or . == "six" or . == "github.com/google/uuid")) | unique | length' "$SBOM")" 3
jq -e '.runs[0].results | map(.ruleId) | index("GHSA-xvch-5gv4-984h-minimist") != null' "$SARIF" > /dev/null \
	&& ok "Grype : vulnérabilité connue trouvée hors ligne à partir du SBOM" || { ko "Grype : vulnérabilité non trouvée"; jq -c '[.runs[].results[].ruleId]' "$SARIF"; }
grep -q 'sbom:/sbom/sbom.cdx.json' "$RES/grype/module.log" 2> /dev/null && ok "Grype : lancé sur le SBOM de l'analyse" \
	|| echo "     (journal de Grype sans la commande : vérifiée par b19-sbom)"
DUUID=$(jq -r '.metadata.properties[] | select(.name == "scanoria:dtrack:project") | .value' "$DT")
expect "dtrack-upload : projet $PKEY, version archive, dans Dependency-Track" \
	"$(curl -s -H "$KEYH" "$API/api/v1/project/lookup?name=$PKEY&version=archive" | jq -r .uuid)" "$DUUID"
expect "Dependency-Track : composants du SBOM rangés" \
	"$(curl -s -H "$KEYH" "$API/api/v1/component/project/$DUUID?pageSize=100" | jq -r '[.[].name] | map(select(. == "minimist" or . == "six")) | unique | join(",")')" "minimist,six"
grep -rqF -- "$(cat "$SEC/scan-token")" "$RES" && ko "clé d'API dans les résultats" || ok "clé d'API absente des résultats et des journaux"
expect "aucun conteneur ni secret laissé" "$(podman ps -a --format '{{.Names}}' | grep -c '^scanoria-scan-' || true)/$(podman secret ls --format '{{.Name}}' | grep -c '^scanoria-scan-' || true)" 0/0
expect "espace de travail supprimé" "$(find "$SCANS/workspaces" -mindepth 1 | wc -l)" 0

# --- 4. Ingestion par la console ------------------------------------------------------------
runuser -u postgres -- psql -X -q -c "ALTER USER postgres PASSWORD 'b19-live-postgres'" > /dev/null
if (cd "$ROOT/webui" && DATABASE_URL="postgres://postgres:b19-live-postgres@127.0.0.1:5432/postgres" SCANORIA_SBOM_LIVE_RESULT="$RES" \
	node_modules/.bin/vitest run --project server tests/integration/sbom-live.test.ts); then
	ok "console : SBOM réel ingéré (sbom_components, lien Dependency-Track)"
else
	ko "console : ingestion du SBOM réel"
fi

# --- 5. Désinstallation --------------------------------------------------------------------
hx uninstall-module '{"id": "dtrack-upload", "keep_data": false}'
hx uninstall-module '{"id": "dependency-track", "keep_data": false}'
expect "désinstallation de Dependency-Track" "$(code)" OK
expect "unités, volume et base retirés" \
	"$(find /etc/containers/systemd -name "$UNIT*" | wc -l)/$(podman volume exists "${UNIT}_data" && echo volume || echo -)/$(runuser -u postgres -- psql -X -A -t -c "SELECT count(*) FROM pg_database WHERE datname = 'mod_dependency_track'")" "0/-/0"

echo
echo "b19-live : $PASS réussis, $FAIL échoués"
[[ "$FAIL" -eq 0 ]]
