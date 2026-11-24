#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Vincent Tisseront
#
# b16-live — un petit service réel installé par le moteur des modules
# « service » (0.4, chantier A), sur une machine de test root jetable (job CI
# services-live). Le helper tourne en mode test sur une racine temporaire, mais
# podman, systemd (générateur Quadlet), PostgreSQL 16 et sysctl sont les vrais :
# /etc/containers/systemd et /etc/postgresql de la racine de test sont des liens
# vers ceux de la machine. L'index du catalogue est signé par une clé jetable.
# Cas :
#   - installation : base mod_web, secrets Podman (variable et fichier monté),
#     réseau propre en /24 fixe et réseau de scan interne, Ulimit, sysctl ;
#   - PostgreSQL joignable depuis le réseau du module avec le secret, refusé
#     depuis un autre réseau (pg_hba) ;
#   - sauvegarde (base et volume), perte de données, restauration vérifiée ;
#   - mise à jour vers une image cassée : retour arrière, données intactes ;
#   - relevés de consommation (contrat 11) ;
#   - Podman root sous le durcissement de scanoria-runner.service ;
#   - désinstallation sans conservation : base, volumes, secrets, unités retirés.
# Images de test (jamais livrées), épinglées par empreinte, relevées le
# 2026-11-24 sur mirror.gcr.io (miroir de Docker Hub) :
#   nginxinc/nginx-unprivileged:1.29-alpine (BSD-2-Clause), busybox:1.37
#   (GPL-2.0), postgres:16-alpine (PostgreSQL License).
# Dépendances : bash, python3, jq, openssl, curl, podman, systemd, postgresql-16 (root).

# shellcheck disable=SC2016
set -euo pipefail
export PYTHONDONTWRITEBYTECODE=1

[[ "$(id -u)" -eq 0 ]] || { echo "b16-live : root requis" >&2; exit 2; }
for t in python3 jq openssl curl podman systemctl systemd-run; do command -v "$t" > /dev/null || { echo "outil manquant : $t" >&2; exit 2; }; done
[[ -d /etc/postgresql/16/main ]] || { echo "PostgreSQL 16 absent" >&2; exit 2; }

WEB_IMAGE="mirror.gcr.io/nginxinc/nginx-unprivileged@sha256:0c79d56aee561a1d81c63f00eee5fb5fe29279560cdc55e91425133104c7fbe6"
BROKEN_IMAGE="mirror.gcr.io/library/busybox@sha256:a7dbc319b1438115a207e11930dc4bb3e643dcb3ec0bdd694bb36cd8fad289ec"
PG_IMAGE="mirror.gcr.io/library/postgres@sha256:f2f98726820d0342055351c6e9d36e705f5bfffb3dd53ff556325114b08afb6d"

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
HELPER="$ROOT/src/rootfs/usr/sbin/scanoria-helper"
PYLIB="$ROOT/src/rootfs/usr/lib/scanoria/py"
TMP=$(mktemp -d)
cleanup() {
	systemctl stop scanoria-mod-web.service > /dev/null 2>&1 || true
	rm -f /etc/containers/systemd/scanoria-mod-web*
	systemctl daemon-reload || true
	podman volume rm --force scanoria-mod-web_html > /dev/null 2>&1 || true
	podman secret rm scanoria-mod-web-db-password scanoria-mod-web-admin-password > /dev/null 2>&1 || true
	rm -rf "$TMP"
}
trap cleanup EXIT

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
	"$T/etc/containers" "$T/opt/scanoria/current" "$T/proc" "$T/var/lib" "$STUBS" "$REL" /etc/containers/systemd
ln -s /etc/containers/systemd "$T/etc/containers/systemd"
ln -s /etc/postgresql "$T/etc/postgresql"
ln -s /sys "$T/sys"
ln -s /var/lib/containers "$T/var/lib/containers"
export SCANORIA_TEST_ROOT="$T" SCANORIA_TEST_BIN="$STUBS" SCANORIA_TEST_HEALTH_TIMEOUT=120
echo 0.4.0 > "$T/opt/scanoria/current/VERSION"
cp /proc/meminfo "$T/proc/meminfo" && grep '^processor' /proc/cpuinfo > "$T/proc/cpuinfo"
echo '{"repo": "exemple/scanoria"}' > "$T/etc/scanoria/catalog.json"
openssl genpkey -algorithm ed25519 -out "$TMP/sign.key" 2> /dev/null
openssl pkey -in "$TMP/sign.key" -pubout -out "$T/etc/scanoria/update-pubkey.pem"

# Vrais outils, sauf curl : la release du catalogue est servie depuis le disque.
for c in podman systemctl sysctl runuser; do ln -s "$(command -v "$c")" "$STUBS/$c"; done
cat > "$STUBS/curl" <<-EOF
	#!/usr/bin/env python3
	import os, shutil, sys
	a = sys.argv[1:]
	url = a[-1]
	if url.startswith("http://127.0.0.1:"):
	    os.execv("$(command -v curl)", ["curl"] + a)
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
EOF
printf '#!/bin/bash\nexit 0\n' > "$STUBS/scanoria-state"
chmod 0755 "$STUBS/curl" "$STUBS/scanoria-state"

systemctl start postgresql.service
PGHBA_BACKUP="$TMP/pg_hba.conf.orig"
cp /etc/postgresql/16/main/pg_hba.conf "$PGHBA_BACKUP"

web() { # VERSION IMAGE
	jq -cn --arg v "$1" --arg img "$2" '
		{id: "web", name: "Service web de test", version: $v, type: "service", categories: ["quality"],
		 license: {spdx: "BSD-2-Clause", url: "https://exemple.test/licence", restrictions: "none"},
		 upstream: {homepage: "https://exemple.test", source: "https://exemple.test/src"},
		 image: $img, resources: {min_ram_mb: 64, min_cpu: 1, disk_mb: 50}, hostname: "web",
		 needs: {sysctl: {"fs.inotify.max_user_instances": 256, nofile: 65536}, postgres: true},
		 requires: {modules: [], feeds: []}, conflicts: [],
		 options: {type: "object", additionalProperties: false, properties: {}},
		 health: null, upgrade: {policy: "on-demand"}, testbed_archive: null, testbed_sha256: null,
		 service: {port: 8080, health_path: "/", units: [{}],
		           volumes: [{name: "html", path: "/usr/share/nginx/html"}], backup: ["html"],
		           env: {APP_DB_URL: "{db_url_jdbc}", APP_DB_USER: "{db_user}"},
		           secrets: [{name: "db-password", env: "APP_DB_PASSWORD"}, "admin-password"]}}'
}
jq -n --argjson a "$(web 1.0.0 "$WEB_IMAGE")" --argjson b "$(web 1.1.0 "$BROKEN_IMAGE")" \
	'{schema: 1, version: 1, generated_at: "2026-11-24T00:00:00Z", modules: [$a, $b], packs: []}' > "$REL/catalog-index.json"
(cd "$REL" && sha256sum catalog-index.json > SHA256SUMS)
openssl pkeyutl -sign -inkey "$TMP/sign.key" -rawin -in "$REL/SHA256SUMS" -out "$REL/SHA256SUMS.sig"
echo '[{"tag_name": "catalog-v1", "name": "Catalogue Scanoria 1", "draft": false, "prerelease": false}]' > "$TMP/api.json"

hx() {
	R=$("$HELPER" exec --origin cli --type "$1" --params "$2" 2> "$TMP/helper.err") || true
	echo "--- $1 : $(jq -c '{code, message}' <<< "${R:-{\}}")"
	sed 's/^/     /' "$TMP/helper.err"
}
code() { jq -r .code <<< "$R"; }
STATE="$T/var/lib/scanoria/modules/state.json"
mstate() { jq -r '[.modules[] | select(.id == "web")][0] | if . == null then "absent" else .status + "/" + .version end' "$STATE"; }
port() { jq -r '.modules.web.host_port' "$T/var/lib/scanoria/modules/installed.json"; }
http() { curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$(port)$1"; }
VOLDIR=/var/lib/containers/storage/volumes/scanoria-mod-web_html/_data
SECDIR="$T/var/lib/scanoria/modules/web/secrets"
psql_web() { runuser -u postgres -- psql -X -A -t -d mod_web -c "$1"; }
diag() {
	systemctl status scanoria-mod-web.service --no-pager -l 2>&1 | tail -20 || true
	journalctl -u scanoria-mod-web.service --no-pager -n 30 2>&1 || true
}

hx refresh-catalog '{}'
expect "catalogue de test" "$(code)" OK

# === Installation ===========================================================
hx install-modules '{"modules": [{"id": "web", "version": "1.0.0", "options": {}}], "accept_licenses": []}'
expect "install web (service réel, base, secrets)" "$(code)/$(mstate)" OK/healthy/1.0.0
[[ "$(code)" == OK ]] || diag
expect "unité Quadlet active" "$(systemctl is-active scanoria-mod-web.service)" active
expect "page servie par le proxy local" "$(http /)" 200
expect "réseau propre en /24 fixe" "$(podman network inspect scanoria-mod-web --format '{{range .Subnets}}{{.Subnet}}{{end}}')" 10.90.0.0/24
expect "réseau de scan interne" "$(podman network inspect scanoria-mod-web_scan --format '{{.Internal}}')" true
expect "secret monté dans le conteneur" "$(podman exec scanoria-mod-web cat /run/secrets/admin-password)" "$(cat "$SECDIR/admin-password" 2>/dev/null || echo absent)"
expect "secret en variable dans le conteneur" "$(podman exec scanoria-mod-web printenv APP_DB_PASSWORD)" "$(cat "$SECDIR/db-password" 2>/dev/null || echo absent)"
expect "aucun secret dans l'inspection du conteneur" "$(podman inspect scanoria-mod-web | grep -c -F "$(cat "$SECDIR/db-password")" || true)" 0
expect "limite nofile appliquée" "$(podman exec scanoria-mod-web sh -c 'ulimit -n')" 65536
expect "sysctl appliqué, jamais baissé" "$(( $(sysctl -n fs.inotify.max_user_instances) >= 256 ))/$([[ -f /etc/sysctl.d/60-scanoria-web.conf ]] || echo absent)" "1/absent"
expect "fichier sysctl de la racine de test" "$(grep -c '^fs.inotify.max_user_instances = ' "$T/etc/sysctl.d/60-scanoria-web.conf")" 1

# PostgreSQL : depuis le réseau du module avec le secret, et refus ailleurs.
podman pull -q "$PG_IMAGE" > /dev/null
pgq() { # réseau
	podman run --rm --network "$1" --secret "scanoria-mod-web-db-password,type=env,target=PGPASSWORD" "$PG_IMAGE" \
		psql -h 10.90.0.1 -U mod_web -d mod_web -X -A -t -c "SELECT current_user" 2>&1
}
expect "PostgreSQL joignable depuis le réseau du module" "$(pgq scanoria-mod-web)" mod_web
expect "PostgreSQL refusé depuis un autre réseau (pg_hba)" "$(pgq podman | grep -c 'no pg_hba.conf entry' || true)" 1

# === Sauvegarde et restauration =============================================
echo "marqueur b16" > "$VOLDIR/marqueur.html"
psql_web "CREATE TABLE b16 (x text); INSERT INTO b16 VALUES ('ligne');" > /dev/null
hx backup-module '{"id": "web"}'
B=$(jq -r .output.backup <<< "$R")
expect "sauvegarde" "$(code)" OK
expect "sauvegarde : base et volume" "$(jq -r '[.files[].name] | join(",")' "$T/var/lib/scanoria/backups/modules/web/$B/manifest.json")" db.dump,volume-html.tar
expect "service relancé après la copie des volumes" "$(http /marqueur.html)" 200
rm "$VOLDIR/marqueur.html"
psql_web "DROP TABLE b16;" > /dev/null
expect "données perdues" "$(http /marqueur.html)" 404
hx restore-module "$(jq -cn --arg b "$B" '{id: "web", backup: $b}')"
expect "restauration" "$(code)/$(mstate)" OK/healthy/1.0.0
expect "restauration : volume" "$(http /marqueur.html)" 200
expect "restauration : base" "$(psql_web 'SELECT x FROM b16')" ligne
expect "restauration : propriétaire de la table = rôle du module" "$(psql_web "SELECT tableowner FROM pg_tables WHERE tablename = 'b16'")" mod_web

# === Mise à jour vers une image cassée ======================================
podman rmi --ignore "$BROKEN_IMAGE" > /dev/null 2>&1 || true
hx update-module '{"id": "web", "version": "1.1.0"}'
expect "mise à jour cassée : retour arrière" "$(code)/$(mstate)" E_HEALTH_ROLLED_BACK/healthy/1.0.0
jq -r '.output.log[]?' <<< "$R" | sed 's/^/     /'
expect "après retour arrière : service et données" "$(http /marqueur.html)/$(psql_web 'SELECT x FROM b16')" 200/ligne
expect "image cassée retirée" "$(podman image exists "$BROKEN_IMAGE" && echo présente || echo retirée)" retirée

# === Relevés (contrat 11) ===================================================
U=$(python3 -I -c "import sys, json; sys.path.insert(0, '$PYLIB')
from scanoria import modules, services
print(json.dumps(services.usage(modules.load_registry())))")
echo "     $U"
expect "relevé : mémoire mesurée" "$(jq -r '.[0].usage.memory_mb > 0' <<< "$U")" true
expect "relevé : disque mesuré (base comprise)" "$(jq -r '.[0].usage.disk_mb > 0' <<< "$U")" true

# === Podman root sous le durcissement de scanoria-runner.service ============
mapfile -t PROPS < <(sed -n '/^\[Service\]/,/^\[/p' "$ROOT/src/rootfs/usr/lib/systemd/system/scanoria-runner.service" \
	| grep -E '^(Protect|ReadWritePaths|NoNewPrivileges|PrivateTmp|RestrictSUIDSGID|LockPersonality|UMask)' | sed 's/^/-p/')
mkdir -p /var/lib/scanoria/scans /etc/containers/networks
if systemd-run --wait --pipe --quiet "${PROPS[@]}" /bin/sh -c "
	podman network create --driver bridge --subnet 10.89.251.0/24 b16-hardening > /dev/null || exit 10
	podman run --rm --network=b16-hardening --read-only --cap-drop=ALL --security-opt=no-new-privileges \
		--pull=never --user 65534:65534 --entrypoint /bin/true '$WEB_IMAGE'
	rc=\$?
	podman network rm -f b16-hardening > /dev/null || rc=11
	exit \$rc" > "$TMP/hardening.log" 2>&1; then
	ok "Podman root fonctionne sous le durcissement du runner"
else
	ko "Podman root fonctionne sous le durcissement du runner"
	sed 's/^/     /' "$TMP/hardening.log"
fi
printf '     %s\n' "${PROPS[@]}"

# === Désinstallation sans conservation ======================================
hx uninstall-module '{"id": "web", "keep_data": false}'
expect "désinstallation" "$(code)/$(mstate)" OK/absent
expect "unités retirées" "$(find /etc/containers/systemd -name 'scanoria-mod-web*' | wc -l)/$(systemctl is-active scanoria-mod-web.service || true)" "0/inactive"
expect "base et rôle supprimés" "$(runuser -u postgres -- psql -X -A -t -d postgres -c "SELECT count(*) FROM pg_roles WHERE rolname = 'mod_web'")$(runuser -u postgres -- psql -X -A -t -d postgres -c "SELECT count(*) FROM pg_database WHERE datname = 'mod_web'")" 00
expect "volume supprimé" "$(podman volume exists scanoria-mod-web_html && echo présent || echo supprimé)" supprimé
expect "secrets supprimés" "$(podman secret ls --format '{{.Name}}' | grep -c scanoria-mod-web || true)/$([[ -e "$SECDIR" ]] && echo présents || echo supprimés)" 0/supprimés
expect "fichier sysctl retiré" "$([[ -e "$T/etc/sysctl.d/60-scanoria-web.conf" ]] && echo présent || echo retiré)" retiré
expect "pg_hba : plus aucun accès module" "$(grep -c mod_web /etc/postgresql/16/main/scanoria-modules-hba.conf || true)" 0

echo
echo "b16-live : $PASS réussis, $FAIL échoués"
[[ "$FAIL" -eq 0 ]]
