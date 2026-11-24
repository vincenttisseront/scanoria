#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Vincent Tisseront
#
# b16 — moteur des modules « service » (0.4, chantier A), sans root. Le helper
# tourne en mode test (SCANORIA_TEST_ROOT) sur une copie de /usr (avec un
# provision.py de test) ; podman, systemctl, sysctl, runuser et curl sont des
# bouchons. Couvre : base et rôle mod_<id>, secret db-password, pg_hba limité
# au sous-réseau du module, listen_addresses ; secrets Podman (jamais dans une
# unité ni dans l'environnement) ; réseau propre et réseau de scan interne ;
# réglages noyau par module sans jamais baisser une valeur ; limites nofile et
# nproc ; ressources (E_SERVICE_RESOURCES) ; sauvegarde (manifeste, empreintes,
# arrêt pendant la copie des volumes, rétention) ; restauration (empreintes,
# version, santé) ; mise à jour avec sauvegarde et retour arrière journalisé ;
# point d'accroche provision.py ; relevés de consommation (contrat 11) ;
# demandes hostiles (identifiants « .. », sysctl hors liste, sauvegarde
# falsifiée ou sortante, gabarit qui réclame un secret).
# Dépendances : bash, python3, jq, openssl, zstd, tar, sha256sum.

# Les motifs jq et les « bash -c » sont volontairement entre apostrophes.
# shellcheck disable=SC2016
set -euo pipefail
export PYTHONDONTWRITEBYTECODE=1

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

PASS=0
FAIL=0
ok() { PASS=$((PASS + 1)); printf 'ok   %s\n' "$1"; }
ko() { FAIL=$((FAIL + 1)); printf 'FAIL %s\n' "$1"; }
expect() { # libellé valeur_obtenue valeur_attendue
	if [[ "$2" == "$3" ]]; then ok "$1"; else ko "$1 (obtenu « $2 », attendu « $3 »)"; fi
}
for t in python3 jq openssl zstd tar sha256sum; do command -v "$t" > /dev/null || { echo "outil manquant : $t" >&2; exit 2; }; done

# Copie de /usr avec un provision.py de test (le vrai appartient au chantier SonarQube).
USR="$TMP/usr"
mkdir -p "$USR"
cp -a "$ROOT/src/rootfs/usr/." "$USR/"
PYLIB="$USR/lib/scanoria/py"
HELPER="$USR/sbin/scanoria-helper"
cat > "$PYLIB/scanoria/provision.py" <<-'EOF'
	"""provision.py de test : journalise l'appel ; échoue si le fichier « provision-fail » existe."""
	import json
	import os
	from . import common
	from .common import Fail


	def run(m, info):
	    with open(common.p("/provision.log"), "a", encoding="utf-8") as f:
	        f.write(json.dumps({"id": m["id"], "version": m["version"], "info": info}, sort_keys=True) + "\n")
	    if os.path.exists(common.p("/provision-fail")):
	        raise Fail("E_INTERNAL", "provisioning failed")


	def act_reset_service_admin(c):
	    """Demande reset-service-admin du vrai provision.py (chantier SonarQube), hors du sujet de b16."""
	    raise Fail("E_PRECONDITION", "not provided by the test provision.py")


	def purge_oneshot(now=None):
	    """Purge des valeurs à lecture unique, appelée à chaque passage du helper."""


	def data_secrets(mid):
	    """Secrets de mise en service sauvegardés avec la base : aucun pour les modules de b16."""
	    return ()
EOF

T="$TMP/root"
FIX="$TMP/fix"
STUBS="$TMP/stubs"
REL="$FIX/rel"
mkdir -p "$T"/var/lib/scanoria/requests/{tmp,incoming,work,done,failed} "$T/run/scanoria" "$T/etc/scanoria" \
	"$T/opt/scanoria/current" "$T/proc" "$T/usr/share/scanoria/schemas" "$T/etc/postgresql/16/main/conf.d" \
	"$STUBS" "$REL"
printf '# pg_hba.conf de test\nlocal all postgres peer\n' > "$T/etc/postgresql/16/main/pg_hba.conf"
chmod 0700 "$T/var/lib/scanoria/requests/incoming" "$T/var/lib/scanoria/requests/work"
export SCANORIA_TEST_ROOT="$T" SCANORIA_TEST_BIN="$STUBS"
unset SCANORIA_TEST_OWNER_UID SCANORIA_TEST_NOW
export SCANORIA_TEST_HEALTH_TIMEOUT=1
CALLS="$TMP/calls.log"
SQL="$TMP/sql.log"
: > "$CALLS"
: > "$SQL"

echo 0.4.0 > "$T/opt/scanoria/current/VERSION"
printf 'MemTotal:       16384000 kB\n' > "$T/proc/meminfo"
for i in 0 1 2 3; do printf 'processor\t: %d\n' "$i"; done > "$T/proc/cpuinfo"
echo '{"fqdn": "analyse.exemple.test"}' > "$T/etc/scanoria/appliance.json"
echo '{"repo": "exemple/scanoria"}' > "$T/etc/scanoria/catalog.json"
cat > "$T/usr/share/scanoria/schemas/catalog-index.schema.json" <<-'EOF'
	{"type": "object", "required": ["schema", "version", "generated_at", "modules", "packs"],
	 "properties": {"modules": {"type": "array"}, "packs": {"type": "array"}}}
EOF
openssl genpkey -algorithm ed25519 -out "$TMP/sign.key" 2> /dev/null
openssl pkey -in "$TMP/sign.key" -pubout -out "$T/etc/scanoria/update-pubkey.pem"

# --- Bouchons ------------------------------------------------------------------
cat > "$STUBS/curl" <<-EOF
	#!/usr/bin/env python3
	import json, os, re, shutil, sys
	a = sys.argv[1:]
	out = a[a.index("--output") + 1] if "--output" in a else None
	wo = a[a.index("--write-out") + 1] if "--write-out" in a else ""
	url, fix = a[-1], "$FIX"
	code, src = 404, None
	if url == "https://api.github.com/repos/exemple/scanoria/releases?per_page=30":
	    code, src = 200, fix + "/api-releases.json"
	elif url.startswith("https://github.com/exemple/scanoria/releases/download/"):
	    p = fix + "/rel/" + url.split("/releases/download/", 1)[1]
	    if os.path.isfile(p):
	        code, src = 200, p
	elif url.startswith("http://127.0.0.1:"):
	    code = 200
	    if os.path.exists(fix + "/health-fail-image"):
	        bad = open(fix + "/health-fail-image").read().strip()
	        for n in os.listdir("$T/etc/containers/systemd"):
	            if n.endswith(".container") and ("Image=" + bad + "\n") in open("$T/etc/containers/systemd/" + n).read():
	                code = 503
	if out and src and code == 200 and out != "/dev/null":
	    shutil.copyfile(src, out)
	sys.stdout.write(wo.replace("%{http_code}", str(code)).replace("%{redirect_url}", ""))
EOF
# podman : « volume export » écrit une archive dont le contenu dépend du volume.
cat > "$STUBS/podman" <<-EOF
	#!/bin/bash
	jq -cn '["podman"] + \$ARGS.positional' --args -- "\$@" >> "$CALLS"
	case "\$1 \${2:-}" in
	"volume export") printf 'contenu de %s\n' "\$5" > "\$4"; exit 0 ;;
	"secret create") [[ -e "$FIX/secret-fail" ]] && exit 125; exit 0 ;;
	"pull "*) exit 0 ;;
	esac
	exit 0
EOF
cat > "$STUBS/systemctl" <<-EOF
	#!/bin/bash
	jq -cn '["systemctl"] + \$ARGS.positional' --args -- "\$@" >> "$CALLS"
	[[ "\$1" == start && -e "$FIX/systemctl-fail-start" ]] && exit 1
	if [[ "\$1" == is-active ]]; then [[ -e "$FIX/stopped" ]] && exit 3; exit 0; fi
	exit 0
EOF
# sysctl -n : valeur courante simulée par fix/sysctl-<clé>.
cat > "$STUBS/sysctl" <<-EOF
	#!/bin/bash
	jq -cn '["sysctl"] + \$ARGS.positional' --args -- "\$@" >> "$CALLS"
	if [[ "\$1" == -n ]]; then cat "$FIX/sysctl-\$2" 2> /dev/null || exit 1; fi
	exit 0
EOF
cat > "$STUBS/runuser" <<-EOF
	#!/bin/bash
	jq -cn '["runuser"] + \$ARGS.positional' --args -- "\$@" >> "$CALLS"
	if [[ " \$* " == *" -c "* ]]; then
		case "\$*" in
		*pg_database_size*) echo 52428800 ;;
		esac
		exit 0
	fi
	cat >> "$SQL"
	[[ " \$* " == *" pg_dump "* ]] && printf 'PGDMP factice\n'
	exit 0
EOF
printf '#!/bin/bash\nexit 0\n' > "$STUBS/scanoria-state"
chmod 0755 "$STUBS"/*

# --- Catalogue -----------------------------------------------------------------
DIGEST=$(printf '%064d' 0 | tr 0 a)
img() { printf 'registry.exemple.test/scanoria/%s@sha256:%s' "$1" "$DIGEST"; }
# svc ID VERSION [jq de surcharge] : module service avec base, deux volumes, secrets et sysctl.
svc() {
	jq -cn --arg id "$1" --arg ver "$2" --arg img "$(img "$1-$2")" '
		{id: $id, name: $id, version: $ver, type: "service", categories: ["quality"],
		 license: {spdx: "MIT", url: "https://exemple.test/licence", restrictions: "none"},
		 upstream: {homepage: "https://exemple.test", source: "https://exemple.test/src"},
		 image: $img, resources: {min_ram_mb: 1024, min_cpu: 1, disk_mb: 100}, hostname: $id,
		 needs: {sysctl: {"vm.max_map_count": 524288, nofile: 131072, nproc: 8192}, postgres: true},
		 requires: {modules: [], feeds: []}, conflicts: [],
		 options: {type: "object", additionalProperties: false, properties: {}},
		 health: null, upgrade: {policy: "on-demand"}, testbed_archive: null, testbed_sha256: null,
		 service: {port: 9000, health_path: "/api/status", units: [{}],
		           volumes: [{name: "data", path: "/opt/app/data"}, {name: "logs", path: "/opt/app/logs"}],
		           backup: ["data"],
		           env: {APP_JDBC_URL: "{db_url_jdbc}", APP_JDBC_USERNAME: "{db_user}"},
		           secrets: [{name: "db-password", env: "APP_JDBC_PASSWORD"}, "admin-password"]}}
		| '"${3:-.}"
}
publish() { # N MODULES_JSON
	local d="$REL/catalog-v$1"
	rm -rf "$d" && mkdir -p "$d"
	jq -n --argjson n "$1" --argjson mods "$2" \
		'{schema: 1, version: $n, generated_at: "2026-11-24T00:00:00Z", modules: $mods, packs: []}' > "$d/catalog-index.json"
	printf '%s  catalog-index.json\n' "$(sha256sum "$d/catalog-index.json" | cut -d' ' -f1)" > "$d/SHA256SUMS"
	openssl pkeyutl -sign -inkey "$TMP/sign.key" -rawin -in "$d/SHA256SUMS" -out "$d/SHA256SUMS.sig"
	jq -n --arg tag "catalog-v$1" '[{tag_name: $tag, name: "Catalogue Scanoria", draft: false, prerelease: false}]' \
		> "$FIX/api-releases.json"
}

hx() {
	R=$("$HELPER" exec --origin cli --type "$1" --params "$2" 2> "$TMP/helper.err") || true
	[[ -n "$R" ]] || { R='{"code":"NO_OUTPUT"}'; sed 's/^/     /' "$TMP/helper.err"; }
}
code() { jq -r .code <<< "$R"; }
STATE="$T/var/lib/scanoria/modules/state.json"
UNITS="$T/etc/containers/systemd"
mstate() { [[ -f "$STATE" ]] || { echo absent; return; }; jq -r --arg id "$1" '[.modules[] | select(.id == $id)][0] | if . == null then "absent" else .status + "/" + (.enabled|tostring) + "/" + .version end' "$STATE"; }
called() { grep -c -F -- "$1" "$CALLS" || true; }
inst() { jq -cn --arg id "$1" --arg v "$2" '{modules: [{id: $id, version: $v, options: {}}], accept_licenses: []}'; }
pyrun() { python3 -I -c "import sys; sys.path.insert(0, '$PYLIB')
$1" "${@:2}"; }

APP1=$(svc app 1.0.0)
APP2=$(svc app 1.1.0)
APP3=$(svc app 1.2.0)
SMALL=$(svc small 1.0.0 '.needs = {sysctl: {"vm.max_map_count": 262144}, postgres: false} | .service.secrets = [] | .service.env = {} | .service.backup = null')
HUGE=$(svc huge 1.0.0 '.resources.min_ram_mb = 20000')
SCAN_LIMIT=$(svc scanlimit 1.0.0 '.type = "scanner" | .service = null | .needs = {sysctl: {nofile: 4096}, postgres: false}
	| .scan = {inputs: ["repo"], command: ["x"], timeout_s: 60, network: "none"}')
publish 1 "$(jq -cn --argjson a "[$APP1,$APP2,$APP3,$SMALL,$HUGE]" '$a')"
hx refresh-catalog '{}'
expect "catalogue de test accepté" "$(code)" OK

# === 1. Demandes et manifestes hostiles =====================================
CATN=1
hostile() { # libellé jq_de_surcharge code_attendu
	CATN=$((CATN + 1))
	publish "$CATN" "$(jq -cn --argjson a "[$(svc evil 1.0.0 "$2")]" '$a')"
	hx refresh-catalog '{}'
	hx install-modules "$(inst evil 1.0.0)"
	expect "manifeste hostile : $1" "$(code)/$(mstate evil)" "$3/absent"
}
hostile "sysctl hors liste blanche" '.needs.sysctl = {"kernel.core_pattern": 1}' E_SERVICE_RESOURCES
hostile "sysctl au-delà de la borne" '.needs.sysctl = {"vm.max_map_count": 4294967296}' E_SERVICE_RESOURCES
hostile "nofile au-delà de la borne" '.needs.sysctl = {nofile: 99999999}' E_SERVICE_RESOURCES
hostile "gabarit qui réclame le mot de passe" '.service.env = {PW: "{db_password}"}' E_INVALID_PARAM
hostile "variable LD_PRELOAD" '.service.env = {LD_PRELOAD: "/tmp/x.so"}' E_INVALID_PARAM
hostile "secret au nom « ../x »" '.service.secrets = ["../x"]' E_INVALID_PARAM
hostile "secret injecté dans PATH" '.service.secrets = [{name: "tok", env: "PATH"}]' E_INVALID_PARAM
hostile "db-password sans PostgreSQL" '.needs.postgres = false | .service.secrets = ["db-password"]' E_INVALID_PARAM
hostile "volume sauvegardé non déclaré" '.service.backup = ["etc"]' E_INVALID_PARAM
hostile "chemin de volume « .. »" '.service.volumes = [{name: "data", path: "/opt/../etc"}]' E_INVALID_PARAM
expect "aucune image tirée pour les manifestes hostiles" "$(called '"pull"')" 0
publish $((CATN + 1)) "$(jq -cn --argjson a "[$APP1,$APP2,$APP3,$SMALL,$HUGE,$SCAN_LIMIT]" '$a')"
hx refresh-catalog '{}'
hx install-modules "$(inst scanlimit 1.0.0)"
expect "limite d'unité refusée pour un scanner" "$(code)" E_RESOURCES
hx backup-module '{"id": "../etc"}'
expect "backup : identifiant « .. » refusé" "$(code)" E_SCHEMA
hx restore-module '{"id": "app", "backup": "../../../etc"}'
expect "restore : sauvegarde « .. » refusée" "$(code)" E_SCHEMA
hx restore-module '{"id": "app", "backup": "20261124T000000Z", "path": "/etc"}'
expect "restore : champ inconnu refusé" "$(code)" E_SCHEMA
hx backup-module '{"id": "app"}'
expect "backup d'un module absent" "$(code)" E_NOT_FOUND

# === 2. Ressources ==========================================================
hx install-modules "$(inst huge 1.0.0)"
expect "service trop gourmand : E_SERVICE_RESOURCES" "$(code)/$(jq -r '.output.resource + "/" + (.output.modules[0])' <<< "$R")" E_SERVICE_RESOURCES/ram/huge
expect "le refus dit ce qui manque" "$(jq -r '.output.needed_mb > .output.available_mb' <<< "$R")" true

# === 3. Installation d'un service ===========================================
echo 1048576 > "$FIX/sysctl-vm.max_map_count"   # valeur système plus haute (Ubuntu 24.04)
hx install-modules "$(inst app 1.0.0)"
expect "install app" "$(code)/$(mstate app)" OK/healthy/true/1.0.0
CONT="$UNITS/scanoria-mod-app.container"
SECDIR="$T/var/lib/scanoria/modules/app/secrets"
expect "secrets générés en 0600 dans un répertoire 0700" "$(stat -c %a "$SECDIR")/$(stat -c %a "$SECDIR/db-password")/$(stat -c %a "$SECDIR/admin-password")" 700/600/600
expect "secrets aléatoires (48 hex) et distincts" "$(grep -c -E '^[0-9a-f]{48}$' "$SECDIR/db-password" "$SECDIR/admin-password" | grep -c ':1$')/$([[ "$(cat "$SECDIR/db-password")" != "$(cat "$SECDIR/admin-password")" ]] && echo distincts)" 2/distincts
PW=$(cat "$SECDIR/db-password")
expect "aucun secret dans les unités ni l'environnement" "$(grep -r -l -F -e "$PW" -e "$(cat "$SECDIR/admin-password")" "$UNITS" "$T/etc/scanoria" "$CALLS" | wc -l)" 0
expect "secret Podman créé depuis le fichier root" "$(called "\"secret\",\"create\",\"scanoria-mod-app-db-password\",\"$SECDIR/db-password\"")" 1
expect "mot de passe injecté par variable" "$(grep -c -x 'Secret=scanoria-mod-app-db-password,type=env,target=APP_JDBC_PASSWORD' "$CONT")" 1
expect "secret admin monté en /run/secrets" "$(grep -c -x 'Secret=scanoria-mod-app-admin-password,type=mount,target=admin-password' "$CONT")" 1
expect "réseau propre en /24 fixe" "$(grep -c -x 'Subnet=10.90.0.0/24' "$UNITS/scanoria-mod-app.network")/$(grep -c -x 'Gateway=10.90.0.1' "$UNITS/scanoria-mod-app.network")" 1/1
expect "réseau de scan interne" "$(grep -c -x 'Internal=true' "$UNITS/scanoria-mod-app_scan.network")/$(grep -c -x 'Network=scanoria-mod-app_scan.network' "$CONT")" 1/1
expect "limites nofile et nproc" "$(grep -c -x -e 'Ulimit=nofile=131072:131072' -e 'Ulimit=nproc=8192:8192' "$CONT")" 2
expect "JDBC vers la passerelle du module" "$(grep -c -x 'APP_JDBC_URL=jdbc:postgresql://10.90.0.1:5432/mod_app' "$T/etc/scanoria/modules/app/env")" 1
expect "fichier d'environnement référencé" "$(grep -c -x "EnvironmentFile=$T/etc/scanoria/modules/app/env" "$CONT")" 1
expect "rôle et base mod_app créés" "$(grep -c -F "\\set name 'mod_app'" "$SQL")/$(grep -c -F 'CREATE DATABASE %I OWNER %I' "$SQL")" 1/1
expect "mot de passe passé par variable psql, jamais en argument" "$(called "$PW")/$(grep -c -F "\\set pw '$PW'" "$SQL")" 0/1
expect "pg_hba : sous-réseau du module seul, scram" "$(grep -c -x 'host mod_app mod_app 10.90.0.0/24 scram-sha-256' "$T/etc/postgresql/16/main/scanoria-modules-hba.conf")" 1
expect "pg_hba.conf inclut le fichier des modules" "$(grep -c -x 'include_if_exists scanoria-modules-hba.conf' "$T/etc/postgresql/16/main/pg_hba.conf")" 1
expect "listen_addresses posé, PostgreSQL redémarré" "$(grep -c -x "listen_addresses = '\\*'" "$T/etc/postgresql/16/main/conf.d/scanoria_modules.conf")/$(called '"systemctl","restart","postgresql.service"')" 1/1
expect "sysctl : fichier par module" "$(grep -c -x 'vm.max_map_count = 1048576' "$T/etc/sysctl.d/60-scanoria-app.conf")" 1
expect "sysctl : valeur système plus haute jamais baissée" "$(called '"-w","vm.max_map_count=')" 0
expect "sysctl : nofile/nproc hors de sysctl.d" "$(grep -c -e nofile -e nproc "$T/etc/sysctl.d/60-scanoria-app.conf" || true)" 0
expect "provision appelé après la santé" "$(jq -r '.info.phase + "/" + .info.network + "/" + (.info.host_port|tostring|.[0:2])' "$T/provision.log")" install/scanoria-mod-app/18
expect "provision : répertoire des secrets transmis" "$(jq -r .info.secrets_dir "$T/provision.log")" "$T/var/lib/scanoria/modules/app/secrets"
expect "état : sauvegardes listées (aucune)" "$(jq -c '.modules[] | select(.id=="app") | .backups' "$STATE")" "[]"

# Sans valeur système lisible : small demande 262144, app 524288 ; aucun
# fichier ne doit poser moins que le maximum des modules installés.
rm "$FIX/sysctl-vm.max_map_count"
hx install-modules "$(inst small 1.0.0)"
expect "install small (sans base)" "$(code)/$(mstate small)" OK/healthy/true/1.0.0
expect "sysctl : aucun fichier ne baisse la valeur d'un autre module" "$(grep -h 'vm.max_map_count' "$T"/etc/sysctl.d/60-scanoria-*.conf | sort -u)" "vm.max_map_count = 524288"
expect "sysctl : valeur appliquée en hausse seulement" "$(called '"-w","vm.max_map_count=524288"')" 1
expect "second module : second /24" "$(grep -c -x 'Subnet=10.90.1.0/24' "$UNITS/scanoria-mod-small.network")" 1
expect "pg_hba : aucun accès pour un module sans base" "$(grep -c small "$T/etc/postgresql/16/main/scanoria-modules-hba.conf" || true)" 0

# === 4. Sauvegarde ==========================================================
: > "$CALLS"
hx backup-module '{"id": "app"}'
expect "backup app" "$(code)" OK
B1=$(jq -r .output.backup <<< "$R")
BD="$T/var/lib/scanoria/backups/modules/app/$B1"
expect "répertoire de sauvegarde 0700" "$(stat -c %a "$BD")" 700
expect "base et volume déclaré seulement (logs exclu)" "$(find "$BD" -type f -printf '%f\n' | sort | tr '\n' ' ')" "db.dump manifest.json volume-data.tar "
expect "manifeste : version, image, empreintes" "$(jq -r '.module + "/" + .module_version + "/" + .reason + "/" + (.image|split("@")[1][0:7])' "$BD/manifest.json")" app/1.0.0/manual/sha256:
expect "manifeste : SHA-256 exacts" "$(jq -r '.files[] | .sha256 + "  " + .name' "$BD/manifest.json" | (cd "$BD" && sha256sum -c --quiet - && echo ok))" ok
expect "module arrêté pendant la copie des volumes, puis relancé" "$(grep -n -F -e '"stop","scanoria-mod-app.service"' -e '"volume","export"' -e '"start","scanoria-mod-app.service"' "$CALLS" | cut -d: -f2 | jq -r '.[1]' | tr '\n' ' ')" "stop volume start "
expect "état : sauvegarde listée" "$(jq -r '.modules[] | select(.id=="app") | .backups[0] | .id + "/" + .reason + "/" + (.database|tostring) + "/" + (.volumes|join(","))' "$STATE")" "$B1/manual/true/data"
touch "$FIX/stopped"
: > "$CALLS"
hx backup-module '{"id": "app"}'
expect "module arrêté : pas relancé après la sauvegarde" "$(code)/$(called '"start","scanoria-mod-app.service"')" OK/0
rm "$FIX/stopped"
for _ in 1 2 3; do hx backup-module '{"id": "app"}'; done
expect "rétention : 3 sauvegardes gardées" "$(find "$T/var/lib/scanoria/backups/modules/app" -mindepth 1 -maxdepth 1 | wc -l)/$(jq '.modules[] | select(.id=="app") | .backups | length' "$STATE")" 3/3
LAST=$(jq -r '.modules[] | select(.id=="app") | .backups[0].id' "$STATE")
mkdir "$T/var/lib/scanoria/backups/modules/app/20990101T000000Z"
hx backup-module '{"id": "app"}'
expect "sauvegarde interrompue (sans manifeste) retirée" "$([[ -e "$T/var/lib/scanoria/backups/modules/app/20990101T000000Z" ]] && echo présente || echo retirée)" retirée
hx backup-module '{"id": "small"}'
expect "backup d'un service sans base ni volume sauvegardé" "$(code)" OK

# === 5. Restauration ========================================================
LAST=$(jq -r '.modules[] | select(.id=="app") | .backups[0].id' "$STATE")
LD="$T/var/lib/scanoria/backups/modules/app/$LAST"
hx restore-module '{"id": "app", "backup": "20000101T000000Z"}'
expect "restore : sauvegarde inconnue" "$(code)" E_BACKUP_NOT_FOUND
cp "$LD/volume-data.tar" "$TMP/v.tar"
echo altéré >> "$LD/volume-data.tar"
: > "$CALLS"
hx restore-module "$(jq -cn --arg b "$LAST" '{id: "app", backup: $b}')"
expect "restore : empreinte fausse refusée avant tout arrêt" "$(code)/$(called '"stop"')" E_BACKUP_INVALID/0
cp "$TMP/v.tar" "$LD/volume-data.tar"
touch "$LD/intrus.tar"
hx restore-module "$(jq -cn --arg b "$LAST" '{id: "app", backup: $b}')"
expect "restore : fichier non listé refusé" "$(code)" E_BACKUP_INVALID
rm "$LD/intrus.tar"
cp "$LD/manifest.json" "$TMP/man.json"
jq '.files[0].name = "../../../etc/passwd"' "$TMP/man.json" > "$LD/manifest.json"
hx restore-module "$(jq -cn --arg b "$LAST" '{id: "app", backup: $b}')"
expect "restore : manifeste avec chemin sortant refusé" "$(code)" E_BACKUP_INVALID
jq '.module = "small"' "$TMP/man.json" > "$LD/manifest.json"
hx restore-module "$(jq -cn --arg b "$LAST" '{id: "app", backup: $b}')"
expect "restore : manifeste d'un autre module refusé" "$(code)" E_BACKUP_INVALID
cp "$TMP/man.json" "$LD/manifest.json"
mv "$LD" "$TMP/ailleurs" && ln -s "$TMP/ailleurs" "$LD"
hx restore-module "$(jq -cn --arg b "$LAST" '{id: "app", backup: $b}')"
expect "restore : lien symbolique refusé" "$(code)" E_BACKUP_INVALID
rm "$LD" && mv "$TMP/ailleurs" "$LD"
: > "$CALLS"
: > "$SQL"
hx restore-module "$(jq -cn --arg b "$LAST" '{id: "app", backup: $b}')"
expect "restore app" "$(code)/$(mstate app)" OK/healthy/true/1.0.0
expect "restore : base recréée puis pg_restore" "$(grep -c -F 'DROP DATABASE IF EXISTS %I WITH (FORCE)' "$SQL")/$(grep -F '"runuser"' "$CALLS" | grep -c -F '/usr/bin/pg_restore' || true)" 1/1
expect "restore : volume recréé puis importé" "$(grep -n -F -e '"volume","rm","--force","scanoria-mod-app_data"' -e '"volume","create","scanoria-mod-app_data"' -e '"volume","import","scanoria-mod-app_data"' "$CALLS" | cut -d: -f2 | jq -r '.[2]' | tr '\n' ' ')" "rm create import "
expect "restore : arrêt, puis santé attendue" "$(called '"stop","scanoria-mod-app.service"')/$(called '"start","scanoria-mod-app.service"')" 1/1
touch "$FIX/systemctl-fail-start"
hx restore-module "$(jq -cn --arg b "$LAST" '{id: "app", backup: $b}')"
expect "restore sans santé : module en échec, erreur notée" "$(code)/$(mstate app)/$(jq -r '.modules[] | select(.id=="app") | .last_error | startswith("restore of")' "$STATE")" E_INTERNAL/failed/true/1.0.0/true
rm "$FIX/systemctl-fail-start"
hx restore-module "$(jq -cn --arg b "$LAST" '{id: "app", backup: $b}')"
expect "restore depuis l'état en échec" "$(code)/$(mstate app)" OK/healthy/true/1.0.0

# === 6. Mise à jour : sauvegarde d'office, retour arrière ===================
img app-1.1.0 > "$FIX/health-fail-image"
: > "$CALLS"
hx update-module '{"id": "app", "version": "1.1.0"}'
expect "update cassée → version précédente gardée" "$(code)/$(mstate app)" E_HEALTH_ROLLED_BACK/healthy/true/1.0.0
UB=$(jq -r .output.backup <<< "$R")
expect "update : sauvegarde faite avant tout changement" "$(jq -r .reason "$T/var/lib/scanoria/backups/modules/app/$UB/manifest.json")/$(grep -n -F -e '"volume","export"' -e '"pull"' "$CALLS" | head -1 | cut -d: -f2 | jq -r '.[1]')" update/volume
expect "update : retour arrière journalisé" "$(jq -r '.output.log | map(split(" ")[0]) | join(",")' <<< "$R")" "backup,pulled,failed:,restored,previous"
expect "update : unités d'avant remises" "$(grep -c -F "Image=$(img app-1.0.0)" "$CONT")" 1
expect "update : image cassée retirée" "$(called "\"rmi\",\"--ignore\",\"$(img app-1.1.0)\"")" 1
rm "$FIX/health-fail-image"
touch "$T/provision-fail"
hx update-module '{"id": "app", "version": "1.1.0"}'
expect "update : échec de provision → retour arrière" "$(code)/$(mstate app)" E_HEALTH_ROLLED_BACK/healthy/true/1.0.0
rm "$T/provision-fail"
hx update-module '{"id": "app", "version": "1.1.0"}'
expect "update app" "$(code)/$(mstate app)/$(jq -r '.output.log[0] | startswith("backup ")' <<< "$R")" OK/healthy/true/1.1.0/true
expect "update : provision rappelé (phase update)" "$(tail -1 "$T/provision.log" | jq -r '.version + "/" + .info.phase')" 1.1.0/update
expect "update : même secret, même sous-réseau" "$(cat "$SECDIR/db-password")/$(grep -c -x 'Subnet=10.90.0.0/24' "$UNITS/scanoria-mod-app.network")" "$PW/1"
OLD=$(jq -r '[.modules[] | select(.id=="app") | .backups[] | select(.module_version == "1.0.0")][0].id' "$STATE")
hx restore-module "$(jq -cn --arg b "$OLD" '{id: "app", backup: $b}')"
expect "restore d'une sauvegarde d'une autre version refusé" "$(code)/$(jq -r .output.backup_version <<< "$R")" E_BACKUP_INVALID/1.0.0

# === 7. Désactivation, réactivation =========================================
hx set-module-state '{"id": "app", "enabled": false}'
expect "désactivation" "$(code)/$(mstate app)" OK/disabled/false/1.1.0
hx set-module-state '{"id": "app", "enabled": true}'
expect "réactivation (provision rappelé)" "$(code)/$(tail -1 "$T/provision.log" | jq -r .info.phase)" OK/enable

# === 8. Relevés de consommation (contrat 11) ================================
CG="$T/sys/fs/cgroup/system.slice/scanoria-mod-app.service"
mkdir -p "$CG" "$T/var/lib/containers/storage/volumes/scanoria-mod-app_data/_data"
echo $((300 << 20)) > "$CG/memory.current"
printf 'anon 1\ninactive_file %d\n' $((100 << 20)) > "$CG/memory.stat"
printf 'usage_usec 1000000\nuser_usec 1\n' > "$CG/cpu.stat"
head -c 3145728 /dev/zero > "$T/var/lib/containers/storage/volumes/scanoria-mod-app_data/_data/f"
U1=$(pyrun 'from scanoria import modules, services; import json; print(json.dumps(services.usage(modules.load_registry(), now=1000.0)))')
expect "relevé : modules permanents seulement" "$(jq -r 'map(.id) | join(",")' <<< "$U1")" app,small
expect "relevé : mémoire hors cache inactif" "$(jq -r '.[0].usage.memory_mb' <<< "$U1")" 200
expect "relevé : CPU inconnu au premier relevé" "$(jq -r '.[0].usage.cpu_pct' <<< "$U1")" null
expect "relevé : disque = volumes + base" "$(jq -r '.[0].usage.disk_mb' <<< "$U1")" 53
expect "relevé : module arrêté à zéro" "$(jq -c '.[1].usage | [.memory_mb, .cpu_pct]' <<< "$U1")" "[0,0.0]"
printf 'usage_usec 31000000\n' > "$CG/cpu.stat"
U2=$(pyrun 'from scanoria import modules, services; import json; print(json.dumps(services.usage(modules.load_registry(), now=1060.0)))')
expect "relevé : CPU moyen depuis le relevé précédent" "$(jq -r '.[0].usage.cpu_pct' <<< "$U2")" 50.0
expect "relevé : disque mis en cache 15 min" "$(grep -c pg_database_size "$CALLS")" 1
expect "relevé conforme au schéma de l'état" "$(pyrun '
import json
from scanoria import schema
s = schema.load("schemas", "state").schema["properties"]["modules_usage"]
print("ok" if not schema.Validator(s).errors(json.loads(sys.argv[1])) else "ko")' "$U2")" ok
expect "état des relevés en 0600" "$(stat -c %a "$T/run/scanoria/modules-usage.json")" 600

# === 9. Désinstallation =====================================================
hx uninstall-module '{"id": "small", "keep_data": false}'
expect "uninstall small" "$(code)/$(mstate small)" OK/absent
expect "sysctl de small retiré, celui d'app gardé" "$(find "$T/etc/sysctl.d" -name '60-scanoria-*.conf' -printf '%f\n')" 60-scanoria-app.conf
expect "sauvegardes de small supprimées avec les données" "$([[ -e "$T/var/lib/scanoria/backups/modules/small" ]] && echo présentes || echo supprimées)" supprimées
hx uninstall-module '{"id": "app", "keep_data": true}'
expect "uninstall app en gardant les données" "$(code)/$(mstate app)" OK/absent
expect "données gardées : secrets et sauvegardes" "$([[ -f "$SECDIR/db-password" && -d "$T/var/lib/scanoria/backups/modules/app" ]] && echo gardées)" gardées
expect "pg_hba : accès retiré" "$(grep -c mod_app "$T/etc/postgresql/16/main/scanoria-modules-hba.conf" || true)" 0
expect "secrets Podman retirés" "$(grep -F 'scanoria-mod-app-db-password' "$CALLS" | tail -1 | grep -c '"secret","rm"')" 1
expect "aucun fichier sysctl restant" "$(find "$T/etc/sysctl.d" -name '60-scanoria-*.conf' | wc -l)" 0
hx install-modules "$(inst app 1.2.0)"
expect "réinstallation : mot de passe gardé repris" "$(code)/$([[ "$(cat "$SECDIR/db-password")" == "$PW" ]] && echo même)" OK/même
touch "$FIX/secret-fail"
hx uninstall-module '{"id": "app", "keep_data": false}'
: > "$SQL"
hx install-modules "$(inst app 1.2.0)"
expect "secret Podman impossible → retour arrière complet" "$(code)/$(mstate app)/$([[ -e "$T/var/lib/scanoria/modules/app" ]] && echo reste || echo propre)/$(grep -c 'DROP ROLE' "$SQL")" E_INTERNAL/absent/propre/1
rm "$FIX/secret-fail"

# === 9 bis. Variantes d'image (option « branches », plugin de branches) =====
VIMG="registry.exemple.test/scanoria/brv-plugin@sha256:$(printf '%064d' 0 | tr 0 b)"
BRV_OPT='.needs = {sysctl: {}, postgres: false} | .service.secrets = [] | .service.env = {} | .service.backup = null
	| .options.properties = {branches: {type: "boolean", default: true}} | .service.features = ["branches"]'
BRV_VAR='.service.variants = [{feature: "branches", option: "branches", image: $v, version: "2.0.7", base_version: "2.0.0",
	license: {spdx: "LGPL-3.0-only", url: "https://exemple.test/l", verified_at: "2026-11-24"},
	upstream: {source: "https://exemple.test/s"},
	leaves: [{volume: "data", dir: "plugins", prefix: "brv-plugin"}]}]'
BRV1=$(svc brv 2.0.0 "$BRV_OPT | .service.variants = []")
BRV1V=$(jq -c --arg v "$VIMG" "$BRV_VAR" <<< "$BRV1")
BRV2=$(svc brv 2.1.0 "$BRV_OPT | .service.variants = []")
publish $((CATN + 2)) "$(jq -cn --argjson a "[$APP1,$APP2,$APP3,$SMALL,$HUGE,$SCAN_LIMIT,$BRV1]" '$a')"
hx refresh-catalog '{}'
hx install-modules "$(inst brv 2.0.0)"
BCONT="$UNITS/scanoria-mod-brv.container"
feat() { jq -r '.modules[] | select(.id=="brv") | .features.branches | (.active|tostring) + "/" + (.code // "-")' "$STATE"; }
expect "variante : sans plugin compatible, image d'origine" "$(code)/$(mstate brv)/$(grep -c -F "Image=$(img brv-2.0.0)" "$BCONT")" OK/healthy/true/2.0.0/1
expect "variante : fonction indisponible publiée avec sa raison" "$(feat)" false/unavailable
hx update-module '{"id": "brv", "version": "2.0.0"}'
expect "variante : même version sans changement d'image refusée" "$(code)" E_VERSION
publish $((CATN + 3)) "$(jq -cn --argjson a "[$APP1,$APP2,$APP3,$SMALL,$HUGE,$SCAN_LIMIT,$BRV1V,$BRV2]" '$a')"
hx refresh-catalog '{}'
: > "$CALLS"
hx update-module '{"id": "brv", "version": "2.0.0"}'
expect "variante devenue compatible : appliquée comme mise à jour" "$(code)/$(mstate brv)" OK/healthy/true/2.0.0
expect "variante : image du plugin tirée puis utilisée" "$(called "\"pull\",\"--quiet\",\"$VIMG\"")/$(grep -c -F "Image=$VIMG" "$BCONT")" 1/1
expect "variante : sauvegarde avant le changement d'image" "$(jq -r '.output.log[0] | startswith("backup ")' <<< "$R")" true
expect "variante : fonction active" "$(feat)" true/-
expect "variante : image d'origine retirée" "$(called "\"rmi\",\"--ignore\",\"$(img brv-2.0.0)\"")" 1
hx update-module '{"id": "brv", "version": "2.0.0"}'
expect "variante déjà appliquée : rien à mettre à jour" "$(code)" E_VERSION
: > "$CALLS"
hx update-module '{"id": "brv", "version": "2.1.0"}'
expect "nouvelle version sans plugin compatible : image d'origine" "$(code)/$(mstate brv)/$(grep -c -F "Image=$(img brv-2.1.0)" "$BCONT")" OK/healthy/true/2.1.0/1
expect "fichiers du plugin cherchés dans le volume avant le démarrage" "$(called '"volume","inspect","--format","{{.Mountpoint}}","scanoria-mod-brv_data"')" 1
expect "fonction de nouveau indisponible" "$(feat)" false/unavailable
expect "image du plugin retirée" "$(called "\"rmi\",\"--ignore\",\"$VIMG\"")" 1
hx uninstall-module '{"id": "brv", "keep_data": false}'
hx install-modules "$(jq -cn '{modules: [{id: "brv", version: "2.0.0", options: {branches: false}}], accept_licenses: []}')"
expect "option « branches » à false : image d'origine même avec variante" "$(code)/$(grep -c -F "Image=$(img brv-2.0.0)" "$BCONT")/$(feat)" OK/1/false/disabled
hx uninstall-module '{"id": "brv", "keep_data": false}'
expect "variante : désinstallation" "$(code)/$(mstate brv)" OK/absent
CATN=$((CATN + 3))
# Écartée dès la vérification du catalogue (check_module) : introuvable ensuite.
hostile "variante non épinglée" "$BRV_OPT"' | .service.variants = [{feature: "branches", option: "branches", image: "registry.exemple.test/x:latest",
	version: "1.0.1", base_version: "1.0.0", license: {spdx: "MIT", url: "https://exemple.test", verified_at: "2026-11-24"},
	upstream: {source: "https://exemple.test"}}]' E_NOT_FOUND

# === 10. Fichiers livrés ====================================================
for f in backup-module restore-module; do
	expect "schéma de demande $f chargeable" "$(pyrun '
from scanoria import schema
schema.load("requests", sys.argv[1]); print("ok")' "$f")" ok
done
expect "pare-feu : PostgreSQL depuis le bloc des modules" "$(grep -c -F 'ip saddr 10.90.0.0/16 tcp dport 5432 accept' "$ROOT/src/rootfs/usr/share/scanoria/nftables/scanoria.nft.tmpl")/$(grep -c -x 'pool = 10.90.0.0/16' "$ROOT/src/rootfs/usr/share/scanoria/modules/services-network.conf")" 1/1
U="$ROOT/src/rootfs/usr/lib/systemd/system/scanoria-runner.service"
for d in 'ProtectSystem=strict' 'ProtectHome=yes' 'PrivateTmp=yes' 'ProtectKernelModules=yes' 'ProtectControlGroups=no'; do
	expect "scanoria-runner.service : $d" "$(grep -c -x "$d" "$U")" 1
done
# EXDEV (#29) : une seule entrée ReadWritePaths par arborescence de file.
expect "scanoria-runner.service : un seul montage pour la file d'analyses" "$(sed -n 's/^ReadWritePaths=//p' "$U" | tr ' ' '\n' | grep -c '^/var/lib/scanoria/scans' || true)" 1
expect "codes et types identiques dans common.py, schemas.ts et result.schema.json" "$(pyrun '
import json, re
from scanoria import common
ts = open(sys.argv[1]).read()
res = json.load(open(sys.argv[2]))
codes = set(re.findall(r"\x27(E_[A-Z_]+)\x27", ts.split("RESULT_CODES")[1].split("] as const")[0]))
types = set(re.findall(r"\x27([a-z-]+)\x27", ts.split("REQUEST_TYPES = [")[1].split("] as const")[0]))
rc = set(res["properties"]["code"]["enum"]) - {"OK"}
rt = set(res["properties"]["type"]["oneOf"][1]["enum"]) if "oneOf" in res["properties"]["type"] else set()
ok = codes == (common.ALL_CODES - {"OK"}) and types == set(common.REQUEST_TYPES)
print("ok" if ok and {"E_SERVICE_RESOURCES", "E_BACKUP_INVALID"} <= rc else "ko")' "$ROOT/webui/shared/schemas.ts" "$ROOT/src/rootfs/usr/share/scanoria/requests/result.schema.json")" ok

echo
echo "b16 : $PASS réussis, $FAIL échoués"
[[ "$FAIL" -eq 0 ]]
