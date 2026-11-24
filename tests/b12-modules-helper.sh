#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Vincent Tisseront
#
# b12 — moteur des modules (scanoria-helper : refresh-catalog, install-modules,
# uninstall-module, set-module-state, update-module), sans root. Le helper
# tourne en mode test (SCANORIA_TEST_ROOT) ; podman, systemctl, sysctl,
# runuser et curl sont des bouchons (curl sert une fausse release du catalogue
# depuis le disque). L'index est signé par une clé Ed25519 jetable.
# Couvre : signature, empreintes, index plus ancien ou mal numéroté, image par
# étiquette ; dépendances, conflits, ressources, sysctl, licences, options ;
# banc d'essai (attendu non atteint, archive piégée : lien, « .. », empreinte) ;
# retour arrière complet ; unités Quadlet, base PostgreSQL, sauvegarde avant
# mise à jour et restauration ; retrait bloqué par une dépendance ; demandes
# hostiles ; conformité de state.json à son schéma.
# Dépendances : bash, python3, jq, openssl, zstd, tar.

# Les motifs jq et les « bash -c » sont volontairement entre apostrophes.
# shellcheck disable=SC2016
set -euo pipefail
export PYTHONDONTWRITEBYTECODE=1

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
HELPER="$ROOT/src/rootfs/usr/sbin/scanoria-helper"
PYLIB="$ROOT/src/rootfs/usr/lib/scanoria/py"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

PASS=0
FAIL=0
ok() { PASS=$((PASS + 1)); printf 'ok   %s\n' "$1"; }
ko() { FAIL=$((FAIL + 1)); printf 'FAIL %s\n' "$1"; }
expect() { # libellé valeur_obtenue valeur_attendue
	if [[ "$2" == "$3" ]]; then ok "$1"; else ko "$1 (obtenu « $2 », attendu « $3 »)"; fi
}
for t in python3 jq openssl zstd tar; do command -v "$t" > /dev/null || { echo "outil manquant : $t" >&2; exit 2; }; done

T="$TMP/root"
FIX="$TMP/fix"
STUBS="$TMP/stubs"
REL="$FIX/rel"
mkdir -p "$T"/var/lib/scanoria/requests/{tmp,incoming,work,done,failed} "$T/run/scanoria" "$T/etc/scanoria" \
	"$T/opt/scanoria/current" "$T/proc" "$T/usr/share/scanoria/schemas" "$STUBS" "$REL"
chmod 0700 "$T/var/lib/scanoria/requests/incoming" "$T/var/lib/scanoria/requests/work"
export SCANORIA_TEST_ROOT="$T" SCANORIA_TEST_BIN="$STUBS"
unset SCANORIA_TEST_OWNER_UID SCANORIA_TEST_NOW
export SCANORIA_TEST_HEALTH_TIMEOUT=1
CALLS="$TMP/calls.log"
: > "$CALLS"

echo 0.2.0 > "$T/opt/scanoria/current/VERSION"
printf 'MemTotal:       16384000 kB\n' > "$T/proc/meminfo"
for i in 0 1 2 3; do printf 'processor\t: %d\n' "$i"; done > "$T/proc/cpuinfo"
echo '{"fqdn": "analyse.exemple.test"}' > "$T/etc/scanoria/appliance.json"
echo '{"repo": "exemple/scanoria"}' > "$T/etc/scanoria/catalog.json"
# Schéma d'index de test (le schéma réel est fourni par le chantier catalogue).
cat > "$T/usr/share/scanoria/schemas/catalog-index.schema.json" <<-'EOF'
	{"type": "object", "required": ["schema", "version", "generated_at", "modules", "packs"],
	 "properties": {"modules": {"type": "array"}, "packs": {"type": "array"}}}
EOF

openssl genpkey -algorithm ed25519 -out "$TMP/sign.key" 2> /dev/null
openssl pkey -in "$TMP/sign.key" -pubout -out "$T/etc/scanoria/update-pubkey.pem"
openssl genpkey -algorithm ed25519 -out "$TMP/other.key" 2> /dev/null

# --- Bouchons ------------------------------------------------------------------
cat > "$STUBS/curl" <<-EOF
	#!/usr/bin/env python3
	import json, os, re, shutil, sys
	a = sys.argv[1:]
	with open("$CALLS", "a") as f:
	    f.write(json.dumps(["curl"] + a) + "\n")
	out = a[a.index("--output") + 1] if "--output" in a else None
	wo = a[a.index("--write-out") + 1] if "--write-out" in a else ""
	url = a[-1]
	fix = "$FIX"
	code, src = 404, None
	m = re.fullmatch(r"https://api\.github\.com/repos/exemple/scanoria/releases\?per_page=30", url)
	if m:
	    c = open(fix + "/api-code").read().strip() if os.path.exists(fix + "/api-code") else "200"
	    code, src = int(c), fix + "/api-releases.json"
	elif url == "https://github.com/exemple/scanoria/releases.atom":
	    code, src = 200, fix + "/releases.atom"
	elif url.startswith("https://github.com/exemple/scanoria/releases/download/"):
	    p = fix + "/rel/" + url.split("/releases/download/", 1)[1]
	    if os.path.isfile(p):
	        code, src = 200, p
	elif url.startswith("http://127.0.0.1:"):
	    code = 503 if os.path.exists(fix + "/health-fail") else 200
	    # health-fail-image : seul le service qui tourne avec cette image est malade.
	    if os.path.exists(fix + "/health-fail-image"):
	        bad = open(fix + "/health-fail-image").read().strip()
	        cont = "$T/etc/containers/systemd/scanoria-mod-svc.container"
	        if os.path.exists(cont) and ("Image=" + bad + "\n") in open(cont).read():
	            code = 503
	if out and src and code == 200 and out != "/dev/null":
	    shutil.copyfile(src, out)
	sys.stdout.write(wo.replace("%{http_code}", str(code)).replace("%{redirect_url}", ""))
EOF
cat > "$STUBS/podman" <<-EOF
	#!/bin/bash
	jq -cn '["podman"] + \$ARGS.positional' --args -- "\$@" >> "$CALLS"
	case "\$1" in
	pull) [[ -e "$FIX/podman-fail-pull" ]] && exit 125; exit 0 ;;
	run)
		out=""
		prev=""
		for a in "\$@"; do
			if [[ "\$prev" == "--volume" && "\$a" == *:/out:rw ]]; then out=\${a%%:/out:rw}; fi
			prev=\$a
		done
		if [[ -z "\$out" ]]; then [[ -e "$FIX/podman-fail-health" ]] && exit 1; exit 0; fi
		case "\$(cat "$FIX/scan-trick" 2> /dev/null)" in
		fifo) mkfifo "\$out/result.sarif"; exit 1 ;;
		dirlink) mkdir -p "$TMP/ailleurs" && cp "$FIX/scan-output" "$TMP/ailleurs/result.sarif" && ln -s "$TMP/ailleurs" "\$out/d"; exit 1 ;;
		esac
		[[ -e "$FIX/scan-output" ]] && cp "$FIX/scan-output" "\$out/result.sarif"
		src=\${out%/out}/src
		echo "\$(stat -c %a "\$src") \$(stat -c %a "\$src/README")" > "$FIX/src-modes"
		stat -c %u "\$src/README" > "$FIX/src-owner"
		exit "\$(cat "$FIX/scan-rc" 2> /dev/null || echo 1)" ;;
	*) exit 0 ;;
	esac
EOF
cat > "$STUBS/systemctl" <<-EOF
	#!/bin/bash
	jq -cn '["systemctl"] + \$ARGS.positional' --args -- "\$@" >> "$CALLS"
	[[ "\$1" == start && -e "$FIX/systemctl-fail-start" ]] && exit 1
	exit 0
EOF
for c in sysctl runuser; do
	cat > "$STUBS/$c" <<-EOF
		#!/bin/bash
		jq -cn --arg c "$c" '[\$c] + \$ARGS.positional' --args -- "\$@" >> "$CALLS"
		cat > /dev/null
		exit 0
	EOF
done
printf '#!/bin/bash\nexit 0\n' > "$STUBS/scanoria-state"
chmod 0755 "$STUBS"/*

# --- Fabrication d'une release du catalogue -------------------------------------
DIGEST=$(printf '%064d' 0 | tr 0 a)
img() { printf 'registry.exemple.test/scanoria/%s@sha256:%s' "$1" "$DIGEST"; }

# Banc d'essai : testbed/README et testbed/src/app.txt (contenu sans motif de secret).
mk_testbed() { # nom_archive [piège : symlink|dotdot]
	local d="$TMP/tb-$1"
	rm -rf "$d" && mkdir -p "$d/testbed/src"
	echo "banc d'essai" > "$d/testbed/README"
	echo "fichier analysé" > "$d/testbed/src/app.txt"
	case "${2:-}" in
	symlink) ln -s /etc/passwd "$d/testbed/src/lien" ;;
	esac
	if [[ "${2:-}" == dotdot ]]; then
		python3 - "$d" "$TMP/$1.tar" <<-'PY'
			import io, sys, tarfile
			with tarfile.open(sys.argv[2], "w", format=tarfile.USTAR_FORMAT) as t:
			    t.add(sys.argv[1] + "/testbed", arcname="testbed")
			    data = b"x"
			    i = tarfile.TarInfo("testbed/../../evade.txt"); i.size = len(data)
			    t.addfile(i, io.BytesIO(data))
		PY
	else
		tar -C "$d" --format=ustar --owner=0 --group=0 -cf "$TMP/$1.tar" testbed
	fi
	zstd -q -f -o "$TMP/$1" "$TMP/$1.tar"
	rm -f "$TMP/$1.tar"
}

# module ID VERSION TYPE [jq de surcharge]
module() {
	local id=$1 ver=$2 type=$3 extra=${4:-.}
	jq -cn --arg id "$id" --arg ver "$ver" --arg type "$type" --arg img "$(img "$id")" '
		{id: $id, name: $id, version: $ver, type: $type, categories: ["secrets"],
		 license: {spdx: "MIT", url: "https://exemple.test/licence", restrictions: "none"},
		 upstream: {homepage: "https://exemple.test", source: "https://exemple.test/src"},
		 image: $img, resources: {min_ram_mb: 256, min_cpu: 1, disk_mb: 100}, hostname: null,
		 needs: {sysctl: {}, postgres: false}, requires: {modules: [], feeds: []}, conflicts: [],
		 options: {type: "object", additionalProperties: false, properties: {}},
		 health: {command: [$id, "--version"]}, upgrade: {policy: "on-demand"},
		 testbed_archive: null, testbed_sha256: null}
		+ (if $type == "scanner" then
			{scan: {inputs: ["repo"], command: [$id, "scan", "/src", "--out", "/out/result.sarif"], timeout_s: 60, network: "none"},
			 outputs: {sarif: {path: "/out/result.sarif", version: "2.1.0"}},
			 testbed: {path: "testbed/", expect: [{rule: "fake-token", category: "secrets", min: 1}]},
			 testbed_archive: ("testbed-" + $id + "-" + $ver + ".tar.zst")}
		   else {} end)
		| '"$extra"
}

# publish N MODULES_JSON [clé] : écrit la release catalog-vN (index, archives, SHA256SUMS signé)
publish() {
	local n=$1 mods=$2 key=${3:-$TMP/sign.key} d="$REL/catalog-v$1" a sums
	rm -rf "$d" && mkdir -p "$d"
	sums=""
	for a in $(jq -r '.[] | .testbed_archive // empty' <<< "$mods"); do
		[[ -f "$TMP/$a" ]] || mk_testbed "$a"
		cp "$TMP/$a" "$d/$a"
	done
	local fixed="[]" m sha
	while read -r m; do
		a=$(jq -r '.testbed_archive // empty' <<< "$m")
		if [[ -n "$a" ]]; then
			sha=$(sha256sum "$d/$a" | cut -d' ' -f1)
			m=$(jq -c --arg s "${TB_SHA_OVERRIDE:-$sha}" '.testbed_sha256 = $s' <<< "$m")
		fi
		fixed=$(jq -c --argjson m "$m" '. + [$m]' <<< "$fixed")
	done < <(jq -c '.[]' <<< "$mods")
	jq -n --argjson n "${INDEX_N:-$n}" --argjson mods "$fixed" \
		'{schema: 1, version: $n, generated_at: "2026-11-24T00:00:00Z", modules: $mods, packs: []}' \
		> "$d/catalog-index.json"
	sums="$(sha256sum "$d/catalog-index.json" | cut -d' ' -f1)  catalog-index.json"$'\n'
	for a in $(find "$d" -maxdepth 1 -name 'testbed-*.tar.zst' -printf '%f\n' | sort); do
		sums+="$(sha256sum "$d/$a" | cut -d' ' -f1)  $a"$'\n'
	done
	printf '%s' "$sums" > "$d/SHA256SUMS"
	openssl pkeyutl -sign -inkey "$key" -rawin -in "$d/SHA256SUMS" -out "$d/SHA256SUMS.sig"
	jq -n --arg tag "catalog-v$n" '[{tag_name: $tag, name: ("Catalogue Scanoria"), draft: false, prerelease: false},
		{tag_name: "v0.1.0", name: "0.1.0", draft: false, prerelease: false}]' > "$FIX/api-releases.json"
}

# --- Exécution ----------------------------------------------------------------
# hx TYPE PARAMS : lance une demande, mémorise le résultat dans $R
hx() {
	R=$("$HELPER" exec --origin cli --type "$1" --params "$2" 2> "$TMP/helper.err") || true
	[[ -n "$R" ]] || { R='{"code":"NO_OUTPUT"}'; sed 's/^/     /' "$TMP/helper.err"; }
}
code() { jq -r .code <<< "$R"; }
STATE="$T/var/lib/scanoria/modules/state.json"
mstate() { jq -r --arg id "$1" '[.modules[] | select(.id == $id)][0] | if . == null then "absent" else .status + "/" + (.enabled|tostring) + "/" + .version end' "$STATE"; }
state_valid() {
	python3 -I -c '
import sys
sys.path.insert(0, sys.argv[1])
from scanoria import common, schema
st = common.load_json_file(sys.argv[2], 1 << 22)
errs = schema.load("schemas", "modules-state").errors(st)
print("ok" if not errs else errs[:3])' "$PYLIB" "$STATE"
}
called() { grep -c -F -- "$1" "$CALLS" || true; }
inst() { # id [version] [options]
	jq -cn --arg id "$1" --arg v "$2" --argjson o "${3:-{\}}" --argjson acc "${ACCEPT:-[]}" \
		'{modules: [{id: $id, version: $v, options: $o}], accept_licenses: $acc}'
}
SARIF_OK=$(jq -cn '{version: "2.1.0", runs: [{tool: {driver: {name: "fake", rules: [{id: "fake-token"}]}},
	results: [{ruleId: "fake-token", message: {text: "jeton factice"}}]}]}')
printf '%s' "$SARIF_OK" > "$FIX/scan-output"

# === 1. refresh-catalog =====================================================
GL1=$(module gitleaks 8.0.0 scanner)
GL2=$(module gitleaks 8.1.0 scanner)
TRIVY=$(module trivy 0.60.0 scanner '.requires.feeds = ["trivy-db"]')
TDB=$(module trivy-db 1 feed '.image = null | .health = null')
SVC=$(module svc 1.0.0 service '.hostname = "svc" | .needs.postgres = true | .needs.sysctl = {"vm.max_map_count": 524288}
	| .service = {port: 9000, health_path: "/health", units: [], volumes: [{name: "data", path: "/data"}],
	              env: {DB_URL: "{db_url_jdbc}", DB_PASSWORD: "{db_password}"}} | .resources.min_ram_mb = 1024')
SVC2=$(module svc 1.1.0 service '.image = "'"$(img svc-next)"'" | .hostname = "svc" | .needs.postgres = true
	| .service = {port: 9000, health_path: "/health", units: [], volumes: [{name: "data", path: "/data"}]}')
BIG=$(module big 1.0.0 scanner '.resources.min_ram_mb = 900000')
MANYCPU=$(module manycpu 1.0.0 scanner '.resources.min_cpu = 64')
SEMG=$(module semgrep 1.0.0 scanner '.license.restrictions = "no-redistribution"')
OPEN=$(module opengrep 1.0.0 scanner '.conflicts = ["semgrep"]')
NEWAPP=$(module newapp 1.0.0 scanner '.requires.appliance = ">=9.0.0"')
DEPTOP=$(module deptop 1.0.0 scanner '.requires.modules = ["gitleaks"]')
WOPT=$(module wopt 1.0.0 scanner '.options.properties = {level: {enum: ["low", "high"], default: "low"}}')
BADSYS=$(module badsys 1.0.0 scanner '.needs.sysctl = {"kernel.core_pattern": 1}')
TRAP1=$(module trapl 1.0.0 scanner)
DEEP=$(module deep 1.0.0 scanner '.outputs.sarif.path = "/out/d/result.sarif"')
TRAP2=$(module trapd 1.0.0 scanner)
mk_testbed testbed-trapl-1.0.0.tar.zst symlink
mk_testbed testbed-trapd-1.0.0.tar.zst dotdot
ALL=$(jq -cn --argjson a "[$GL1,$GL2,$TRIVY,$TDB,$SVC,$SVC2,$BIG,$MANYCPU,$SEMG,$OPEN,$NEWAPP,$DEPTOP,$WOPT,$BADSYS,$TRAP1,$TRAP2,$DEEP]" '$a')

publish 3 "$ALL"
# Appliance installée avant l'entrée tmpfiles.d : répertoire créé en 0700 par un
# helper plus ancien. Il doit être rétabli en 0750 (groupe scanoria hors mode test),
# sinon la console ne peut pas lire l'index publié (« catalogue pas encore disponible »).
mkdir -p "$T/var/lib/scanoria" && install -d -m 0700 "$T/var/lib/scanoria/catalog"
rm -f "$T/var/lib/scanoria/modules/state.json"
hx refresh-catalog '{}'
expect "refresh-catalog : index signé accepté" "$(code)" OK
expect "refresh-catalog : répertoire du catalogue lisible par la console (0750)" "$(stat -c %a "$T/var/lib/scanoria/catalog")" 750
expect "refresh-catalog : état des modules publié dès la première actualisation" \
	"$(jq -c '[.version, .modules]' "$T/var/lib/scanoria/modules/state.json" 2> /dev/null)" '[1,[]]'
expect "refresh-catalog : répertoire des modules lisible par la console (0750)" "$(stat -c %a "$T/var/lib/scanoria/modules")" 750
expect "refresh-catalog : numéro publié" "$(jq -r .version "$T/var/lib/scanoria/catalog/catalog-index.json")" 3
expect "refresh-catalog : droits 0640" "$(stat -c %a "$T/var/lib/scanoria/catalog/catalog-index.json")" 640
expect "refresh-catalog : source mémorisée" "$(jq -r .tag "$T/var/lib/scanoria/catalog/source.json")" catalog-v3
hx refresh-catalog '{}'
expect "refresh-catalog : même index, inchangé" "$(jq -r .output.changed <<< "$R")" false
hx refresh-catalog '{"force": true}'
expect "refresh-catalog : paramètre inconnu refusé" "$(code)" E_SCHEMA

cp "$T/var/lib/scanoria/catalog/catalog-index.json" "$TMP/index-v3.json"
publish 2 "$ALL"
hx refresh-catalog '{}'
expect "refresh-catalog : index plus ancien refusé" "$(code)" E_VERSION
publish 4 "$ALL" "$TMP/other.key"
hx refresh-catalog '{}'
expect "refresh-catalog : signature d'une autre clé refusée" "$(code)" E_SIGNATURE
publish 4 "$ALL"
rm "$REL/catalog-v4/SHA256SUMS.sig"
hx refresh-catalog '{}'
expect "refresh-catalog : index non signé refusé" "$(code)" E_NOT_FOUND
publish 4 "$ALL"
echo ' ' >> "$REL/catalog-v4/catalog-index.json"
hx refresh-catalog '{}'
expect "refresh-catalog : index modifié après signature refusé" "$(code)" E_CHECKSUM
INDEX_N=7 publish 4 "$ALL"
hx refresh-catalog '{}'
expect "refresh-catalog : numéro de l'index différent du tag refusé" "$(code)" E_VERSION
publish 4 "$(jq -c '.[0].image = "registry.exemple.test/scanoria/gitleaks:latest"' <<< "$ALL")"
hx refresh-catalog '{}'
expect "refresh-catalog : image par étiquette refusée" "$(code)" E_CHECKSUM
publish 4 "$(jq -c '.[0].id = "../gitleaks"' <<< "$ALL")"
hx refresh-catalog '{}'
expect "refresh-catalog : identifiant « ../ » refusé" "$(code)" E_CHECKSUM
publish 4 "$(jq -c '.[0].scan.env = {"LD_PRELOAD": "/tmp/x.so"}' <<< "$ALL")"
hx refresh-catalog '{}'
expect "refresh-catalog : variable LD_* dans scan.env refusée" "$(code)" E_CHECKSUM
publish 4 "$(jq -c '. + [.[0]]' <<< "$ALL")"
hx refresh-catalog '{}'
expect "refresh-catalog : module en double refusé" "$(code)" E_CHECKSUM
publish 4 "$ALL"
jq 'del(.packs)' "$REL/catalog-v4/catalog-index.json" > "$TMP/i.json"
mv "$TMP/i.json" "$REL/catalog-v4/catalog-index.json"
(cd "$REL/catalog-v4" && { printf '%s  catalog-index.json\n' "$(sha256sum catalog-index.json | cut -d' ' -f1)"; grep testbed- SHA256SUMS; } > S && mv S SHA256SUMS)
openssl pkeyutl -sign -inkey "$TMP/sign.key" -rawin -in "$REL/catalog-v4/SHA256SUMS" -out "$REL/catalog-v4/SHA256SUMS.sig"
hx refresh-catalog '{}'
expect "refresh-catalog : index hors schéma refusé" "$(code)" E_CHECKSUM
expect "refresh-catalog : l'index vérifié reste en place" "$(jq -r .version "$T/var/lib/scanoria/catalog/catalog-index.json")" 3
echo 429 > "$FIX/api-code"
publish 4 "$ALL"
cat > "$FIX/releases.atom" <<-'EOF'
	<?xml version="1.0" encoding="UTF-8"?>
	<feed xmlns="http://www.w3.org/2005/Atom">
	<entry><title>Catalogue Scanoria 4</title><link rel="alternate" href="https://github.com/exemple/scanoria/releases/tag/catalog-v4"/></entry>
	<entry><title>[rejected] Catalogue Scanoria 9</title><link rel="alternate" href="https://github.com/exemple/scanoria/releases/tag/catalog-v9"/></entry>
	<entry><title>0.1.0</title><link rel="alternate" href="https://github.com/exemple/scanoria/releases/tag/v0.1.0"/></entry>
	</feed>
EOF
hx refresh-catalog '{}'
expect "refresh-catalog : repli sur releases.atom en 429 (rejetée ignorée)" "$(code)/$(jq -r .output.version <<< "$R")" OK/4
rm "$FIX/api-code"

# === 2. Demandes hostiles ===================================================
hx install-modules '{"modules": [{"id": "../etc", "version": "1", "options": {}}], "accept_licenses": []}'
expect "install : id « ../ » refusé par le schéma" "$(code)" E_SCHEMA
hx install-modules '{"modules": [{"id": "gitleaks", "version": "8.0.0/../x", "options": {}}], "accept_licenses": []}'
expect "install : version avec « / » refusée" "$(code)" E_SCHEMA
hx install-modules '{"modules": [{"id": "gitleaks", "version": "8.0.0", "options": {}, "image": "x"}], "accept_licenses": []}'
expect "install : champ inconnu (image) refusé" "$(code)" E_SCHEMA
hx install-modules '{"modules": [], "accept_licenses": []}'
expect "install : liste vide refusée" "$(code)" E_SCHEMA
hx install-modules "$(jq -cn '{modules: [{id: "gitleaks", version: "8.0.0", options: {}}, {id: "gitleaks", version: "8.1.0", options: {}}], accept_licenses: []}')"
expect "install : identifiant en double refusé" "$(code)" E_INVALID_PARAM
hx install-modules "$(inst gitleaks 9.9.9)"
expect "install : version absente du catalogue" "$(code)" E_NOT_FOUND
hx install-modules "$(inst wopt 1.0.0 '{"level": "max"}')"
expect "install : option hors schéma refusée" "$(code)" E_INVALID_PARAM
hx install-modules "$(inst wopt 1.0.0 '{"cmd": "rm -rf /"}')"
expect "install : option inconnue refusée" "$(code)" E_INVALID_PARAM
hx uninstall-module '{"id": "gitleaks", "keep_data": "no"}'
expect "uninstall : keep_data non booléen refusé" "$(code)" E_SCHEMA
hx set-module-state '{"id": "gitleaks"}'
expect "set-module-state : enabled manquant refusé" "$(code)" E_SCHEMA
expect "aucune image tirée par les demandes refusées" "$(called '"pull"')" 0

# === 3. Contrôles préalables ================================================
hx install-modules "$(inst big 1.0.0)"
expect "install : mémoire insuffisante, refus clair" "$(code)/$(jq -r .output.resource <<< "$R")" E_RESOURCES/ram
hx install-modules "$(inst manycpu 1.0.0)"
expect "install : CPU insuffisants" "$(code)" E_RESOURCES
hx install-modules "$(inst badsys 1.0.0)"
expect "install : réglage noyau non autorisé" "$(code)" E_RESOURCES
hx install-modules "$(inst semgrep 1.0.0)"
expect "install : licence restreinte sans acceptation" "$(code)/$(jq -r '.output.licenses[0].restrictions' <<< "$R")" E_LICENSE/no-redistribution
hx install-modules "$(inst newapp 1.0.0)"
expect "install : version de l'appliance insuffisante" "$(code)" E_DEPENDENCY
expect "aucun changement après les refus" "$(called '"pull"')/$(jq '.modules | length' "$STATE" 2> /dev/null || echo 0)" 0/0

# === 4. Installation d'un scanner, banc d'essai =============================
hx install-modules "$(inst gitleaks 8.0.0)"
expect "install gitleaks : succès" "$(code)" OK
expect "install gitleaks : sain et activé" "$(mstate gitleaks)" healthy/true/8.0.0
expect "install gitleaks : banc d'essai passé" "$(jq -r '.modules[] | select(.id=="gitleaks") | .testbed.passed' "$STATE")" true
expect "install gitleaks : image tirée par empreinte" "$(called "\"pull\",\"--quiet\",\"$(img gitleaks)\"")" 1
expect "state.json conforme à son schéma" "$(state_valid)" ok
expect "state.json : droits 0640" "$(stat -c %a "$STATE")" 640
expect "state.json : opération terminée" "$(jq -r '.operations[-1] | .kind + "/" + .result + "/" + (.progress|tostring)' "$STATE")" install/ok/100
RUNLINE=$(grep -F '"podman","run"' "$CALLS" | grep -F /out:rw | tail -1)
for flag in '"--network=none"' '"--read-only"' '"--cap-drop=ALL"' '"--security-opt=no-new-privileges"' \
	'"--user","65534:65534"' '"--pids-limit","512"' '"--pull=never"' ':/src:ro"' '"--entrypoint","[\"gitleaks\"]"'; do
	expect "banc d'essai confiné : $flag" "$(grep -c -F -- "$flag" <<< "$RUNLINE")" 1
done
expect "banc d'essai : droits du propriétaire seul" "$(cat "$FIX/src-modes" 2> /dev/null)" "700 600"
# Root : chown direct ; sans root : « podman unshare chown -R » (bouchon).
if [[ "$(id -u)" -eq 0 ]]; then
	expect "banc d'essai : sources données à 65534" "$(cat "$FIX/src-owner" 2> /dev/null)" 65534
else
	expect "banc d'essai : sources données à 65534" "$(grep -F '"podman","unshare","chown","-R","65534:65534"' "$CALLS" | grep -c -F '/src"')" 1
fi
expect "répertoire de travail du banc d'essai supprimé" "$(find "$T/var/lib/scanoria/modules/work" -mindepth 1 | wc -l)" 0
hx install-modules "$(inst gitleaks 8.0.0)"
expect "install : déjà installé, sans effet" "$(code)/$(jq -r '.output.skipped[0]' <<< "$R")" OK/gitleaks
hx install-modules "$(inst opengrep 1.0.0)"
expect "install opengrep (sans conflit installé)" "$(code)" OK
ACCEPT='["semgrep"]' hx install-modules "$(ACCEPT='["semgrep"]' inst semgrep 1.0.0)"
expect "install : conflit avec un module installé" "$(code)" E_CONFLICT
hx uninstall-module '{"id": "opengrep", "keep_data": false}'
expect "uninstall opengrep" "$(code)/$(mstate opengrep)" OK/absent
hx install-modules "$(ACCEPT='["semgrep"]' inst semgrep 1.0.0)"
expect "install : licence restreinte acceptée" "$(code)" OK
hx install-modules "$(inst opengrep 1.0.0)"
expect "install : conflit déclaré par le nouveau module" "$(code)" E_CONFLICT

# Échecs du banc d'essai et retour arrière complet
jq -c '.runs[0].results = []' <<< "$SARIF_OK" > "$FIX/scan-output"
hx install-modules "$(inst wopt 1.0.0 '{"level": "high"}')"
expect "banc d'essai : attendu non atteint → échec" "$(code)" E_TESTBED
expect "banc d'essai : module retiré (retour arrière)" "$(mstate wopt)" absent
expect "banc d'essai : image retirée" "$(called "\"rmi\",\"--ignore\",\"$(img wopt)\"")" 1
expect "banc d'essai : opération en échec" "$(jq -r '.operations[-1].result' "$STATE")" failed
echo 'pas du json' > "$FIX/scan-output"
hx install-modules "$(inst wopt 1.0.0)"
expect "banc d'essai : sortie non JSON → échec" "$(code)" E_TESTBED
jq -c '.version = "2.0.0"' <<< "$SARIF_OK" > "$FIX/scan-output"
hx install-modules "$(inst wopt 1.0.0)"
expect "banc d'essai : SARIF d'une autre version → échec" "$(code)" E_TESTBED
rm "$FIX/scan-output"
hx install-modules "$(inst wopt 1.0.0)"
expect "banc d'essai : sortie absente → échec" "$(code)" E_TESTBED
printf '%s' "$SARIF_OK" > "$FIX/scan-output"
echo 2 > "$FIX/scan-rc"
hx install-modules "$(inst wopt 1.0.0)"
expect "banc d'essai : code de sortie inattendu → échec" "$(code)" E_TESTBED
rm "$FIX/scan-rc"
hx install-modules "$(inst trapl 1.0.0)"
expect "banc d'essai : archive avec lien symbolique refusée" "$(code)/$(mstate trapl)" E_ARCHIVE/absent
hx install-modules "$(inst trapd 1.0.0)"
expect "banc d'essai : archive avec « .. » refusée" "$(code)/$(mstate trapd)" E_ARCHIVE/absent
expect "aucun fichier hors du répertoire de travail" "$(find "$T" -name evade.txt | wc -l)" 0
echo fifo > "$FIX/scan-trick"
hx install-modules "$(inst wopt 1.0.0)"
expect "sortie piégée : FIFO refusé sans bloquer le helper" "$(code)/$(mstate wopt)" E_TESTBED/absent
echo dirlink > "$FIX/scan-trick"
hx install-modules "$(inst deep 1.0.0)"
expect "sortie piégée : lien vers un répertoire de l'hôte refusé" "$(code)/$(mstate deep)" E_TESTBED/absent
rm "$FIX/scan-trick"
expect "conteneur nommé retiré après chaque exécution" "$(grep -c -F '"podman","rm","--force","--ignore","--time","0","scanoria-run-' "$CALLS")" "$(grep -F '"podman","run"' "$CALLS" | grep -c -F '"--timeout"')"
touch "$FIX/podman-fail-health"
hx install-modules "$(inst wopt 1.0.0)"
expect "santé du scanner en échec → retour arrière" "$(code)/$(mstate wopt)" E_HEALTH_ROLLED_BACK/absent
rm "$FIX/podman-fail-health"
touch "$FIX/podman-fail-pull"
hx install-modules "$(inst wopt 1.0.0)"
expect "image introuvable → échec" "$(code)/$(mstate wopt)" E_NETWORK/absent
rm "$FIX/podman-fail-pull"
hx install-modules "$(inst wopt 1.0.0 '{"level": "high"}')"
expect "install wopt avec option" "$(code)/$(jq -r '.modules[] | select(.id=="wopt") | .options.level' "$STATE")" OK/high

# Dépendances (G1)
hx install-modules "$(inst trivy 0.60.0)"
expect "install trivy : feed requis installé d'office" "$(code)/$(mstate trivy-db)" OK/healthy/true/1
expect "trivy : feed monté en lecture seule" "$(grep -F '"podman","run"' "$CALLS" | grep -F /out:rw | tail -1 | grep -c -F '/feeds/trivy-db:ro')" 1
hx uninstall-module '{"id": "trivy-db", "keep_data": true}'
expect "uninstall : retrait bloqué par une dépendance" "$(code)/$(jq -r '.output.required_by[0]' <<< "$R")" E_DEPENDENCY/trivy
hx set-module-state '{"id": "trivy-db", "enabled": false}'
expect "désactivation bloquée par un module actif qui en dépend" "$(code)" E_DEPENDENCY
hx set-module-state '{"id": "trivy", "enabled": false}'
expect "désactivation d'un scanner" "$(code)/$(mstate trivy)" OK/disabled/false/0.60.0
hx set-module-state '{"id": "trivy", "enabled": false}'
expect "désactivation répétée sans effet" "$(code)/$(jq -r .output.changed <<< "$R")" OK/false
hx set-module-state '{"id": "trivy-db", "enabled": false}'
expect "désactivation du feed une fois trivy désactivé" "$(code)" OK
hx set-module-state '{"id": "trivy", "enabled": true}'
expect "réactivation refusée tant que le feed est désactivé" "$(code)" E_DEPENDENCY
hx set-module-state '{"id": "trivy-db", "enabled": true}'
hx set-module-state '{"id": "trivy", "enabled": true}'
expect "réactivation" "$(code)/$(mstate trivy)" OK/healthy/true/0.60.0
hx install-modules "$(inst deptop 1.0.0)"
expect "install avec dépendance déjà présente" "$(code)/$(jq -r '.output.skipped[0]' <<< "$R")" OK/gitleaks

# === 5. Module service : Quadlet, base, sysctl, routage ======================
UNITS="$T/etc/containers/systemd"
hx install-modules "$(inst svc 1.0.0)"
expect "install svc : succès" "$(code)/$(mstate svc)" OK/healthy/true/1.0.0
CONT="$UNITS/scanoria-mod-svc.container"
expect "Quadlet : conteneur généré" "$([[ -f "$CONT" ]] && echo oui)" oui
expect "Quadlet : image par empreinte" "$(grep -c -F "Image=$(img svc)" "$CONT")" 1
expect "Quadlet : publié sur 127.0.0.1 seulement" "$(grep -c -E '^PublishPort=127\.0\.0\.1:18[0-9]{3}:9000$' "$CONT")" 1
expect "Quadlet : aucune capacité" "$(grep -c -x 'DropCapability=ALL' "$CONT")" 1
expect "Quadlet : démarrage à l'amorçage" "$(grep -c -x 'WantedBy=multi-user.target' "$CONT")" 1
expect "Quadlet : réseau et volume" "$(find "$UNITS" -maxdepth 1 \( -name scanoria-mod-svc.network -o -name scanoria-mod-svc_data.volume \) | wc -l)" 2
expect "base PostgreSQL créée" "$(grep -F '"runuser"' "$CALLS" | grep -c -F psql)" 1
expect "identifiants de base en 0600" "$(stat -c %a "$T/etc/scanoria/modules/svc/db.json")" 600
expect "fichier d'environnement en 0600 sans gabarit restant" "$(stat -c %a "$T/etc/scanoria/modules/svc/env")/$(grep -c '{' "$T/etc/scanoria/modules/svc/env")" 600/0
expect "sysctl posé" "$(cat "$T/etc/sysctl.d/60-scanoria-modules.conf" | grep -c -x 'vm.max_map_count = 524288')" 1
expect "systemd rechargé puis service démarré" "$(called '"systemctl","start","scanoria-mod-svc.service"')" 1
expect "state.json conforme après un service" "$(state_valid)" ok
hx set-module-state '{"id": "svc", "enabled": false}'
expect "désactivation d'un service" "$(code)/$(mstate svc)" OK/disabled/false/1.0.0
expect "service désactivé : plus de section [Install]" "$(grep -c WantedBy "$CONT" || true)" 0
expect "service désactivé : arrêté" "$(called '"systemctl","stop","scanoria-mod-svc.service"')" 1
touch "$FIX/health-fail"
hx set-module-state '{"id": "svc", "enabled": true}'
expect "réactivation en échec de santé → reste désactivé" "$(code)/$(mstate svc)" E_HEALTH_ROLLED_BACK/disabled/false/1.0.0
expect "réactivation en échec : unités d'avant remises" "$(grep -c WantedBy "$CONT" || true)" 0
rm "$FIX/health-fail"
hx set-module-state '{"id": "svc", "enabled": true}'
expect "réactivation d'un service" "$(code)/$(mstate svc)" OK/healthy/true/1.0.0

# Mise à jour : sauvegarde préalable, retour arrière en cas d'échec
img svc-next > "$FIX/health-fail-image"
hx update-module '{"id": "svc", "version": "1.1.0"}'
expect "update svc en échec de santé → version précédente gardée" "$(code)/$(mstate svc)" E_HEALTH_ROLLED_BACK/healthy/true/1.0.0
expect "update : sauvegarde de la base avant changement" "$(grep -F '"runuser"' "$CALLS" | grep -c -F pg_dump)" 1
expect "update : volume sauvegardé" "$(called '"volume","export"')" 1
expect "update en échec : base restaurée" "$(grep -F '"runuser"' "$CALLS" | grep -c -F pg_restore)" 1
expect "update en échec : unités d'avant remises" "$(grep -c -F "Image=$(img svc)" "$CONT")" 1
expect "update en échec : erreur notée" "$(jq -r '.modules[] | select(.id=="svc") | .last_error | startswith("update to 1.1.0 failed")' "$STATE")" true
rm "$FIX/health-fail-image"
hx update-module '{"id": "svc", "version": "1.1.0"}'
expect "update svc" "$(code)/$(mstate svc)" OK/healthy/true/1.1.0
expect "update : sysctl retiré (plus exigé)" "$([[ -e "$T/etc/sysctl.d/60-scanoria-modules.conf" ]] && echo présent || echo retiré)" retiré
hx update-module '{"id": "svc", "version": "1.0.0"}'
expect "update vers une version plus ancienne refusée" "$(code)" E_VERSION
hx update-module '{"id": "gitleaks", "version": "8.1.0"}'
expect "update d'un scanner (banc d'essai rejoué)" "$(code)/$(mstate gitleaks)" OK/healthy/true/8.1.0
hx uninstall-module '{"id": "svc", "keep_data": true}'
expect "uninstall svc en gardant les données" "$(code)/$(mstate svc)" OK/absent
expect "données gardées : identifiants conservés" "$([[ -f "$T/etc/scanoria/modules/svc/db.json" ]] && echo oui)" oui
expect "unités retirées" "$(find "$UNITS" -maxdepth 1 -name 'scanoria-mod-svc*' | wc -l)" 0
hx install-modules "$(inst svc 1.1.0)"
expect "réinstallation : base gardée reprise" "$(code)/$(jq -r .password "$T/etc/scanoria/modules/svc/db.json" | wc -c)" OK/49
touch "$FIX/systemctl-fail-start"
hx uninstall-module '{"id": "svc", "keep_data": false}'
expect "uninstall svc en supprimant les données" "$(code)/$(mstate svc)" OK/absent
expect "données supprimées : base détruite" "$(grep -F '"runuser"' "$CALLS" | grep -c -F 'psql')" 3
expect "données supprimées : volume détruit" "$(called '"volume","rm","--force","scanoria-mod-svc_data"')" 1
expect "données supprimées : identifiants effacés" "$([[ -e "$T/etc/scanoria/modules/svc" ]] && echo présent || echo effacé)" effacé
hx install-modules "$(inst svc 1.0.0)"
expect "install service en échec de démarrage → retour arrière" "$(code)/$(mstate svc)" E_INTERNAL/absent
expect "retour arrière : unités retirées" "$(find "$UNITS" -maxdepth 1 -name 'scanoria-mod-svc*' | wc -l)" 0
expect "retour arrière : base créée puis détruite" "$([[ -e "$T/etc/scanoria/modules/svc" ]] && echo présent || echo effacé)" effacé
expect "retour arrière : sysctl retiré" "$([[ -e "$T/etc/sysctl.d/60-scanoria-modules.conf" ]] && echo présent || echo retiré)" retiré
rm "$FIX/systemctl-fail-start"

# === 6. File de demandes (chemin console) ===================================
ID=$(cat /proc/sys/kernel/random/uuid)
NOW=$(date -u +%Y-%m-%dT%H:%M:%SZ)
NAME="$(date -u -d "$NOW" +%Y%m%dT%H%M%SZ)-$ID.json"
jq -cn --arg id "$ID" --arg c "$NOW" '{version: 1, id: $id, type: "uninstall-module", created_at: $c,
	requested_by: {user_id: 1, username: "admin"}, params: {id: "deptop", keep_data: false}}' \
	> "$T/var/lib/scanoria/requests/incoming/$NAME"
"$HELPER" run 2> "$TMP/helper.err" || ko "scanoria-helper run"
expect "file : désinstallation déposée par la console" "$(jq -r .code "$T/var/lib/scanoria/requests/done/$NAME")/$(mstate deptop)" OK/absent
hx uninstall-module '{"id": "absent", "keep_data": false}'
expect "uninstall d'un module absent" "$(code)" E_NOT_FOUND
expect "state.json conforme en fin de batterie" "$(state_valid)" ok
expect "20 opérations au plus" "$(jq '.operations | length <= 20' "$STATE")" true

# === 7. Fichiers livrés ======================================================
for f in refresh-catalog install-modules uninstall-module set-module-state update-module; do
	expect "schéma de demande $f présent et chargeable" "$(python3 -I -c '
import sys
sys.path.insert(0, sys.argv[1])
from scanoria import schema
schema.load("requests", sys.argv[2]); print("ok")' "$PYLIB" "$f")" ok
done
expect "timer de rafraîchissement du catalogue" "$(grep -c -x 'OnCalendar=daily' "$ROOT/src/rootfs/usr/lib/systemd/system/scanoria-catalog-refresh.timer")" 1

echo
echo "b12 : $PASS réussis, $FAIL échoués"
[[ "$FAIL" -eq 0 ]]
