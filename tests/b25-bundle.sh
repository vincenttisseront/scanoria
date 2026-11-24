#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Vincent Tisseront
#
# b25 — lots hors ligne signés (0.6, chantier A, CLAUDE.md § 9), sans root.
# Deux appliances en mode test (SCANORIA_TEST_ROOT) : A exporte, B importe.
# skopeo, podman, curl, systemctl et runuser sont des bouchons ; openssl et
# tar sont les vrais. L'index du catalogue est signé par une clé jetable.
# Couvre : clé de l'appliance créée une fois (0600), aller-retour export →
# import (base, banc d'essai, image chargée par empreinte, index installé),
# fermeture des dépendances (G1), date d'origine de la base gardée (G16),
# bascule atomique et base plus ancienne jamais appliquée, droits des
# fichiers, rotation, magasin des clés de confiance (ajout, empreinte
# fausse, retrait) et lots piégés : signature fausse, clé inconnue ou
# retirée, image absente de l'index, SHA-256 faux, « .. », lien
# symbolique, membre non déclaré ou en double, membre manquant, archive
# tronquée, manifeste trop gros, ordre des membres. Après chaque refus :
# rien n'a changé et le téléversement est supprimé.
# Dépendances : bash, python3, jq, openssl, zstd, tar.

# shellcheck disable=SC2016
set -euo pipefail
export PYTHONDONTWRITEBYTECODE=1

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
HELPER="$ROOT/src/rootfs/usr/sbin/scanoria-helper"
FORGE="$ROOT/tests/lib/forgebundle.py"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
for t in python3 jq openssl zstd tar; do command -v "$t" > /dev/null || { echo "outil manquant : $t" >&2; exit 2; }; done

PASS=0
FAIL=0
ok() { PASS=$((PASS + 1)); printf 'ok   %s\n' "$1"; }
ko() { FAIL=$((FAIL + 1)); printf 'FAIL %s\n' "$1"; }
expect() {
	if [[ "$2" == "$3" ]]; then ok "$1"; else ko "$1 (obtenu « $2 », attendu « $3 »)"; fi
}

STUBS="$TMP/stubs"
FIX="$TMP/fix"
IMG="$FIX/image"
CALLS="$TMP/calls.log"
mkdir -p "$STUBS" "$FIX"
: > "$CALLS"
export SCANORIA_TEST_BIN="$STUBS" SCANORIA_TEST_HEALTH_TIMEOUT=1
unset SCANORIA_TEST_OWNER_UID SCANORIA_TEST_NOW

# --- Fausse image et bouchons ---------------------------------------------------
DIGEST=$(python3 "$FORGE" image "$IMG")
IMAGE="registry.exemple.test/scanoria/gitleaks@$DIGEST"

cat > "$STUBS/skopeo" <<-EOF
	#!/bin/bash
	jq -cn '["skopeo"] + \$ARGS.positional' --args -- "\$@" >> "$CALLS"
	case "\$1" in
	inspect) [[ -e "$FIX/registry-down" ]] && exit 1; cat "$IMG/manifest.json" ;;
	copy)
		src=\${@: -2:1}
		dst=\${@: -1}
		case "\$dst" in
		dir:*) mkdir -p "\${dst#dir:}" && cp "$IMG"/* "\${dst#dir:}/" ;;
		containers-storage:*)
			[[ -f "\${src#oci:}/index.json" ]] || exit 1
			echo "\${dst#containers-storage:}" >> "\$SCANORIA_TEST_ROOT/loaded-images" ;;
		*) exit 1 ;;
		esac ;;
	*) exit 1 ;;
	esac
EOF
cat > "$STUBS/podman" <<-EOF
	#!/bin/bash
	jq -cn '["podman"] + \$ARGS.positional' --args -- "\$@" >> "$CALLS"
	if [[ "\$1 \$2" == "image exists" ]]; then grep -qxF -- "\$3" "\$SCANORIA_TEST_ROOT/loaded-images" 2> /dev/null; exit; fi
	exit 0
EOF
# curl : seule la base OSV factice est servie (export d'une base jamais téléchargée).
cat > "$STUBS/curl" <<-EOF
	#!/usr/bin/env python3
	import json, shutil, sys
	a = sys.argv[1:]
	with open("$CALLS", "a") as f:
	    f.write(json.dumps(["curl"] + a) + "\n")
	out = a[a.index("--output") + 1] if "--output" in a else None
	wo = a[a.index("--write-out") + 1] if "--write-out" in a else ""
	code = 200 if a[-1].startswith("https://feeds.exemple.test/") else 404
	if out and code == 200 and out != "/dev/null":
	    shutil.copyfile("$FIX/feed.zip", out)
	sys.stdout.write(wo.replace("%{http_code}", str(code)).replace("%{redirect_url}", ""))
EOF
for c in systemctl runuser sysctl nft scanoria-state; do printf '#!/bin/bash\ncat > /dev/null 2>&1 || true\nexit 0\n' > "$STUBS/$c"; done
chmod 0755 "$STUBS"/*
python3 -c 'import sys, zipfile; z = zipfile.ZipFile(sys.argv[1], "w"); z.writestr("GHSA-0000-0000-0000.json", "{}"); z.close()' "$FIX/feed.zip"

# --- Catalogue signé ------------------------------------------------------------
openssl genpkey -algorithm ed25519 -out "$TMP/catalog.key" 2> /dev/null
openssl pkey -in "$TMP/catalog.key" -pubout -out "$TMP/catalog.pub"
mkdir -p "$TMP/tb/testbed/src" "$FIX/catalog"
echo "banc d'essai" > "$TMP/tb/testbed/README"
echo "fichier analysé" > "$TMP/tb/testbed/src/app.txt"
TB=testbed-gitleaks-8.0.0.tar.zst
tar -C "$TMP/tb" --format=ustar --owner=0 --group=0 -cf - testbed | zstd -q -o "$FIX/catalog/$TB"
TB_SHA=$(sha256sum "$FIX/catalog/$TB" | cut -d' ' -f1)
base_module() { # id version type
	jq -cn --arg id "$1" --arg ver "$2" --arg type "$3" '
		{id: $id, name: $id, version: $ver, type: $type, categories: ["secrets"],
		 license: {spdx: "MIT", url: "https://exemple.test/licence", restrictions: "none"},
		 upstream: {homepage: "https://exemple.test", source: "https://exemple.test/src"},
		 image: null, resources: {min_ram_mb: 256, min_cpu: 1, disk_mb: 100}, hostname: null,
		 needs: {sysctl: {}, postgres: false}, requires: {modules: [], feeds: []}, conflicts: [],
		 options: {type: "object", additionalProperties: false, properties: {}},
		 health: null, upgrade: {policy: "on-demand"}, testbed_archive: null, testbed_sha256: null}'
}
GL=$(base_module gitleaks 8.0.0 scanner | jq -c --arg img "$IMAGE" --arg tb "$TB" --arg sha "$TB_SHA" '
	.image = $img | .health = {command: ["gitleaks", "version"]} | .requires.feeds = ["osv-db"]
	| .scan = {inputs: ["repo"], command: ["gitleaks", "dir", "/src"], timeout_s: 60, network: "none"}
	| .outputs = {sarif: {path: "/out/result.sarif", version: "2.1.0"}}
	| .testbed = {path: "testbed/", expect: [{rule: "fake-token", category: "secrets", min: 1}]}
	| .testbed_archive = $tb | .testbed_sha256 = $sha')
OSV=$(base_module osv-db 1 feed | jq -c '.feed = {format: "osv-zip", mount: "/feeds/osv-db",
	source: {kind: "https", ref: "https://feeds.exemple.test/{ecosystem}/all.zip"}, schedule: "daily"}
	| .options.properties.ecosystems = {type: "array", default: ["npm"], items: {type: "string"}}')
jq -n --argjson gl "$GL" --argjson osv "$OSV" \
	'{schema: 1, version: 12, generated_at: "2026-11-24T00:00:00Z", modules: [$gl, $osv], packs: []}' > "$FIX/catalog/catalog-index.json"
printf '%s  catalog-index.json\n%s  %s\n' "$(sha256sum "$FIX/catalog/catalog-index.json" | cut -d' ' -f1)" "$TB_SHA" "$TB" > "$FIX/catalog/SHA256SUMS"
openssl pkeyutl -sign -inkey "$TMP/catalog.key" -rawin -in "$FIX/catalog/SHA256SUMS" -out "$FIX/catalog/SHA256SUMS.sig"

# mkroot DIR [avec catalogue : oui|non]
mkroot() {
	local r=$1
	mkdir -p "$r"/var/lib/scanoria/requests/{tmp,incoming,work,done,failed} "$r/run/scanoria" "$r/etc/scanoria" \
		"$r/opt/scanoria/current" "$r/proc" "$r/var/lib/scanoria/uploads"
	chmod 0700 "$r/var/lib/scanoria/requests/incoming" "$r/var/lib/scanoria/requests/work"
	echo 0.6.0 > "$r/opt/scanoria/current/VERSION"
	printf 'MemTotal:       16384000 kB\n' > "$r/proc/meminfo"
	printf 'processor\t: 0\n' > "$r/proc/cpuinfo"
	echo '{"fqdn": "analyse.exemple.test"}' > "$r/etc/scanoria/appliance.json"
	echo '{"repo": "exemple/scanoria"}' > "$r/etc/scanoria/catalog.json"
	cp "$TMP/catalog.pub" "$r/etc/scanoria/update-pubkey.pem"
	if [[ "${2:-non}" == oui ]]; then
		mkdir -p "$r/var/lib/scanoria/catalog/testbeds"
		cp "$FIX/catalog/catalog-index.json" "$FIX/catalog/SHA256SUMS" "$FIX/catalog/SHA256SUMS.sig" "$r/var/lib/scanoria/catalog/"
		cp "$FIX/catalog/$TB" "$r/var/lib/scanoria/catalog/testbeds/"
		echo '{"repo": "exemple/scanoria", "tag": "catalog-v12", "checked_at": "2026-11-24T00:00:00Z"}' > "$r/var/lib/scanoria/catalog/source.json"
	fi
}
A="$TMP/a"
B="$TMP/b"
mkroot "$A" oui
mkroot "$B"

# hx RACINE TYPE PARAMS : demande au helper de cette appliance ; résultat dans $R
hx() {
	R=$(SCANORIA_TEST_ROOT="$1" "$HELPER" exec --origin cli --type "$2" --params "$3" 2> "$TMP/helper.err") || true
	[[ -n "$R" ]] || { R='{"code":"NO_OUTPUT"}'; sed 's/^/     /' "$TMP/helper.err"; }
}
code() { jq -r .code <<< "$R"; }
out() { jq -r ".output$1" <<< "$R"; }
mode() { stat -c %a "$1"; }
# py RACINE CODE : évalue du Python avec le paquet scanoria de cette appliance
py() { SCANORIA_TEST_ROOT="$1" python3 -c "import sys; sys.path.insert(0, '$ROOT/src/rootfs/usr/lib/scanoria/py'); $2"; }
upload() { # RACINE FICHIER : téléverse comme la console, affiche l'identifiant
	local id
	id=$(python3 -c 'import uuid; print(uuid.uuid4())')
	mkdir -p "$1/var/lib/scanoria/uploads/$id"
	cp "$2" "$1/var/lib/scanoria/uploads/$id/bundle.tar"
	echo "$id"
}

# === 1. Clé de l'appliance =======================================================
hx "$A" trust-key '{"action": "remove", "fingerprint": "'"$(printf '%064d' 0)"'"}'
KEY="$A/etc/scanoria/keys/appliance.ed25519"
expect "clé de l'appliance créée au premier passage du helper" "$([[ -f "$KEY" ]] && echo oui)" oui
expect "clé privée 0600, répertoire 0700" "$(mode "$KEY")/$(mode "$A/etc/scanoria/keys")" 600/700
sum=$(sha256sum "$KEY")
hx "$A" trust-key '{"action": "remove", "fingerprint": "'"$(printf '%064d' 0)"'"}'
expect "clé jamais régénérée" "$(sha256sum "$KEY")" "$sum"
A_PUB=$(py "$A" 'from scanoria import offline; print(offline.appliance_key_info()["public_key"])')
A_FP=$(py "$A" 'from scanoria import offline; print(offline.appliance_key_info()["fingerprint"])')
expect "empreinte = SHA-256 de la clé publique brute" "$A_FP" "$(base64 -d <<< "$A_PUB" | sha256sum | cut -d' ' -f1)"
expect "clé privée jamais publiée dans l'état" "$(grep -rlc 'PRIVATE KEY' "$A/run/scanoria" "$A/var/lib/scanoria/offline" 2> /dev/null | wc -l)" 0

# === 2. Export ===================================================================
hx "$A" export-bundle '{"modules": ["gitleaks"], "dry_run": true}'
expect "estimation : OK sans fichier" "$(code)/$(find "$A/var/lib/scanoria/bundles" -name '*.tar' 2> /dev/null | wc -l)" OK/0
expect "estimation : base requise ajoutée (G1)" "$(out '.modules | join(",")')" gitleaks,osv-db
touch "$FIX/registry-down"
hx "$A" export-bundle '{"modules": ["gitleaks"]}'
expect "registre injoignable : E_BUNDLE_SOURCE" "$(code)" E_BUNDLE_SOURCE
rm "$FIX/registry-down"
hx "$A" export-bundle '{"modules": ["absent"]}'
expect "module inconnu du catalogue refusé" "$(code)" E_NOT_FOUND
hx "$A" export-bundle '{"modules": ["../etc"]}'
expect "identifiant hostile refusé par le schéma" "$(code)" E_SCHEMA

hx "$A" export-bundle '{"modules": ["gitleaks"]}'
expect "export : OK" "$(code)" OK
NAME=$(out .name)
GOOD="$A/var/lib/scanoria/bundles/$NAME"
expect "export : nom horodaté" "$([[ "$NAME" =~ ^scanoria-bundle-[0-9]{8}T[0-9]{6}Z\.tar$ ]] && echo oui)" oui
expect "export : base, image et banc d'essai" "$(out '.feeds | join(",")')/$(out '.images | join(",")')/$(out .testbeds)" osv-db/gitleaks/1
expect "export : signé par la clé de l'appliance" "$(out .signer_fingerprint)" "$A_FP"
expect "export : lot 0640, répertoire 0750 (console en lecture)" "$(mode "$GOOD")/$(mode "$A/var/lib/scanoria/bundles")" 640/750
expect "export : fiche du lot" "$(jq -r .sha256 "${GOOD%.tar}.json")" "$(sha256sum "$GOOD" | cut -d' ' -f1)"
expect "export : ordre des membres" "$(tar -tf "$GOOD" | head -2 | tr '\n' ' ')" "manifest.json manifest.json.sig "
expect "export : aucun répertoire de travail laissé" "$(find "$A/var/lib/scanoria/bundles/.work" -mindepth 1 -maxdepth 1 2> /dev/null | wc -l)" 0
FEED_AT=$(tar -xOf "$GOOD" manifest.json | jq -r '.feeds[0].updated_at')
expect "export : date de la base = date du téléchargement" "$FEED_AT" "$(jq -r .updated_at "$A/var/lib/scanoria/feeds/.store/osv-db/status.json")"

# === 3. Magasin des clés de confiance (B) =======================================
hx "$B" trust-key '{"action": "add", "public_key": "'"$A_PUB"'", "fingerprint": "'"$(printf '%064d' 1)"'"}'
expect "clé de confiance : empreinte fausse refusée" "$(code)" E_KEY_INVALID
hx "$B" trust-key '{"action": "add", "public_key": "AAAA", "fingerprint": "'"$A_FP"'"}'
expect "clé de confiance : clé mal formée refusée" "$(code)" E_SCHEMA
hx "$B" trust-key '{"action": "add", "public_key": "'"$A_PUB"'", "fingerprint": "'"$A_FP"'"}'
expect "clé de confiance : ajout" "$(code)" OK
expect "magasin 0700, clé 0600" "$(mode "$B/etc/scanoria/trusted-keys")/$(mode "$(find "$B/etc/scanoria/trusted-keys" -type f | head -1)")" 700/600

# === 4. Lots piégés ==============================================================
openssl genpkey -algorithm ed25519 -out "$TMP/other.key" 2> /dev/null
STATE_BEFORE=$(find "$B/var/lib/scanoria" -path '*/requests' -prune -o -path '*/uploads' -prune -o -path '*/bundles' -prune -o -print | sort | sha256sum)
trap_bundle() { # libellé piège clé code_attendu
	local f="$TMP/trap-$2.tar" id
	python3 "$FORGE" forge "$GOOD" "$f" "$3" "$2"
	id=$(upload "$B" "$f")
	hx "$B" import-bundle '{"upload_id": "'"$id"'"}'
	expect "lot piégé ($1) : $4" "$(code)" "$4"

	expect "lot piégé ($1) : téléversement supprimé" "$([[ -e "$B/var/lib/scanoria/uploads/$id" ]] && echo reste || echo supprimé)" supprimé
}
trap_bundle "signature fausse" badsig "$KEY" E_BUNDLE_SIGNATURE
trap_bundle "clé inconnue" signer "$TMP/other.key" E_BUNDLE_UNTRUSTED
trap_bundle "image absente de l'index" image-unknown "$KEY" E_BUNDLE_IMAGE
trap_bundle "SHA-256 faux" sha "$KEY" E_BUNDLE_CHECKSUM
trap_bundle "membre « .. »" dotdot-member "$KEY" E_BUNDLE_ARCHIVE
trap_bundle "chemin « .. » déclaré" dotdot-path "$KEY" E_BUNDLE_INVALID
trap_bundle "lien symbolique" symlink "$KEY" E_BUNDLE_ARCHIVE
trap_bundle "fichier non déclaré" extra "$KEY" E_BUNDLE_ARCHIVE
trap_bundle "membre en double" duplicate "$KEY" E_BUNDLE_ARCHIVE
trap_bundle "membre manquant" missing "$KEY" E_BUNDLE_ARCHIVE
trap_bundle "archive tronquée" truncated "$KEY" E_BUNDLE_ARCHIVE
trap_bundle "manifeste trop gros" big-manifest "$KEY" E_BUNDLE_INVALID
trap_bundle "signature avant le manifeste" order "$KEY" E_BUNDLE_ARCHIVE
expect "lots piégés : rien n'a changé sur l'appliance" "$(find "$B/var/lib/scanoria" -path '*/requests' -prune -o -path '*/uploads' -prune -o -path '*/bundles' -prune -o -print | sort | sha256sum)" "$STATE_BEFORE"
expect "lots piégés : aucune image chargée" "$([[ -e "$B/loaded-images" ]] && echo chargée || echo aucune)" aucune
expect "lots piégés : aucun extrait hors de l'appliance" "$(find "$TMP" -name 'evade*' | wc -l)" 0
id=$(python3 -c 'import uuid; print(uuid.uuid4())')
mkdir -p "$B/var/lib/scanoria/uploads/$id"
ln -s "$GOOD" "$B/var/lib/scanoria/uploads/$id/bundle.tar"
hx "$B" import-bundle '{"upload_id": "'"$id"'"}'
expect "téléversement remplacé par un lien refusé" "$(code)" E_BUNDLE_ARCHIVE
hx "$B" import-bundle '{"upload_id": "../../etc"}'
expect "identifiant de téléversement hostile refusé" "$(code)" E_SCHEMA

# === 5. Aller-retour =============================================================
hx "$B" import-bundle '{"upload_id": "'"$(upload "$B" "$GOOD")"'"}'
expect "import : OK" "$(code)" OK
expect "import : index du catalogue installé" "$(out .catalog.installed)/$(jq -r .version "$B/var/lib/scanoria/catalog/catalog-index.json")" true/12
expect "import : banc d'essai" "$(sha256sum "$B/var/lib/scanoria/catalog/testbeds/$TB" | cut -d' ' -f1)" "$TB_SHA"
expect "import : image chargée par son empreinte" "$(cat "$B/loaded-images")" "registry.exemple.test/scanoria/gitleaks@$DIGEST"
expect "import : base appliquée, date d'origine gardée (G16)" "$(out '.feeds[0].applied')/$(jq -r .updated_at "$B/var/lib/scanoria/feeds/.store/osv-db/status.json")" "true/$FEED_AT"
expect "import : base lisible par OSV-Scanner" "$([[ -f "$B/var/lib/scanoria/feeds/osv-db/osv-scalibr/npm/all.zip" ]] && echo oui)" oui
expect "import : fichiers de la base 0640" "$(mode "$B/var/lib/scanoria/feeds/osv-db/osv-scalibr/npm/all.zip")" 640
expect "import : source « bundle »" "$(jq -r .source "$B/var/lib/scanoria/feeds/.store/osv-db/status.json")" bundle
expect "import : état publié" "$(jq -r '.last_import.signer_fingerprint' "$B/var/lib/scanoria/offline/status.json")" "$A_FP"
expect "import : aucun répertoire de travail laissé" "$(find "$B/var/lib/scanoria/bundles/.work" -mindepth 1 -maxdepth 1 2> /dev/null | wc -l)" 0
first=$(readlink "$B/var/lib/scanoria/feeds/osv-db")
hx "$B" import-bundle '{"upload_id": "'"$(upload "$B" "$GOOD")"'"}'
expect "réimport : base non plus récente jamais appliquée" "$(code)/$(out '.feeds[0].applied')/$(out '.feeds[0].reason')" OK/false/not-newer
expect "réimport : base active inchangée" "$(readlink "$B/var/lib/scanoria/feeds/osv-db")" "$first"

# Base plus récente sur A : bascule atomique sur B, version précédente gardée.
sleep 1
py "$A" 'from scanoria import feeds, modules; m = [x for x in modules.catalog() if x["id"] == "osv-db"][0]; feeds.refresh(m, None, timeout=60)'
: > "$A/var/lib/scanoria/bundles/.scanoria-bundle-20261101T000000Z.tar.part"   # export interrompu
hx "$A" export-bundle '{"modules": ["gitleaks"], "keep": 1}'
expect "rotation : fichier partiel d'un export interrompu retiré" "$(find "$A/var/lib/scanoria/bundles" -maxdepth 1 -name '*.part' | wc -l)" 0
expect "deuxième export : rotation (keep 1)" "$(code)/$(out '.removed | length')/$(find "$A/var/lib/scanoria/bundles" -maxdepth 1 -name '*.tar' | wc -l)" OK/1/1
NEWER="$A/var/lib/scanoria/bundles/$(out .name)"
hx "$B" import-bundle '{"upload_id": "'"$(upload "$B" "$NEWER")"'"}'
second=$(readlink "$B/var/lib/scanoria/feeds/osv-db")
expect "base plus récente : bascule par lien" "$(code)/$(out '.feeds[0].applied')/$([[ "$first" != "$second" ]] && echo nouveau)" OK/true/nouveau
expect "base plus récente : version précédente gardée" "$([[ -d "$B/var/lib/scanoria/feeds/$first" ]] && echo gardée)" gardée

# === 6. Clé retirée ==============================================================
hx "$B" trust-key '{"action": "remove", "fingerprint": "'"$A_FP"'"}'
expect "retrait de la clé" "$(code)/$(find "$B/etc/scanoria/trusted-keys" -type f | wc -l)" OK/0
hx "$B" import-bundle '{"upload_id": "'"$(upload "$B" "$NEWER")"'"}'
expect "clé retirée : lot refusé" "$(code)" E_BUNDLE_UNTRUSTED

# === 7. Export périodique ========================================================
hx "$A" export-bundle '{"schedule": {"enabled": true, "every_days": 7, "keep": 2, "modules": []}}'
expect "export périodique sans module refusé" "$(code)" E_INVALID_PARAM
hx "$A" export-bundle '{"schedule": {"enabled": false, "every_days": 7, "keep": 2, "modules": []}}'
hx "$A" export-bundle '{"scheduled": true}'
expect "export périodique désactivé : rien" "$(code)/$(out .skipped)" OK/disabled
hx "$A" export-bundle '{"schedule": {"enabled": true, "every_days": 7, "keep": 2, "modules": ["gitleaks"]}}'
hx "$A" export-bundle '{"scheduled": true}'
expect "export périodique dû : lot produit" "$(code)/$(jq -r .scheduled "$A/var/lib/scanoria/bundles/$(out .name | sed 's/\.tar$/.json/')")" OK/true
hx "$A" export-bundle '{"scheduled": true}'
expect "export périodique pas encore dû : rien" "$(code)/$(out .skipped)" OK/not-due

echo
echo "b25 : $PASS réussis, $FAIL échoués"
[[ "$FAIL" -eq 0 ]]
