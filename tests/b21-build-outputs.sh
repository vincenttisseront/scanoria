#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Vincent Tisseront
#
# b21 — sorties RÉELLES de « build.sh --bundle » ou « --iso » (ARCHITECTURE
# § 6.2, § 6.3), sans root ni réseau. Lit SCANORIA_OUT ; sans cette variable
# (batteries de la CI hors construction), la batterie est sautée.
#   - SHA256SUMS : exactement deux lignes, empreintes exactes ;
#   - release.json : schéma, version, archive, empreinte, taille, node_major ;
#   - archive : uniquement fichiers et répertoires sous scanoria-X.Y.Z/, rootfs
#     dans les préfixes autorisés, update-source.json, MANIFEST, console,
#     migrations, assistant de premier démarrage, aucune clé privée ;
#   - installation initiale (scanoria-selfupdate install-local) du lot réel
#     dans une arborescence de test (SCANORIA_TEST_ROOT, commandes système
#     remplacées par des bouchons) ;
#   - ISO (si présente) : empreinte, contenu ajouté (autoinstall, scripts,
#     lot identique à celui de la sortie, dépôt hors ligne).
# Dépendances : bash, python3 (+ jsonschema si disponible), jq, zstd, tar,
# sha256sum, xorriso (pour l'ISO).

# shellcheck disable=SC2016
set -euo pipefail
export PYTHONDONTWRITEBYTECODE=1

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
OUT=${SCANORIA_OUT:-}
if [[ -z "$OUT" ]]; then
	echo "b21 : SCANORIA_OUT absent, batterie sautée (sorties de construction requises)"
	exit 0
fi
[[ -d "$OUT" ]] || { echo "b21 : SCANORIA_OUT=$OUT n'est pas un répertoire" >&2; exit 2; }
for t in python3 jq zstd tar sha256sum; do command -v "$t" > /dev/null || { echo "outil manquant : $t" >&2; exit 2; }; done

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
PASS=0
FAIL=0
ok() { PASS=$((PASS + 1)); printf 'ok   %s\n' "$1"; }
ko() { FAIL=$((FAIL + 1)); printf 'FAIL %s\n' "$1"; }
check() { # libellé commande…
	local label=$1
	shift
	if "$@" > "$TMP/last.log" 2>&1; then ok "$label"; else ko "$label"; sed 's/^/     /' "$TMP/last.log" | head -n 20; fi
}

V=$(tr -d '[:space:]' < "$ROOT/VERSION")
A="scanoria-$V.tar.zst"
ALLOWED='^usr/(sbin/scanoria-[a-z0-9][a-z0-9-]*|lib/scanoria/.+|share/scanoria/.+|lib/systemd/system/scanoria-[A-Za-z0-9@._-]+|lib/sysusers\.d/scanoria\.conf|lib/tmpfiles\.d/scanoria\.conf)$'

# --- Actifs ----------------------------------------------------------------------
for f in "$A" release.json SHA256SUMS; do check "présent : $f" test -s "$OUT/$f"; done
check "SHA256SUMS : exactement 2 lignes (release.json, archive)" bash -c \
	'[[ $(wc -l < "$1/SHA256SUMS") -eq 2 ]] && awk "{print \$2}" "$1/SHA256SUMS" | tr "\n" " " | grep -qx "release.json $2 "' _ "$OUT" "$A"
check "SHA256SUMS : empreintes exactes" bash -c 'cd "$1" && sha256sum --check --strict --quiet SHA256SUMS' _ "$OUT"

cat > "$TMP/rel.py" <<'EOF'
import hashlib, json, os, sys
schema_path, rel_path, out, version, node_major = sys.argv[1:6]
rel = json.load(open(rel_path))
try:
    import jsonschema
except ImportError:
    jsonschema = None
if jsonschema is not None:
    jsonschema.validate(rel, json.load(open(schema_path)))
else:
    print("jsonschema absent : contrôle des champs seulement")
    for k in ("release", "tag", "commit", "built_at", "archive", "archive_sha256",
              "archive_size", "min_upgrade_from", "node_major", "notes_md"):
        assert k in rel, k
assert rel["release"] == version, rel["release"]
assert rel["tag"] == "v" + version
assert rel["archive"] == "scanoria-%s.tar.zst" % version
a = os.path.join(out, rel["archive"])
assert rel["archive_size"] == os.path.getsize(a) <= 1 << 30
h = hashlib.sha256()
with open(a, "rb") as f:
    for b in iter(lambda: f.read(1 << 20), b""):
        h.update(b)
assert rel["archive_sha256"] == h.hexdigest()
assert rel["node_major"] == int(node_major)
assert rel["notes_md"].strip(), "notes_md vide"
EOF
NODE_MAJOR=$(sed -n 's/^NODE_VERSION=\([0-9]*\)\..*/\1/p' "$ROOT/src/iso/node-release.env")
check "release.json : schéma et cohérence" python3 -I "$TMP/rel.py" \
	"$ROOT/src/rootfs/usr/share/scanoria/schemas/release.schema.json" "$OUT/release.json" "$OUT" "$V" "$NODE_MAJOR"

# --- Archive ---------------------------------------------------------------------
tar --zstd -tvf "$OUT/$A" > "$TMP/list" 2> /dev/null || true
check "archive : lisible" test -s "$TMP/list"
check "archive : fichiers et répertoires seulement" bash -c '! cut -c1 "$1" | grep -qv "^[-d]$"' _ "$TMP/list"
tar --zstd -tf "$OUT/$A" > "$TMP/names" 2> /dev/null || true
check "archive : tout sous scanoria-$V/, ni .. ni chemin absolu" bash -c \
	'! grep -vE "^scanoria-$2(/|$)" "$1" && ! grep -qE "(^|/)\.\.(/|$)|^/" "$1"' _ "$TMP/names" "$V"
mkdir -p "$TMP/x"
tar --zstd -xf "$OUT/$A" -C "$TMP/x" --no-same-owner --no-same-permissions
L="$TMP/x/scanoria-$V"
check "lot : VERSION et webui/VERSION = $V" bash -c '[[ $(cat "$1/VERSION") == "$2" && $(cat "$1/webui/VERSION") == "$2" ]]' _ "$L" "$V"
for f in LICENSE CHANGELOG.md OPEN-SOURCE.md webui/server/index.mjs webui/nitro.json webui/migrate.mjs \
	webui/migrations/001_initial.sql rootfs/usr/sbin/scanoria-helper rootfs/usr/sbin/scanoria-selfupdate \
	rootfs/usr/sbin/scanoria-firstboot rootfs/usr/lib/systemd/system/scanoria-firstboot.service \
	rootfs/usr/lib/systemd/system/scanoria-console.service rootfs/usr/share/scanoria/MANIFEST \
	webui/services/worker.mjs rootfs/usr/lib/systemd/system/scanoria-worker.service; do
	check "lot : $f" test -s "$L/$f"
done
check "lot : pg embarqué pour migrate.mjs (webui/server/node_modules/pg)" test -f "$L/webui/server/node_modules/pg/package.json"
check "rootfs : préfixes autorisés (§ 3.3)" bash -c \
	'cd "$1/rootfs" && ! find . -type f -printf "%P\n" | grep -vE "$2"' _ "$L" "$ALLOWED"
check "rootfs : update-source.json conforme" bash -c \
	'jq -e "keys == [\"repo\"] and (.repo | test(\"^[A-Za-z0-9-]{1,39}/[A-Za-z0-9._-]{1,100}$\"))" "$1/rootfs/usr/share/scanoria/update-source.json"' _ "$L"
check "rootfs : MANIFEST = fichiers déployés" bash -c \
	'diff <(cd "$1/rootfs" && find . -type f -printf "/%P\n" | LC_ALL=C sort) "$1/rootfs/usr/share/scanoria/MANIFEST"' _ "$L"
# Même motif que build.sh (en-tête suivi d'un corps base64) : un simple texte
# indicatif (champ de saisie de la console) n'est pas une clé.
cat > "$TMP/pk.py" <<'EOF'
import os, re, sys
pat = re.compile(rb"-----BEGIN ([A-Z0-9]+ )*PRIVATE KEY-----\r?\n[A-Za-z0-9+/=]{40,}")
bad = []
for d, _, files in os.walk(sys.argv[1]):
    for n in files:
        p = os.path.join(d, n)
        if n.endswith((".key", ".p12", ".pfx")) or pat.search(open(p, "rb").read()):
            bad.append(p)
print("\n".join(bad))
sys.exit(1 if bad else 0)
EOF
check "lot : aucune clé privée" python3 -I "$TMP/pk.py" "$L"
check "lot : migrations = celles du dépôt" diff -r "$ROOT/webui/server/db/migrations" "$L/webui/migrations"

# --- Installation initiale du lot réel (arborescence de test) ----------------------
T="$TMP/root"
STUBS="$TMP/stubs"
mkdir -p "$T/etc/scanoria" "$T/opt/scanoria" "$T/run/scanoria" "$STUBS"
cp "$ROOT/update-pubkey.pem" "$T/etc/scanoria/update-pubkey.pem"
printf '#!/bin/bash\necho v%s.0.0\n' "$NODE_MAJOR" > "$STUBS/node"
printf '#!/bin/bash\nexit 0\n' > "$STUBS/scanoria-state"
chmod 0755 "$STUBS"/*
mkdir -p "$TMP/assets"
cp "$OUT/$A" "$OUT/release.json" "$OUT/SHA256SUMS" "$TMP/assets/"
res=$(SCANORIA_TEST_ROOT="$T" SCANORIA_TEST_BIN="$STUBS" bash "$L/rootfs/usr/sbin/scanoria-selfupdate" \
	install-local "$TMP/assets" 2> "$TMP/install.err" || true)
check "install-local : code OK" test "$(jq -r '.code // empty' <<< "$res" 2> /dev/null)" = OK
check "install-local : current → releases/$V" test "$(readlink "$T/opt/scanoria/current")" = "releases/$V"
check "install-local : commandes déployées" test -x "$T/usr/sbin/scanoria-helper" -a -x "$T/usr/sbin/scanoria-firstboot"
check "install-local : MANIFEST déployé" cmp "$L/rootfs/usr/share/scanoria/MANIFEST" "$T/usr/share/scanoria/MANIFEST"
check "install-local : rien hors des préfixes" bash -c \
	'cd "$1" && ! find usr -type f -printf "%P\n" | sed "s#^#usr/#" | grep -vE "$2"' _ "$T" "$ALLOWED"

# --- ISO (facultative) -------------------------------------------------------------
ISO="$OUT/scanoria-$V-amd64.iso"
if [[ -f "$ISO" ]]; then
	command -v xorriso > /dev/null || { echo "outil manquant : xorriso" >&2; exit 2; }
	check "ISO : empreinte .sha256" bash -c 'cd "$1" && sha256sum --check --strict --quiet "$2.sha256"' _ "$OUT" "$(basename "$ISO")"
	{ xorriso -indev "$ISO" -find / -type f 2> /dev/null || true; } | tr -d "'" > "$TMP/iso-files"
	for f in /nocloud/user-data /nocloud/meta-data /boot/grub/grub.cfg /scanoria/late-install.sh \
		/scanoria/check-hardware.sh /scanoria/update-pubkey.pem /scanoria/iso.env /scanoria/SHA256SUMS \
		/scanoria/pool/Packages "/scanoria/bundle/$A" /scanoria/bundle/release.json /scanoria/bundle/SHA256SUMS; do
		check "ISO : $f" grep -qx -- "$f" "$TMP/iso-files"
	done
	mkdir -p "$TMP/iso"
	xorriso -osirrox on -indev "$ISO" -extract /scanoria/bundle/SHA256SUMS "$TMP/iso/SHA256SUMS" \
		-extract /scanoria/update-pubkey.pem "$TMP/iso/update-pubkey.pem" > /dev/null 2>&1 || true
	check "ISO : lot embarqué = lot de la sortie" cmp "$OUT/SHA256SUMS" "$TMP/iso/SHA256SUMS"
	check "ISO : clé publique = update-pubkey.pem" cmp "$ROOT/update-pubkey.pem" "$TMP/iso/update-pubkey.pem"
else
	echo "skip ISO absente de $OUT"
fi

printf '\nb21 : %d réussi(s), %d échec(s)\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
