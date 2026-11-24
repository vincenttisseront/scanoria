#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Vincent Tisseront
#
# b11 — index du catalogue signé (CLAUDE.md § 4.3, F11, G1), sans root ni
# réseau. Sur les manifestes fictifs de catalog/tests/fixtures/ (et sur les
# vrais modules/ s'ils existent) :
#   - construction reproductible : deux constructions (arbres copiés, dates de
#     fichiers et umask différents) donnent les mêmes octets ;
#   - signature Ed25519 brute de SHA256SUMS par .github/scripts/sign-assets.sh
#     avec une clé JETABLE générée ici, vérifiée par « build.py verify » ;
#     signature d'une autre clé, altérée ou tronquée, index, archive ou
#     SHA256SUMS altérés refusés ;
#   - index hostiles refusés (schéma et cohérence) ;
#   - constructions hostiles refusées (G1 : dépendance introuvable, cycle,
#     conflit ; packs ; YAML piégé ; banc d'essai avec lien) ;
#   - archives de banc d'essai piégées (lien, « .. », chemin absolu) refusées ;
#   - schéma déployé identique à catalog/schema/index.schema.json et chargeable
#     par scanoria/schema.py.
# Dépendances : bash, python3 (PyYAML), jq, openssl (≥ 3.0), zstd, tar.

# shellcheck disable=SC2016,SC2015
set -euo pipefail
export PYTHONDONTWRITEBYTECODE=1

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
B="$ROOT/catalog/build.py"
FX="$ROOT/catalog/tests/fixtures"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

PASS=0
FAIL=0
ok() { PASS=$((PASS + 1)); printf 'ok   %s\n' "$1"; }
ko() { FAIL=$((FAIL + 1)); printf 'FAIL %s\n' "$1"; }
expect_ok() {
	local l=$1
	shift
	if "$@" > "$TMP/log" 2>&1; then ok "$l"; else ko "$l"; sed 's/^/     /' "$TMP/log" | head -n 20; fi
}
expect_ko() { # libellé motif_attendu commande…
	local l=$1 want=$2
	shift 2
	if "$@" > "$TMP/log" 2>&1; then
		ko "$l (accepté à tort)"
	elif grep -q -- "$want" "$TMP/log"; then
		ok "$l"
	else
		ko "$l (refusé, mais sans « $want »)"
		sed 's/^/     /' "$TMP/log" | head -n 10
	fi
}
for t in python3 jq openssl zstd tar sha256sum cmp; do
	command -v "$t" > /dev/null || { echo "outil manquant : $t" >&2; exit 2; }
done
python3 -c 'import yaml' 2> /dev/null || { echo "outil manquant : PyYAML (python3-yaml)" >&2; exit 2; }

DATE=1767225600 # 2026-01-01T00:00:00Z
fx_build() { # sortie [arbre des modules] [packs] [options…]
	local out=$1 mods=${2:-$FX/modules} packs=${3:-$FX/packs.yaml}
	shift 3 2> /dev/null || shift $#
	python3 "$B" build --modules "$mods" --packs "$packs" --module-schema "$FX/module.schema.json" \
		--date "$DATE" --version 7 --out "$out" "$@"
}

# --- Schémas --------------------------------------------------------------------------
expect_ok "schéma déployé identique à catalog/schema/index.schema.json" \
	cmp "$ROOT/catalog/schema/index.schema.json" "$ROOT/src/rootfs/usr/share/scanoria/schemas/catalog-index.schema.json"
expect_ok "schéma déployé chargeable par scanoria/schema.py" \
	python3 -I -c 'import sys; sys.path.insert(0, sys.argv[1]); from scanoria import schema; schema.load("schemas", "catalog-index")' \
	"$ROOT/src/rootfs/usr/lib/scanoria/py"
expect_ok "définition d'un pack identique dans index.schema.json et packs.schema.json" \
	python3 -I -c 'import json, sys
i = json.load(open(sys.argv[1]))["properties"]["packs"]["items"]
p = json.load(open(sys.argv[2]))["properties"]["packs"]["items"]
sys.exit(i != p)' "$ROOT/catalog/schema/index.schema.json" "$ROOT/catalog/schema/packs.schema.json"
expect_ok "catalog/VERSION : entier positif" grep -Eqx '[1-9][0-9]{0,8}' "$ROOT/catalog/VERSION"
expect_ok "catalog/packs.yaml conforme à packs.schema.json" python3 -I -c 'import sys
sys.path.insert(0, sys.argv[1])
import build
v = build.validator(sys.argv[2])
build.validate(v, build.load_yaml(sys.argv[3]), "packs.yaml")' "$ROOT/catalog" "$ROOT/catalog/schema/packs.schema.json" "$ROOT/catalog/packs.yaml"

# --- Construction reproductible ------------------------------------------------------------
expect_ok "construction des manifestes d'essai" fx_build "$TMP/a"
cp -a "$FX" "$TMP/fx2"
find "$TMP/fx2" -exec touch -d '2001-02-03 04:05:06' {} +
(umask 0002 && fx_build "$TMP/b" "$TMP/fx2/modules" "$TMP/fx2/packs.yaml") > "$TMP/log" 2>&1 \
	&& ok "deuxième construction (copie, autres dates, autre umask)" || ko "deuxième construction"
if diff -r "$TMP/a" "$TMP/b" > /dev/null; then ok "deux constructions : mêmes octets"; else ko "deux constructions : octets différents"; fi
expect_ok "reconstruction dans la même sortie" fx_build "$TMP/a"
if diff -r "$TMP/a" "$TMP/b" > /dev/null; then ok "reconstruction : mêmes octets"; else ko "reconstruction : octets différents"; fi
outs=$(cd "$TMP/a" && find . -mindepth 1 -printf '%P\n' | LC_ALL=C sort | tr '\n' ' ')
[[ "$outs" == "SHA256SUMS catalog-index.json testbed-alpha-scan-1.2.3.tar.zst testbed-gamma-svc-10.0.0.tar.zst " ]] \
	&& ok "sorties attendues (index, SHA256SUMS, deux bancs d'essai)" || ko "sorties : $outs"
I="$TMP/a/catalog-index.json"
jq -e '.schema == 1 and .version == 7 and .generated_at == "2026-01-01T00:00:00Z"
	and ([.modules[].id] == ["alpha-scan", "beta-db", "gamma-svc"])
	and (.modules[1].testbed_archive == null and .modules[1].testbed_sha256 == null)
	and (.modules[1].requires == {modules: [], feeds: []} and .modules[1].conflicts == [])
	and (.modules[0].requires.appliance == ">=0.2.0")
	and (.packs == [{id: "essai", name: "Essai", modules: ["alpha-scan", "gamma-svc"], technologies: ["npm"]}])' "$I" > /dev/null \
	&& ok "index : contenu normalisé" || ko "index : contenu normalisé"
[[ "$(head -n 1 "$TMP/a/SHA256SUMS" | cut -c67-)" == "catalog-index.json" ]] && ok "SHA256SUMS : index en première ligne" || ko "SHA256SUMS : première ligne"
(cd "$TMP/a" && sha256sum --check --strict --quiet SHA256SUMS) && ok "SHA256SUMS conforme (sha256sum)" || ko "SHA256SUMS (sha256sum)"
[[ "$(jq -r '.modules[0].testbed_sha256' "$I")" == "$(sha256sum "$TMP/a/testbed-alpha-scan-1.2.3.tar.zst" | cut -d' ' -f1)" ]] \
	&& ok "testbed_sha256 = empreinte de l'archive" || ko "testbed_sha256"
listing=$(zstd -dc "$TMP/a/testbed-alpha-scan-1.2.3.tar.zst" | tar -tvf - | awk '{print $1, $2, $NF}' | tr '\n' ';')
[[ "$listing" == "drwxr-xr-x 0/0 testbed/;-rw-r--r-- 0/0 testbed/README.txt;drwxr-xr-x 0/0 testbed/src/;-rw-r--r-- 0/0 testbed/src/package.json;-rwxr-xr-x 0/0 testbed/src/run.sh;" ]] \
	&& ok "archive : préfixe testbed/, root:root, modes normalisés, ordre trié" || ko "archive : $listing"
zstd -dc "$TMP/a/testbed-alpha-scan-1.2.3.tar.zst" | tar -tvf - --full-time | grep -qv '2026-01-01 00:00:00' \
	&& ko "archive : mtime fixe" || ok "archive : mtime fixe (date de construction)"
expect_ok "vérification sans signature" python3 "$B" verify "$TMP/a" --no-signature --expect-version 7
expect_ko "verify exige --pubkey ou --no-signature" "--pubkey" python3 "$B" verify "$TMP/a"
expect_ko "version attendue différente" "attendue" python3 "$B" verify "$TMP/a" --no-signature --expect-version 8
mkdir -p "$TMP/foreign" && echo x > "$TMP/foreign/notes.txt"
expect_ko "sortie contenant un fichier étranger : rien effacé" "étranger" fx_build "$TMP/foreign"
[[ -f "$TMP/foreign/notes.txt" ]] && ok "fichier étranger conservé" || ko "fichier étranger effacé"

# --- Signature (clés jetables, même procédé que le lot de mise à jour) ----------------------------
K="$TMP/keys"
mkdir -m 0700 "$K"
openssl genpkey -algorithm ed25519 -out "$K/test.key" 2> /dev/null
openssl pkey -in "$K/test.key" -pubout -out "$K/test.pub"
openssl genpkey -algorithm ed25519 -out "$K/other.key" 2> /dev/null
openssl pkey -in "$K/other.key" -pubout -out "$K/other.pub"
cp -a "$TMP/a" "$TMP/signed"
SIGNING_KEY_PEM=$(cat "$K/test.key") bash "$ROOT/.github/scripts/sign-assets.sh" "$K/test.pub" "$TMP/signed/SHA256SUMS" > "$TMP/log" 2>&1 \
	&& ok "signature par sign-assets.sh (clé jetable)" || { ko "signature par sign-assets.sh"; cat "$TMP/log"; }
expect_ok "signature valide vérifiée" python3 "$B" verify "$TMP/signed" --pubkey "$K/test.pub" --expect-version 7
expect_ko "autre clé publique refusée" "signature" python3 "$B" verify "$TMP/signed" --pubkey "$K/other.pub"

fresh() { rm -rf "$TMP/w" && cp -a "$TMP/signed" "$TMP/w"; }
fresh
printf '\x00' | dd of="$TMP/w/SHA256SUMS.sig" bs=1 seek=10 conv=notrunc 2> /dev/null
expect_ko "signature altérée refusée" "signature" python3 "$B" verify "$TMP/w" --pubkey "$K/test.pub"
fresh
head -c 63 "$TMP/signed/SHA256SUMS.sig" > "$TMP/w/SHA256SUMS.sig"
expect_ko "signature tronquée refusée" "64 octets" python3 "$B" verify "$TMP/w" --pubkey "$K/test.pub"
fresh
echo x > "$TMP/w/extra.txt"
expect_ko "fichier étranger à SHA256SUMS refusé" "absents de SHA256SUMS" python3 "$B" verify "$TMP/w" --pubkey "$K/test.pub"
fresh
cp "$TMP/w/testbed-alpha-scan-1.2.3.tar.zst" "$TMP/w/testbed-x-1.tar.zst"
expect_ko "archive non signée ajoutée refusée" "absents de SHA256SUMS" python3 "$B" verify "$TMP/w" --pubkey "$K/test.pub"
fresh
rm "$TMP/w/SHA256SUMS.sig"
expect_ko "signature absente refusée" "absent" python3 "$B" verify "$TMP/w" --pubkey "$K/test.pub"
fresh
echo "$(printf '0%.0s' {1..64})  extra.txt" >> "$TMP/w/SHA256SUMS"
expect_ko "ligne ajoutée à SHA256SUMS refusée (signature)" "signature" python3 "$B" verify "$TMP/w" --pubkey "$K/test.pub"
fresh
sed -i 's/"Alpha Scan"/"Alpha Scam"/' "$TMP/w/catalog-index.json"
expect_ko "index altéré refusé" "empreinte" python3 "$B" verify "$TMP/w" --pubkey "$K/test.pub"
fresh
printf 'x' >> "$TMP/w/testbed-alpha-scan-1.2.3.tar.zst"
expect_ko "archive altérée refusée" "empreinte" python3 "$B" verify "$TMP/w" --pubkey "$K/test.pub"
fresh
rm "$TMP/w/testbed-gamma-svc-10.0.0.tar.zst"
expect_ko "archive absente refusée" "absent" python3 "$B" verify "$TMP/w" --pubkey "$K/test.pub"
fresh
rm "$TMP/w/testbed-gamma-svc-10.0.0.tar.zst" && ln -s testbed-alpha-scan-1.2.3.tar.zst "$TMP/w/testbed-gamma-svc-10.0.0.tar.zst"
expect_ko "archive remplacée par un lien refusée" "lien" python3 "$B" verify "$TMP/w" --pubkey "$K/test.pub"

# Republication cohérente mais incomplète : SHA256SUMS sans une archive, re-signé.
resign() { SIGNING_KEY_PEM=$(cat "$K/test.key") bash "$ROOT/.github/scripts/sign-assets.sh" "$K/test.pub" "$TMP/w/SHA256SUMS" > /dev/null; }
fresh
sed -i '/testbed-gamma/d' "$TMP/w/SHA256SUMS" && rm "$TMP/w/testbed-gamma-svc-10.0.0.tar.zst" && resign
expect_ko "archive de l'index absente de SHA256SUMS refusée" "mêmes archives" python3 "$B" verify "$TMP/w" --pubkey "$K/test.pub"
fresh
{ sed -n 2p "$TMP/signed/SHA256SUMS"; sed -n 1p "$TMP/signed/SHA256SUMS"; sed -n 3p "$TMP/signed/SHA256SUMS"; } > "$TMP/w/SHA256SUMS" && resign
expect_ko "SHA256SUMS sans l'index en première ligne refusé" "première ligne" python3 "$B" verify "$TMP/w" --pubkey "$K/test.pub"
fresh
sed -i 's/  testbed-alpha/ *testbed-alpha/' "$TMP/w/SHA256SUMS" && resign
expect_ko "ligne de SHA256SUMS mal formée refusée" "mal formée" python3 "$B" verify "$TMP/w" --pubkey "$K/test.pub"

# Archive piégée, empreintes et signature recalculées : refusée à son contenu.
trap_archive() { # libellé motif script_python
	local l=$1 want=$2 py=$3
	fresh
	python3 -I -c "$py" "$TMP/w/raw.tar"
	zstd -q -f "$TMP/w/raw.tar" -o "$TMP/w/testbed-alpha-scan-1.2.3.tar.zst" && rm "$TMP/w/raw.tar"
	local sha
	sha=$(sha256sum "$TMP/w/testbed-alpha-scan-1.2.3.tar.zst" | cut -d' ' -f1)
	jq --arg s "$sha" '.modules[0].testbed_sha256 = $s' "$TMP/w/catalog-index.json" > "$TMP/w/i" && mv "$TMP/w/i" "$TMP/w/catalog-index.json"
	(cd "$TMP/w" && sha256sum catalog-index.json testbed-alpha-scan-1.2.3.tar.zst testbed-gamma-svc-10.0.0.tar.zst > SHA256SUMS)
	resign
	expect_ko "$l" "$want" python3 "$B" verify "$TMP/w" --pubkey "$K/test.pub"
}
TAR_HEAD='import io, sys, tarfile
t = tarfile.open(sys.argv[1], "w")
def f(n, kind=tarfile.REGTYPE, link=""):
    i = tarfile.TarInfo(n); i.type = kind; i.linkname = link; d = b"x" if kind == tarfile.REGTYPE else b""
    i.size = len(d); t.addfile(i, io.BytesIO(d))
'
trap_archive "archive avec lien symbolique refusée" "non ordinaire" "$TAR_HEAD"'f("testbed/a", tarfile.SYMTYPE, "/etc/passwd"); t.close()'
trap_archive "archive avec lien physique refusée" "non ordinaire" "$TAR_HEAD"'f("testbed/a"); f("testbed/b", tarfile.LNKTYPE, "testbed/a"); t.close()'
trap_archive "archive avec « .. » refusée" "chemin refusé" "$TAR_HEAD"'f("testbed/../../evil"); t.close()'
trap_archive "archive avec chemin absolu refusée" "chemin refusé" "$TAR_HEAD"'f("/etc/evil"); t.close()'
trap_archive "archive hors de testbed/ refusée" "chemin refusé" "$TAR_HEAD"'f("autre/x"); t.close()'
trap_archive "archive avec périphérique refusée" "non ordinaire" "$TAR_HEAD"'f("testbed/dev", tarfile.CHRTYPE); t.close()'
trap_archive "archive avec membre en double refusée" "double" "$TAR_HEAD"'f("testbed/a"); f("testbed/a"); t.close()'

# --- Index hostiles (schéma et cohérence) -------------------------------------------------------
hostile_index() { # libellé motif filtre_jq
	jq "$3" "$I" > "$TMP/h.json"
	expect_ko "index hostile : $1" "$2" python3 "$B" check-index "$TMP/h.json"
}
expect_ok "index construit conforme (check-index)" python3 "$B" check-index "$I"
hostile_index "schéma 2" "schéma" '.schema = 2'
hostile_index "champ inconnu à la racine" "schéma" '.extra = 1'
hostile_index "version nulle" "schéma" '.version = 0'
hostile_index "version textuelle" "schéma" '.version = "7"'
hostile_index "date mal formée" "schéma" '.generated_at = "hier"'
hostile_index "aucun module" "schéma" '.modules = []'
hostile_index "identifiant avec .." "schéma" '.modules[0].id = "../alpha"'
hostile_index "image par étiquette" "schéma" '.modules[0].image = "registry.exemple.test/outils/alpha:latest"'
hostile_index "scanner sans image" "schéma" 'del(.modules[0].image)'
hostile_index "archive hors du répertoire" "schéma" '.modules[0].testbed_archive = "../../etc/passwd"'
hostile_index "archive d'un autre module" "testbed_archive attendu" '.modules[0].testbed_archive = "testbed-gamma-svc-10.0.0.tar.zst"'
hostile_index "empreinte d'archive mal formée" "schéma" '.modules[0].testbed_sha256 = "abc"'
hostile_index "banc d'essai sans archive" "schéma" '.modules[0].testbed_archive = null'
hostile_index "scanner sans banc d'essai" "schéma" '.modules[0].testbed = null | .modules[0].testbed_archive = null | .modules[0].testbed_sha256 = null'
hostile_index "restriction de licence inconnue" "schéma" '.modules[0].license.restrictions = "aucune"'
hostile_index "type inconnu" "schéma" '.modules[0].type = "plugin"'
hostile_index "requires avec champ inconnu" "schéma" '.modules[0].requires.services = []'
hostile_index "requires.appliance mal formé" "schéma" '.modules[0].requires.appliance = "0.2"'
hostile_index "libellé DNS invalide" "schéma" '.modules[2].hostname = "Gamma_svc"'
hostile_index "libellé DNS en double" "en double" '.modules[1].hostname = "gamma"'
hostile_index "service sans libellé DNS" "schéma" '.modules[2].hostname = null'
hostile_index "module en double" "non triés\|double" '.modules += [.modules[0]]'
hostile_index "modules non triés" "non triés" '.modules |= reverse'
hostile_index "base requise introuvable" "introuvable" '.modules[0].requires.feeds = ["absente"]'
hostile_index "module requis de type base" "feed" '.modules[2].requires.modules = ["beta-db"]'
hostile_index "conflit dans les dépendances" "conflit" '.modules[2].conflicts = ["beta-db"]'
hostile_index "conflit avec un module introuvable" "introuvable" '.modules[2].conflicts = ["absent"]'
hostile_index "dépendance circulaire" "circulaire" '.modules[0].requires.modules = ["gamma-svc"]'
hostile_index "pack vers un module absent" "absent" '.packs[0].modules += ["absent"]'
hostile_index "pack contenant une base" "base" '.packs[0].modules += ["beta-db"]'
hostile_index "pack en double" "double" '.packs += [.packs[0]]'
hostile_index "pack avec champ inconnu" "schéma" '.packs[0].prix = 0'
printf '{"schema": 1, "version": NaN}' > "$TMP/h.json"
expect_ko "index hostile : constante NaN" "constante" python3 "$B" check-index "$TMP/h.json"
printf '\xff\xfe' > "$TMP/h.json"
expect_ko "index hostile : octets non UTF-8" "JSON invalide" python3 "$B" check-index "$TMP/h.json"

# --- Constructions hostiles -------------------------------------------------------------------
hostile_build() { # libellé motif script_bash (dans la copie $TMP/hb)
	rm -rf "$TMP/hb" && cp -a "$FX" "$TMP/hb"
	(cd "$TMP/hb" && bash -c "$3")
	expect_ko "construction hostile : $1" "$2" fx_build "$TMP/hb-out" "$TMP/hb/modules" "$TMP/hb/packs.yaml"
}
hostile_build "dépendance introuvable" "introuvable" 'sed -i "s/feeds: \[beta-db\]/feeds: [absente]/" modules/alpha-scan/module.yaml'
hostile_build "module requis introuvable" "introuvable" 'sed -i "s/modules: \[alpha-scan\]/modules: [absent]/" modules/gamma-svc/module.yaml'
hostile_build "conflit avec une dépendance" "conflit" 'sed -i "s/^conflicts: \[\]/conflicts: [alpha-scan]/" modules/gamma-svc/module.yaml'
hostile_build "conflit à l'intérieur d'un pack" "conflit" 'echo "conflicts: [gamma-svc]" >> modules/alpha-scan/module.yaml'
hostile_build "dépendance circulaire" "circulaire" 'sed -i "s/requires: { feeds/requires: { modules: [gamma-svc], feeds/" modules/alpha-scan/module.yaml'
hostile_build "pack vers un module absent" "absent" 'sed -i "s/\[alpha-scan, gamma-svc\]/[alpha-scan, absent]/" packs.yaml'
hostile_build "pack contenant une base" "base" 'sed -i "s/\[alpha-scan, gamma-svc\]/[alpha-scan, beta-db]/" packs.yaml'
hostile_build "pack avec champ inconnu" "schéma" 'echo "    prix: 0" >> packs.yaml'
hostile_build "id différent du répertoire" "répertoire" 'sed -i "s/^id: alpha-scan/id: alpha-scan2/" modules/alpha-scan/module.yaml'
hostile_build "manifeste hors schéma (image par étiquette)" "schéma" 'sed -i "s|alpha@sha256:0*|alpha:latest|" modules/alpha-scan/module.yaml'
hostile_build "répertoire de module mal nommé" "identifiant" 'mv modules/beta-db modules/Beta_DB'
hostile_build "lien symbolique dans le banc d'essai" "lien" 'ln -s /etc/passwd modules/alpha-scan/testbed/src/passwd'
hostile_build "lien physique dans le banc d'essai" "lien physique" 'ln modules/alpha-scan/testbed/README.txt modules/alpha-scan/testbed/LISEZMOI.txt'
hostile_build "banc d'essai qui est un lien" "lien" 'mv modules/gamma-svc/testbed modules/gamma-svc/vrai && ln -s vrai modules/gamma-svc/testbed'
hostile_build "FIFO dans le banc d'essai" "ordinaires" 'mkfifo modules/alpha-scan/testbed/fifo'
hostile_build "nom de fichier douteux dans le banc d'essai" "nom de fichier" 'touch "modules/alpha-scan/testbed/a b\$(x)"'
hostile_build "testbed.path sortant" "testbed.path" 'sed -i "s|path: testbed/|path: ../gamma-svc/testbed|" modules/alpha-scan/module.yaml'
hostile_build "banc d'essai absent" "absent" 'rm -r modules/gamma-svc/testbed'
hostile_build "scanner sans banc d'essai" "banc d'essai" 'python3 -I -c "import sys; p=sys.argv[1]; s=open(p).read(); open(p,\"w\").write(s[:s.index(\"testbed:\")])" modules/alpha-scan/module.yaml'
hostile_build "manifeste lien symbolique" "lien" 'mv modules/beta-db/module.yaml modules/beta-db/m.yaml && ln -s m.yaml modules/beta-db/module.yaml'
hostile_build "YAML : alias" "alias" 'printf "a: &x [1]\nb: *x\n" >> modules/beta-db/module.yaml'
hostile_build "YAML : clé en double" "double" 'echo "name: Autre" >> modules/beta-db/module.yaml'
hostile_build "YAML : plusieurs documents" "un seul document" 'printf -- "---\nid: x\n" >> modules/beta-db/module.yaml'
hostile_build "YAML : étiquette Python" "YAML invalide" 'echo "x: !!python/object/apply:os.system [id]" >> modules/beta-db/module.yaml'
rm -rf "$TMP/hb" && cp -a "$FX" "$TMP/hb" && sed -i "s/^name: Beta DB/name: yes/" "$TMP/hb/modules/beta-db/module.yaml"
fx_build "$TMP/hb-out" "$TMP/hb/modules" "$TMP/hb/packs.yaml" > /dev/null 2>&1 \
	&& [[ "$(jq -r '.modules[1].name | type + ":" + .' "$TMP/hb-out/catalog-index.json")" == "string:yes" ]] \
	&& ok "YAML : yes reste une chaîne" || ko "YAML : yes reste une chaîne"
hostile_build "YAML : version flottante" "schéma" 'sed -i "s/^version: \"2026.11.1\"/version: 2026.11/" modules/beta-db/module.yaml'
hostile_build "requires.appliance mal formé" "appliance" 'sed -i "s/>=0.2.0/0.2/" modules/alpha-scan/module.yaml'
rm -rf "$TMP/hb" && cp -a "$FX" "$TMP/hb" && echo "0" > "$TMP/VERSION0"
expect_ko "construction hostile : catalog/VERSION nul" "entier positif" python3 -I -c 'import sys
sys.path.insert(0, sys.argv[1]); import build
build.read_catalog_version(sys.argv[2])' "$ROOT/catalog" "$TMP/VERSION0"
echo '{"$ref": "#/x"}' > "$TMP/ref.schema.json"
expect_ko "construction hostile : schéma de module hors sous-ensemble" "non pris en charge" \
	python3 "$B" build --modules "$FX/modules" --packs "$FX/packs.yaml" --module-schema "$TMP/ref.schema.json" \
	--date "$DATE" --version 1 --out "$TMP/hb-out"

# --- Vrai catalogue (modules/ du dépôt), quand il existe -------------------------------------------
shopt -s nullglob
manifests=("$ROOT"/modules/*/module.yaml)
if [[ ${#manifests[@]} -gt 0 ]]; then
	expect_ok "vrai catalogue : construction" python3 "$B" build --date "$DATE" --out "$TMP/real1"
	expect_ok "vrai catalogue : deuxième construction" python3 "$B" build --date "$DATE" --out "$TMP/real2"
	if diff -r "$TMP/real1" "$TMP/real2" > /dev/null; then ok "vrai catalogue : mêmes octets"; else ko "vrai catalogue : octets différents"; fi
	expect_ok "vrai catalogue : vérification" python3 "$B" verify "$TMP/real1" --no-signature \
		--expect-version "$(tr -d '[:space:]' < "$ROOT/catalog/VERSION")"
else
	echo "info vrai catalogue : aucun modules/*/module.yaml dans le dépôt, construction réelle non testée"
fi

echo "b11 : $PASS ok, $FAIL échec(s)"
[[ "$FAIL" -eq 0 ]]
