#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Vincent Tisseront
#
# b20 — ISO et installation, contrôles statiques sans root ni réseau :
#   - présence des fichiers, en-têtes SPDX, fins de ligne LF ;
#   - shellcheck et bash -n sur les scripts du lot ;
#   - YAML de l'autoinstall (user-data, meta-data) et menu GRUB ;
#   - valeurs épinglées (ISO de base, Node.js, clé GPG, update-pubkey.pem) ;
#   - vérification d'empreinte sur une fausse ISO (cas valides et hostiles) ;
#   - assemblage du lot (§ 6.3) sur une fausse sortie de console : préfixes,
#     liens, clés privées, update-source.json, MANIFEST, release.json,
#     SHA256SUMS, reproductibilité ;
#   - plancher matériel D6 ;
#   - contrôles de l'assistant de premier démarrage (FQDN, réseaux, PBKDF2).
# Dépendances : bash, python3 (+ PyYAML), jq, zstd, tar, gpg, openssl,
# ShellCheck (pip install shellcheck-py), xorriso (facultatif).

# Les « bash -c '…' » reçoivent leurs valeurs en arguments : voulu.
# shellcheck disable=SC2016
# shellcheck source-path=SCRIPTDIR/..
set -euo pipefail
export PYTHONDONTWRITEBYTECODE=1

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
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
refuse() { # libellé commande… (doit échouer)
	local label=$1
	shift
	if "$@" > "$TMP/last.log" 2>&1; then ko "$label (accepté à tort)"; else ok "$label"; fi
}
need() { command -v "$1" > /dev/null 2>&1 || { echo "outil manquant : $1" >&2; exit 2; }; }
for t in python3 jq zstd tar gpg gpgv openssl shellcheck sha256sum; do need "$t"; done
python3 -c 'import yaml' 2> /dev/null || { echo "PyYAML manquant (python3-yaml)" >&2; exit 2; }

FB="$ROOT/src/rootfs/usr/lib/scanoria/firstboot"
FBS="$ROOT/src/rootfs/usr/sbin/scanoria-firstboot"
SCRIPTS=(build.sh src/iso/scripts/check-hardware.sh src/iso/scripts/late-install.sh
	src/rootfs/usr/sbin/scanoria-firstboot tests/b20-iso-static.sh)
FILES=("${SCRIPTS[@]}" make-iso.ps1 src/iso/ubuntu-release.env src/iso/node-release.env
	src/iso/build.env src/iso/packages.list src/iso/autoinstall/user-data
	src/iso/autoinstall/meta-data src/iso/grub/grub.cfg src/iso/keys/ubuntu-cdimage-2012.asc
	src/rootfs/usr/lib/systemd/system/scanoria-firstboot.service
	src/rootfs/usr/lib/scanoria/firstboot/hash-password.py
	src/rootfs/usr/lib/scanoria/firstboot/netcheck.py update-pubkey.pem)

# --- Fichiers -----------------------------------------------------------------
for f in "${FILES[@]}"; do
	check "présent : $f" test -s "$ROOT/$f"
done
for f in "${FILES[@]}"; do
	case "$f" in *.asc|*.pem) continue ;; esac
	check "SPDX : $f" grep -q 'SPDX-License-Identifier: AGPL-3.0-or-later' "$ROOT/$f"
	check "copyright : $f" grep -q 'Copyright (C) 2026 Vincent Tisseront' "$ROOT/$f"
	refuse "fins de ligne LF : $f" grep -q $'\r' "$ROOT/$f"
done
for f in build.sh src/iso/scripts/check-hardware.sh src/iso/scripts/late-install.sh \
	src/rootfs/usr/sbin/scanoria-firstboot tests/b20-iso-static.sh; do
	check "exécutable : $f" test -x "$ROOT/$f"
done

# --- Scripts ----------------------------------------------------------------
for f in "${SCRIPTS[@]}"; do
	check "bash -n : $f" bash -n "$ROOT/$f"
	check "shellcheck : $f" shellcheck -x "$ROOT/$f"
done
check "python : hash-password.py, netcheck.py" python3 -I -c \
	'import ast, sys; [ast.parse(open(p).read(), p) for p in sys.argv[1:]]' "$FB/hash-password.py" "$FB/netcheck.py"

# --- Autoinstall --------------------------------------------------------------
UD="$ROOT/src/iso/autoinstall/user-data"
check "user-data : 1re ligne #cloud-config" test "$(head -n 1 "$UD")" = "#cloud-config"
cat > "$TMP/ud.py" <<'EOF'
import sys, yaml
d = yaml.safe_load(open(sys.argv[1]))
a = d["autoinstall"]
assert a["version"] == 1
assert a["interactive-sections"] == []
assert a["storage"]["layout"]["name"] == "lvm"
assert a["locale"] == "en_US.UTF-8"
assert a["shutdown"] == "poweroff"
assert ["sh", "/cdrom/scanoria/check-hardware.sh"] in a["early-commands"]
assert ["bash", "/cdrom/scanoria/late-install.sh"] in a["late-commands"]
assert "identity" not in a, "pas de mot de passe dans user-data"
users = a["user-data"]["users"]
assert all(u.get("lock_passwd") is True for u in users)
assert not any(k in u for u in users for k in ("passwd", "hashed_passwd", "plain_text_passwd"))
assert a["ssh"]["install-server"] is True
EOF
check "user-data : YAML et contenu" python3 -I "$TMP/ud.py" "$UD"
check "meta-data : YAML" python3 -I -c 'import sys,yaml; d=yaml.safe_load(open(sys.argv[1])); assert d["instance-id"]' \
	"$ROOT/src/iso/autoinstall/meta-data"
refuse "aucun mot de passe en clair dans src/iso" grep -rniE '(^|[[:space:]])(password|passwd|plain_text_passwd|hashed_passwd)[[:space:]]*:' \
	"$ROOT/src/iso/autoinstall"
# Seul l'identifiant technique de la source d'installation (id: ubuntu-server) est admis.
refuse "aucune mention d'Ubuntu (user-data, grub.cfg)" bash -c 'grep -hi ubuntu "$1" "$2" | grep -vqE "^[[:space:]]+id: ubuntu-server$"' _ "$UD" "$ROOT/src/iso/grub/grub.cfg"
check "grub.cfg : autoinstall nocloud" grep -q 'autoinstall ds=nocloud\\;s=/cdrom/nocloud/' "$ROOT/src/iso/grub/grub.cfg"
check "grub.cfg : noyau et initrd" grep -qE '^\s*initrd\s+/casper/initrd' "$ROOT/src/iso/grub/grub.cfg"

# --- Valeurs épinglées ------------------------------------------------------
# shellcheck source=build.sh
source "$ROOT/build.sh"
UE="$ROOT/src/iso/ubuntu-release.env"
NE="$ROOT/src/iso/node-release.env"
check "ubuntu-release.env : empreinte" bash -c '[[ $1 =~ ^[0-9a-f]{64}$ ]]' _ "$(env_get "$UE" UBUNTU_ISO_SHA256)"
check "ubuntu-release.env : nom de l'ISO 24.04.x" bash -c '[[ $1 =~ ^ubuntu-24\.04(\.[0-9]+)?-live-server-amd64\.iso$ ]]' _ "$(env_get "$UE" UBUNTU_ISO_NAME)"
check "ubuntu-release.env : HTTPS" bash -c '[[ $1 == https://* ]]' _ "$(env_get "$UE" UBUNTU_ISO_BASE_URL)"
check "node-release.env : Node 22" bash -c '[[ $1 =~ ^22\.[0-9]+\.[0-9]+$ && $2 == "node-v$1-linux-x64.tar.xz" && $3 =~ ^[0-9a-f]{64}$ ]]' _ \
	"$(env_get "$NE" NODE_VERSION)" "$(env_get "$NE" NODE_TARBALL)" "$(env_get "$NE" NODE_SHA256)"
GPGH="$TMP/gnupg"; mkdir -m 0700 "$GPGH"
GNUPGHOME="$GPGH" gpg --batch --quiet --no-auto-check-trustdb --import "$ROOT/$(printf 'src/iso/%s' "$(env_get "$UE" UBUNTU_GPG_KEY_FILE)")" 2> /dev/null
check "clé GPG de l'ISO = empreinte épinglée" test "$(GNUPGHOME="$GPGH" gpg --batch --with-colons --fingerprint 2> /dev/null | awk -F: '$1=="fpr"{print $10; exit}')" = "$(env_get "$UE" UBUNTU_GPG_FPR)"
check "update-pubkey.pem = empreinte épinglée" test \
	"$(openssl pkey -pubin -in "$ROOT/update-pubkey.pem" -outform DER | sha256sum | cut -d' ' -f1)" = \
	"$(env_get "$ROOT/src/iso/build.env" UPDATE_PUBKEY_SHA256)"
check "build.env : image de construction épinglée par empreinte" bash -c '[[ $1 =~ ^docker\.io/library/ubuntu:24\.04@sha256:[0-9a-f]{64}$ ]]' _ "$(env_get "$ROOT/src/iso/build.env" BUILD_IMAGE)"
check "packages.list : noms valides" bash -c '! grep -Ev "^[[:space:]]*(#|$)" "$1" | grep -vqE "^[a-z0-9][a-z0-9.+-]+$"' _ "$ROOT/src/iso/packages.list"
for p in postgresql-16 nginx podman nftables jq zstd openssl curl whiptail python3; do
	check "packages.list : $p" grep -qx "$p" "$ROOT/src/iso/packages.list"
done

# --- Empreinte sur une fausse ISO ------------------------------------------------
head -c 1048576 /dev/urandom > "$TMP/fake.iso"
SHA=$(sha256sum "$TMP/fake.iso" | cut -d' ' -f1)
printf '%s *fake.iso\n%s *other.iso\n' "$SHA" "$(printf '0%.0s' {1..64})" > "$TMP/SUMS"
check "ISO : empreinte conforme" verify_iso_checksum "$TMP/fake.iso" "$TMP/SUMS" fake.iso "$SHA"
printf '%s  fake.iso\n' "$SHA" > "$TMP/SUMS.text"
check "ISO : format sha256sum texte" verify_iso_checksum "$TMP/fake.iso" "$TMP/SUMS.text" fake.iso "$SHA"
refuse "ISO : empreinte épinglée différente" verify_iso_checksum "$TMP/fake.iso" "$TMP/SUMS" fake.iso "$(printf 'a%.0s' {1..64})"
refuse "ISO : absente de SHA256SUMS" verify_iso_checksum "$TMP/fake.iso" "$TMP/SUMS" absent.iso "$SHA"
printf '%s *fake.iso\n%s *fake.iso\n' "$SHA" "$SHA" > "$TMP/SUMS.dup"
refuse "ISO : ligne en double" verify_iso_checksum "$TMP/fake.iso" "$TMP/SUMS.dup" fake.iso "$SHA"
cp "$TMP/fake.iso" "$TMP/fake2.iso"; printf 'x' >> "$TMP/fake2.iso"; mv "$TMP/fake2.iso" "$TMP/fake.iso"
refuse "ISO : fichier altéré" verify_iso_checksum "$TMP/fake.iso" "$TMP/SUMS" fake.iso "$SHA"
refuse "ISO : empreinte épinglée mal formée" verify_iso_checksum "$TMP/fake.iso" "$TMP/SUMS" fake.iso "XYZ"
# Signature GPG : une signature d'une autre clé est refusée.
GPGO="$TMP/gnupg-other"; mkdir -m 0700 "$GPGO"
GNUPGHOME="$GPGO" gpg --batch --quiet --pinentry-mode loopback --passphrase '' \
	--quick-gen-key 'Test <test@exemple.test>' ed25519 sign never 2> /dev/null
GNUPGHOME="$GPGO" gpg --batch --quiet --detach-sign -o "$TMP/SUMS.gpg" "$TMP/SUMS" 2> /dev/null
refuse "SHA256SUMS signé par une clé inconnue" verify_sums_signature "$TMP/SUMS" "$TMP/SUMS.gpg" \
	"$ROOT/src/iso/keys/ubuntu-cdimage-2012.asc" "$(env_get "$UE" UBUNTU_GPG_FPR)"
GNUPGHOME="$GPGO" gpg --batch --quiet --armor --export > "$TMP/other.asc"
OFPR=$(GNUPGHOME="$GPGO" gpg --batch --with-colons --fingerprint 2> /dev/null | awk -F: '$1=="fpr"{print $10; exit}')
check "SHA256SUMS signé par la clé attendue" verify_sums_signature "$TMP/SUMS" "$TMP/SUMS.gpg" "$TMP/other.asc" "$OFPR"
printf 'x' >> "$TMP/SUMS"
refuse "SHA256SUMS modifié après signature" verify_sums_signature "$TMP/SUMS" "$TMP/SUMS.gpg" "$TMP/other.asc" "$OFPR"

# --- Assemblage du lot ---------------------------------------------------------------
make_src() { # répertoire
	local s=$1
	mkdir -p "$s/webui/server/db" "$s/src"
	cp "$ROOT/VERSION" "$ROOT/LICENSE" "$ROOT/CHANGELOG.md" "$s/"
	cp "$ROOT/webui/VERSION" "$s/webui/VERSION"
	cp -R "$ROOT/webui/server/db/migrations" "$s/webui/server/db/"
	cp -R "$ROOT/src/rootfs" "$s/src/rootfs"
	printf '// SPDX-License-Identifier: AGPL-3.0-or-later\nprocess.exit(0)\n' > "$s/webui/migrate.mjs"
	mkdir -p "$s/output/server" "$s/output/public"
	printf 'export default {}\n' > "$s/output/server/index.mjs"
	printf '{"preset":"node-server"}\n' > "$s/output/nitro.json"
	printf '<!doctype html>\n' > "$s/output/public/index.html"
}
VERSION=$(tr -d '[:space:]' < "$ROOT/VERSION")
COMMIT=0123456789abcdef0123456789abcdef01234567
EPOCH=1795392000
S="$TMP/src"; make_src "$S"
check "lot : assemblage" assemble_stage "$S" "$S/output" "$TMP/stage" exemple/scanoria
STAGE="$TMP/stage/scanoria-$VERSION"
check "lot : update-source.json généré" test "$(jq -c . "$STAGE/rootfs/usr/share/scanoria/update-source.json")" = '{"repo":"exemple/scanoria"}'
check "lot : MANIFEST liste rootfs" bash -c 'diff <(cd "$1/rootfs" && find . -type f -printf "/%P\n" | LC_ALL=C sort) "$1/rootfs/usr/share/scanoria/MANIFEST"' _ "$STAGE"
check "lot : console, VERSION, migrations" test -f "$STAGE/webui/server/index.mjs" -a -f "$STAGE/webui/migrate.mjs" \
	-a -f "$STAGE/webui/VERSION" -a -f "$STAGE/webui/migrations/001_initial.sql" -a -f "$STAGE/VERSION"
check "lot : assistant de premier démarrage" test -f "$STAGE/rootfs/usr/sbin/scanoria-firstboot"
check "lot : make_bundle" make_bundle "$STAGE" "$TMP/out1" "$COMMIT" "$EPOCH" 0.1.0 22
A="scanoria-$VERSION.tar.zst"
check "lot : SHA256SUMS = exactement 2 lignes" bash -c '[[ $(wc -l < "$1/SHA256SUMS") -eq 2 ]] && (cd "$1" && sha256sum --check --quiet --strict SHA256SUMS) && awk "{print \$2}" "$1/SHA256SUMS" | tr "\n" " " | grep -qx "release.json $2 "' _ "$TMP/out1" "$A"
cat > "$TMP/rel.py" <<'EOF'
import json, re, sys, hashlib, os
schema = json.load(open(sys.argv[1]))
rel = json.load(open(sys.argv[2]))
props = schema["properties"]
assert set(rel) == set(schema["required"]) == set(props), set(rel) ^ set(props)
for k, v in rel.items():
    p = props[k]
    if "const" in p: assert v == p["const"], k
    if "pattern" in p: assert re.search(p["pattern"], v), k
    if p.get("type") == "integer": assert isinstance(v, int) and v >= p.get("minimum", v) and v <= p.get("maximum", v), k
    if "maxLength" in p: assert len(v) <= p["maxLength"], k
arch = os.path.join(os.path.dirname(sys.argv[2]), rel["archive"])
assert hashlib.sha256(open(arch, "rb").read()).hexdigest() == rel["archive_sha256"]
assert os.path.getsize(arch) == rel["archive_size"]
assert rel["tag"] == "v" + rel["release"] and rel["release"] == sys.argv[3]
assert rel["notes_md"].strip() and not rel["notes_md"].startswith("## ")
EOF
check "lot : release.json conforme au schéma" python3 -I "$TMP/rel.py" \
	"$ROOT/src/rootfs/usr/share/scanoria/schemas/release.schema.json" "$TMP/out1/release.json" "$VERSION"
zstd -dc "$TMP/out1/$A" > "$TMP/bundle.tar"
check "lot : un seul répertoire racine" bash -c '! tar -tf "$1" | grep -v "^scanoria-$2/"' _ "$TMP/bundle.tar" "$VERSION"
check "lot : propriétaire 0:0, ni lien ni fichier spécial" bash -c '! tar --numeric-owner -tvf "$1" | awk "{print substr(\$1,1,1), \$2}" | grep -vE "^[-d] 0/0$"' _ "$TMP/bundle.tar"
check "lot : rootfs sous les préfixes autorisés" bash -c '! tar -tf "$1" | grep "^scanoria-$2/rootfs/." | sed "s|^scanoria-$2/rootfs/||; s|/$||" | grep -vE "$3|$4"' _ \
	"$TMP/bundle.tar" "$VERSION" "$ROOTFS_ALLOWED_RE" "$ROOTFS_DIRS_RE"
check "lot : aucune clé privée" bash -c '! tar -xOf "$1" | grep -aA1 -E "^-----BEGIN ([A-Z0-9]+ )*PRIVATE KEY-----$" | grep -aqE "^[A-Za-z0-9+/=]{40,}$"' _ "$TMP/bundle.tar"
check "lot : reproductible" bash -c 'source "$1"; make_bundle "$2" "$3" "$4" "$5" 0.1.0 22 && cmp "$6/SHA256SUMS" "$3/SHA256SUMS"' _ \
	"$ROOT/build.sh" "$STAGE" "$TMP/out2" "$COMMIT" "$EPOCH" "$TMP/out1"
refuse "lot : MIN_UPGRADE_FROM > version" make_bundle "$STAGE" "$TMP/out3" "$COMMIT" "$EPOCH" 99.0.0 22
refuse "lot : commit invalide" make_bundle "$STAGE" "$TMP/out3" "abc" "$EPOCH" 0.1.0 22
refuse "lot : node_major < 22" make_bundle "$STAGE" "$TMP/out3" "$COMMIT" "$EPOCH" 0.1.0 20

hostile() { # libellé préparation
	local d="$TMP/h-$RANDOM"
	make_src "$d"
	(cd "$d/src/rootfs" && eval "$2")
	refuse "lot hostile : $1" assemble_stage "$d" "$d/output" "$d/stage" exemple/scanoria
}
hostile "fichier dans /etc" 'mkdir -p etc/scanoria && echo x > etc/scanoria/a.json'
hostile "lien symbolique" 'ln -s /etc/shadow usr/share/scanoria/shadow'
hostile "lien vers un répertoire" 'ln -s ../../.. usr/lib/scanoria/up'
hostile "commande hors préfixe" 'mkdir -p usr/sbin && echo x > usr/sbin/evil'
hostile "unité hors préfixe" 'mkdir -p usr/lib/systemd/system && echo x > usr/lib/systemd/system/ssh.service'
hostile "tmpfiles autre que scanoria.conf" 'mkdir -p usr/lib/tmpfiles.d && echo x > usr/lib/tmpfiles.d/evil.conf'
hostile "nom avec espace" 'echo x > "usr/share/scanoria/a b"'
hostile "tube nommé" 'mkfifo usr/share/scanoria/fifo'
hostile "clé privée (fichier .key)" 'echo x > usr/share/scanoria/server.key'
hostile "clé privée (contenu PEM)" 'openssl genpkey -algorithm ed25519 -out usr/share/scanoria/k.pem 2>/dev/null'
d="$TMP/h-hardlink"; make_src "$d"; echo x > "$d/src/rootfs/usr/share/scanoria/a"; ln "$d/src/rootfs/usr/share/scanoria/a" "$d/src/rootfs/usr/share/scanoria/b"
check "lot : lien physique de la source copié en fichiers distincts" bash -c 'source "$1" && st=$(assemble_stage "$2" "$2/output" "$2/stage" exemple/scanoria) && [[ -z $(find "$st" -type f -links +1) ]]' _ "$ROOT/build.sh" "$d"
d="$TMP/h-console"; make_src "$d"; ln -s /etc/passwd "$d/output/public/leak"
check "lot : lien de la console déréférencé (pas de lien dans le lot)" bash -c 'source "$1" && st=$(assemble_stage "$2" "$2/output" "$2/stage" exemple/scanoria) && [[ -z $(find "$st" -type l) ]]' _ "$ROOT/build.sh" "$d"
d="$TMP/h-version"; make_src "$d"; echo 0.1.1 > "$d/webui/VERSION"
refuse "lot : webui/VERSION ≠ VERSION" assemble_stage "$d" "$d/output" "$d/stage" exemple/scanoria
d="$TMP/h-repo"; make_src "$d"
refuse "lot : dépôt invalide" assemble_stage "$d" "$d/output" "$d/stage" 'exemple/scanoria;rm'
check "changelog_section : section 0.1.0 sans titre" bash -c 'source "$1"; s=$(changelog_section "$2" 0.1.0); [[ -n $s ]] && ! grep -q "^## " <<< "$s" && grep -q "^### " <<< "$s"' _ "$ROOT/build.sh" "$ROOT/CHANGELOG.md"
check "changelog_section : version absente → vide" bash -c 'source "$1"; [[ -z $(changelog_section "$2" 9.9.9) ]]' _ "$ROOT/build.sh" "$ROOT/CHANGELOG.md"

# --- Plancher matériel D6 ------------------------------------------------------
HW="$ROOT/src/iso/scripts/check-hardware.sh"
hw() { SCANORIA_HW_CPUS=$1 SCANORIA_HW_MEM_KB=$2 SCANORIA_HW_DISK_BYTES=$3 sh "$HW"; }
check "D6 : 2 vCPU, 4 Go, 40 Go acceptés" hw 2 3900000 42949672960
check "D6 : 8 vCPU, 32 Go, 300 Go acceptés" hw 8 32000000 300000000000
refuse "D6 : 1 vCPU refusé" hw 1 3900000 42949672960
refuse "D6 : 2 Go refusés" hw 2 2000000 42949672960
refuse "D6 : 30 Go refusés" hw 2 3900000 30000000000
refuse "D6 : valeur non numérique refusée" hw 'x' 3900000 42949672960

# --- Assistant de premier démarrage ---------------------------------------------
fb() { bash -c 'source "$1"; shift; "$@"' _ "$FBS" "$@"; }
for v in analyse.exemple.test a1.exemple.test x-y.z.exemple.test; do check "FQDN valide : $v" fb valid_fqdn "$v"; done
for v in exemple Analyse.exemple.test '-a.exemple.test' 'a..exemple.test' '*.exemple.test' 'a.exemple.test.' \
	'a.exemple.test;id' 'a b.exemple.test' 'a.exemple.1'; do
	refuse "FQDN refusé : $v" fb valid_fqdn "$v"
done
nc() { python3 -I "$FB/netcheck.py" "$@"; }
check "réseaux : canonisation" test "$(nc networks '192.0.2.7/24, 2001:DB8::1/48 198.51.100.0/24,192.0.2.0/24')" = \
	'["192.0.2.0/24", "2001:db8::/48", "198.51.100.0/24"]'
for v in '' '192.0.2.0' '192.0.2.0/33' '300.1.1.1/8' '192.0.2.0/24;rm -rf /' "\$(id)/24" 'exemple.test/24'; do
	refuse "réseaux refusés : '$v'" nc networks "$v"
done
check "réseaux : 64 au plus" bash -c 'l=$(for i in $(seq 0 64); do printf "10.%d.0.0/16," "$i"; done); ! python3 -I "$1" networks "$l"' _ "$FB/netcheck.py"
check "interface : 192.0.2.10/24" test "$(nc iface 192.0.2.10/24)" = 192.0.2.10/24
check "interface : réseau 192.0.2.0/24" test "$(nc iface-network 192.0.2.10/24)" = 192.0.2.0/24
refuse "interface : sans préfixe" nc iface 192.0.2.10
refuse "interface : /32 IPv4" nc iface 192.0.2.10/32
check "DNS : 3 adresses" test "$(nc ips '192.0.2.53, 2001:db8::53 198.51.100.53')" = '192.0.2.53 2001:db8::53 198.51.100.53'
refuse "DNS : 4 adresses" nc ips '192.0.2.1 192.0.2.2 192.0.2.3 192.0.2.4'
check "ip -j : réseaux globaux" test "$(printf '%s' '[{"ifname":"en0","addr_info":[{"local":"192.0.2.10","prefixlen":24,"scope":"global"},{"local":"fe80::1","prefixlen":64,"scope":"link"}]}]' | nc ipjson-networks)" = '["192.0.2.0/24"]'
check "netplan : statique valide" bash -c 'source "$1"; netplan_yaml en0 static 192.0.2.10/24 192.0.2.1 "192.0.2.53 2001:db8::53" exemple.test | python3 -I -c "
import sys, yaml
d = yaml.safe_load(sys.stdin)[\"network\"][\"ethernets\"][\"en0\"]
assert d[\"addresses\"] == [\"192.0.2.10/24\"] and d[\"routes\"][0][\"via\"] == \"192.0.2.1\"
assert d[\"nameservers\"][\"addresses\"] == [\"192.0.2.53\", \"2001:db8::53\"] and d[\"nameservers\"][\"search\"] == [\"exemple.test\"]
"' _ "$FBS"
check "netplan : DHCP valide" bash -c 'source "$1"; netplan_yaml en0 dhcp "" "" "" "" | python3 -I -c "import sys,yaml; assert yaml.safe_load(sys.stdin)[\"network\"][\"ethernets\"][\"en0\"][\"dhcp4\"] is True"' _ "$FBS"
check "mot de passe : 12 caractères acceptés" fb valid_password 'abcdefghijkl'
refuse "mot de passe : 11 caractères refusés" fb valid_password 'abcdefghijk'
check "clavier : fr-ch → ch:fr" test "$(fb keyboard_layout fr-ch)" = "ch:fr"
refuse "clavier : choix inconnu" fb keyboard_layout 'fr;id'
mkdir -p "$TMP/zi/Europe"; : > "$TMP/zi/Europe/Paris"
check "fuseau : Europe/Paris" env SCANORIA_ZONEINFO_DIR="$TMP/zi" bash -c 'source "$1"; valid_timezone Europe/Paris' _ "$FBS"
refuse "fuseau : ../../etc/passwd" env SCANORIA_ZONEINFO_DIR="$TMP/zi" bash -c 'source "$1"; valid_timezone ../../etc/passwd' _ "$FBS"
PW='Mot de passe très sûr 42 ✓'
H=$(printf '%s' "$PW" | python3 -I "$FB/hash-password.py")
check "PBKDF2 : format PHC" bash -c '[[ $1 =~ ^\$pbkdf2-sha256\$i=600000\$[A-Za-z0-9+/]{22}\$[A-Za-z0-9+/]{43}$ ]]' _ "$H"
check "PBKDF2 : vérification" python3 -I -c '
import base64, hashlib, sys
_, alg, it, salt, h = sys.argv[1].split("$")
pad = lambda s: s + "=" * (-len(s) % 4)
dk = hashlib.pbkdf2_hmac("sha256", sys.argv[2].encode(), base64.b64decode(pad(salt)), int(it[2:]), 32)
assert base64.b64encode(dk).decode().rstrip("=") == h' "$H" "$PW"
refuse "PBKDF2 : mot de passe trop court" bash -c 'printf "%s" court | python3 -I "$1"' _ "$FB/hash-password.py"
check "firstboot : unité conditionnée par firstboot.done" grep -qx 'ConditionPathExists=!/var/lib/scanoria/firstboot.done' "$ROOT/src/rootfs/usr/lib/systemd/system/scanoria-firstboot.service"
refuse "firstboot : aucun mot de passe en argument (pas de --password)" grep -nE -- '--password[= ]|chpasswd [^-]|echo "\$pw' "$FBS"

# Mode sans intervention (docs/TESTING.md § 4) : fichier de réponses validé en bloc.
mkdir -p "$TMP/zi/Etc"; : > "$TMP/zi/Etc/UTC"
UA_OK='{"version":1,"language":"en","keyboard":"us","timezone":"Etc/UTC","network":{"mode":"dhcp"},
"fqdn":"analyse.exemple.test","admin_password":"Mot de passe admin 42","sysadmin_password":"Mot de passe système 42",
"admin_networks":["192.0.2.0/24"],"report":"serial","poweroff":false}'
ua() { # json [jq de modification] → charge le fichier, affiche l'état obtenu
	printf '%s' "$1" | jq -c "${2:-.}" > "$TMP/ua.json"
	SCANORIA_FIRSTBOOT_DIR="$FB" SCANORIA_ZONEINFO_DIR="$TMP/zi" bash -c 'source "$1"; load_unattended "$2" || exit 1
		printf "%s|%s|%s|%s|%s|%s|%s|%s|%s|%s\n" "$UI_LANG" "$KB_CHOICE" "$TZ_NAME" "$FQDN" "$NET_MODE" "$NET_ADDR" \
			"$ADMIN_NETWORKS_JSON" "$UA_REPORT" "$UA_POWEROFF" "${ADMIN_HASH:0:23}"' _ "$FBS" "$TMP/ua.json"
}
UA_OUT=$(ua "$UA_OK" || true)
check "sans intervention : fichier DHCP accepté" test "$UA_OUT" = 'en|us|Etc/UTC|analyse.exemple.test|dhcp||["192.0.2.0/24"]|serial|false|$pbkdf2-sha256$i=600000'
UA_OUT=$(ua "$UA_OK" '.network = {mode: "static", interface: "en0", address: "192.0.2.10/24", gateway: "192.0.2.1", dns: ["192.0.2.53"], search: "exemple.test"} | .admin_networks = ["192.0.2.7/24"] | .poweroff = true' || true)
check "sans intervention : statique accepté et canonisé" test "$UA_OUT" = 'en|us|Etc/UTC|analyse.exemple.test|static|192.0.2.10/24|["192.0.2.0/24"]|serial|true|$pbkdf2-sha256$i=600000'
refuse "sans intervention : aucun mot de passe en clair dans l'état" grep -q 'Mot de passe' <<< "$UA_OUT"
for m in '. + {extra: 1}' '.version = 2' '.language = "de"' '.keyboard = "fr;id"' '.timezone = "../../etc/passwd"' \
	'.fqdn = "a.exemple.test;reboot"' '.fqdn = "Analyse.Exemple.Test"' '.admin_password = "court"' \
	'.sysadmin_password = "Mot de passe\nsur deux lignes"' '.admin_password = 42' '.admin_networks = []' \
	'.admin_networks = ["192.0.2.0/24;id"]' '.admin_networks = ["exemple.test/24"]' '.report = "/dev/sda"' \
	'.poweroff = "yes"' '.network = {mode: "dhcp", address: "192.0.2.10/24"}' '.network = {mode: "static"}' \
	'.network = {mode: "static", address: "192.0.2.10/32"}' '.network = {mode: "dhcp", interface: "en0;id"}' \
	'.network = {mode: "static", address: "192.0.2.10/24", dns: ["192.0.2.1","192.0.2.2","192.0.2.3","192.0.2.4"]}' \
	'del(.fqdn)' '[.]'; do
	refuse "sans intervention : refusé ($m)" ua "$UA_OK" "$m"
done
refuse "sans intervention : fichier absent" ua '' '.'

# --- Assemblage ISO (xorriso, facultatif) ----------------------------------------
if command -v xorriso > /dev/null 2>&1; then
	mkdir -p "$TMP/iso/casper" "$TMP/iso/boot/grub"
	echo k > "$TMP/iso/casper/vmlinuz"; echo i > "$TMP/iso/casper/initrd"
	xorriso -as mkisofs -quiet -o "$TMP/base.iso" "$TMP/iso" 2> /dev/null
	xorriso -indev "$TMP/base.iso" -outdev "$TMP/new.iso" -map "$ROOT/src/iso/autoinstall" /nocloud \
		-map "$ROOT/src/iso/grub/grub.cfg" /boot/grub/grub.cfg -boot_image any replay > /dev/null 2>&1
	check "xorriso : user-data et grub.cfg dans l'ISO" bash -c 'xorriso -indev "$1" -find / -type f 2>/dev/null | grep -qx "'"'"'/nocloud/user-data'"'"'"' _ "$TMP/new.iso"
else
	echo "skip xorriso absent"
fi

printf '\nb20-iso-static : %d ok, %d échec(s)\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
