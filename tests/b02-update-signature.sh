#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Vincent Tisseront
#
# b02 — mises à jour signées (F18), sans root ni réseau. Une clé Ed25519
# JETABLE est générée dans un répertoire temporaire (jamais versionnée) ; sa
# clé publique remplace la clé épinglée dans une arborescence de test
# (SCANORIA_TEST_ROOT). On construit de fausses releases conformes au
# § 6.2–6.3 et on vérifie :
#   - acceptation d'une release correctement signée ;
#   - rejet d'une signature altérée, tronquée ou d'une autre clé (E_SIGNATURE),
#     d'un SHA256SUMS, d'un release.json ou d'une archive altérés (E_CHECKSUM),
#     d'une version inattendue (E_VERSION) ;
#   - installation initiale, mise à jour par téléversement, rétrogradation et
#     version identique refusées, min_upgrade_from et node_major ;
#   - archives piégées (lien, .., chemin absolu, hors préfixe, lien physique,
#     FIFO, doublon) refusées sans rien écrire hors de la cible (E_ARCHIVE) ;
#   - retour arrière automatique sur échec de santé, retour à N-1 sur demande
#     (version abandonnée notée), échéance trop proche refusée avant tout arrêt ;
#   - release GitHub toujours proposée (ni brouillon, ni [rejected], bon canal) ;
#   - clé publique épinglée du dépôt : Ed25519, empreinte attendue.
# Les commandes système (systemctl, runuser/pg_dump, curl, node) sont des
# bouchons. Dépendances : bash, python3, jq, openssl (≥ 3.0), zstd.

# shellcheck disable=SC2016,SC2015
set -euo pipefail
shopt -s lastpipe
export PYTHONDONTWRITEBYTECODE=1

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
SU="$ROOT/src/rootfs/usr/sbin/scanoria-selfupdate"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
PINNED_SHA256=696af1d4c9cfb71c47e9940e6d80d69a8074786967fc1e7e857f5865a3b1f803

PASS=0
FAIL=0
ok() { PASS=$((PASS + 1)); printf 'ok   %s\n' "$1"; }
ko() { FAIL=$((FAIL + 1)); printf 'FAIL %s\n' "$1"; }
expect() { if [[ "$2" == "$3" ]]; then ok "$1"; else ko "$1 (obtenu « $2 », attendu « $3 »)"; fi; }
for t in python3 jq openssl zstd sha256sum; do command -v "$t" > /dev/null || { echo "outil manquant : $t" >&2; exit 2; }; done

# --- Clé publique épinglée du dépôt ----------------------------------------------
openssl pkey -pubin -in "$ROOT/update-pubkey.pem" -noout -text 2> /dev/null | grep -q ED25519 \
	&& ok "update-pubkey.pem : clé Ed25519" || ko "update-pubkey.pem : pas une clé Ed25519"
expect "update-pubkey.pem : empreinte SHA-256 (DER) épinglée" \
	"$(openssl pkey -pubin -in "$ROOT/update-pubkey.pem" -outform DER | sha256sum | cut -d' ' -f1)" "$PINNED_SHA256"
if find "$ROOT/src/rootfs" -type f -exec grep -l 'PRIVATE KEY-----$' {} + 2> /dev/null | grep -q .; then
	ko "aucune clé privée dans src/rootfs"
else
	ok "aucune clé privée dans src/rootfs"
fi

# --- Arborescence de test et clés jetables -----------------------------------------
T="$TMP/root"
K="$TMP/keys"
STUBS="$TMP/stubs"
mkdir -p "$T/etc/scanoria" "$T/opt/scanoria" "$T/run/scanoria" "$T/var/lib/scanoria/uploads" "$K" "$STUBS"
chmod 0700 "$K"
openssl genpkey -algorithm ed25519 -out "$K/test-signing.key" 2> /dev/null
openssl genpkey -algorithm ed25519 -out "$K/other-signing.key" 2> /dev/null
openssl pkey -in "$K/test-signing.key" -pubout -out "$T/etc/scanoria/update-pubkey.pem"
chmod 0644 "$T/etc/scanoria/update-pubkey.pem"
export SCANORIA_TEST_ROOT="$T" SCANORIA_TEST_BIN="$STUBS" SCANORIA_TEST_HEALTH_TIMEOUT=0
unset SCANORIA_TEST_OWNER_UID

echo '{"status":"ok","version":"0.0.0","db":"ok"}' > "$TMP/health.json"
cat > "$STUBS/curl" <<-EOF
	#!/bin/bash
	cat "$TMP/health.json"
EOF
printf '#!/bin/bash\necho v22.11.0\n' > "$STUBS/node"
printf '#!/bin/bash\nexit 0\n' > "$STUBS/scanoria-selftest"
printf '#!/bin/bash\nexit 0\n' > "$STUBS/scanoria-state"
chmod 0755 "$STUBS"/*

# Fausse release : mkrel VERSION RÉPERTOIRE [piège] [node_major] [min_upgrade_from]
mkrel() {
	local v=$1 out=$2 trap_kind=${3:-none} node=${4:-22} min=${5:-0.1.0} a
	mkdir -p "$out"
	a="scanoria-$v.tar.zst"
	python3 -I -B - "$out/scanoria-$v.tar" "$v" "$trap_kind" <<-'EOF'
		import io, sys, tarfile
		path, v, kind = sys.argv[1:]
		p = "scanoria-" + v
		def add(tf, name, data=b"", mode=0o644, typ=tarfile.REGTYPE, link=""):
		    ti = tarfile.TarInfo(name)
		    ti.type, ti.mode, ti.mtime, ti.linkname = typ, mode, 1700000000, link
		    if typ == tarfile.DIRTYPE:
		        ti.mode = 0o755
		        tf.addfile(ti)
		    elif typ == tarfile.REGTYPE:
		        ti.size = len(data)
		        tf.addfile(ti, io.BytesIO(data))
		    else:
		        tf.addfile(ti)
		with tarfile.open(path, "w", format=tarfile.GNU_FORMAT) as tf:
		    for d in ("", "/webui", "/webui/server", "/webui/migrations", "/rootfs", "/rootfs/usr",
		              "/rootfs/usr/sbin", "/rootfs/usr/share", "/rootfs/usr/share/scanoria"):
		        add(tf, p + d, typ=tarfile.DIRTYPE)
		    add(tf, p + "/VERSION", (v + "\n").encode())
		    add(tf, p + "/webui/VERSION", (v + "\n").encode())
		    add(tf, p + "/webui/server/index.mjs", b"export {}\n")
		    add(tf, p + "/webui/migrate.mjs", b"export {}\n", 0o755)
		    add(tf, p + "/webui/migrations/001_initial.sql", b"SELECT 1;\n")
		    add(tf, p + "/rootfs/usr/sbin/scanoria-dummy", ("#!/bin/bash\necho %s\n" % v).encode(), 0o755)
		    add(tf, p + "/rootfs/usr/share/scanoria/only-in-" + v, b"x\n")
		    add(tf, p + "/rootfs/etc-is-ignored", b"x\n")
		    if kind == "symlink":
		        add(tf, p + "/rootfs/usr/sbin/scanoria-evil", typ=tarfile.SYMTYPE, link="/etc/passwd")
		    elif kind == "dotdot":
		        add(tf, p + "/../../../escaped-dotdot", b"evil\n")
		    elif kind == "absolute":
		        add(tf, "/tmp/escaped-absolute", b"evil\n")
		    elif kind == "outside":
		        add(tf, "other/escaped-outside", b"evil\n")
		    elif kind == "hardlink":
		        add(tf, p + "/rootfs/usr/sbin/scanoria-hl", typ=tarfile.LNKTYPE, link=p + "/VERSION")
		    elif kind == "fifo":
		        add(tf, p + "/rootfs/fifo", typ=tarfile.FIFOTYPE)
		    elif kind == "duplicate":
		        add(tf, p + "/VERSION", (v + "\n").encode())
		    elif kind == "badversion":
		        add(tf, p + "/webui/extra", b"x\n")
	EOF
	if [[ "$trap_kind" == badversion ]]; then
		# webui/VERSION différent de VERSION : reconstruit l'archive avec un mauvais contenu
		python3 -I -B -c 'import sys,tarfile,io
src, v = sys.argv[1], sys.argv[2]
members = []
with tarfile.open(src) as tf:
    for m in tf.getmembers():
        data = tf.extractfile(m).read() if m.isreg() else None
        if m.name.endswith("/webui/VERSION"):
            data = b"9.9.9\n"; m.size = len(data)
        members.append((m, data))
with tarfile.open(src, "w", format=tarfile.GNU_FORMAT) as tf:
    for m, d in members:
        tf.addfile(m, io.BytesIO(d) if d is not None else None)' "$out/scanoria-$v.tar" "$v"
	fi
	zstd -q -3 --rm -f "$out/scanoria-$v.tar" -o "$out/$a"
	jq -n --arg v "$v" --arg a "$a" --arg sha "$(sha256sum "$out/$a" | cut -d' ' -f1)" \
		--argjson size "$(stat -c %s "$out/$a")" --argjson node "$node" --arg min "$min" \
		'{version: 1, name: "scanoria", release: $v, tag: ("v" + $v),
		  commit: "0123456789abcdef0123456789abcdef01234567", built_at: "2026-11-23T08:00:00Z",
		  archive: $a, archive_sha256: $sha, archive_size: $size, min_upgrade_from: $min,
		  node_major: $node, notes_md: ("## " + $v + "\n\n- test\n")}' > "$out/release.json"
	(cd "$out" && sha256sum release.json "$a" > SHA256SUMS)
	sign "$out"
}
sign() { # répertoire [clé]
	openssl pkeyutl -sign -inkey "${2:-$K/test-signing.key}" -rawin -in "$1/SHA256SUMS" -out "$1/SHA256SUMS.sig"
}
code() { jq -r '.code' 2> /dev/null <<< "$1" || echo "?"; }
verify() { local out; out=$("$SU" verify "$@" 2> "$TMP/su.err" || true); code "$out"; }
upload() { # répertoire de release -> identifiant de téléversement
	local id
	id=$(cat /proc/sys/kernel/random/uuid)
	mkdir -p "$T/var/lib/scanoria/uploads/$id"
	cp "$1"/* "$T/var/lib/scanoria/uploads/$id/"
	echo "$id"
}
apply_upload() { local out; out=$("$SU" apply --upload-id "$1" 2> "$TMP/su.err" || true); [[ -z "${B21_DEBUG:-}" ]] || echo "$out" >&2; code "$out"; }
current() { readlink "$T/opt/scanoria/current" 2> /dev/null || echo none; }
previous() { readlink "$T/opt/scanoria/previous" 2> /dev/null || echo none; }

# --- 1. Vérification (signature, empreintes) ----------------------------------------
R1="$TMP/rel-0.1.0"
mkrel 0.1.0 "$R1"
expect "release signée → OK" "$(verify "$R1" --version 0.1.0)" OK
openssl pkeyutl -verify -pubin -inkey "$T/etc/scanoria/update-pubkey.pem" -rawin \
	-in "$R1/SHA256SUMS" -sigfile "$R1/SHA256SUMS.sig" > /dev/null \
	&& ok "commande de vérification du § 6.2 acceptée par openssl" || ko "openssl pkeyutl -verify"
expect "signature brute de 64 octets" "$(stat -c %s "$R1/SHA256SUMS.sig")" 64
expect "version attendue différente → E_VERSION" "$(verify "$R1" --version 0.1.1)" E_VERSION

tamper() { # libellé code_attendu commande_de_sabotage (sur une copie)
	local d="$TMP/tamper"
	rm -rf "$d"
	cp -r "$R1" "$d"
	(cd "$d" && eval "$3")
	expect "$1" "$(verify "$d" --version 0.1.0)" "$2"
}
tamper "signature altérée → E_SIGNATURE" E_SIGNATURE \
	'printf "\\x$(printf %02x $(( ($(od -An -tu1 -N1 SHA256SUMS.sig) + 1) % 256 )))" | dd of=SHA256SUMS.sig bs=1 count=1 conv=notrunc 2>/dev/null'
tamper "signature tronquée (63 octets) → E_SIGNATURE" E_SIGNATURE 'truncate -s 63 SHA256SUMS.sig'
tamper "signature de 65 octets → E_SIGNATURE" E_SIGNATURE 'printf x >> SHA256SUMS.sig'
tamper "signature absente → E_SIGNATURE" E_SIGNATURE 'rm SHA256SUMS.sig'
tamper "signature d'une autre clé → E_SIGNATURE" E_SIGNATURE "openssl pkeyutl -sign -inkey '$K/other-signing.key' -rawin -in SHA256SUMS -out SHA256SUMS.sig"
tamper "SHA256SUMS altéré (non re-signé) → E_SIGNATURE" E_SIGNATURE 'sed -i "1s/^./0/;1s/^0/1/" SHA256SUMS'
tamper "SHA256SUMS à trois lignes (re-signé) → E_CHECKSUM" E_CHECKSUM \
	"echo \"\$(printf '%064d' 0)  extra.txt\" >> SHA256SUMS && openssl pkeyutl -sign -inkey '$K/test-signing.key' -rawin -in SHA256SUMS -out SHA256SUMS.sig"
tamper "release.json altéré → E_CHECKSUM" E_CHECKSUM 'sed -i "s/- test/- piégé/" release.json'
tamper "archive altérée → E_CHECKSUM" E_CHECKSUM 'printf x >> scanoria-0.1.0.tar.zst'
tamper "release.json hors schéma (re-signé) → E_CHECKSUM" E_CHECKSUM \
	"jq -c '. + {extra: 1}' release.json > r && mv r release.json && sha256sum release.json scanoria-0.1.0.tar.zst > SHA256SUMS && openssl pkeyutl -sign -inkey '$K/test-signing.key' -rawin -in SHA256SUMS -out SHA256SUMS.sig"
tamper "release.json d'une autre version (re-signé) → E_CHECKSUM" E_CHECKSUM \
	"jq -c '.release = \"0.1.1\"' release.json > r && mv r release.json && sha256sum release.json scanoria-0.1.0.tar.zst > SHA256SUMS && openssl pkeyutl -sign -inkey '$K/test-signing.key' -rawin -in SHA256SUMS -out SHA256SUMS.sig"
rm -f "$T/etc/scanoria/update-pubkey.pem.bak"
mv "$T/etc/scanoria/update-pubkey.pem" "$T/etc/scanoria/update-pubkey.pem.bak"
expect "clé épinglée absente → E_PRECONDITION" "$(verify "$R1" --version 0.1.0)" E_PRECONDITION
mv "$T/etc/scanoria/update-pubkey.pem.bak" "$T/etc/scanoria/update-pubkey.pem"

# --- 2. Installation initiale et mise à jour ---------------------------------------------
out=$("$SU" install-local "$R1" 2> "$TMP/su.err" || true)
expect "install-local 0.1.0 → OK" "$(code "$out")" OK
expect "install-local : lien current" "$(current)" releases/0.1.0
expect "install-local : rootfs déployé (préfixes autorisés)" "$(cat "$T/usr/sbin/scanoria-dummy" | tail -n 1)" "echo 0.1.0"
[[ ! -e "$T/etc-is-ignored" ]] && ok "install-local : chemin hors préfixes ignoré" || ko "chemin hors préfixes déployé"
grep -qx /usr/share/scanoria/only-in-0.1.0 "$T/usr/share/scanoria/MANIFEST" && ok "MANIFEST écrit" || ko "MANIFEST"
expect "install-local refusé si current existe → E_PRECONDITION" "$(code "$("$SU" install-local "$R1" 2> /dev/null || true)")" E_PRECONDITION

R2="$TMP/rel-0.2.0"; mkrel 0.2.0 "$R2"
echo '{"status":"ok","version":"0.2.0","db":"ok"}' > "$TMP/health.json"
# Unités à activer après la mise à jour (appliance déjà mise en service).
touch "$T/var/lib/scanoria/firstboot.done"
printf '# commentaire\nscanoria-runner.service\nscanoria-state.timer\n../evil.service\nnginx.service\n' \
	> "$T/usr/share/scanoria/units.list"
id=$(upload "$R2")
expect "mise à jour 0.1.0 → 0.2.0 par téléversement → OK" "$(apply_upload "$id")" OK
expect "liens après mise à jour" "$(current) $(previous)" "releases/0.2.0 releases/0.1.0"
expect "rootfs de 0.2.0 déployé" "$(tail -n 1 "$T/usr/sbin/scanoria-dummy")" "echo 0.2.0"
[[ ! -e "$T/usr/share/scanoria/only-in-0.1.0" && -e "$T/usr/share/scanoria/only-in-0.2.0" ]] \
	&& ok "fichier retiré du manifeste supprimé" || ko "nettoyage selon MANIFEST"
[[ -f "$T/var/lib/scanoria/backups/pre-update/0.1.0.dump" ]] && ok "sauvegarde de base avant mise à jour" || ko "sauvegarde"
[[ ! -e "$T/var/lib/scanoria/uploads/$id" ]] && ok "téléversement nettoyé" || ko "téléversement non nettoyé"
grep -qF '["systemctl","stop","scanoria-console.service"]' "$T/test-commands.log" && ok "console arrêtée pendant le déploiement" || ko "arrêt console"
grep -qF '["systemctl","enable","--now","scanoria-runner.service"]' "$T/test-commands.log" \
	&& grep -qF '["systemctl","try-restart","scanoria-runner.service"]' "$T/test-commands.log" \
	&& grep -qF '["systemctl","enable","--now","scanoria-state.timer"]' "$T/test-commands.log" \
	&& ok "unités de units.list activées, services redémarrés" || ko "activation des unités"
grep -qF '"try-restart","scanoria-state.timer"' "$T/test-commands.log" && ko "timer redémarré" || ok "timer non redémarré"
grep -qE 'evil|"nginx.service"' "$T/test-commands.log" && ko "unité hors liste activée" || ok "noms d'unités invalides ignorés"

R3="$TMP/rel-0.1.5"; mkrel 0.1.5 "$R3"
expect "rétrogradation 0.2.0 → 0.1.5 → E_VERSION" "$(apply_upload "$(upload "$R3")")" E_VERSION
expect "même version 0.2.0 → E_VERSION" "$(apply_upload "$(upload "$R2")")" E_VERSION
R4="$TMP/rel-0.3.0-min"; mkrel 0.3.0 "$R4" none 22 0.2.1
expect "min_upgrade_from > installée → E_VERSION" "$(apply_upload "$(upload "$R4")")" E_VERSION
R5="$TMP/rel-0.3.0-node"; mkrel 0.3.0 "$R5" none 24
expect "node_major différent → E_VERSION" "$(apply_upload "$(upload "$R5")")" E_VERSION
R6="$TMP/rel-0.3.0-other"; mkrel 0.3.0 "$R6"; sign "$R6" "$K/other-signing.key"
expect "téléversement signé par une autre clé → E_SIGNATURE" "$(apply_upload "$(upload "$R6")")" E_SIGNATURE

# Téléversement piégé
R7="$TMP/rel-0.3.0"; mkrel 0.3.0 "$R7"
id=$(upload "$R7"); rm "$T/var/lib/scanoria/uploads/$id/release.json"; ln -s "$R7/release.json" "$T/var/lib/scanoria/uploads/$id/release.json"
expect "fichier téléversé en lien symbolique → E_PRECONDITION" "$(apply_upload "$id")" E_PRECONDITION
id=$(upload "$R7")
out=$(SCANORIA_TEST_OWNER_UID=$(( $(id -u) + 4242 )) "$SU" apply --upload-id "$id" 2> /dev/null || true)
expect "téléversement d'un autre propriétaire → E_PRECONDITION" "$(code "$out")" E_PRECONDITION
expect "téléversement inexistant → E_NOT_FOUND" "$(apply_upload "$(cat /proc/sys/kernel/random/uuid)")" E_NOT_FOUND

# --- 3. Archives piégées (correctement signées) ---------------------------------------------
for kind in symlink dotdot absolute outside hardlink fifo duplicate badversion; do
	d="$TMP/trap-$kind"; mkrel 0.3.0 "$d" "$kind"
	expect "archive piégée ($kind) → E_ARCHIVE" "$(apply_upload "$(upload "$d")")" E_ARCHIVE
done
expect "rien d'écrit hors de la cible" \
	"$(find "$TMP" / -xdev -maxdepth 3 -name 'escaped-*' 2> /dev/null | wc -l)" 0
expect "archives piégées : versions inchangées" "$(current) $(previous)" "releases/0.2.0 releases/0.1.0"
expect "archives piégées : aucun répertoire 0.3.0 résiduel" "$(find "$T/opt/scanoria/releases" -maxdepth 1 -name '0.3.0*' | wc -l)" 0

# --- 4. Retour arrière automatique (santé en échec) ------------------------------------------
echo '{"status":"ok","version":"0.2.0","db":"ok"}' > "$TMP/health.json"
: > "$T/test-commands.log"
expect "santé en échec → E_HEALTH_ROLLED_BACK" "$(apply_upload "$(upload "$R7")")" E_HEALTH_ROLLED_BACK
expect "retour arrière automatique : liens rétablis" "$(current) $(previous)" "releases/0.2.0 releases/0.1.0"
expect "retour arrière automatique : rootfs rétabli" "$(tail -n 1 "$T/usr/sbin/scanoria-dummy")" "echo 0.2.0"
grep -q 'pg_restore' "$T/test-commands.log" && ok "retour arrière automatique : base restaurée" || ko "restauration de base"
[[ ! -d "$T/opt/scanoria/releases/0.3.0" ]] && ok "retour arrière automatique : 0.3.0 retirée" || ko "0.3.0 résiduelle"

# --- 4 bis. Budget de temps : jamais d'arrêt de la console sans réserve pour revenir ------------
: > "$T/test-commands.log"
echo '{"status":"ok","version":"0.3.0","db":"ok"}' > "$TMP/health.json"
out=$(SCANORIA_UPDATE_DEADLINE=$(( $(date +%s) + 600 )) "$SU" apply --upload-id "$(upload "$R7")" 2> /dev/null || true)
expect "échéance trop proche → E_TIMEOUT avant tout changement" "$(code "$out")" E_TIMEOUT
expect "échéance trop proche : versions inchangées" "$(current) $(previous)" "releases/0.2.0 releases/0.1.0"
grep -qF '["systemctl","stop","scanoria-console.service"]' "$T/test-commands.log" \
	&& ko "échéance trop proche : console arrêtée" || ok "échéance trop proche : console jamais arrêtée"
[[ ! -d "$T/opt/scanoria/releases/0.3.0" ]] && ok "échéance trop proche : 0.3.0 retirée" || ko "0.3.0 résiduelle"
out=$(SCANORIA_UPDATE_DEADLINE=$(( $(date +%s) + 600 )) "$SU" rollback --expected-current 0.2.0 --expected-target 0.1.0 2> /dev/null || true)
expect "retour N-1 sans assez de temps → E_TIMEOUT" "$(code "$out")" E_TIMEOUT
expect "retour N-1 refusé : versions inchangées" "$(current) $(previous)" "releases/0.2.0 releases/0.1.0"

# --- 5. Retour à N-1 sur demande ----------------------------------------------------------------
rb() { code "$("$SU" rollback --expected-current "$1" --expected-target "$2" 2> /dev/null || true)"; }
expect "retour N-1 avec versions inattendues → E_PRECONDITION" "$(rb 0.2.0 0.0.9)" E_PRECONDITION
echo '{"status":"ok","version":"0.1.0","db":"ok"}' > "$TMP/health.json"
expect "retour N-1 0.2.0 → 0.1.0 → OK" "$(rb 0.2.0 0.1.0)" OK
expect "après retour N-1 : current 0.1.0, plus de previous" "$(current) $(previous)" "releases/0.1.0 none"
expect "après retour N-1 : rootfs de 0.1.0" "$(tail -n 1 "$T/usr/sbin/scanoria-dummy")" "echo 0.1.0"
expect "second retour N-1 → E_NO_PREVIOUS" "$(rb 0.1.0 0.0.9)" E_NO_PREVIOUS
expect "après retour N-1 : version abandonnée notée (skip-version.json)" \
	"$(jq -r .version "$T/var/lib/scanoria/updates/skip-version.json" 2> /dev/null)" 0.2.0

# --- 6. Release GitHub toujours proposée (rejet, brouillon, canal) ------------------------------
offered=$(python3 -I -B - "$ROOT/src/rootfs/usr/lib/scanoria/py" "$TMP" <<-'EOF'
	import sys
	sys.path.insert(0, sys.argv[1])
	from scanoria import selfupdate as su
	from scanoria.common import Fail
	REPO = "exemple/scanoria"
	def rel(**kw):
	    r = {"tag_name": "v0.3.0", "name": "v0.3.0", "draft": False, "prerelease": False}
	    r.update(kw)
	    return r
	def run(api, channel, stable=None, atom=()):
	    su.api_get = lambda tmp, path: api
	    su.latest_stable_fallback = lambda repo, tmp: stable
	    su.atom_entries = lambda repo, tmp: list(atom)
	    try:
	        su.check_offered(REPO, "0.3.0", channel, sys.argv[2])
	        return "OK"
	    except Fail as e:
	        return e.code
	res = [
	    run((200, rel()), "stable"),
	    run((200, rel(name="[rejected] v0.3.0")), "prerelease"),
	    run((200, rel(draft=True)), "prerelease"),
	    run((200, rel(prerelease=True)), "stable"),
	    run((200, rel(prerelease=True)), "prerelease"),
	    run((200, rel(tag_name="v0.3.1")), "stable"),
	    run((404, None), "stable"),
	    run((403, None), "stable", stable={"version": "0.3.0"}),
	    run((403, None), "stable", stable={"version": "0.2.0"}),
	    run((429, None), "prerelease", atom=[("0.3.0", "[rejected] v0.3.0", None, "v0.3.0")]),
	    run((429, None), "prerelease", atom=[("0.3.0", "v0.3.0", None, "v0.3.0")]),
	    run((0, None), "prerelease", atom=[]),
	]
	# apply --version : la release est revérifiée avant tout téléchargement.
	calls = []
	su.api_get = lambda tmp, path: (200, rel(name="[rejected] v0.3.0"))
	su.fetch_signed = lambda *a: calls.append("fetch")
	su.source_repo = lambda: REPO
	try:
	    su.cmd_apply(version="0.3.0")
	    res.append("OK")
	except Fail as e:
	    res.append(e.code + ("+fetch" if calls else ""))
	print(" ".join(res))
EOF
)
expect "release proposée : stable, rejet, brouillon, canal, tag, 404, replis ; apply --version" "$offered" \
	"OK E_VERSION E_VERSION E_VERSION OK E_VERSION E_NOT_FOUND OK E_VERSION E_VERSION OK E_VERSION E_VERSION"

# --- 7. Dernière version stable, même si releases/latest est l'index du catalogue ---------------
latest=$(python3 -I -B - "$ROOT/src/rootfs/usr/lib/scanoria/py" "$TMP" <<-'EOF'
	import sys
	sys.path.insert(0, sys.argv[1])
	from scanoria import selfupdate as su
	def rel(tag, pre=False):
	    return {"tag_name": tag, "name": tag, "draft": False, "prerelease": pre}
	LIST = [rel("catalog-v2"), rel("v0.3.0", True), rel("v0.2.0"), rel("v0.1.0"), rel("catalog-v1")]
	def run(answers, channel="stable"):
	    it = iter(answers)
	    su.api_get = lambda tmp, path: next(it)
	    r = su.find_latest("exemple/scanoria", channel, sys.argv[2])
	    return r["version"] if r else "none"
	print(" ".join([
	    run([(200, rel("v0.2.0"))]),
	    run([(200, rel("v0.3.0", True))]),
	    run([(200, rel("catalog-v2")), (200, LIST)]),
	    run([(200, rel("catalog-v1")), (200, [rel("catalog-v1"), rel("v0.1.0", True)])]),
	    run([(200, rel("catalog-v1")), (403, None)]),
	    run([(200, LIST)], "prerelease"),
	]))
EOF
)
expect "dernière stable : latest, pré-version, catalogue → liste, aucune stable, limite, canal pré-version" \
	"$latest" "0.2.0 none 0.2.0 none none 0.3.0"

echo
echo "b02 : $PASS réussi(s), $FAIL échec(s)"
[[ $FAIL -eq 0 ]]
