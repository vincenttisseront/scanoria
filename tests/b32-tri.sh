#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Vincent Tisseront
#
# b32-tri — responsables CODEOWNERS (0.7, F6), sans root ni conteneur. Le
# fichier CODEOWNERS vient du dépôt analysé : c'est une donnée hostile.
# Cas :
#   - runner (scanoria.codeowners, python3 -I) : emplacements GitHub, GitLab
#     et Forgejo dans l'ordre, copie à l'identique en 0640 ; refus d'un lien
#     symbolique (fichier ou dossier parent), d'un lien dur, d'un dossier, d'un
#     fichier trop grand, d'un octet nul, d'un contenu non UTF-8 ; un fichier
#     piégé n'est jamais lu hors de la source ; capture() ne lève jamais ;
#   - console (webui/server/findings/codeowners.ts, node --experimental-strip-types) :
#     motifs pathologiques en temps borné, « .. » et classes refusés, fichier
#     trop grand ignoré, nombre de règles et de responsables bornés, rien
#     d'interprété dans les responsables.
# Dépendances : bash, python3 (≥ 3.10), node ≥ 22.6 pour le volet console
# (ignoré, et signalé, avec un node plus ancien).

set -euo pipefail
export PYTHONDONTWRITEBYTECODE=1

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
PY="$ROOT/src/rootfs/usr/lib/scanoria/py"
TS="$ROOT/webui/server/findings/codeowners.ts"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
command -v python3 > /dev/null || { echo "outil manquant : python3" >&2; exit 2; }

PASS=0
FAIL=0
ok() { PASS=$((PASS + 1)); printf 'ok   %s\n' "$1"; }
ko() { FAIL=$((FAIL + 1)); printf 'FAIL %s\n' "$1"; }
expect() {
	if [[ "$2" == "$3" ]]; then ok "$1"; else ko "$1 (obtenu « $2 », attendu « $3 »)"; fi
}

# capture(src, rdir) du runner ; affiche True/False puis l'empreinte de codeowners.txt (ou « - »).
capture() { # src
	local rdir="$TMP/out.$RANDOM"
	mkdir -p "$rdir"
	(cd "$TMP" && SCANORIA_TEST_ROOT="$TMP" python3 -I -c 'import hashlib, os, sys
sys.path.insert(0, sys.argv[1])
from scanoria import codeowners
r = codeowners.capture(sys.argv[2], sys.argv[3])
p = os.path.join(sys.argv[3], "codeowners.txt")
if os.path.exists(p):
    st = os.stat(p)
    print(r, hashlib.sha256(open(p, "rb").read()).hexdigest()[:12], oct(st.st_mode & 0o777))
else:
    print(r, "-", "-")' "$PY" "$1" "$rdir")
}
sha() { python3 -I -c 'import hashlib, sys; print(hashlib.sha256(open(sys.argv[1], "rb").read()).hexdigest()[:12])' "$1"; }

# --- runner : emplacements et copie ---
S="$TMP/src-ok"
mkdir -p "$S/.github" "$S/.gitlab"
printf '* @org/tous\n*.js @front\n' > "$S/.github/CODEOWNERS"
printf '* @gitlab\n' > "$S/.gitlab/CODEOWNERS"
expect ".github/CODEOWNERS prioritaire, copié tel quel en 0640" "$(capture "$S")" "True $(sha "$S/.github/CODEOWNERS") 0o640"
rm "$S/.github/CODEOWNERS"
expect "repli sur .gitlab/CODEOWNERS" "$(capture "$S")" "True $(sha "$S/.gitlab/CODEOWNERS") 0o640"
F="$TMP/src-forgejo"
mkdir -p "$F/.forgejo"
printf '* @forgejo\n' > "$F/.forgejo/CODEOWNERS"
expect "emplacement Forgejo" "$(capture "$F")" "True $(sha "$F/.forgejo/CODEOWNERS") 0o640"
mkdir -p "$TMP/src-none"
expect "aucun CODEOWNERS : rien copié" "$(capture "$TMP/src-none")" "False - -"
expect "source absente : rien copié, aucune erreur" "$(capture "$TMP/absente")" "False - -"

# --- runner : fichiers piégés ---
SECRET="$TMP/hors-source"
printf '* @fuite\n' > "$SECRET"
L="$TMP/src-symlink"
mkdir -p "$L"
ln -s "$SECRET" "$L/CODEOWNERS"
expect "lien symbolique refusé" "$(capture "$L")" "False - -"
D="$TMP/src-dirlink"
mkdir -p "$D" "$TMP/ailleurs"
printf '* @fuite\n' > "$TMP/ailleurs/CODEOWNERS"
ln -s "$TMP/ailleurs" "$D/.github"
expect "dossier parent en lien symbolique refusé" "$(capture "$D")" "False - -"
H="$TMP/src-hardlink"
mkdir -p "$H"
ln "$SECRET" "$H/CODEOWNERS"
expect "lien dur refusé" "$(capture "$H")" "False - -"
R="$TMP/src-dir"
mkdir -p "$R/CODEOWNERS"
expect "dossier nommé CODEOWNERS refusé" "$(capture "$R")" "False - -"
B="$TMP/src-big"
mkdir -p "$B"
python3 -I -c 'import sys; open(sys.argv[1], "w").write("* @x\n" + "#" * (128 * 1024))' "$B/CODEOWNERS"
expect "fichier de plus de 128 Kio refusé" "$(capture "$B")" "False - -"
N="$TMP/src-nul"
mkdir -p "$N"
printf '* @x\0\n' > "$N/CODEOWNERS"
expect "octet nul refusé" "$(capture "$N")" "False - -"
U="$TMP/src-latin1"
mkdir -p "$U"
printf '* @\xe9quipe\n' > "$U/CODEOWNERS"
expect "contenu non UTF-8 refusé" "$(capture "$U")" "False - -"
X="$TMP/src-fifo"
mkdir -p "$X"
mkfifo "$X/CODEOWNERS"
expect "tube nommé refusé sans blocage" "$(timeout 10 bash -c "$(declare -f capture); TMP='$TMP' PY='$PY' capture '$X'")" "False - -"
expect "le fichier hors source n'a pas été modifié" "$(cat "$SECRET")" "* @fuite"

# --- console : analyseur TypeScript ---
rm -f /tmp/scanoria-b32-pwn
if node --experimental-strip-types -e '' > /dev/null 2>&1; then
	# shellcheck disable=SC2016 # code JavaScript littéral, rien à développer
	out=$(cd "$TMP" && node --no-warnings --experimental-strip-types --input-type=module -e '
const m = await import(process.argv[1])
const res = {}
const t0 = Date.now()
for (const p of ["*a*a*a*a*a*a*a*a*a*a*a*a*a*a*b", "**/**/**/x", "?".repeat(16), "a*".repeat(8) + "b"]) {
  const f = m.compilePattern(p)
  if (f) f("a".repeat(400) + "/" + "a/".repeat(200) + "a".repeat(400))
}
res.fast = Date.now() - t0 < 1000
res.tooMany = m.compilePattern("*".repeat(17)) === null && m.compilePattern("**/a/**/b/**/c/**/d") === null
res.parent = m.parseCodeowners("../x @a\na/../b @a\n").issues.map(i => i.code).join(",")
res.cls = m.compilePattern("[a-z]*") === null
res.big = m.parseCodeowners("* @x\n" + "#".repeat(m.MAX_CODEOWNERS_BYTES)).rules.length
const lines = Array.from({ length: m.MAX_RULES + 10 }, (_, i) => "f" + i + " @o").join("\n")
res.rules = m.parseCodeowners(lines).rules.length === m.MAX_RULES
const wide = m.parseCodeowners("* " + Array.from({ length: 50 }, (_, i) => "@o" + i).join(" "))
res.owners = m.ownersFor(wide, "x").length <= m.MAX_OWNERS
const evil = m.parseCodeowners("*.sh @ok $(touch /tmp/scanoria-b32-pwn) `id` <b>x</b>\n")
res.evil = JSON.stringify(m.ownersFor(evil, "a.sh")) + ":" + evil.issues.map(i => i.code).join(",")
res.escape = JSON.stringify(m.ownersFor(m.parseCodeowners("/a\\ b.txt @e\n"), "a b.txt"))
res.dotdot = m.ownersFor(m.parseCodeowners("* @x\n"), "../etc/passwd").length
console.log(JSON.stringify(res))
' "$TS")
	j() { python3 -I -c 'import json, sys; print(json.loads(sys.argv[1])[sys.argv[2]])' "$out" "$1"; }
	expect "motifs pathologiques en temps borné" "$(j fast)" "True"
	expect "trop de jokers ou de ** refusés" "$(j tooMany)" "True"
	expect "segments « .. » signalés" "$(j parent)" "parent-segment,parent-segment"
	expect "classes de caractères refusées" "$(j cls)" "True"
	expect "fichier trop grand ignoré" "$(j big)" "0"
	expect "nombre de règles borné" "$(j rules)" "True"
	expect "nombre de responsables borné" "$(j owners)" "True"
	expect "responsables piégés écartés, rien d'interprété" "$(j evil)" '["@ok"]:bad-owner'
	expect "échappement « \\ » d'un espace" "$(j escape)" '["@e"]'
	expect "chemin « .. » sans responsable" "$(j dotdot)" "0"
else
	echo "skip volet console : node ≥ 22.6 requis (--experimental-strip-types)"
fi
if [[ -e /tmp/scanoria-b32-pwn ]]; then ko "aucune commande exécutée"; else ok "aucune commande exécutée"; fi

echo "b32-tri : $PASS ok, $FAIL échec(s)"
[[ $FAIL -eq 0 ]]
