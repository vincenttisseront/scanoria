#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Vincent Tisseront
#
# b27 — délais d'exécution de la 0.6 (chantier C, contrat 22), sans root :
#   V1  prefetch-images : demandes hostiles, images présentes ou récupérées,
#       versions figées inconnues du catalogue signé refusées ; --pull=never ;
#   V2  miroir Git : script de récupération exécuté avec le vrai git (chemins
#       du conteneur remplacés), miroir piégé (hooks, fsmonitor, filtres,
#       alternates, lien symbolique), dépôt piégé (lien sortant, sous-module),
#       seconde récupération limitée aux nouveaux objets, commit déjà présent
#       sans contacter la forge, historique complet par alternates, miroir
#       corrompu recréé, purge des projets supprimés ;
#   V7  bases épinglées : bail, bascule et nettoyage pendant une analyse ;
#   V9  seuil du tmpfs, reprise sur disque, exclusions communes ;
#   V10 cache sonar-plugins : seules les extensions vérifiées restent ;
#   montages en lecture seule du runner (bouchon podman).
# Dépendances : bash, python3, jq, git.

# shellcheck disable=SC2016,SC2015
set -euo pipefail
export PYTHONDONTWRITEBYTECODE=1

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
RUNNER="$ROOT/src/rootfs/usr/sbin/scanoria-runner"
PYLIB="$ROOT/src/rootfs/usr/lib/scanoria/py"
TMP=$(mktemp -d)
trap 'chmod -R u+rwX "$TMP" 2> /dev/null; rm -rf "$TMP"' EXIT

# Compteurs tenus dans un fichier : report tourne dans le sous-shell d'un tube.
ok() { echo + >> "$TMP/tally"; printf 'ok   %s\n' "$1"; }
ko() { echo - >> "$TMP/tally"; printf 'FAIL %s\n' "$1"; }
expect() { # libellé valeur_obtenue valeur_attendue
	if [[ "$2" == "$3" ]]; then ok "$1"; else ko "$1 (obtenu « $2 », attendu « $3 »)"; fi
}
for t in python3 jq git; do command -v "$t" > /dev/null || { echo "outil manquant : $t" >&2; exit 2; }; done

T="$TMP/root"
STUBS="$TMP/stubs"
mkdir -p "$T/var/lib/scanoria/modules" "$T/var/lib/scanoria/catalog" "$T/run/scanoria" "$T/proc" "$STUBS"
export SCANORIA_TEST_ROOT="$T" SCANORIA_TEST_BIN="$STUBS"
unset SCANORIA_TEST_OWNER_UID SCANORIA_SCANS_DIR SCANORIA_RUNNER_STATE
printf 'MemTotal:       16384000 kB\nMemAvailable:    8192000 kB\n' > "$T/proc/meminfo"
for i in 0 1 2 3; do printf 'processor\t: %d\n' "$i"; done > "$T/proc/cpuinfo"
# Un bloc Python interrompu (exception) compte comme un échec.
py() { python3 -I -B - "$PYLIB" "$@" || echo "ko bloc Python interrompu (code $?)"; }

# Lanceur commun des cas Python : chaque ligne « ok|ko libellé » est reportée.
report() {
	while IFS= read -r line; do
		case "$line" in
			"ok "*) ok "${line#ok }" ;;
			"ko "*) ko "${line#ko }" ;;
			*) printf '     %s\n' "$line" ;;
		esac
	done
}

# --- 1. V2 : script de récupération avec le vrai git ----------------------------------------
G="$TMP/git"
mkdir -p "$G/forge" "$G/tt"
git -c init.defaultBranch=main init -q "$G/forge/depot"
(
	cd "$G/forge/depot"
	git config user.email ci@exemple.test
	git config user.name ci
	for i in $(seq 1 40); do printf 'fichier %s\n' "$i" > "f$i.txt"; done
	mkdir -p lib && echo 'print(1)' > lib/app.py
	ln -s /etc/passwd lien-sortant
	printf '* filter=piege\n' > .gitattributes
	printf '[submodule "sous"]\n\tpath = sous\n\turl = https://forge.exemple.test/sous.git\n' > .gitmodules
	git add -A
	git update-index --add --cacheinfo "160000,5ca1ab1e5ca1ab1e5ca1ab1e5ca1ab1e5ca1ab1e,sous"
	git commit -qm un
	echo deux > deux.txt && git add deux.txt && git commit -qm deux
) > /dev/null

cat > "$TMP/harness.py" <<'EOF'
# Exécute fetch.FETCH_SCRIPT avec le vrai git, chemins du conteneur remplacés.
import json, os, subprocess, sys
sys.path.insert(0, sys.argv[1])
from scanoria import fetch
tt, mirror, src, gitd, url, ref, want, mode = sys.argv[2:10]
script = fetch.FETCH_SCRIPT
for i, (cpath, real) in enumerate((("/tmp/", tt + "/"), ("/mirror", mirror), ("/src", src), ("/git", gitd))):
    script = script.replace(cpath, "\x00%d\x00" % i)
for i, real in enumerate((tt + "/", mirror, src, gitd)):
    script = script.replace("\x00%d\x00" % i, real)
env, _ = fetch.git_env(None)
n = int(env["GIT_CONFIG_COUNT"])
# Le conteneur n'autorise que https et ssh ; la forge de test est un dépôt local.
env.update({"GIT_CONFIG_KEY_%d" % n: "protocol.file.allow", "GIT_CONFIG_VALUE_%d" % n: "always",
            "GIT_CONFIG_COUNT": str(n + 1), "PATH": os.environ["PATH"], "HOME": tt})
for d in (src, gitd):
    os.makedirs(d, exist_ok=True)
r = subprocess.run(["/bin/sh", "-c", script, "git-fetch", url, ref, want, mode, "k" * 16],
                   env=env, capture_output=True, text=True)
print(json.dumps({"rc": r.returncode, "out": r.stdout, "err": r.stderr[-2000:]}))
EOF
fetchrun() { # miroir src git url ref commit mode
	rm -rf "$2" "$3"
	python3 -I -B "$TMP/harness.py" "$PYLIB" "$G/tt" "$1" "$2" "$3" "$4" "$5" "$6" "$7"
}
M="$TMP/root/var/lib/scanoria/git-mirrors/11111111-1111-4111-8111-111111111111.git"
PID=11111111-1111-4111-8111-111111111111
URL="file://$G/forge/depot"
mk_mirror() { py "$PID" "$URL" <<'EOF'
import sys; sys.path.insert(0, sys.argv[1])
from scanoria import gitmirror
print(gitmirror.prepare(sys.argv[2], sys.argv[3])[1])
EOF
}
expect "miroir : créé au premier usage" "$(mk_mirror)" created
expect "miroir : répertoire 0700" "$(stat -c %a "$M")" 700
R=$(fetchrun "$M" "$G/s" "$G/g" "$URL" main "" shallow)
expect "miroir : premier clone réussi" "$(jq -r .rc <<< "$R")" 0
grep -q '^scanoria=mirror-fetch$' <<< "$(jq -r .out <<< "$R")" && ok "miroir : objets récupérés" || ko "miroir : marqueur absent"
C2=$(git -C "$G/forge/depot" rev-parse HEAD)
expect "miroir : commit extrait" "$(jq -r .out <<< "$R" | sed -n 's/^commit=//p')" "$C2"
[[ -f "$M/shallow" ]] && ok "miroir : premier clone superficiel" || ko "miroir : clone complet inattendu"
[[ -f "$G/s/f40.txt" && -f "$G/s/lib/app.py" ]] && ok "extraction : arbre complet dans /src" || ko "extraction : fichiers absents"
[[ -f "$G/s/lien-sortant" && ! -L "$G/s/lien-sortant" ]] && ok "dépôt piégé : lien sortant écrit en fichier ordinaire" || ko "dépôt piégé : lien symbolique extrait"
[[ -z "$(ls -A "$G/s/sous" 2> /dev/null)" ]] && ok "dépôt piégé : sous-module jamais récupéré" || ko "dépôt piégé : sous-module peuplé"
expect "extraction : /src/.git désigne /git" "$(cat "$G/s/.git")" "gitdir: $G/g"
[[ ! -e "$G/g/HEAD" ]] && ok "superficiel : aucun dépôt /git préparé" || ko "superficiel : /git préparé"
[[ ! -e "$M/index" ]] && ok "miroir : aucun index écrit dans le miroir" || ko "miroir : index écrit dans le miroir"

# Seconde récupération : seuls les nouveaux objets.
before=$(git --git-dir="$M" count-objects -v | awk '/^(count|in-pack):/ {s += $2} END {print s}')
(cd "$G/forge/depot" && echo trois > trois.txt && git add trois.txt && git commit -qm trois)
C3=$(git -C "$G/forge/depot" rev-parse HEAD)
R=$(fetchrun "$M" "$G/s" "$G/g" "$URL" main "" shallow)
after=$(git --git-dir="$M" count-objects -v | awk '/^(count|in-pack):/ {s += $2} END {print s}')
expect "seconde récupération : commit à jour" "$(jq -r .out <<< "$R" | sed -n 's/^commit=//p')" "$C3"
[[ $((after - before)) -le 6 ]] && ok "seconde récupération : $((after - before)) objet(s) nouveaux seulement" || ko "seconde récupération : $((after - before)) objets récupérés"

# Commit déjà présent : la forge n'est pas contactée (URL injoignable).
R=$(fetchrun "$M" "$G/s" "$G/g" "file://$G/forge/absent" main "$C3" shallow)
expect "commit présent : réussi sans la forge" "$(jq -r .rc <<< "$R")" 0
grep -q '^scanoria=mirror-hit$' <<< "$(jq -r .out <<< "$R")" && ok "commit présent : marqueur mirror-hit" || ko "commit présent : forge contactée"

# Miroir piégé : hooks, fsmonitor, filtre, alternates, attributs, lien ; le runner nettoie.
MARK="$TMP/piege-execute"
mkdir -p "$M/hooks" "$TMP/ailleurs/objects"
for h in reference-transaction post-checkout pre-auto-gc; do
	printf '#!/bin/sh\ntouch %s\n' "$MARK" > "$M/hooks/$h"
	chmod +x "$M/hooks/$h"
done
printf '#!/bin/sh\ntouch %s\n' "$MARK" > "$TMP/fsmon"
chmod +x "$TMP/fsmon"
printf '[core]\n\tfsmonitor = %s\n\thooksPath = %s/hooks\n[filter "piege"]\n\tsmudge = %s\n\trequired = true\n' \
	"$TMP/fsmon" "$M" "$TMP/fsmon" >> "$M/config"
mkdir -p "$M/info" && printf '* filter=piege\n' > "$M/info/attributes"
echo "$TMP/ailleurs/objects" > "$M/objects/info/alternates"
echo piege > "$M/config.worktree"
expect "miroir piégé : réutilisé après nettoyage" "$(mk_mirror)" reused
for f in hooks info/attributes objects/info/alternates config.worktree; do
	[[ ! -e "$M/$f" ]] && ok "miroir piégé : $f retiré" || ko "miroir piégé : $f laissé"
done
grep -q fsmonitor "$M/config" && grep -q 'fsmonitor = false' "$M/config" && ! grep -q piege "$M/config" &&
	ok "miroir piégé : configuration réécrite" || ko "miroir piégé : configuration conservée"
R=$(fetchrun "$M" "$G/s" "$G/g" "$URL" main "" shallow)
expect "miroir piégé : récupération réussie" "$(jq -r .rc <<< "$R")" 0
[[ ! -e "$MARK" ]] && ok "miroir piégé : aucun hook, fsmonitor ni filtre exécuté" || ko "miroir piégé : code du dépôt exécuté"
ln -s "$TMP/ailleurs" "$M/refs/lien"
expect "miroir piégé : lien symbolique → miroir recréé" "$(mk_mirror)" created
[[ ! -L "$M/refs/lien" ]] && ok "miroir piégé : lien retiré avec le miroir" || ko "miroir piégé : lien laissé"

# Historique complet : /git emprunte les objets du miroir (alternates), rien n'est copié.
R=$(fetchrun "$M" "$G/s" "$G/g" "$URL" main "" full)
expect "historique complet : réussi" "$(jq -r .rc <<< "$R")" 0
[[ ! -f "$M/shallow" ]] && ok "historique complet : miroir complet" || ko "historique complet : miroir superficiel"
expect "historique complet : alternates vers le miroir" "$(cat "$G/g/objects/info/alternates")" "$M/objects"
expect "historique complet : trois commits lisibles depuis /git" "$(git --git-dir="$G/g" log --oneline | wc -l | tr -d ' ')" 3
expect "historique complet : /git ne copie aucun objet" "$(find "$G/g/objects" -type f ! -path '*/info/*' | wc -l | tr -d ' ')" 0
# Superficiel sur un miroir complet : aucune profondeur (le miroir reste complet).
(cd "$G/forge/depot" && echo quatre > quatre.txt && git add quatre.txt && git commit -qm quatre)
R=$(fetchrun "$M" "$G/s" "$G/g" "$URL" main "" shallow)
[[ ! -f "$M/shallow" ]] && ok "miroir complet : reste complet après un clone superficiel" || ko "miroir complet : redevenu superficiel"

# Miroir corrompu : extraction impossible → code 74, marqueur « corrupt ».
C4=$(git -C "$G/forge/depot" rev-parse HEAD)
tree=$(git --git-dir="$M" rev-parse "$C4^{tree}")
git --git-dir="$M" repack -q -d -a 2> /dev/null || true
# Paquets tronqués après leur en-tête : l'index annonce les objets, aucun n'est lisible
# (indépendant de la version de git et de zlib).
find "$M/objects/pack" -name '*.pack' -exec sh -c 'chmod u+w "$1"; truncate -s 64 "$1"' _ {} \;
find "$M/objects" -path "*/${tree:0:2}/${tree:2}" -delete 2> /dev/null || true
R=$(fetchrun "$M" "$G/s" "$G/g" "$URL" main "$C4" shallow)
expect "miroir corrompu : code 74" "$(jq -r .rc <<< "$R")" 74
grep -q '^scanoria=corrupt$' <<< "$(jq -r .out <<< "$R")" && ok "miroir corrompu : marqueur corrupt" || ko "miroir corrompu : marqueur absent ($(jq -r .err <<< "$R" | tail -2))"

# --- 2. V2 : miroir, sessions et purge (unité) ----------------------------------------------
py "$TMP" <<'EOF' | report
import os, sys, time, json
sys.path.insert(0, sys.argv[1])
from scanoria import gitmirror, common
def check(label, cond):
    print(("ok " if cond else "ko ") + label)
for bad in ("../x", "1111", "11111111-1111-4111-8111-111111111111/../x", None):
    try:
        gitmirror.path_of(bad); check("identifiant hostile refusé : %r" % bad, False)
    except gitmirror.MirrorError:
        check("identifiant hostile refusé : %r" % bad, True)
pid = "22222222-2222-4222-8222-222222222222"
p, st = gitmirror.prepare(pid, "https://forge.exemple.test/a.git")
check("prepare : créé", st == "created" and os.path.isfile(p + "/HEAD"))
p, st = gitmirror.prepare(pid, "https://forge.exemple.test/a.git")
check("prepare : réutilisé", st == "reused")
open(p + "/objects/marque", "w").close()
p, st = gitmirror.prepare(pid, "https://forge.exemple.test/autre.git")
check("prepare : URL changée → recréé", st == "created" and not os.path.exists(p + "/objects/marque"))
gitmirror.MAX_MIRROR_BYTES = 10
open(p + "/objects/gros", "w").write("x" * 100)
p, st = gitmirror.prepare(pid, "https://forge.exemple.test/autre.git")
check("prepare : trop gros → recréé", st == "created")
gitmirror.MAX_MIRROR_BYTES = 8 << 30
os.makedirs(p + "/info", exist_ok=True); os.rename(p + "/info", p + "/info.reel"); os.symlink("/etc", p + "/info")
try:
    gitmirror.sanitize(p); check("sanitize : lien intermédiaire refusé", False)
except gitmirror.MirrorError as e:
    check("sanitize : lien intermédiaire refusé", e.code == "E_GITMIRROR_LAYOUT" and os.path.isdir("/etc"))
os.unlink(p + "/info"); os.rename(p + "/info.reel", p + "/info")
os.mkfifo(p + "/objects/tube")
p, st = gitmirror.prepare(pid, "https://forge.exemple.test/autre.git")
check("prepare : fichier spécial → recréé", st == "created")
# Verrou : une seconde session du même projet attend, puis abandonne (busy).
with gitmirror.locked(pid):
    try:
        with gitmirror.locked(pid, timeout=1):
            check("verrou : exclusif", False)
    except gitmirror.MirrorError as e:
        check("verrou : exclusif (%s)" % e.code, e.code == "E_GITMIRROR_BUSY")
# Session sans projet : miroir jetable dans l'espace de travail.
ws = os.path.join(sys.argv[2], "ws")
os.makedirs(ws)
with gitmirror.Session(None, "https://forge.exemple.test/a.git", ws) as s:
    check("session sans projet : miroir jetable dans l'espace", s.path == ws + "/mirror" and s.project_id is None)
gitmirror.note_tree(pid, 3, 12345)
check("taille du dernier arbre notée", gitmirror.last_tree_bytes(pid) == 12345)
# Purge : liste du worker (jobs/tmp/live-projects.json).
live = os.path.join(sys.argv[2], "live.json")
other = "33333333-3333-4333-8333-333333333333"
gitmirror.prepare(other, "https://forge.exemple.test/b.git")
check("liste absente : aucune purge", gitmirror.purge_orphans(gitmirror.live_projects(live)) == [])
open(live, "w").write(json.dumps({"schema": 1, "projects": [pid]}))
check("liste lue", gitmirror.live_projects(live) == {pid})
os.utime(live, (time.time() - 7200, time.time() - 7200))
check("liste trop ancienne : ignorée", gitmirror.live_projects(live) is None)
open(live, "w").write(json.dumps({"schema": 1, "projects": ["../../etc"]}))
check("liste hostile : ignorée", gitmirror.live_projects(live) is None)
first = "11111111-1111-4111-8111-111111111111"
open(live, "w").write(json.dumps({"schema": 1, "projects": [pid, first]}))
check("projet supprimé mais utilisé récemment : gardé", gitmirror.purge_orphans(gitmirror.live_projects(live)) == [])
dropped = []
done = gitmirror.purge_orphans(gitmirror.live_projects(live), extra=(dropped.append,), now=time.time() + 7 * 3600)
check("projet supprimé : miroir purgé", done == [other] and not os.path.exists(gitmirror.path_of(other)))
check("projet supprimé : caches purgés", dropped == [other])
check("projet existant : miroir gardé", os.path.isdir(gitmirror.path_of(pid)))
EOF

# --- 3. V9 : tmpfs et exclusions -------------------------------------------------------------
py "$TMP" <<'EOF' | report
import os, sys
sys.path.insert(0, sys.argv[1])
from scanoria import workspace
def check(label, cond):
    print(("ok " if cond else "ko ") + label)
check("tmpfs : 2 vCPU / 4 Go (2,5 Go libres, scanner 512 Mo) → en mémoire",
      workspace.tmpfs_size_mb(2560, 512, 1024) == 256)
check("tmpfs : SonarQube (2 Go) sur 4 Go → disque", workspace.tmpfs_size_mb(2560, 2048, 1024) == 0)
check("tmpfs : borné à 1 Gio", workspace.tmpfs_size_mb(64000, 512, 1024) == 1024)
check("tmpfs : dernier arbre trop gros → disque", workspace.tmpfs_size_mb(8000, 512, 1024, 900 << 20) == 0)
check("tmpfs : dernier arbre petit → mémoire", workspace.tmpfs_size_mb(8000, 512, 1024, 10 << 20) == 1024)
check("tmpfs : RAM libre illisible → disque", workspace.tmpfs_size_mb(0, 512, 1024) == 0)
root = os.path.join(sys.argv[2], "arbre")
def mk(rel, data="x"):
    p = os.path.join(root, rel); os.makedirs(os.path.dirname(p), exist_ok=True); open(p, "w").write(data)
for i in range(5):
    mk("web/node_modules/pkg%d/index.js" % i)
mk("node_modules/a/b/c.js")
mk("go/vendor/modules.txt"); mk("go/vendor/x/y.go")
mk("php/vendor/autoload.php")
mk("propre/vendor/notre-code.py")
mk("img/logo.png"); mk("img/photo.JPG"); mk("fonts/a.woff2")
mk("lib/app.jar"); mk("bin/outil"); mk("modele.pkl"); mk("src/main.py")
os.symlink("/etc", os.path.join(root, "lien-node_modules"))
mk("ok-mais-:virgule,/node_modules/x.js")
masks, exl = workspace.common_exclusions(root)
ex = {e["pattern"]: e["count"] for e in exl}
check("exclusion : node_modules comptés (6 fichiers)", ex.get("**/node_modules/**") == 6)
check("exclusion : vendor de Go et de Composer (3 fichiers)", ex.get("**/vendor/**") == 3)
check("exclusion : vendor de code propre gardé", "propre/vendor" not in dict(masks))
check("exclusion : rien n'est retiré de l'arbre (secrets et SAST voient tout)",
      all(os.path.isfile(root + "/" + p) for p in ("web/node_modules/pkg0/index.js", "go/vendor/x/y.go", "img/logo.png")))
check("exclusion : masques triés, répertoires et fichiers", ("node_modules", "dir") in masks and ("img/logo.png", "file") in masks
      and ("web/node_modules", "dir") in masks)
check("exclusion : chemin avec « : » ou « , » jamais masqué", not any(":" in r or "," in r for r, _ in masks))
check("exclusion : rien d'un chemin non masqué n'est compté", ex.get("**/node_modules/**") == 6)
check("exclusion : secrets et SAST voient tout l'arbre", workspace.sees_full_tree({"categories": ["sca", "secrets"]})
      and workspace.sees_full_tree({"categories": ["quality", "sast"]}) and not workspace.sees_full_tree({"categories": ["sca"]})
      and workspace.sees_full_tree({}))
mounts = workspace.mask_mounts(sys.argv[2], masks)
check("exclusion : masques en lecture seule sous /src", all(t.startswith("/src/") and mo == "ro" for _, t, mo in mounts)
      and os.listdir(sys.argv[2] + "/mask-dir") == [] and os.path.getsize(sys.argv[2] + "/mask-file") == 0)
workspace.MAX_MASKS = 2
check("exclusion : nombre de masques borné", len(workspace.common_exclusions(root)[0]) == 2)
workspace.MAX_MASKS = 200
check("exclusion : images et polices", ex.get("**/*.png") == 1 and ex.get("**/*.jpg") == 1 and ex.get("**/*.woff2") == 1)
check("exclusion : jar, exécutable, modèle et code jamais masqués", not {r for r, _ in masks} & {"lib/app.jar", "bin/outil", "modele.pkl", "src/main.py"})
check("exclusion : lien symbolique jamais suivi", os.path.islink(root + "/lien-node_modules") and os.path.isdir("/etc"))
EOF

# --- 4. V7 : bases épinglées pendant l'analyse ----------------------------------------------
py <<'EOF' | report
import os, sys
sys.path.insert(0, sys.argv[1])
from scanoria import feeds, common
def check(label, cond):
    print(("ok " if cond else "ko ") + label)
J1 = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
feeds._dirs()
os.makedirs(feeds.store_dir("trivy-db"), exist_ok=True)
def version(name):
    d = os.path.join(feeds.store_dir("trivy-db"), name)
    os.makedirs(d + "/db"); open(d + "/db/trivy.db", "w").write(name)
    return d
check("base vide : aucun bail", feeds.lease("trivy-db", J1) is None)
v1 = version("20261120T010000Z-00000001")
feeds.swap("trivy-db", v1)
l = feeds.lease("trivy-db", J1)
check("bail : version active épinglée", l["path"] == os.path.realpath(v1) and l["version"] == "20261120T010000Z-00000001")
check("bail : date de la version", l["updated_at"] == "2026-11-20T01:00:00Z")
v2 = version("20261121T010000Z-00000002"); prev = feeds.swap("trivy-db", v2); feeds.prune("trivy-db", prev)
v3 = version("20261122T010000Z-00000003"); prev = feeds.swap("trivy-db", v3); feeds.prune("trivy-db", prev)
check("bascules pendant l'analyse : version montée gardée", os.path.isfile(v1 + "/db/trivy.db"))
check("bascules : lien sur la dernière version", os.path.realpath(feeds.link_path("trivy-db")) == os.path.realpath(v3))
J2 = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
check("analyse suivante : nouvelle version", feeds.lease("trivy-db", J2)["path"] == os.path.realpath(v3))
feeds.release("trivy-db", J1)
v4 = version("20261123T010000Z-00000004"); prev = feeds.swap("trivy-db", v4); feeds.prune("trivy-db", prev)
check("bail rendu : ancienne version retirée", not os.path.exists(v1))
check("bail en cours (J2) : version gardée", os.path.isdir(v3))
feeds.release_all()
check("redémarrage du runner : baux rendus", feeds.leased_versions("trivy-db") == set())
try:
    feeds.lease("trivy-db", "../../x"); check("bail : identifiant hostile refusé", False)
except common.Fail:
    check("bail : identifiant hostile refusé", True)
os.unlink(feeds.link_path("trivy-db"))
os.symlink("/etc", feeds.link_path("trivy-db"))
try:
    feeds.lease("trivy-db", J1); check("bail : lien hors du magasin refusé", False)
except common.Fail:
    check("bail : lien hors du magasin refusé", True)
# Base héritée (répertoire réel, 0.2 à 0.3.3) montée pendant la première bascule.
os.makedirs(feeds.store_dir("osv-db"), exist_ok=True)
os.makedirs(feeds.link_path("osv-db") + "/db"); open(feeds.link_path("osv-db") + "/db/all.zip", "w").write("ancienne")
l = feeds.lease("osv-db", J1)
check("base héritée : bail pris", l["path"] == feeds.link_path("osv-db") and feeds.leased_versions("osv-db") == {"legacy"})
n1 = os.path.join(feeds.store_dir("osv-db"), "20261124T010000Z-00000001"); os.makedirs(n1)
prev = feeds.swap("osv-db", n1); feeds.prune("osv-db", prev)
kept = [n for n in os.listdir(feeds.store_dir("osv-db")) if n.startswith("legacy-")]
check("base héritée : gardée pendant l'analyse", len(kept) == 1 and os.path.isfile(os.path.join(feeds.store_dir("osv-db"), kept[0], "db/all.zip")))
feeds.release("osv-db", J1); feeds.prune("osv-db")
check("base héritée : retirée après le bail", not [n for n in os.listdir(feeds.store_dir("osv-db")) if n.startswith("legacy-")])
# G11 : la version montée figure dans le résultat.
from scanoria import runner
reg = {"modules": {}}
m = {"id": "lecteur", "requires": {"feeds": ["osv-db"]}}
fi = runner.feeds_info(reg, m, {"osv-db": {"path": n1, "version": "20261124T010000Z-00000001", "updated_at": "2026-11-24T01:00:00Z"}})
check("résultat : version montée enregistrée (G11)", fi == [{"id": "osv-db", "version": None, "updated_at": "2026-11-24T01:00:00Z", "revision": "20261124T010000Z-00000001"}])
fi = runner.feeds_info(reg, m, {"osv-db": {"path": "x", "version": None, "updated_at": None}})
check("résultat : base héritée sans révision", "revision" not in fi[0])
EOF

# --- 5. V1 : prefetch-images -------------------------------------------------------------------
IMG="ghcr.io/exemple/faux@sha256:$(printf 'faux' | sha256sum | cut -d' ' -f1)"
ABS="ghcr.io/exemple/absent@sha256:$(printf 'absent' | sha256sum | cut -d' ' -f1)"
PIN="ghcr.io/exemple/faux@sha256:$(printf 'ancien' | sha256sum | cut -d' ' -f1)"
cat > "$STUBS/podman" <<EOF
#!/usr/bin/env python3
import json, sys
a = sys.argv[1:]
open("$TMP/podman.log", "a").write(json.dumps(a) + "\n")
if a[:2] == ["image", "exists"]:
    sys.exit(1 if ("absent" in a[2] or "$PIN" == a[2]) else 0)
if a[:1] == ["pull"]:
    sys.exit(1 if "casse" in a[-1] else 0)
sys.exit(0)
EOF
chmod 0755 "$STUBS/podman"
py "$IMG" "$ABS" "$PIN" <<'EOF' | report
import json, os, sys
sys.path.insert(0, sys.argv[1])
img, absent, pin = sys.argv[2:5]
from scanoria import common, modules, catalogverify, prefetch, schema
def check(label, cond):
    print(("ok " if cond else "ko ") + label)
def man(mid, image):
    return {"manifest": {"id": mid, "version": "1.0.0", "type": "scanner", "image": image}, "status": "healthy", "enabled": True}
reg = {"modules": {"faux": man("faux", img), "manque": man("manque", absent), "feed": {"manifest": {"id": "feed", "type": "feed"}}}}
common.write_json(modules.REGISTRY, reg)
common.write_json(catalogverify.INDEX_FILE, {"version": 12, "modules": [
    {"id": "faux", "version": "1.0.0", "image": img}, {"id": "faux", "version": "0.9.0", "image": pin}]})
v = schema.load("requests", "prefetch-images")
base = {"version": 1, "id": "cccccccc-cccc-4ccc-8ccc-cccccccccccc", "type": "prefetch-images",
        "created_at": "2026-11-24T10:00:00Z", "requested_by": {"user_id": 0, "username": "system"}}
def req(params):
    return dict(base, params=params)
d = "sha256:" + "a" * 64
check("schéma : demande vide acceptée", not v.errors(req({})))
for label, params in (("image imposée", {"image": img}),
                      ("empreinte invalide", {"pins": [{"module_id": "faux", "version": "1", "image_digest": "sha256:zz"}]}),
                      ("champ en trop", {"pins": [{"module_id": "faux", "version": "1", "image_digest": d, "image": img}]}),
                      ("module hostile", {"pins": [{"module_id": "../x", "version": "1", "image_digest": d}]}),
                      ("trop de versions figées", {"pins": [{"module_id": "faux", "version": "1", "image_digest": d}] * 501})):
    check("schéma : %s refusé" % label, bool(v.errors(req(params))))
class C:
    def __init__(self, params): self.params = params
    def left(self): return 3000
log = os.path.join(os.environ["SCANORIA_TEST_ROOT"], "..", "podman.log")
open(log, "w").close()
out = prefetch.act_prefetch_images(C({}))
pulls = [json.loads(x) for x in open(log) if json.loads(x)[:1] == ["pull"]]
check("installés : image présente non récupérée, image absente récupérée",
      out["checked"] == 2 and out["present"] == 1 and [p[-1] for p in pulls] == [absent])
check("installés : récupération par empreinte (@sha256:)", all("@sha256:" in p[-1] for p in pulls))
check("feed déclaratif sans image : ignoré", all(p[-1] != None for p in pulls))
out = prefetch.act_prefetch_images(C({"pins": [{"module_id": "faux", "version": "0.9.0", "image_digest": pin.split("@")[1]}]}))
check("version figée connue du catalogue : récupérée", {"module": "faux", "origin": "pin"} in out["pulled"])
try:
    prefetch.act_prefetch_images(C({"pins": [{"module_id": "faux", "version": "0.9.0", "image_digest": d}]}))
    check("version figée inconnue du catalogue : refusée", False)
except common.Fail as f:
    check("version figée inconnue du catalogue : refusée (%s)" % f.code, f.code == "E_PREFETCH_UNKNOWN_IMAGE")
    pulled = [json.loads(x)[-1] for x in open(log) if json.loads(x)[:1] == ["pull"]]
    check("version figée inconnue : jamais récupérée", not any(x.endswith(d) for x in pulled))
reg["modules"]["casse"] = man("casse", absent.replace("absent", "absent-casse"))
common.write_json(modules.REGISTRY, reg)
try:
    prefetch.act_prefetch_images(C({}))
    check("récupération impossible : E_PREFETCH_FAILED", False)
except common.Fail as f:
    check("récupération impossible : E_PREFETCH_FAILED", f.code == "E_PREFETCH_FAILED" and f.output["failed"][0]["module"] == "casse")
EOF

# --- 6. Runner : montages, tmpfs, reprise sur disque, cache vérifié ---------------------------
SCANS="$T/var/lib/scanoria/scans"
SCEN="$TMP/scenario"
COMMIT=$(printf 'b27' | sha256sum | cut -c1-40)
GOOD_JAR="contenu de l'extension"
GOOD_KEY=$(printf '%s' "$GOOD_JAR" | sha256sum | cut -c1-64)
cat > "$STUBS/podman" <<EOF
#!/usr/bin/env python3
# Bouchon de podman : récupération et scanners simulés.
import json, os, sys
a = sys.argv[1:]
open("$TMP/podman.log", "a").write(json.dumps(a) + "\n")
scen = open("$SCEN").read().strip()
if a[:2] == ["image", "exists"]:
    sys.exit(0)
if a[:2] == ["network", "exists"] or a[:1] in (["inspect"], ["rm"], ["unshare"], ["ps"]):
    print("false" if a[:1] == ["inspect"] else ""); sys.exit(0)
if a[:1] != ["run"]:
    sys.exit(0)
vols = {}
for i, x in enumerate(a):
    if x == "--volume":
        host, target, mode = a[i + 1].rsplit(":", 2)
        vols[target] = host
ep = json.loads(a[a.index("--entrypoint") + 1])
if ep == ["/bin/sh"]:
    once = "$TMP/once"
    if scen in ("nospace-once", "corrupt-once") and not os.path.exists(once):
        open(once, "w").close()
        print("scanoria=" + ("nospace" if scen == "nospace-once" else "corrupt"))
        sys.exit(75 if scen == "nospace-once" else 74)
    src = vols["/src"]
    for d in ("lib", "node_modules/dep", "img"):
        os.makedirs(os.path.join(src, d), exist_ok=True)
    open(src + "/lib/app.py", "w").write("print(1)\n")
    open(src + "/node_modules/dep/index.js", "w").write("x\n")
    open(src + "/img/logo.png", "w").write("x\n")
    open(src + "/.git", "w").write("gitdir: /git\n")
    print("scanoria=mirror-fetch")
    print("commit=$COMMIT")
    sys.exit(0)
out = vols["/out"]
if "/cache" in vols:
    c = vols["/cache"]
    os.makedirs(c + "/cache/$GOOD_KEY", exist_ok=True)
    open(c + "/cache/$GOOD_KEY/sonar-java.jar", "w").write("$GOOD_JAR")
    os.makedirs(c + "/cache/" + "0" * 32, exist_ok=True)
    open(c + "/cache/" + "0" * 32 + "/piege.jar", "w").write("code planté")
    os.makedirs(c + "/js/node-runtime", exist_ok=True)
    open(c + "/js/node-runtime/node", "w").write("binaire planté")
open(out + "/result.sarif", "w").write(json.dumps({"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "f"}}, "results": []}]}))
sys.exit(0)
EOF
cat > "$STUBS/nft" <<'EOF'
#!/bin/sh
exit 0
EOF
chmod 0755 "$STUBS/podman" "$STUBS/nft"
GIMG="docker.io/exemple/git@sha256:$(printf 'git' | sha256sum | cut -d' ' -f1)"
py "$IMG" "$GIMG" <<'EOF'
import os, sys
sys.path.insert(0, sys.argv[1])
from scanoria import common, feeds, modules
img, gimg = sys.argv[2:4]
def m(mid, image, extra=None, cats=("secrets",), feeds_=()):
    man = {"id": mid, "name": mid, "type": "scanner", "version": "1.0.0", "categories": list(cats),
           "license": {"spdx": "MIT", "restrictions": "none"}, "image": image,
           "resources": {"min_ram_mb": 256, "min_cpu": 1, "disk_mb": 10},
           "requires": {"modules": [], "feeds": list(feeds_)}, "conflicts": [],
           "options": {"type": "object", "additionalProperties": False, "properties": {}},
           "scan": {"inputs": ["repo"], "network": "none", "timeout_s": 60, "exit_codes_ok": [0],
                    "command": ["faux", "/src"]},
           "outputs": {"sarif": {"path": "/out/result.sarif", "version": "2.1.0"}}}
    man["scan"].update(extra or {})
    return {"manifest": man, "status": "healthy", "enabled": True, "options": {}}
common.write_json(modules.REGISTRY, {"modules": {
    "git-fetch": m("git-fetch", gimg, cats=("system",)),
    "base": m("base", img, cats=("sca",), feeds_=("trivy-db",)),
    "histo": m("histo", img, {"history": "full", "history_command": ["faux", "git", "/src"]}),
    "sonarish": m("sonarish", img, {"cache": "sonar-plugins"}),
}, "operations": []})
feeds._dirs()
d = os.path.join(feeds.store_dir("trivy-db"), "20261124T010000Z-0000000a")
os.makedirs(d + "/db")
open(d + "/db/trivy.db", "w").write("v")
feeds.swap("trivy-db", d)
EOF
uuid() { python3 -c 'import uuid; print(uuid.uuid4())'; }
PROJ=44444444-4444-4444-8444-444444444444
job() { # id modules-json [historique]
	jq -cn --arg id "$1" --arg sid "$(uuid)" --arg pid "$PROJ" --argjson mods "$2" --arg h "${3:-shallow}" \
		'{schema: 1, id: $id, scan_id: $sid, project_id: $pid, created_at: "2026-11-24T10:00:00Z",
		  source: {kind: "git", url: "https://forge.exemple.test/exemple/depot.git", ref: "main", history: $h}, modules: $mods}'
}
export SCANORIA_TEST_RESOLVE="forge.exemple.test=192.0.2.10"
run_job() { # scénario modules [historique] → id
	local id; id=$(uuid)
	echo "$1" > "$SCEN"
	rm -f "$TMP/once"
	: > "$TMP/podman.log"
	: > "$T/test-commands.log"
	mkdir -p "$SCANS/jobs/incoming"
	job "$id" "$2" "${3:-shallow}" > "$SCANS/jobs/incoming/$id.json"
	chmod 0600 "$SCANS/jobs/incoming/$id.json"
	"$RUNNER" --once 2> "$TMP/runner.err" || sed 's/^/     /' "$TMP/runner.err" >&2
	echo "$id"
}
echo ok > "$SCEN"
"$RUNNER" --once 2> /dev/null || true
id=$(run_job ok '[{"id": "base", "version": "1.0.0"}, {"id": "histo", "version": "1.0.0"}]' full)
R=$(cat "$SCANS/results/$id/result.json")
expect "runner : analyse réussie" "$(jq -r '[.status] + [.modules[].status] | join(",")' <<< "$R")" ok,ok,ok
expect "runner : miroir du projet utilisé" "$(jq -r .source.mirror <<< "$R")" created
expect "runner : sources en mémoire (8 Go libres)" "$(jq -r .source.workdir <<< "$R")" tmpfs
expect "runner : exclusions notées" "$(jq -c '.source.excluded' <<< "$R")" '[{"pattern":"**/*.png","count":1},{"pattern":"**/node_modules/**","count":1}]'
grep -q '"mount","-t","tmpfs"' "$T/test-commands.log" && grep -q '"umount"' "$T/test-commands.log" &&
	ok "runner : tmpfs monté puis démonté" || ko "runner : tmpfs absent"
grep -F '"mount","-t","tmpfs"' "$T/test-commands.log" | grep -q 'nosuid,nodev,noexec' && ok "runner : tmpfs nosuid, nodev, noexec" || ko "runner : options du tmpfs"
runs=$(grep '^\["run"' "$TMP/podman.log")
[[ $(grep -c . <<< "$runs") -eq 3 ]] && ! grep -v -q -- '--pull=never' <<< "$runs" && ok "V1 : chaque conteneur avec --pull=never" || ko "V1 : --pull=never manquant"
scan=$(grep '"--name", "scanoria-scan-' <<< "$runs")
grep -F -- "/src:ro" <<< "$scan" | grep -q . && ! grep -F '/src:rw' <<< "$scan" | grep -q . && ok "montage : /src en lecture seule" || ko "montage : /src écrivable"
grep -F -- 'feeds/.store/trivy-db/20261124T010000Z-0000000a:/feeds/trivy-db:ro' <<< "$scan" | grep -q . && ok "montage : base épinglée en lecture seule (V7)" || ko "montage : base non épinglée"
grep -F -- '.git:/mirror:ro' <<< "$scan" | grep -q . && ok "montage : miroir en lecture seule pour l'historique" || ko "montage : miroir absent ou écrivable"
expect "montage : miroir seulement pour le module à historique" "$(grep -cF ':/mirror:ro' <<< "$scan")" 1
sca=$(grep -v '"git"' <<< "$scan")
histo=$(grep '"git"' <<< "$scan")
grep -qF -- 'mask-dir:/src/node_modules:ro' <<< "$sca" && grep -qF -- 'mask-file:/src/img/logo.png:ro' <<< "$sca" &&
	ok "V9 : exclusions masquées pour un module SCA" || ko "V9 : exclusions non masquées pour un module SCA"
! grep -qF -- 'mask-' <<< "$histo" && ok "V9 : module secrets, arbre entier" || ko "V9 : module secrets privé d'une partie de l'arbre"
grep '"--name", "scanoria-fetch-' <<< "$runs" | grep -qF -- "$PROJ.git:/mirror:rw" && ok "récupération : miroir du projet monté" || ko "récupération : miroir du projet absent"
grep '"--name", "scanoria-fetch-' <<< "$runs" | grep -q -- '"--memory", "2048m"' && ok "récupération : mémoire augmentée du tmpfs" || ko "récupération : mémoire du tmpfs non comptée"
expect "bail : rendu en fin d'analyse" "$(find "$T/var/lib/scanoria/feeds/.store/trivy-db/.leases" -type f 2> /dev/null | wc -l | tr -d ' ')" 0
expect "espace de travail supprimé" "$(find "$SCANS/workspaces" -mindepth 1 -maxdepth 1 | wc -l | tr -d ' ')" 0
expect "taille de l'arbre notée pour le projet" "$(jq -r '.last_tree_bytes > 0' "$T/var/lib/scanoria/git-mirrors/$PROJ.json")" true

# Arbre trop gros pour le tmpfs : reprise sur disque, sans nouvelle erreur.
rm -f "$T/var/lib/scanoria/git-mirrors/$PROJ.json"
id=$(run_job nospace-once '[{"id": "base", "version": "1.0.0"}]')
R=$(cat "$SCANS/results/$id/result.json")
expect "tmpfs plein : analyse réussie sur disque" "$(jq -r '.status + "/" + .source.workdir' <<< "$R")" ok/disk
expect "tmpfs plein : deux passages de récupération" "$(grep -c '"--name", "scanoria-fetch-' "$TMP/podman.log")" 2
# Miroir corrompu : recréé, puis récupération réussie.
id=$(run_job corrupt-once '[{"id": "base", "version": "1.0.0"}]')
R=$(cat "$SCANS/results/$id/result.json")
expect "miroir corrompu : recréé puis réussi" "$(jq -r '.status + "/" + .source.mirror' <<< "$R")" ok/created
# RAM libre insuffisante : sur disque d'emblée.
printf 'MemTotal:       4096000 kB\nMemAvailable:    1500000 kB\n' > "$T/proc/meminfo"
id=$(run_job ok '[{"id": "base", "version": "1.0.0"}]')
expect "4 Go, 1,5 Go libres : sur disque" "$(jq -r .source.workdir "$SCANS/results/$id/result.json")" disk
grep -q '"mount"' "$T/test-commands.log" && ko "4 Go : tmpfs monté quand même" || ok "4 Go : aucun tmpfs"
printf 'MemTotal:       16384000 kB\nMemAvailable:    8192000 kB\n' > "$T/proc/meminfo"

# V10 : cache du projet, seules les extensions vérifiées restent.
id=$(run_job ok '[{"id": "sonarish", "version": "1.0.0"}]')
C="$T/var/lib/scanoria/scan-cache/sonarish/$PROJ"
expect "cache : analyse réussie" "$(jq -r '.modules[0].status' "$SCANS/results/$id/result.json")" ok
grep '"--name", "scanoria-scan-' "$TMP/podman.log" | grep -qF -- "$PROJ:/cache:rw" && ok "cache : monté pour le projet" || ko "cache : non monté"
grep '"--name", "scanoria-scan-' "$TMP/podman.log" | grep -qF 'SCANORIA_CACHE_DIR=/cache' && ok "cache : variable transmise" || ko "cache : variable absente"
[[ -f "$C/cache/$GOOD_KEY/sonar-java.jar" ]] && ok "cache : extension vérifiée gardée" || ko "cache : extension vérifiée retirée"
[[ ! -e "$C/cache/00000000000000000000000000000000" ]] && ok "cache : extension à empreinte fausse retirée" || ko "cache : extension plantée gardée"
[[ ! -e "$C/js" ]] && ok "cache : exécutable hors politique retiré" || ko "cache : exécutable planté gardé"
run_job ok '[{"id": "base", "version": "1.0.0"}]' > /dev/null
grep -qF ':/cache:' "$TMP/podman.log" && ko "cache : monté pour un module sans scan.cache" || ok "cache : seulement pour scan.cache"

# Purge des projets supprimés par le runner (liste du worker dans jobs/tmp).
printf '{"schema": 1, "projects": []}' > "$SCANS/jobs/tmp/live-projects.json"
py <<'EOF' | report
import os, sys
sys.path.insert(0, sys.argv[1])
from scanoria import runner, gitmirror
pid = "44444444-4444-4444-8444-444444444444"
m = gitmirror.read_meta(pid); m["used_at"] = "2026-01-01T00:00:00Z"; gitmirror.write_meta(pid, m)
runner.purge_projects()
print(("ok " if not os.path.exists(gitmirror.path_of(pid)) else "ko ") + "purge : miroir du projet supprimé retiré")
print(("ok " if not os.path.exists(os.path.join(runner.SCAN_CACHE, "sonarish", pid)) else "ko ") + "purge : cache du projet supprimé retiré")
EOF

PASS=$(grep -c '^+' "$TMP/tally" || true)
FAIL=$(grep -c '^-' "$TMP/tally" || true)
echo
echo "b27 : $PASS réussis, $FAIL échoués"
[[ $FAIL -eq 0 ]]
