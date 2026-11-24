#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Vincent Tisseront
#
# b14 — scanoria-runner (ARCHITECTURE § 12, CLAUDE.md § 6.4), sans root. Le
# runner tourne en mode test (SCANORIA_TEST_ROOT) ; podman et nft sont des
# bouchons qui simulent le clone, les scanners et le cgroup du conteneur.
# Couvre : tâches hostiles (propriétaire, mode, lien, taille, JSON piégé, champ
# imposé, URL file:// et ext::, ref --upload-pack, nom invalide), module non
# installé ou hors schéma d'options, clone confiné (réseau dédié, règle nftables
# posée puis retirée, jeton hors de l'argv, du journal et de result.json),
# historique complet, archive piégée (« .. », liens, fichiers spéciaux), bornes
# de taille, classes d'erreur (infra, tool, input), mesures, redémarrage,
# purge, capacité, espace de travail supprimé, résultats conformes au schéma.
# Dépendances : bash, python3, jq, tar.

# shellcheck disable=SC2016,SC2015
set -euo pipefail
export PYTHONDONTWRITEBYTECODE=1

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
RUNNER="$ROOT/src/rootfs/usr/sbin/scanoria-runner"
PYLIB="$ROOT/src/rootfs/usr/lib/scanoria/py"
TMP=$(mktemp -d)
trap 'chmod -R u+rwX "$TMP" 2> /dev/null; rm -rf "$TMP"' EXIT

PASS=0
FAIL=0
ok() { PASS=$((PASS + 1)); printf 'ok   %s\n' "$1"; }
ko() { FAIL=$((FAIL + 1)); printf 'FAIL %s\n' "$1"; }
expect() { # libellé valeur_obtenue valeur_attendue
	if [[ "$2" == "$3" ]]; then ok "$1"; else ko "$1 (obtenu « $2 », attendu « $3 »)"; fi
}
for t in python3 jq tar; do command -v "$t" > /dev/null || { echo "outil manquant : $t" >&2; exit 2; }; done

T="$TMP/root"
STUBS="$TMP/stubs"
SCANS="$T/var/lib/scanoria/scans"
mkdir -p "$T/var/lib/scanoria/modules" "$T/var/lib/scanoria/uploads" "$T/run/scanoria" "$T/proc" \
	"$T/sys/fs/cgroup/fake.scope/container" "$T/etc/ssl/certs" "$STUBS"
export SCANORIA_TEST_ROOT="$T" SCANORIA_TEST_BIN="$STUBS"
export SCANORIA_TEST_RESOLVE="forge.exemple.test=192.0.2.10;boucle.exemple.test=127.0.0.1;meta.exemple.test=169.254.169.254"
unset SCANORIA_TEST_OWNER_UID SCANORIA_SCANS_DIR SCANORIA_RUNNER_STATE
printf 'MemTotal:       16384000 kB\n' > "$T/proc/meminfo"
for i in 0 1 2 3; do printf 'processor\t: %d\n' "$i"; done > "$T/proc/cpuinfo"
echo "52428800" > "$T/sys/fs/cgroup/fake.scope/container/memory.peak"
printf 'usage_usec 1234000\nuser_usec 1000000\n' > "$T/sys/fs/cgroup/fake.scope/container/cpu.stat"
echo "AC de test" > "$T/etc/ssl/certs/ca-certificates.crt"

# Jeton de test : forme manifestement fausse, générée à l'exécution (jamais dans le dépôt).
TOKEN="scn_$(head -c 64 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 40)"
COMMIT=$(printf 'b14' | sha1sum | cut -d' ' -f1)
SCEN="$TMP/scenario"
echo ok > "$SCEN"

# --- Bouchons ------------------------------------------------------------------------------
cat > "$STUBS/podman" <<EOF
#!/usr/bin/env python3
# Bouchon de podman : journal des arguments, clone et scanners simulés.
import json, os, sys, time
a = sys.argv[1:]
with open("$TMP/podman.log", "a") as f:
    f.write(json.dumps(a) + "\n")
scen = open("$SCEN").read().strip()
if a[:2] == ["image", "exists"]:
    sys.exit(1 if "absent" in a[2] else 0)
if a[:2] == ["network", "exists"]:
    sys.exit(0 if os.path.exists("$TMP/net") else 1)
if a[:2] == ["network", "create"]:
    open("$TMP/net", "w").close(); sys.exit(0)
if a[:1] == ["inspect"]:
    fmt = a[a.index("--format") + 1]
    print("/fake.scope" if "Cgroup" in fmt else ("true" if scen == "scan-oom-flag" else "false"))
    sys.exit(0)
if a[:1] == ["ps"]:
    print("0123456789ab" if scen == "orphans" else ""); sys.exit(0)
if a[:1] in (["rm"], ["unshare"], ["kill"]):
    sys.exit(0)
if a[:1] != ["run"]:
    sys.exit(0)
vols = {}
for i, x in enumerate(a):
    if x == "--volume":
        host, target, mode = a[i + 1].rsplit(":", 2)
        vols[target] = host
ep = json.loads(a[a.index("--entrypoint") + 1])
img_i = a.index("--entrypoint") + 2
image, rest = a[img_i], a[img_i + 1:]
if ep == ["/bin/sh"]:   # git-fetch
    print("remote: echo " + os.environ.get("SCANORIA_GIT_TOKEN", "-"), file=sys.stderr)
    if scen == "fetch-auth":
        print("fatal: Authentication failed for 'https://forge.exemple.test/'", file=sys.stderr); sys.exit(128)
    if scen == "fetch-slow":
        time.sleep(30)
    src = vols["/src"]
    os.makedirs(src + "/lib", exist_ok=True)
    open(src + "/.git", "w").write("gitdir: /git\n")
    open(src + "/README.md", "w").write("projet\n")
    open(src + "/lib/app.py", "w").write("print(1)\n")
    with open(src + "/gros.bin", "wb") as f:
        f.truncate(101 << 20)
    os.mkfifo(src + "/tube")
    print("depth=" + rest[-1])
    print("commit=$COMMIT")
    sys.exit(0)
# scanner
out = vols["/out"]
print("scan de /src avec " + os.environ.get("SCANORIA_GIT_TOKEN", "aucun jeton"))
print("valeur trouvée : $TOKEN")
open("$TMP/last-cmd", "w").write(json.dumps([ep[0]] + rest))
if scen == "scan-exit3":
    sys.exit(3)
if scen == "scan-oom":
    sys.exit(137)
if scen == "scan-oom-flag":
    sys.exit(1)
if scen == "scan-nooutput":
    sys.exit(0)
data = "pas du JSON" if scen == "scan-invalid" else json.dumps({"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "faux"}}, "results": [{"ruleId": "r1", "message": {"text": "m"}}]}]})
if scen == "scan-symlink":
    os.symlink("/etc/passwd", out + "/result.sarif")
else:
    open(out + "/result.sarif", "w").write(data)
sys.exit(0)
EOF
cat > "$STUBS/nft" <<EOF
#!/usr/bin/env python3
import json, os, sys
a = sys.argv[1:]
data = sys.stdin.read() if a[:2] == ["-f", "-"] else ""
with open("$TMP/nft.log", "a") as f:
    f.write(json.dumps(a + ([data] if data else [])) + "\n")
sys.exit(1 if a[:1] == ["list"] and not os.path.exists("$TMP/nft-table") else 0)
EOF
chmod 0755 "$STUBS/podman" "$STUBS/nft"

# --- Registre des modules ------------------------------------------------------------------
IMG="ghcr.io/exemple/faux@sha256:$(printf 'faux' | sha256sum | cut -d' ' -f1)"
GIMG="docker.io/exemple/git@sha256:$(printf 'git' | sha256sum | cut -d' ' -f1)"
python3 - "$T/var/lib/scanoria/modules/installed.json" "$IMG" "$GIMG" <<'EOF'
import json, sys
path, img, gimg = sys.argv[1:4]
def m(mid, image, extra=None, cats=("secrets",), status="healthy", enabled=True):
    man = {"id": mid, "name": mid, "type": "scanner", "version": "1.0.0", "categories": list(cats),
           "license": {"spdx": "MIT", "restrictions": "none"}, "image": image,
           "resources": {"min_ram_mb": 256, "min_cpu": 1, "disk_mb": 10},
           "requires": {"modules": ["git-fetch"], "feeds": []}, "conflicts": [],
           "options": {"type": "object", "additionalProperties": False, "properties": {
               "seuil": {"type": "integer", "default": 10, "minimum": 1, "maximum": 100},
               "history": {"type": "boolean", "default": True}}},
           "scan": {"inputs": ["repo", "archive"], "network": "none", "timeout_s": 60, "exit_codes_ok": [0, 1],
                    "command": ["faux", "dir", "/src", "--seuil", "{opt.seuil}", "--out", "/out/result.sarif"]},
           "outputs": {"sarif": {"path": "/out/result.sarif", "version": "2.1.0"}}}
    if extra:
        man["scan"].update(extra)
    return {"manifest": man, "status": status, "enabled": enabled, "options": {}}
reg = {"modules": {
    "faux": m("faux", img),
    "histo": m("histo", img, {"history": "full", "history_command": ["faux", "git", "/src", "--out", "/out/result.sarif"]}),
    "absent-img": m("absent-img", img.replace("exemple/faux", "exemple/absent")),
    "eteint": m("eteint", img, enabled=False),
    "git-fetch": m("git-fetch", gimg, cats=("system",)),
}, "operations": []}
reg["modules"]["git-fetch"]["manifest"]["requires"]["modules"] = []
json.dump(reg, open(path, "w"))
EOF

# --- Outils --------------------------------------------------------------------------------
uuid() { python3 -c 'import uuid; print(uuid.uuid4())'; }
# job ID [source-json] [modules-json] [extra-jq]
job() {
	local id=$1 src=${2:-} mods=${3:-}
	[[ -n "$src" ]] || src=$(jq -cn --arg t "$TOKEN" '{kind: "git", url: "https://forge.exemple.test/exemple/depot.git", ref: "main", history: "shallow", credential: {kind: "token", token: $t}}')
	[[ -n "$mods" ]] || mods='[{"id": "faux", "version": "1.0.0"}]'
	jq -cn --arg id "$id" --arg sid "$(uuid)" --argjson src "$src" --argjson mods "$mods" \
		'{schema: 1, id: $id, scan_id: $sid, created_at: "2026-11-24T10:00:00Z", source: $src, modules: $mods}'
}
drop() { # ID contenu [mode]
	printf '%s' "$2" > "$SCANS/jobs/incoming/$1.json"
	chmod "${3:-0600}" "$SCANS/jobs/incoming/$1.json"
}
run_runner() { "$RUNNER" --once 2> "$TMP/runner.err" || { echo "runner : code $?"; sed 's/^/     /' "$TMP/runner.err"; }; }
res() { cat "$SCANS/results/$1/result.json" 2> /dev/null || echo '{}'; }
valid() { # ID : result.json conforme à scan-result.schema.json
	python3 -I -B -c 'import json, sys; sys.path.insert(0, sys.argv[1]); from scanoria import schema
errs = schema.load("schemas", "scan-result").errors(json.load(open(sys.argv[2])))
print("; ".join(errs[:3])); sys.exit(1 if errs else 0)' "$PYLIB" "$SCANS/results/$1/result.json"
}

# --- 1. Démarrage : arborescence et capacité -----------------------------------------------
run_runner
for d in jobs/tmp jobs/incoming jobs/work results workspaces; do
	[[ -d "$SCANS/$d" ]] && ok "arborescence : $d" || ko "arborescence : $d absent"
done
expect "jobs/work 0700" "$(stat -c %a "$SCANS/jobs/work")" 700
expect "jobs/incoming 0700" "$(stat -c %a "$SCANS/jobs/incoming")" 700
expect "results 0750" "$(stat -c %a "$SCANS/results")" 750
expect "capacité publiée (16 Go, 4 CPU → 4 places)" "$(jq -c '{slots, busy}' "$T/run/scanoria/runner.json")" '{"slots":4,"busy":0}'
expect "runner.json 0640" "$(stat -c %a "$T/run/scanoria/runner.json")" 640

# --- 2. Tâches hostiles --------------------------------------------------------------------
hostile() { # libellé ID contenu mode motif-du-message
	drop "$2" "$3" "$4"
	run_runner
	local r; r=$(res "$2")
	expect "hostile : $1 → E_JOB_INVALID (input)" "$(jq -r '.error.code + "/" + .error.class' <<< "$r")" "E_JOB_INVALID/input"
	if jq -r .error.message <<< "$r" | grep -qF -- "$5"; then ok "hostile : $1 : motif « $5 »"; else ko "hostile : $1 : motif absent ($(jq -r .error.message <<< "$r"))"; fi
	[[ -e "$SCANS/jobs/incoming/$2.json" || -e "$SCANS/jobs/work/$2.json" ]] && ko "hostile : $1 : fichier laissé" || ok "hostile : $1 : fichier supprimé"
	valid "$2" > /dev/null && ok "hostile : $1 : résultat conforme" || ko "hostile : $1 : résultat non conforme"
}
id=$(uuid); hostile "mode 0644" "$id" "$(job "$id")" 0644 "0600"
id=$(uuid); SCANORIA_TEST_OWNER_UID=4242 hostile "propriétaire autre que scanoria" "$id" "$(job "$id")" 0600 "owned by scanoria"
id=$(uuid); hostile "JSON à clé dupliquée" "$id" '{"schema": 1, "schema": 1}' 0600 "valid JSON"
id=$(uuid); hostile "JSON trop imbriqué" "$id" "$(printf '[%.0s' $(seq 1 40))" 0600 "valid JSON"
id=$(uuid); hostile "taille > 256 Kio" "$id" "$(head -c 300000 /dev/zero | tr '\0' ' ')" 0600 "too large"
id=$(uuid); hostile "image imposée par la tâche" "$id" "$(job "$id" "" '[{"id": "faux", "version": "1.0.0", "image": "docker.io/exemple/pirate:latest"}]')" 0600 "schema"
id=$(uuid); hostile "URL file://" "$id" "$(job "$id" '{"kind": "git", "url": "file:///etc", "ref": "main", "history": "shallow"}')" 0600 "schema"
id=$(uuid); hostile "URL ext::" "$id" "$(job "$id" '{"kind": "git", "url": "ext::sh -c touch% /tmp/pwn", "ref": "main", "history": "shallow"}')" 0600 "schema"
id=$(uuid); hostile "ref --upload-pack" "$id" "$(job "$id" '{"kind": "git", "url": "https://forge.exemple.test/a.git", "ref": "--upload-pack=touch /tmp/pwn", "history": "shallow"}')" 0600 "schema"
id=$(uuid); hostile "identifiant ≠ nom du fichier" "$id" "$(job "$(uuid)")" 0600 "differs"
# Lien symbolique vers un fichier sensible : jamais lu ni supprimé.
id=$(uuid)
echo "contenu sensible" > "$TMP/cible"
ln -s "$TMP/cible" "$SCANS/jobs/incoming/$id.json"
run_runner
expect "hostile : lien symbolique → E_JOB_INVALID" "$(res "$id" | jq -r .error.code)" E_JOB_INVALID
expect "hostile : cible du lien intacte" "$(cat "$TMP/cible")" "contenu sensible"
# Nom invalide : supprimé, sans résultat.
printf '{}' > "$SCANS/jobs/incoming/pas-une-tache.json"
run_runner
expect "nom invalide : fichier supprimé" "$(find "$SCANS/jobs/incoming" -type f | wc -l)" 0

# --- 3. Analyse Git complète ---------------------------------------------------------------
: > "$TMP/podman.log"
id=$(uuid)
drop "$id" "$(job "$id" "" '[{"id": "faux", "version": "1.0.0", "options": {"seuil": 42}}, {"id": "inconnu", "version": "1.0.0"}, {"id": "eteint", "version": "1.0.0"}, {"id": "faux", "version": "9.9.9"}]')"
run_runner
R=$(res "$id")
valid "$id" && ok "git : résultat conforme au schéma" || ko "git : résultat non conforme"
expect "git : statut ok" "$(jq -r .status <<< "$R")" ok
expect "git : commit relevé" "$(jq -r .source.commit <<< "$R")" "$COMMIT"
expect "git : historique superficiel" "$(jq -r .source.history <<< "$R")" shallow
expect "git : profondeur 1 demandée au clone" "$(grep '"--name", "scanoria-fetch-' "$TMP/podman.log" | head -n 1 | jq -r '.[-1]')" 1
expect "git : fichiers comptés (hors .git, gros fichier et tube écartés)" "$(jq -c '.source | {files, skipped: [.skipped[] | .reason] | sort}' <<< "$R")" '{"files":2,"skipped":["size","special"]}'
expect "git : module faux ok" "$(jq -r '.modules[0].status' <<< "$R")" ok
expect "git : sortie SARIF publiée" "$(jq -r '.modules[0].outputs.sarif' <<< "$R")" "faux/result.sarif"
[[ -f "$SCANS/results/$id/faux/result.sarif" ]] && ok "git : fichier SARIF présent" || ko "git : fichier SARIF absent"
expect "git : sortie 0640" "$(stat -c %a "$SCANS/results/$id/faux/result.sarif")" 640
expect "git : option de la tâche substituée ({opt.seuil} → 42)" "$(jq -c . "$TMP/last-cmd")" '["faux","dir","/src","--seuil","42","--out","/out/result.sarif"]'
expect "git : empreinte d'image" "$(jq -r '.modules[0].image_digest' <<< "$R")" "${IMG#*@}"
expect "git : mesures (pic 50 Mo, CPU 1234 ms)" "$(jq -c '.modules[0].stats | {peak_memory_mb, cpu_ms}' <<< "$R")" '{"peak_memory_mb":50,"cpu_ms":1234}'
jq -e '.modules[0].stats.duration_ms >= 0' <<< "$R" > /dev/null && ok "git : durée mesurée" || ko "git : durée absente"
expect "git : module inconnu → missing (input)" "$(jq -r '.modules[1] | .status + "/" + .error.class' <<< "$R")" "missing/input"
expect "git : module désactivé → missing" "$(jq -r '.modules[2].status' <<< "$R")" missing
expect "git : autre version → missing" "$(jq -r '.modules[3].status' <<< "$R")" missing
expect "git : journal du module publié" "$(jq -r '.modules[0].log' <<< "$R")" "faux/module.log"
grep -q "valeur trouvée : \*\*\*" "$SCANS/results/$id/faux/module.log" && ok "git : jeton masqué dans le journal" || ko "git : jeton non masqué"
if grep -rqF -- "$TOKEN" "$SCANS/results/$id"; then ko "git : jeton présent dans les résultats"; else ok "git : jeton absent des résultats et de result.json"; fi
if grep -qF -- "$TOKEN" "$TMP/podman.log"; then ko "git : jeton dans l'argv de podman"; else ok "git : jeton absent de l'argv de podman"; fi
F=$(grep '"--name", "scanoria-fetch-' "$TMP/podman.log" | head -n 1)
S=$(grep '"faux", "dir"\|"--seuil"' "$TMP/podman.log" | grep '"run"' | head -n 1)
for want in '"--network", "scanoria-fetch"' '"--dns=none"' '"--add-host", "forge.exemple.test:192.0.2.10"' '"--cap-drop=ALL"' '"--read-only"' '"--env", "SCANORIA_GIT_TOKEN"' 'GIT_CONFIG_NOSYSTEM=1' 'core.hooksPath' 'protocol.allow' 'core.symlinks'; do
	grep -qF -- "$want" <<< "$F" && ok "clone confiné : $want" || ko "clone confiné : $want absent"
done
grep -qF -- '"--network=none"' <<< "$F" && ko "clone : --network=none non remplacé" || ok "clone : réseau dédié seulement"
for want in '"--network=none"' '"--read-only"' '"--cap-drop=ALL"' '"--security-opt=no-new-privileges"' '"65534:65534"' ':/src:ro"' ':/out:rw"' '"--pids-limit"' '"--memory"'; do
	grep -qF -- "$want" <<< "$S" && ok "scanner confiné : $want" || ko "scanner confiné : $want absent"
done
grep -qF -- ':/git:ro' <<< "$S" && ko "scanner sans historique : /git monté à tort" || ok "scanner sans historique : /git non monté"
grep -q '"add", "element", "inet", "scanoria_fetch", "allow4", "{ 10.89.250.10 . 192.0.2.10 . 443 }"' "$TMP/nft.log" \
	&& ok "nftables : sortie ouverte vers la forge (conteneur . forge . 443)" || ko "nftables : élément non ajouté"
grep -q '"delete", "element", "inet", "scanoria_fetch", "allow4", "{ 10.89.250.10 . 192.0.2.10 . 443 }"' "$TMP/nft.log" \
	&& ok "nftables : sortie refermée après le clone" || ko "nftables : élément non retiré"
grep -q 'ip saddr 10.89.250.0/24 drop' "$TMP/nft.log" && ok "nftables : table chargée, sous-réseau substitué" || ko "nftables : table non chargée"
expect "espace de travail supprimé" "$(find "$SCANS/workspaces" -mindepth 1 | wc -l)" 0
expect "marqueur de tâche retiré" "$(find "$SCANS/jobs/work" -mindepth 1 | wc -l)" 0

# --- 4. Historique complet -----------------------------------------------------------------
: > "$TMP/podman.log"
id=$(uuid)
drop "$id" "$(job "$id" "" '[{"id": "histo", "version": "1.0.0"}]')"
run_runner
R=$(res "$id")
expect "historique : clone complet" "$(jq -r .source.history <<< "$R")" full
grep '"--name", "scanoria-fetch-' "$TMP/podman.log" | head -n 1 | jq -e '.[-1] == ""' > /dev/null && ok "historique : aucune profondeur" || ko "historique : profondeur imposée"
expect "historique : history_command lancée" "$(jq -c . "$TMP/last-cmd")" '["faux","git","/src","--out","/out/result.sarif"]'
grep '"--name", "scanoria-scan-' "$TMP/podman.log" | grep -qF ':/git:ro' && ok "historique : dépôt Git monté en lecture seule sur /git" || ko "historique : /git non monté"
id=$(uuid)
drop "$id" "$(job "$id" "" '[{"id": "histo", "version": "1.0.0", "options": {"history": false}}]')"
run_runner
expect "historique : option history=false → clone superficiel" "$(res "$id" | jq -r .source.history)" shallow
expect "historique : option history=false → command" "$(jq -r '.[1]' "$TMP/last-cmd")" dir

# --- 5. Options et modules hors plan -------------------------------------------------------
id=$(uuid)
drop "$id" "$(job "$id" "" '[{"id": "faux", "version": "1.0.0", "options": {"seuil": 1000}}, {"id": "faux", "version": "1.0.0", "options": {"pirate": "x"}}, {"id": "git-fetch", "version": "1.0.0"}]')"
run_runner
R=$(res "$id")
expect "options hors bornes → E_OPTIONS_INVALID (input)" "$(jq -r '.modules[0] | .status + "/" + .error.code + "/" + .error.class' <<< "$R")" "error/E_OPTIONS_INVALID/input"
expect "option inconnue → E_OPTIONS_INVALID" "$(jq -r '.modules[1].error.code' <<< "$R")" E_OPTIONS_INVALID
expect "module système dans une tâche → refusé" "$(jq -r '.modules[2].status' <<< "$R")" missing
expect "aucun module exécutable : pas de clone" "$(jq -r .source.commit <<< "$R")" null

# --- 6. Classes d'erreur -------------------------------------------------------------------
err_case() { # scénario libellé module statut code classe
	echo "$1" > "$SCEN"
	local id; id=$(uuid)
	drop "$id" "$(job "$id" "" "[{\"id\": \"$3\", \"version\": \"1.0.0\"}]")"
	run_runner
	expect "erreur : $2" "$(res "$id" | jq -r '.modules[0] | .status + "/" + .error.code + "/" + .error.class')" "$4/$5/$6"
	valid "$id" > /dev/null && ok "erreur : $2 : résultat conforme" || ko "erreur : $2 : résultat non conforme"
	echo ok > "$SCEN"
}
err_case scan-exit3 "code de sortie inattendu" faux error E_TOOL_EXIT tool
err_case scan-oom "mémoire (137)" faux oom E_MODULE_OOM infra
err_case scan-oom-flag "mémoire (OOMKilled)" faux oom E_MODULE_OOM infra
err_case scan-invalid "sortie invalide" faux invalid-output E_INVALID_OUTPUT tool
err_case scan-nooutput "sortie absente" faux invalid-output E_INVALID_OUTPUT tool
err_case scan-symlink "sortie en lien symbolique" faux invalid-output E_INVALID_OUTPUT tool
err_case ok "image absente" absent-img error E_IMAGE_MISSING infra
echo fetch-auth > "$SCEN"
id=$(uuid)
drop "$id" "$(job "$id")"
run_runner
R=$(res "$id")
expect "clone refusé : E_SOURCE_AUTH (input), tâche en erreur" "$(jq -r '.status + "/" + .error.code + "/" + .error.class' <<< "$R")" "error/E_SOURCE_AUTH/input"
expect "clone refusé : modules sautés" "$(jq -r '.modules[0].status' <<< "$R")" skipped
[[ -f "$SCANS/results/$id/fetch.log" ]] && ok "clone refusé : journal du clone publié" || ko "clone refusé : fetch.log absent"
if grep -qF -- "$TOKEN" "$SCANS/results/$id/fetch.log"; then ko "clone refusé : jeton dans fetch.log"; else ok "clone refusé : jeton masqué dans fetch.log"; fi
grep -q '"delete", "element"' "$TMP/nft.log" && ok "clone refusé : règle retirée" || ko "clone refusé : règle laissée"
# Jeton très court : masqué lui aussi.
id=$(uuid)
drop "$id" "$(job "$id" '{"kind": "git", "url": "https://forge.exemple.test/a.git", "ref": "main", "history": "shallow", "credential": {"kind": "token", "token": "q7z"}}')"
run_runner
if grep -qF -- "q7z" "$SCANS/results/$id/fetch.log"; then ko "jeton de 3 caractères : présent dans fetch.log"; else ok "jeton de 3 caractères : masqué dans fetch.log"; fi
echo ok > "$SCEN"
addr_case() { # hôte code
	local id; id=$(uuid)
	drop "$id" "$(job "$id" "{\"kind\": \"git\", \"url\": \"https://$1/a.git\", \"ref\": \"main\", \"history\": \"shallow\"}")"
	run_runner
	expect "adresse de forge interdite : $1 → $2" "$(res "$id" | jq -r '.error.code + "/" + .error.class')" "$2"
}
addr_case boucle.exemple.test E_SOURCE_ADDRESS/input
addr_case meta.exemple.test E_SOURCE_ADDRESS/input
addr_case 10.89.250.7 E_SOURCE_ADDRESS/input
addr_case inconnu.exemple.test E_SOURCE_RESOLVE/infra
# Forge sur l'appliance elle-même : seul le proxy inverse (443) est joignable.
export SCANORIA_TEST_LOCAL_ADDRS=192.0.2.10
addr_case forge.exemple.test:8443 E_SOURCE_ADDRESS/input
id=$(uuid); drop "$id" "$(job "$id")"; run_runner
expect "forge sur l'appliance, port 443 : acceptée" "$(res "$id" | jq -r .status)" ok
unset SCANORIA_TEST_LOCAL_ADDRS
# Espace disque insuffisant : refus à l'admission, sans clone.
: > "$TMP/podman.log"
id=$(uuid); drop "$id" "$(job "$id")"; SCANORIA_TEST_FREE_MB=100 run_runner
expect "disque plein : E_DISK_FULL (infra)" "$(res "$id" | jq -r '.error.code + "/" + .error.class')" "E_DISK_FULL/infra"
grep -q 'scanoria-fetch-' "$TMP/podman.log" && ko "disque plein : clone lancé" || ok "disque plein : aucun clone"
# Bornes de stockage d'une récupération en cours.
python3 -I -B - "$PYLIB" "$TMP/ws" <<'PY' && ok "stockage : dépôt trop gros et disque plein arrêtent la récupération" || ko "stockage : bornes non appliquées"
import os, sys
sys.path.insert(0, sys.argv[1])
from scanoria import fetch
os.makedirs(sys.argv[2] + "/git")
with open(sys.argv[2] + "/git/pack", "wb") as f:
    f.write(b"x" * 65536)
assert fetch.storage_check(sys.argv[2]) is None
fetch.MAX_CLONE_BYTES = 1024
assert fetch.storage_check(sys.argv[2]).code == "E_SOURCE_TOO_LARGE"
os.environ["SCANORIA_TEST_FREE_MB"] = "1"
assert fetch.storage_check(sys.argv[2]).code == "E_DISK_FULL"
PY
# Doublon d'une tâche en cours : écarté sans toucher à l'original ni publier.
id=$(uuid)
printf '{"id": "%s"}' "$id" > "$SCANS/jobs/work/$id.running"
mkdir -p "$SCANS/workspaces/$id"
python3 -I -B - "$PYLIB" "$id" "$(job "$id")" <<'PY' && ok "doublon en cours : écarté, original intact, aucun résultat" || ko "doublon en cours : mal traité"
import os, sys
sys.path.insert(0, sys.argv[1])
from scanoria import runner
p = os.path.join(runner.INCOMING, sys.argv[2] + ".json")
fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
os.write(fd, sys.argv[3].encode()); os.close(fd)
r = runner.Runner(); r.slots = 4
assert r.tick([]) == 0
assert not os.path.exists(p)
assert os.path.exists(runner.marker_path(sys.argv[2]))
assert os.path.isdir(os.path.join(runner.WORKSPACES, sys.argv[2]))
assert not os.path.exists(os.path.join(runner.RESULTS, sys.argv[2]))
PY
rm -rf "$SCANS/jobs/work/$id.running" "$SCANS/workspaces/$id"
# Doublon d'une tâche terminée : écarté, résultat inchangé.
id=$(uuid); drop "$id" "$(job "$id")"; run_runner
before=$(sha256sum < "$SCANS/results/$id/result.json")
drop "$id" "$(job "$id" "" '[{"id": "inconnu", "version": "1.0.0"}]')"; run_runner
expect "doublon terminé : résultat inchangé" "$(sha256sum < "$SCANS/results/$id/result.json")" "$before"
[[ -e "$SCANS/jobs/incoming/$id.json" ]] && ko "doublon terminé : fichier laissé" || ok "doublon terminé : fichier supprimé"
mv "$T/var/lib/scanoria/modules/installed.json" "$TMP/reg.json"
jq '.modules["git-fetch"].enabled = false' "$TMP/reg.json" > "$T/var/lib/scanoria/modules/installed.json"
id=$(uuid); drop "$id" "$(job "$id")"; run_runner
expect "git-fetch désactivé : E_FETCH_MODULE_MISSING" "$(res "$id" | jq -r .error.code)" E_FETCH_MODULE_MISSING
mv "$TMP/reg.json" "$T/var/lib/scanoria/modules/installed.json"

# --- 7. Archives téléversées ---------------------------------------------------------------
mkarch() { # upload_id script-python
	mkdir -p "$T/var/lib/scanoria/uploads/$1"
	python3 -c "$2" "$T/var/lib/scanoria/uploads/$1"
}
arch_job() { # upload_id
	local id; id=$(uuid)
	drop "$id" "$(job "$id" "{\"kind\": \"archive\", \"upload_id\": \"$1\"}")"
	run_runner
	res "$id"
}
up=$(uuid)
mkarch "$up" 'import io, sys, tarfile
t = tarfile.open(sys.argv[1] + "/source.tar.gz", "w:gz")
def add(name, data=b"x", **kw):
    i = tarfile.TarInfo(name); i.size = len(data); [setattr(i, k, v) for k, v in kw.items()]
    t.addfile(i, io.BytesIO(data) if i.isreg() else None)
add("./", type=tarfile.DIRTYPE, size=0)
add("./src/app.py", b"print(1)\n")
add("src/lien", type=tarfile.SYMTYPE, linkname="/etc/passwd", size=0)
add("src/dur", type=tarfile.LNKTYPE, linkname="src/app.py", size=0)
add("src/tube", type=tarfile.FIFOTYPE, size=0)
add("src/dev", type=tarfile.CHRTYPE, size=0)
t.close()'
R=$(arch_job "$up")
expect "archive tar.gz : ok, historique « none »" "$(jq -r '.status + "/" + .source.history' <<< "$R")" ok/none
expect "archive tar.gz : 1 fichier, liens et fichiers spéciaux écartés" "$(jq -c '.source | {files, skipped: [.skipped[].reason] | sort}' <<< "$R")" '{"files":1,"skipped":["special","special","symlink","symlink"]}'
expect "archive : aucun commit" "$(jq -r .source.commit <<< "$R")" null
up=$(uuid)
mkarch "$up" 'import sys, zipfile
z = zipfile.ZipFile(sys.argv[1] + "/source.zip", "w")
z.writestr("ok.txt", "bonjour")
z.writestr("../../evasion.txt", "piège")
z.close()'
R=$(arch_job "$up")
expect "archive zip « .. » → E_ARCHIVE_UNSAFE (input)" "$(jq -r '.error.code + "/" + .error.class' <<< "$R")" "E_ARCHIVE_UNSAFE/input"
[[ -e "$T/var/lib/scanoria/scans/evasion.txt" || -e "$T/var/lib/scanoria/evasion.txt" ]] && ko "archive zip : fichier écrit hors de l'espace de travail" || ok "archive zip : rien d'écrit hors de l'espace de travail"
up=$(uuid)
mkarch "$up" 'import sys, zipfile, stat
z = zipfile.ZipFile(sys.argv[1] + "/source.zip", "w")
z.writestr("a.txt", "a")
i = zipfile.ZipInfo("lien"); i.external_attr = (stat.S_IFLNK | 0o777) << 16
z.writestr(i, "/etc/passwd")
z.close()'
R=$(arch_job "$up")
expect "archive zip : lien écarté" "$(jq -c '.source | {files, skipped: [.skipped[].reason]}' <<< "$R")" '{"files":1,"skipped":["symlink"]}'
up=$(uuid)
mkarch "$up" 'import sys; open(sys.argv[1] + "/source.tar", "wb").write(b"pas une archive" * 100)'
expect "archive illisible → E_ARCHIVE_INVALID" "$(arch_job "$up" | jq -r .error.code)" E_ARCHIVE_INVALID
expect "archive absente → E_ARCHIVE_MISSING" "$(arch_job "$(uuid)" | jq -r .error.code)" E_ARCHIVE_MISSING
up=$(uuid)
mkarch "$up" 'import os, sys; os.symlink("/etc/passwd", sys.argv[1] + "/source.tar")'
expect "archive en lien symbolique → refusée" "$(arch_job "$up" | jq -r .error.code)" E_ARCHIVE_INVALID
# Répertoire du téléversement remplacé par un lien : jamais suivi.
up=$(uuid)
mkarch "$(uuid)" 'import sys, tarfile, io
t = tarfile.open(sys.argv[1] + "/source.tar", "w"); i = tarfile.TarInfo("a.txt"); i.size = 1
t.addfile(i, io.BytesIO(b"a")); t.close()'
mkdir -p "$TMP/ailleurs" && cp "$(find "$T/var/lib/scanoria/uploads" -name source.tar | head -1)" "$TMP/ailleurs/"
ln -s "$TMP/ailleurs" "$T/var/lib/scanoria/uploads/$up"
expect "répertoire de téléversement en lien → E_ARCHIVE_MISSING" "$(arch_job "$up" | jq -r .error.code)" E_ARCHIVE_MISSING

# --- 8. Redémarrage, capacité, purge -------------------------------------------------------
id=$(uuid); sid=$(uuid)
printf '{"id": "%s", "scan_id": "%s", "source_kind": "git"}' "$id" "$sid" > "$SCANS/jobs/work/$id.running"
mkdir -p "$SCANS/workspaces/$id/src" && echo reste > "$SCANS/workspaces/$id/src/f"
touch "$TMP/nft-table"; : > "$TMP/nft.log"; : > "$TMP/podman.log"; echo orphans > "$SCEN"
run_runner
echo ok > "$SCEN"; rm -f "$TMP/nft-table"
grep -q '"flush", "set", "inet", "scanoria_fetch", "allow4"' "$TMP/nft.log" && ok "redémarrage : autorisations nftables héritées vidées" || ko "redémarrage : ensemble allow4 non vidé"
grep -q '"rm", "--force", "--ignore", "--time", "0", "0123456789ab"' "$TMP/podman.log" && ok "redémarrage : conteneur orphelin retiré" || ko "redémarrage : conteneur orphelin laissé"
expect "redémarrage : E_RUNNER_RESTARTED (infra)" "$(res "$id" | jq -r '.error.code + "/" + .error.class + "/" + .scan_id')" "E_RUNNER_RESTARTED/infra/$sid"
expect "redémarrage : espace de travail orphelin supprimé" "$(find "$SCANS/workspaces" -mindepth 1 | wc -l)" 0
valid "$id" > /dev/null && ok "redémarrage : résultat conforme" || ko "redémarrage : résultat non conforme"
old=$(uuid); new=$(uuid)
mkdir -p "$SCANS/results/$old" "$SCANS/results/$new"
touch -d '2 days ago' "$SCANS/results/$old"
run_runner
[[ -d "$SCANS/results/$old" ]] && ko "purge : résultat de plus de 24 h gardé" || ok "purge : résultat de plus de 24 h retiré"
[[ -d "$SCANS/results/$new" ]] && ok "purge : résultat récent gardé" || ko "purge : résultat récent retiré"
printf 'MemTotal:       4194304 kB\n' > "$T/proc/meminfo"
run_runner
expect "capacité : 4 Go → 1 place" "$(jq -r .slots "$T/run/scanoria/runner.json")" 1
# Une tâche au-delà de la capacité attend : le runner en traite une seule à la fois.
python3 -I -B - "$PYLIB" "$SCANS" <<'EOF' && ok "capacité : tâche en attente laissée dans incoming/" || ko "capacité : tâche prise au-delà de la capacité"
import os, sys
sys.path.insert(0, sys.argv[1])
from scanoria import runner
r = runner.Runner(); r.slots = 1; r.busy = 1
open(os.path.join(runner.INCOMING, "00000000-0000-4000-8000-00000000000a.json"), "w").close()
taken = r.tick([])
assert taken == 0 and os.path.exists(os.path.join(runner.INCOMING, "00000000-0000-4000-8000-00000000000a.json"))
os.unlink(os.path.join(runner.INCOMING, "00000000-0000-4000-8000-00000000000a.json"))
EOF
printf 'MemTotal:       16384000 kB\n' > "$T/proc/meminfo"

# --- 9. Selftest : runner.alive ------------------------------------------------------------
python3 -I -B - "$PYLIB" <<'EOF' && ok "selftest : runner.alive lit la capacité publiée" || ko "selftest : runner.alive"
import sys
sys.path.insert(0, sys.argv[1])
from scanoria import selftest
rep = selftest.Report()
selftest.check_runner(rep)
c = [x for x in rep.checks if x["id"] == "runner.alive"][0]
# systemctl est un bouchon (sortie vide) : service non actif, mais capacité fraîche.
assert c["status"] == "fail" and "not active" in c["message"] and "capacity fresh" in c["message"], c
EOF

echo
echo "b14 : $PASS réussis, $FAIL échoués"
[[ "$FAIL" -eq 0 ]]
