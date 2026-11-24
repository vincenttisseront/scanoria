#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Vincent Tisseront
#
# b28 — délais d'orchestration de la 0.6 (chantier D), sans root :
#   1. clé du cache de résultats (contrat 21) : stable, sensible à chaque champ ;
#   2. empreinte du contenu de /src : stable, sensible au contenu, au mode et
#      au chemin, sans le .git de la racine ;
#   3. applicabilité (V6, contrat 23) : clés de détection, motifs, module sans
#      applies_to toujours lancé, applies_to mal formé → lancé ;
#   4. graphe et budget (V3, V5) : dépendances déclarées et règle SBOM,
#      parallélisme borné par la mémoire, une tâche toujours servie, cycle ;
#   5. runner réel en mode test (podman simulé) : not-applicable, clé publiée,
#      sortie reprise du cache puis revalidée, entrées piégées ignorées, tâche
#      sans cache (essai F13), module qui lit l'historique jamais réutilisé,
#      modules indépendants en parallèle, consommateur du SBOM après Syft,
#      graphe déclaré respecté, tâche hostile (after) refusée.
# Dépendances : bash, python3, jq.

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
expect() { if [[ "$2" == "$3" ]]; then ok "$1"; else ko "$1 (obtenu « $2 », attendu « $3 »)"; fi; }
for t in python3 jq; do command -v "$t" > /dev/null || { echo "outil manquant : $t" >&2; exit 2; }; done

# --- 1 à 4 : fonctions pures ----------------------------------------------------------------
python3 -I - "$PYLIB" "$TMP/pure" <<'EOF' > "$TMP/pure.out" || true
import json, os, sys, threading, time
sys.path.insert(0, sys.argv[1])
from scanoria import applicability as ap, resultcache as rc, schedule as sc

def check(label, cond):
    print(("ok   " if cond else "FAIL ") + label)

# 1. Clé du contrat 21.
D = "sha256:" + "d" * 64
base = dict(module_id="trivy", image_digest=D, input_={"kind": "tree", "tree_sha": "a" * 64},
            feeds=[{"id": "trivy-db", "version": "2@2026-11-24T00:00:00Z"}, {"id": "a-db", "version": "1@x"}],
            options_sha256="0" * 64)
k = rc.compute_key(**base)
check("clé : 64 caractères hexadécimaux", bool(rc.KEY_RE.match(k)))
check("clé : stable", k == rc.compute_key(**base))
check("clé : bases triées par id (ordre indifférent)", k == rc.compute_key(**dict(base, feeds=list(reversed(base["feeds"])))))
expected = rc.sha256_hex(json.dumps({"v": 1, "module_id": "trivy", "image_digest": D, "input": base["input_"],
                                     "feeds": sorted(base["feeds"], key=lambda f: f["id"]), "options_sha256": "0" * 64},
                                    sort_keys=True, separators=(",", ":")).encode())
check("clé : JSON canonique du contrat 21", k == expected)
for field, value in [("module_id", "grype"), ("image_digest", "sha256:" + "e" * 64),
                     ("input_", {"kind": "tree", "tree_sha": "b" * 64}),
                     ("input_", {"kind": "sbom", "sbom_sha256": "a" * 64}),
                     ("feeds", [{"id": "trivy-db", "version": "2@2026-11-25T00:00:00Z"}, {"id": "a-db", "version": "1@x"}]),
                     ("feeds", [{"id": "trivy-db", "version": "2@2026-11-24T00:00:00Z"}]),
                     ("options_sha256", "1" * 64)]:
    check("clé : sensible à %s (%s)" % (field, json.dumps(value)[:40]), rc.compute_key(**dict(base, **{field: value})) != k)
o = rc.options_sha256({"seuil": 1}, ["x", "/src"], {"A": "1"})
check("options : stable", o == rc.options_sha256({"seuil": 1}, ["x", "/src"], {"A": "1"}))
check("options : sensibles aux options, à la commande (dépôt ou SBOM) et à l'environnement",
      len({o, rc.options_sha256({"seuil": 2}, ["x", "/src"], {"A": "1"}), rc.options_sha256({"seuil": 1}, ["y", "/src"], {"A": "1"}),
           rc.options_sha256({"seuil": 1}, ["x", "/src"], {"A": "2"})}) == 4)

# 2. Empreinte du contenu.
root = sys.argv[2]
def tree(files):
    import shutil
    shutil.rmtree(root, ignore_errors=True)
    for rel, (data, mode) in files.items():
        p = os.path.join(root, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w") as f:
            f.write(data)
        os.chmod(p, mode)
    os.makedirs(root, exist_ok=True)
    return ap.inspect(root)
F = {"README.md": ("x\n", 0o644), "lib/app.py": ("print(1)\n", 0o644), "Dockerfile": ("FROM x\n", 0o644)}
t1, det, paths = tree(F)
check("arbre : stable", t1 == tree(F)[0])
check("arbre : chemins triés", paths == ["Dockerfile", "README.md", "lib/app.py"])
check("arbre : détection (python, containers)", det == {"python": 1, "containers": 1})
check("arbre : sensible au contenu", tree(dict(F, **{"lib/app.py": ("print(2)\n", 0o644)}))[0] != t1)
check("arbre : sensible au mode exécutable", tree(dict(F, **{"lib/app.py": ("print(1)\n", 0o755)}))[0] != t1)
check("arbre : sensible au chemin", tree({"README.md": ("x\n", 0o644), "lib/autre.py": ("print(1)\n", 0o644), "Dockerfile": ("FROM x\n", 0o644)})[0] != t1)
check("arbre : .git de la racine ignoré", tree(dict(F, **{".git/HEAD": ("ref\n", 0o644)}))[0] == t1)
check("arbre : .git d'un sous-répertoire compté", tree(dict(F, **{"sub/.git/HEAD": ("ref\n", 0o644)}))[0] != t1)

# 3. Applicabilité.
check("clés : Dockerfile.prod, workflow, rôle Ansible, verrou, manifeste",
      [ap.keys_of(p) for p in ("a/Dockerfile.prod", ".github/workflows/ci.yml", "roles/web/tasks/main.yml", "x/yarn.lock", "go.mod")]
      == [["containers"], ["ci"], ["ansible"], ["lockfiles"], ["manifests"]])
m = lambda spec: {"scan": {"applies_to": spec}} if spec is not None else {"scan": {}}
check("applicabilité : sans applies_to → lancé", ap.applies(m(None), {}, []) is None)
check("applicabilité : clé présente → lancé", ap.applies(m({"detect": ["containers"]}), {"containers": 1}, ["Dockerfile"]) is None)
check("applicabilité : clé absente → not-applicable", ap.applies(m({"detect": ["terraform"]}), {"python": 1}, ["a.py"]) == "no-matching-files")
check("applicabilité : motif ** trouvé", ap.applies(m({"paths": ["**/*.tf"]}), {}, ["infra/main.tf"]) is None)
check("applicabilité : motif sans / sur le nom, à toute profondeur", ap.applies(m({"paths": ["*.tf"]}), {}, ["infra/main.tf"]) is None)
check("applicabilité : motif ancré non trouvé", ap.applies(m({"paths": ["docs/*.md"]}), {}, ["docs/a/b.md"]) == "no-matching-files")
check("applicabilité : alternative {a,b}", ap.applies(m({"paths": ["**/*.{yml,yaml}"]}), {}, ["k/x.yaml"]) is None)
for bad in ({"paths": ["../x"]}, {"paths": ["/etc/*"]}, {"paths": ["{a"]}, {"paths": [1]}, "x", {"detect": "x"}, {}):
    check("applicabilité : applies_to mal formé %s → lancé (G13)" % json.dumps(bad), ap.applies(m(bad), {}, ["a"]) is None)

# 4. Graphe et budget.
man = lambda mid, mem=256, out=None, scan=None: {"id": mid, "resources": {"min_ram_mb": mem, "min_cpu": 1},
                                                  "outputs": out or {"sarif": {}}, "scan": scan or {"inputs": ["repo"]}}
syft = man("syft", out={"cyclonedx": {}})
grype = man("grype", scan={"inputs": ["repo", "sbom"], "prefers_sbom": True, "sbom_command": ["g"]})
gl = man("gitleaks")
run = [({"id": x["id"]}, {"manifest": x}) for x in (grype, gl, syft)]
deps = sc.dependencies({"modules": [{"id": "gitleaks", "after": ["grype", "inconnu"]}]}, run)
check("graphe : règle SBOM ajoutée sans after (plan antérieur)", deps["grype"] == {"syft"})
check("graphe : after déclaré, limité aux modules lancés", deps["gitleaks"] == {"grype"} and deps["syft"] == set())

def simulate(items, deps, mem_total, cpus, delay=0.2):
    b = sc.Budget()
    b.configure(mem_total, cpus)
    lock, active, peak, spans = threading.Lock(), [0], [0], {}
    def one(e, s):
        with lock:
            active[0] += 1
            peak[0] = max(peak[0], active[0])
        t0 = time.monotonic()
        time.sleep(delay)
        spans[e["id"]] = (t0, time.monotonic())
        with lock:
            active[0] -= 1
    sc.run_all("job", items, deps, one, budget=b)
    return peak[0], spans, b

items = [({"id": "m%d" % i}, {"manifest": man("m%d" % i, 512)}) for i in range(4)]
peak, _, b = simulate(items, {}, 4096, 4)
check("budget : 4 modules indépendants, 4 CPU, 4 Go → 4 en parallèle", peak == 4)
check("budget : tout est rendu à la fin", (b.mem_used, b.cpu_used, b.per_job) == (0, 0, {}))
peak, _, _ = simulate(items, {}, 1100, 4)
check("budget : 1,1 Go → 2 conteneurs de 512 Mo à la fois", peak == 2)
peak, _, _ = simulate(items, {}, 4096, 2)
check("budget : 2 processeurs → 2 à la fois", peak == 2)
peak, _, _ = simulate([({"id": "gros"}, {"manifest": man("gros", 8192)})], {}, 0, 1)
check("budget : une tâche est toujours servie, même au-delà du budget", peak == 1)
peak, spans, _ = simulate(items[:2], {"m1": {"m0"}}, 4096, 4)
check("graphe : m1 attend la fin de m0", spans["m1"][0] >= spans["m0"][1])
peak, spans, _ = simulate(items[:2], {"m0": {"m1"}, "m1": {"m0"}}, 4096, 4, 0.05)
check("graphe : cycle → on avance quand même, dans l'ordre", set(spans) == {"m0", "m1"})
# Deux tâches : la seconde a toujours sa place garantie.
# Outil d'appliance monté (scan.tool) : son contenu entre dans la clé (une mise à jour l'invalide).
tool = os.path.join(sys.argv[2], "tool")
os.makedirs(tool, exist_ok=True)
with open(os.path.join(tool, "t.py"), "w") as f:
    f.write("v1")
h1 = rc.tree_sha256(tool)
with open(os.path.join(tool, "t.py"), "w") as f:
    f.write("v2")
h2 = rc.tree_sha256(tool)
check("outil : empreinte de l'arbre sensible au contenu", h1 and h2 and h1 != h2)
check("outil : empreinte dans options_sha256", rc.options_sha256({}, ["x"], {}, h1) != rc.options_sha256({}, ["x"], {}, h2))
check("outil : sans outil, options_sha256 inchangé (clés antérieures)", rc.options_sha256({}, ["x"], {}) == rc.sha256_hex(rc.canonical({"options": {}, "command": ["x"], "env": {}})))
os.symlink("/etc/hostname", os.path.join(tool, "lien"))
check("outil : lien dans l'arbre → jamais réutilisable", rc.tree_sha256(tool) is None)

# Thread impossible à démarrer : réservation rendue, module en erreur, les autres continuent.
class NoThread(threading.Thread):
    def start(self):
        if self.name == "mod-b":
            raise RuntimeError("can't start new thread")
        super().start()
real, sc.threading.Thread = sc.threading.Thread, NoThread
bud = sc.Budget()
bud.configure(4096, 2)
ran, failed = [], []
try:
    sc.run_all("J", [({"id": "a"}, {"manifest": {}}), ({"id": "b"}, {"manifest": {}}), ({"id": "c"}, {"manifest": {}})],
               {"c": {"b"}}, lambda e, s: ran.append(e["id"]), budget=bud,
               on_start_error=lambda e, exc: failed.append(e["id"]))
finally:
    sc.threading.Thread = real
check("ordonnancement : échec de démarrage signalé", failed == ["b"])
check("ordonnancement : autres modules lancés (dépendant compris)", sorted(ran) == ["a", "c"])
check("ordonnancement : budget entièrement rendu", bud.mem_used == 0 and bud.cpu_used == 0 and not bud.per_job)

b = sc.Budget()
b.configure(600, 4)
with b.cv:
    check("budget : premier module de la tâche A admis", b.admit("A", 512, 1))
    check("budget : second module de A refusé (mémoire)", not b.admit("A", 512, 1))
    check("budget : premier module de la tâche B toujours admis", b.admit("B", 512, 1))
EOF
while IFS= read -r line; do
	case "$line" in
		"ok   "*) ok "${line#ok   }" ;;
		"FAIL "*) ko "${line#FAIL }" ;;
		*) printf '     %s\n' "$line" ;;
	esac
done < "$TMP/pure.out"
grep -q '^ok   budget : premier module de la tâche B' "$TMP/pure.out" || ko "fonctions pures : exécution interrompue"

# --- 5. Runner en mode test -----------------------------------------------------------------
T="$TMP/root"
STUBS="$TMP/stubs"
SCANS="$T/var/lib/scanoria/scans"
CACHE="$TMP/result-cache"
mkdir -p "$T/var/lib/scanoria/modules" "$T/run/scanoria" "$T/proc" "$T/sys/fs/cgroup" "$STUBS" "$CACHE"
export SCANORIA_TEST_ROOT="$T" SCANORIA_TEST_BIN="$STUBS" SCANORIA_RESULT_CACHE="$CACHE"
export SCANORIA_TEST_RESOLVE="forge.exemple.test=192.0.2.10"
unset SCANORIA_TEST_OWNER_UID SCANORIA_SCANS_DIR SCANORIA_RUNNER_STATE
printf 'MemTotal:       16384000 kB\n' > "$T/proc/meminfo"
for i in 0 1 2 3; do printf 'processor\t: %d\n' "$i"; done > "$T/proc/cpuinfo"
COMMIT=$(printf 'b28' | sha256sum | cut -c1-40)

cat > "$STUBS/podman" <<EOF
#!/usr/bin/env python3
# Bouchon de podman : clone simulé, scanners qui écrivent un SARIF (ou un SBOM) après 1 s.
import json, os, sys, time
a = sys.argv[1:]
if a[:2] == ["image", "exists"] or a[:2] == ["network", "exists"]:
    sys.exit(0)
if a[:1] == ["inspect"]:
    print("false"); sys.exit(0)
if a[:1] != ["run"]:
    sys.exit(0)
vols = {}
for i, x in enumerate(a):
    if x == "--volume":
        host, target, mode = a[i + 1].rsplit(":", 2)
        vols[target] = host
ep = json.loads(a[a.index("--entrypoint") + 1])
rest = a[a.index("--entrypoint") + 2:][1:]
if ep == ["/bin/sh"]:
    src = vols["/src"]
    os.makedirs(src + "/lib", exist_ok=True)
    open(src + "/lib/app.py", "w").write("print(1)\n")
    open(src + "/Dockerfile", "w").write("FROM scratch\n")
    print("commit=$COMMIT")
    sys.exit(0)
name = a[a.index("--name") + 1]
t0 = time.time()
time.sleep(1)
with open("$TMP/runs.log", "a") as f:
    f.write(json.dumps({"cmd": [ep[0]] + rest, "start": t0, "end": time.time(), "sbom": os.path.isdir(vols.get("/src", "")) and os.path.isfile(vols["/src"] + "/sbom.cdx.json")}) + "\n")
out = vols["/out"]
if ep[0] == "syft":
    open(out + "/sbom.cdx.json", "w").write(json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1, "components": [{"type": "library", "name": "x", "version": "1", "purl": "pkg:npm/x@1"}]}))
else:
    open(out + "/result.sarif", "w").write(json.dumps({"version": "2.1.0", "runs": [{"tool": {"driver": {"name": ep[0]}}, "results": [{"ruleId": "r", "message": {"text": "frais"}}]}]}))
sys.exit(0)
EOF
printf '#!/bin/sh\nexit 0\n' > "$STUBS/nft"
chmod 0755 "$STUBS/podman" "$STUBS/nft"

IMG="ghcr.io/exemple/faux@sha256:$(printf 'faux' | sha256sum | cut -d' ' -f1)"
GIMG="docker.io/exemple/git@sha256:$(printf 'git' | sha256sum | cut -d' ' -f1)"
python3 - "$T/var/lib/scanoria/modules/installed.json" "$IMG" "$GIMG" <<'EOF'
import json, sys
path, img, gimg = sys.argv[1:4]
def m(mid, image=img, scan=None, out=None, cats=("lint",)):
    man = {"id": mid, "name": mid, "type": "scanner", "version": "1.0.0", "categories": list(cats),
           "license": {"spdx": "MIT", "restrictions": "none"}, "image": image,
           "resources": {"min_ram_mb": 256, "min_cpu": 1, "disk_mb": 10},
           "requires": {"modules": ["git-fetch"], "feeds": []}, "conflicts": [],
           "options": {"type": "object", "additionalProperties": False, "properties": {}},
           "scan": {"inputs": ["repo", "archive"], "network": "none", "timeout_s": 60, "exit_codes_ok": [0],
                    "command": [mid, "/src"]},
           "outputs": out or {"sarif": {"path": "/out/result.sarif", "version": "2.1.0"}}}
    man["scan"].update(scan or {})
    return {"manifest": man, "status": "healthy", "enabled": True, "options": {}}
reg = {"modules": {
    "pylint": m("pylint", scan={"applies_to": {"detect": ["python"]}}),
    "tflint": m("tflint", scan={"applies_to": {"paths": ["**/*.tf"]}}),
    "simple": m("simple"),
    "autre": m("autre"),
    "histo": m("histo", scan={"history": "full", "history_command": ["histo", "/git"]}),
    "syft": m("syft", out={"cyclonedx": {"path": "/out/sbom.cdx.json", "version": "1.6"}}, cats=("sbom",)),
    "grype": m("grype", scan={"inputs": ["repo", "archive", "sbom"], "prefers_sbom": True, "sbom_command": ["grype", "sbom:/src/sbom.cdx.json"]}, cats=("sca",)),
    "git-fetch": m("git-fetch", gimg, cats=("system",)),
}, "operations": []}
reg["modules"]["git-fetch"]["manifest"]["requires"]["modules"] = []
json.dump(reg, open(path, "w"))
EOF

uuid() { python3 -c 'import uuid; print(uuid.uuid4())'; }
job() { # ID modules-json [cache true|false|absent]
	local extra='{}'
	[[ "${3:-true}" == absent ]] || extra=$(jq -cn --argjson c "${3:-true}" '{cache: $c}')
	jq -cn --arg id "$1" --arg sid "$(uuid)" --argjson mods "$2" --argjson extra "$extra" \
		'{schema: 1, id: $id, scan_id: $sid, created_at: "2026-11-24T10:00:00Z",
		  source: {kind: "git", url: "https://forge.exemple.test/exemple/depot.git", ref: "main", history: "shallow"}, modules: $mods} + $extra'
}
drop() { printf '%s' "$2" > "$SCANS/jobs/incoming/$1.json"; chmod 0600 "$SCANS/jobs/incoming/$1.json"; }
run_runner() { "$RUNNER" --once 2> "$TMP/runner.err" || { echo "runner : code $?"; sed 's/^/     /' "$TMP/runner.err"; }; }
res() { cat "$SCANS/results/$1/result.json" 2> /dev/null || echo '{}'; }
mod() { jq -c --arg m "$2" '.modules[] | select(.id == $m)' <<< "$1"; }
valid() {
	python3 -I -B -c 'import json, sys; sys.path.insert(0, sys.argv[1]); from scanoria import schema
errs = schema.load("schemas", "scan-result").errors(json.load(open(sys.argv[2])))
print("; ".join(errs[:3])); sys.exit(1 if errs else 0)' "$PYLIB" "$SCANS/results/$1/result.json"
}
run_runner   # arborescence

# 5a. Applicabilité, empreinte, clé publiée.
: > "$TMP/runs.log"
id=$(uuid)
drop "$id" "$(job "$id" '[{"id": "pylint", "version": "1.0.0"}, {"id": "tflint", "version": "1.0.0"}, {"id": "simple", "version": "1.0.0"}, {"id": "histo", "version": "1.0.0"}]')"
run_runner
R=$(res "$id")
valid "$id" > /dev/null && ok "runner : résultat conforme (not-applicable, tree, detection, cache_key)" || ko "runner : résultat non conforme ($(valid "$id"))"
expect "V6 : tflint sans fichier .tf → not-applicable" "$(mod "$R" tflint | jq -r .status)" not-applicable
expect "V6 : pylint (python détecté) lancé" "$(mod "$R" pylint | jq -r .status)" ok
expect "V6 : module sans applies_to lancé" "$(mod "$R" simple | jq -r .status)" ok
expect "V6 : not-applicable jamais lancé" "$(grep -c '"tflint"' "$TMP/runs.log" || true)" 0
expect "V6 : détection relevée" "$(jq -cS .source.detection <<< "$R")" '{"containers":1,"python":1}'
TREE=$(jq -r .source.tree <<< "$R")
[[ "$TREE" =~ ^[0-9a-f]{64}$ ]] && ok "V4 : empreinte du contenu publiée" || ko "V4 : empreinte absente ($TREE)"
KEY=$(mod "$R" simple | jq -r .cache_key)
[[ "$KEY" =~ ^[0-9a-f]{64}$ ]] && ok "V4 : clé publiée pour un module ok" || ko "V4 : clé absente"
expect "V4 : module qui lit l'historique jamais réutilisable" "$(mod "$R" histo | jq -r '.cache_key // "aucune"')" aucune
expect "V3 : entrée lue notée" "$(mod "$R" simple | jq -r .input)" src
expect "V4 : attestation du runner pour la sortie neuve" \
	"$(jq -r '.sha256.sarif' "$T/var/lib/scanoria/scans/cache-attest/$KEY.json" 2> /dev/null)" \
	"$(sha256sum < "$SCANS/results/$(jq -r .id <<< "$R")/simple/result.sarif" | cut -c1-64)"
expect "V4 : clé recalculée identique (même contenu)" "$(python3 -I - "$PYLIB" "$TREE" "$IMG" <<'EOF'
import sys
sys.path.insert(0, sys.argv[1])
from scanoria import resultcache as rc
print(rc.compute_key("simple", sys.argv[3].split("@", 1)[1], {"kind": "tree", "tree_sha": sys.argv[2]}, [],
                     rc.options_sha256({}, ["simple", "/src"], {})))
EOF
)" "$KEY"

# 5b. Même source : sortie reprise du cache, revalidée, recopiée.
put() { # clé module fichier-sarif [méta]
	mkdir -p "$CACHE/$1"
	printf '%s' "${4:-$(jq -cn --arg k "$1" --arg m "$2" '{v: 1, key: $k, module_id: $m, image_digest: "x", outputs: {sarif: "sarif.json"}}')}" > "$CACHE/$1/meta.json"
	printf '%s' "$3" > "$CACHE/$1/sarif.json"
	attest "$1" "$2" "$3"
}
ATTEST="$T/var/lib/scanoria/scans/cache-attest"
attest() { # clé module contenu : attestation que le runner aurait écrite pour cette sortie
	mkdir -p "$ATTEST"
	jq -cn --arg k "$1" --arg m "$2" --arg h "$(printf '%s' "$3" | sha256sum | cut -c1-64)" \
		'{v: 1, key: $k, module_id: $m, sha256: {sarif: $h}}' > "$ATTEST/$1.json"
}
CACHED='{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"simple"}},"results":[{"ruleId":"r","message":{"text":"du cache"}}]}]}'
put "$KEY" simple "$CACHED"
: > "$TMP/runs.log"
id=$(uuid)
drop "$id" "$(job "$id" '[{"id": "simple", "version": "1.0.0"}, {"id": "pylint", "version": "1.0.0"}]')"
run_runner
R=$(res "$id")
valid "$id" > /dev/null && ok "V4 : résultat conforme (reused_from)" || ko "V4 : résultat non conforme ($(valid "$id"))"
expect "V4 : sortie reprise (reused_from = clé)" "$(mod "$R" simple | jq -r '.status + "/" + .reused_from')" "ok/$KEY"
expect "V4 : aucun conteneur lancé pour le module repris" "$(grep -c '"simple"' "$TMP/runs.log" || true)" 0
expect "V4 : sortie recopiée telle quelle" "$(cat "$SCANS/results/$id/simple/result.sarif")" "$CACHED"
expect "V4 : aucune mesure pour une sortie reprise" "$(mod "$R" simple | jq -r '.stats // "aucune"')" aucune
expect "V4 : autre module lancé normalement" "$(mod "$R" pylint | jq -r '.status + "/" + (.reused_from // "neuf")')" "ok/neuf"

# 5c. Entrées piégées : ignorées, le module tourne (jamais un résultat faux ou vide).
trap_case() { # libellé préparation
	rm -rf "${CACHE:?}/$KEY"
	eval "$2"
	: > "$TMP/runs.log"
	local id; id=$(uuid)
	drop "$id" "$(job "$id" '[{"id": "simple", "version": "1.0.0"}]')"
	run_runner
	local r; r=$(res "$id")
	expect "V4 piégé : $1 → module lancé" "$(mod "$r" simple | jq -r '.status + "/" + (.reused_from // "neuf") + "/" + (.cache_key // "-")')" "ok/neuf/$KEY"
	grep -q 'frais' "$SCANS/results/$id/simple/result.sarif" && ok "V4 piégé : $1 : sortie fraîche" || ko "V4 piégé : $1 : sortie du cache utilisée"
}
trap_case "SARIF invalide (G2)" 'put "$KEY" simple "pas du JSON"'
trap_case "SARIF d'une autre version" 'put "$KEY" simple "{\"version\":\"1.0.0\",\"runs\":[]}"'
trap_case "méta d'un autre module" 'put "$KEY" simple "$CACHED" "$(jq -cn --arg k "$KEY" "{v: 1, key: \$k, module_id: \"autre\", outputs: {sarif: \"sarif.json\"}}")"'
trap_case "méta d'une autre clé" 'put "$KEY" simple "$CACHED" "{\"v\":1,\"key\":\"$(printf "%064d" 0)\",\"module_id\":\"simple\",\"outputs\":{\"sarif\":\"sarif.json\"}}"'
trap_case "nom de fichier hors liste" 'put "$KEY" simple "$CACHED" "$(jq -cn --arg k "$KEY" "{v: 1, key: \$k, module_id: \"simple\", outputs: {sarif: \"../../etc/passwd\"}}")"'
trap_case "sortie en lien symbolique" 'put "$KEY" simple "$CACHED"; rm "$CACHE/$KEY/sarif.json"; ln -s /etc/hostname "$CACHE/$KEY/sarif.json"'
trap_case "sortie à deux liens" 'put "$KEY" simple "$CACHED"; ln "$CACHE/$KEY/sarif.json" "$TMP/second-lien"'
trap_case "entrée en lien symbolique" 'mkdir -p "$TMP/ailleurs"; put ailleurs-x simple "$CACHED"; ln -s "$CACHE/ailleurs-x" "$CACHE/$KEY"'
trap_case "sortie modifiée après attestation (console non fiable)" 'put "$KEY" simple "$CACHED"; attest "$KEY" simple "autre contenu"'
trap_case "attestation absente" 'put "$KEY" simple "$CACHED"; rm -f "$ATTEST/$KEY.json"'
trap_case "attestation d'un autre module" 'put "$KEY" simple "$CACHED"; attest "$KEY" autre "$CACHED"'
trap_case "méta JSON à clé dupliquée" 'put "$KEY" simple "$CACHED" "{\"v\":1,\"v\":1}"'
rm -rf "${CACHE:?}/$KEY" "$CACHE/ailleurs-x"

# 5d. Tâche sans cache (analyse d'essai F13, ou tâche antérieure à la 0.6).
put "$KEY" simple "$CACHED"
for c in false absent; do
	id=$(uuid)
	drop "$id" "$(job "$id" '[{"id": "simple", "version": "1.0.0"}]' "$c")"
	run_runner
	expect "V4 : tâche cache=$c → ni lecture ni clé" "$(mod "$(res "$id")" simple | jq -r '(.reused_from // "-") + "/" + (.cache_key // "-")')" "-/-"
done
rm -rf "${CACHE:?}/$KEY"

# 5e. Parallélisme (V5) et graphe (V3).
span() { jq -s --arg a "$1" --arg b "$2" '([.[] | select(.cmd[0] == $a)][0]) as $x | ([.[] | select(.cmd[0] == $b)][0]) as $y | if ($y.start < $x.end and $x.start < $y.end) then "chevauchement" else "successifs" end' -r "$TMP/runs.log"; }
: > "$TMP/runs.log"
id=$(uuid)
drop "$id" "$(job "$id" '[{"id": "simple", "version": "1.0.0"}, {"id": "autre", "version": "1.0.0"}]' false)"
run_runner
expect "V5 : modules indépendants en parallèle (4 CPU, 16 Go)" "$(span simple autre)" chevauchement
expect "V5 : ordre du résultat = ordre de la tâche" "$(res "$id" | jq -c '[.modules[].id]')" '["simple","autre"]'
: > "$TMP/runs.log"
id=$(uuid)
drop "$id" "$(job "$id" '[{"id": "simple", "version": "1.0.0"}, {"id": "autre", "version": "1.0.0", "after": ["simple"]}]' false)"
run_runner
expect "V3 : graphe déclaré respecté (after)" "$(span simple autre)" successifs
: > "$TMP/runs.log"
id=$(uuid)
drop "$id" "$(job "$id" '[{"id": "grype", "version": "1.0.0"}, {"id": "syft", "version": "1.0.0"}, {"id": "simple", "version": "1.0.0"}]' false)"
run_runner
R=$(res "$id")
expect "V3 : Grype après Syft, même sans graphe (plan antérieur)" "$(span syft grype)" successifs
expect "V3 : module indépendant en parallèle de Syft" "$(span syft simple)" chevauchement
expect "V3 : Grype lit le SBOM de l'analyse" "$(mod "$R" grype | jq -r .input)" sbom
jq -s -e '[.[] | select(.cmd[0] == "grype")][0].sbom' "$TMP/runs.log" > /dev/null && ok "V3 : SBOM monté pour Grype" || ko "V3 : SBOM non monté"
: > "$TMP/runs.log"
id=$(uuid)
drop "$id" "$(job "$id" '[{"id": "grype", "version": "1.0.0"}]' false)"
run_runner
expect "V3 : sans SBOM, Grype lit le dépôt et le repli est noté" "$(mod "$(res "$id")" grype | jq -c '{status, input, sbom_fallback}')" '{"status":"ok","input":"src","sbom_fallback":true}'

# 5f. Tâche hostile : graphe.
for bad in '["Pas un id"]' '"simple"' '["a","a"]'; do
	id=$(uuid)
	drop "$id" "$(job "$id" "[{\"id\": \"simple\", \"version\": \"1.0.0\", \"after\": $bad}]")"
	run_runner
	expect "hostile : after=$bad → E_JOB_INVALID" "$(res "$id" | jq -r .error.code)" E_JOB_INVALID
done
id=$(uuid)
drop "$id" "$(job "$id" '[{"id": "simple", "version": "1.0.0"}]' '"oui"')"
run_runner
expect "hostile : cache non booléen → E_JOB_INVALID" "$(res "$id" | jq -r .error.code)" E_JOB_INVALID
expect "espaces de travail supprimés" "$(find "$SCANS/workspaces" -mindepth 1 | wc -l)" 0

echo
echo "b28 : $PASS réussis, $FAIL échoués"
[[ "$FAIL" -eq 0 ]]
