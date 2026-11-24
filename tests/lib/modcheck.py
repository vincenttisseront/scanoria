# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Vincent Tisseront
"""Contrôles des modules du catalogue (tests/b10-modules.sh, tests/b10-live.sh).

Sous-commandes :
  manifest FICHIER…          valide des manifestes (schéma + règles ci-dessous) ;
                             code 1 et une ligne « id: erreur » par refus
  repo RACINE                valide tous les modules/<id>/module.yaml du dépôt
                             et leurs liens (requires, conflicts, testbed)
  expect MANIFESTE SARIF     vérifie testbed.expect sur une sortie SARIF
  sarif SCHEMA SARIF         valide une sortie contre le schéma SARIF 2.1.0 officiel
  podman MANIFESTE SRC OUT FEEDS
                             écrit (séparés par NUL) les arguments de « podman
                             run » confinés (CLAUDE.md § 6.4) du scanner

Le schéma est validé deux fois : par le validateur de l'appliance
(scanoria/schema.py, sous-ensemble utilisé aussi par catalog/build.py et le
helper) et par python3-jsonschema (conformité draft 2020-12).
"""

import json
import os
import re
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "src/rootfs/usr/lib/scanoria/py"))

import jsonschema  # noqa: E402
import yaml  # noqa: E402
from scanoria import schema as appliance_schema  # noqa: E402

SCHEMA_PATH = os.path.join(ROOT, "catalog/schema/module.schema.json")
OPTION_NAME = re.compile(r"^[a-z][a-z0-9_]{0,40}\Z")
# Même règle que catalogverify.ENV_KEY_RE : ni LD_*, ni PATH, ni HOME.
ENV_NAME = re.compile(r"^(?!LD_|PATH\Z|HOME\Z)[A-Z][A-Z0-9_]{0,63}\Z")
TESTBED_NAME = re.compile(r"^[A-Za-z0-9._+@-]+\Z")


def load_schema():
    with open(SCHEMA_PATH, encoding="utf-8") as f:
        schema = json.load(f)
    jsonschema.Draft202012Validator.check_schema(schema)
    return schema, appliance_schema.Validator(schema), jsonschema.Draft202012Validator(schema)


def load_yaml(path):
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f)


def option_errors(manifest):
    """Règles d'options non exprimables dans le sous-ensemble du schéma."""
    errs = []
    props = manifest.get("options", {}).get("properties", {})
    for name, prop in props.items():
        if not OPTION_NAME.match(name):
            errs.append(f"options: nom d'option invalide : {name!r}")
            continue
        sub = {k: v for k, v in prop.items() if k not in ("default", "title", "description")}
        default_errs = [e.message for e in jsonschema.Draft202012Validator(sub).iter_errors(prop["default"])]
        if default_errs:
            errs.append(f"options.{name}: défaut non conforme : {default_errs[0]}")
        if prop.get("minimum") is not None and prop.get("maximum") is not None and prop["minimum"] > prop["maximum"]:
            errs.append(f"options.{name}: minimum > maximum")
    for name in manifest.get("options_i18n", {}) or {}:
        if name not in props:
            errs.append(f"options_i18n: option inconnue : {name!r}")
    return errs


def scan_errors(manifest):
    errs = []
    scan = manifest.get("scan")
    if not scan:
        return errs
    for name in scan.get("env", {}) or {}:
        if not ENV_NAME.match(name):
            errs.append(f"scan.env: nom de variable invalide : {name!r}")
    if any(".." in arg.split("/") for arg in scan["command"]):
        errs.append("scan.command: chemin avec « .. »")
    props = (manifest.get("options") or {}).get("properties") or {}
    for key in ("command", "history_command"):
        for arg in scan.get(key) or []:
            for name in re.findall(r"\{opt\.([^}]*)\}", arg):
                if name not in props:
                    errs.append(f"scan.{key}: option inconnue dans {{opt.{name}}}")
    for kind, out in (manifest.get("outputs") or {}).items():
        for key in ("command", "history_command"):
            if key in scan and out["path"] not in scan[key]:
                errs.append(f"outputs.{kind}: {out['path']} absent de scan.{key}")
    if "history_command" in scan and scan.get("history") != "full":
        errs.append("scan.history_command exige scan.history: full")
    feeds = manifest.get("requires", {}).get("feeds", [])
    for feed in feeds:
        if not any(f"/feeds/{feed}" in arg for arg in scan["command"] + list((scan.get("env") or {}).values())):
            errs.append(f"requires.feeds: /feeds/{feed} n'est utilisé ni par scan.command ni par scan.env")
    return errs


def manifest_errors(manifest, validators):
    """Toutes les erreurs d'un manifeste (liste vide si valide)."""
    _schema, appliance, standard = validators
    errs = [f"schéma (appliance): {e}" for e in appliance.errors(manifest)]
    errs += [f"schéma (jsonschema): {e.message}" for e in standard.iter_errors(manifest)]
    if errs:
        return errs  # les règles suivantes supposent un manifeste conforme
    return option_errors(manifest) + scan_errors(manifest)


def testbed_errors(module_dir, manifest):
    errs = []
    tb = manifest.get("testbed")
    if not tb:
        return errs
    base = os.path.realpath(module_dir)
    path = os.path.realpath(os.path.join(module_dir, tb["path"]))
    if not path.startswith(base + os.sep):
        return [f"testbed.path sort du module : {tb['path']}"]
    if not os.path.isdir(path):
        return [f"testbed.path absent : {tb['path']}"]
    count = 0
    for dirpath, dirnames, filenames in os.walk(path):
        for n in dirnames + filenames:
            p = os.path.join(dirpath, n)
            rel = os.path.relpath(p, path)
            if os.path.islink(p):
                errs.append(f"testbed: lien symbolique interdit : {rel}")
            elif not (os.path.isdir(p) or os.path.isfile(p)):
                errs.append(f"testbed: fichier spécial interdit : {rel}")
            if not TESTBED_NAME.match(n):
                errs.append(f"testbed: nom de fichier hors jeu de caractères : {rel}")
            count += n in filenames
    if count == 0:
        errs.append("testbed: vide")
    return errs


def repo_errors(root):
    validators = load_schema()
    modules_dir = os.path.join(root, "modules")
    manifests, errs = {}, []
    for mid in sorted(os.listdir(modules_dir)):
        mdir = os.path.join(modules_dir, mid)
        mfile = os.path.join(mdir, "module.yaml")
        if not os.path.isdir(mdir):
            continue
        if os.path.islink(mfile) or os.path.islink(mdir):
            errs.append(f"{mid}: lien symbolique interdit (module.yaml ou dossier)")
            continue
        if not os.path.isfile(mfile):
            errs.append(f"{mid}: module.yaml absent")
            continue
        with open(mfile, encoding="utf-8") as f:
            head = f.read(400)
        if "SPDX-License-Identifier: AGPL-3.0-or-later" not in head:
            errs.append(f"{mid}: en-tête SPDX absent de module.yaml")
        m = load_yaml(mfile)
        errs += [f"{mid}: {e}" for e in manifest_errors(m, validators)]
        if isinstance(m, dict) and m.get("id") != mid:
            errs.append(f"{mid}: id du manifeste ({m.get('id')!r}) ≠ nom du dossier")
        if isinstance(m, dict):
            errs += [f"{mid}: {e}" for e in testbed_errors(mdir, m)]
            manifests[mid] = m
    for mid, m in manifests.items():
        req = m.get("requires", {})
        for dep in req.get("feeds", []):
            if manifests.get(dep, {}).get("type") != "feed":
                errs.append(f"{mid}: requires.feeds cite {dep!r}, qui n'est pas un module feed du dépôt")
        for dep in req.get("modules", []):
            if dep not in manifests or manifests[dep].get("type") == "feed":
                errs.append(f"{mid}: requires.modules cite {dep!r} (absent ou feed)")
        if mid in m.get("conflicts", []):
            errs.append(f"{mid}: conflit avec lui-même")
        if m.get("type") == "feed":
            users = [o for o, om in manifests.items() if m["id"] in om.get("requires", {}).get("feeds", [])]
            if not users:
                errs.append(f"{mid}: feed requis par aucun module")
    return errs


def sarif_results(sarif):
    """Résultats SARIF (après contrôle de structure minimal, G2)."""
    if sarif.get("version") != "2.1.0" or not isinstance(sarif.get("runs"), list) or not sarif["runs"]:
        raise ValueError("SARIF : version 2.1.0 et au moins un « run » attendus")
    out = []
    for run in sarif["runs"]:
        if not isinstance(run.get("tool", {}).get("driver", {}).get("name"), str):
            raise ValueError("SARIF : runs[].tool.driver.name absent")
        for res in run.get("results") or []:
            if not isinstance(res.get("message", {}).get("text"), str):
                raise ValueError("SARIF : results[].message.text absent")
            out.append(res)
    return out


def expect_report(manifest, sarif):
    """[(attente, nombre, réussite)] pour testbed.expect."""
    results = sarif_results(sarif)
    report = []
    for exp in manifest["testbed"]["expect"]:
        n = sum(1 for r in results if r.get("ruleId") == exp["rule"])
        report.append((exp, n, n >= exp["min"]))
    return report


def podman_args(manifest, src, out, feeds, tool=True):
    """Arguments de « podman run » d'un scanner confiné (CLAUDE.md § 6.4)."""
    scan = manifest["scan"]
    res = manifest["resources"]
    args = [
        "run", "--rm", "--pull=never",
        "--network=none" if scan["network"] == "none" else "--network=slirp4netns",
        "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges",
        # Mêmes bornes que l'appliance (testbed.confined_args) : le banc
        # d'essai de la CI doit reproduire exactement celui de l'installation.
        "--user=65534:65534", f"--memory={max(128, min(res['min_ram_mb'], 65536))}m",
        f"--cpus={max(res['min_cpu'], 1)}", "--pids-limit=512",
        "--tmpfs=/tmp:rw,nosuid,nodev,size=256m,mode=1777", "--env=HOME=/tmp", "--env=TMPDIR=/tmp",
        f"--volume={src}:/src:ro", f"--volume={out}:/out:rw",
    ]
    for feed in manifest["requires"]["feeds"]:
        args.append(f"--volume={os.path.join(feeds, feed)}:/feeds/{feed}:ro")
    # Outil de l'appliance (scan.tool) monté en lecture seule sur /scanoria, comme svcnet.tool_mount
    # (tool=False : l'appelant monte lui-même celui de sa racine de test, comme sonar_live).
    if tool and scan.get("tool"):
        tools = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "src", "rootfs", "usr", "lib", "scanoria", "scan-tools")
        args.append(f"--volume={os.path.realpath(os.path.join(tools, scan['tool']))}:/scanoria:ro")
    for k, v in sorted((scan.get("env") or {}).items()):
        args.append(f"--env={k}={v}")
    cmd = render_defaults(manifest, scan["command"])
    args += [f"--entrypoint={cmd[0]}", manifest["image"]] + cmd[1:]
    return args


def render_defaults(manifest, command):
    """{opt.<nom>} remplacé par le défaut de l'option (comme testbed.render_command)."""
    props = (manifest.get("options") or {}).get("properties") or {}

    def value(m):
        v = props[m.group(1)]["default"]
        return ("true" if v else "false") if isinstance(v, bool) else ",".join(v) if isinstance(v, list) else str(v)
    return [re.sub(r"\{opt\.([a-z][a-z0-9_]{0,40})\}", value, a) for a in command]


def main(argv):
    if len(argv) < 2:
        print(__doc__, file=sys.stderr)
        return 2
    cmd, rest = argv[1], argv[2:]
    if cmd == "manifest":
        validators = load_schema()
        bad = 0
        for path in rest:
            m = load_yaml(path)
            errs = manifest_errors(m, validators) if isinstance(m, dict) else ["pas un objet"]
            for e in errs:
                print(f"{os.path.basename(path)}: {e}")  # b10 ignore le préfixe
            bad |= bool(errs)
        return 1 if bad else 0
    if cmd == "repo":
        errs = repo_errors(rest[0])
        for e in errs:
            print(e)
        return 1 if errs else 0
    if cmd == "expect":
        m = load_yaml(rest[0])
        with open(rest[1], encoding="utf-8") as f:
            sarif = json.load(f)
        ok = True
        for exp, n, good in expect_report(m, sarif):
            print(f"{'ok  ' if good else 'FAIL'} {exp.get('rule', '*')} ({exp.get('category', '-')}) : {n} ≥ {exp['min']}")
            ok &= good
        return 0 if ok else 1
    if cmd == "sarif":
        with open(rest[0], encoding="utf-8") as f:
            schema = json.load(f)
        with open(rest[1], encoding="utf-8") as f:
            sarif = json.load(f)
        cls = jsonschema.validators.validator_for(schema)
        errs = [e.message for e in cls(schema).iter_errors(sarif)]
        for e in errs[:20]:
            print(f"SARIF invalide : {e}")
        sarif_results(sarif)
        return 1 if errs else 0
    if cmd == "podman":
        m = load_yaml(rest[0])
        sys.stdout.write("\0".join(podman_args(m, *rest[1:4])) + "\0")
        return 0
    print(f"sous-commande inconnue : {cmd}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
