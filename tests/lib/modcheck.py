# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Vincent Tisseront
"""Contrôles des modules du catalogue (tests/b10-modules.sh, tests/b10-live.sh).

Sous-commandes :
  manifest FICHIER…          valide des manifestes (schéma + règles ci-dessous) ;
                             code 1 et une ligne « id: erreur » par refus
  repo RACINE                valide tous les modules/<id>/module.yaml du dépôt
                             et leurs liens (requires, conflicts, testbed)
  expect MANIFESTE SORTIE    vérifie testbed.expect sur une sortie SARIF, ou
                             CycloneDX (nom des composants, contrat 14 de la 0.5)
  sarif SCHEMA SARIF         valide une sortie contre le schéma SARIF 2.1.0 officiel
  podman MANIFESTE SRC OUT FEEDS [IMAGE]
                             écrit (séparés par NUL) les arguments de « podman
                             run » confinés (CLAUDE.md § 6.4) du scanner ;
                             IMAGE : image construite localement (0.7)
  containerfile FICHIER ID   contrôle un Containerfile d'image d'outil
                             (FROM épinglés, USER 65534, étiquettes OCI)

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
# Images d'outils construites par la CI de Scanoria (0.7, modules/<id>/image/).
FROM_PINNED = re.compile(r"^FROM\s+(?:--platform=\S+\s+)?[a-z0-9-]+(\.[a-z0-9-]+)+(:[0-9]{1,5})?(/[a-z0-9]+([._-]{1,2}[a-z0-9]+)*)+@sha256:[0-9a-f]{64}(\s+AS\s+(?P<alias>[A-Za-z0-9_-]+))?\s*$")
FROM_STAGE = re.compile(r"^FROM\s+(?:--platform=\S+\s+)?([A-Za-z0-9_-]+)(\s+AS\s+[A-Za-z0-9_-]+)?\s*$")
TOOL_IMAGE_REPO = "ghcr.io/vincenttisseront/scanoria-"
OCI_LABELS = ("org.opencontainers.image.source", "org.opencontainers.image.revision",
              "org.opencontainers.image.version", "org.opencontainers.image.licenses")


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



def _output_dir_name(cmd, path, kind):
    """« --output-path /out --output-name kics » (KICS) : <répertoire>/<nom>.<format>."""
    def val(flag):
        return cmd[cmd.index(flag) + 1] if flag in cmd and cmd.index(flag) + 1 < len(cmd) else None
    d, n = val("--output-path"), val("--output-name")
    return bool(d and n) and path == "%s/%s.%s" % (d.rstrip("/"), n, kind)

def scan_errors(manifest):
    errs = []
    scan = manifest.get("scan")
    if not scan:
        return errs
    for name in scan.get("env", {}) or {}:
        if not ENV_NAME.match(name):
            errs.append(f"scan.env: nom de variable invalide : {name!r}")
    for key in ("command", "sbom_command"):
        if any(".." in arg.split("/") for arg in scan.get(key) or []):
            errs.append(f"scan.{key}: chemin avec « .. »")
    props = (manifest.get("options") or {}).get("properties") or {}
    for key in ("command", "history_command", "sbom_command"):
        for arg in scan.get(key) or []:
            for name in re.findall(r"\{opt\.([^}]*)\}", arg):
                if name not in props:
                    errs.append(f"scan.{key}: option inconnue dans {{opt.{name}}}")
    for kind, out in (manifest.get("outputs") or {}).items():
        for key in ("command", "history_command", "sbom_command"):
            # « --output format=/out/fichier » (Syft) compte comme le chemin lui-même.
            if key in scan and not any(a == out["path"] or a.endswith("=" + out["path"]) for a in scan[key]) \
                    and not _output_dir_name(scan[key], out["path"], kind):
                errs.append(f"outputs.{kind}: {out['path']} absent de scan.{key}")
    if "sbom_command" in scan and "sbom" not in scan.get("inputs", []):
        errs.append("scan.sbom_command exige l'entrée « sbom »")
    if scan.get("prefers_sbom") and not scan.get("sbom_command"):
        errs.append("scan.prefers_sbom exige scan.sbom_command")
    if scan.get("requires_sbom") and "sbom" not in scan.get("inputs", []):
        errs.append("scan.requires_sbom exige l'entrée « sbom »")
    if scan.get("service_optional") and not str(scan.get("network", "")).startswith("service:"):
        errs.append("scan.service_optional exige scan.network: service:<id>")
    if "history_command" in scan and scan.get("history") != "full":
        errs.append("scan.history_command exige scan.history: full")
    if "sbom_command" in scan and ("sbom" not in scan.get("inputs", []) or not any(a == "/src/sbom.cdx.json" or a.endswith(":/src/sbom.cdx.json") for a in scan["sbom_command"])):
        errs.append("scan.sbom_command exige l'entrée sbom et lit /src/sbom.cdx.json")
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


def containerfile_errors(path, mid):
    """Règles d'un Containerfile d'image d'outil (docs/MODULES.md § 7)."""
    with open(path, encoding="utf-8") as f:
        text = f.read()
    # Lignes logiques : continuations « \\ » réunies, commentaires écartés.
    logical, cur = [], ""
    for raw in text.splitlines():
        line = raw.strip()
        if not cur and (not line or line.startswith("#")):
            continue
        if line.endswith("\\"):
            cur += line[:-1] + " "
            continue
        logical.append((cur + line).strip())
        cur = ""
    errs = []
    stages, aliases = [], set()
    for ln in logical:
        if ln.split(None, 1)[0] == "FROM":
            m = FROM_PINNED.match(ln)
            st = FROM_STAGE.match(ln)
            if m:
                if m.group("alias"):
                    aliases.add(m.group("alias"))
            elif not (st and st.group(1) in aliases):
                # Seule une étape déjà déclarée (« FROM build ») échappe à l'épinglage.
                errs.append(f"image/Containerfile : FROM non épinglé par empreinte : {ln[:120]}")
            stages.append([])
        elif ln.split(None, 1)[0].upper() == "FROM":
            errs.append(f"image/Containerfile : FROM en majuscules attendu : {ln[:120]}")
            stages.append([])
        elif stages:
            stages[-1].append(ln)
    if not stages:
        errs.append("image/Containerfile : aucun FROM")
    # Utilisateur de l'image finale : dernier USER de la dernière étape seulement.
    final_users = [ln.split(None, 1)[1].strip() if len(ln.split(None, 1)) > 1 else "" for ln in (stages[-1] if stages else []) if ln.split(None, 1)[0].upper() == "USER"]
    if not final_users or final_users[-1] != "65534:65534":
        errs.append("image/Containerfile : la dernière instruction USER de l'étape finale doit être 65534:65534")
    labels = " ".join(ln for ln in logical if ln.split(None, 1)[0].upper() == "LABEL")
    for key in OCI_LABELS:
        if not re.search(r"(^|\s)" + re.escape(key) + r'=("[^"\s][^"]*"|[^"\s]+)', labels):
            errs.append(f"image/Containerfile : étiquette {key} absente ou vide")
    if not re.search(r'(^|\s)io\.scanoria\.module=("?)' + re.escape(mid) + r'\2(\s|$)', labels):
        errs.append(f"image/Containerfile : étiquette io.scanoria.module={mid} absente")
    for ln in logical:
        word = ln.split(None, 1)[0].upper()
        if word == "ADD" and re.search(r"https?://", ln):
            errs.append("image/Containerfile : ADD d'une URL interdit (téléchargement vérifié dans un RUN)")
        if word == "RUN" and re.search(r"\bpip3?\s+install\b", ln) and "--require-hashes" not in ln:
            errs.append("image/Containerfile : pip install sans --require-hashes")
        if word == "RUN" and re.search(r"\b(curl|wget)\b", ln) and "sha256sum" not in ln:
            errs.append("image/Containerfile : téléchargement sans vérification sha256sum dans le même RUN")
    return errs


def image_errors(module_dir, manifest):
    """Image en attente (image_pending) ou construite par la CI : Containerfile présent et conforme."""
    mid = manifest.get("id")
    cf = os.path.join(module_dir, "image", "Containerfile")
    image = manifest.get("image") or ""
    built_here = image.startswith(TOOL_IMAGE_REPO)
    idir = os.path.join(module_dir, "image")
    if os.path.islink(idir):
        return ["image/ : lien symbolique interdit"]
    if os.path.isdir(idir):
        for dirpath, dirnames, filenames in os.walk(idir):
            for n in dirnames + filenames:
                if os.path.islink(os.path.join(dirpath, n)):
                    return [f"image/ : lien symbolique interdit : {os.path.relpath(os.path.join(dirpath, n), idir)}"]
    if not os.path.isfile(cf):
        if manifest.get("image_pending") or built_here:
            return ["image/Containerfile absent (image construite par la CI de Scanoria)"]
        return []
    errs = []
    if image and not image.startswith(f"{TOOL_IMAGE_REPO}{mid}@sha256:"):
        errs.append(f"image : une image construite ici est publiée sous {TOOL_IMAGE_REPO}{mid}@sha256:…")
    return errs + containerfile_errors(cf, mid)


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
            errs += [f"{mid}: {e}" for e in image_errors(mdir, m)]
            manifests[mid] = m
    for mid, m in manifests.items():
        req = m.get("requires", {})
        for dep in req.get("feeds", []):
            if manifests.get(dep, {}).get("type") != "feed":
                errs.append(f"{mid}: requires.feeds cite {dep!r}, qui n'est pas un module feed du dépôt")
        for dep in req.get("modules", []):
            if dep not in manifests or manifests[dep].get("type") == "feed":
                errs.append(f"{mid}: requires.modules cite {dep!r} (absent ou feed)")
            elif manifests[dep].get("image_pending") and not m.get("image_pending"):
                errs.append(f"{mid}: requires.modules cite {dep!r}, en attente d'image (absent de l'index)")
        if mid in m.get("conflicts", []):
            errs.append(f"{mid}: conflit avec lui-même")
        if m.get("type") == "feed":
            users = [o for o, om in manifests.items() if m["id"] in om.get("requires", {}).get("feeds", [])]
            # Un feed exporté pour la console (feed.export, 0.5 contrat 17 : EPSS, KEV)
            # est lu par la console elle-même, sans scanner qui le monte.
            if not users and not (m.get("feed") or {}).get("export"):
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


def cyclonedx_names(doc):
    """Noms des composants d'un SBOM CycloneDX (comme testbed.cyclonedx_components)."""
    if not isinstance(doc.get("specVersion"), str) or not isinstance(doc.get("components", []), list):
        raise ValueError("CycloneDX : specVersion et components attendus")
    return [c.get("name") for c in doc.get("components", []) if isinstance(c, dict)]


def expect_report(manifest, sarif):
    """[(attente, nombre, réussite)] pour testbed.expect."""
    if isinstance(sarif, dict) and sarif.get("bomFormat") == "CycloneDX":
        keys = cyclonedx_names(sarif)
    else:
        keys = [r.get("ruleId") for r in sarif_results(sarif)]
    report = []
    for exp in manifest["testbed"]["expect"]:
        n = sum(1 for k in keys if k == exp["rule"])
        report.append((exp, n, n >= exp["min"]))
    return report


def podman_args(manifest, src, out, feeds, tool=True, image=None):
    """Arguments de « podman run » d'un scanner confiné (CLAUDE.md § 6.4).

    image : image construite localement (module en attente d'image, 0.7)."""
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
    args += [f"--entrypoint={cmd[0]}", image or manifest["image"]] + cmd[1:]
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
        # 5e argument facultatif : image construite localement (module en attente d'image).
        image = rest[4] if len(rest) > 4 and rest[4] else None
        sys.stdout.write("\0".join(podman_args(m, *rest[1:4], image=image)) + "\0")
        return 0
    if cmd == "containerfile":
        errs = containerfile_errors(rest[0], rest[1])
        for e in errs:
            print(e)
        return 1 if errs else 0
    print(f"sous-commande inconnue : {cmd}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
