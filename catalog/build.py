#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Vincent Tisseront
"""Construction et vérification de l'index du catalogue (CLAUDE.md § 4.3, § 10).

  build.py build  [--root R] [--modules D] [--packs F] [--module-schema F]
                  [--index-schema F] [--version N] [--date EPOCH] [--out D]
  build.py verify RÉPERTOIRE [--pubkey PEM | --no-signature] [--index-schema F]
                  [--expect-version N]
  build.py check-index FICHIER [--index-schema F]

« build » lit modules/*/module.yaml et catalog/packs.yaml, valide chaque
manifeste contre catalog/schema/module.schema.json, contrôle les dépendances et
les conflits (G1) et les packs (F11), empaquette chaque testbed/ en
testbed-<id>-<version>.tar.zst reproductible, puis écrit catalog-index.json et
SHA256SUMS dans le répertoire de sortie (vidé au préalable). Deux constructions
du même arbre, à la même date, donnent les mêmes octets.

« verify » contrôle un répertoire de publication avant et après la release
(mêmes contrôles que le service root de l'appliance, qui a sa propre vérification) :
signature Ed25519 brute de SHA256SUMS (openssl pkeyutl -rawin, même procédé que
le lot de mise à jour), empreintes, index conforme au schéma et cohérent,
archives des bancs d'essai sans lien ni chemin sortant.

YAML : PyYAML (paquet Ubuntu 24.04 python3-yaml, déjà installé en CI), lu par
un chargeur restreint : pas d'alias, pas de clé en double, booléens limités à
true/false, dates laissées en chaînes. Ce script ne tourne qu'à la
construction (CI, poste du développeur), jamais sur l'appliance.
"""

import argparse
import datetime
import hashlib
import io
import json
import os
import re
import stat
import subprocess
import sys
import tarfile

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(DEFAULT_ROOT, "src", "rootfs", "usr", "lib", "scanoria", "py"))

from scanoria.schema import SchemaError, Validator  # noqa: E402

INDEX_NAME = "catalog-index.json"
SUMS_NAME = "SHA256SUMS"
SIG_NAME = "SHA256SUMS.sig"
SIG_SIZE = 64
MAX_YAML = 256 * 1024
MAX_INDEX = 4 * 1024 * 1024
MAX_SUMS = 64 * 1024
MAX_TESTBED_FILES = 2000
MAX_TESTBED_BYTES = 16 * 1024 * 1024
MAX_ARCHIVE = 16 * 1024 * 1024
MAX_MODULES = 500
ZSTD_LEVEL = "-19"
TOOL_DIRS = ("/usr/bin", "/bin", "/usr/local/bin")

ID_RE = re.compile(r"[a-z0-9][a-z0-9-]{1,40}\Z")
NAME_RE = re.compile(r"[A-Za-z0-9._+@-]{1,128}\Z")
SUM_LINE_RE = re.compile(r"([0-9a-f]{64})  ([A-Za-z0-9][A-Za-z0-9._+-]{0,200})\Z")
APPLIANCE_RE = re.compile(r">=(0|[1-9][0-9]{0,3})\.(0|[1-9][0-9]{0,3})\.(0|[1-9][0-9]{0,3})\Z")


class BuildError(Exception):
    pass


# --- YAML restreint -------------------------------------------------------------

def _yaml_loader():
    try:
        import yaml
    except ImportError as e:  # pragma: no cover - dépend de l'environnement
        raise BuildError("PyYAML absent (paquet python3-yaml)") from e

    class Loader(yaml.SafeLoader):
        pass

    # Résolveurs implicites réduits : null, true/false, entiers et flottants
    # décimaux, le reste en chaîne (pas de yes/no/on/off, ni de dates).
    Loader.yaml_implicit_resolvers = {}
    rules = (
        ("tag:yaml.org,2002:null", r"^(?:~|null|Null|NULL|)$", list("~nN") + [""]),
        ("tag:yaml.org,2002:bool", r"^(?:true|True|TRUE|false|False|FALSE)$", list("tTfF")),
        ("tag:yaml.org,2002:int", r"^-?(?:0|[1-9][0-9]*)$", list("-0123456789")),
        ("tag:yaml.org,2002:float", r"^-?(?:0|[1-9][0-9]*)\.[0-9]+(?:[eE][-+]?[0-9]+)?$", list("-0123456789")),
    )
    for tag, rx, first in rules:
        Loader.add_implicit_resolver(tag, re.compile(rx), first)

    def compose_node(self, parent, index):
        if self.check_event(yaml.AliasEvent):
            raise BuildError("YAML : alias interdits")
        return yaml.SafeLoader.compose_node(self, parent, index)

    def construct_mapping(self, node, deep=False):
        seen = set()
        for k, _ in node.value:
            key = self.construct_object(k, deep=True)
            if not isinstance(key, str):
                raise BuildError("YAML : clé non textuelle %r" % (key,))
            if key in seen:
                raise BuildError("YAML : clé en double « %s »" % key)
            seen.add(key)
        return yaml.SafeLoader.construct_mapping(self, node, deep=True)

    Loader.compose_node = compose_node
    Loader.construct_mapping = construct_mapping
    Loader.add_constructor("tag:yaml.org,2002:map", lambda l, n: l.construct_mapping(n))
    return yaml, Loader


def load_yaml(path):
    st = _lstat_regular(path)
    if st.st_size > MAX_YAML:
        raise BuildError("%s : plus de %d octets" % (path, MAX_YAML))
    yaml, loader = _yaml_loader()
    with open(path, "rb") as f:
        raw = f.read()
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as e:
        raise BuildError("%s : UTF-8 invalide" % path) from e
    try:
        docs = list(yaml.load_all(text, Loader=loader))
    except yaml.YAMLError as e:
        raise BuildError("%s : YAML invalide (%s)" % (path, str(e).splitlines()[0])) from e
    if len(docs) != 1:
        raise BuildError("%s : un seul document YAML attendu" % path)
    _check_json_value(docs[0], path)
    return docs[0]


def _check_json_value(v, where, depth=0):
    if depth > 32:
        raise BuildError("%s : imbrication trop profonde" % where)
    if isinstance(v, dict):
        for x in v.values():
            _check_json_value(x, where, depth + 1)
    elif isinstance(v, list):
        for x in v:
            _check_json_value(x, where, depth + 1)
    elif isinstance(v, float):
        if v != v or v in (float("inf"), float("-inf")):
            raise BuildError("%s : nombre non fini" % where)
    elif v is not None and not isinstance(v, (str, int, bool)):
        raise BuildError("%s : valeur de type %s non représentable en JSON" % (where, type(v).__name__))


# --- Utilitaires -----------------------------------------------------------------

def tool(name):
    """Chemin absolu d'un outil système (jamais résolu par PATH)."""
    for d in TOOL_DIRS:
        exe = os.path.join(d, name)
        if os.path.isfile(exe) and os.access(exe, os.X_OK):
            return exe
    raise BuildError("%s absent de %s" % (name, ", ".join(TOOL_DIRS)))


def _lstat_regular(path):
    try:
        st = os.lstat(path)
    except FileNotFoundError as e:
        raise BuildError("fichier absent : %s" % path) from e
    if not stat.S_ISREG(st.st_mode):
        raise BuildError("%s : fichier ordinaire attendu (lien ou fichier spécial refusé)" % path)
    return st


def load_json(path, limit):
    st = _lstat_regular(path)
    if st.st_size > limit:
        raise BuildError("%s : plus de %d octets" % (path, limit))
    with open(path, "rb") as f:
        try:
            return json.loads(f.read().decode("utf-8"),
                              parse_constant=lambda c: _raise(BuildError("%s : constante %s" % (path, c))))
        except (UnicodeDecodeError, ValueError) as e:
            raise BuildError("%s : JSON invalide (%s)" % (path, e)) from e


def _raise(e):
    raise e


def validator(path):
    try:
        return Validator(load_json(path, 1 << 20))
    except SchemaError as e:
        raise BuildError("%s : schéma non pris en charge (%s)" % (path, e)) from e


def validate(v, value, what):
    errs = v.errors(value)
    if errs:
        raise BuildError("%s non conforme au schéma : %s" % (what, "; ".join(errs[:10])))


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def dump_json(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False) + "\n").encode("utf-8")


def iso_date(epoch):
    return datetime.datetime.fromtimestamp(epoch, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def source_epoch(root, explicit):
    if explicit is not None:
        return explicit
    env = os.environ.get("SOURCE_DATE_EPOCH", "")
    if env:
        if not re.fullmatch(r"[0-9]{1,12}", env):
            raise BuildError("SOURCE_DATE_EPOCH invalide")
        return int(env)
    try:
        out = subprocess.run([tool("git"), "-C", root, "log", "-1", "--format=%ct"],
                             capture_output=True, text=True, check=True, timeout=30).stdout.strip()
        return int(out)
    except (OSError, subprocess.SubprocessError, ValueError, BuildError) as e:
        raise BuildError("date de construction inconnue : --date ou SOURCE_DATE_EPOCH") from e


def read_catalog_version(path):
    _lstat_regular(path)
    with open(path, encoding="utf-8") as f:
        v = f.read().strip()
    if not re.fullmatch(r"[1-9][0-9]{0,8}", v):
        raise BuildError("%s : entier positif attendu, obtenu « %s »" % (path, v))
    return int(v)


# --- Bancs d'essai -----------------------------------------------------------------

def _testbed_files(base):
    """Fichiers du banc d'essai, triés ; refuse liens, fichiers spéciaux et noms douteux."""
    files = []
    total = 0
    for cur, dirs, names in os.walk(base, followlinks=False):
        dirs.sort()
        for d in list(dirs):
            p = os.path.join(cur, d)
            if not NAME_RE.fullmatch(d) or d in (".", ".."):
                raise BuildError("banc d'essai : nom de répertoire refusé %r" % p)
            if os.path.islink(p):
                raise BuildError("banc d'essai : lien symbolique refusé : %s" % p)
        for n in sorted(names):
            p = os.path.join(cur, n)
            if not NAME_RE.fullmatch(n):
                raise BuildError("banc d'essai : nom de fichier refusé %r" % p)
            st = os.lstat(p)
            if stat.S_ISLNK(st.st_mode):
                raise BuildError("banc d'essai : lien symbolique refusé : %s" % p)
            if not stat.S_ISREG(st.st_mode):
                raise BuildError("banc d'essai : seuls les fichiers ordinaires sont admis : %s" % p)
            if st.st_nlink > 1:
                raise BuildError("banc d'essai : lien physique refusé : %s" % p)
            total += st.st_size
            files.append((os.path.relpath(p, base).replace(os.sep, "/"), p, bool(st.st_mode & 0o111)))
            if len(files) > MAX_TESTBED_FILES or total > MAX_TESTBED_BYTES:
                raise BuildError("banc d'essai trop gros : %s" % base)
    if not files:
        raise BuildError("banc d'essai vide : %s" % base)
    return sorted(files)


def make_testbed_archive(base, dest, epoch):
    """tar USTAR reproductible (préfixe testbed/, mtime fixe, root:root, modes 0644/0755), zstd."""
    files = _testbed_files(base)
    dirs = set()
    for rel, _, _ in files:
        parts = rel.split("/")[:-1]
        for i in range(1, len(parts) + 1):
            dirs.add("/".join(parts[:i]))
    entries = [(d, None, True) for d in dirs] + files
    entries.sort(key=lambda e: e[0])
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.USTAR_FORMAT) as tf:
        top = tarfile.TarInfo("testbed")
        _norm(top, epoch, tarfile.DIRTYPE, 0o755)
        tf.addfile(top)
        for rel, path, flag in entries:
            if path is None:
                ti = tarfile.TarInfo("testbed/" + rel)
                _norm(ti, epoch, tarfile.DIRTYPE, 0o755)
                tf.addfile(ti)
                continue
            with open(path, "rb") as f:
                data = f.read()
            ti = tarfile.TarInfo("testbed/" + rel)
            _norm(ti, epoch, tarfile.REGTYPE, 0o755 if flag else 0o644)
            ti.size = len(data)
            try:
                tf.addfile(ti, io.BytesIO(data))
            except ValueError as e:
                raise BuildError("banc d'essai : chemin trop long pour USTAR : %s" % rel) from e
    try:
        r = subprocess.run([tool("zstd"), "-q", ZSTD_LEVEL, "-T1", "-c"], input=buf.getvalue(),
                           capture_output=True, check=True, timeout=600)
    except subprocess.CalledProcessError as e:
        raise BuildError("zstd en échec : %s" % e.stderr.decode("utf-8", "replace")) from e
    if len(r.stdout) > MAX_ARCHIVE:
        raise BuildError("archive du banc d'essai > %d octets : %s" % (MAX_ARCHIVE, dest))
    with open(dest, "wb") as f:
        f.write(r.stdout)


def _norm(ti, epoch, kind, mode):
    ti.type = kind
    ti.mode = mode
    ti.mtime = epoch
    ti.uid = ti.gid = 0
    ti.uname = ti.gname = ""


def _decompress_capped(path, limit):
    """zstd -d en flux, arrêté dès que la sortie dépasse limit octets."""
    try:
        proc = subprocess.Popen([tool("zstd"), "-q", "-d", "-c", "--", path],
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    except OSError as e:
        raise BuildError("%s : décompression impossible" % path) from e
    chunks, total = [], 0
    try:
        while True:
            chunk = proc.stdout.read(1 << 16)
            if not chunk:
                break
            total += len(chunk)
            if total > limit:
                raise BuildError("%s : contenu décompressé trop gros" % path)
            chunks.append(chunk)
        if proc.wait(timeout=600) != 0:
            raise BuildError("%s : décompression impossible" % path)
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()
        proc.stdout.close()
    return b"".join(chunks)


def check_testbed_archive(path):
    """Contrôle d'une archive publiée : membres ordinaires ou répertoires sous testbed/."""
    st = _lstat_regular(path)
    if st.st_size > MAX_ARCHIVE:
        raise BuildError("%s : archive trop grosse" % path)
    raw = _decompress_capped(path, MAX_TESTBED_BYTES + (MAX_TESTBED_FILES * 2 + 2) * 1024)
    seen = set()
    try:
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as tf:
            for m in tf.getmembers():
                n = m.name
                parts = n.split("/")
                if (n != "testbed" and not n.startswith("testbed/")) or n.startswith("/") \
                        or any(p in ("", ".", "..") for p in parts) or "\\" in n:
                    raise BuildError("%s : chemin refusé %r" % (path, n))
                if not (m.isreg() or m.isdir()):
                    raise BuildError("%s : membre non ordinaire %r" % (path, n))
                if n in seen:
                    raise BuildError("%s : membre en double %r" % (path, n))
                seen.add(n)
    except tarfile.TarError as e:
        raise BuildError("%s : archive tar invalide" % path) from e


# --- Dépendances, conflits, packs (G1, F11) ------------------------------------------

def check_graph(modules, packs):
    """modules : {id: entrée}. Refuse dépendances introuvables, cycles et conflits."""
    for mid, m in modules.items():
        req = m["requires"]
        for r in req.get("modules", []):
            if r == mid:
                raise BuildError("%s : se requiert lui-même" % mid)
            if r not in modules:
                raise BuildError("%s : module requis introuvable « %s »" % (mid, r))
            if modules[r]["type"] == "feed":
                raise BuildError("%s : « %s » est une base (feed), à déclarer dans requires.feeds" % (mid, r))
        for r in req.get("feeds", []):
            if r not in modules:
                raise BuildError("%s : base requise introuvable « %s »" % (mid, r))
            if modules[r]["type"] != "feed":
                raise BuildError("%s : « %s » n'est pas une base (feed)" % (mid, r))
        if "appliance" in req and not APPLIANCE_RE.fullmatch(str(req["appliance"])):
            raise BuildError("%s : requires.appliance doit être de la forme >=X.Y.Z" % mid)
        for c in m["conflicts"]:
            if c == mid:
                raise BuildError("%s : en conflit avec lui-même" % mid)
            if c not in modules:
                raise BuildError("%s : conflit avec un module introuvable « %s »" % (mid, c))

    closures = {}

    def closure(mid, stack):
        if mid in closures:
            return closures[mid]
        if mid in stack:
            raise BuildError("dépendance circulaire : %s" % " → ".join(stack + [mid]))
        req = modules[mid]["requires"]
        out = {mid}
        for r in list(req.get("modules", [])) + list(req.get("feeds", [])):
            out |= closure(r, stack + [mid])
        closures[mid] = frozenset(out)
        return closures[mid]

    def conflicts_in(group, what):
        for x in sorted(group):
            for c in modules[x]["conflicts"]:
                if c in group:
                    raise BuildError("%s : « %s » est en conflit avec « %s »" % (what, x, c))

    for mid in sorted(modules):
        conflicts_in(closure(mid, []), "module " + mid)

    seen = set()
    for p in packs:
        if p["id"] in seen:
            raise BuildError("pack en double : %s" % p["id"])
        seen.add(p["id"])
        group = set()
        for mid in p["modules"]:
            if mid not in modules:
                raise BuildError("pack %s : module absent du catalogue « %s »" % (p["id"], mid))
            if modules[mid]["type"] == "feed":
                raise BuildError("pack %s : « %s » est une base, installée par dépendance" % (p["id"], mid))
            group |= closure(mid, [])
        conflicts_in(group, "pack " + p["id"])


def check_index(index, index_validator):
    """Schéma puis cohérence interne (identifiants uniques, archives, graphe)."""
    validate(index_validator, index, INDEX_NAME)
    modules = {}
    for m in index["modules"]:
        if m["id"] in modules:
            raise BuildError("module en double dans l'index : %s" % m["id"])
        want = "testbed-%s-%s.tar.zst" % (m["id"], m["version"])
        if m.get("testbed_archive") not in (None, want):
            raise BuildError("%s : testbed_archive attendu « %s »" % (m["id"], want))
        modules[m["id"]] = m
    hostnames = {}
    for m in index["modules"]:
        h = m.get("hostname")
        if h is not None:
            if h in hostnames:
                raise BuildError("libellé DNS « %s » en double : %s et %s" % (h, hostnames[h], m["id"]))
            hostnames[h] = m["id"]
    ids = [m["id"] for m in index["modules"]]
    if ids != sorted(ids):
        raise BuildError("modules de l'index non triés par identifiant")
    check_graph(modules, index["packs"])
    return modules


# --- Construction -----------------------------------------------------------------------

def normalize(manifest):
    m = json.loads(json.dumps(manifest))
    req = m.get("requires") or {}
    m["requires"] = dict(req, modules=list(req.get("modules") or []), feeds=list(req.get("feeds") or []))
    m["conflicts"] = list(m.get("conflicts") or [])
    return m


OUT_FILE_RE = re.compile(r"(catalog-index\.json|SHA256SUMS(\.sig)?|testbed-[A-Za-z0-9._+-]+\.tar\.zst)\Z")


def prepare_out(out):
    """Crée ou vide la sortie, sans jamais effacer autre chose que des fichiers du catalogue."""
    if not os.path.lexists(out):
        os.makedirs(out)
        return
    if os.path.islink(out) or not os.path.isdir(out):
        raise BuildError("sortie : répertoire attendu : %s" % out)
    names = os.listdir(out)
    for n in names:
        p = os.path.join(out, n)
        if not OUT_FILE_RE.fullmatch(n) or os.path.islink(p) or not os.path.isfile(p):
            raise BuildError("sortie %s : contient « %s », étranger au catalogue (rien effacé)" % (out, n))
    for n in names:
        os.unlink(os.path.join(out, n))


def build(a):
    root = os.path.abspath(a.root)
    modules_dir = a.modules or os.path.join(root, "modules")
    packs_file = a.packs or os.path.join(root, "catalog", "packs.yaml")
    mod_v = validator(a.module_schema or os.path.join(root, "catalog", "schema", "module.schema.json"))
    idx_v = validator(a.index_schema or os.path.join(root, "catalog", "schema", "index.schema.json"))
    packs_v = validator(os.path.join(HERE, "schema", "packs.schema.json"))
    version = a.version if a.version is not None else read_catalog_version(os.path.join(root, "catalog", "VERSION"))
    epoch = source_epoch(root, a.date)
    out = os.path.abspath(a.out or os.path.join(root, "out", "catalog"))

    if not os.path.isdir(modules_dir):
        raise BuildError("répertoire des modules absent : %s" % modules_dir)
    ids = sorted(d for d in os.listdir(modules_dir) if not d.startswith("."))
    if not ids:
        raise BuildError("aucun module dans %s" % modules_dir)
    if len(ids) > MAX_MODULES:
        raise BuildError("trop de modules")

    prepare_out(out)

    entries = []
    for mid in ids:
        mdir = os.path.join(modules_dir, mid)
        if os.path.islink(mdir) or not os.path.isdir(mdir):
            raise BuildError("modules/%s : répertoire attendu" % mid)
        if not ID_RE.fullmatch(mid):
            raise BuildError("modules/%s : identifiant de répertoire refusé" % mid)
        manifest = load_yaml(os.path.join(mdir, "module.yaml"))
        validate(mod_v, manifest, "modules/%s/module.yaml" % mid)
        if not isinstance(manifest, dict) or manifest.get("id") != mid:
            raise BuildError("modules/%s/module.yaml : id ≠ nom du répertoire" % mid)
        m = normalize(manifest)
        tb = m.get("testbed")
        if tb is None:
            if m.get("type") == "scanner":
                raise BuildError("%s : un scanner livre un banc d'essai (F12)" % mid)
            m["testbed_archive"] = m["testbed_sha256"] = None
        else:
            rel = str(tb.get("path", "")).rstrip("/")
            if not rel or rel.startswith("/") or any(p in ("", ".", "..") for p in rel.split("/")):
                raise BuildError("%s : testbed.path refusé « %s »" % (mid, tb.get("path")))
            base = os.path.join(mdir, *rel.split("/"))
            cur = mdir
            for part in rel.split("/"):
                cur = os.path.join(cur, part)
                if os.path.islink(cur):
                    raise BuildError("%s : testbed.path traverse un lien" % mid)
            if not os.path.isdir(base):
                raise BuildError("%s : banc d'essai absent : %s" % (mid, base))
            name = "testbed-%s-%s.tar.zst" % (mid, m.get("version"))
            if not SUM_LINE_RE.fullmatch("0" * 64 + "  " + name):
                raise BuildError("%s : version impropre à un nom d'archive" % mid)
            dest = os.path.join(out, name)
            make_testbed_archive(base, dest, epoch)
            m["testbed_archive"] = name
            m["testbed_sha256"] = sha256_file(dest)
        entries.append(m)

    packs_doc = load_yaml(packs_file)
    validate(packs_v, packs_doc, os.path.relpath(packs_file, root))
    index = {
        "schema": 1,
        "version": version,
        "generated_at": iso_date(epoch),
        "modules": entries,
        "packs": packs_doc["packs"],
    }
    check_index(index, idx_v)
    data = dump_json(index)
    if len(data) > MAX_INDEX:
        raise BuildError("index > %d octets" % MAX_INDEX)
    with open(os.path.join(out, INDEX_NAME), "wb") as f:
        f.write(data)
    names = [INDEX_NAME] + sorted(m["testbed_archive"] for m in entries if m["testbed_archive"])
    with open(os.path.join(out, SUMS_NAME), "w", encoding="ascii", newline="\n") as f:
        for n in names:
            f.write("%s  %s\n" % (sha256_file(os.path.join(out, n)), n))
    print("catalogue %d : %d modules, %d packs, %d bancs d'essai → %s"
          % (version, len(entries), len(index["packs"]), len(names) - 1, out))
    return 0


# --- Vérification d'un répertoire de publication ----------------------------------------------

def read_sums(path):
    st = _lstat_regular(path)
    if st.st_size > MAX_SUMS:
        raise BuildError("SHA256SUMS trop gros")
    with open(path, "rb") as f:
        raw = f.read()
    if not raw.endswith(b"\n"):
        raise BuildError("SHA256SUMS : fin de ligne finale absente")
    try:
        lines = raw.decode("ascii").split("\n")[:-1]
    except UnicodeDecodeError as e:
        raise BuildError("SHA256SUMS : ASCII attendu") from e
    sums = {}
    for line in lines:
        mt = SUM_LINE_RE.fullmatch(line)
        if not mt:
            raise BuildError("SHA256SUMS : ligne mal formée %r" % line)
        if mt.group(2) in sums:
            raise BuildError("SHA256SUMS : fichier en double %s" % mt.group(2))
        sums[mt.group(2)] = mt.group(1)
    if lines[:1] != ["%s  %s" % (sums.get(INDEX_NAME, ""), INDEX_NAME)]:
        raise BuildError("SHA256SUMS : catalog-index.json attendu en première ligne")
    return sums


def verify(a):
    d = os.path.abspath(a.dir)
    sums_path = os.path.join(d, SUMS_NAME)
    if not a.no_signature:
        if not a.pubkey:
            raise BuildError("--pubkey ou --no-signature obligatoire")
        sig = os.path.join(d, SIG_NAME)
        if _lstat_regular(sig).st_size != SIG_SIZE:
            raise BuildError("SHA256SUMS.sig : signature brute de 64 octets attendue")
        _lstat_regular(sums_path)
        r = subprocess.run([tool("openssl"), "pkeyutl", "-verify", "-pubin", "-inkey", a.pubkey, "-rawin",
                            "-in", sums_path, "-sigfile", sig], capture_output=True, timeout=60)
        if r.returncode != 0:
            raise BuildError("signature de SHA256SUMS invalide")
    sums = read_sums(sums_path)
    allowed = set(sums) | {SUMS_NAME} | (set() if a.no_signature else {SIG_NAME})
    extra = sorted(set(os.listdir(d)) - allowed)
    if extra:
        raise BuildError("fichiers absents de SHA256SUMS : %s" % ", ".join(extra))
    for name, want in sums.items():
        p = os.path.join(d, name)
        _lstat_regular(p)
        if sha256_file(p) != want:
            raise BuildError("empreinte non conforme : %s" % name)
    idx_v = validator(a.index_schema or os.path.join(HERE, "schema", "index.schema.json"))
    index = load_json(os.path.join(d, INDEX_NAME), MAX_INDEX)
    modules = check_index(index, idx_v)
    if a.expect_version is not None and index["version"] != a.expect_version:
        raise BuildError("version de l'index %s ≠ %s attendue" % (index["version"], a.expect_version))
    listed = {m["testbed_archive"]: m for m in modules.values() if m["testbed_archive"]}
    if set(listed) != set(sums) - {INDEX_NAME}:
        raise BuildError("SHA256SUMS et index ne listent pas les mêmes archives")
    for name, m in listed.items():
        if m["testbed_sha256"] != sums[name]:
            raise BuildError("%s : testbed_sha256 ≠ SHA256SUMS" % name)
        check_testbed_archive(os.path.join(d, name))
    print("catalogue %d vérifié%s : %d modules, %d archives"
          % (index["version"], "" if a.no_signature else " (signature valide)", len(modules), len(listed)))
    return 0


def check_index_cmd(a):
    idx_v = validator(a.index_schema or os.path.join(HERE, "schema", "index.schema.json"))
    index = load_json(a.file, MAX_INDEX)
    check_index(index, idx_v)
    print("index conforme")
    return 0


def main(argv=None):
    p = argparse.ArgumentParser(description="Index du catalogue Scanoria")
    sub = p.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("build")
    b.add_argument("--root", default=DEFAULT_ROOT)
    b.add_argument("--modules")
    b.add_argument("--packs")
    b.add_argument("--module-schema")
    b.add_argument("--index-schema")
    b.add_argument("--version", type=int)
    b.add_argument("--date", type=int)
    b.add_argument("--out")
    v = sub.add_parser("verify")
    v.add_argument("dir")
    v.add_argument("--pubkey")
    v.add_argument("--no-signature", action="store_true")
    v.add_argument("--index-schema")
    v.add_argument("--expect-version", type=int)
    c = sub.add_parser("check-index")
    c.add_argument("file")
    c.add_argument("--index-schema")
    a = p.parse_args(argv)
    try:
        return {"build": build, "verify": verify, "check-index": check_index_cmd}[a.cmd](a)
    except BuildError as e:
        print("catalog: ERREUR : %s" % e, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
