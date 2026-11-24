# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Vincent Tisseront
"""Contenu de /src et outils lancés selon le contenu (0.6, V6, contrat 23).

Après la récupération de la source, le runner parcourt une fois /src (déjà
borné par fetch.bound_tree : fichiers réguliers et répertoires seulement) et
en tire :
  - l'empreinte du contenu (« tree ») : SHA-256 de la liste triée des
    chemins, modes et SHA-256 des fichiers, telle que les modules la voient.
    Elle entre dans la clé du cache de résultats (V4, contrat 21) ; le .git de
    la racine n'y entre pas (ses paquets varient d'une récupération à l'autre,
    et les modules qui lisent l'historique ne sont jamais réutilisés) ;
  - la détection : nombre de fichiers par clé de la détection F1, calculée sur
    les chemins seuls (jamais sur le contenu), rangée par la console dans
    content_detection ;
  - l'applicabilité : un module qui déclare scan.applies_to ne tourne que si
    au moins un fichier correspond à une de ses clés ou à un de ses motifs.
    Sinon il est « not-applicable » (couverture G15, jamais absent pour G13).
    Les répertoires de dépendances (node_modules, vendor…) comptent : dans le
    doute, le module tourne. Un module sans applies_to tourne toujours, et un
    applies_to mal formé fait tourner le module.
"""

import hashlib
import os
import re
import stat

# Clés de la détection F1 (webui/server/projects/detect.ts), sur les chemins seuls.
_LOCKFILES = {"package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "bun.lock",
              "poetry.lock", "uv.lock", "pdm.lock", "Pipfile.lock", "go.sum", "gradle.lockfile",
              "Cargo.lock", "composer.lock", "Gemfile.lock", "packages.lock.json"}
_MANIFEST_RE = re.compile(r"(package\.json|pyproject\.toml|requirements(-[a-z0-9_-]+)?\.txt|Pipfile|go\.mod|pom\.xml"
                          r"|build\.gradle(\.kts)?|Cargo\.toml|composer\.json|Gemfile|.+\.csproj)\Z")
_EXT = {
    "python": {"py", "pyi"},
    "javascript": {"js", "mjs", "cjs", "jsx", "vue", "svelte", "ts", "tsx", "mts", "cts"},
    "go": {"go"},
    "java": {"java"},
    "shell": {"sh", "bash", "zsh", "ksh"},
    "terraform": {"tf"},
}
_CONTAINER_RE = re.compile(r"(Dockerfile|Containerfile)(\..+)?\Z")
_ANSIBLE_RE = re.compile(r"(^|/)(roles/[^/]+/tasks/main\.ya?ml|(playbooks?/.+|site|playbook)\.ya?ml)\Z")
_CI_RE = re.compile(r"(\.(github|forgejo|gitea)/workflows/[^/]+\.ya?ml|\.gitlab-ci\.yml)\Z")

DETECT_KEYS = ("containers", "terraform", "helm", "ansible", "ci", "shell", "python", "javascript", "go", "java",
               "lockfiles", "manifests")
CHUNK = 1 << 20


def keys_of(rel):
    """Clés de détection d'un chemin relatif (séparateur « / »)."""
    name = rel.rsplit("/", 1)[-1]
    ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
    out = [k for k, exts in _EXT.items() if ext in exts]
    if _CONTAINER_RE.match(name) or re.search(r"\.(dockerfile|containerfile)\Z", name, re.I):
        out.append("containers")
    if name == "Chart.yaml":
        out.append("helm")
    if name == "ansible.cfg" or _ANSIBLE_RE.search(rel):
        out.append("ansible")
    if _CI_RE.match(rel) or name == "Jenkinsfile":
        out.append("ci")
    if name in _LOCKFILES:
        out.append("lockfiles")
    if _MANIFEST_RE.match(name):
        out.append("manifests")
    return out


def _file_sha256(path):
    h = hashlib.sha256()
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as f:
        if not stat.S_ISREG(os.fstat(f.fileno()).st_mode):
            raise OSError("not a regular file")
        for block in iter(lambda: f.read(CHUNK), b""):
            h.update(block)
    return h.hexdigest()


def inspect(root):
    """(tree, detection, chemins) de root, parcouru sans suivre de lien.

    tree : empreinte hexadécimale du contenu (None si un fichier est illisible) ; detection : {clé: nombre} des
    clés présentes ; chemins : liste triée des fichiers (relatifs, « / »)."""
    entries, detection, unknown = [], {}, False
    for d, dirs, names in os.walk(root, topdown=True, followlinks=False):
        reld = os.path.relpath(d, root)
        if reld == ".":
            dirs[:] = [n for n in dirs if n != ".git"]
        dirs.sort()
        for n in sorted(names):
            p = os.path.join(d, n)
            rel = n if reld == "." else "%s/%s" % (reld.replace(os.sep, "/"), n)
            if reld == "." and n == ".git":
                continue
            st = os.lstat(p)
            if not stat.S_ISREG(st.st_mode):
                continue
            try:
                digest = _file_sha256(p) if unknown is False else ""
            except OSError:
                unknown = True     # fichier illisible : empreinte inconnue, aucune réutilisation (V4)
                digest = ""
            entries.append((rel, "x" if st.st_mode & 0o111 else "f", digest))
            for k in keys_of(rel):
                detection[k] = detection.get(k, 0) + 1
    entries.sort()
    if unknown:
        return None, detection, [e[0] for e in entries]
    h = hashlib.sha256(b"scanoria-tree-v1\n")
    for rel, mode, digest in entries:
        h.update(("%s %s %s\n" % (mode, digest, rel)).encode("utf-8", "surrogateescape"))
    return h.hexdigest(), detection, [e[0] for e in entries]


def glob_re(pattern):
    """Expression régulière d'un motif : « ** » tout chemin, « * » un segment,
    « ? » un caractère, {a,b} une alternative, [..] une classe. Un motif sans
    « / » porte sur le nom du fichier, à toute profondeur."""
    if "/" not in pattern:
        pattern = "**/" + pattern
    out, i = [], 0
    while i < len(pattern):
        c = pattern[i]
        if pattern.startswith("**/", i):
            out.append("(?:.*/)?")
            i += 3
            continue
        if pattern.startswith("**", i):
            out.append(".*")
            i += 2
            continue
        if c == "*":
            out.append("[^/]*")
        elif c == "?":
            out.append("[^/]")
        elif c == "{":
            j = pattern.find("}", i)
            if j < 0:
                raise ValueError("unbalanced brace")
            out.append("(?:%s)" % "|".join(re.escape(a) for a in pattern[i + 1:j].split(",")))
            i = j + 1
            continue
        elif c == "[":
            j = pattern.find("]", i + 1)
            if j < 0:
                raise ValueError("unbalanced bracket")
            body = pattern[i + 1:j].replace("\\", "\\\\")
            out.append("[%s]" % (("^" + body[1:]) if body.startswith("!") else body))
            i = j + 1
            continue
        else:
            out.append(re.escape(c))
        i += 1
    return re.compile("".join(out) + r"\Z")


def applies(manifest, detection, paths):
    """None si le module tourne, sinon la raison « no-matching-files »."""
    spec = (manifest.get("scan") or {}).get("applies_to")
    if spec is None:
        return None
    if not isinstance(spec, dict):
        return None
    keys = spec.get("detect") or []
    pats = spec.get("paths") or []
    if not isinstance(keys, list) or not isinstance(pats, list) or (not keys and not pats):
        return None
    if any(isinstance(k, str) and detection.get(k) for k in keys):
        return None
    try:
        res = [glob_re(p) for p in pats if isinstance(p, str) and p and ".." not in p and not p.startswith("/")]
    except (ValueError, re.error):
        return None
    if len(res) != len(pats):
        return None
    for rel in paths:
        if any(r.match(rel) for r in res):
            return None
    return "no-matching-files"
