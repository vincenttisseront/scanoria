# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Vincent Tisseront
"""Index des imports et des appels d'un dépôt (module reach-index, I11).

Usage : python3 -I reach_index.py <sources> <sortie.sarif>

Relève, SANS RIEN EXÉCUTER, les modules importés par le code du dépôt et les
appels faits à travers ces imports, pour que la console puisse dire à l'IA où
une dépendance vulnérable est utilisée (atteignabilité assistée, CLAUDE.md
§ 15, I11). Bibliothèque standard seulement ; tourne dans le conteneur
jetable du scanner (§ 6.4 : aucun réseau, sources en lecture seule).

Analyse par langage :
  - Python : module ast (analyse syntaxique pure, aucun import ni exécution) ;
  - JavaScript et TypeScript, Go, Java : analyse lexicale (expressions
    régulières sur le texte, commentaires retirés).

Le dépôt analysé est hostile : aucun lien symbolique n'est suivi, les
fichiers trop gros et les répertoires de dépendances sont ignorés, toutes les
tailles sont bornées, et un fichier illisible ou invalide est compté puis
ignoré sans faire échouer l'index.

Sortie : SARIF 2.1.0 dont chaque résultat est « informational » (SARIF
§ 3.27.9 : ce n'est pas un problème ; la console ne l'ingère pas comme
résultat d'analyse) :
  ruleId reach-index/import | reach-index/call, emplacement et extrait de la
  ligne, properties { language, module, symbol } ;
  runs[0].properties["scanoria/reach-index"] = { version, languages, files,
  truncated, errors }.
"""

import ast
import json
import os
import re
import stat
import sys
from urllib.parse import quote

VERSION = "1.0.0"
INDEX_VERSION = 1
MAX_FILES = 20000
MAX_FILE_BYTES = 1 << 20
MAX_ENTRIES = 100000
MAX_PER_FILE = 2000
MAX_DEPTH = 40
MAX_EXCERPT = 300
MAX_NAME = 300
SKIP_DIRS = {".git", ".hg", ".svn", "node_modules", "bower_components", "vendor", "third_party",
             ".venv", "venv", "env", "__pycache__", ".tox", ".mypy_cache", "dist", "build", "target",
             ".gradle", ".idea", ".next", ".nuxt", "coverage"}
LANG_BY_EXT = {
    ".py": "python",
    ".js": "javascript", ".mjs": "javascript", ".cjs": "javascript", ".jsx": "javascript",
    ".ts": "typescript", ".tsx": "typescript", ".mts": "typescript", ".cts": "typescript",
    ".go": "go",
    ".java": "java",
}
CTRL_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f  ]")


def clean(text, limit):
    return CTRL_RE.sub(" ", text).strip()[:limit]


class Index:
    def __init__(self):
        self.results = []
        self.languages = set()
        self.files = 0
        self.errors = 0
        self.skipped = 0  # fichiers de code non lus (taille, lien, illisible) et dossiers de code embarqué sautés
        self.truncated = False

    def add(self, kind, path, line, module, symbol, excerpt, language):
        if len(self.results) >= MAX_ENTRIES:
            self.truncated = True
            return False
        self.results.append({
            "ruleId": "reach-index/" + kind,
            "kind": "informational",
            "level": "none",
            "message": {"text": clean("%s %s" % (kind, symbol or module), MAX_NAME)},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": quote(path, safe="/._-~+@")},
                "region": {"startLine": line, "snippet": {"text": clean(excerpt, MAX_EXCERPT)}},
            }}],
            "properties": {"language": language, "module": clean(module, MAX_NAME), "symbol": clean(symbol, MAX_NAME)},
        })
        return True


# --------------------------------------------------------------------------
# Python (ast)
# --------------------------------------------------------------------------

def dotted(node):
    """« a.b.c » d'une expression Name / Attribute, sinon None."""
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    return None


def index_python(text, emit):
    tree = ast.parse(text)
    lines = text.splitlines()
    line_of = lambda n: lines[n - 1] if 0 < n <= len(lines) else ""
    bindings = {}  # nom local → (module, symbole d'origine)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.asname:
                    bindings[a.asname] = (a.name, a.name)
                else:
                    root = a.name.split(".")[0]
                    bindings[root] = (root, root)
                emit("import", node.lineno, a.name, a.asname or a.name, line_of(node.lineno))
        elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
            for a in node.names:
                full = node.module if a.name == "*" else "%s.%s" % (node.module, a.name)
                if a.name != "*":
                    bindings[a.asname or a.name] = (node.module, full)
                emit("import", node.lineno, node.module, a.name, line_of(node.lineno))
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            name = dotted(node.func)
            if not name:
                continue
            root, _, rest = name.partition(".")
            if root not in bindings:
                continue
            module, origin = bindings[root]
            symbol = origin + ("." + rest if rest else "")
            # import a.b puis a.b.f() : le module le plus précis connu est « a.b ».
            emit("call", node.lineno, module, symbol, line_of(node.lineno))


# --------------------------------------------------------------------------
# Analyse lexicale (JavaScript / TypeScript, Go, Java)
# --------------------------------------------------------------------------

def strip_comments(text, hash_comments=False):
    """Retire les commentaires // et /* */ en gardant les sauts de ligne et les chaînes."""
    out, i, n = [], 0, len(text)
    quote_ch = None
    while i < n:
        c = text[i]
        if quote_ch:
            out.append(c)
            if c == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if c == quote_ch or (c == "\n" and quote_ch != "`"):
                quote_ch = None
            i += 1
            continue
        if c in "'\"`":
            quote_ch = c
            out.append(c)
            i += 1
        elif text.startswith("//", i):
            j = text.find("\n", i)
            i = n if j < 0 else j
        elif text.startswith("/*", i):
            j = text.find("*/", i + 2)
            seg = text[i:n if j < 0 else j + 2]
            out.append("\n" * seg.count("\n"))
            i = n if j < 0 else j + 2
        else:
            out.append(c)
            i += 1
    return "".join(out)


class Lines:
    def __init__(self, text):
        self.text = text
        self.raw = text.splitlines()
        self.starts = [0]
        for m in re.finditer("\n", text):
            self.starts.append(m.end())

    def line(self, offset):
        lo, hi = 0, len(self.starts) - 1
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if self.starts[mid] <= offset:
                lo = mid
            else:
                hi = mid - 1
        return lo + 1

    def excerpt(self, line):
        return self.raw[line - 1] if 0 < line <= len(self.raw) else ""


IDENT = r"[A-Za-z_$][\w$]*"
JS_IMPORT_RE = re.compile(r"\bimport\s+(?:type\s+)?([\w$*{}\s,]{1,500}?)\s+from\s*['\"]([^'\"\n]{1,300})['\"]")
JS_SIDE_RE = re.compile(r"\bimport\s*['\"]([^'\"\n]{1,300})['\"]")
JS_EXPORT_FROM_RE = re.compile(r"\bexport\s+[\w$*{}\s,]{1,500}?\s+from\s*['\"]([^'\"\n]{1,300})['\"]")
JS_REQUIRE_RE = re.compile(r"(?:\b(?:const|let|var)\s+(" + IDENT + r"|\{[^}]{0,500}\})\s*=\s*)?\brequire\s*\(\s*['\"]([^'\"\n]{1,300})['\"]\s*\)")
JS_DYNAMIC_RE = re.compile(r"\bimport\s*\(\s*['\"]([^'\"\n]{1,300})['\"]\s*\)")


def js_bindings(clause):
    """Noms liés par « X », « * as ns », « { a as b, c } », « { a, b: c } » → [(local, importé)]."""
    out = []
    clause = clause.strip()
    m = re.match(r"^(" + IDENT + r")\s*(?:,|$)", clause)
    if m and not clause.startswith("{"):
        out.append((m.group(1), "default"))
    m = re.search(r"\*\s*as\s+(" + IDENT + ")", clause)
    if m:
        out.append((m.group(1), "*"))
    m = re.search(r"\{([^}]*)\}", clause)
    if m:
        for part in m.group(1).split(","):
            part = re.sub(r"^\s*type\s+", "", part).strip()
            if not part:
                continue
            a = re.match(r"^(" + IDENT + r")\s*(?:as|:)\s*(" + IDENT + r")$", part)
            if a:
                out.append((a.group(2), a.group(1)))
            elif re.match("^" + IDENT + "$", part):
                out.append((part, part))
    return out


def is_relative(spec):
    return spec.startswith(".") or spec.startswith("/")


def index_calls(code, lines, bindings, emit):
    """Appels B(…), B.m(…), new B(…) pour chaque nom lié par un import."""
    for local, (module, origin) in bindings.items():
        pat = re.compile(r"(?<![\w$.])(new\s+)?" + re.escape(local) + r"(?:\s*\.\s*(" + IDENT + r"))?\s*[(<]")
        for m in pat.finditer(code):
            line = lines.line(m.start())
            member = m.group(2)
            symbol = origin + ("." + member if member else "")
            if not emit("call", line, module, symbol, lines.excerpt(line)):
                return


def index_js(text, emit):
    code = strip_comments(text)
    lines = Lines(code)
    raw = Lines(text)
    bindings = {}
    for m in JS_IMPORT_RE.finditer(code):
        spec = m.group(2)
        if is_relative(spec):
            continue
        line = lines.line(m.start())
        for local, imported in js_bindings(m.group(1)):
            bindings[local] = (spec, imported if imported not in ("default", "*") else spec)
            emit("import", line, spec, local if imported in ("default", "*") else imported, raw.excerpt(line))
    for rx in (JS_SIDE_RE, JS_EXPORT_FROM_RE, JS_DYNAMIC_RE):
        for m in rx.finditer(code):
            spec = m.group(1)
            if not is_relative(spec):
                line = lines.line(m.start())
                emit("import", line, spec, "", raw.excerpt(line))
    for m in JS_REQUIRE_RE.finditer(code):
        spec = m.group(2)
        if is_relative(spec):
            continue
        line = lines.line(m.start())
        target = m.group(1)
        if target and target.startswith("{"):
            for local, imported in js_bindings(target):
                bindings[local] = (spec, imported)
                emit("import", line, spec, imported, raw.excerpt(line))
        else:
            if target:
                bindings[target] = (spec, spec)
            emit("import", line, spec, target or "", raw.excerpt(line))
    index_calls(code, Lines(code), bindings, lambda k, ln, mod, sym, _ex: emit(k, ln, mod, sym, raw.excerpt(ln)))


GO_SINGLE_RE = re.compile(r"^\s*import\s+(?:(" + IDENT + r"|\.|_)\s+)?\"([^\"\n]{1,300})\"", re.M)
GO_BLOCK_RE = re.compile(r"^\s*import\s*\(([^)]*)\)", re.M)
GO_SPEC_RE = re.compile(r"^\s*(?:(" + IDENT + r"|\.|_)\s+)?\"([^\"\n]{1,300})\"", re.M)


def go_default_name(path):
    parts = path.split("/")
    last = parts[-1]
    if re.match(r"^v[0-9]+$", last) and len(parts) > 1:
        last = parts[-2]
    last = re.sub(r"\.v[0-9]+$", "", last)
    last = re.sub(r"^go-", "", last)
    return re.sub(r"[^\w]", "_", last)


def index_go(text, emit):
    code = strip_comments(text)
    lines = Lines(code)
    raw = Lines(text)
    bindings = {}
    specs = []
    for m in GO_SINGLE_RE.finditer(code):
        specs.append((m.start(2), m.group(1), m.group(2)))
    for b in GO_BLOCK_RE.finditer(code):
        for m in GO_SPEC_RE.finditer(b.group(1)):
            specs.append((b.start(1) + m.start(2), m.group(1), m.group(2)))
    for off, alias, path in specs:
        line = lines.line(off)
        emit("import", line, path, alias or "", raw.excerpt(line))
        if alias not in (".", "_"):
            bindings[alias or go_default_name(path)] = (path, path)
    # En Go, seuls les appels qualifiés pkg.F(…) passent par l'import.
    for local, (module, origin) in bindings.items():
        pat = re.compile(r"(?<![\w.])" + re.escape(local) + r"\s*\.\s*(" + IDENT + r")\s*\(")
        for m in pat.finditer(code):
            line = lines.line(m.start())
            if not emit("call", line, module, origin + "." + m.group(1), raw.excerpt(line)):
                return


JAVA_IMPORT_RE = re.compile(r"^\s*import\s+(static\s+)?([A-Za-z_][\w.]*?)(\.\*)?\s*;", re.M)


def index_java(text, emit):
    code = strip_comments(text)
    lines = Lines(code)
    raw = Lines(text)
    bindings = {}
    for m in JAVA_IMPORT_RE.finditer(code):
        name, star, static = m.group(2), m.group(3), m.group(1)
        line = lines.line(m.start(2))
        emit("import", line, name, "*" if star else name.rsplit(".", 1)[-1], raw.excerpt(line))
        if not star:
            local = name.rsplit(".", 1)[-1]
            bindings[local] = ((name.rsplit(".", 1)[0] if static else name), name)
    for local, (module, origin) in bindings.items():
        pat = re.compile(r"(?<![\w.])(new\s+)?" + re.escape(local) + r"(?:\s*\.\s*(" + IDENT + r"))?\s*[(<]")
        for m in pat.finditer(code):
            line = lines.line(m.start())
            if m.group(0).lstrip().startswith("import"):
                continue
            symbol = origin + ("." + m.group(2) if m.group(2) else "")
            if not emit("call", line, module, symbol, raw.excerpt(line)):
                return


INDEXERS = {"python": index_python, "javascript": index_js, "typescript": index_js, "go": index_go, "java": index_java}


# --------------------------------------------------------------------------
# Parcours
# --------------------------------------------------------------------------

def read_regular(path):
    """Contenu d'un fichier ordinaire (jamais un lien), ou None."""
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    except OSError:
        return None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_size > MAX_FILE_BYTES:
            return None
        data = os.read(fd, MAX_FILE_BYTES + 1)
    finally:
        os.close(fd)
    if len(data) > MAX_FILE_BYTES:
        return None
    return data.decode("utf-8", errors="replace")


# Dossiers de code embarqué du projet : sautés, mais l'index se dit alors incomplet.
VENDORED_DIRS = {"vendor", "third_party"}


def walk(root, idx):
    """(chemin relatif, chemin complet, langage), sans suivre de lien, profondeur bornée.

    Ce qui n'est pas lu alors que ce pourrait être du code du projet (lien
    symbolique, dossier de code embarqué, profondeur dépassée) est compté dans
    idx.skipped : un index incomplet ne permet pas de dire « jamais appelé ».
    """
    root = os.path.abspath(root)
    for base, dirs, files in os.walk(root, followlinks=False):
        rel_base = os.path.relpath(base, root)
        depth = 0 if rel_base == "." else rel_base.count(os.sep) + 1
        keep = []
        for d in sorted(dirs):
            if d in SKIP_DIRS:
                if d in VENDORED_DIRS:
                    idx.skipped += 1
                continue
            if os.path.islink(os.path.join(base, d)) or depth >= MAX_DEPTH:
                idx.skipped += 1
                continue
            keep.append(d)
        dirs[:] = keep
        for f in sorted(files):
            lang = LANG_BY_EXT.get(os.path.splitext(f)[1].lower())
            if not lang:
                continue
            full = os.path.join(base, f)
            if os.path.islink(full):
                idx.skipped += 1
                continue
            rel = f if rel_base == "." else os.path.join(rel_base, f)
            yield rel.replace(os.sep, "/"), full, lang


def build(root):
    idx = Index()
    for rel, full, lang in walk(root, idx):
        if idx.files >= MAX_FILES:
            idx.truncated = True
            break
        text = read_regular(full)
        if text is None:
            idx.skipped += 1
            continue
        idx.files += 1
        idx.languages.add(lang)
        count = [0]

        def emit(kind, line, module, symbol, excerpt, rel=rel, lang=lang, count=count):
            if not module or line < 1:
                return True
            count[0] += 1
            if count[0] > MAX_PER_FILE:
                idx.truncated = True
                return False
            return idx.add(kind, rel, line, module, symbol, excerpt, lang)

        try:
            INDEXERS[lang](text, emit)
        except (SyntaxError, ValueError, RecursionError, MemoryError):
            idx.errors += 1
        if idx.truncated and len(idx.results) >= MAX_ENTRIES:
            break
    return idx


def sarif(idx):
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "reach-index",
                "version": VERSION,
                "rules": [
                    {"id": "reach-index/import", "shortDescription": {"text": "Module imported by the code"},
                     "defaultConfiguration": {"level": "none"}},
                    {"id": "reach-index/call", "shortDescription": {"text": "Call through an imported module"},
                     "defaultConfiguration": {"level": "none"}},
                ],
            }},
            "properties": {"scanoria/reach-index": {
                "version": INDEX_VERSION, "languages": sorted(idx.languages), "files": idx.files,
                "truncated": idx.truncated, "errors": idx.errors, "skipped": idx.skipped,
            }},
            "results": idx.results,
        }],
    }


def main(argv):
    if len(argv) != 3:
        print("usage: reach_index.py <sources> <sortie.sarif>", file=sys.stderr)
        return 2
    src, out = argv[1], argv[2]
    if not os.path.isdir(src):
        print("reach-index: sources introuvables", file=sys.stderr)
        return 2
    sys.setrecursionlimit(4000)
    idx = build(src)
    tmp = out + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(sarif(idx), fh, ensure_ascii=False, separators=(",", ":"))
    os.replace(tmp, out)
    print("reach-index: %d fichiers, %d entrées, langages %s%s" % (
        idx.files, len(idx.results), ",".join(sorted(idx.languages)) or "-", ", tronqué" if idx.truncated else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
