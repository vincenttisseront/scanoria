# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Vincent Tisseront
"""Vulnhuntr (K3, 0.7) dans le conteneur du module, relié au relais IA.

Usage : vulnhuntr_sarif.py /src /out/<nom>.sarif [confiance minimale 1..10]
        vulnhuntr_sarif.py --convert [confiance] < vulnhuntr.log > sortie.sarif
          (conversion seule ; sources = répertoire courant)

Vulnhuntr (Protect AI, AGPL-3.0, sources livrées non modifiées dans vendor/)
suit, fichier Python par fichier Python, les chaînes d'appel de l'entrée
utilisateur jusqu'à la sortie pour trouver des failles exploitables à distance
(LFI, RCE, SSRF, AFO, SQLI, XSS, IDOR). Il interroge un modèle par l'API
compatible OpenAI (« -l gpt ») : ici, toujours le relais de scanoria-ai
(OPENAI_BASE_URL, jeton éphémère OPENAI_API_KEY, modèle SCANORIA_AI_MODEL
choisi par l'appliance), qui masque les secrets et journalise. Jamais
Anthropic ni un Ollama direct : leurs variables sont retirées.

Le dépôt n'est jamais lu directement : seuls ses fichiers Python réguliers
(aucun lien symbolique, taille et nombre bornés, dossiers de dépendances
exclus) et son README sont copiés dans un répertoire de travail en /tmp, que
Vulnhuntr analyse. Il n'exécute rien : jedi et parso lisent le code.

Vulnhuntr n'a pas de sortie structurée : son journal JSON (structlog,
vulnhuntr.log) porte chaque rapport (pydantic Response). Le dernier rapport
de chaque couple (fichier, type de faille) devient un résultat SARIF si sa
confiance atteint le seuil (7 par défaut, recommandation amont). Ces
résultats sont marqués « IA » par l'appliance et restent hors verdict tant
qu'une personne ne les a pas confirmés.

Codes de sortie : 0 analyse terminée ; 2 usage ; 3 modèle injoignable ou
réponse invalide (panne d'infrastructure, jamais « aucun résultat »).
"""

import hashlib
import json
import os
import re
import shutil
import stat
import sys
import tempfile
import traceback
from urllib.parse import quote

VENDOR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vendor")
VERSION = "0.1.0+ead88c5"
SKIP_DIRS = {".git", "node_modules", "vendor", "site-packages", ".venv", "venv", "__pycache__", ".tox", "dist", "build"}
MAX_FILES = 2000
MAX_FILE_BYTES = 512 * 1024
MAX_TOTAL_BYTES = 32 * 1024 * 1024
MAX_LOG_BYTES = 64 * 1024 * 1024
MAX_RESULTS = 500
CTRL_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f\u200b-\u200f\u202a-\u202e\u2066-\u2069\ufeff]")
README_RE = re.compile(r"^readme(\.[a-z]{1,4})?$", re.I)
PATH_RE = re.compile(r"""(?:PosixPath|WindowsPath|Path)\(['"](.+)['"]\)$""")

TYPES = {
    "LFI": ("Local file inclusion", ["CWE-22", "CWE-98"]),
    "RCE": ("Remote code execution", ["CWE-94", "CWE-78"]),
    "SSRF": ("Server-side request forgery", ["CWE-918"]),
    "AFO": ("Arbitrary file overwrite", ["CWE-73"]),
    "SQLI": ("SQL injection", ["CWE-89"]),
    "XSS": ("Cross-site scripting", ["CWE-79"]),
    "IDOR": ("Insecure direct object reference", ["CWE-639"]),
}


def clean(value, limit=1000):
    return CTRL_RE.sub(" ", str(value if value is not None else "")).strip()[:limit]


def copy_tree(src, work):
    """Copie les fichiers Python réguliers et le README du dépôt ; nombre de fichiers copiés."""
    count, total = 0, 0
    for name in sorted(os.listdir(src)):
        p = os.path.join(src, name)
        if README_RE.match(name) and stat.S_ISREG(os.lstat(p).st_mode) and os.lstat(p).st_size <= MAX_FILE_BYTES:
            shutil.copyfile(p, os.path.join(work, name), follow_symlinks=False)
    for root, dirs, files in os.walk(src, followlinks=False):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS and not os.path.islink(os.path.join(root, d)))
        for f in sorted(files):
            if not f.endswith(".py"):
                continue
            p = os.path.join(root, f)
            try:
                st = os.lstat(p)
            except OSError:
                continue
            if not stat.S_ISREG(st.st_mode) or st.st_size > MAX_FILE_BYTES or total + st.st_size > MAX_TOTAL_BYTES:
                continue
            dst = os.path.join(work, os.path.relpath(p, src))
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            shutil.copyfile(p, dst, follow_symlinks=False)
            count += 1
            total += st.st_size
            if count >= MAX_FILES:
                return count
    return count


def _path(value, work):
    """Chemin relatif au dépôt d'un fichier cité par le journal, ou None s'il en sort."""
    if not isinstance(value, str) or not value:
        return None
    m = PATH_RE.match(value)
    p = m.group(1) if m else value
    rel = os.path.relpath(os.path.normpath(os.path.join(work, p)), os.path.normpath(work)).replace(os.sep, "/")
    if rel == "." or rel == ".." or rel.startswith("../") or rel.startswith("/"):
        return None
    return rel


def reports(log_lines, work):
    """{(fichier, type) : rapport} : dernier rapport de chaque type, à défaut le rapport initial."""
    initial, final, current, last_key = {}, {}, None, None
    for line in log_lines:
        try:
            ev = json.loads(line)
        except ValueError:
            continue
        if not isinstance(ev, dict):
            continue
        event = ev.get("event")
        if event == "Performing initial analysis":
            current = _path(ev.get("file"), work)
        elif event == "Initial analysis complete" and current and isinstance(ev.get("report"), dict):
            initial[current] = ev["report"]
        elif event == "Performing vuln-specific analysis":
            current = _path(ev.get("file"), work) or current
            last_key = (current, str(ev.get("vuln_type") or "").split(".")[-1].upper())
            final.setdefault(last_key, None)
        elif event == "Secondary analysis complete" and isinstance(ev.get("secondary_analysis_report"), dict):
            if last_key and last_key[0]:
                final[last_key] = ev["secondary_analysis_report"]
    out = {}
    for f, rep in initial.items():
        for vt in rep.get("vulnerability_types") or []:
            vt = str(vt).split(".")[-1].upper()
            if vt in TYPES:
                out[(f, vt)] = rep
    for (f, vt), rep in final.items():
        if rep is not None and vt in TYPES:
            out[(f, vt)] = rep
    return out


def _line(work, rel, rep):
    """Ligne de la première citation de code du rapport retrouvée dans le fichier, sinon 1."""
    wanted = [clean(c.get("code_line"), 300) for c in (rep.get("context_code") or []) if isinstance(c, dict)]
    wanted = [w for w in wanted if len(w) >= 6]
    if not wanted:
        return 1
    try:
        with open(os.path.join(work, rel), encoding="utf-8", errors="replace") as fh:
            for i, line in enumerate(fh, 1):
                if any(w in line for w in wanted):
                    return i
    except OSError:
        pass
    return 1


def sarif(found, work, min_conf, tool_version=None):
    rules, results = {}, []
    for (rel, vt), rep in sorted(found.items()):
        try:
            conf = int(rep.get("confidence_score") or 0)
        except (TypeError, ValueError):
            conf = 0
        types = [str(t).split(".")[-1].upper() for t in rep.get("vulnerability_types") or []]
        if conf < min_conf or (types and vt not in types) or len(results) >= MAX_RESULTS:
            continue
        rid = "vulnhuntr/" + vt.lower()
        title, cwes = TYPES[vt]
        if rid not in rules:
            rules[rid] = {
                "id": rid, "name": vt,
                "shortDescription": {"text": title},
                "fullDescription": {"text": "%s reachable from remote user input, found by an AI-driven call-chain analysis (Vulnhuntr)." % title},
                "properties": {"tags": ["security", "ai", "python"] + cwes},
            }
        line = _line(work, rel, rep)
        results.append({
            "ruleId": rid,
            "level": "error" if conf >= 9 else "warning",
            "message": {"text": clean("%s (confidence %d/10): %s" % (title, conf, clean(rep.get("analysis"), 900)), 1000)},
            "partialFingerprints": {"vulnhuntr/v1": hashlib.sha256(("%s|%s" % (rel, rid)).encode()).hexdigest()},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": quote(rel), "uriBaseId": "SRCROOT"},
                "region": {"startLine": max(1, line)},
            }}],
            "properties": {"confidence": conf, "vulnerabilityType": vt, "poc": clean(rep.get("poc"), 600)},
        })
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "vulnhuntr", "version": tool_version or VERSION,
                                "informationUri": "https://github.com/protectai/vulnhuntr", "rules": list(rules.values())}},
            "originalUriBaseIds": {"SRCROOT": {"uri": "file:///src/"}},
            "results": results,
            "properties": {"scanoria/min-confidence": min_conf},
        }],
    }


def read_log(path):
    try:
        if os.path.getsize(path) > MAX_LOG_BYTES:
            return []
        with open(path, encoding="utf-8", errors="replace") as fh:
            return fh.read().splitlines()
    except OSError:
        return []


SRC_DIR = "/src"
OUT_DIR = "/out"
NAME_RE = re.compile(r"[A-Za-z0-9._-]{1,100}")


def out_path(arg, ext):
    """Chemin de sortie reconstruit sous OUT_DIR depuis un nom validé ; None si l'argument n'est pas /out/<nom><ext>."""
    if os.path.dirname(arg) != OUT_DIR:
        return None
    m = NAME_RE.fullmatch(os.path.basename(arg))
    if not m or not m.group(0).endswith(ext) or m.group(0) in (".", ".."):
        return None
    path = os.path.realpath(os.path.join(OUT_DIR, m.group(0)))
    return path if os.path.dirname(path) == os.path.realpath(OUT_DIR) else None


def write(doc, out):
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(doc, fh)
    print("vulnhuntr: %d result(s)" % len(doc["runs"][0]["results"]))


def analyse(src, out, min_conf):
    for k in list(os.environ):
        if k.startswith(("ANTHROPIC_", "OLLAMA_")):
            del os.environ[k]
    if not os.environ.get("OPENAI_BASE_URL") or not os.environ.get("OPENAI_API_KEY"):
        print("vulnhuntr: relais IA absent (OPENAI_BASE_URL)", file=sys.stderr)
        return 3
    os.environ["OPENAI_MODEL"] = os.environ.get("SCANORIA_AI_MODEL") or "scanoria"
    base = tempfile.mkdtemp(prefix="vulnhuntr-")
    work = os.path.join(base, "repo")
    os.makedirs(work)
    n = copy_tree(src, work)
    if n == 0:
        write(sarif({}, work, min_conf), out)
        return 0
    # Journal structlog et .env éventuel lus dans le répertoire courant : jamais celui du dépôt.
    os.chdir(base)
    sys.path.insert(0, VENDOR)
    sys.argv = ["vulnhuntr", "-r", work, "-l", "gpt"]
    try:
        import vulnhuntr.__main__ as vh
        vh.print = lambda *a, **k: None  # rapports lisibles inutiles : le journal JSON suffit
        vh.run()
    except Exception as e:  # erreurs du modèle ou du relais : panne d'infrastructure (G12)
        # Dernière ligne de la pile seulement, pour le journal du module (G20).
        tb = traceback.format_exception_only(type(e), e)[-1]
        print("vulnhuntr: analyse interrompue (%s)" % clean(tb, 300), file=sys.stderr)
        return 3
    finally:
        os.chdir("/")
    write(sarif(reports(read_log(os.path.join(base, "vulnhuntr.log")), work), work, min_conf), out)
    shutil.rmtree(base, ignore_errors=True)
    return 0


def _conf(value):
    try:
        v = int(value)
    except (TypeError, ValueError):
        return None
    return v if 1 <= v <= 10 else None


def main(argv):
    if argv[1:2] == ["--convert"] and len(argv) <= 3:
        # Conversion seule (diagnostic, tests) : journal sur l'entrée standard, sources = répertoire courant.
        conf = _conf(argv[2]) if len(argv) == 3 else 7
        if conf is None:
            return 2
        work = os.getcwd()
        lines = sys.stdin.read(MAX_LOG_BYTES).splitlines()
        json.dump(sarif(reports(lines, work), work, conf), sys.stdout)
        return 0
    out = out_path(argv[2], ".sarif") if len(argv) in (3, 4) else None
    conf = _conf(argv[3]) if len(argv) == 4 else 7
    if out is None or argv[1] != SRC_DIR or conf is None:
        print(__doc__, file=sys.stderr)
        return 2
    return analyse(SRC_DIR, out, conf)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
