# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Vincent Tisseront
"""Paquets de skills d'agents du dépôt (module skill-scanner, K6, 0.7).

Usage :
  python3 -I skill_sarif.py /src /out/<nom>.sarif
  python3 -I skill_sarif.py --merge < { "<dossier-skill>": <sarif> … } > sortie.sarif

Trouve chaque skill du dépôt (dossier qui contient SKILL.md) et le fait
analyser par Cisco Skill Scanner, hors ligne : analyseurs statiques (règles
YAML et YARA-X), bytecode, chaînes de commandes et flux de données
(« --use-behavioral », analyse ast sans exécution). Ne sont JAMAIS activés :
le juge LLM (module skill-scanner-llm, par le relais de scanoria-ai),
VirusTotal, Cisco AI Defense, ni la recherche de vulnérabilités en ligne sur
OSV.dev (« --use-osv ») : les dépendances des skills sont couvertes hors
ligne par les modules SCA (OSV-Scanner, Trivy, Grype) et leurs bases locales.

Les SARIF de chaque skill sont fusionnés : chemins ramenés à la racine du
dépôt (l'amont les donne relatifs au skill, ou absolus), règles préfixées
skill-scanner/, textes nettoyés et bornés.
"""

import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
from urllib.parse import quote, unquote, urlparse

VERSION = "1.0.0"
MAX_SKILLS = 200
MAX_RESULTS = 10000
MAX_SARIF = 32 << 20
SKILL_TIMEOUT = 300
SKIP_DIRS = {".git", "node_modules", "vendor", ".venv", "venv", "__pycache__", "dist", "build", "site-packages"}
CTRL_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f\u200b-\u200f\u202a-\u202e\u2066-\u2069\ufeff]")
RULE_RE = re.compile(r"[^A-Za-z0-9_.-]+")
SCANNER = ["skill-scanner"]
OFFLINE_FLAGS = ["--use-behavioral", "--format", "sarif"]


def clean(value, limit=1000):
    return CTRL_RE.sub(" ", str(value)).strip()[:limit]


def skills(src):
    """Dossiers de skills (contenant un SKILL.md régulier), relatifs à la racine."""
    out = []
    for root, dirs, names in os.walk(src, followlinks=False):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS and not os.path.islink(os.path.join(root, d)))
        if "SKILL.md" in names:
            try:
                if stat.S_ISREG(os.lstat(os.path.join(root, "SKILL.md")).st_mode):
                    out.append(os.path.relpath(root, src).replace(os.sep, "/"))
            except OSError:
                pass
        if len(out) >= MAX_SKILLS:
            break
    return out


def run_skill(src, rel, tmp):
    """SARIF de l'amont pour un skill, ou None si l'analyse échoue (comptée)."""
    out = os.path.join(tmp, hashlib.sha256(rel.encode()).hexdigest()[:16] + ".sarif")
    target = os.path.normpath(os.path.join(src, rel))
    env = {k: v for k, v in os.environ.items()
           if not k.startswith(("OPENAI_", "ANTHROPIC_", "AZURE_", "VIRUSTOTAL_", "AI_DEFENSE_", "SKILL_SCANNER_LLM"))}
    try:
        subprocess.run(SCANNER + ["scan", target] + OFFLINE_FLAGS + ["--output-sarif", out],
                       env=env, cwd=src, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                       timeout=SKILL_TIMEOUT, check=False)
        if os.path.getsize(out) > MAX_SARIF:
            return None
        with open(out, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError, subprocess.SubprocessError):
        return None


def repo_path(uri, base_id, skill_rel, src_abs):
    """Chemin relatif à la racine du dépôt, ou None s'il en sort."""
    if not isinstance(uri, str) or not uri:
        return None
    if uri.startswith("file://"):
        p = unquote(urlparse(uri).path)
        rel = os.path.relpath(os.path.normpath(p), src_abs)
    elif os.path.isabs(uri):
        rel = os.path.relpath(os.path.normpath(uri), src_abs)
    else:
        # L'amont écrit les chemins relatifs au répertoire courant (la racine du
        # dépôt, cwd de run_skill) ; un chemin relatif au skill reste admis.
        u = os.path.normpath(unquote(uri)).replace(os.sep, "/")
        rel = u if skill_rel in (".", "") or u == skill_rel or u.startswith(skill_rel + "/") else os.path.normpath(os.path.join(skill_rel, u))
    rel = rel.replace(os.sep, "/")
    if rel == ".." or rel.startswith("../") or rel.startswith("/"):
        return None
    return rel


def merge(src, per_skill, tool_version=None):
    src_abs = os.path.normpath(os.path.abspath(src))
    rules, results, failed = {}, [], []
    for skill_rel, doc in per_skill:
        if not isinstance(doc, dict) or not isinstance(doc.get("runs"), list):
            failed.append(skill_rel)
            continue
        for run in doc["runs"][:4]:
            if not isinstance(run, dict):
                continue
            driver = ((run.get("tool") or {}).get("driver") or {})
            for r in driver.get("rules") or []:
                if isinstance(r, dict) and isinstance(r.get("id"), str):
                    rid = "skill-scanner/" + RULE_RE.sub("-", r["id"]).lower()[:100]
                    if rid not in rules:
                        props = r.get("properties") if isinstance(r.get("properties"), dict) else {}
                        rules[rid] = {
                            "id": rid,
                            "name": clean(r.get("name") or r["id"], 120),
                            "shortDescription": {"text": clean((r.get("shortDescription") or {}).get("text") or r["id"], 200)},
                            # La description amont cite des chemins absolus du conteneur : seule la description courte est gardée.
                            "fullDescription": {"text": clean((r.get("shortDescription") or {}).get("text") or r["id"], 1000)},
                            "properties": {"tags": [clean(t, 80) for t in (props.get("tags") or []) if isinstance(t, str)][:20]},
                        }
            for res in run.get("results") or []:
                if len(results) >= MAX_RESULTS or not isinstance(res, dict) or not isinstance(res.get("ruleId"), str):
                    continue
                rid = "skill-scanner/" + RULE_RE.sub("-", res["ruleId"]).lower()[:100]
                props = res.get("properties") if isinstance(res.get("properties"), dict) else {}
                locs = []
                for loc in (res.get("locations") or [])[:1]:
                    phys = (loc or {}).get("physicalLocation") or {}
                    art = phys.get("artifactLocation") or {}
                    path = repo_path(art.get("uri"), art.get("uriBaseId"), skill_rel, src_abs)
                    if path is None:
                        continue
                    region = phys.get("region") if isinstance(phys.get("region"), dict) else {}
                    reg = {}
                    if isinstance(region.get("startLine"), int) and region["startLine"] > 0:
                        reg["startLine"] = region["startLine"]
                    snip = (region.get("snippet") or {}).get("text") if isinstance(region.get("snippet"), dict) else None
                    if snip:
                        reg["snippet"] = {"text": clean(snip, 300)}
                    pl = {"artifactLocation": {"uri": quote(path), "uriBaseId": "SRCROOT"}}
                    if reg:
                        pl["region"] = reg
                    locs.append({"physicalLocation": pl})
                level = res.get("level") if res.get("level") in ("error", "warning", "note", "none") else "warning"
                fp = hashlib.sha256(("%s|%s|%s" % (skill_rel, rid, json.dumps(res.get("fingerprints") or res.get("message"), sort_keys=True))).encode()).hexdigest()
                item = {
                    "ruleId": rid,
                    "level": level,
                    # L'amont cite les chemins absolus du conteneur : ramenés à la racine du dépôt.
                    "message": {"text": clean(str((res.get("message") or {}).get("text") or rid).replace(src_abs + "/", ""), 600)},
                    "partialFingerprints": {"skillScanner/v1": fp},
                    "properties": {
                        "skill": skill_rel,
                        "severity": clean(props.get("severity") or "", 20).lower(),
                        "category": clean(props.get("category") or "", 80),
                        "remediation": clean(props.get("remediation") or "", 600),
                    },
                }
                if locs:
                    item["locations"] = locs
                results.append(item)
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "skill-scanner", "version": tool_version or VERSION,
                                "informationUri": "https://github.com/cisco-ai-defense/skill-scanner", "rules": list(rules.values())}},
            "originalUriBaseIds": {"SRCROOT": {"uri": "file:///src/"}},
            "results": results,
            "properties": {"scanoria/skills": {"analysed": len(per_skill) - len(failed), "failed": failed[:50]}},
        }],
    }


def _version():
    try:
        from importlib.metadata import version
        return version("cisco-ai-skill-scanner")
    except Exception:
        return None



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


def write_json(path, doc):
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(doc, fh)


def main(argv):
    if argv[1:] == ["--merge"]:
        # Fusion seule (diagnostic, tests) : { "<dossier-skill>": <SARIF amont> } sur l'entrée standard.
        per = [(str(rel), doc if isinstance(doc, dict) else None) for rel, doc in json.load(sys.stdin).items()]
        json.dump(merge(SRC_DIR, per, None), sys.stdout)
        return 0
    out = out_path(argv[2], ".sarif") if len(argv) == 3 else None
    if out is None or argv[1] != SRC_DIR:
        print(__doc__, file=sys.stderr)
        return 2
    with tempfile.TemporaryDirectory(prefix="skills-") as tmp:
        per = [(rel, run_skill(SRC_DIR, rel, tmp)) for rel in skills(SRC_DIR)]
    doc = merge(SRC_DIR, per, _version())
    failed = doc["runs"][0]["properties"]["scanoria/skills"]["failed"]
    if per and len(failed) == len(per):
        print("skill-scanner: every skill analysis failed", file=sys.stderr)
        return 3
    write_json(out, doc)
    print("skill-scanner: %d result(s)" % len(doc["runs"][0]["results"]))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
