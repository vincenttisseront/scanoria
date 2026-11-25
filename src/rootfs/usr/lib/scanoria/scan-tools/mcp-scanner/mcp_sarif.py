# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Vincent Tisseront
"""Définitions et configurations MCP du dépôt (module mcp-scanner, K5, 0.7).

Usage : python3 -I mcp_sarif.py <sources> <sortie.sarif>

Relève, SANS RIEN EXÉCUTER ni joindre aucun serveur, ce que le dépôt déclare
sur des serveurs MCP :
  - listes d'outils et d'invites (sorties tools/list et prompts/list
    enregistrées en JSON : { "tools": [ { name, description, inputSchema } ] }) ;
  - configurations de clients MCP (mcpServers / servers : commande,
    arguments, adresse ; noms des variables d'environnement seulement,
    jamais leurs valeurs) ;
  - outils et invites déclarés dans le code d'un serveur : décorateurs
    @….tool / @….prompt en Python (ast, docstring et paramètres), appels
    server.tool("nom", "description") et registerTool en JavaScript et
    TypeScript (analyse lexicale).
Chaque élément passe par les règles YARA de Cisco MCP Scanner (empoisonnement
d'outil, injection d'invite, exécution de code, exfiltration…), hors ligne.
Ni l'API Cisco AI Defense, ni VirusTotal, ni l'analyse par LLM ne sont
utilisées ici (l'analyse LLM est le module mcp-scanner-llm, par le relais).

Sortie : SARIF 2.1.0, un résultat par règle déclenchée et par élément
(ruleId mcp-scanner/<règle>, catégorie sast), avec le fichier et la ligne.
"""

import ast
import asyncio
import hashlib
import json
import os
import re
import stat
import sys
from urllib.parse import quote

VERSION = "1.0.0"
MAX_FILES = 20000
MAX_FILE_BYTES = 1 << 20
MAX_ITEMS = 5000
MAX_CONTENT = 20000
MAX_TEXT = 300
SKIP_DIRS = {".git", "node_modules", "vendor", ".venv", "venv", "env", "__pycache__", ".tox", "dist", "build", "site-packages"}
CODE_EXT = {".py", ".js", ".mjs", ".cjs", ".ts", ".mts", ".cts"}
DATA_EXT = {".json"}
CTRL_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f​-‏‪-‮⁦-⁩﻿]")
SLUG_RE = re.compile(r"[^a-z0-9]+")
LEVELS = {"HIGH": "error", "MEDIUM": "warning", "LOW": "note"}
JS_TOOL_RE = re.compile(
    r"""\.(tool|prompt|registerTool|registerPrompt)\s*\(\s*(["'`])([^"'`\n]{1,200})\2\s*,\s*(?:\{[^}]*?description\s*:\s*)?(["'`])((?:\\.|(?!\4).){0,4000})\4""",
    re.S,
)


def clean(value, limit=MAX_TEXT):
    return CTRL_RE.sub(" ", str(value)).strip()[:limit]


def slug(text):
    return SLUG_RE.sub("-", str(text).lower()).strip("-")[:60] or "unknown"


def files(src):
    count = 0
    for root, dirs, names in os.walk(src, followlinks=False):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS and not os.path.islink(os.path.join(root, d)))
        for f in sorted(names):
            ext = os.path.splitext(f)[1].lower()
            if ext not in CODE_EXT | DATA_EXT:
                continue
            p = os.path.join(root, f)
            try:
                st = os.lstat(p)
            except OSError:
                continue
            if not stat.S_ISREG(st.st_mode) or st.st_size > MAX_FILE_BYTES:
                continue
            count += 1
            if count > MAX_FILES:
                return
            yield p, ext


def _line_of(text, needle):
    i = text.find(needle) if needle else -1
    return text.count("\n", 0, i) + 1 if i >= 0 else 1


def _from_json(rel, text):
    try:
        doc = json.loads(text)
    except ValueError:
        return []
    if not isinstance(doc, dict):
        return []
    items = []
    for key, kind in (("tools", "tool"), ("prompts", "prompt")):
        for t in doc.get(key) or [] if isinstance(doc.get(key), list) else []:
            if not isinstance(t, dict) or not isinstance(t.get("name"), str):
                continue
            if kind == "tool" and not any(k in t for k in ("inputSchema", "input_schema", "description")):
                continue
            params = t.get("inputSchema") or t.get("input_schema") or t.get("arguments") or {}
            items.append({
                "path": rel, "line": _line_of(text, '"%s"' % t["name"]), "kind": kind, "name": t["name"],
                "description": str(t.get("description") or ""), "parameters": json.dumps(params)[:MAX_CONTENT],
            })
    servers = doc.get("mcpServers")
    if servers is None and isinstance(doc.get("mcp"), dict):
        servers = doc["mcp"].get("servers")
    if servers is None and isinstance(doc.get("servers"), dict) and any(
            isinstance(v, dict) and ("command" in v or "url" in v) for v in doc["servers"].values()):
        servers = doc["servers"]
    if isinstance(servers, dict):
        for name, cfg in servers.items():
            if not isinstance(cfg, dict):
                continue
            args = cfg.get("args") if isinstance(cfg.get("args"), list) else []
            env = cfg.get("env") if isinstance(cfg.get("env"), dict) else {}
            # Valeurs des variables jamais lues : elles portent souvent des jetons.
            content = " ".join(str(x) for x in [cfg.get("command") or "", *args[:200], cfg.get("url") or ""])
            items.append({
                "path": rel, "line": _line_of(text, '"%s"' % name), "kind": "server", "name": str(name),
                "description": content, "parameters": json.dumps({"env": sorted(str(k) for k in env)[:100]}),
            })
    return items


def _decorator_kind(dec):
    node = dec.func if isinstance(dec, ast.Call) else dec
    name = node.attr if isinstance(node, ast.Attribute) else node.id if isinstance(node, ast.Name) else ""
    return "tool" if name == "tool" else "prompt" if name == "prompt" else None


def _from_python(rel, text):
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError, RecursionError):
        return []
    items = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for dec in node.decorator_list:
            kind = _decorator_kind(dec)
            if not kind:
                continue
            desc = ast.get_docstring(node) or ""
            name = node.name
            if isinstance(dec, ast.Call):
                for kw in dec.keywords:
                    if kw.arg in ("description", "name") and isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
                        if kw.arg == "description":
                            desc = kw.value.value + "\n" + desc
                        else:
                            name = kw.value.value
            params = [a.arg for a in node.args.args + node.args.kwonlyargs]
            items.append({"path": rel, "line": node.lineno, "kind": kind, "name": name,
                          "description": desc, "parameters": json.dumps({"parameters": params})})
            break
    return items


def _from_js(rel, text):
    items = []
    for m in JS_TOOL_RE.finditer(text):
        kind = "prompt" if "rompt" in m.group(1) else "tool"
        items.append({"path": rel, "line": text.count("\n", 0, m.start()) + 1, "kind": kind, "name": m.group(3),
                      "description": m.group(5).encode().decode("unicode_escape", "replace") if "\\" in m.group(5) else m.group(5),
                      "parameters": "{}"})
    return items


def discover(src):
    out = []
    for p, ext in files(src):
        try:
            with open(p, encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except OSError:
            continue
        rel = os.path.relpath(p, src).replace(os.sep, "/")
        if ext in DATA_EXT:
            out += _from_json(rel, text)
        elif ext == ".py":
            if "tool" in text or "prompt" in text:
                out += _from_python(rel, text)
        elif ".tool" in text or ".prompt" in text or "registerTool" in text or "registerPrompt" in text:
            out += _from_js(rel, text)
        if len(out) >= MAX_ITEMS:
            return out[:MAX_ITEMS]
    return out


def scan(items, analyzer):
    """(élément, constat) pour chaque règle YARA déclenchée sur la description ou les paramètres."""
    found = []
    for it in items:
        seen = set()
        for content_type, content in (("description", it["description"]), ("parameters", it["parameters"])):
            if not content:
                continue
            for f in asyncio.run(analyzer.analyze(content[:MAX_CONTENT], {"tool_name": it["name"], "content_type": content_type})):
                raw = (f.details or {}).get("raw_response") or {}
                rule = raw.get("rule") or "unknown"
                if rule in seen:
                    continue
                seen.add(rule)
                found.append((it, {"rule": rule, "severity": str(f.severity or "UNKNOWN").upper(),
                                   "category": f.threat_category, "description": raw.get("description") or "",
                                   "threat_type": raw.get("threat_type") or "", "content_type": content_type}))
    return found


def sarif(found, tool_version=None):
    rules, results = {}, []
    for it, f in found:
        rid = "mcp-scanner/" + slug(f["rule"])
        if rid not in rules:
            rules[rid] = {
                "id": rid, "name": clean(f["rule"], 120),
                "shortDescription": {"text": clean(f["threat_type"] or f["rule"], 120).capitalize()},
                "fullDescription": {"text": clean(f["description"] or f["rule"], 1000)},
                "properties": {"tags": ["mcp", "llm", clean(f["category"] or "", 80)]},
            }
        where = {"tool": "tool", "prompt": "prompt", "server": "server configuration"}[it["kind"]]
        msg = 'MCP %s "%s": %s (%s)' % (where, clean(it["name"], 120), clean(f["description"] or f["rule"], 300), f["content_type"])
        results.append({
            "ruleId": rid,
            "level": LEVELS.get(f["severity"], "warning"),
            "message": {"text": clean(msg, 600)},
            "partialFingerprints": {"mcpScanner/v1": hashlib.sha256(("%s|%s|%s|%s" % (it["path"], it["kind"], it["name"], rid)).encode()).hexdigest()},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": quote(it["path"]), "uriBaseId": "SRCROOT"},
                "region": {"startLine": max(1, int(it["line"]))},
            }}],
            "properties": {"kind": it["kind"], "name": clean(it["name"], 120), "severity": f["severity"].lower(),
                           "threatCategory": clean(f["category"] or "", 80)},
        })
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "mcp-scanner", "version": tool_version or VERSION,
                                "informationUri": "https://github.com/cisco-ai-defense/mcp-scanner", "rules": list(rules.values())}},
            "originalUriBaseIds": {"SRCROOT": {"uri": "file:///src/"}},
            "results": results,
        }],
    }


def main(argv):
    if len(argv) != 3:
        print(__doc__, file=sys.stderr)
        return 2
    src, out = argv[1], argv[2]
    for k in list(os.environ):
        if k.startswith(("MCP_SCANNER_", "VIRUSTOTAL_", "OPENAI_", "AZURE_OPENAI_")):
            del os.environ[k]
    from mcpscanner.core.analyzers.yara_analyzer import YaraAnalyzer
    try:
        from importlib.metadata import version
        tv = version("cisco-ai-mcp-scanner")
    except Exception:
        tv = None
    items = discover(src)
    doc = sarif(scan(items, YaraAnalyzer()), tv)
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(doc, fh)
    print("mcp-scanner: %d element(s), %d result(s)" % (len(items), len(doc["runs"][0]["results"])))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
