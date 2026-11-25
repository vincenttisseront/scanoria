# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Vincent Tisseront
"""Inventaire des workflows d'agents (module agentic-radar, K7, 0.7).

Usage :
  python3 -I radar_sarif.py /src /out/<nom>.sarif [/out/<nom>.json]
  python3 -I radar_sarif.py --convert < graphes-bruts.json > sortie.sarif
    (conversion seule ; sources = répertoire courant)

Lance les analyseurs statiques d'Agentic Radar (LangGraph, CrewAI, n8n,
OpenAI Agents, AutoGen) sur le dépôt, SANS RIEN EXÉCUTER ni appeler aucun
modèle : seules la lecture du code (ast) et la table des vulnérabilités
connues des outils livrée avec Agentic Radar sont utilisées ; les commandes
qui exigent OpenAI (« test », « --harden-prompts ») ne le sont jamais.

Sortie : SARIF 2.1.0
  - un résultat par vulnérabilité connue d'un outil d'agent (ruleId
    agentic-radar/<vulnérabilité>, catégorie sast) : outil, catégorie,
    workflow et correspondances OWASP (LLM Top 10, Agentic) ;
  - runs[0].properties["scanoria/agent-inventory"] = inventaire borné
    (version, frameworks, workflows : nœuds, arêtes, agents, outils, serveurs
    MCP). Les invites système ne sont jamais recopiées (longueur seulement) :
    elles peuvent contenir des secrets et l'inventaire peut être envoyé à
    l'IA (I22) sous forme de métadonnées.

Le dépôt analysé est hostile : tout texte est nettoyé et borné, aucun lien
symbolique n'est suivi par la recherche d'emplacement, et un analyseur qui
échoue sur un fichier est compté sans faire échouer l'analyse.
"""

import hashlib
import json
import os
import re
import stat
import sys
from urllib.parse import quote

VERSION = "1.0.0"
INVENTORY_VERSION = 1
FRAMEWORKS = ["langgraph", "crewai", "n8n", "openai-agents", "autogen"]
MAX_WORKFLOWS = 50
MAX_ITEMS = 500
MAX_TEXT = 300
MAX_DESC = 2000
MAX_INVENTORY = 900_000
MAX_FILES = 20000
MAX_FILE_BYTES = 1 << 20
SKIP_DIRS = {".git", "node_modules", "vendor", ".venv", "venv", "env", "__pycache__", ".tox", "dist", "build", "site-packages"}
CTRL_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f\u200b-\u200f\u202a-\u202e\u2066-\u2069\ufeff]")
SLUG_RE = re.compile(r"[^a-z0-9]+")
# Catégories d'outils qui exécutent du code ou lisent le système : gravité « error ».
HIGH_CATEGORIES = {"code_interpreter"}


def clean(value, limit=MAX_TEXT):
    if value is None:
        return None
    return CTRL_RE.sub(" ", str(value)).strip()[:limit]


def slug(text):
    return SLUG_RE.sub("-", str(text).lower()).strip("-")[:60] or "unknown"


def _no_llm():
    """Aucun appel de modèle : l'analyseur OpenAI Agents interroge OpenAI pour juger les
    garde-fous des agents dès qu'une clé est présente. Les clés sont retirées et la
    fonction remplacée ; le conteneur n'a de toute façon aucun réseau."""
    for k in list(os.environ):
        if k.startswith(("OPENAI_", "AZURE_OPENAI_")):
            del os.environ[k]
    import agentic_radar.analysis.openai_agents.analyze as oa
    oa.get_agent_vulnerabilities = lambda *a, **k: None


def analyze(src):
    """Graphes bruts d'Agentic Radar, vulnérabilités connues associées ; un analyseur en échec est compté."""
    _no_llm()
    from agentic_radar.analysis import (AutogenAgentChatAnalyzer, CrewAIAnalyzer, LangGraphAnalyzer,
                                        N8nAnalyzer, OpenAIAgentsAnalyzer)
    from agentic_radar.mapper import map_vulnerabilities
    from agentic_radar.utils import sanitize_graph
    analyzers = {
        "langgraph": LangGraphAnalyzer, "crewai": CrewAIAnalyzer, "n8n": N8nAnalyzer,
        "openai-agents": OpenAIAgentsAnalyzer, "autogen": AutogenAgentChatAnalyzer,
    }
    raws, errors = [], []
    for fw in FRAMEWORKS:
        try:
            graph = analyzers[fw]().analyze(src)
        except Exception as exc:  # analyseur amont : un dépôt hostile ne fait pas échouer l'analyse
            errors.append({"framework": fw, "error": clean(type(exc).__name__, 80)})
            continue
        if len(graph.nodes) <= 2 and not graph.tools and not graph.agents:
            continue  # seulement START et END : aucun workflow pour ce framework
        sanitize_graph(graph)
        map_vulnerabilities(graph)
        raws.append({"framework": fw, "graph": graph.model_dump(mode="json")})
    return {"tool_version": _tool_version(), "workflows": raws, "errors": errors}


def _tool_version():
    try:
        from agentic_radar import __version__
        return clean(__version__, 40)
    except Exception:
        return None


def _items(value):
    return value[:MAX_ITEMS] if isinstance(value, list) else []


def _node(n):
    if not isinstance(n, dict):
        return None
    return {
        "name": clean(n.get("name")),
        "type": clean(n.get("node_type") or n.get("type"), 40),
        "category": clean(n.get("category"), 40),
        "description": clean(n.get("description")),
        "vulnerabilities": [clean(v.get("name"), 120) for v in _items(n.get("vulnerabilities")) if isinstance(v, dict)],
    }


def inventory(raw):
    """Inventaire borné, sans invite système (longueur seulement)."""
    workflows = []
    for w in _items(raw.get("workflows"))[:MAX_WORKFLOWS]:
        fw, g = w.get("framework"), w.get("graph")
        if fw not in FRAMEWORKS or not isinstance(g, dict):
            continue
        nodes = [x for x in (_node(n) for n in _items(g.get("nodes"))) if x]
        tools = [x for x in (_node(t) for t in _items(g.get("tools"))) if x]
        workflows.append({
            "framework": fw,
            "name": clean(g.get("name")),
            "nodes": [n for n in nodes if n["type"] != "mcp_server"],
            "edges": [{"start": clean(e.get("start")), "end": clean(e.get("end")), "condition": clean(e.get("condition"))}
                      for e in _items(g.get("edges")) if isinstance(e, dict)],
            "agents": [{"name": clean(a.get("name")), "llm": clean(a.get("llm"), 120),
                        "is_guardrail": a.get("is_guardrail") is True,
                        "system_prompt_chars": len(a.get("system_prompt") or "") if isinstance(a.get("system_prompt"), str) else 0}
                       for a in _items(g.get("agents")) if isinstance(a, dict)],
            "tools": [t for t in tools if t["type"] != "mcp_server"],
            "mcp_servers": [n for n in nodes + tools if n["type"] == "mcp_server"],
        })
    inv = {
        "version": INVENTORY_VERSION,
        "tool_version": clean(raw.get("tool_version"), 40),
        "frameworks": sorted({w["framework"] for w in workflows}),
        "workflows": workflows,
        "errors": [{"framework": e.get("framework"), "error": clean(e.get("error"), 80)}
                   for e in _items(raw.get("errors")) if isinstance(e, dict) and e.get("framework") in FRAMEWORKS],
        "truncated": False,
    }
    while len(json.dumps(inv)) > MAX_INVENTORY and inv["workflows"]:
        inv["workflows"].pop()
        inv["truncated"] = True
    return inv


def _source_files(src):
    count = 0
    for root, dirs, files in os.walk(src, followlinks=False):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS and not os.path.islink(os.path.join(root, d)))
        for f in sorted(files):
            if not f.endswith((".py", ".json")):
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
            yield p


def locate(src, names):
    """Premier fichier et ligne où apparaît l'un des noms (identifiant ou chaîne), ou None."""
    wanted = [n for n in names if n and len(n) >= 3]
    if not wanted:
        return {}
    pats = [re.compile(r"(?<![A-Za-z0-9_])" + re.escape(n) + r"(?![A-Za-z0-9_])") for n in wanted]
    found = {}
    for p in _source_files(src):
        try:
            with open(p, encoding="utf-8", errors="replace") as fh:
                for i, line in enumerate(fh, 1):
                    for n, pat in zip(wanted, pats):
                        if n not in found and pat.search(line):
                            found[n] = (os.path.relpath(p, src), i, clean(line, 200))
        except OSError:
            continue
        if len(found) == len(wanted):
            break
    return found


def sarif(raw, src):
    inv = inventory(raw)
    rules, results = {}, []
    tools = [(w["framework"], w["name"], t) for w in inv["workflows"] for t in w["tools"] + w["mcp_servers"]]
    where = locate(src, sorted({t["name"] for _, _, t in tools if t["name"]}))
    # Descriptions des vulnérabilités, reprises des graphes bruts (table amont).
    defs = {}
    for w in _items(raw.get("workflows")):
        g = w.get("graph") if isinstance(w, dict) else None
        for n in (_items(g.get("tools")) + _items(g.get("nodes"))) if isinstance(g, dict) else []:
            for v in _items(n.get("vulnerabilities")) if isinstance(n, dict) else []:
                if isinstance(v, dict) and v.get("name"):
                    defs.setdefault(clean(v["name"], 120), v)
    for fw, wname, t in tools:
        for vname in t["vulnerabilities"]:
            rid = "agentic-radar/" + slug(vname)
            v = defs.get(vname, {})
            mapping = v.get("security_framework_mapping") if isinstance(v.get("security_framework_mapping"), dict) else {}
            if rid not in rules:
                rules[rid] = {
                    "id": rid,
                    "name": clean(vname, 120),
                    "shortDescription": {"text": clean(vname, 120)},
                    "fullDescription": {"text": clean(v.get("description"), MAX_DESC) or clean(vname, 120)},
                    "help": {"text": clean(v.get("remediation"), MAX_DESC) or ""},
                    "properties": {"tags": ["agentic", "llm"] + [clean(f"{k}: {val}", 120) for k, val in sorted(mapping.items())][:8]},
                }
            level = "error" if t["category"] in HIGH_CATEGORIES else "warning"
            msg = f"Tool \"{t['name']}\" ({t['category'] or t['type']}) of the {fw} workflow \"{wname}\": {clean(vname, 120)}"
            res = {
                "ruleId": rid,
                "level": level,
                "message": {"text": clean(msg, 600)},
                "partialFingerprints": {"agenticRadar/v1": hashlib.sha256(f"{fw}|{wname}|{t['name']}|{rid}".encode()).hexdigest()},
                "properties": {"framework": fw, "workflow": wname, "tool": t["name"], "toolCategory": t["category"], "toolType": t["type"]},
            }
            loc = where.get(t["name"])
            if loc:
                res["locations"] = [{"physicalLocation": {
                    "artifactLocation": {"uri": quote(loc[0].replace(os.sep, "/")), "uriBaseId": "SRCROOT"},
                    "region": {"startLine": loc[1], "snippet": {"text": loc[2]}},
                }}]
            results.append(res)
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "agentic-radar", "version": inv["tool_version"] or VERSION,
                                "informationUri": "https://github.com/splx-ai/agentic-radar", "rules": list(rules.values())}},
            "originalUriBaseIds": {"SRCROOT": {"uri": "file:///src/"}},
            "results": results,
            "properties": {"scanoria/agent-inventory": inv},
        }],
    }



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
    if argv[1:] == ["--convert"]:
        # Conversion seule (diagnostic, tests) : graphes bruts sur l'entrée standard, sources = répertoire courant.
        json.dump(sarif(json.load(sys.stdin), os.getcwd()), sys.stdout)
        return 0
    outs = [out_path(a, ext) for a, ext in zip(argv[2:], (".sarif", ".json"))]
    if len(argv) not in (3, 4) or argv[1] != SRC_DIR or None in outs:
        print(__doc__, file=sys.stderr)
        return 2
    raw = analyze(SRC_DIR)
    if len(outs) == 2:
        write_json(outs[1], raw)
    doc = sarif(raw, SRC_DIR)
    write_json(outs[0], doc)
    inv = doc["runs"][0]["properties"]["scanoria/agent-inventory"]
    print(f"agentic-radar: {len(inv['workflows'])} workflow(s), {len(doc['runs'][0]['results'])} result(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
