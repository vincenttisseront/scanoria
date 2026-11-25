# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Vincent Tisseront
"""Module pr-agent (0.7, K2) : revue d'une PR par PR-Agent, sans forge.

Usage (sous le pont du relais IA) : python3 -I /scanoria/pragent_scan.py <sortie.sarif>

PR-Agent tourne en mode « diff seul » (plain-diff, amont 0.50.0) : il lit le
diff de la PR que le runner a calculé (SCANORIA_PR_DIFF, /pr.diff), sans
jeton de forge, sans URL de PR, et n'écrit que des fichiers. Ses deux
commandes, `review` puis `describe`, rendent du JSON structuré
(--json-output) ; ce script le convertit en SARIF 2.1.0 :

  - pr-agent/key-issue : un point à revoir (bogue, faille, performance),
    avec son fichier et ses lignes ; gravité « medium » à la confirmation ;
  - pr-agent/security-concern : préoccupation de sécurité de la PR,
    gravité « high » à la confirmation ;
  - runs[0].properties["scanoria/pr-agent"] : description proposée (titre,
    type, résumé), effort de revue (1 à 5), note (0 à 100), fichiers non
    revus. Elle n'est jamais publiée par l'outil : le client de forge de
    l'appliance décide (contrat 30).

Le modèle est celui de l'appliance (alias « scanoria ») joint par le relais
(OPENAI_BASE_URL, OPENAI_API_KEY posés par le pont). Toutes les sorties sont
bornées et nettoyées ; un chemin absolu, avec « .. » ou hors du diff est
écarté. Codes de sortie : 0 (SARIF écrit, même vide), 2 (usage), 3 (PR-Agent
n'a rien rendu : le module est « skipped », jamais une erreur G13).
"""

import json
import os
import re
import sys
import tempfile

VERSION = "1.0.0"
MAX_ISSUES = 50
MAX_TEXT = 4000
MAX_TITLE = 300
MAX_PATH = 1024
MAX_JSON_BYTES = 8 << 20
CTRL_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")
DIFF_PATH_RE = re.compile(r'^\+\+\+ (?:b/(.+)|"b/((?:[^"\\]|\\.)+)")$', re.M)
C_ESCAPES = {"n": "\n", "t": "\t", '"': '"', "\\": "\\"}
RULES = {
    "pr-agent/key-issue": ("Point à revoir dans la PR (PR-Agent)", "medium"),
    "pr-agent/security-concern": ("Préoccupation de sécurité dans la PR (PR-Agent)", "high"),
}


def text(v, limit=MAX_TEXT):
    if not isinstance(v, str):
        return ""
    return CTRL_RE.sub("", v.replace("\r\n", "\n")).strip()[:limit]


def as_int(v, lo, hi):
    if isinstance(v, bool):
        return None
    if isinstance(v, str) and re.fullmatch(r"\s*\d{1,6}\s*", v):
        v = int(v)
    return v if isinstance(v, int) and lo <= v <= hi else None


def clean_path(p, known):
    p = text(p, MAX_PATH).strip("`'\" ")
    if p.startswith("b/") and p[2:] in known:
        p = p[2:]
    if not p or p.startswith("/") or "\\" in p or any(s in ("", ".", "..") for s in p.split("/")):
        return None
    return p if p in known else None


def unquote(p):
    """Chemin cité par git (« "b/…" », séquences C et octets en octal) → texte."""
    out, i = bytearray(), 0
    while i < len(p):
        c = p[i]
        if c == "\\" and i + 1 < len(p):
            n = p[i + 1]
            if re.fullmatch(r"[0-7]{3}", p[i + 1:i + 4]):
                out.append(int(p[i + 1:i + 4], 8) & 0xFF)
                i += 4
                continue
            out += C_ESCAPES.get(n, n).encode()
            i += 2
            continue
        out += c.encode()
        i += 1
    return out.decode("utf-8", "replace")


def diff_files(diff):
    """Fichiers de la PR d'après les en-têtes « +++ b/… » (cités ou non) du diff."""
    found = set()
    for m in DIFF_PATH_RE.finditer(diff):
        p = m.group(1) if m.group(1) is not None else unquote(m.group(2))
        if p.strip():
            found.add(p.strip())
    return found


def load(path):
    try:
        if os.path.getsize(path) > MAX_JSON_BYTES:
            return None
        with open(path, encoding="utf-8") as f:
            doc = json.load(f)
    except (OSError, ValueError):
        return None
    return doc if isinstance(doc, dict) else None


def convert(review, describe, known):
    """JSON de PR-Agent (review, describe) → document SARIF 2.1.0."""
    r = (review or {}).get("review") if isinstance((review or {}).get("review"), dict) else {}
    results = []
    issues = r.get("key_issues_to_review")
    for it in (issues if isinstance(issues, list) else [])[:MAX_ISSUES]:
        if not isinstance(it, dict):
            continue
        header = text(it.get("issue_header"), MAX_TITLE)
        content = text(it.get("issue_content"))
        if not header and not content:
            continue
        res = {"ruleId": "pr-agent/key-issue", "level": "warning",
               "message": {"text": ("%s : %s" % (header, content)) if header and content else (header or content)},
               "properties": {"severity": "medium", "tags": ["ai", "review"]}}
        path = clean_path(it.get("relevant_file"), known)
        if path:
            start = as_int(it.get("start_line"), 1, 10_000_000)
            end = as_int(it.get("end_line"), 1, 10_000_000)
            region = {"startLine": start} if start else None
            if region and end and end >= start:
                region["endLine"] = end
            loc = {"artifactLocation": {"uri": path}}
            if region:
                loc["region"] = region
            res["locations"] = [{"physicalLocation": loc}]
        results.append(res)
    concern = text(r.get("security_concerns"))
    if concern and not re.fullmatch(r"(?i)no\.?", concern):
        results.append({"ruleId": "pr-agent/security-concern", "level": "error", "message": {"text": concern},
                        "properties": {"severity": "high", "tags": ["ai", "security"]}})
    props = {"version": VERSION}
    effort = None
    for k, v in r.items():
        if isinstance(k, str) and k.startswith("estimated_effort_to_review"):
            effort = as_int(v, 1, 5) if not isinstance(v, str) else as_int(v.split(",")[0], 1, 5)
    if effort:
        props["effort"] = effort
    score = as_int(r.get("score"), 0, 100)
    if score is not None:
        props["score"] = score
    cov = (review or {}).get("coverage") if isinstance((review or {}).get("coverage"), dict) else {}
    nr = cov.get("files_not_reviewed")
    if isinstance(nr, list):
        props["files_not_reviewed"] = [p for p in (clean_path(x, known) for x in nr[:200]) if p]
    if isinstance(describe, dict):
        kind = describe.get("type")
        kind = ", ".join(text(x, 60) for x in kind[:5] if isinstance(x, str)) if isinstance(kind, list) else text(kind, 200)
        d = {"title": text(describe.get("title"), MAX_TITLE), "type": kind,
             "description": text(describe.get("description"))}
        d = {k: v for k, v in d.items() if v}
        if d:
            props["description"] = d
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "pr-agent", "version": VERSION,
                                "informationUri": "https://github.com/the-pr-agent/pr-agent",
                                "rules": [{"id": k, "shortDescription": {"text": t},
                                           "properties": {"severity": s, "tags": ["ai"]}}
                                          for k, (t, s) in sorted(RULES.items())]}},
            "results": results,
            "properties": {"scanoria/pr-agent": props},
        }],
    }


def configure():
    """Réglages de PR-Agent par l'environnement (dynaconf) : modèle de l'appliance, aucun repli."""
    base = os.environ.get("OPENAI_BASE_URL", "")
    model = "openai/" + (os.environ.get("SCANORIA_AI_MODEL") or "scanoria")
    os.environ.update({
        "CONFIG__MODEL": model,
        "CONFIG__MODEL_WEAK": model,
        "CONFIG__MODEL_REASONING": model,
        "CONFIG__FALLBACK_MODELS": "@json []",
        "CONFIG__CUSTOM_MODEL_MAX_TOKENS": os.environ.get("SCANORIA_AI_CONTEXT", "32768"),
        "CONFIG__PUBLISH_OUTPUT_PROGRESS": "false",
        "CONFIG__VERBOSITY_LEVEL": "0",
        "OPENAI__KEY": os.environ.get("OPENAI_API_KEY", ""),
        "OPENAI__API_BASE": base,
        "LITELLM_LOCAL_MODEL_COST_MAP": "True",
        "GIT_PYTHON_REFRESH": "quiet",
    })
    for k in ("PR_AGENT_EXTRA_CONFIG_URL", "PR_AGENT_CONFIG_BRANCH"):
        os.environ.pop(k, None)


def run_pr_agent(diff_path, work):
    """review puis describe, dans le processus (aucun sous-processus) ; chemins des JSON produits."""
    from pr_agent import cli  # noqa: PLC0415 (après configure())
    out = {}
    for command in ("review", "describe"):
        path = os.path.join(work, command + ".json")
        try:
            cli.run(inargs=["--diff-file", diff_path, "--json-output", path, command])
        except SystemExit:
            pass
        except Exception as e:  # noqa: BLE001 (une commande en échec n'empêche pas l'autre)
            sys.stderr.write("pr-agent %s failed: %s\n" % (command, e.__class__.__name__))
        out[command] = load(path)
    return out


def main(argv):
    if len(argv) != 2:
        sys.stderr.write("usage: pragent_scan.py <output.sarif>\n")
        return 2
    diff_path = os.environ.get("SCANORIA_PR_DIFF") or ""
    try:
        with open(diff_path, encoding="utf-8", errors="replace") as f:
            diff = f.read(MAX_JSON_BYTES)
    except OSError:
        sys.stderr.write("pr-agent: no pull request diff\n")
        return 3
    configure()
    work = tempfile.mkdtemp(prefix="pr-agent-", dir=os.environ.get("TMPDIR") or "/tmp")
    os.chdir(work)               # aucune racine Git : PR-Agent reste sur le seul diff
    produced = run_pr_agent(diff_path, work)
    if produced.get("review") is None:
        sys.stderr.write("pr-agent: the review produced no structured output\n")
        return 3
    doc = convert(produced["review"], produced.get("describe"), diff_files(diff))
    tmp = argv[1] + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(doc, f, ensure_ascii=False, separators=(",", ":"))
    os.replace(tmp, argv[1])
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
