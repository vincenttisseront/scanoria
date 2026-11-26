# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Vincent Tisseront
"""Module fraim (0.7, K4) : analyse IA du code, de l'IaC et du risque d'une PR.

Usage (sous le pont du relais IA) : python3 -I /scanoria/fraim_scan.py /src <sortie.sarif>

Lance dans le processus, sans sous-processus ni réseau autre que le relais,
les workflows de Fraim 0.8.0 :

  - « code » (SAST par LLM) et « iac » (Terraform, Kubernetes, Dockerfile…)
    sur les sources montées en lecture seule ; pour une PR incrémentale
    (SCANORIA_CHANGED_FILES), sur ses seuls fichiers modifiés ;
  - « risk_flagger » si le diff de la PR est fourni (SCANORIA_PR_DIFF) : le
    diff est lu dans ce fichier, jamais calculé par git dans le conteneur, et
    aucun commentaire, relecteur ni message Slack n'est envoyé (aucune URL
    de PR ni de webhook n'est passée à l'outil).

Les résultats de Fraim (SARIF par pydantic) sont repris en SARIF 2.1.0 :
règle « fraim/<workflow> » (code, iac, risk-flagger ; le type de
problème relevé par le modèle va dans le message et properties.type), chemins relatifs à /src (un chemin hors
des sources est écarté), textes bornés, gravité native dans
properties.severity (critical…low, à la confirmation ; contrat 32).
runs[0].properties["scanoria/fraim"] : workflows lancés, en échec, et
indicateur de risque de la PR (plus haute gravité des risques relevés).

Codes de sortie : 0 (SARIF écrit ; « partial » si une partie des appels au
modèle a échoué), 2 (usage), 3 (aucun workflow n'a abouti, ou aucun appel au
modèle n'a réussi, ou rien à analyser : module « skipped », jamais une
erreur G13 ; litellm.acompletion est lu à chaque appel par Fraim 0.8.0,
fraim/core/llms/litellm.py, d'où le comptage par remplacement de l'attribut).
"""

import asyncio
import fnmatch
import json
import os
import re
import sys
import tempfile

VERSION = "1.0.0"
MAX_RESULTS = 500
MAX_TEXT = 4000
MAX_TITLE = 300
MAX_DIFF_BYTES = 4 << 20
MAX_CHANGED = 3000
CTRL_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")
RULE_TITLES = {
    "fraim/code": "Faille probable dans le code (Fraim)",
    "fraim/iac": "Configuration d'infrastructure risquée (Fraim)",
    "fraim/risk-flagger": "Changement à risque dans la PR (Fraim)",
}
LEVEL_SEVERITY = {"error": "high", "warning": "medium", "note": "low", "none": "info"}
SEVERITIES = ("critical", "high", "medium", "low")
CONFIDENCE = 7


OUT_DIR = os.environ.get("SCANORIA_OUT_DIR") or "/out"     # /out dans le conteneur
NAME_RE = re.compile(r"[A-Za-z0-9._-]{1,100}")


def out_path(arg):
    """Sortie reconstruite sous OUT_DIR depuis un nom validé ; None si l'argument n'est pas <OUT_DIR>/<nom>.sarif."""
    if os.path.dirname(arg) != OUT_DIR.rstrip("/"):
        return None
    m = NAME_RE.fullmatch(os.path.basename(arg))
    if not m or not m.group(0).endswith(".sarif") or m.group(0) in (".", ".."):
        return None
    path = os.path.realpath(os.path.join(OUT_DIR, m.group(0)))
    return path if os.path.dirname(path) == os.path.realpath(OUT_DIR) else None


def text(v, limit=MAX_TEXT):
    if isinstance(v, dict):
        v = v.get("text")
    if not isinstance(v, str):
        return ""
    return CTRL_RE.sub("", v.replace("\r\n", "\n")).strip()[:limit]


def rel_path(uri, root):
    """Chemin relatif aux sources, ou None (hors des sources, absolu étranger, « .. »)."""
    p = text(uri, 1024)
    if p.startswith("file://"):
        p = p[7:]
    root = root.rstrip("/") + "/"
    if p.startswith(root):
        p = p[len(root):]
    elif p.startswith("/"):
        return None
    if p.startswith("./"):
        p = p[2:]
    if not p or "\\" in p or any(s in ("", ".", "..") for s in p.split("/")):
        return None
    return p


def as_line(v):
    return v if isinstance(v, int) and not isinstance(v, bool) and 1 <= v <= 10_000_000 else None


def convert(found, root):
    """[(workflow, résultat SARIF de Fraim en dict)] → résultats SARIF 2.1.0 bornés."""
    results, rules = [], {}
    for item in found[:MAX_RESULTS]:
        if not (isinstance(item, (tuple, list)) and len(item) == 2 and isinstance(item[1], dict)):
            continue
        workflow, r = item
        props = r.get("properties") if isinstance(r.get("properties"), dict) else {}
        kind = props.get("risk_type") if workflow == "risk_flagger" else props.get("type")
        rule = "fraim/" + workflow.replace("_", "-")
        level = r.get("level") if r.get("level") in LEVEL_SEVERITY else "warning"
        severity = props.get("risk_severity") if props.get("risk_severity") in SEVERITIES else LEVEL_SEVERITY[level]
        kind = text(kind, MAX_TITLE)
        msg = text(r.get("message")) or kind or rule
        if kind and not msg.lower().startswith(kind.lower()):
            msg = ("%s : %s" % (kind, msg))[:MAX_TEXT]
        explanation = text(props.get("explanation"))
        if explanation and explanation not in msg:
            msg = (msg + "\n\n" + explanation)[:MAX_TEXT]
        out = {"ruleId": rule, "level": level, "message": {"text": msg},
               "properties": {"severity": severity, "tags": ["ai", workflow.replace("_", "-")]}}
        if kind:
            out["properties"]["type"] = kind
        conf = props.get("confidence")
        if isinstance(conf, int) and not isinstance(conf, bool) and 1 <= conf <= 10:
            out["properties"]["confidence"] = conf
        locs = []
        for loc in (r.get("locations") if isinstance(r.get("locations"), list) else [])[:5]:
            pl = (loc or {}).get("physicalLocation") if isinstance(loc, dict) else None
            if not isinstance(pl, dict):
                continue
            path = rel_path(((pl.get("artifactLocation") or {}).get("uri")), root)
            if not path:
                continue
            region = pl.get("region") if isinstance(pl.get("region"), dict) else {}
            start, end = as_line(region.get("startLine")), as_line(region.get("endLine"))
            phys = {"artifactLocation": {"uri": path}}
            if start:
                phys["region"] = {"startLine": start, **({"endLine": end} if end and end >= start else {})}
            locs.append({"physicalLocation": phys})
        if locs:
            out["locations"] = locs
        results.append(out)
        rules.setdefault(rule, {"id": rule, "shortDescription": {"text": RULE_TITLES.get(rule, rule)},
                                "properties": {"tags": ["ai"]}})
    return results, [rules[k] for k in sorted(rules)]


def document(results, rules, props):
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "fraim", "version": VERSION,
                                "informationUri": "https://github.com/fraim-dev/fraim", "rules": rules}},
            "results": results,
            "properties": {"scanoria/fraim": props},
        }],
    }


def risk_level(results):
    found = [r["properties"]["severity"] for r in results if r["ruleId"] == "fraim/risk-flagger"]
    for s in SEVERITIES:
        if s in found:
            return s
    return "none"


def changed_files():
    path = os.environ.get("SCANORIA_CHANGED_FILES") or ""
    if not path:
        return None
    try:
        with open(path, encoding="utf-8") as f:
            files = [ln.rstrip("\n") for ln in f.read(4 << 20).splitlines()[:MAX_CHANGED]]
    except OSError:
        return None
    return [p for p in files if p and not p.startswith("/") and not any(s in ("", ".", "..") for s in p.split("/"))]


def globs_for(patterns, files):
    """Fichiers modifiés que le workflow aurait analysés ; None : tout le dépôt ; [] : rien."""
    if files is None:
        return None
    return [p for p in files if any(fnmatch.fnmatch(os.path.basename(p), g) for g in patterns)]


async def run_workflow(name, options):
    """Un workflow de Fraim dans le processus ; liste de résultats (dict)."""
    from fraim.core.workflows.discovery import discover_workflows  # noqa: PLC0415
    cls = discover_workflows()[name]
    opts_cls = cls.options()
    fields = set(getattr(opts_cls, "__dataclass_fields__", {}))
    wf = cls(args=opts_cls(**{k: v for k, v in options.items() if k in fields}))
    found = await wf.run() or []
    return [r.model_dump(mode="json", exclude_none=True) if hasattr(r, "model_dump") else r for r in found]


async def run_plan(plan):
    """Workflows dans une seule boucle asyncio (celle de litellm) ; (trouvés, lancés, en échec)."""
    found, ran, failed = [], [], []
    for name, options in plan:
        try:
            found += [(name, r) for r in await run_workflow(name, options)]
            ran.append(name)
        except (Exception, SystemExit) as e:  # noqa: BLE001 (un workflow en échec n'empêche pas les autres)
            # SystemExit compris : un workflow de Fraim qui abandonne (réponses du
            # modèle toutes invalides) appelle sys.exit et sortait en code 255.
            sys.stderr.write("fraim %s failed: %s\n" % (name, e.__class__.__name__))
            failed.append(name)
    return found, ran, failed


CALLS = {"ok": 0, "failed": 0}


def count_llm_calls():
    """Fraim saute en silence un morceau dont l'appel au modèle échoue : chaque appel est
    compté, pour qu'un relais injoignable ne passe jamais pour « aucun résultat »."""
    import litellm  # noqa: PLC0415
    real = litellm.acompletion

    async def counted(*args, **kwargs):
        try:
            res = await real(*args, **kwargs)
        except BaseException:
            CALLS["failed"] += 1
            raise
        CALLS["ok"] += 1
        repair_response(res)
        return res
    litellm.acompletion = counted


THINK_RE = re.compile(r"<think>.*?</think>", re.DOTALL | re.IGNORECASE)
FENCE_RE = re.compile(r"\A\s*```[A-Za-z0-9_-]*\s*\n(.*?)\n?\s*```\s*\Z", re.DOTALL)
RESULT_KEYS = ("locations", "level", "ruleId")
LINE_KEYS = ("startLine", "endLine", "startColumn", "endColumn")


def repair_json(v):
    """Écarts courants des modèles par rapport au SARIF attendu par Fraim, corrigés
    sans rien inventer : objet {text} donné comme simple chaîne (snippet, message),
    artifactLocation donné comme chemin, numéros de ligne donnés comme chaînes."""
    if isinstance(v, list):
        return [repair_json(x) for x in v]
    if not isinstance(v, dict):
        return v
    out = {}
    for k, x in v.items():
        if isinstance(x, str) and (k == "snippet" or (k == "message" and any(r in v for r in RESULT_KEYS))):
            x = {"text": x}
        elif k == "artifactLocation" and isinstance(x, str):
            x = {"uri": x}
        elif k in LINE_KEYS and isinstance(x, str) and x.strip().isdigit():
            x = int(x.strip())
        out[k] = repair_json(x)
    return out


def repair_text(content):
    """Réponse du modèle rendue lisible par Fraim quel que soit le modèle : blocs de
    raisonnement <think> retirés, clôture Markdown retirée, JSON remis en forme
    (repair_json). Un texte qui n'est pas du JSON est rendu sans autre changement."""
    if not isinstance(content, str):
        return content
    text = THINK_RE.sub("", content).strip()
    m = FENCE_RE.match(text)
    if m:
        text = m.group(1).strip()
    try:
        data = json.loads(text)
    except ValueError:
        return text
    if not isinstance(data, (dict, list)):
        return text
    return json.dumps(repair_json(data), ensure_ascii=False)


def repair_response(res):
    try:
        for choice in res.choices:
            choice.message.content = repair_text(choice.message.content)
    except Exception as e:  # noqa: BLE001 (la réponse d'origine reste utilisée telle quelle)
        sys.stderr.write("fraim: response not repaired: %s\n" % e.__class__.__name__)


def use_diff_file(diff):
    """Le diff de la PR remplace git dans le conteneur (fraim.inputs.git_diff)."""
    from fraim.inputs import git_diff  # noqa: PLC0415
    git_diff.GitDiff._git_repo = lambda self: None
    git_diff.GitDiff._git_diff = lambda self, repo: diff


def configure():
    os.environ.update({"LITELLM_LOCAL_MODEL_COST_MAP": "True", "GIT_PYTHON_REFRESH": "quiet"})
    for k in ("GITHUB_TOKEN", "GH_TOKEN", "SLACK_WEBHOOK_URL"):
        os.environ.pop(k, None)


def main(argv):
    output = out_path(argv[2]) if len(argv) == 3 else None
    if output is None:
        sys.stderr.write("usage: fraim_scan.py <sources> /out/<nom>.sarif\n")
        return 2
    root = argv[1]
    configure()
    work = tempfile.mkdtemp(prefix="fraim-")   # TMPDIR du manifeste, privé (0700)
    os.chdir(work)
    model = "openai/" + (os.environ.get("SCANORIA_AI_MODEL") or "scanoria")
    base = {"location": root, "model": model, "temperature": 0, "confidence": CONFIDENCE,
            "output": work, "max_concurrent_chunks": 2}
    from fraim.workflows.code.workflow import FILE_PATTERNS as CODE  # noqa: PLC0415
    from fraim.workflows.iac.workflow import FILE_PATTERNS as IAC  # noqa: PLC0415
    files = changed_files()
    plan = []
    for name, patterns in (("code", CODE), ("iac", IAC)):
        globs = globs_for(patterns, files)
        if globs != []:
            plan.append((name, dict(base, globs=globs)))
    diff = None
    diff_path = os.environ.get("SCANORIA_PR_DIFF") or ""
    if diff_path:
        try:
            with open(diff_path, encoding="utf-8", errors="replace") as f:
                diff = f.read(MAX_DIFF_BYTES)
        except OSError:
            diff = None
    if diff and diff.strip():
        use_diff_file(diff)
        plan.append(("risk_flagger", dict(base, diff=True, pr_url="", approver="", slack_webhook_url="",
                                          no_gh_comment=True)))
    if not plan:
        sys.stderr.write("fraim: nothing to analyse (no source, IaC or pull request diff)\n")
        return 3
    count_llm_calls()
    found, ran, failed = asyncio.run(run_plan(plan))
    if not ran:
        sys.stderr.write("fraim: no workflow completed\n")
        return 3
    if CALLS["failed"] and not CALLS["ok"]:
        sys.stderr.write("fraim: every call to the AI relay failed\n")
        return 3
    results, rules = convert(found, root)
    props = {"version": VERSION, "workflows": ran, "failed": failed,
             "llm_calls": dict(CALLS), "partial": bool(CALLS["failed"])}
    if diff:
        props["pr_risk"] = risk_level(results)
    tmp = output + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(document(results, rules, props), f, ensure_ascii=False, separators=(",", ":"))
    os.replace(tmp, output)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
