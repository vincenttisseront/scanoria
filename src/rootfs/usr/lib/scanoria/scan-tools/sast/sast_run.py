# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Vincent Tisseront
"""Enveloppe des scanners SAST, IaC et CI de Scanoria (0.7, chantier A).

Usage (dans le conteneur confiné du module, outil monté sur /scanoria) :
    python3 -I /scanoria/sast_run.py <moteur> [options]

Moteurs : opengrep, semgrep, checkov, bandit, zizmor, scorecard.

Disposition (CLAUDE.md § 6.4, contrat 34) :
  /src    sources, lecture seule ;
  /out    sorties du module ;
  /rules  jeux de règles G4 retenus par le plan, un dossier par jeu
          (/rules/<slug>/rules.yaml, policies.yaml…), lecture seule, monté
          par le runner seulement quand le profil en rattache ;
  /scanoria  cet outil et les règles maison (rules/opengrep/scanoria-base.yaml).

Sortie : SARIF 2.1.0 dans /out/<moteur>.sarif. Codes de sortie :
  0  analyse faite, sortie écrite ;
  2  échec de l'outil (le runner le classe E_TOOL_EXIT) ;
  3  jeu de règles refusé par le moteur (E_RULESET_INVALID, classe input) ;
  4  aucun jeu de règles pour un moteur qui en exige un (Semgrep CE).

Aucun appel réseau (le conteneur n'en a pas) ; aucune valeur de secret
recopiée : l'extrait de code d'un résultat de type « secret » est remplacé.
"""

import json
import os
import re
import shutil
import subprocess
import sys

TOOL_VERSION = "1.0.0"
SRC = "/src"
OUT = "/out"
RULES = "/rules"
HERE = os.path.dirname(os.path.abspath(__file__))
BUILTIN_OPENGREP = os.path.join(HERE, "rules", "opengrep", "scanoria-base.yaml")
MAX_RESULTS = 20000
MAX_TEXT = 1000
MAX_SNIPPET = 400
MAX_NATIVE = 256 << 20
CTRL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")
REDACTED = "[valeur masquée par Scanoria]"
# Règle qui vise un secret écrit en dur : son extrait n'est jamais recopié.
SECRET_RULE_RE = re.compile(r"(?i)(secret|password|passw|pwd|token|api[-_]?key|credential|private[-_]?key|hardcoded)")
SECRET_CWES = {"CWE-259", "CWE-321", "CWE-798", "CWE-547"}

RC_OK, RC_TOOL, RC_RULESET, RC_NO_RULES = 0, 2, 3, 4


class ToolError(Exception):
    def __init__(self, code, message):
        Exception.__init__(self, message)
        self.code = code


def log(msg):
    sys.stderr.write("sast_run: %s\n" % msg)


def clean(value, limit=MAX_TEXT):
    if not isinstance(value, str):
        return ""
    return CTRL_RE.sub(" ", value)[:limit]


def read_json(path, limit=MAX_NATIVE):
    if not os.path.isfile(path) or os.path.islink(path):
        raise ToolError(RC_TOOL, "%s missing" % os.path.basename(path))
    if os.path.getsize(path) > limit:
        raise ToolError(RC_TOOL, "%s too large" % os.path.basename(path))
    with open(path, "rb") as f:
        return json.loads(f.read().decode("utf-8", "replace"))


def write_json(path, doc):
    tmp = path + ".part"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(doc, f, ensure_ascii=False, separators=(",", ":"))
    os.replace(tmp, path)


def ruleset_dirs(root=None):
    """Dossiers /rules/<slug> retenus par le plan, triés ; jamais un lien."""
    root = root or RULES
    if not os.path.isdir(root) or os.path.islink(root):
        return []
    out = []
    for name in sorted(os.listdir(root)):
        p = os.path.join(root, name)
        if SLUG_RE.match(name) and os.path.isdir(p) and not os.path.islink(p):
            out.append((name, p))
    return out


def ruleset_files(name, root=None):
    """Fichiers <name> des jeux de règles montés : [(slug, chemin)]."""
    res = []
    for slug, d in ruleset_dirs(root):
        p = os.path.join(d, name)
        if os.path.isfile(p) and not os.path.islink(p):
            res.append((slug, p))
    return res


def run(argv, timeout=None, stdout=None, cwd=None):
    try:
        return subprocess.run(argv, stdout=stdout, stderr=None, timeout=timeout, cwd=cwd, check=False).returncode
    except FileNotFoundError:
        raise ToolError(RC_TOOL, "%s not found in the image" % argv[0])


# --------------------------------------------------------------------------
# SARIF : mise en forme commune
# --------------------------------------------------------------------------

def rel_uri(uri):
    """Chemin relatif à /src (les outils écrivent /src/a.py, file:///src/a.py ou a.py)."""
    if not isinstance(uri, str):
        return None
    u = uri
    if u.startswith("file://"):
        u = u[len("file://"):]
    if u.startswith(SRC + "/"):
        u = u[len(SRC) + 1:]
    while u.startswith("./"):
        u = u[2:]
    if not u or u.startswith("/") or "\x00" in u or any(p == ".." for p in u.split("/")):
        return None
    return u


def is_secret_rule(rule_id, rule):
    if SECRET_RULE_RE.search(rule_id or ""):
        return True
    props = (rule or {}).get("properties") or {}
    tags = [t for t in (props.get("tags") or []) if isinstance(t, str)]
    if any(t.upper().split(":")[0].strip() in SECRET_CWES for t in tags):
        return True
    return any("secret" in t.lower() for t in tags)


def tidy_sarif(doc, tool_name):
    """Revoit une sortie SARIF native : chemins sous /src, extraits bornés,
    extraits des règles de secrets masqués, nombre de résultats borné."""
    if not isinstance(doc, dict) or not isinstance(doc.get("runs"), list):
        raise ToolError(RC_TOOL, "native output is not SARIF")
    doc["$schema"] = "https://json.schemastore.org/sarif-2.1.0.json"
    doc["version"] = "2.1.0"
    kept = 0
    for run_ in doc["runs"]:
        if not isinstance(run_, dict):
            continue
        rules = ((run_.get("tool") or {}).get("driver") or {}).get("rules") or []
        by_id = {r.get("id"): r for r in rules if isinstance(r, dict)}
        results = run_.get("results") if isinstance(run_.get("results"), list) else []
        out = []
        for res in results:
            if not isinstance(res, dict):
                continue
            if kept >= MAX_RESULTS:
                props = run_.setdefault("properties", {})
                props.setdefault("scanoria", {})["truncated"] = True
                break
            rid = res.get("ruleId") if isinstance(res.get("ruleId"), str) else ""
            secret = is_secret_rule(rid, by_id.get(rid))
            for loc in res.get("locations") or []:
                phys = (loc or {}).get("physicalLocation") or {}
                art = phys.get("artifactLocation") or {}
                if "uri" in art:
                    rel = rel_uri(art.get("uri"))
                    if rel is None:
                        art.pop("uri", None)
                    else:
                        art["uri"] = rel
                    art.pop("uriBaseId", None)
                for key in ("region", "contextRegion"):
                    reg = phys.get(key)
                    if isinstance(reg, dict) and isinstance(reg.get("snippet"), dict):
                        if secret:
                            reg["snippet"] = {"text": REDACTED}
                        else:
                            reg["snippet"]["text"] = clean(reg["snippet"].get("text"), MAX_SNIPPET)
            # Une correction proposée par l'outil peut citer le secret : jamais recopiée.
            # Le message peut interpoler la valeur (métavariables) : texte de la règle à la place.
            if secret:
                res.pop("fixes", None)
                res.pop("codeFlows", None)
                desc = ((by_id.get(rid) or {}).get("shortDescription") or {}).get("text")
                res["message"] = {"text": clean(desc, 300) if isinstance(desc, str) and desc else "Possible hardcoded secret (%s)" % clean(rid, 120)}
            out.append(res)
            kept += 1
        run_["results"] = out
        run_.pop("originalUriBaseIds", None)
        props = run_.setdefault("properties", {})
        props.setdefault("scanoria", {}).update({"wrapper": "sast_run", "wrapper_version": TOOL_VERSION, "tool": tool_name})
    return doc


def new_sarif(name, version, uri, rules, results, props=None):
    run_ = {
        "tool": {"driver": {"name": name, "version": version, "informationUri": uri, "rules": rules}},
        "results": results,
        "properties": {"scanoria": dict({"wrapper": "sast_run", "wrapper_version": TOOL_VERSION}, **(props or {}))},
    }
    return {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0", "runs": [run_]}


# --------------------------------------------------------------------------
# Opengrep et Semgrep CE (même syntaxe de règles)
# --------------------------------------------------------------------------

def grep_configs(engine, builtin):
    """Fichiers de règles : jeux G4 montés, plus les règles maison (Opengrep, option).
    [(nom, chemin)] ; le nom sert de fichier dans le répertoire de travail."""
    files = list(ruleset_files("rules.yaml"))
    # Semgrep CE : ses règles viennent des jeux G4 (règles officielles importées par
    # l'administrateur) ; les règles maison ne servent qu'à défaut, au banc d'essai,
    # car le plan n'en lance pas l'analyse sans jeu de règles rattaché.
    use_builtin = builtin if engine == "opengrep" else not files
    if use_builtin and os.path.isfile(BUILTIN_OPENGREP):
        files.insert(0, ("scanoria-base", BUILTIN_OPENGREP))
    return files


GREP_WORK = "/tmp/sast-rules"


def stage_configs(configs, work=None):
    """Copie chaque fichier de règles en <work>/<nom>.yaml : lancé depuis work,
    le moteur ne préfixe pas les identifiants de règle par le chemin du fichier."""
    work = work or GREP_WORK
    shutil.rmtree(work, ignore_errors=True)
    os.makedirs(work)
    names = []
    for name, path in configs:
        dst = os.path.join(work, name + ".yaml")
        shutil.copyfile(path, dst)
        names.append(name + ".yaml")
    return names


def run_grep(engine, args):
    builtin = "--builtin=false" not in args
    configs = grep_configs(engine, builtin)
    if not configs:
        raise ToolError(RC_NO_RULES, "no rules for %s: attach a ruleset to the profile" % engine)
    names = stage_configs(configs)
    native = os.path.join(OUT, engine + ".native.sarif")
    binary = os.environ.get("SCANORIA_%s_BIN" % engine.upper()) or engine
    argv = [binary, "scan"]
    for c in names:
        argv += ["--config", c]
    argv += ["--sarif-output", native, "--quiet", "--disable-version-check", "--no-git-ignore",
             "--timeout", "60", "--max-target-bytes", "5000000"]
    if engine == "semgrep":
        argv += ["--metrics", "off", "--oss-only"]
    argv.append(SRC)
    rc = run(argv, cwd=GREP_WORK)
    # 0 : rien ; 1 : résultats (--error) ; autre : règles invalides ou échec.
    if rc not in (0, 1) or not os.path.isfile(native):
        uses_rulesets = any(p != BUILTIN_OPENGREP for _, p in configs)
        raise ToolError(RC_RULESET if uses_rulesets and rc in (2, 4, 5, 7) else RC_TOOL,
                        "%s exited with code %d" % (engine, rc))
    doc = tidy_sarif(read_json(native), engine)
    os.unlink(native)
    write_json(os.path.join(OUT, engine + ".sarif"), doc)


# --------------------------------------------------------------------------
# Checkov
# --------------------------------------------------------------------------

def checkov_external_dirs(work):
    """policies.yaml d'un jeu de règles : une politique ou une liste de
    politiques YAML Checkov ; chacune devient un fichier de work/<slug>/."""
    import yaml  # présent dans l'image de Checkov
    dirs, ids = [], []
    for slug, path in ruleset_files("policies.yaml"):
        with open(path, "rb") as f:
            raw = f.read((1 << 20) + 1)
        try:
            docs = yaml.safe_load(raw.decode("utf-8"))
        except (yaml.YAMLError, UnicodeDecodeError) as e:
            raise ToolError(RC_RULESET, "ruleset %s: invalid YAML (%s)" % (slug, type(e).__name__))
        policies = docs if isinstance(docs, list) else [docs]
        d = os.path.join(work, slug)
        os.makedirs(d, exist_ok=True)
        for i, p in enumerate(policies):
            if not isinstance(p, dict) or not isinstance(p.get("metadata"), dict) \
                    or not isinstance(p.get("definition"), (dict, list)) \
                    or not isinstance(p["metadata"].get("id"), str):
                raise ToolError(RC_RULESET, "ruleset %s: policy %d needs metadata.id and definition" % (slug, i + 1))
            with open(os.path.join(d, "policy-%03d.yaml" % i), "w", encoding="utf-8") as f:
                yaml.safe_dump(p, f)
            ids.append(str(p["metadata"]["id"]))
        dirs.append(d)
    return dirs, ids


CHECKOV_WORK = "/tmp/checkov-rules"


def run_checkov(args):
    work = CHECKOV_WORK
    shutil.rmtree(work, ignore_errors=True)
    os.makedirs(work)
    ext, ids = checkov_external_dirs(work)
    odir = os.path.join(OUT, "checkov.d")
    os.makedirs(odir, exist_ok=True)
    binary = os.environ.get("SCANORIA_CHECKOV_BIN") or "checkov"
    argv = [binary, "--directory", SRC, "--output", "sarif", "--output-file-path", odir,
            "--soft-fail", "--skip-download", "--quiet", "--compact", "--no-guide",
            "--skip-framework", "secrets", "sca_package", "sca_image", "--skip-results-upload"]
    for d in ext:
        argv += ["--external-checks-dir", d]
    if "--external-only" in args:
        # Validation d'un jeu de règles (demande validate-ruleset) : ses seules politiques.
        if not ids:
            raise ToolError(RC_NO_RULES, "no checkov policy to validate")
        argv += ["--check", ",".join(ids)]
    rc = run(argv)
    native = os.path.join(odir, "results_sarif.sarif")
    if rc != 0 or not os.path.isfile(native):
        raise ToolError(RC_RULESET if ext and rc != 0 else RC_TOOL, "checkov exited with code %d" % rc)
    doc = tidy_sarif(read_json(native), "checkov")
    shutil.rmtree(odir, ignore_errors=True)
    write_json(os.path.join(OUT, "checkov.sarif"), doc)


# --------------------------------------------------------------------------
# Bandit (JSON natif → SARIF)
# --------------------------------------------------------------------------

# Tests de Bandit qui visent un secret écrit en dur : extrait jamais recopié.
BANDIT_SECRET_TESTS = {"B105", "B106", "B107"}
BANDIT_CONFIDENCE_DOWN = {"high": "medium", "medium": "low", "low": "low"}


def bandit_severity(sev, conf):
    """Gravité Bandit (HIGH/MEDIUM/LOW), abaissée d'un cran si la confiance est faible."""
    s = (sev or "").strip().lower()
    if s not in ("high", "medium", "low"):
        s = "low"
    if (conf or "").strip().lower() == "low":
        s = BANDIT_CONFIDENCE_DOWN[s]
    return s


def convert_bandit(report):
    if not isinstance(report, dict) or not isinstance(report.get("results"), list):
        raise ToolError(RC_TOOL, "bandit report is malformed")
    rules, index, results = [], {}, []
    for r in report["results"][:MAX_RESULTS]:
        if not isinstance(r, dict):
            continue
        tid = clean(r.get("test_id"), 16) or "B000"
        rid = "bandit/%s" % tid
        cwe = r.get("issue_cwe") or {}
        cwe_id = "CWE-%d" % cwe["id"] if isinstance(cwe.get("id"), int) else None
        if rid not in index:
            index[rid] = len(rules)
            tags = ["security"] + ([cwe_id] if cwe_id else [])
            rules.append({
                "id": rid,
                "name": clean(r.get("test_name"), 120) or tid,
                "shortDescription": {"text": clean(r.get("test_name"), 200) or tid},
                "helpUri": clean(r.get("more_info"), 300) or "https://bandit.readthedocs.io/",
                "properties": {"tags": tags},
            })
        path = rel_uri(r.get("filename"))
        line = r.get("line_number") if isinstance(r.get("line_number"), int) and r.get("line_number") > 0 else 1
        snippet = REDACTED if tid in BANDIT_SECRET_TESTS else clean(r.get("code"), MAX_SNIPPET)
        sev = bandit_severity(r.get("issue_severity"), r.get("issue_confidence"))
        res = {
            "ruleId": rid,
            "ruleIndex": index[rid],
            "level": {"high": "error", "medium": "warning", "low": "note"}[sev],
            # B105–B107 : le message de Bandit recopie la valeur trouvée ; jamais transmis.
            "message": {"text": ("Possible hardcoded password (%s)" % tid) if tid in BANDIT_SECRET_TESTS
                        else (clean(r.get("issue_text")) or tid)},
            "properties": {
                "severity": sev,
                "bandit_severity": clean(r.get("issue_severity"), 16),
                "bandit_confidence": clean(r.get("issue_confidence"), 16),
            },
        }
        if path:
            res["locations"] = [{"physicalLocation": {
                "artifactLocation": {"uri": path},
                "region": {"startLine": line, "snippet": {"text": snippet}},
            }}]
        results.append(res)
    errors = [e for e in (report.get("errors") or []) if isinstance(e, dict)]
    doc = new_sarif("Bandit", clean(report.get("generated_by"), 40) or "unknown",
                    "https://github.com/PyCQA/bandit", rules, results)
    if errors:
        doc["runs"][0]["invocations"] = [{"executionSuccessful": True, "toolExecutionNotifications": [
            {"level": "warning", "message": {"text": clean("%s: %s" % (rel_uri(e.get("filename")) or "?", e.get("reason")), 300)}}
            for e in errors[:100]]}]
    return doc


def run_bandit(args):
    native = os.path.join(OUT, "bandit.json")
    binary = os.environ.get("SCANORIA_BANDIT_BIN") or "bandit"
    rc = run([binary, "--recursive", SRC, "--format", "json", "--output", native, "--exit-zero", "--quiet"])
    if rc != 0 or not os.path.isfile(native):
        raise ToolError(RC_TOOL, "bandit exited with code %d" % rc)
    doc = convert_bandit(read_json(native))
    os.unlink(native)
    write_json(os.path.join(OUT, "bandit.sarif"), doc)


# --------------------------------------------------------------------------
# zizmor (SARIF natif sur la sortie standard)
# --------------------------------------------------------------------------

def run_zizmor(args):
    native = os.path.join(OUT, "zizmor.native.sarif")
    binary = os.environ.get("SCANORIA_ZIZMOR_BIN") or "zizmor"
    with open(native, "wb") as f:
        rc = run([binary, "--format", "sarif", "--offline", "--no-progress", "--color", "never", SRC], stdout=f)
    if rc != 0:
        raise ToolError(RC_TOOL, "zizmor exited with code %d" % rc)
    doc = tidy_sarif(read_json(native), "zizmor")
    os.unlink(native)
    write_json(os.path.join(OUT, "zizmor.sarif"), doc)


# --------------------------------------------------------------------------
# OpenSSF Scorecard (mode --local, JSON natif → SARIF)
# --------------------------------------------------------------------------

SCORECARD_URI = "https://github.com/ossf/scorecard/blob/main/docs/checks.md"
# Risque déclaré par Scorecard pour chaque contrôle → gravité d'un contrôle
# faible. Volontairement non bloquant : seul le score global sous le seuil
# l'est (règle scorecard/score-below-threshold), pour ne pas doubler zizmor.
SCORECARD_RISK = {
    "Dangerous-Workflow": "medium",
    "Binary-Artifacts": "low", "Branch-Protection": "low", "Code-Review": "low",
    "Dependency-Update-Tool": "low", "Signed-Releases": "low", "Token-Permissions": "low",
    "Vulnerabilities": "low", "Webhooks": "low",
    "Fuzzing": "info", "Maintained": "info", "Packaging": "info", "Pinned-Dependencies": "info",
    "SAST": "info", "Security-Policy": "info", "CI-Tests": "info", "CII-Best-Practices": "info",
    "Contributors": "info", "License": "info", "SBOM": "info",
}
THRESHOLD_RULE = "scorecard/score-below-threshold"
SEV_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
DETAIL_PATH_RE = re.compile(r"^(?:Warn|Info|Debug): .*?([A-Za-z0-9._/@+-]+\.[A-Za-z0-9]+):(\d+)")


def parse_min_score(args):
    for a in args:
        if a.startswith("--min-score="):
            try:
                v = float(a.split("=", 1)[1])
            except ValueError:
                raise ToolError(RC_TOOL, "invalid --min-score")
            if not 0 <= v <= 10:
                raise ToolError(RC_TOOL, "--min-score must be within 0..10")
            return v
    return 4.0


def check_location(details):
    """Premier fichier cité par un détail « Warn: … chemin:ligne », s'il y en a un."""
    for d in details or []:
        m = DETAIL_PATH_RE.match(d) if isinstance(d, str) else None
        if m:
            rel = rel_uri(m.group(1))
            if rel:
                return rel, int(m.group(2)) or 1
    return None


def convert_scorecard(report, min_score):
    if not isinstance(report, dict) or not isinstance(report.get("checks"), list):
        raise ToolError(RC_TOOL, "scorecard report is malformed")
    sc = report.get("scorecard") or {}
    rules, results, scores = [], [], {}
    rules.append({
        "id": THRESHOLD_RULE,
        "name": "ScoreBelowThreshold",
        "shortDescription": {"text": "OpenSSF Scorecard: aggregate score below the appliance threshold"},
        "helpUri": SCORECARD_URI,
        "properties": {"tags": ["supply-chain", "posture"]},
    })
    for c in report["checks"][:64]:
        if not isinstance(c, dict) or not isinstance(c.get("name"), str):
            continue
        name = clean(c["name"], 60)
        score = c.get("score")
        if not isinstance(score, (int, float)):
            continue
        scores[name] = score
        # -1 : contrôle non concluant ou non applicable en mode local ; 10 : rien à dire.
        if score < 0 or score >= 10:
            continue
        rid = "scorecard/%s" % name
        doc_ = c.get("documentation") or {}
        rules.append({
            "id": rid,
            "name": name.replace("-", ""),
            "shortDescription": {"text": clean(doc_.get("short"), 300) or name},
            "helpUri": clean(doc_.get("url"), 300) or SCORECARD_URI,
            "properties": {"tags": ["supply-chain", "posture"]},
        })
        sev = SCORECARD_RISK.get(name, "info")
        details = [clean(d, 300) for d in (c.get("details") or [])[:20] if isinstance(d, str)]
        res = {
            "ruleId": rid,
            "ruleIndex": len(rules) - 1,
            "level": SEV_LEVEL[sev],
            "message": {"text": clean("%s: %s/10. %s" % (name, score, c.get("reason") or ""))},
            "partialFingerprints": {"scorecardCheck/v1": name},
            "properties": {"severity": sev, "score": score, "details": details},
        }
        loc = check_location(c.get("details"))
        if loc:
            res["locations"] = [{"physicalLocation": {"artifactLocation": {"uri": loc[0]},
                                                      "region": {"startLine": loc[1]}}}]
        results.append(res)
    aggregate = report.get("score")
    if isinstance(aggregate, (int, float)) and 0 <= aggregate < min_score:
        results.insert(0, {
            "ruleId": THRESHOLD_RULE,
            "ruleIndex": 0,
            "level": "error",
            "message": {"text": "OpenSSF Scorecard aggregate score %.1f/10 is below the threshold %.1f (local checks only)."
                        % (aggregate, min_score)},
            "partialFingerprints": {"scorecardCheck/v1": "aggregate"},
            "properties": {"severity": "high", "score": aggregate, "threshold": min_score},
        })
    return new_sarif("OpenSSF Scorecard", clean(sc.get("version"), 40) or "unknown",
                     "https://github.com/ossf/scorecard", rules, results,
                     {"score": aggregate if isinstance(aggregate, (int, float)) else None,
                      "threshold": min_score, "mode": "local", "checks": scores})


def run_scorecard(args):
    min_score = parse_min_score(args)
    native = os.path.join(OUT, "scorecard.json")
    binary = os.environ.get("SCANORIA_SCORECARD_BIN") or "scorecard"
    rc = run([binary, "--local", SRC, "--format", "json", "--show-details", "--output", native])
    if rc != 0 or not os.path.isfile(native):
        raise ToolError(RC_TOOL, "scorecard exited with code %d" % rc)
    doc = convert_scorecard(read_json(native), min_score)
    os.unlink(native)
    write_json(os.path.join(OUT, "scorecard.sarif"), doc)


ENGINES = {
    "opengrep": lambda a: run_grep("opengrep", a),
    "semgrep": lambda a: run_grep("semgrep", a),
    "checkov": run_checkov,
    "bandit": run_bandit,
    "zizmor": run_zizmor,
    "scorecard": run_scorecard,
}


def main(argv):
    if len(argv) < 2 or argv[1] not in ENGINES:
        sys.stderr.write("usage: sast_run.py {%s} [options]\n" % "|".join(sorted(ENGINES)))
        return RC_TOOL
    # --out= : sortie déclarée dans le manifeste (contrat de sortie G2) ; une seule valeur admise.
    outs = [a.split("=", 1)[1] for a in argv[2:] if a.startswith("--out=")]
    if any(o != os.path.join(OUT, argv[1] + ".sarif") for o in outs):
        log("--out must be %s" % os.path.join(OUT, argv[1] + ".sarif"))
        return RC_TOOL
    try:
        ENGINES[argv[1]](argv[2:])
    except ToolError as e:
        log(str(e))
        return e.code
    return RC_OK


if __name__ == "__main__":
    sys.exit(main(sys.argv))
