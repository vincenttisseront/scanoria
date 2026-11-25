# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Vincent Tisseront
"""Jeux de règles G4 côté root (0.7, chantier A, contrat 34).

La console (scanoria-worker) range chaque version retenue par le plan dans
/var/lib/scanoria/scans/jobs/rulesets/<sha256>, puis cite dans la tâche
{slug, engine, version, sha256} pour chaque module qui déclare
scan.rulesets. Le runner et le helper ne font confiance à rien :
  - fichier régulier du compte scanoria, lien unique, ouvert sans suivre de
    lien, 1 Mio au plus, empreinte égale à son nom et à la tâche ;
  - moteur égal à celui du manifeste ; slug [a-z0-9-] ;
  - contrôles statiques du contenu : UTF-8 sans NUL, et pour gitleaks aucune
    inclusion d'un autre fichier ([extend] path ou url) ; pour KICS, document
    JSON {queries: [{id, metadata, query}]} déplié en fichiers ;
  - la validation par le moteur se fait dans le conteneur confiné, jamais sur
    l'hôte (code de sortie 3 de l'outil = E_RULESET_INVALID, classe input).
Les jeux sont posés sous <workspace>/rules/<module>/<slug>/, lisibles par le
conteneur (65534) et montés en lecture seule sur /rules.
"""

import hashlib
import json
import os
import re
import stat

from . import common
from .common import Fail

ENGINES = ("opengrep", "semgrep", "gitleaks", "checkov", "kics")
FILE_OF = {"opengrep": "rules.yaml", "semgrep": "rules.yaml", "gitleaks": "gitleaks.toml",
           "checkov": "policies.yaml"}
MAX_BYTES = 1 << 20
MAX_PER_MODULE = 16
MAX_KICS_QUERIES = 500
SLUG_RE = re.compile(r"[a-z0-9][a-z0-9-]{0,62}\Z")
SHA_RE = re.compile(r"[0-9a-f]{64}\Z")
KICS_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,79}\Z")
# gitleaks : [extend] path = "…" ou url = "…" lirait un autre fichier ; useDefault seul est permis.
GITLEAKS_EXTEND_RE = re.compile(r"(?m)^\s*\[\s*extend\s*\]\s*$")
GITLEAKS_INCLUDE_RE = re.compile(r"(?m)^\s*(path|url)\s*=")
RESERVED = ("scanoria-base",)

E_INVALID = "E_RULESET_INVALID"
E_MISSING = "E_RULESET_MISSING"
E_NONE = "E_RULESET_NONE"


def store_dir(scans_dir):
    return os.path.join(scans_dir, "jobs", "rulesets")


def spec_of(manifest):
    """scan.rulesets du manifeste, ou None."""
    rs = ((manifest or {}).get("scan") or {}).get("rulesets")
    if not isinstance(rs, dict) or rs.get("engine") not in ENGINES or rs.get("mount") != "/rules":
        return None
    return rs


def _read_store(base, sha):
    path = os.path.join(store_dir(base), sha)
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        raise Fail(E_MISSING, "ruleset %s is missing from the queue" % sha[:12])
    except OSError:
        raise Fail(E_INVALID, "ruleset %s is not a regular file" % sha[:12])
    with os.fdopen(fd, "rb") as f:
        st = os.fstat(f.fileno())
        if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
            raise Fail(E_INVALID, "ruleset %s is not a regular file" % sha[:12])
        if not common.TEST_ROOT and st.st_uid != common.scanoria_ids()[0]:
            raise Fail(E_INVALID, "ruleset %s has a wrong owner" % sha[:12])
        if st.st_size > MAX_BYTES:
            raise Fail(E_INVALID, "ruleset %s is larger than 1 MiB" % sha[:12])
        data = f.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES or hashlib.sha256(data).hexdigest() != sha:
        raise Fail(E_INVALID, "ruleset %s does not match its digest" % sha[:12])
    return data


def kics_queries(data):
    """Document JSON des requêtes KICS → [(id, metadata JSON, rego)]."""
    try:
        doc = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise Fail(E_INVALID, "KICS ruleset is not valid JSON")
    qs = doc.get("queries") if isinstance(doc, dict) else None
    if not isinstance(qs, list) or not 1 <= len(qs) <= MAX_KICS_QUERIES or set(doc) - {"queries"}:
        raise Fail(E_INVALID, "KICS ruleset must be {queries: [...]} with 1 to %d queries" % MAX_KICS_QUERIES)
    out, seen = [], set()
    for i, q in enumerate(qs):
        if not isinstance(q, dict) or set(q) - {"id", "metadata", "query"}:
            raise Fail(E_INVALID, "KICS query %d: only id, metadata and query are allowed" % (i + 1))
        qid, meta, rego = q.get("id"), q.get("metadata"), q.get("query")
        if not isinstance(qid, str) or not KICS_ID_RE.match(qid) or qid in seen:
            raise Fail(E_INVALID, "KICS query %d: invalid or duplicate id" % (i + 1))
        if not isinstance(meta, dict) or not isinstance(rego, str) or not rego.strip() or "\x00" in rego:
            raise Fail(E_INVALID, "KICS query %s: metadata object and query text are required" % qid)
        seen.add(qid)
        out.append((qid, json.dumps(meta, ensure_ascii=False, sort_keys=True), rego))
    return out


def check_content(engine, data):
    """Contrôles statiques, sans interpréter les règles (le moteur le fait, confiné)."""
    if engine not in ENGINES:
        raise Fail(E_INVALID, "unknown ruleset engine")
    if not data or len(data) > MAX_BYTES:
        raise Fail(E_INVALID, "ruleset size must be within 1 byte and 1 MiB")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise Fail(E_INVALID, "ruleset is not UTF-8 text")
    if "\x00" in text:
        raise Fail(E_INVALID, "ruleset contains a NUL byte")
    if engine == "gitleaks" and GITLEAKS_EXTEND_RE.search(text):
        # La section [extend] ne peut que reprendre la configuration par défaut.
        sect = text[GITLEAKS_EXTEND_RE.search(text).end():]
        nxt = re.search(r"(?m)^\s*\[", sect)
        if GITLEAKS_INCLUDE_RE.search(sect[:nxt.start()] if nxt else sect):
            raise Fail(E_INVALID, "gitleaks [extend] may only use useDefault, never path or url")
    if engine in ("opengrep", "semgrep") and not re.search(r"(?m)^rules\s*:", text):
        raise Fail(E_INVALID, "%s ruleset needs a top-level rules: key" % engine)
    if engine == "checkov" and not (re.search(r"(?m)^\s*-?\s*metadata\s*:", text)
                                    and re.search(r"(?m)^\s*definition\s*:", text)):
        raise Fail(E_INVALID, "checkov policy needs metadata: and definition:")
    if engine == "kics":
        kics_queries(data)
    return text


def load(item, manifest, base):
    """Jeux de règles d'un module de la tâche : [{slug, engine, version, sha256, data}]."""
    spec = spec_of(manifest)
    given = item.get("rulesets") or []
    if spec is None:
        if given:
            raise Fail(E_INVALID, "module %s does not read rulesets" % manifest.get("id"))
        return []
    if not isinstance(given, list) or len(given) > MAX_PER_MODULE:
        raise Fail(E_INVALID, "too many rulesets")
    out, seen = [], set()
    for r in given:
        if not isinstance(r, dict):
            raise Fail(E_INVALID, "malformed ruleset reference")
        slug, engine, sha, ver = r.get("slug"), r.get("engine"), r.get("sha256"), r.get("version")
        if not isinstance(slug, str) or not SLUG_RE.match(slug) or slug in RESERVED or slug in seen:
            raise Fail(E_INVALID, "invalid or duplicate ruleset slug")
        if engine != spec["engine"]:
            raise Fail(E_INVALID, "ruleset %s is for %s, not %s" % (slug, engine, spec["engine"]))
        if not isinstance(sha, str) or not SHA_RE.match(sha):
            raise Fail(E_INVALID, "ruleset %s: invalid digest" % slug)
        if not isinstance(ver, int) or isinstance(ver, bool) or ver < 1:
            raise Fail(E_INVALID, "ruleset %s: invalid version" % slug)
        data = _read_store(base, sha)
        check_content(engine, data)
        seen.add(slug)
        out.append({"slug": slug, "engine": engine, "version": ver, "sha256": sha, "data": data})
    if spec.get("env") and len(out) > 1:
        raise Fail(E_INVALID, "%s reads a single configuration: attach one %s ruleset only" % (manifest.get("id"), spec["engine"]))
    return out


def _write(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
    with os.fdopen(fd, "wb") as f:
        f.write(data)


def stage(rulesets, dest):
    """Pose les jeux sous dest/<slug>/ (dest neuf), lisibles par le conteneur."""
    os.mkdir(dest, 0o755)
    for r in rulesets:
        d = os.path.join(dest, r["slug"])
        os.mkdir(d, 0o755)
        if r["engine"] == "kics":
            for qid, meta, rego in kics_queries(r["data"]):
                q = os.path.join(d, qid)
                os.mkdir(q, 0o755)
                _write(os.path.join(q, "metadata.json"), meta.encode("utf-8"))
                _write(os.path.join(q, "query.rego"), rego.encode("utf-8"))
        else:
            _write(os.path.join(d, FILE_OF[r["engine"]]), r["data"])
    for root, dirs, files in os.walk(dest):
        os.chmod(root, 0o755)
        for f in files:
            os.chmod(os.path.join(root, f), 0o644)
    return dest


def env_of(manifest, rulesets):
    """Variable du moteur à fichier unique (gitleaks : GITLEAKS_CONFIG)."""
    spec = spec_of(manifest)
    if not spec or not spec.get("env") or not rulesets:
        return {}
    r = rulesets[0]
    return {spec["env"]: "/rules/%s/%s" % (r["slug"], FILE_OF[r["engine"]])}


def digest_of(rulesets):
    """Empreintes retenues, pour la clé de réutilisation V4 et le plan (G11)."""
    return [{"slug": r["slug"], "version": r["version"], "sha256": r["sha256"]} for r in rulesets]


# --------------------------------------------------------------------------
# Demande validate-ruleset (G4, I12) : le moteur juge le jeu de règles, confiné
# --------------------------------------------------------------------------

E_ENGINE_MISSING = "E_RULESET_ENGINE_MISSING"
SAMPLE_NAME_RE = re.compile(r"[A-Za-z0-9_][A-Za-z0-9._-]{0,99}\Z")
MAX_SAMPLES = 10
MAX_SAMPLE = 8192
VALIDATE_TIMEOUT = 300
# Module qui porte chaque moteur.
MODULE_OF = {"opengrep": "opengrep", "semgrep": "semgrep", "gitleaks": "gitleaks",
             "checkov": "checkov", "kics": "kics"}
KICS_BUILTIN = "/app/bin/assets/queries"


def validation_command(engine, manifest):
    """Commande du module réduite aux seules règles du jeu (sans règles intégrées quand c'est possible)."""
    from . import testbed
    scan = manifest["scan"]
    opts = testbed.option_defaults(manifest)
    if "builtin_rules" in opts:
        opts["builtin_rules"] = False
    cmd = testbed.render_command(scan["command"], opts)
    if engine == "checkov":
        cmd = cmd + ["--external-only"]
    elif engine == "kics":
        out = []
        i = 0
        while i < len(cmd):
            if cmd[i] == "--queries-path" and i + 1 < len(cmd) and cmd[i + 1] == KICS_BUILTIN:
                i += 2
                continue
            out.append(cmd[i])
            i += 1
        cmd = out
    return cmd


def count_by_sample(manifest, out_dir, names):
    """Résultats par échantillon, lus dans la sortie SARIF déclarée (sans suivre de lien)."""
    from . import testbed
    decl = (manifest.get("outputs") or {}).get("sarif") or {}
    rel = testbed._out_rel(decl.get("path") or "")
    doc = testbed._read_output(out_dir, rel)
    testbed.sarif_results(doc)   # contrôle de forme
    counts = {n: 0 for n in names}
    results = [r for run in doc["runs"] if isinstance(run, dict) for r in (run.get("results") or [])
               if isinstance(r, dict)]
    for res in results[:100000]:
        for loc in res.get("locations") or []:
            uri = (((loc or {}).get("physicalLocation") or {}).get("artifactLocation") or {}).get("uri")
            if isinstance(uri, str):
                base = uri.replace("file://", "").split("/")[-1]
                if base in counts:
                    counts[base] += 1
                    break
    return counts


def act_validate_ruleset(c):
    from . import modules, testbed
    p = c.params
    engine, sha = p.get("engine"), p.get("sha256")
    if engine not in ENGINES or not isinstance(sha, str) or not SHA_RE.match(sha):
        raise Fail("E_INVALID_PARAM", "invalid engine or digest")
    samples = p.get("samples") or []
    if not isinstance(samples, list) or len(samples) > MAX_SAMPLES:
        raise Fail("E_INVALID_PARAM", "at most %d samples" % MAX_SAMPLES)
    names = []
    for s in samples:
        name, content = (s or {}).get("name"), (s or {}).get("content")
        if not isinstance(name, str) or not SAMPLE_NAME_RE.match(name) or name in names or ".." in name:
            raise Fail("E_INVALID_PARAM", "invalid or duplicate sample name")
        if not isinstance(content, str) or len(content.encode("utf-8")) > MAX_SAMPLE or "\x00" in content:
            raise Fail("E_INVALID_PARAM", "sample %s is too large or not text" % name)
        names.append(name)
    reg = modules.load_registry()
    mid = MODULE_OF[engine]
    e = reg["modules"].get(mid)
    m = e.get("manifest") if isinstance(e, dict) else None
    if not isinstance(m, dict) or e.get("status") != "healthy" or e.get("enabled") is not True \
            or spec_of(m) is None or spec_of(m)["engine"] != engine:
        raise Fail(E_ENGINE_MISSING, "module %s is not installed, healthy and enabled" % mid)
    try:
        data = _read_store(_scans_dir(), sha)
        check_content(engine, data)
    except Fail as f:
        return {"engine": engine, "module": mid, "version": m.get("version"), "ok": False,
                "errors": [f.message], "samples": []}
    common.set_step("run")
    import secrets as _secrets
    os.makedirs(testbed.WORK, mode=0o700, exist_ok=True)
    work = os.path.join(testbed.WORK, "ruleset-%s" % _secrets.token_hex(6))
    os.mkdir(work, 0o700)
    try:
        src, out = os.path.join(work, "src"), os.path.join(work, "out")
        os.mkdir(src, 0o755)
        for s in samples:
            _write(os.path.join(src, s["name"]), s["content"].encode("utf-8"))
            os.chmod(os.path.join(src, s["name"]), 0o644)
        testbed._prepare_out(out)
        staged = stage([{"slug": "candidate", "engine": engine, "version": 1, "sha256": sha, "data": data}],
                       os.path.join(work, "rules"))
        env = dict(m["scan"].get("env") or {})
        env.update(env_of(m, [{"slug": "candidate", "engine": engine}]))
        cmd = validation_command(engine, m)
        timeout = max(30, min(VALIDATE_TIMEOUT, int(c.left()) - 30))
        mounts = [(src, "/src", "ro"), (out, "/out", "rw"), (staged, "/rules", "ro")]
        from . import svcnet
        try:
            mounts += svcnet.tool_mount(m)
        except svcnet.Unavailable as u:
            raise Fail(E_ENGINE_MISSING, u.message)
        rc, hint = testbed.run_confined(m, cmd, mounts, timeout=timeout, env=env, with_stderr=True)
        base = {"engine": engine, "module": mid, "version": m.get("version")}
        if rc == 3:
            return dict(base, ok=False, errors=["rejected by %s: %s" % (engine, hint or "invalid rules")], samples=[])
        if rc not in (m["scan"].get("exit_codes_ok") or testbed.SCANNER_OK_RC):
            raise Fail("E_TESTBED", "%s exited with code %d while validating%s" % (mid, rc, (": " + hint) if hint else ""))
        try:
            counts = count_by_sample(m, out, names)
        except Fail as f:
            return dict(base, ok=False, errors=["no usable output: %s" % f.message], samples=[])
        return dict(base, ok=True, errors=[], samples=[{"name": n, "matches": counts[n]} for n in names])
    finally:
        import shutil
        shutil.rmtree(work, ignore_errors=True)


def _scans_dir():
    from . import runner
    return runner.SCANS
