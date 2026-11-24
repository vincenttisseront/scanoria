# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Vincent Tisseront
"""Analyse SonarQube d'un dépôt puis export SARIF (module sonar-scanner, contrat 12).

Lancé par scanoria-runner dans le conteneur jetable du module (image
sonar-scanner-cli), rattaché au seul réseau interne du service SonarQube :
  1. attend que le serveur réponde UP (api/system/status) ;
  2. lance sonar-scanner sur /src (lecture seule), clé de projet fournie par
     le runner (scanoria-<uuid court>), projet créé automatiquement ;
  3. attend la tâche de calcul (api/ce/task) ;
  4. lit issues et hotspots ouverts (api/issues/search, api/hotspots/search),
     paginés et bornés, puis écrit le SARIF demandé en argument, par défaut
     /out/result.sarif (sonar_sarif.py).

Branches et PR (option « branches » du module sonarqube, plugin
sonarqube-community-branch-plugin) : le runner ne transmet SCANORIA_BRANCH
que pour une référence autre que la branche par défaut, et seulement si le
service a la fonction active ; SCANORIA_PR_KEY, SCANORIA_PR_BRANCH et
SCANORIA_PR_BASE décrivent une PR (analyse des PR, G18). L'analyse et la
lecture des résultats portent alors sur cette branche ou cette PR seulement.

Le jeton d'analyse arrive par un secret Podman monté en fichier : il n'est
jamais passé en argument et n'est transmis à sonar-scanner que par la
variable SONAR_TOKEN de son propre processus. Codes de sortie : 0 succès,
3 serveur indisponible, 4 échec de l'analyse, 5 échec de l'export.
"""

import json
import os
import re
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import sonar_sarif  # noqa: E402

TOKEN_FILE = os.environ.get("SCANORIA_TOKEN_FILE", "/run/secrets/scan-token")
# Réseau interne Internal=true du service, sans sortie : HTTP en clair (contrat 12).
HOST_RE = re.compile(r"http:/{2}[a-z0-9][a-z0-9._-]{0,100}(:[0-9]{1,5})?\Z")
PROJECT_KEY_RE = re.compile(r"scanoria-([0-9a-f]{12}|testbed)\Z")
TASK_RE = re.compile(r"[A-Za-z0-9_-]{1,100}\Z")
# Noms de branche transmis par le runner (déjà validés) : revalidés ici, sans
# tiret initial, sans « .. », sans espace ni caractère de contrôle.
BRANCH_RE = re.compile(r"(?!-)(?!.*\.\.)(?!.*//)[A-Za-z0-9._/+-]{1,200}(?<![/.])\Z")
PR_KEY_RE = re.compile(r"[1-9][0-9]{0,9}\Z")
PAGE_SIZE = 500
MAX_PAGES = 20         # 20 × 500 = 10 000, plafond de api/issues/search
HTTP_TIMEOUT = 30
MAX_RESPONSE = 32 << 20
OUT_DIR = os.environ.get("SCANORIA_OUT_DIR", "/out")
SRC_DIR = os.environ.get("SCANORIA_SRC_DIR", "/src")
SCANNER = os.environ.get("SCANORIA_SONAR_SCANNER", "sonar-scanner")


class Failure(Exception):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


def log(msg):
    sys.stderr.write("sonar-scan: %s\n" % msg)
    sys.stderr.flush()


class Api:
    def __init__(self, host, token):
        self.host, self.token = host.rstrip("/"), token

    def get(self, path, params=None):
        url = "%s/%s" % (self.host, path)
        if params:
            url += "?" + urllib.parse.urlencode(params)
        req = urllib.request.Request(url, headers={"Authorization": "Bearer " + self.token,
                                                   "Accept": "application/json"})
        # Aucun mandataire : le conteneur n'a de toute façon qu'un réseau interne.
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        try:
            with opener.open(req, timeout=HTTP_TIMEOUT) as r:
                data = r.read(MAX_RESPONSE + 1)
        except urllib.error.HTTPError as e:
            raise Failure(5, "%s answered HTTP %d" % (path, e.code))
        except (urllib.error.URLError, OSError) as e:
            raise Failure(3, "%s unreachable (%s)" % (path, getattr(e, "reason", e)))
        if len(data) > MAX_RESPONSE:
            raise Failure(5, "%s response too large" % path)
        try:
            return json.loads(data.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            raise Failure(5, "%s did not return JSON" % path)


def wait_up(api, deadline):
    while True:
        try:
            st = api.get("api/system/status")
            if isinstance(st, dict) and st.get("status") == "UP":
                v = st.get("version")
                return v if isinstance(v, str) else None
        except Failure as f:
            if time.monotonic() > deadline:
                raise Failure(3, "SonarQube is not available: %s" % f)
        if time.monotonic() > deadline:
            raise Failure(3, "SonarQube is not UP")
        time.sleep(3)


def target_from_env(environ):
    """Branche ou PR analysée : {} (branche principale), {"branch": nom} ou
    {"pr": clé, "pr_branch": nom, "pr_base": nom}. Lève Failure(2) si invalide."""
    branch = environ.get("SCANORIA_BRANCH", "")
    pr = environ.get("SCANORIA_PR_KEY", "")
    if branch and pr:
        raise Failure(2, "SCANORIA_BRANCH and SCANORIA_PR_KEY are exclusive")
    if pr:
        head, base = environ.get("SCANORIA_PR_BRANCH", ""), environ.get("SCANORIA_PR_BASE", "")
        if not PR_KEY_RE.match(pr) or not BRANCH_RE.match(head) or not BRANCH_RE.match(base):
            raise Failure(2, "invalid pull request description")
        return {"pr": pr, "pr_branch": head, "pr_base": base}
    if branch:
        if not BRANCH_RE.match(branch):
            raise Failure(2, "invalid SCANORIA_BRANCH")
        return {"branch": branch}
    return {}


def target_args(target):
    """Paramètres sonar-scanner de la branche ou de la PR (vide : branche principale)."""
    if "pr" in target:
        return ["-Dsonar.pullrequest.key=" + target["pr"],
                "-Dsonar.pullrequest.branch=" + target["pr_branch"],
                "-Dsonar.pullrequest.base=" + target["pr_base"]]
    if "branch" in target:
        return ["-Dsonar.branch.name=" + target["branch"]]
    return []


def target_params(target):
    """Filtre des API web sur la branche ou la PR analysée."""
    if "pr" in target:
        return {"pullRequest": target["pr"]}
    if "branch" in target:
        return {"branch": target["branch"]}
    return {}


def run_scanner(host, token, key, work, cache, deadline, target=None):
    os.makedirs(work, exist_ok=True)
    os.makedirs(cache, exist_ok=True)
    binaries = os.path.join(work, "empty-binaries")
    os.makedirs(binaries, exist_ok=True)
    # Le dépôt analysé ne règle jamais sa propre analyse : son
    # sonar-project.properties (exclusions, règles ignorées…) est remplacé
    # par un fichier vide, hors de /src.
    settings = os.path.join(work, "scanoria-project.properties")
    with open(settings, "w", encoding="utf-8") as f:
        f.write("# Scanoria : réglages du dépôt ignorés\n")
    args = [SCANNER,
            "-Dsonar.host.url=" + host,
            "-Dsonar.projectKey=" + key,
            "-Dsonar.projectName=" + key,
            "-Dsonar.projectBaseDir=" + SRC_DIR,
            "-Dproject.settings=" + settings,
            "-Dsonar.sources=.",
            "-Dsonar.working.directory=" + os.path.join(work, "scannerwork"),
            "-Dsonar.scm.disabled=true",
            "-Dsonar.scanner.skipJreProvisioning=true",
            "-Dsonar.java.binaries=" + binaries,
            "-Dsonar.qualitygate.wait=false"] + target_args(target or {})
    env = {k: v for k, v in os.environ.items() if k in ("PATH", "LANG", "LC_ALL", "JAVA_HOME", "NODE_OPTIONS")}
    env.update(HOME=work, SONAR_USER_HOME=cache, SONAR_TOKEN=token, SONAR_SCANNER_OPTS="-Xmx1024m")
    left = max(30, int(deadline - time.monotonic()))
    try:
        r = subprocess.run(args, env=env, cwd=work, stdin=subprocess.DEVNULL, timeout=left, check=False)
    except subprocess.TimeoutExpired:
        raise Failure(4, "sonar-scanner timed out")
    except OSError as e:
        raise Failure(4, "sonar-scanner cannot start (%s)" % e)
    if r.returncode != 0:
        raise Failure(4, "sonar-scanner exited with code %d" % r.returncode)
    report = os.path.join(work, "scannerwork", "report-task.txt")
    try:
        with open(report, encoding="utf-8") as f:
            text = f.read(65536)
    except OSError:
        raise Failure(4, "report-task.txt missing")
    m = re.search(r"^ceTaskId=(.+)$", text, re.M)
    if not m or not TASK_RE.match(m.group(1).strip()):
        raise Failure(4, "no computation task id in report-task.txt")
    return m.group(1).strip()


def wait_task(api, task, deadline):
    delay = 2
    while True:
        r = api.get("api/ce/task", {"id": task})
        st = (r.get("task") or {}).get("status") if isinstance(r, dict) else None
        if st == "SUCCESS":
            return
        if st in ("FAILED", "CANCELED"):
            raise Failure(4, "computation task %s" % str(st).lower())
        if time.monotonic() > deadline:
            raise Failure(4, "computation task still %s at the deadline" % (st or "unknown"))
        time.sleep(delay)
        delay = min(10, delay + 1)


def pages(api, path, params, items_key):
    """Pages successives (au plus MAX_PAGES) ; s'arrête à la dernière.
    Retourne (pages, total annoncé par le serveur ou None)."""
    out = []
    announced = None
    for p in range(1, MAX_PAGES + 1):
        page = api.get(path, dict(params, ps=PAGE_SIZE, p=p))
        if not isinstance(page, dict):
            raise Failure(5, "%s returned a malformed page" % path)
        out.append(page)
        items = page.get(items_key)
        paging = page.get("paging") if isinstance(page.get("paging"), dict) else {}
        total = paging.get("total", page.get("total"))
        if isinstance(total, int) and not isinstance(total, bool):
            announced = total
        if not isinstance(items, list) or len(items) < PAGE_SIZE:
            break
        if isinstance(total, int) and p * PAGE_SIZE >= total:
            break
    return out, announced


def export(api, key, version, target=None):
    where = target_params(target or {})
    issues, n_issues = pages(api, "api/issues/search", dict(where, components=key, resolved="false",
                                                            additionalFields="_all"), "issues")
    hotspots, n_hotspots = pages(api, "api/hotspots/search", dict(where, project=key, status="TO_REVIEW"),
                                 "hotspots")
    conv = sonar_sarif.Converter(key, version)
    # Au-delà de ce que l'API rend (10 000), le document est marqué tronqué :
    # trou de couverture signalé par la console, jamais « tout a été lu ».
    conv.declare_total(n_issues)
    conv.declare_total(n_hotspots)
    for p in issues:
        conv.add_issues(p)
    for p in hotspots:
        conv.add_hotspots(p)
    keys = sorted(conv.rules)
    for i in range(0, min(len(keys), 2000), 100):
        try:
            conv.add_rule_names(api.get("api/rules/search", {"rule_keys": ",".join(keys[i:i + 100]),
                                                             "f": "name", "ps": 100}))
        except Failure as f:   # noms facultatifs : la clé de règle suffit
            log("rule names unavailable: %s" % f)
            break
    return conv.sarif()


def main(argv):
    out = argv[0] if argv else os.path.join(OUT_DIR, "result.sarif")
    if len(argv) > 1 or os.path.dirname(out) != OUT_DIR or not re.fullmatch(r"[A-Za-z0-9._-]{1,100}",
                                                                              os.path.basename(out)):
        log("usage: sonar_scan.py [%s/<file>.sarif]" % OUT_DIR)
        return 2
    host = os.environ.get("SCANORIA_SERVICE_URL", "")
    key = os.environ.get("SCANORIA_PROJECT_KEY", "")
    if not HOST_RE.match(host) or not PROJECT_KEY_RE.match(key):
        log("invalid SCANORIA_SERVICE_URL or SCANORIA_PROJECT_KEY")
        return 2
    try:
        with open(TOKEN_FILE, encoding="ascii") as f:
            token = f.read(512).strip()
    except (OSError, UnicodeDecodeError):
        token = ""
    if not re.fullmatch(r"[A-Za-z0-9_]{10,200}", token):
        log("analysis token missing or malformed")
        return 3
    try:
        budget = int(os.environ.get("SCANORIA_BUDGET_S", "1700"))
    except ValueError:
        budget = 1700
    deadline = time.monotonic() + max(60, budget)
    try:
        target = target_from_env(os.environ)
    except Failure as f:
        log(str(f))
        return f.code
    work = os.path.join(OUT_DIR, ".work")
    try:
        api = Api(host, token)
        version = wait_up(api, min(deadline, time.monotonic() + 300))
        where = (" pull request %s" % target["pr"]) if "pr" in target else \
            (" branch %s" % target["branch"]) if "branch" in target else " main branch"
        log("SonarQube %s is UP, analysing as %s,%s" % (version or "?", key, where))
        task = run_scanner(host, token, key, work, os.path.join(work, "cache"), deadline, target)
        wait_task(api, task, deadline)
        doc = export(api, key, version, target)
        tmp = os.path.join(OUT_DIR, ".result.sarif.tmp")
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(doc, f, ensure_ascii=False)
        os.replace(tmp, out)
        info = doc["runs"][0]["properties"]["scanoria"]
        log("%d result(s) exported%s" % (info["kept"], " (truncated)" if info["truncated"] else ""))
        return 0
    except Failure as f:
        log(str(f))
        return f.code
    finally:
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
