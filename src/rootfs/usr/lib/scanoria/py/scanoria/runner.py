# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Vincent Tisseront
"""scanoria-runner : exécute les tâches d'analyse en root (ARCHITECTURE § 12).

  scanoria-runner           service (scanoria-runner.service)
  scanoria-runner --once    traite les tâches présentes puis s'arrête (tests)

Principe 4 : rien n'est pris dans la tâche sans contrôle. Le fichier déposé par
scanoria-worker dans jobs/incoming/ doit être un fichier régulier du compte
scanoria, 0600, à lien unique, de taille bornée, en JSON strict conforme à
scan-job.schema.json ; il est déplacé dans jobs/work/, lu, puis supprimé
aussitôt (il peut porter un jeton). Chaque module doit être installé, sain,
actif et à la version demandée dans le registre des modules ; image, commande,
délai, limites, sorties et bases viennent de son manifeste vérifié, et les
options de la tâche sont revalidées contre le schéma du manifeste.

La source est récupérée une fois (fetch.py), puis chaque module tourne dans un
conteneur jetable confiné (§ 6.4), sources en lecture seule sur /src. Durée,
pic mémoire et temps CPU sont mesurés (F14, G20) ; le journal est borné à 1 Mo
et masqué. Les sorties déclarées sont validées (SARIF 2.1.0, CycloneDX ; G2)
puis publiées dans results/<id>/ avec result.json (scan-result.schema.json),
écrit en dernier. Erreurs classées (G12) : infra, tool, input. L'espace de
travail est supprimé dans tous les cas ; les résultats sont purgés après 24 h.
"""

import json
import os
import re
import shutil
import stat
import sys
import threading
import time
import urllib.parse

import contextlib

from . import catalogverify, common, feeds, fetch, modules, sbom, schema, svcnet, testbed, vigilance
from .common import Fail


def _test_path(var, default):
    """SCANORIA_SCANS_DIR et SCANORIA_RUNNER_STATE : surchargeables en mode test seulement."""
    v = os.environ.get(var, "") if common.TEST_ROOT else ""
    return v if v and os.path.isabs(v) else default


SCANS = _test_path("SCANORIA_SCANS_DIR", common.VARLIB + "/scans")
JOBS = SCANS + "/jobs"
TMP = os.path.join(JOBS, "tmp")
INCOMING = JOBS + "/incoming"
WORK = JOBS + "/work"
RESULTS = SCANS + "/results"
WORKSPACES = SCANS + "/workspaces"
STATE = _test_path("SCANORIA_RUNNER_STATE", common.RUN + "/runner.json")

MAX_JOB = 256 << 10
RESULT_TTL = 24 * 3600
POLL_S = 1.0
STATE_REFRESH_S = 30
PURGE_EVERY_S = 300
MAX_SLOTS = 8
DEFAULT_SCANNER_RAM = 512
NIL_UUID = "00000000-0000-4000-8000-000000000000"
JOB_NAME_RE = re.compile(r"([0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})\.json\Z")
OOM_RC = 137


# --------------------------------------------------------------------------
# Arborescence
# --------------------------------------------------------------------------

LAYOUT = (
    # chemin, mode, propriétaire scanoria (sinon root), groupe scanoria
    (SCANS, 0o750, False, True),
    (JOBS, 0o750, False, True),
    (TMP, 0o700, True, True),
    (INCOMING, 0o700, True, True),
    (WORK, 0o700, False, False),
    (RESULTS, 0o750, False, True),
    (WORKSPACES, 0o700, False, False),
)


def ensure_layout():
    """Crée ou rétablit l'arborescence (§ 12.2) ; refuse tout lien symbolique."""
    uid, gid = (0, 0) if common.TEST_ROOT else common.scanoria_ids()
    for path, mode, own, grp in LAYOUT:
        try:
            st = os.lstat(path)
        except FileNotFoundError:
            os.makedirs(os.path.dirname(path), mode=0o750, exist_ok=True)
            os.mkdir(path, mode)
            st = os.lstat(path)
        if not stat.S_ISDIR(st.st_mode):
            raise Fail("E_INTERNAL", "%s is not a directory" % path)
        os.chmod(path, mode)
        if not common.TEST_ROOT:
            os.chown(path, uid if own else 0, gid if grp else 0)
    os.makedirs(os.path.dirname(STATE), mode=0o750, exist_ok=True)


def _owner_ok(st):
    return st.st_uid == common.scanoria_ids()[0]


# --------------------------------------------------------------------------
# Capacité (/run/scanoria/runner.json)
# --------------------------------------------------------------------------

def capacity(reg):
    """Places simultanées : mémoire hors services, divisée par la limite du plus gros scanner."""
    try:
        total = modules._meminfo_mb()
    except Fail:
        total = 0
    perm, biggest = 0, 0
    for e in reg["modules"].values():
        m = e.get("manifest") or {}
        if not e.get("enabled"):
            continue
        if m.get("type") in ("service", "runner"):
            perm += modules._res(m, "min_ram_mb")
        elif m.get("type") == "scanner":
            biggest = max(biggest, modules._res(m, "min_ram_mb"))
    # Le clone (fetch.FETCH_MEMORY_MB) occupe aussi une place le temps de la récupération.
    biggest = max(int(biggest) or DEFAULT_SCANNER_RAM, fetch.FETCH_MEMORY_MB)
    slots = int((total - modules.RESERVED_RAM_MB - perm) // biggest)
    return max(1, min(slots, MAX_SLOTS, modules._cpus()))


def publish_capacity(slots, busy):
    common.write_json(STATE, {"slots": slots, "busy": busy, "updated_at": common.iso(common.now())}, 0o640)


# --------------------------------------------------------------------------
# Résultats
# --------------------------------------------------------------------------

def _err(code, cls, message):
    return {"code": code, "class": cls, "message": str(message)[:2000]}


def result_dir(job_id):
    d = os.path.join(RESULTS, job_id)
    try:
        st = os.lstat(d)
        if not stat.S_ISDIR(st.st_mode):
            os.unlink(d)
            raise FileNotFoundError
    except FileNotFoundError:
        os.mkdir(d, 0o750)
    if not common.TEST_ROOT:
        os.chown(d, 0, common.scanoria_ids()[1])
    return d


def write_result_file(path, data):
    common.atomic_write(path, data, 0o640)


def publish(result):
    """Écrit results/<id>/result.json en dernier, après validation contre son schéma."""
    errs = schema.load("schemas", "scan-result").errors(result)
    if errs:
        common.log("runner: result does not match its schema: %s" % "; ".join(errs[:5]))
        result = dict(result, status="error", error=_err("E_RUNNER_INTERNAL", "infra",
                                                        "runner produced an invalid result"))
        result["modules"] = [dict(m, outputs={}, log=None) for m in result["modules"]]
        if schema.load("schemas", "scan-result").errors(result):
            result["modules"] = []
    d = result_dir(result["id"])
    common.write_json(os.path.join(d, "result.json"), result, 0o640)


def error_result(job_id, scan_id, error, started=None, source_kind="git", modules_=()):
    t = common.iso(common.now())
    return {"schema": 1, "id": job_id, "scan_id": scan_id if common.UUID4_RE.match(scan_id or "") else NIL_UUID,
            "status": "error", "error": error, "started_at": started or t, "finished_at": t,
            "source": {"kind": source_kind, "commit": None, "history": "none", "files": 0, "bytes": 0,
                       "skipped": []},
            "modules": list(modules_)}


def purge_results(now=None):
    """Retire les résultats de plus de 24 h (et les écritures inachevées du worker)."""
    now = now or time.time()
    for base, ttl in ((RESULTS, RESULT_TTL), (TMP, RESULT_TTL)):
        try:
            names = os.listdir(base)
        except OSError:
            continue
        for n in names:
            p = os.path.join(base, n)
            try:
                st = os.lstat(p)
            except FileNotFoundError:
                continue
            if now - st.st_mtime < ttl:
                continue
            if stat.S_ISDIR(st.st_mode):
                shutil.rmtree(p, ignore_errors=True)
            else:
                try:
                    os.unlink(p)
                except OSError:
                    pass


# --------------------------------------------------------------------------
# Prise en charge d'une tâche
# --------------------------------------------------------------------------

class Rejected(Exception):
    def __init__(self, job_id, scan_id, message):
        super().__init__(message)
        self.job_id, self.scan_id, self.message = job_id, scan_id, message


def pending():
    """Tâches prêtes, les plus anciennes d'abord."""
    out = []
    try:
        names = os.listdir(INCOMING)
    except OSError:
        return out
    for n in names:
        p = os.path.join(INCOMING, n)
        try:
            st = os.lstat(p)
        except FileNotFoundError:
            continue
        out.append((st.st_mtime, n))
    return [n for _, n in sorted(out)]


def _discard(path):
    try:
        st = os.lstat(path)
        if stat.S_ISDIR(st.st_mode):
            shutil.rmtree(path, ignore_errors=True)
        else:
            os.unlink(path)
    except OSError:
        pass


def claim(name):
    """Déplace incoming/<name> dans work/, le lit, le supprime, le valide ; retourne la tâche.

    Lève Rejected (tâche à refuser avec un résultat d'erreur) ou ValueError (nom
    invalide : supprimé sans résultat)."""
    src = os.path.join(INCOMING, name)
    m = JOB_NAME_RE.match(name)
    if not m:
        _discard(src)
        raise ValueError("invalid job file name")
    job_id = m.group(1)
    if os.path.lexists(marker_path(job_id)) or os.path.lexists(os.path.join(result_dir(job_id), "result.json")):
        # Tâche déjà en cours ou déjà terminée : le doublon est écarté sans toucher à l'original.
        _discard(src)
        raise ValueError("duplicate of job %s, already running or done" % job_id)
    dst = os.path.join(WORK, name)
    try:
        os.rename(src, dst)
    except OSError:
        raise ValueError("job vanished")
    try:
        try:
            fd = os.open(dst, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_NOCTTY)
        except OSError:
            raise Rejected(job_id, None, "job is not a regular file")
        with os.fdopen(fd, "rb") as f:
            st = os.fstat(f.fileno())
            if not stat.S_ISREG(st.st_mode):
                raise Rejected(job_id, None, "job is not a regular file")
            if not _owner_ok(st):
                raise Rejected(job_id, None, "job is not owned by scanoria")
            if stat.S_IMODE(st.st_mode) != 0o600:
                raise Rejected(job_id, None, "job mode must be 0600")
            if st.st_nlink != 1:
                raise Rejected(job_id, None, "job has several links")
            if st.st_size > MAX_JOB:
                raise Rejected(job_id, None, "job too large")
            os.set_blocking(f.fileno(), True)
            data = f.read(MAX_JOB + 1)
    finally:
        _discard(dst)
    if len(data) > MAX_JOB:
        raise Rejected(job_id, None, "job too large")
    try:
        job = common.loads_strict(data)
    except common.JsonError as e:
        raise Rejected(job_id, None, "job is not valid JSON (%s)" % e)
    scan_id = job.get("scan_id") if isinstance(job, dict) and isinstance(job.get("scan_id"), str) else None
    errs = schema.load("schemas", "scan-job").errors(job)
    if errs:
        raise Rejected(job_id, scan_id, "job does not match its schema: %s" % "; ".join(errs[:3]))
    if job["id"] != job_id:
        raise Rejected(job_id, scan_id, "job id differs from its file name")
    return job


def marker_path(job_id):
    return os.path.join(WORK, job_id + ".running")


def write_marker(job):
    common.write_json(marker_path(job["id"]), {"id": job["id"], "scan_id": job["scan_id"],
                                               "source_kind": job["source"]["kind"],
                                               "started_at": common.iso(common.now())},
                      0o600, group_scanoria=False)


def recover():
    """Au démarrage : toute tâche restée dans work/ est publiée en erreur infra."""
    try:
        names = os.listdir(WORK)
    except OSError:
        names = []
    for n in names:
        p = os.path.join(WORK, n)
        job_id, scan_id, kind = None, None, "git"
        mm = JOB_NAME_RE.match(n) or re.fullmatch(r"([0-9a-f-]{36})\.running", n)
        if mm and common.UUID4_RE.match(mm.group(1)):
            job_id = mm.group(1)
            try:
                with open(p, "rb") as f:
                    if stat.S_ISREG(os.fstat(f.fileno()).st_mode):
                        obj = common.loads_strict(f.read(MAX_JOB))
                        scan_id = obj.get("scan_id") if isinstance(obj, dict) else None
                        src = obj.get("source_kind") or (obj.get("source") or {}).get("kind")
                        kind = src if src in ("git", "archive", "sbom") else "git"
            except (OSError, common.JsonError, AttributeError):
                pass
        _discard(p)
        if job_id:
            publish(error_result(job_id, scan_id, _err("E_RUNNER_RESTARTED", "infra",
                                                       "the runner restarted while the job was running"),
                                 source_kind=kind))
            common.log("runner: job %s interrupted by a restart" % job_id)
    for n in os.listdir(WORKSPACES) if os.path.isdir(WORKSPACES) else []:
        shutil.rmtree(os.path.join(WORKSPACES, n), ignore_errors=True)
    shutil.rmtree(fetch.CRED_DIR, ignore_errors=True)
    svcnet.remove_orphan_secrets()
    fetch.reset_network()


# --------------------------------------------------------------------------
# Plan vérifié
# --------------------------------------------------------------------------

def wants_history(m, options):
    """Le module lit l'historique Git (scan.history: full), sauf option history à false."""
    scan = m.get("scan") or {}
    return scan.get("history") == "full" and options.get("history") is not False


def _module_entry(mid, version, status, error=None, m=None):
    image = (m or {}).get("image") or ""
    digest = image.split("@", 1)[1] if "@sha256:" in image else None
    return {"id": mid, "version": version, "status": status, "error": error, "image_digest": digest,
            "feeds": [], "started_at": None, "finished_at": None, "exit_code": None,
            "outputs": {}, "log": None}


def plan(reg, job):
    """[(entrée de résultat, spécification exécutable ou None)] dans l'ordre de la tâche."""
    kind = job["source"]["kind"]
    want_input = {"git": "repo", "archive": "archive", "sbom": "sbom"}[kind]
    out = []
    for item in job["modules"]:
        mid, ver = item["id"], item["version"]
        e = reg["modules"].get(mid)
        m = e.get("manifest") if isinstance(e, dict) else None
        # 0.6 (B, contrats 24 et 25) : version figée par le projet ou candidate d'un essai.
        alt = vigilance.alternate(e, item) if isinstance(m, dict) and e.get("status") == "healthy" \
            and e.get("enabled") is True else None
        if alt is False:
            out.append((_module_entry(mid, ver, "missing", _err(
                "E_IMAGE_MISSING", "infra", "version %s of module %s is not kept on this appliance" % (ver, mid))),
                None))
            continue
        if alt is not None:
            m = alt
        if not isinstance(m, dict) or e.get("status") != "healthy" or e.get("enabled") is not True \
                or m.get("version") != ver:
            out.append((_module_entry(mid, ver, "missing", _err(
                "E_MODULE_MISSING", "input", "module %s %s is not installed, healthy and enabled" % (mid, ver))),
                None))
            continue
        try:
            catalogverify.check_module(m)
            if m.get("type") != "scanner" or "system" in (m.get("categories") or []):
                raise Fail("E_INVALID_PARAM", "module %s is not a scanner" % mid)
            scan = m["scan"]
            hist_cmd = scan.get("history_command")
            if hist_cmd is not None:
                catalogverify._check_command(hist_cmd, mid)
            if scan.get("sbom_command") is not None:
                catalogverify._check_command(scan["sbom_command"], mid)
        except Fail as f:
            out.append((_module_entry(mid, ver, "missing", _err("E_MODULE_INVALID", "input", f.message), m), None))
            continue
        # 0.5 (contrat 16) : une source SBOM ne lance que sbom_command ; sans lui, le module est ignoré.
        if want_input not in (scan.get("inputs") or []) or (kind == "sbom" and not scan.get("sbom_command")):
            out.append((_module_entry(mid, ver, "skipped", _err(
                "E_INPUT_UNSUPPORTED", "input", "module %s does not read a %s source" % (mid, want_input)), m),
                None))
            continue
        if scan.get("network", "none") == "target":
            out.append((_module_entry(mid, ver, "skipped", _err(
                "E_NETWORK_UNSUPPORTED", "input", "networked scanners are not supported yet"), m), None))
            continue
        # Contrat 12 (0.4) : branche par défaut seulement, puis service joignable.
        # Branches et PR (option « branches » du service) : sinon branche par défaut seulement.
        feats = svcnet.service_features(reg, m)
        reason = svcnet.refs_skip(m, job["source"], feats)
        if reason:
            out.append((_module_entry(mid, ver, "skipped", _err("E_REF_NOT_DEFAULT", "input", reason), m), None))
            continue
        try:
            svc, mounts = None, svcnet.tool_mount(m)
            if svcnet.service_of(m):
                key = svcnet.project_key(job.get("project_id"))
                if key is None:
                    out.append((_module_entry(mid, ver, "skipped", _err(
                        "E_PROJECT_UNKNOWN", "input", "the project of this scan is unknown to the runner"), m), None))
                    continue
                svc = dict(svcnet.resolve(reg, m), key=key, branch=svcnet.branch_of(m, job["source"], feats))
        except svcnet.Unavailable as u:
            if scan.get("service_optional") is True and u.code == svcnet.E_SERVICE_MISSING:
                # Complément facultatif (envoi des SBOM à Dependency-Track, 0.5) : sans effet sur le verdict.
                out.append((_module_entry(mid, ver, "skipped", _err(u.code, "input", u.message), m), None))
                continue
            # Service absent, inactif ou sans jeton : module « missing », verdict non concluant (G13).
            out.append((_module_entry(mid, ver, "missing", _err(u.code, "input", u.message), m), None))
            continue
        try:
            given = dict(e.get("options") or {})
            given.update(item.get("options") or {})
            options = modules.resolve_options(m, given)
        except Fail as f:
            out.append((_module_entry(mid, ver, "error", _err("E_OPTIONS_INVALID", "input", f.message), m), None))
            continue
        history = kind == "git" and wants_history(m, options)
        try:
            base_cmd = scan["sbom_command"] if kind == "sbom" else (hist_cmd if history and hist_cmd else scan["command"])
            command = testbed.render_command(base_cmd, options)
        except Fail as f:
            out.append((_module_entry(mid, ver, "error", _err("E_OPTIONS_INVALID", "input", f.message), m), None))
            continue
        try:
            sbom_cmd = sbom.command_of(m, options)
        except Fail as f:
            out.append((_module_entry(mid, ver, "error", _err("E_OPTIONS_INVALID", "input", f.message), m), None))
            continue
        spec = {"manifest": m, "options": options, "command": command, "history": history,
                "service": svc, "mounts": mounts, "sbom_command": sbom_cmd}
        out.append((_module_entry(mid, ver, "ok", None, m), spec))
    return out


def feeds_info(reg, m):
    res = []
    for fid in (m.get("requires") or {}).get("feeds") or []:
        if not isinstance(fid, str) or not catalogverify.MODULE_ID_RE.match(fid):
            continue
        fe = reg["modules"].get(fid)
        ver = (fe.get("manifest") or {}).get("version") if isinstance(fe, dict) else None
        # Date du dernier téléchargement réussi de la base (feeds.py, 0.3.4).
        updated = feeds.public_status(fid).get("updated_at")
        res.append({"id": fid, "version": ver if isinstance(ver, str) else None, "updated_at": updated})
    return res


# --------------------------------------------------------------------------
# Exécution d'un module
# --------------------------------------------------------------------------

class Sampler(threading.Thread):
    """Relève le pic mémoire et le temps CPU du cgroup du conteneur pendant qu'il tourne."""

    def __init__(self, name):
        super().__init__(daemon=True)
        self.name, self.stop_ev = name, threading.Event()
        self.peak, self.cpu_us, self.path = 0, 0, None

    def _find(self):
        r = common.run("podman", ["inspect", "--format", "{{.State.CgroupPath}}", self.name], timeout=30)
        rel = r.text.strip()
        if r.returncode != 0 or not rel.startswith("/") or ".." in rel:
            return None
        base = common.p("/sys/fs/cgroup") + rel
        for cand in (base + "/container", base):
            if os.path.isfile(cand + "/cpu.stat"):
                return cand
        return None

    def sample(self):
        if self.path is None:
            return
        for f in ("memory.peak", "memory.current"):
            v = common.read_text(os.path.join(self.path, f), 64)
            if v and v.isdigit():
                self.peak = max(self.peak, int(v))
        txt = common.read_text(os.path.join(self.path, "cpu.stat"), 4096) or ""
        mm = re.search(r"^usage_usec (\d+)$", txt, re.M)
        if mm:
            self.cpu_us = max(self.cpu_us, int(mm.group(1)))

    def run(self):
        delay = 0.2
        while not self.stop_ev.is_set():
            if self.path is None:
                self.path = self._find()
            self.sample()
            self.stop_ev.wait(delay)
            delay = min(1.0, delay * 1.5)


def _out_name(kind, declared, used):
    """Nom de la copie (nom de base de la sortie, préfixé par son type s'il est déjà pris)."""
    name = os.path.basename(declared)
    if name in used:
        name = "%s-%s" % (kind, name)
    used.add(name)
    return name


def _copy_output(out_dir, declared, kind, version, dest):
    """Lit une sortie sans suivre de lien, la valide (G2) et la copie ; lève Fail si invalide."""
    rel = testbed._out_rel(declared)
    try:
        fd = testbed._open_under(out_dir, rel)
    except OSError:
        raise Fail("E_TESTBED", "declared output %s missing" % declared)
    with os.fdopen(fd, "rb") as f:
        if not stat.S_ISREG(os.fstat(f.fileno()).st_mode):
            raise Fail("E_TESTBED", "declared output %s is not a regular file" % declared)
        os.set_blocking(f.fileno(), True)
        data = f.read(testbed.MAX_OUTPUT + 1)
    if len(data) > testbed.MAX_OUTPUT:
        raise Fail("E_TESTBED", "output %s too large" % declared)
    try:
        doc = common.loads_strict(data)
    except common.JsonError:
        raise Fail("E_TESTBED", "output %s is not valid JSON" % declared)
    if kind == "sarif":
        testbed.sarif_results(doc, version or "2.1.0")
    elif kind == "cyclonedx":
        testbed.cyclonedx_components(doc, version or "1.5")
    else:
        raise Fail("E_TESTBED", "unsupported output kind %s" % kind)
    write_result_file(dest, data)


def run_module(job, entry, spec, ws, rdir, reg, secrets):
    """Lance un module confiné sur ws/src ; complète entry (statut, sorties, journal, mesures)."""
    m, mid = spec["manifest"], spec["manifest"]["id"]
    scan = m["scan"]
    entry["feeds"] = feeds_info(reg, m)
    entry["started_at"] = common.iso(common.now())
    t0 = time.monotonic()
    out = os.path.join(ws, "out", mid)
    os.makedirs(os.path.dirname(out), mode=0o700, exist_ok=True)
    os.mkdir(out, 0o700)
    testbed._give_to_container(out)
    log_tmp = os.path.join(ws, "logs", mid + ".log")
    os.makedirs(os.path.dirname(log_tmp), mode=0o700, exist_ok=True)
    mdir = os.path.join(rdir, mid)
    os.mkdir(mdir, 0o750)
    if not common.TEST_ROOT:
        os.chown(mdir, 0, common.scanoria_ids()[1])

    def finish(status, error=None, rc=None):
        entry.update(status=status, error=error, exit_code=rc, finished_at=common.iso(common.now()))
        entry.setdefault("stats", {})["duration_ms"] = int((time.monotonic() - t0) * 1000)
        if os.path.isfile(log_tmp):
            with open(log_tmp, "rb") as f:
                write_result_file(os.path.join(mdir, "module.log"), f.read(fetch.MAX_LOG + 4096))
            entry["log"] = "%s/module.log" % mid

    if common.run("podman", ["image", "exists", m["image"]], timeout=60).returncode != 0:
        return finish("error", _err("E_IMAGE_MISSING", "infra", "image of module %s is missing" % mid))
    try:
        feeds.require_ready(m)
    except Fail as f:
        # Base vide : message clair plutôt que le code 127 du scanner.
        return finish("error", _err("E_FEED_MISSING", "infra", f.message))
    timeout = scan.get("timeout_s") if isinstance(scan.get("timeout_s"), int) else testbed.DEFAULT_TIMEOUT
    timeout = max(10, min(timeout, 86400))
    # Contrat 14 (0.5) : SBOM produit plus tôt dans l'analyse, lu par Grype et dtrack-upload.
    sbom_dir = sbom.available(ws) if sbom.consumes(m) else None
    if sbom_dir is None and sbom.required(m):
        return finish("skipped", _err(sbom.E_SBOM_MISSING, "input", "module %s needs the SBOM of the analysis, "
                                      "which no module produced" % mid))
    use_sbom = sbom_dir is not None and sbom.prefers(m) and spec.get("sbom_command") is not None
    # Grype sur le SBOM : il remplace le dépôt sur /src, comme en re-corrélation (contrat 16).
    mounts = [(sbom_dir if use_sbom else os.path.join(ws, "src"), "/src", "ro"), (out, "/out", "rw")]
    if sbom_dir is not None and not use_sbom:
        mounts.append((sbom_dir, sbom.MOUNT, "ro"))
    if spec["history"] and os.path.isdir(os.path.join(ws, "git")):
        mounts.append((os.path.join(ws, "git"), "/git", "ro"))
    mounts += spec.get("mounts") or []
    name = "scanoria-scan-%s-%s" % (job["id"][:8], os.urandom(4).hex())
    try:
        args = [a for a in testbed.confined_args(m, mounts + testbed.feed_mounts(m), name=name) if a != "--rm"]
    except Fail as f:
        return finish("error", _err("E_MODULE_INVALID", "input", f.message))
    svc = spec.get("service")
    stack = contextlib.ExitStack()
    if svc:
        try:
            att = stack.enter_context(svcnet.Attachment(svc, svc["key"], budget_s=max(60, timeout - 60)))
            args = svcnet.network_args(args, att.args())
        except (svcnet.Unavailable, Fail) as f:
            stack.close()
            return finish("error", _err(f.code, "infra", f.message))
        secrets = list(secrets or []) + [svc["token"]]
        if sbom.consumes(m):
            # Version du projet dans le service (Dependency-Track) : la référence analysée.
            args += ["--env", "SCANORIA_REF=" + sbom.ref_label(job["source"])]
    try:
        args += ["--timeout", str(timeout)]
        for k in sorted(scan.get("env") or {}):
            args += ["--env", "%s=%s" % (k, scan["env"][k])]
        cmd = spec["command"]
        if use_sbom:
            cmd = spec["sbom_command"]
        args += ["--entrypoint", json.dumps([cmd[0]]), m["image"]] + list(cmd[1:])
        sampler = Sampler(name)
        sampler.start()
    except BaseException:
        stack.close()   # secret Podman du jeton jamais laissé derrière
        raise
    try:
        rc, _, timed_out = fetch.run_logged(args, log_tmp, timeout + 30, None, secrets)
        sampler.sample()
    finally:
        stack.close()
        sampler.stop_ev.set()
        sampler.join(5)
        r = common.run("podman", ["inspect", "--format", "{{.State.OOMKilled}}", name], timeout=60)
        oom = r.returncode == 0 and r.text.strip() == "true"
        common.run("podman", ["rm", "--force", "--ignore", "--time", "0", name], timeout=120)
    stats = entry.setdefault("stats", {})
    if sampler.peak:
        stats["peak_memory_mb"] = int(sampler.peak // (1 << 20))
    if sampler.cpu_us:
        stats["cpu_ms"] = int(sampler.cpu_us // 1000)
    if timed_out:
        return finish("timeout", _err("E_MODULE_TIMEOUT", "infra", "module %s exceeded %d s" % (mid, timeout)))
    if oom or rc == OOM_RC:
        return finish("oom", _err("E_MODULE_OOM", "infra", "module %s ran out of memory" % mid), rc)
    if rc in (125, 126, 127):
        return finish("error", _err("E_PODMAN", "infra", "container of module %s could not start (exit %d)"
                                    % (mid, rc)), rc)
    if rc not in (scan.get("exit_codes_ok") or testbed.SCANNER_OK_RC):
        return finish("error", _err("E_TOOL_EXIT", "tool", "module %s exited with code %d" % (mid, rc)), rc)
    outputs, used = {}, set()
    try:
        decl = m.get("outputs")
        if not isinstance(decl, dict) or not decl:
            raise Fail("E_TESTBED", "module declares no output")
        for kind, d in sorted(decl.items()):
            if not isinstance(d, dict):
                raise Fail("E_TESTBED", "malformed output declaration")
            fname = _out_name(kind, d.get("path") or "", used)
            _copy_output(out, d.get("path"), kind, d.get("version"), os.path.join(mdir, fname))
            outputs[kind] = "%s/%s" % (mid, fname)
    except Fail as f:
        return finish("invalid-output", _err("E_INVALID_OUTPUT", "tool", f.message), rc)
    entry["outputs"] = outputs
    if "cyclonedx" in outputs and not sbom.consumes(m):
        # Premier SBOM de l'analyse : offert aux modules suivants qui lisent l'entrée « sbom ».
        sbom.offer(ws, os.path.join(rdir, outputs["cyclonedx"]))
    return finish("ok", None, rc)


# --------------------------------------------------------------------------
# Tâche complète
# --------------------------------------------------------------------------

def execute(job):
    started = common.iso(common.now())
    src = job["source"]
    secrets = fetch.secret_values(src.get("credential"))
    try:
        reg = modules.load_registry()
    except Fail as f:
        return error_result(job["id"], job["scan_id"], _err("E_RUNNER_INTERNAL", "infra", f.message), started,
                            src["kind"])
    planned = plan(reg, job)
    entries = [e for e, _ in planned]
    runnable = [(e, s) for e, s in planned if s is not None]
    history = "full" if src["kind"] == "git" and (src.get("history") == "full" or any(
        s["history"] for _, s in runnable)) else ("shallow" if src["kind"] == "git" else "none")
    source = {"kind": src["kind"], "commit": None, "history": history, "files": 0, "bytes": 0, "skipped": []}
    result = {"schema": 1, "id": job["id"], "scan_id": job["scan_id"], "status": "ok", "error": None,
              "started_at": started, "finished_at": started, "source": source, "modules": entries}
    if not runnable:
        result["finished_at"] = common.iso(common.now())
        return result
    if fetch.disk_free(SCANS) < fetch.MIN_FREE_BYTES:
        return error_result(job["id"], job["scan_id"], _err("E_DISK_FULL", "infra",
                                                            "not enough free space left on the appliance"),
                            started, src["kind"])
    ws = os.path.join(WORKSPACES, job["id"])
    rdir = result_dir(job["id"])
    os.mkdir(ws, 0o700)          # échoue si l'espace existe déjà : il n'est alors jamais supprimé ici
    try:
        os.mkdir(os.path.join(ws, "logs"), 0o700)
        try:
            if src["kind"] == "git":
                source["commit"] = fetch.fetch_git(job, ws, reg["modules"], history,
                                                   os.path.join(ws, "logs", "fetch.log"), secrets)
                files, size, skipped = fetch.bound_tree(os.path.join(ws, "src"))
            elif src["kind"] == "sbom":
                files, size, skipped = write_sbom(src["components"], ws)
            else:
                files, size, skipped = fetch.extract_upload(src["upload_id"], ws)
        except fetch.SourceError as e:
            for ent, _ in runnable:
                ent.update(status="skipped", error=None)
            result.update(status="error", error=e.as_error())
            _copy_fetch_log(ws, rdir)
            return result
        source.update(files=files, bytes=size, skipped=skipped)
        for ent, spec in sbom.ordered(runnable):
            try:
                run_module(job, ent, spec, ws, rdir, reg, secrets)
            except Exception as e:  # noqa: BLE001 — une erreur d'un module n'arrête pas les autres
                common.log("runner: module %s failed: %r" % (ent["id"], e))
                ent.update(status="error", error=_err("E_RUNNER_INTERNAL", "infra", "internal runner error"))
    finally:
        shutil.rmtree(ws, ignore_errors=True)
    result["finished_at"] = common.iso(common.now())
    return result


# --------------------------------------------------------------------------
# Source SBOM (re-corrélation, 0.5, contrat 16)
# --------------------------------------------------------------------------

SBOM_PURL_RE = re.compile(r"pkg:([a-z][a-z0-9.+-]{0,31})/([\x21-\x7e]{1,1000})\Z")


def _purl_component(purl):
    """Composant CycloneDX minimal tiré d'un purl, ou None. Seul le purl est
    gardé tel quel ; nom, groupe et version en sont déduits ici."""
    m = SBOM_PURL_RE.match(purl) if isinstance(purl, str) and len(purl) <= 1024 else None
    if not m:
        return None
    rest = m.group(2).split("#", 1)[0].split("?", 1)[0]
    path, _, version = rest.rpartition("@") if "@" in rest else (rest, "", "")
    segs = [s for s in path.split("/") if s]
    if not segs:
        return None
    try:
        segs = [urllib.parse.unquote(s, errors="strict") for s in segs]
        version = urllib.parse.unquote(version, errors="strict")
    except UnicodeDecodeError:
        return None
    if any(not s.isprintable() or len(s) > 255 for s in segs) or not version.isprintable() or len(version) > 128:
        return None
    comp = {"type": "library", "bom-ref": purl, "name": segs[-1], "purl": purl}
    if len(segs) > 1:
        comp["group"] = "/".join(segs[:-1])
    if version:
        comp["version"] = version
    return comp


def write_sbom(purls, ws):
    """Écrit ws/src/sbom.cdx.json (CycloneDX 1.5) à partir des purl de la tâche."""
    comps, seen = [], set()
    for p in purls:
        c = _purl_component(p)
        if c and p not in seen:
            seen.add(p)
            comps.append(c)
    if not comps:
        raise fetch.SourceError("E_SOURCE_EMPTY", "input", "no usable package URL in the SBOM")
    doc = {"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
           "metadata": {"tools": {"components": [{"type": "application", "name": "scanoria-runner"}]}},
           "components": comps}
    src = os.path.join(ws, "src")
    os.mkdir(src, 0o755)
    path = os.path.join(src, "sbom.cdx.json")
    data = json.dumps(doc, ensure_ascii=True, separators=(",", ":")).encode("ascii")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
    # Comme une archive (fetch) : l'arbre appartient à l'utilisateur du
    # conteneur ; le masque du runner (077) rendrait sinon le fichier illisible.
    testbed._give_to_container(src)
    return 1, len(data), []


def _copy_fetch_log(ws, rdir):
    p = os.path.join(ws, "logs", "fetch.log")
    if os.path.isfile(p):
        with open(p, "rb") as f:
            write_result_file(os.path.join(rdir, "fetch.log"), f.read(fetch.MAX_LOG + 4096))


def handle(job):
    """Exécute une tâche et publie son résultat ; ne lève jamais."""
    try:
        try:
            result = execute(job)
        except Exception as e:  # noqa: BLE001
            common.log("runner: job %s failed: %r" % (job["id"], e))
            result = error_result(job["id"], job["scan_id"], _err("E_RUNNER_INTERNAL", "infra",
                                                                  "internal runner error"),
                                  source_kind=job["source"]["kind"])
        try:
            publish(result)
        except Exception as e:  # noqa: BLE001 — le worker constatera l'absence de résultat à son délai
            common.log("runner: cannot publish the result of job %s: %r" % (job["id"], e))
    finally:
        try:
            os.unlink(marker_path(job["id"]))
        except OSError:
            pass


# --------------------------------------------------------------------------
# Boucle principale
# --------------------------------------------------------------------------

class Runner:
    def __init__(self):
        self.lock = threading.Lock()
        self.busy = 0
        self.slots = 1
        self.published = None
        self.last_publish = 0.0
        self.last_purge = 0.0

    def refresh_capacity(self, force=False):
        try:
            self.slots = capacity(modules.load_registry())
        except Fail:
            self.slots = 1
        now = time.monotonic()
        cur = (self.slots, self.busy)
        if force or cur != self.published or now - self.last_publish >= STATE_REFRESH_S:
            try:
                publish_capacity(*cur)
                self.published, self.last_publish = cur, now
            except OSError as e:
                common.log("runner: cannot publish capacity: %s" % e)

    def _done(self, job, t):
        def run():
            try:
                handle(job)
            finally:
                with self.lock:
                    self.busy -= 1
                self.refresh_capacity(force=True)
        th = threading.Thread(target=run, name="job-" + job["id"][:8], daemon=False)
        t.append(th)
        th.start()

    def tick(self, threads):
        """Prend autant de tâches que de places libres ; retourne le nombre prises."""
        taken = 0
        for name in pending():
            with self.lock:
                if self.busy >= self.slots:
                    break
            try:
                job = claim(name)
            except ValueError as e:
                common.log("runner: %s discarded: %s" % (name, e))
                continue
            except Rejected as r:
                common.log("runner: job %s rejected: %s" % (r.job_id, r.message))
                publish(error_result(r.job_id, r.scan_id, _err("E_JOB_INVALID", "input", r.message)))
                continue
            write_marker(job)
            with self.lock:
                self.busy += 1
            taken += 1
            self.refresh_capacity(force=True)
            self._done(job, threads)
        return taken

    def housekeeping(self):
        now = time.monotonic()
        if now - self.last_purge >= PURGE_EVERY_S:
            self.last_purge = now
            purge_results()
        self.refresh_capacity()


def main(argv):
    if argv not in ([], ["--once"]):
        sys.stderr.write("usage: scanoria-runner [--once]\n")
        return 2
    if not common.TEST_ROOT and os.geteuid() != 0:
        sys.stderr.write("scanoria-runner: root required\n")
        return 2
    os.umask(0o027)
    ensure_layout()
    recover()
    r = Runner()
    r.refresh_capacity(force=True)
    purge_results()
    threads = []
    if argv == ["--once"]:
        while True:
            taken = r.tick(threads)
            for t in threads:
                t.join()
            threads.clear()
            if not taken and not pending():
                break
        r.refresh_capacity(force=True)
        return 0
    common.log("runner: started with %d slot(s)" % r.slots)
    while True:
        try:
            r.tick(threads)
            threads[:] = [t for t in threads if t.is_alive()]
            r.housekeeping()
        except Exception as e:  # noqa: BLE001 — la boucle ne s'arrête jamais sur une tâche
            common.log("runner: loop error: %r" % (e,))
        time.sleep(POLL_S)
