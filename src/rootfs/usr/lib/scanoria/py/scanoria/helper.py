# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Vincent Tisseront
"""scanoria-helper : file des demandes de la console (ARCHITECTURE § 5).

  scanoria-helper run
  scanoria-helper exec --origin timer|firstboot|cli --type <type> --params '<json>'
  scanoria-helper scheduled update-check|update-apply|cert-renew|bundle-export

Choix de Python 3 (bibliothèque standard) plutôt que bash pour ce service :
validation JSON Schema réelle (liste fermée, additionalProperties: false),
JSON strict (clés dupliquées, NaN, UTF-8 invalide), contrôles de fichiers sur
descripteur (O_NOFOLLOW, fstat, nombre de liens), adresses IP canoniques
(ipaddress) et sous-processus toujours lancés avec un tableau d'arguments,
sans shell. Les commandes de bas niveau (openssl, nft) restent en bash.
"""

import datetime
import errno
import fcntl
import os
import re
import secrets
import shutil
import stat
import sys
import tempfile
import time
import uuid

from . import aiendpoint, bundle, common, mirror, modules, netutil, offline, pkgdates, prefetch, provision, schema, vigilance
from . import dns as dnscheck
from . import rulesets
from . import attest
from . import release
from .common import Fail

MAX_SIZE = 128 * 1024
# 0.8 (contrat 37) : seuls les types de signature portent un contenu de 4 Mio
# (base64 compris). Tout autre type au-delà de MAX_SIZE est refusé avant le
# décodage JSON (repère du type lu dans les octets bruts, puis revérifié).
LARGE_TYPES = {"sign-release-report": 6 * 1024 * 1024}
MAX_READ = max([MAX_SIZE] + list(LARGE_TYPES.values()))
LARGE_TYPE_RE = re.compile(rb'"type":"(' + b"|".join(re.escape(t.encode()) for t in LARGE_TYPES) + rb')"')
NAME_RE = re.compile(r"([0-9]{8}T[0-9]{6}Z)-([0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})\.json\Z")
TIMEOUTS = {
    "set-hostname": 300, "set-admin-networks": 60, "issue-certificate": 120,
    "import-certificate": 120, "check-update": 120, "apply-update": 3300,
    "rollback-update": 3300, "set-update-policy": 30, "run-selftest": 300,
    "check-dns": 180,
    "refresh-catalog": 300, "install-modules": 3300, "uninstall-module": 900,
    "set-module-state": 1200, "update-module": 3300,
    "set-ai-endpoint": 120, "refresh-feeds": 3300,
    "backup-module": 3300, "restore-module": 3300,
    "reset-service-admin": 360,
    "package-dates": 360,
    "export-bundle": 3300, "import-bundle": 3300, "set-mirror": 180, "trust-key": 60,
    "self-sbom": 3300, "run-canaries": 3300, "start-trial": 1200,
    "prefetch-images": 3300,
    "validate-ruleset": 420,
    "sign-attestation": 120,
    "sign-release-report": 120,
}
# Marge laissée entre l'échéance passée à scanoria-selfupdate et l'arrêt forcé
# du helper : selfupdate ne franchit le point de non-retour (arrêt de la
# console) que s'il lui reste de quoi déployer, vérifier et revenir en arrière.
UPDATE_DEADLINE_MARGIN = 300
ORIGINS = ("timer", "firstboot", "cli")
# PEM : analyse ligne à ligne, en temps linéaire (aucune expression ambiguë
# susceptible d'un retour arrière exponentiel dans ce processus root).
PEM_BEGIN_RE = re.compile(r"-----BEGIN ([A-Z0-9 ]{1,40})-----\Z", re.ASCII)
PEM_END_RE = re.compile(r"-----END ([A-Z0-9 ]{1,40})-----\Z", re.ASCII)
PEM_BODY_RE = re.compile(r"[A-Za-z0-9+/=]{1,128}\Z", re.ASCII)
PEM_HEADER_RE = re.compile(r"[A-Za-z][A-Za-z0-9-]{0,39}: [A-Za-z0-9+/=,_ -]{1,128}\Z", re.ASCII)
PEM_MAX_BLOCKS = 16
PEM_MAX_LINES = 2000


def pem_ok(text):
    """Un ou plusieurs blocs PEM bien formés (BEGIN/END assortis, corps base64)."""
    if not isinstance(text, str) or not text.isascii():
        return False
    lines = text.replace("\r\n", "\n").split("\n")
    while lines and lines[-1] == "":
        lines.pop()
    label, body, blocks = None, 0, 0
    for ln in lines:
        if label is None:
            if ln == "" and blocks:
                continue
            m = PEM_BEGIN_RE.match(ln)
            if not m or blocks >= PEM_MAX_BLOCKS:
                return False
            label, body, blocks = m.group(1), 0, blocks + 1
            continue
        m = PEM_END_RE.match(ln)
        if m:
            if m.group(1) != label or body == 0:
                return False
            label = None
            continue
        body += 1
        if body > PEM_MAX_LINES:
            return False
        if not (PEM_BODY_RE.match(ln) or ln == "" or PEM_HEADER_RE.match(ln)):
            return False
    return label is None and blocks > 0


def _now():
    t = os.environ.get("SCANORIA_TEST_NOW", "") if common.TEST_ROOT else ""
    return common.parse_iso(t) if t else common.now()


# --------------------------------------------------------------------------
# Verrou
# --------------------------------------------------------------------------

class Lock:
    def __init__(self, wait):
        self.wait = wait
        self.fd = None

    def __enter__(self):
        os.makedirs(common.RUN, exist_ok=True)
        self.fd = os.open(common.RUN + "/helper.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        end = time.monotonic() + self.wait
        while True:
            try:
                fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                return self
            except OSError as e:
                if e.errno not in (errno.EAGAIN, errno.EACCES) or time.monotonic() > end:
                    os.close(self.fd)
                    raise Fail("E_PRECONDITION", "helper busy")
                time.sleep(0.5)

    def __exit__(self, *exc):
        fcntl.flock(self.fd, fcntl.LOCK_UN)
        os.close(self.fd)


# --------------------------------------------------------------------------
# Résultats
# --------------------------------------------------------------------------

def make_result(rid, rtype, origin, code, message, received, started, output=None):
    status = "ok" if code == "OK" else ("rejected" if code in common.REJECT_CODES else "error")
    res = {
        "version": 1, "id": rid, "type": rtype, "origin": origin, "status": status,
        "code": code, "message": message[:2000], "received_at": common.iso(received),
        "started_at": common.iso(started) if started else None,
        "finished_at": common.iso(common.now()), "output": output or {},
    }
    v = schema.load("requests", "result")
    if not v.valid(res):
        common.log("result does not match its schema: %s" % v.errors(res)[:3])
        res.update(status="error", code="E_INTERNAL", message="invalid result", output={})
    return res


def write_result(name, res):
    sub = "done" if res["status"] == "ok" else "failed"
    common.write_json(os.path.join(common.REQ, sub, name), res, 0o640)


def invalid_name():
    return "invalid-%s-%s.json" % (_now().strftime("%Y%m%dT%H%M%SZ"), secrets.token_hex(8))


def id_seen(rid):
    suffix = "-" + rid + ".json"
    for sub in ("done", "failed"):
        try:
            for n in os.listdir(os.path.join(common.REQ, sub)):
                if n.endswith(suffix):
                    return True
        except FileNotFoundError:
            pass
    return False


# --------------------------------------------------------------------------
# Lecture sûre d'une demande
# --------------------------------------------------------------------------

def remove_entry(dirfd, name):
    """Supprime une entrée de work/ quel que soit son type, sans suivre de lien."""
    try:
        st = os.lstat(name, dir_fd=dirfd)
    except FileNotFoundError:
        return
    if stat.S_ISDIR(st.st_mode):
        shutil.rmtree(os.path.join(common.REQ, "work", name), ignore_errors=True)
    else:
        os.unlink(name, dir_fd=dirfd)


def large_allowed(data):
    """Demande de plus de MAX_SIZE : seulement un type de LARGE_TYPES, dans sa limite.

    Repère lu dans l'en-tête brut (avant tout décodage JSON), revérifié par
    validate() une fois l'objet décodé."""
    m = LARGE_TYPE_RE.search(data[:512])
    return bool(m) and len(data) <= LARGE_TYPES[m.group(1).decode()]


def take(name):
    """Déplace incoming/name dans work/ et en lit une copie unique.

    Retourne (contenu, None) ou (None, (code, message))."""
    inc = os.open(os.path.join(common.REQ, "incoming"), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    work = os.open(os.path.join(common.REQ, "work"), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        remove_entry(work, name)
        os.rename(name, name, src_dir_fd=inc, dst_dir_fd=work)
        try:
            st = os.lstat(name, dir_fd=work)
            if not stat.S_ISREG(st.st_mode):
                return None, ("E_NOT_REGULAR_FILE", "not a regular file")
            if st.st_nlink != 1:
                return None, ("E_NOT_REGULAR_FILE", "hard link")
            if st.st_uid != common.scanoria_ids()[0]:
                return None, ("E_BAD_OWNER", "unexpected owner")
            if st.st_size > MAX_READ:
                return None, ("E_TOO_LARGE", "request too large")
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_NOCTTY, dir_fd=work)
            try:
                st2 = os.fstat(fd)
                if (st2.st_ino, st2.st_dev) != (st.st_ino, st.st_dev) or not stat.S_ISREG(st2.st_mode):
                    return None, ("E_NOT_REGULAR_FILE", "file changed")
                chunks, total = [], 0
                while total <= MAX_READ:
                    b = os.read(fd, 65536)
                    if not b:
                        break
                    chunks.append(b)
                    total += len(b)
            finally:
                os.close(fd)
            data = b"".join(chunks)
            if len(data) > MAX_SIZE and not large_allowed(data):
                return None, ("E_TOO_LARGE", "request too large")
            return data, None
        finally:
            remove_entry(work, name)
    finally:
        os.close(inc)
        os.close(work)


def validate(obj, expected_id=None, name_ts=None, size=0):
    """Contrôles de forme (§ 5.4, point 4). Retourne (type, None) ou (type, (code, msg))."""
    if not isinstance(obj, dict):
        return None, ("E_SCHEMA", "request must be an object")
    rtype = obj.get("type")
    if not isinstance(rtype, str) or rtype not in common.REQUEST_TYPES:
        return None, ("E_UNKNOWN_TYPE", "unknown request type")
    if size > LARGE_TYPES.get(rtype, MAX_SIZE):
        return rtype, ("E_TOO_LARGE", "request too large")
    v = schema.load("requests", rtype)
    errs = v.errors(obj)
    if errs:
        return rtype, ("E_SCHEMA", "; ".join(errs[:5]))
    if expected_id is not None and obj["id"] != expected_id:
        return rtype, ("E_ID_MISMATCH", "id differs from file name")
    created = common.parse_iso(obj["created_at"])
    if name_ts is not None and created.strftime("%Y%m%dT%H%M%SZ") != name_ts:
        return rtype, ("E_ID_MISMATCH", "file name timestamp differs from created_at")
    if id_seen(obj["id"]):
        return rtype, ("E_DUPLICATE_ID", "request id already processed")
    now = _now()
    if created < now - datetime.timedelta(hours=24) or created > now + datetime.timedelta(minutes=5):
        return rtype, ("E_STALE", "created_at outside the accepted window")
    if obj["requested_by"]["user_id"] == 0 and obj["requested_by"]["username"] != "system":
        return rtype, ("E_INVALID_PARAM", "user_id 0 is reserved")
    return rtype, None


# --------------------------------------------------------------------------
# Actions
# --------------------------------------------------------------------------

class Ctx:
    def __init__(self, req, deadline):
        self.req = req
        self.params = req["params"]
        self.deadline = deadline

    def left(self):
        return max(5, int(self.deadline - time.monotonic()))


def read_json_or(path, default):
    try:
        return common.load_json_file(path, 1 << 20)
    except (OSError, common.JsonError):
        return default


def appliance_fqdn():
    fqdn = read_json_or(common.ETC + "/appliance.json", {}).get("fqdn")
    return fqdn if netutil.check_fqdn(fqdn) else None


def tls_mode():
    m = read_json_or(common.ETC + "/tls.json", {}).get("mode")
    return m if m in ("internal", "imported") else "none"


def write_hosts(fqdn):
    short = fqdn.split(".", 1)[0]
    path = common.p("/etc/hosts")
    try:
        with open(path, encoding="utf-8") as f:
            lines = f.read().splitlines()
    except FileNotFoundError:
        lines = ["127.0.0.1 localhost", "::1 localhost ip6-localhost ip6-loopback"]
    lines = [ln for ln in lines if not ln.startswith("127.0.1.1")]
    lines.insert(1 if lines else 0, "127.0.1.1 %s %s" % (fqdn, short))
    common.atomic_write(path, "\n".join(lines) + "\n", 0o644, group_scanoria=False)


def nginx_apply(fqdn, timeout):
    """Génère le site nginx, le contrôle (nginx -t) et recharge ; ancien fichier remis sinon."""
    with open(os.path.join(common.SHARE_DIR, "nginx", "scanoria.conf.tmpl"), encoding="utf-8") as f:
        conf = f.read().replace("@FQDN@", fqdn)
    if not os.path.exists("/proc/net/if_inet6"):  # IPv6 désactivé : pas d'écoute [::]
        conf = "".join(ln for ln in conf.splitlines(True) if "listen [::]" not in ln)
    avail = common.p("/etc/nginx/sites-available")
    enabled = common.p("/etc/nginx/sites-enabled")
    for d in (avail, enabled, common.p("/etc/nginx/scanoria.d")):
        os.makedirs(d, mode=0o755, exist_ok=True)
    target = avail + "/scanoria.conf"
    old = None
    if os.path.isfile(target):
        with open(target, "rb") as f:
            old = f.read()
    common.atomic_write(target, conf, 0o644, group_scanoria=False)
    link = enabled + "/scanoria.conf"
    if not os.path.islink(link):
        if os.path.lexists(link):
            os.unlink(link)
        os.symlink("/etc/nginx/sites-available/scanoria.conf", link)
    default = enabled + "/default"
    if os.path.islink(default):
        os.unlink(default)
    r = common.run("nginx", ["-t", "-q"], timeout=timeout)
    if r.returncode != 0:
        if old is not None:
            common.atomic_write(target, old, 0o644, group_scanoria=False)
        else:
            os.unlink(link)
            os.unlink(target)
        raise Fail("E_INTERNAL", "nginx configuration test failed")
    common.run("systemctl", ["try-reload-or-restart", "nginx.service"], timeout=timeout)


def act_set_hostname(c):
    fqdn = c.params["fqdn"]
    if not netutil.check_fqdn(fqdn):
        raise Fail("E_INVALID_PARAM", "invalid fqdn")
    was_imported = tls_mode() == "imported"
    ca, _ = common.run_protocol("scanoria-ca", ["init", "--fqdn", fqdn], timeout=c.left())
    cert, _ = common.run_protocol("scanoria-ca", ["issue", "--force", "--fqdn", fqdn], timeout=c.left())
    r = common.run("hostnamectl", ["set-hostname", fqdn.split(".", 1)[0]], timeout=c.left())
    if r.returncode != 0:
        raise Fail("E_INTERNAL", "hostnamectl failed")
    write_hosts(fqdn)
    common.write_json(common.ETC + "/appliance.json", {"fqdn": fqdn})
    nginx_apply(fqdn, c.left())
    return {"fqdn": fqdn, "tls_mode_changed": was_imported,
            "ca_fingerprint_sha256": ca.get("ca_fingerprint_sha256"),
            "not_after": cert.get("not_after")}


def act_set_admin_networks(c):
    nets = []
    for s in c.params["networks"]:
        n = netutil.canonical_network(s)
        if n is None:
            raise Fail("E_INVALID_PARAM", "network not in canonical CIDR form")
        nets.append(n)
    addr = c.req["requested_by"].get("address")
    if addr is not None and not c.params.get("allow_self_lockout", False):
        a = netutil.parse_address(addr)
        if a is None:
            raise Fail("E_INVALID_PARAM", "invalid requester address")
        if not netutil.covered(a, nets):
            raise Fail("E_LOCKOUT", "requester address not covered by the new networks")
    path = common.ETC + "/admin-networks.json"
    old = None
    if os.path.isfile(path):
        with open(path, "rb") as f:
            old = f.read()
    common.write_json(path, {"networks": [str(n) for n in nets]})
    try:
        out, _ = common.run_protocol("scanoria-firewall", ["apply"], timeout=c.left())
    except Fail:
        if old is not None:
            common.atomic_write(path, old, 0o640)
        else:
            os.unlink(path)
        raise
    return {"networks": [str(n) for n in nets], "loaded": bool(out.get("loaded"))}


def act_issue_certificate(c):
    fqdn = appliance_fqdn()
    if fqdn is None:
        raise Fail("E_PRECONDITION", "appliance name not set")
    args = ["issue", "--fqdn", fqdn] + (["--force"] if c.params.get("force") else [])
    out, _ = common.run_protocol("scanoria-ca", args, timeout=c.left())
    return out


def act_import_certificate(c):
    fqdn = appliance_fqdn()
    if fqdn is None:
        raise Fail("E_PRECONDITION", "appliance name not set")
    files = {"cert": c.params["cert_pem"], "key": c.params["key_pem"]}
    if "chain_pem" in c.params:
        files["chain"] = c.params["chain_pem"]
    for v in files.values():
        if not pem_ok(v):
            raise Fail("E_CERT_INVALID", "malformed PEM")
    tmp = tempfile.mkdtemp(prefix="import-", dir=common.RUN)
    try:
        args = ["import", "--fqdn", fqdn]
        for k, v in files.items():
            fp = os.path.join(tmp, k + ".pem")
            fd = os.open(fp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, "w", encoding="ascii") as f:
                f.write(v)
            args += ["--" + k, fp]
        out, _ = common.run_protocol("scanoria-ca", args, timeout=c.left())
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    out.pop("key_pem", None)
    return out


def act_check_update(c):
    args = ["check", "--json"]
    if "channel" in c.params:
        args += ["--channel", c.params["channel"]]
    out, _ = common.run_protocol("scanoria-selfupdate", args, timeout=c.left())
    return out


def update_env(c):
    """Échéance (horloge murale, s) transmise à scanoria-selfupdate."""
    left = c.left()
    return {"SCANORIA_UPDATE_DEADLINE": str(int(time.time()) + max(0, left - UPDATE_DEADLINE_MARGIN))}


def act_apply_update(c):
    if c.params["source"] == "github":
        args = ["apply", "--version", c.params["version"]]
    else:
        args = ["apply", "--upload-id", c.params["upload_id"]]
    out, _ = common.run_protocol("scanoria-selfupdate", args, timeout=c.left(), env=update_env(c))
    return out


def act_rollback_update(c):
    out, _ = common.run_protocol("scanoria-selfupdate", [
        "rollback", "--expected-current", c.params["expected_current"],
        "--expected-target", c.params["expected_target"]], timeout=c.left(), env=update_env(c))
    return out


def act_set_update_policy(c):
    pol = {k: c.params[k] for k in ("channel", "auto_check", "auto_apply", "maintenance_window")}
    if pol["auto_apply"] and not pol["maintenance_window"]:
        raise Fail("E_INVALID_PARAM", "auto_apply requires a maintenance window")
    old = read_json_or(common.ETC + "/update.json", {})
    common.write_json(common.ETC + "/update.json", pol)
    if not isinstance(old, dict) or old.get("channel") != pol["channel"]:
        # Le résultat de la dernière vérification valait pour l'ancien canal.
        try:
            os.unlink(common.UPDATE_CHECK_FILE)
        except FileNotFoundError:
            pass
    return pol


def act_run_selftest(c):
    args = ["--json"] + (["--quick"] if c.params.get("quick") else [])
    r = common.run("scanoria-selftest", args, timeout=c.left())
    try:
        report = common.loads_strict(r.stdout)
    except common.JsonError:
        report = None
    if r.returncode not in (0, 1) or not schema.load("schemas", "selftest").valid(report):
        raise Fail("E_INTERNAL", "selftest failed to run (exit %d)" % r.returncode)
    os.makedirs(os.path.dirname(common.SELFTEST_LAST), exist_ok=True)
    common.write_json(common.SELFTEST_LAST, report)
    return report


ACTIONS = {
    "set-hostname": act_set_hostname,
    "set-admin-networks": act_set_admin_networks,
    "issue-certificate": act_issue_certificate,
    "import-certificate": act_import_certificate,
    "check-update": act_check_update,
    "apply-update": act_apply_update,
    "rollback-update": act_rollback_update,
    "set-update-policy": act_set_update_policy,
    "run-selftest": act_run_selftest,
    "check-dns": dnscheck.act_check_dns,
    "refresh-catalog": modules.act_refresh_catalog,
    "install-modules": modules.act_install_modules,
    "uninstall-module": modules.act_uninstall_module,
    "set-module-state": modules.act_set_module_state,
    "update-module": modules.act_update_module,
    "set-ai-endpoint": aiendpoint.act_set_ai_endpoint,
    "refresh-feeds": modules.act_refresh_feeds,
    "backup-module": modules.act_backup_module,
    "restore-module": modules.act_restore_module,
    "reset-service-admin": provision.act_reset_service_admin,
    "package-dates": pkgdates.act_package_dates,
    "export-bundle": bundle.act_export_bundle,
    "import-bundle": bundle.act_import_bundle,
    "set-mirror": mirror.act_set_mirror,
    "trust-key": offline.act_trust_key,
    "self-sbom": vigilance.act_self_sbom,
    "run-canaries": vigilance.act_run_canaries,
    "start-trial": vigilance.act_start_trial,
    "prefetch-images": prefetch.act_prefetch_images,
    "validate-ruleset": rulesets.act_validate_ruleset,
    "sign-attestation": attest.act_sign_attestation,
    "sign-release-report": release.act_sign_release_report,
}


def execute(req, origin, received):
    """Exécute une demande validée ; retourne le résultat (non écrit)."""
    started = common.now()
    rtype = req["type"]
    common.write_json(common.CURRENT_FILE, {"id": req["id"], "type": rtype, "step": "run",
                                            "started_at": common.iso(started)})
    os.environ["SCANORIA_STEP_FILE"] = common.CURRENT_FILE
    common.publish_state()
    try:
        ctx = Ctx(req, time.monotonic() + TIMEOUTS[rtype])
        output = ACTIONS[rtype](ctx)
        code, msg = "OK", rtype + " done"
    except Fail as e:
        code, msg, output = e.code, e.message, e.output
    except Exception as e:  # noqa: BLE001 — toute erreur imprévue devient E_INTERNAL
        common.log("internal error in %s: %r" % (rtype, e))
        code, msg, output = "E_INTERNAL", "internal error", {}
    finally:
        os.environ.pop("SCANORIA_STEP_FILE", None)
        try:
            os.unlink(common.CURRENT_FILE)
        except FileNotFoundError:
            pass
    return make_result(req["id"], rtype, origin, code, msg, received, started, output)


# --------------------------------------------------------------------------
# File d'attente
# --------------------------------------------------------------------------

def handle(name):
    received = common.now()
    m = NAME_RE.match(name)
    if not m:
        work = os.open(os.path.join(common.REQ, "work"), os.O_RDONLY | os.O_DIRECTORY)
        inc = os.open(os.path.join(common.REQ, "incoming"), os.O_RDONLY | os.O_DIRECTORY)
        tmpname = invalid_name()
        try:
            os.rename(name, tmpname, src_dir_fd=inc, dst_dir_fd=work)
            remove_entry(work, tmpname)
        finally:
            os.close(work)
            os.close(inc)
        write_result(tmpname, make_result(None, None, "console", "E_INVALID_NAME",
                                          "invalid request file name", received, None))
        return
    name_ts, rid = m.group(1), m.group(2)
    data, err = take(name)
    rtype = None
    if err is None:
        try:
            obj = common.loads_strict(data)
        except common.JsonError:
            err = ("E_INVALID_JSON", "invalid JSON")
        else:
            rtype, err = validate(obj, rid, name_ts, len(data))
    if err is not None:
        rname = name
        if err[0] == "E_DUPLICATE_ID" or id_seen(rid):
            # Ne jamais écraser ni contredire le résultat d'une demande déjà traitée.
            rname, rid, rtype = invalid_name(), None, None
        write_result(rname, make_result(rid, rtype, "console", err[0], err[1], received, None))
        return
    res = execute(obj, "console", received)
    # État publié AVANT le résultat : la console relit l'état dès qu'elle voit le
    # résultat final, et doit y trouver l'effet de l'action (pas l'état d'avant).
    common.publish_state()
    write_result(name, res)


def recover_work():
    """Après un arrêt brutal : les demandes restées dans work/ sont closes en erreur."""
    wdir = os.path.join(common.REQ, "work")
    wfd = os.open(wdir, os.O_RDONLY | os.O_DIRECTORY)
    try:
        for n in sorted(os.listdir(wdir)):
            m = NAME_RE.match(n)
            remove_entry(wfd, n)
            if m and not id_seen(m.group(2)):
                write_result(n, make_result(m.group(2), None, "console", "E_INTERNAL",
                                            "interrupted", common.now(), None))
    finally:
        os.close(wfd)


def cmd_run():
    # Une demande « exec » (premier démarrage, timer) peut tenir le verrou jusqu'à
    # la fin d'une mise à jour : attendre plutôt qu'échouer et être relancé en boucle.
    with Lock(wait=3300):
        recover_work()
        provision.purge_oneshot()   # valeurs à lecture unique échues (mot de passe admin d'un service)
        ensure_appliance_key()
        for _ in range(10000):
            names = sorted(os.listdir(os.path.join(common.REQ, "incoming")))
            if not names:
                break
            for n in names:
                try:
                    handle(n)
                except FileNotFoundError:
                    continue
                except Exception as e:  # noqa: BLE001
                    common.log("cannot handle %r: %r" % (n, e))
            common.publish_state()
    common.publish_state()
    return 0


def ensure_appliance_key():
    """Clé Ed25519 de l'appliance (lots hors ligne) : créée au premier passage si absente."""
    try:
        if offline.ensure_key():
            offline.publish_status()
    except (Fail, OSError) as e:
        common.log("appliance key not created: %s" % getattr(e, "message", e))


def cmd_exec(origin, rtype, params_text):
    received = common.now()
    rid = str(uuid.uuid4())
    name = "%s-%s.json" % (received.strftime("%Y%m%dT%H%M%SZ"), rid)
    try:
        params = common.loads_strict(params_text)
    except common.JsonError:
        res = make_result(rid, None, origin, "E_INVALID_JSON", "invalid params JSON", received, None)
    else:
        req = {"version": 1, "id": rid, "type": rtype, "created_at": common.iso(received),
               "requested_by": {"user_id": 0, "username": "system"}, "params": params}
        with Lock(wait=TIMEOUTS.get(rtype, 60) + 60):
            ensure_appliance_key()
            t, err = validate(req)
            if err is not None:
                res = make_result(rid, t, origin, err[0], err[1], received, None)
            else:
                res = execute(req, origin, received)
    common.publish_state()
    write_result(name, res)
    sys.stdout.write(common.dumps(res))
    return 0 if res["status"] == "ok" else 1


# --------------------------------------------------------------------------
# Tâches planifiées (timers)
# --------------------------------------------------------------------------

DAYS = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")


def in_window(win, now_local):
    if not isinstance(win, dict):
        return False
    try:
        hh, mm = (int(x) for x in win["start"].split(":"))
        dur = datetime.timedelta(minutes=int(win["duration_minutes"]))
        days = set(win["days"])
    except (KeyError, ValueError, TypeError):
        return False
    for back in (0, 1):
        d = (now_local - datetime.timedelta(days=back)).date()
        if DAYS[d.weekday()] not in days:
            continue
        start = datetime.datetime(d.year, d.month, d.day, hh, mm, tzinfo=now_local.tzinfo)
        if start <= now_local < start + dur:
            return True
    return False


def cmd_scheduled(job):
    pol = read_json_or(common.ETC + "/update.json", {})
    if job == "update-check":
        if pol.get("auto_check") is not True:
            return 0
        return cmd_exec("timer", "check-update", "{}")
    if job == "bundle-export":
        # Rien à faire (ni résultat écrit) tant que l'export périodique n'est pas activé.
        if not offline.load_schedule().get("enabled"):
            return 0
        return cmd_exec("timer", "export-bundle", '{"scheduled": true}')
    if job == "cert-renew":
        if appliance_fqdn() is None:
            return 0
        # Certificat du miroir des bases (feeds.<nom>), quel que soit le mode TLS.
        try:
            from . import dtmirror
            dtmirror.refresh_tls()
        except Fail as e:
            common.log("feeds mirror certificate not renewed: %s" % e.message)
        # 0.7 (contrat 31) : certificat du relais IA ; scanoria-ai le relit à son redémarrage.
        try:
            from . import aiendpoint
            aiendpoint.refresh_relay_certificate()
        except Fail as e:
            common.log("AI relay certificate not renewed: %s" % e.message)
        if tls_mode() != "internal":
            return 0
        return cmd_exec("timer", "issue-certificate", '{"force": false}')
    if job == "update-apply":
        if pol.get("auto_apply") is not True or not in_window(pol.get("maintenance_window"),
                                                              datetime.datetime.now().astimezone()):
            return 0
        channel = pol.get("channel") if pol.get("channel") in ("stable", "prerelease") else "stable"
        # Vérification fraîche juste avant d'appliquer : une version rejetée ou
        # retirée depuis la dernière vérification n'est jamais installée.
        if cmd_exec("timer", "check-update", "{}") != 0:
            return 1
        chk = read_json_or(common.UPDATE_CHECK_FILE, {})
        if not isinstance(chk, dict) or chk.get("channel") != channel or chk.get("code") != "OK":
            return 0
        try:
            if common.now() - common.parse_iso(chk.get("checked_at")) > datetime.timedelta(minutes=30):
                return 0
        except (TypeError, ValueError):
            return 0
        latest, cur = chk.get("latest_version"), common.installed_version()
        try:
            if not chk.get("available") or common.parse_version(latest) <= common.parse_version(cur):
                return 0
            skip = read_json_or(common.UPDATE_SKIP_FILE, {})
            if isinstance(skip, dict) and isinstance(skip.get("version"), str) \
                    and common.parse_version(latest) <= common.parse_version(skip["version"]):
                return 0  # version abandonnée par un retour à N-1 : jamais réinstallée d'office
        except (TypeError, ValueError):
            return 0
        marker = common.VARLIB + "/updates/auto-apply.json"
        last = read_json_or(marker, {})
        if last.get("version") == latest and last.get("code") != "OK":
            return 0  # pas de nouvel essai automatique d'une version qui a échoué
        common.write_json(marker, {"version": latest, "code": None, "at": common.iso(common.now())},
                          0o600, group_scanoria=False)
        params = common.dumps({"source": "github", "version": latest})
        rc = cmd_exec("timer", "apply-update", params)
        common.write_json(marker, {"version": latest, "code": "OK" if rc == 0 else "failed",
                                   "at": common.iso(common.now())}, 0o600, group_scanoria=False)
        return rc
    sys.stderr.write("scanoria-helper: unknown job\n")
    return 2


USAGE = """usage: scanoria-helper run
       scanoria-helper exec --origin timer|firstboot|cli --type TYPE --params JSON
       scanoria-helper scheduled update-check|update-apply|cert-renew|bundle-export
"""


def main(argv):
    if not common.TEST_ROOT and os.geteuid() != 0:
        sys.stderr.write("scanoria-helper: root required\n")
        return 2
    os.umask(0o027)
    try:
        if argv == ["run"]:
            return cmd_run()
        if len(argv) == 2 and argv[0] == "scheduled":
            return cmd_scheduled(argv[1])
        if len(argv) == 7 and argv[0] == "exec":
            opts = dict(zip(argv[1::2], argv[2::2]))
            if set(opts) == {"--origin", "--type", "--params"} and opts["--origin"] in ORIGINS \
                    and opts["--type"] in common.REQUEST_TYPES and len(opts["--params"]) <= MAX_SIZE:
                return cmd_exec(opts["--origin"], opts["--type"], opts["--params"])
    except Fail as e:
        sys.stderr.write("scanoria-helper: %s\n" % e.message)
        return 1
    sys.stderr.write(USAGE)
    return 2
