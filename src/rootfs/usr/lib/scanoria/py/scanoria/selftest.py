# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Vincent Tisseront
"""scanoria-selftest : tests de fumée de l'appliance (ARCHITECTURE § 8).

  scanoria-selftest [--json] [--quick]

Codes de sortie : 0 = pass ou warn, 1 = au moins un fail, 2 = erreur d'usage
ou interne. Avec --json, rapport conforme à schemas/selftest.schema.json.
"""

import datetime
import os
import re
import secrets
import socket
import stat
import sys

from . import common, netutil, schema


class Report:
    def __init__(self):
        self.checks = []

    def add(self, cid, status, message, details=None):
        c = {"id": cid, "status": status, "message": message[:500]}
        if details:
            c["details"] = details
        self.checks.append(c)

    def status(self):
        st = {c["status"] for c in self.checks}
        return "fail" if "fail" in st else ("warn" if "warn" in st else "pass")


def _json(path):
    try:
        return common.load_json_file(path, 1 << 20)
    except (OSError, common.JsonError):
        return None


def fqdn():
    f = (_json(common.ETC + "/appliance.json") or {}).get("fqdn")
    return f if netutil.check_fqdn(f) else None


# --------------------------------------------------------------------------

def check_version(rep):
    a = common.read_text(common.OPT + "/current/VERSION", 64)
    b = common.read_text(common.OPT + "/current/webui/VERSION", 64)
    if a and a == b and common.SEMVER_RE.match(a):
        rep.add("version.files", "pass", "version %s" % a)
    else:
        rep.add("version.files", "fail", "VERSION and webui/VERSION differ or are missing")


def check_layout(rep):
    bad = []
    for link, required in (("current", True), ("previous", False)):
        path = os.path.join(common.OPT, link)
        if not os.path.lexists(path):
            if required:
                bad.append(link + " missing")
            continue
        target = os.readlink(path) if os.path.islink(path) else ""
        m = re.fullmatch(r"releases/((?:0|[1-9][0-9]{0,3})\.(?:0|[1-9][0-9]{0,3})\.(?:0|[1-9][0-9]{0,3}))", target)
        if not m or common.read_text(os.path.join(path, "VERSION"), 64) != m.group(1):
            bad.append(link + " invalid")
    if bad:
        rep.add("layout.release", "fail", ", ".join(bad))
    else:
        rep.add("layout.release", "pass", "release links valid")


# (chemin, propriétaire, groupe, mode) — ARCHITECTURE § 3.2
PERMS = (
    ("/opt/scanoria", "root", "root", 0o755),
    ("/etc/scanoria", "root", "scanoria", 0o750),
    ("/etc/scanoria/pki", "root", "root", 0o700),
    ("/var/lib/scanoria", "root", "scanoria", 0o750),
    ("/var/lib/scanoria/requests", "root", "scanoria", 0o750),
    ("/var/lib/scanoria/requests/tmp", "scanoria", "scanoria", 0o700),
    ("/var/lib/scanoria/requests/incoming", "scanoria", "scanoria", 0o700),
    ("/var/lib/scanoria/requests/work", "root", "root", 0o700),
    ("/var/lib/scanoria/requests/done", "root", "scanoria", 0o750),
    ("/var/lib/scanoria/requests/failed", "root", "scanoria", 0o750),
    ("/var/lib/scanoria/uploads", "scanoria", "scanoria", 0o700),
    ("/var/lib/scanoria/updates", "root", "root", 0o700),
    ("/var/lib/scanoria/backups/pre-update", "root", "root", 0o700),
    ("/run/scanoria", "root", "scanoria", 0o750),
)


def _ids(user, group):
    if common.TEST_ROOT:
        return None
    import grp
    import pwd
    return pwd.getpwnam(user).pw_uid, grp.getgrnam(group).gr_gid


def check_perms(rep):
    bad = []
    for path, user, group, mode in PERMS:
        try:
            st = os.lstat(common.p(path))
        except FileNotFoundError:
            bad.append(path + " missing")
            continue
        if not stat.S_ISDIR(st.st_mode) or stat.S_IMODE(st.st_mode) != mode:
            bad.append("%s mode %o" % (path, stat.S_IMODE(st.st_mode)))
            continue
        try:
            ids = _ids(user, group)
        except KeyError:
            bad.append("account %s missing" % user)
            continue
        if ids and (st.st_uid, st.st_gid) != ids:
            bad.append(path + " owner")
    if bad:
        rep.add("perms.paths", "fail", "; ".join(bad[:10]), {"problems": bad})
    else:
        rep.add("perms.paths", "pass", "owners and modes as expected")


def check_pubkey(rep):
    try:
        st = os.lstat(common.PUBKEY)
    except FileNotFoundError:
        rep.add("pubkey.present", "fail", "update-pubkey.pem missing")
        return
    r = common.run("openssl", ["pkey", "-pubin", "-in", common.PUBKEY, "-noout", "-text"], timeout=30)
    if not stat.S_ISREG(st.st_mode) or stat.S_IMODE(st.st_mode) != 0o644 \
            or (not common.TEST_ROOT and st.st_uid != 0):
        rep.add("pubkey.present", "fail", "update-pubkey.pem must be a root-owned 0644 file")
    elif r.returncode != 0 or "ED25519" not in r.text:
        rep.add("pubkey.present", "fail", "update-pubkey.pem is not an Ed25519 public key")
    else:
        rep.add("pubkey.present", "pass", "Ed25519 public key pinned")


SERVICE_CHECKS = (
    ("services.postgresql", "postgresql.service"),
    ("services.nginx", "nginx.service"),
    ("services.console", "scanoria-console.service"),
    ("services.helper-path", "scanoria-helper.path"),
)


def check_services(rep):
    r = common.run("systemctl", ["is-active"] + [u for _, u in SERVICE_CHECKS], timeout=30)
    states = r.text.splitlines()
    for i, (cid, unit) in enumerate(SERVICE_CHECKS):
        s = states[i].strip() if i < len(states) else "unknown"
        rep.add(cid, "pass" if s == "active" else "fail", "%s %s" % (unit, s))


WORKER_HEARTBEAT = common.VARLIB + "/console/worker.json"


def check_worker(rep):
    """worker.alive (0.3) : scanoria-worker actif et signe de vie de moins de 2 minutes."""
    r = common.run("systemctl", ["is-active", "scanoria-worker.service"], timeout=30)
    state = (r.text.splitlines() or ["unknown"])[0].strip()
    beat = _json(WORKER_HEARTBEAT)
    beat = beat if isinstance(beat, dict) else {}
    age = None
    try:
        age = (common.now() - common.parse_iso(beat.get("at", ""))).total_seconds()
    except (TypeError, ValueError):
        pass
    if state == "active" and age is not None and age <= 120:
        rep.add("worker.alive", "pass", "scan queue worker alive (%ds ago)" % max(0, int(age)))
    else:
        rep.add("worker.alive", "fail", "scanoria-worker.service %s, last heartbeat %s"
                % (state, "never" if age is None else "%ds ago" % int(age)),
                {"state": state, "heartbeat_age_s": None if age is None else int(age)})


def psql(sql):
    r = common.run("runuser", ["-u", "postgres", "--", common.SYSTEM_CMDS["psql"], "-XAtq",
                               "-d", "scanoria", "-c", sql], timeout=30)
    return r.returncode, r.text.strip()


def check_db(rep):
    rc, out = psql("SELECT 1")
    if rc != 0 or out != "1":
        rep.add("db.connect", "fail", "cannot connect to database scanoria")
        rep.add("db.migrations", "skip", "database unavailable")
        return
    rep.add("db.connect", "pass", "database reachable")
    shipped = 0
    try:
        for n in os.listdir(common.OPT + "/current/webui/migrations"):
            m = re.fullmatch(r"([0-9]{3})_[a-z0-9_]+\.sql", n)
            if m:
                shipped = max(shipped, int(m.group(1)))
    except OSError:
        pass
    rc, out = psql("SELECT coalesce(max(version), 0) FROM schema_migrations")
    if rc != 0 or not out.isdigit():
        rep.add("db.migrations", "fail", "schema_migrations unreadable")
    elif int(out) != shipped:
        rep.add("db.migrations", "fail", "applied %s, shipped %d" % (out, shipped))
    else:
        rep.add("db.migrations", "pass", "migration %03d applied" % shipped)


def check_console(rep, name, version):
    if not name:
        rep.add("console.health", "fail", "appliance name not set")
        return
    args = ["--silent", "--max-time", "10", "--proto", "=https",
            "--resolve", "%s:443:127.0.0.1" % name]
    mode = (_json(common.ETC + "/tls.json") or {}).get("mode")
    if mode == "internal":
        args += ["--cacert", common.ETC + "/pki/ca/ca.crt"]
    args.append("https://%s/api/health" % name)
    r = common.run("curl", args, timeout=30)
    try:
        h = common.loads_strict(r.stdout)
    except common.JsonError:
        h = None
    if isinstance(h, dict) and h.get("status") == "ok" and h.get("version") == version:
        rep.add("console.health", "pass", "console answers through nginx")
    else:
        rep.add("console.health", "fail", "console health check through nginx failed")


def _enddate(cert):
    r = common.run("openssl", ["x509", "-in", cert, "-noout", "-enddate"], timeout=30)
    m = re.fullmatch(r"notAfter=(.+)", r.text.strip())
    if r.returncode != 0 or not m:
        return None
    try:
        dt = datetime.datetime.strptime(m.group(1).replace("  ", " "), "%b %d %H:%M:%S %Y GMT")
    except ValueError:
        return None
    return dt.replace(tzinfo=datetime.timezone.utc)


def _pub(kind, path):
    if kind == "x509":
        r = common.run("openssl", ["x509", "-in", path, "-noout", "-pubkey"], timeout=30)
    else:
        r = common.run("openssl", ["pkey", "-in", path, "-passin", "pass:", "-pubout"], timeout=30)
    return r.stdout.strip() if r.returncode == 0 else None


def _checkhost(cert, host):
    r = common.run("openssl", ["x509", "-in", cert, "-noout", "-checkhost", host], timeout=30)
    return r.returncode == 0 and r.text.strip().endswith(" does match certificate")


def check_tls(rep, name):
    cert = common.ETC + "/pki/active/fullchain.pem"
    key = common.ETC + "/pki/active/privkey.pem"
    end = _enddate(cert) if os.path.isfile(cert) else None
    if end is None:
        rep.add("tls.cert-valid", "fail", "no active certificate")
    else:
        days = (end - common.now()).total_seconds() / 86400
        st = "pass" if days > 14 else ("warn" if days >= 1 else "fail")
        rep.add("tls.cert-valid", st, "expires in %d days" % int(days) if days >= 0 else "expired",
                {"not_after": common.iso(end)})
    if end is not None and name:
        probe = "z%s.%s" % (secrets.token_hex(6), name)
        ok = _checkhost(cert, name) and _checkhost(cert, probe)
        rep.add("tls.cert-names", "pass" if ok else "fail",
                "certificate covers %s and *.%s" % (name, name) if ok else "certificate names do not cover the appliance")
    else:
        rep.add("tls.cert-names", "fail", "no certificate or appliance name")
    pc, pk = (_pub("x509", cert), _pub("pkey", key)) if end is not None else (None, None)
    rep.add("tls.key-match", "pass" if pc and pc == pk else "fail",
            "key matches certificate" if pc and pc == pk else "key does not match certificate")
    ca = common.ETC + "/pki/ca/ca.crt"
    pub = common.VARLIB + "/public/scanoria-ca.crt"
    try:
        with open(ca, "rb") as a, open(pub, "rb") as b:
            same = a.read() == b.read()
    except OSError:
        same = False
    rep.add("tls.ca-present", "pass" if same else "fail",
            "internal CA present and published" if same else "internal CA missing or not published")


def check_firewall(rep):
    try:
        out, _ = common.run_protocol("scanoria-firewall", ["status"], timeout=30)
    except common.Fail:
        out = {}
    if out.get("loaded") is True and out.get("admin_networks"):
        rep.add("firewall.loaded", "pass", "table inet scanoria loaded",
                {"admin_networks": out["admin_networks"]})
    else:
        rep.add("firewall.loaded", "fail", "table inet scanoria not loaded or no admin network")


def check_queue(rep):
    old = 0
    d = common.REQ + "/incoming"
    limit = common.now().timestamp() - 600
    try:
        for n in os.listdir(d):
            try:
                if os.lstat(os.path.join(d, n)).st_mtime < limit:
                    old += 1
            except FileNotFoundError:
                pass
    except OSError:
        rep.add("requests.queue", "warn", "request queue unreadable")
        return
    rep.add("requests.queue", "warn" if old else "pass",
            "%d request(s) waiting for more than 10 minutes" % old if old else "queue healthy")


def check_disk(rep):
    worst, details = "pass", {}
    for mount in ("/", "/var"):
        try:
            v = os.statvfs(mount)
        except OSError:
            continue
        pct = 100.0 * v.f_bavail / v.f_blocks if v.f_blocks else 0.0
        details[mount] = round(pct, 1)
        st = "fail" if pct < 5 else ("warn" if pct < 10 else "pass")
        if ("pass", "warn", "fail").index(st) > ("pass", "warn", "fail").index(worst):
            worst = st
    rep.add("disk.free", worst, "free space: " + ", ".join("%s %.1f%%" % kv for kv in details.items()),
            {"free_percent": details})


def check_dns(rep, name):
    if not name:
        rep.add("dns.resolve", "warn", "appliance name not set")
        return
    bad = []
    for host in (name, "test." + name):
        try:
            socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP)
        except (OSError, UnicodeError):
            bad.append(host)
    rep.add("dns.resolve", "warn" if bad else "pass",
            "not resolved: " + ", ".join(bad) if bad else "%s and *.%s resolve" % (name, name))


def check_routing(rep):
    """routing.sites : sites nginx des modules cohérents avec modules/state.json."""
    from . import routing
    st, msg, details = routing.sites_status()
    rep.add("routing.sites", st, msg, details)


def check_time(rep):
    r = common.run("timedatectl", ["show", "--property=NTPSynchronized", "--value"], timeout=30)
    ok = r.text.strip() == "yes"
    rep.add("time.sync", "pass" if ok else "warn", "clock synchronized" if ok else "clock not synchronized")


RUNNER_STATE = common.RUN + "/runner.json"
RUNNER_MAX_AGE_S = 120


def check_runner(rep):
    """runner.alive : scanoria-runner actif et capacité publiée récemment (ARCHITECTURE § 12.1)."""
    r = common.run("systemctl", ["is-active", "scanoria-runner.service"], timeout=30)
    active = r.text.strip() == "active"
    st = _json(RUNNER_STATE)
    age = None
    try:
        age = (common.now() - common.parse_iso(st["updated_at"])).total_seconds()
    except (TypeError, KeyError, ValueError):
        pass
    fresh = age is not None and -60 <= age <= RUNNER_MAX_AGE_S
    if active and fresh:
        rep.add("runner.alive", "pass", "scanoria-runner active, %s slot(s), %s busy" % (st.get("slots"), st.get("busy")),
                {"slots": st.get("slots"), "busy": st.get("busy")})
    else:
        rep.add("runner.alive", "fail", "scanoria-runner %s, capacity %s" % (
            "active" if active else "not active",
            "fresh" if fresh else ("stale" if age is not None else "not published")))


def check_hardware(rep):
    from .state import memory_mb
    cpu, mem = os.cpu_count() or 0, memory_mb()
    v = os.statvfs("/")
    disk_gb = v.f_blocks * v.f_frsize / 1e9
    ok = cpu >= 2 and mem >= 3700 and disk_gb >= 38
    rep.add("hardware.floor", "pass" if ok else "warn",
            "%d vCPU, %d MB, %.0f GB" % (cpu, mem, disk_gb),
            {"cpu": cpu, "memory_mb": mem, "disk_gb": round(disk_gb)})


def check_ai(rep):
    """ai.alive : seulement si le connecteur IA est actif (CLAUDE.md § 3.5)."""
    from . import aiendpoint
    conf = aiendpoint.load_conf()
    if not conf.get("enabled"):
        return
    r = common.run("systemctl", ["is-active", "scanoria-ai.service"], timeout=30)
    active = r.returncode == 0
    status = _json(aiendpoint.STATUS_FILE) or {}
    changed = bool((status.get("resolution") or {}).get("changed"))
    if not active:
        # Avertissement, jamais un échec : l'appliance fonctionne à l'identique
        # sans l'IA (CLAUDE.md § 1, § 3.5). Un échec ici faisait annuler une
        # mise à jour, puis échouer son retour arrière (0.5.0 → 0.7.0).
        rep.add("ai.alive", "warn", "AI connector enabled but scanoria-ai is not running")
    elif changed:
        rep.add("ai.alive", "warn", "AI server name now resolves differently: confirm it again in the console",
                {"pinned": conf.get("addresses", [])})
    else:
        rep.add("ai.alive", "pass", "scanoria-ai running", {"addresses": conf.get("addresses", [])})


def run_checks(quick):
    rep = Report()
    started = common.now()
    name = fqdn()
    version = common.installed_version() or "0.0.0"
    check_version(rep)
    check_layout(rep)
    check_perms(rep)
    check_pubkey(rep)
    check_services(rep)
    check_worker(rep)
    check_db(rep)
    check_console(rep, name, version)
    check_tls(rep, name)
    check_firewall(rep)
    check_queue(rep)
    check_disk(rep)
    check_routing(rep)
    check_ai(rep)
    check_runner(rep)
    if not quick:
        check_dns(rep, name)
        check_time(rep)
        check_hardware(rep)
    return {"version": 1, "appliance_version": version, "started_at": common.iso(started),
            "finished_at": common.iso(common.now()), "status": rep.status(), "checks": rep.checks}


def main(argv):
    opts = set(argv)
    if len(opts) != len(argv) or not opts <= {"--json", "--quick"}:
        sys.stderr.write("usage: scanoria-selftest [--json] [--quick]\n")
        return 2
    if not common.TEST_ROOT and os.geteuid() != 0:
        sys.stderr.write("scanoria-selftest: root required\n")
        return 2
    try:
        report = run_checks("--quick" in opts)
        errs = schema.load("schemas", "selftest").errors(report)
        if errs:
            raise RuntimeError("report does not match its schema: %s" % errs[:3])
    except Exception as e:  # noqa: BLE001 — erreur interne : code 2
        sys.stderr.write("scanoria-selftest: internal error: %r\n" % (e,))
        return 2
    if "--json" in opts:
        sys.stdout.write(common.dumps(report))
    else:
        for c in report["checks"]:
            sys.stdout.write("%-5s %-22s %s\n" % (c["status"].upper(), c["id"], c["message"]))
        sys.stdout.write("%s\n" % report["status"].upper())
    return 1 if report["status"] == "fail" else 0
