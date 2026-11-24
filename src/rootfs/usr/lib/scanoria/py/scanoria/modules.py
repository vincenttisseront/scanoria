# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Vincent Tisseront
"""Moteur des modules (CLAUDE.md § 4.3) : demandes install-modules,
uninstall-module, set-module-state et update-module, exécutées en root.

Rien n'est pris dans la demande sans contrôle : seuls l'identifiant, la version
et les options en viennent ; tout le reste (image, commandes, ressources,
licence, dépendances) vient de l'index du catalogue vérifié, et chaque valeur
est revalidée avant usage. Toutes les vérifications (dépendances et conflits,
G1 ; ressources ; licences ; options, G3) sont faites avant le premier
changement. Ensuite, au moindre échec (image, santé, banc d'essai F12,
routage), tout ce que l'opération a posé est retiré : retour arrière complet.

Registre interne : /var/lib/scanoria/modules/installed.json (root, 0600), qui
garde le manifeste de chaque module installé. État publié pour la console :
/var/lib/scanoria/modules/state.json (root:scanoria 0640), conforme à
modules-state.schema.json, avec la progression des opérations.
"""

import os
import re
import secrets
import shutil
import time
import uuid

from . import catalogverify, common, quadlet, schema, testbed
from .common import Fail

MODULES_DIR = common.VARLIB + "/modules"
REGISTRY = MODULES_DIR + "/installed.json"
STATE = MODULES_DIR + "/state.json"
BACKUPS = common.VARLIB + "/backups/modules"
SYSCTL_FILE = common.p("/etc/sysctl.d/60-scanoria-modules.conf")
MAX_OPERATIONS = 20
KEEP_BACKUPS = 2
HOST_PORTS = range(18000, 19000)
# Mémoire laissée au système, à PostgreSQL et à la console (plancher D6 : 4 Go).
RESERVED_RAM_MB = 3072
RESERVED_DISK_MB = 2048
HEALTH_TIMEOUT = 600
if common.TEST_ROOT and os.environ.get("SCANORIA_TEST_HEALTH_TIMEOUT", "").isdigit():
    HEALTH_TIMEOUT = int(os.environ["SCANORIA_TEST_HEALTH_TIMEOUT"])
SCANNER_HEALTH_TIMEOUT = 120
SYSCTL_ALLOWED = {
    "vm.max_map_count": (65530, 1 << 30),
    "fs.file-max": (8192, 1 << 31),
    "fs.inotify.max_user_watches": (8192, 1 << 24),
    "fs.inotify.max_user_instances": (128, 1 << 16),
    "net.core.somaxconn": (128, 65535),
}
OPTION_NAME_RE = re.compile(r"[a-z][a-z0-9_]{0,40}\Z")
HEALTH_PATH_RE = re.compile(r"/[A-Za-z0-9._~/?=&%-]{0,200}\Z")
APPLIANCE_REQ_RE = re.compile(r"(>=|<=|==|=|>|<)?\s*((?:0|[1-9][0-9]{0,3})\.(?:0|[1-9][0-9]{0,3})\.(?:0|[1-9][0-9]{0,3}))\Z")


# --------------------------------------------------------------------------
# Versions
# --------------------------------------------------------------------------

def vkey(v):
    """Clé de tri naturelle d'une version amont (1.10.0 > 1.9.3)."""
    return [(0, int(x), "") if x.isdigit() else (1, 0, x) for x in re.split(r"[.+_-]", v)]


def appliance_ok(spec):
    """Contrainte requires.appliance (« >=0.2.0 », plusieurs séparées par des virgules)."""
    if spec in (None, ""):
        return True
    cur = common.installed_version()
    if cur is None:
        raise Fail("E_PRECONDITION", "installed appliance version unknown")
    cv = common.parse_version(cur)
    if not isinstance(spec, str) or len(spec) > 100:
        raise Fail("E_DEPENDENCY", "invalid appliance requirement")
    for part in re.split(r"[,\s]+(?=[<>=])|,", spec.strip()):
        m = APPLIANCE_REQ_RE.match(part.strip())
        if not m:
            raise Fail("E_DEPENDENCY", "invalid appliance requirement")
        op, want = m.group(1) or "==", common.parse_version(m.group(2))
        ok = {">=": cv >= want, "<=": cv <= want, ">": cv > want, "<": cv < want,
              "=": cv == want, "==": cv == want}[op]
        if not ok:
            return False
    return True


# --------------------------------------------------------------------------
# Registre et état publié
# --------------------------------------------------------------------------

def load_registry():
    try:
        reg = common.load_json_file(REGISTRY, 16 << 20)
    except FileNotFoundError:
        reg = {}
    except (OSError, common.JsonError):
        raise Fail("E_INTERNAL", "module registry unreadable")
    if not isinstance(reg, dict):
        raise Fail("E_INTERNAL", "module registry malformed")
    reg.setdefault("modules", {})
    reg.setdefault("operations", [])
    return reg


def save_registry(reg):
    os.makedirs(MODULES_DIR, mode=0o750, exist_ok=True)
    common.write_json(REGISTRY, reg, 0o600, group_scanoria=False)
    publish(reg)


def public_entry(mid, e):
    m = e["manifest"]
    return {"id": mid, "version": m["version"], "type": m["type"], "status": e["status"],
            "enabled": e["enabled"], "installed_at": e["installed_at"], "options": e["options"],
            "testbed": e.get("testbed"), "route": e.get("route"), "last_error": e.get("last_error")}


def publish(reg):
    st = {"version": 1, "updated_at": common.iso(common.now()),
          "modules": [public_entry(k, reg["modules"][k]) for k in sorted(reg["modules"])],
          "operations": reg["operations"][-MAX_OPERATIONS:]}
    v = schema.load("schemas", "modules-state")
    errs = v.errors(st)
    if errs:
        common.log("modules state does not match its schema: %s" % errs[:3])
        raise Fail("E_INTERNAL", "invalid modules state")
    common.write_json(STATE, st, 0o640)


class Op:
    """Opération suivie dans state.json (indicateur d'attente de la console)."""

    def __init__(self, reg, kind, module, request_id):
        self.reg = reg
        self.rec = {"id": str(uuid.uuid4()), "request_id": request_id, "kind": kind, "module": module,
                    "step": "resolve", "progress": 0, "started_at": common.iso(common.now()),
                    "finished_at": None, "result": None, "message": None}
        reg["operations"].append(self.rec)
        del reg["operations"][:-MAX_OPERATIONS]
        save_registry(reg)

    def step(self, step, progress, module=None):
        self.rec.update(step=step, progress=max(0, min(99, int(progress))))
        if module:
            self.rec["module"] = module
        save_registry(self.reg)
        common.set_step(step)

    def finish(self, ok, message):
        self.rec.update(finished_at=common.iso(common.now()), result="ok" if ok else "failed",
                        progress=100 if ok else self.rec["progress"], step="done" if ok else self.rec["step"],
                        message=str(message)[:500])
        save_registry(self.reg)


# --------------------------------------------------------------------------
# Index du catalogue
# --------------------------------------------------------------------------

def catalog():
    idx = catalogverify.installed_index()
    if idx is None:
        # Principe 8 : premier usage sans index local, on le récupère d'office.
        catalogverify.refresh()
        idx = catalogverify.installed_index()
    if idx is None or not isinstance(idx.get("modules"), list):
        raise Fail("E_PRECONDITION", "catalog index not available")
    for m in idx["modules"]:
        catalogverify.check_module(m)
    return idx["modules"]


def lookup(mods, mid, version=None):
    cands = [m for m in mods if m["id"] == mid and (version is None or m["version"] == version)]
    if not cands:
        raise Fail("E_NOT_FOUND", "module %s%s not in the catalog" % (mid, " " + version if version else ""))
    return max(cands, key=lambda m: vkey(m["version"]))


def requires_of(m):
    r = m.get("requires") or {}
    out = []
    for key in ("modules", "feeds"):
        for d in r.get(key) or []:
            if not isinstance(d, str) or not catalogverify.MODULE_ID_RE.match(d):
                raise Fail("E_DEPENDENCY", "%s: invalid dependency" % m["id"])
            out.append(d)
    return out


def conflicts_of(m):
    return [c for c in (m.get("conflicts") or []) if isinstance(c, str)]


def dependents(reg, mid, only_enabled=False):
    return sorted(k for k, e in reg["modules"].items()
                  if k != mid and mid in requires_of(e["manifest"]) and (e["enabled"] or not only_enabled))


# --------------------------------------------------------------------------
# Contrôles préalables
# --------------------------------------------------------------------------

def resolve_options(m, given):
    sch = m.get("options")
    if sch is None:
        sch = {"type": "object", "properties": {}}
    if not isinstance(sch, dict) or sch.get("type") != "object" or not isinstance(sch.get("properties", {}), dict):
        raise Fail("E_PRECONDITION", "%s: invalid options schema" % m["id"])
    props = sch.get("properties", {})
    opts = {}
    for k, p in props.items():
        if not OPTION_NAME_RE.match(k):
            raise Fail("E_PRECONDITION", "%s: invalid option name" % m["id"])
        if not isinstance(p, dict) or "default" not in p:
            raise Fail("E_PRECONDITION", "%s: option %s has no default" % (m["id"], k))
        opts[k] = p["default"]
    for k, v in (given or {}).items():
        if k not in props:
            raise Fail("E_INVALID_PARAM", "%s: unknown option %s" % (m["id"], k))
        opts[k] = v
    try:
        errs = schema.Validator(sch).errors(opts)
    except schema.SchemaError:
        raise Fail("E_PRECONDITION", "%s: unsupported options schema" % m["id"])
    if errs:
        raise Fail("E_INVALID_PARAM", "%s: invalid options: %s" % (m["id"], "; ".join(errs[:3])))
    return opts


def _meminfo_mb():
    try:
        with open(common.p("/proc/meminfo"), encoding="ascii") as f:
            for ln in f:
                if ln.startswith("MemTotal:"):
                    return int(ln.split()[1]) // 1024
    except (OSError, ValueError, IndexError):
        pass
    raise Fail("E_RESOURCES", "cannot read the memory size")


def _cpus():
    try:
        with open(common.p("/proc/cpuinfo"), encoding="ascii", errors="replace") as f:
            n = sum(1 for ln in f if ln.startswith("processor"))
        if n:
            return n
    except OSError:
        pass
    return os.cpu_count() or 1


def _free_disk_mb():
    path = common.p("/var/lib/containers")
    if not os.path.isdir(path):
        path = common.VARLIB
    st = os.statvfs(path)
    return st.f_bavail * st.f_frsize // (1 << 20)


def _res(m, key):
    v = (m.get("resources") or {}).get(key, 0)
    return v if isinstance(v, (int, float)) and not isinstance(v, bool) and v >= 0 else 0


def check_resources(installed, planned, freed=()):
    """installed, planned : manifestes ; freed : manifestes remplacés (mise à jour)."""
    freed_ids = {(m["id"], m["version"]) for m in freed}
    keep = [m for m in installed if (m["id"], m["version"]) not in freed_ids]
    allm = keep + list(planned)
    perm = sum(_res(m, "min_ram_mb") for m in allm if m["type"] in ("service", "runner"))
    trans = max([_res(m, "min_ram_mb") for m in allm if m["type"] in ("scanner", "feed")] or [0])
    need, have = RESERVED_RAM_MB + perm + trans, _meminfo_mb()
    if need > have:
        raise Fail("E_RESOURCES", "not enough memory: %d MB needed, %d MB available" % (need, have),
                   {"resource": "ram", "needed_mb": int(need), "available_mb": have})
    cpu = max([_res(m, "min_cpu") for m in planned] or [0])
    if cpu > _cpus():
        raise Fail("E_RESOURCES", "not enough CPUs: %s needed, %d available" % (cpu, _cpus()),
                   {"resource": "cpu", "needed": cpu, "available": _cpus()})
    disk = sum(_res(m, "disk_mb") for m in planned)
    free = _free_disk_mb()
    if disk + RESERVED_DISK_MB > free:
        raise Fail("E_DISK_SPACE", "not enough disk space: %d MB needed, %d MB free" % (disk + RESERVED_DISK_MB, free),
                   {"resource": "disk", "needed_mb": int(disk + RESERVED_DISK_MB), "available_mb": free})
    for m in planned:
        sysctl_of(m)


def sysctl_of(m):
    req = (m.get("needs") or {}).get("sysctl") or {}
    if not isinstance(req, dict):
        raise Fail("E_RESOURCES", "%s: invalid sysctl requirement" % m["id"])
    out = {}
    for k, v in req.items():
        if k not in SYSCTL_ALLOWED:
            raise Fail("E_RESOURCES", "%s: kernel setting %s is not allowed" % (m["id"], k))
        lo, hi = SYSCTL_ALLOWED[k]
        if not isinstance(v, int) or isinstance(v, bool) or not lo <= v <= hi:
            raise Fail("E_RESOURCES", "%s: kernel setting %s out of range" % (m["id"], k))
        out[k] = v
    return out


def check_license(m, accepted):
    r = m["license"]["restrictions"]
    return r == "none" or m["id"] in accepted


# --------------------------------------------------------------------------
# Actions système
# --------------------------------------------------------------------------

def systemctl(*args, timeout=300, check=True):
    r = common.run("systemctl", list(args), timeout=timeout)
    if check and r.returncode != 0:
        raise Fail("E_INTERNAL", "systemctl %s failed" % args[0])
    return r.returncode


def podman(*args, timeout=900):
    return common.run("podman", list(args), timeout=timeout, stdout_limit=1 << 20).returncode


def pull(m, timeout):
    if podman("pull", "--quiet", m["image"], timeout=timeout) != 0:
        raise Fail("E_NETWORK", "cannot pull the image of %s" % m["id"])


def remove_image(reg, image):
    if not image:
        return
    if any(e["manifest"].get("image") == image for e in reg["modules"].values()):
        return
    podman("rmi", "--ignore", image, timeout=300)


def apply_sysctl(reg, extra=()):
    want = {}
    for m in [e["manifest"] for e in reg["modules"].values()] + list(extra):
        for k, v in sysctl_of(m).items():
            want[k] = max(v, want.get(k, 0))
    if not want:
        if os.path.exists(SYSCTL_FILE):
            os.unlink(SYSCTL_FILE)
        return
    os.makedirs(os.path.dirname(SYSCTL_FILE), mode=0o755, exist_ok=True)
    text = "# Généré par scanoria-helper (réglages exigés par les modules installés).\n"
    text += "".join("%s = %d\n" % (k, want[k]) for k in sorted(want))
    common.atomic_write(SYSCTL_FILE, text, 0o644, group_scanoria=False)
    if common.run("sysctl", ["-q", "-p", "/etc/sysctl.d/60-scanoria-modules.conf"], timeout=60).returncode != 0:
        raise Fail("E_RESOURCES", "kernel settings could not be applied")


def db_name(mid):
    return "scanoria_mod_" + mid.replace("-", "_")


def _psql(sql, timeout=300):
    r = common.run("runuser", ["-u", "postgres", "--", "/usr/bin/psql", "-X", "-q", "-v", "ON_ERROR_STOP=1",
                               "-d", "postgres"], input=sql.encode(), timeout=timeout)
    if r.returncode != 0:
        raise Fail("E_INTERNAL", "PostgreSQL command failed")


def db_file(mid):
    return os.path.join(quadlet.MODULE_ETC, mid, "db.json")


def ensure_database(mid):
    """Crée (ou reprend, si ses données ont été gardées) la base du module. Retourne (identifiants, créée)."""
    name = db_name(mid)
    try:
        cred = common.load_json_file(db_file(mid), 4096)
        existed = isinstance(cred, dict) and re.fullmatch(r"[0-9a-f]{48}", str(cred.get("password", ""))) is not None
    except (OSError, common.JsonError):
        existed = False
    if not existed:
        cred = {"name": name, "user": name, "password": secrets.token_hex(24)}
    pw = cred["password"]
    _psql("DO $$BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '%s') THEN "
          "CREATE ROLE \"%s\" LOGIN PASSWORD '%s'; ELSE ALTER ROLE \"%s\" LOGIN PASSWORD '%s'; END IF; END$$;\n"
          "SELECT 'CREATE DATABASE \"%s\" OWNER \"%s\"' WHERE NOT EXISTS "
          "(SELECT FROM pg_database WHERE datname = '%s')\\gexec\n" % (name, name, pw, name, pw, name, name, name))
    os.makedirs(os.path.dirname(db_file(mid)), mode=0o700, exist_ok=True)
    common.write_json(db_file(mid), {"name": name, "user": name, "password": pw}, 0o600, group_scanoria=False)
    return cred, not existed


def drop_database(mid):
    name = db_name(mid)
    _psql('DROP DATABASE IF EXISTS "%s" WITH (FORCE);\nDROP ROLE IF EXISTS "%s";\n' % (name, name))


def remove_data(m):
    mid = m["id"]
    if (m.get("needs") or {}).get("postgres"):
        drop_database(mid)
    for name, _ in quadlet.volumes(m):
        podman("volume", "rm", "--force", quadlet.volume_name(mid, name), timeout=300)
    shutil.rmtree(os.path.join(quadlet.MODULE_ETC, mid), ignore_errors=True)
    if m["type"] == "feed":
        shutil.rmtree(os.path.join(testbed.FEEDS, mid), ignore_errors=True)


def env_values(m, cred, host_port, options):
    vals = {"host_port": host_port, "hostname": m.get("hostname") or ""}
    if cred:
        vals.update(db_host="host.containers.internal", db_port=5432, db_name=cred["name"],
                    db_user=cred["user"], db_password=cred["password"],
                    db_url_jdbc="jdbc:postgresql://host.containers.internal:5432/" + cred["name"])
    for k, v in options.items():
        if isinstance(v, (str, int, float)) and not isinstance(v, bool):
            vals["opt." + k] = v
        elif isinstance(v, bool):
            vals["opt." + k] = "true" if v else "false"
    return vals


def wait_http(port, path, timeout):
    if not isinstance(path, str) or not HEALTH_PATH_RE.match(path):
        raise Fail("E_INVALID_PARAM", "invalid health path")
    end = time.monotonic() + timeout
    while True:
        r = common.run("curl", ["--proto", "=http", "--silent", "--max-time", "5", "--output", "/dev/null",
                                "--write-out", "%{http_code}", "http://127.0.0.1:%d%s" % (port, path)], timeout=30)
        code = r.text.strip()
        if r.returncode == 0 and (code == "" and common.TEST_ROOT or re.fullmatch(r"[23][0-9]{2}", code)):
            return
        if time.monotonic() > end:
            raise Fail("E_HEALTH_ROLLED_BACK", "service did not become healthy")
        time.sleep(0.2 if common.TEST_ROOT else 3)


def scanner_health(m, timeout):
    cmd = (m.get("health") or {}).get("command")
    if cmd:
        rc = testbed.run_confined(m, cmd, timeout=min(timeout, SCANNER_HEALTH_TIMEOUT))
        if rc != 0:
            raise Fail("E_HEALTH_ROLLED_BACK", "health command of %s failed (exit %d)" % (m["id"], rc))


def alloc_port(reg):
    import socket
    used = {e.get("host_port") for e in reg["modules"].values()}
    for p in HOST_PORTS:
        if p in used:
            continue
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as so:
            try:
                so.bind(("127.0.0.1", p))
            except OSError:
                continue  # port déjà pris par un autre processus
        return p
    raise Fail("E_RESOURCES", "no free internal port")


def route(reg):
    """Régénère l'aiguillage par nom (chantier routage) ; journalise son absence."""
    services = [{"id": k, "hostname": e["manifest"].get("hostname"), "port": e.get("host_port"),
                 "enabled": bool(e["enabled"] and e["status"] == "healthy")}
                for k, e in sorted(reg["modules"].items()) if e["manifest"]["type"] == "service"]
    try:
        from . import routing
    except ImportError:
        common.log("routing module not available: name-based routing not applied")
        return
    res = routing.apply(None, services) or []
    by_id = {r["id"]: r for r in res if isinstance(r, dict) and isinstance(r.get("id"), str)}
    for k, e in reg["modules"].items():
        if e["manifest"]["type"] == "service":
            r = by_id.get(k)
            e["route"] = {"hostname": r.get("hostname"), "url": r.get("url")} if r else None


def start_service(m, entry, timeout):
    """Unités écrites, systemd rechargé, service démarré et sain."""
    mid = m["id"]
    systemctl("daemon-reload")
    systemctl("start", quadlet.unit_name(mid), timeout=min(timeout, 900))
    if systemctl("is-active", "--quiet", quadlet.unit_name(mid), check=False) != 0:
        raise Fail("E_HEALTH_ROLLED_BACK", "unit of %s is not active" % mid)
    if m["type"] == "service":
        svc = m.get("service") or {}
        wait_http(entry["host_port"], svc.get("health_path") or "/", min(timeout, HEALTH_TIMEOUT))


def write_units(m, entry, options, cred):
    has_env = False
    tpl = (m.get("service") or {}).get("env")
    if tpl:
        quadlet.write_env(m["id"], quadlet.render_env(tpl, env_values(m, cred, entry["host_port"], options)))
        has_env = True
    quadlet.write(m["id"], quadlet.render(m, entry["host_port"], entry["enabled"], has_env))


def stop_service(mid):
    systemctl("stop", quadlet.unit_name(mid), check=False)


# --------------------------------------------------------------------------
# install-modules
# --------------------------------------------------------------------------

def plan_install(reg, mods, wanted, accepted):
    plan, given = {}, {}
    order = []
    skipped = []

    def add(mid, version, chain):
        if mid in chain:
            raise Fail("E_DEPENDENCY", "dependency cycle: %s" % " -> ".join(chain + [mid]))
        if mid in reg["modules"]:
            if version is not None and reg["modules"][mid]["manifest"]["version"] != version:
                raise Fail("E_PRECONDITION", "%s is already installed in another version: use update-module" % mid)
            if mid not in skipped:
                skipped.append(mid)
            return
        if mid in plan:
            if version is not None and plan[mid]["version"] != version:
                raise Fail("E_DEPENDENCY", "two versions of %s requested" % mid)
            return
        m = lookup(mods, mid, version)
        for d in requires_of(m):
            add(d, None, chain + [mid])
        plan[mid] = m
        order.append(mid)

    for w in wanted:
        given[w["id"]] = w["options"]
        add(w["id"], w["version"], [])
    planned = [plan[k] for k in order]
    installed = [e["manifest"] for e in reg["modules"].values()]
    ids = set(reg["modules"]) | set(plan)
    for m in planned:
        for c in conflicts_of(m):
            if c in ids:
                raise Fail("E_CONFLICT", "%s conflicts with %s" % (m["id"], c), {"module": m["id"], "conflicts_with": c})
        if not appliance_ok((m.get("requires") or {}).get("appliance")):
            raise Fail("E_DEPENDENCY", "%s requires appliance %s" % (m["id"], m["requires"]["appliance"]))
        for d in requires_of(m):
            de = reg["modules"].get(d)
            if de is not None and not de["enabled"]:
                raise Fail("E_DEPENDENCY", "%s requires %s, which is disabled" % (m["id"], d))
    for m in installed:
        for c in conflicts_of(m):
            if c in plan:
                raise Fail("E_CONFLICT", "%s conflicts with installed %s" % (c, m["id"]),
                           {"module": c, "conflicts_with": m["id"]})
    missing = [m for m in planned if not check_license(m, accepted)]
    if missing:
        raise Fail("E_LICENSE", "license acceptance required: %s" % ", ".join(m["id"] for m in missing),
                   {"licenses": [{"id": m["id"], "spdx": m["license"].get("spdx"),
                                  "restrictions": m["license"]["restrictions"],
                                  "url": m["license"].get("url")} for m in missing]})
    options = {m["id"]: resolve_options(m, given.get(m["id"], {})) for m in planned}
    check_resources(installed, planned)
    return planned, options, skipped


def install_one(c, reg, op, m, options, frac):
    """Installe un module ; laisse dans reg une entrée « installing » tant qu'il n'est pas sain."""
    mid = m["id"]
    entry = {"manifest": m, "status": "installing", "enabled": True, "installed_at": common.iso(common.now()),
             "options": options, "testbed": None, "route": None, "last_error": None,
             "accepted": m["license"]["restrictions"], "host_port": None, "created_db": False}
    reg["modules"][mid] = entry
    if m["type"] == "feed" and not m.get("image"):
        # Feed déclaratif (0.2) : sa base est posée sous /var/lib/scanoria/feeds/<id>.
        os.makedirs(os.path.join(testbed.FEEDS, mid), mode=0o755, exist_ok=True)
        entry.update(status="healthy", testbed=testbed.run(m))
        save_registry(reg)
        return
    op.step("pull", frac(0.05), mid)
    pull(m, c.left())
    if m["type"] in ("service", "runner"):
        cred = None
        if (m.get("needs") or {}).get("postgres"):
            op.step("database", frac(0.3), mid)
            cred, entry["created_db"] = ensure_database(mid)
        op.step("sysctl", frac(0.35), mid)
        apply_sysctl(reg)
        entry["host_port"] = alloc_port(reg) if m["type"] == "service" else None
        op.step("units", frac(0.4), mid)
        write_units(m, entry, options, cred)
        op.step("health", frac(0.5), mid)
        start_service(m, entry, c.left())
    else:
        op.step("health", frac(0.4), mid)
        scanner_health(m, c.left())
    entry["status"] = "testing"
    op.step("testbed", frac(0.7), mid)
    entry["testbed"] = testbed.run(m, timeout=c.left())
    entry["status"] = "healthy"
    save_registry(reg)


def undo_install(reg, mid):
    """Retour arrière d'une installation (même partielle) de cette opération."""
    e = reg["modules"].get(mid)
    if e is None:
        return
    m = e["manifest"]
    if m["type"] in ("service", "runner"):
        stop_service(mid)
        quadlet.remove(mid)
        systemctl("daemon-reload", check=False)
    if e.get("created_db"):
        drop_database(mid)
        shutil.rmtree(os.path.join(quadlet.MODULE_ETC, mid), ignore_errors=True)
    elif os.path.exists(os.path.join(quadlet.MODULE_ETC, mid, "env")):
        os.unlink(os.path.join(quadlet.MODULE_ETC, mid, "env"))
    if m["type"] == "feed":
        shutil.rmtree(os.path.join(testbed.FEEDS, mid), ignore_errors=True)
    del reg["modules"][mid]
    remove_image(reg, m.get("image"))
    apply_sysctl(reg)


def act_install_modules(c):
    reg = load_registry()
    wanted = c.params["modules"]
    if len({w["id"] for w in wanted}) != len(wanted):
        raise Fail("E_INVALID_PARAM", "duplicate module id")
    accepted = set(c.params["accept_licenses"])
    mods = catalog()
    planned, options, skipped = plan_install(reg, mods, wanted, accepted)
    if not planned:
        return {"installed": [], "skipped": skipped}
    op = Op(reg, "install", planned[0]["id"], c.req["id"])
    done = []
    try:
        for i, m in enumerate(planned):
            n = len(planned)
            done.append(m["id"])
            install_one(c, reg, op, m, options[m["id"]], lambda f, i=i: 100.0 * (i + f) / n)
        if any(m["type"] == "service" for m in planned):
            op.step("route", 95)
            route(reg)
    except Exception as e:
        err = e if isinstance(e, Fail) else Fail("E_INTERNAL", "internal error")
        if not isinstance(e, Fail):
            common.log("install-modules: %r" % e)
        op.step("rollback", op.rec["progress"])
        rb_ok = rollback_installs(reg, done)
        op.finish(False, err.message)
        if not rb_ok:
            raise Fail("E_ROLLBACK_FAILED", "%s; rollback incomplete" % err.message)
        raise err
    op.finish(True, "installed: %s" % ", ".join(done))
    return {"installed": [{"id": m["id"], "version": m["version"]} for m in planned], "skipped": skipped,
            "operation": op.rec["id"]}


def rollback_installs(reg, done):
    ok = True
    for mid in reversed(done):
        try:
            undo_install(reg, mid)
        except Exception as e:  # noqa: BLE001 — le retour arrière continue malgré tout
            common.log("rollback of %s failed: %r" % (mid, e))
            ok = False
            if mid in reg["modules"]:
                reg["modules"][mid].update(status="failed", enabled=False, last_error="rollback failed")
    try:
        if any(reg["modules"].get(k) is None for k in done):
            route(reg)
    except Exception as e:  # noqa: BLE001
        common.log("routing after rollback failed: %r" % e)
        ok = False
    save_registry(reg)
    return ok


# --------------------------------------------------------------------------
# uninstall-module
# --------------------------------------------------------------------------

def as_fail(exc, what):
    """Toute exception devient un Fail (journalisée si imprévue) : l'opération est toujours close."""
    if isinstance(exc, Fail):
        return exc
    common.log("%s: %r" % (what, exc))
    return Fail("E_INTERNAL", "internal error")


def get_entry(reg, mid):
    e = reg["modules"].get(mid)
    if e is None:
        raise Fail("E_NOT_FOUND", "module %s is not installed" % mid)
    return e


def act_uninstall_module(c):
    reg = load_registry()
    mid, keep = c.params["id"], c.params["keep_data"]
    e = get_entry(reg, mid)
    deps = dependents(reg, mid)
    if deps:
        raise Fail("E_DEPENDENCY", "%s is required by %s" % (mid, ", ".join(deps)), {"required_by": deps})
    m = e["manifest"]
    op = Op(reg, "uninstall", mid, c.req["id"])
    try:
        e["status"] = "removing"
        if m["type"] in ("service", "runner"):
            op.step("units", 20)
            stop_service(mid)
            quadlet.remove(mid)
            systemctl("daemon-reload")
        if not keep:
            op.step("data", 50)
            remove_data(m)
        elif os.path.exists(os.path.join(quadlet.MODULE_ETC, mid, "env")):
            os.unlink(os.path.join(quadlet.MODULE_ETC, mid, "env"))
        del reg["modules"][mid]
        op.step("image", 70)
        remove_image(reg, m.get("image"))
        apply_sysctl(reg)
        if m["type"] == "service":
            op.step("route", 90)
            route(reg)
    except Exception as exc:  # noqa: BLE001 — l'opération est close dans tous les cas
        err = as_fail(exc, "uninstall-module")
        if mid in reg["modules"]:
            reg["modules"][mid].update(status="failed", enabled=False, last_error=err.message)
        op.finish(False, err.message)
        raise err
    op.finish(True, "removed")
    return {"id": mid, "version": m["version"], "data_kept": keep}


# --------------------------------------------------------------------------
# set-module-state
# --------------------------------------------------------------------------

def act_set_module_state(c):
    reg = load_registry()
    mid, enabled = c.params["id"], c.params["enabled"]
    e = get_entry(reg, mid)
    if e["status"] not in ("healthy", "disabled"):
        raise Fail("E_PRECONDITION", "module %s is %s" % (mid, e["status"]))
    if e["enabled"] == enabled:
        return {"id": mid, "enabled": enabled, "changed": False}
    m = e["manifest"]
    if not enabled:
        deps = dependents(reg, mid, only_enabled=True)
        if deps:
            raise Fail("E_DEPENDENCY", "%s is required by enabled modules: %s" % (mid, ", ".join(deps)),
                       {"required_by": deps})
    else:
        off = [d for d in requires_of(m) if d in reg["modules"] and not reg["modules"][d]["enabled"]]
        if off:
            raise Fail("E_DEPENDENCY", "%s requires disabled modules: %s" % (mid, ", ".join(off)), {"requires": off})
    op = Op(reg, "enable" if enabled else "disable", mid, c.req["id"])
    snap = quadlet.snapshot(mid)
    try:
        e["enabled"] = enabled
        if m["type"] in ("service", "runner"):
            op.step("units", 30)
            cred = _cred(mid) if (m.get("needs") or {}).get("postgres") else None
            write_units(m, e, e["options"], cred)
            if enabled:
                op.step("health", 50)
                start_service(m, e, c.left())
            else:
                stop_service(mid)
                systemctl("daemon-reload")
        e["status"] = "healthy" if enabled else "disabled"
        e["last_error"] = None
        if m["type"] == "service":
            op.step("route", 90)
            route(reg)
    except Exception as exc:  # noqa: BLE001
        err = as_fail(exc, "set-module-state")
        e["enabled"] = not enabled
        e["status"] = "healthy" if not enabled else "disabled"
        e["last_error"] = err.message
        if m["type"] in ("service", "runner"):
            if enabled:
                stop_service(mid)
            quadlet.restore(mid, snap)
            systemctl("daemon-reload", check=False)
        op.finish(False, err.message)
        raise err
    op.finish(True, "enabled" if enabled else "disabled")
    return {"id": mid, "enabled": enabled, "changed": True}


def _cred(mid):
    try:
        cred = common.load_json_file(db_file(mid), 4096)
    except (OSError, common.JsonError):
        raise Fail("E_PRECONDITION", "database credentials of %s missing" % mid)
    return cred


# --------------------------------------------------------------------------
# update-module
# --------------------------------------------------------------------------

def backup(m):
    """Sauvegarde de la base et des volumes avant mise à jour ; retourne le répertoire."""
    mid = m["id"]
    d = os.path.join(BACKUPS, "%s-%s-%s" % (mid, m["version"], common.now().strftime("%Y%m%dT%H%M%SZ")))
    os.makedirs(d, mode=0o700)
    if (m.get("needs") or {}).get("postgres"):
        if run_to_file("runuser", ["-u", "postgres", "--", "/usr/bin/pg_dump", "-Fc", db_name(mid)],
                       os.path.join(d, "db.dump"), timeout=1800) != 0:
            raise Fail("E_INTERNAL", "database backup failed")
    for name, _ in quadlet.volumes(m):
        if podman("volume", "export", "--output", os.path.join(d, "volume-%s.tar" % name),
                  quadlet.volume_name(mid, name), timeout=1800) != 0:
            raise Fail("E_INTERNAL", "volume backup failed")
    prune_backups(mid)
    return d


def run_to_file(name, args, dest, timeout):
    """Comme common.run, mais la sortie va dans dest (0600) au lieu de la mémoire."""
    import subprocess
    exe = common.resolve(name)
    if exe is None:
        common.run(name, args, timeout=timeout)  # bouchon du mode test : journalisé
        common.atomic_write(dest, b"", 0o600, group_scanoria=False)
        return 0
    fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as out:
        try:
            p = subprocess.run([exe] + list(args), stdin=subprocess.DEVNULL, stdout=out, env=common.child_env(),
                               timeout=timeout, cwd="/", close_fds=True, check=False)
        except subprocess.TimeoutExpired:
            raise Fail("E_TIMEOUT", "%s timed out" % name)
        out.flush()
        os.fsync(out.fileno())
    return p.returncode


def prune_backups(mid):
    try:
        names = sorted(n for n in os.listdir(BACKUPS) if n.startswith(mid + "-"))
    except FileNotFoundError:
        return
    olds = [n for n in names if re.fullmatch(re.escape(mid) + r"-.+-[0-9]{8}T[0-9]{6}Z", n)]
    olds.sort(key=lambda n: n[-16:])
    for n in olds[:-KEEP_BACKUPS]:
        shutil.rmtree(os.path.join(BACKUPS, n), ignore_errors=True)


def restore(m, d):
    mid = m["id"]
    dump = os.path.join(d, "db.dump")
    if os.path.exists(dump):
        r = common.run("runuser", ["-u", "postgres", "--", "/usr/bin/pg_restore", "--clean", "--if-exists",
                                   "-d", db_name(mid), dump], timeout=1800)
        if r.returncode != 0:
            raise Fail("E_ROLLBACK_FAILED", "database restore failed")
    for name, _ in quadlet.volumes(m):
        f = os.path.join(d, "volume-%s.tar" % name)
        if os.path.exists(f) and podman("volume", "import", quadlet.volume_name(mid, name), f,
                                        timeout=1800) != 0:
            raise Fail("E_ROLLBACK_FAILED", "volume restore failed")


def act_update_module(c):
    reg = load_registry()
    mid, version = c.params["id"], c.params["version"]
    e = get_entry(reg, mid)
    if e["status"] not in ("healthy", "disabled"):
        raise Fail("E_PRECONDITION", "module %s is %s" % (mid, e["status"]))
    old = e["manifest"]
    new = lookup(catalog(), mid, version)
    if vkey(new["version"]) <= vkey(old["version"]):
        raise Fail("E_VERSION", "%s %s is not newer than the installed %s" % (mid, version, old["version"]))
    if new["type"] != old["type"]:
        raise Fail("E_PRECONDITION", "module type changed: reinstall the module")
    r = new["license"]["restrictions"]
    if r != "none" and r != e.get("accepted"):
        raise Fail("E_LICENSE", "the license restrictions of %s changed: reinstall to accept them" % mid,
                   {"licenses": [{"id": mid, "spdx": new["license"].get("spdx"), "restrictions": r,
                                  "url": new["license"].get("url")}]})
    for d in requires_of(new):
        if d not in reg["modules"]:
            raise Fail("E_DEPENDENCY", "%s %s requires %s: install it first" % (mid, version, d), {"requires": [d]})
    for c2 in conflicts_of(new):
        if c2 in reg["modules"]:
            raise Fail("E_CONFLICT", "%s %s conflicts with %s" % (mid, version, c2), {"conflicts_with": c2})
    for k, other in reg["modules"].items():
        if k != mid and mid in conflicts_of(other["manifest"]):
            raise Fail("E_CONFLICT", "%s conflicts with installed %s" % (mid, k), {"conflicts_with": k})
    if not appliance_ok((new.get("requires") or {}).get("appliance")):
        raise Fail("E_DEPENDENCY", "%s %s requires appliance %s" % (mid, version, new["requires"]["appliance"]))
    props = (new.get("options") or {}).get("properties") or {}
    options = resolve_options(new, {k: v for k, v in e["options"].items() if k in props})
    check_resources([x["manifest"] for x in reg["modules"].values()], [new], freed=[old])

    op = Op(reg, "update", mid, c.req["id"])
    is_svc = old["type"] in ("service", "runner")
    snap = quadlet.snapshot(mid) if is_svc else {}
    bdir = None
    try:
        if is_svc:
            op.step("backup", 10)
            bdir = backup(old)
        declarative = new["type"] == "feed" and not new.get("image")
        if not declarative:
            op.step("pull", 25)
            pull(new, c.left())
        if declarative:
            pass
        elif is_svc:
            op.step("units", 40)
            stop_service(mid)
            cred = _cred(mid) if (new.get("needs") or {}).get("postgres") else None
            apply_sysctl(reg, [new])
            write_units(new, e, options, cred)
            op.step("health", 55)
            start_service(new, e, c.left())
            if not e["enabled"]:
                stop_service(mid)
        else:
            op.step("health", 50)
            scanner_health(new, c.left())
        op.step("testbed", 75)
        tb = testbed.run(new, timeout=c.left())
    except Exception as exc:  # noqa: BLE001
        err = as_fail(exc, "update-module")
        op.step("rollback", op.rec["progress"])
        try:
            if is_svc:
                stop_service(mid)
                if bdir:
                    restore(old, bdir)
                quadlet.restore(mid, snap)
                systemctl("daemon-reload")
                apply_sysctl(reg)
                if e["enabled"]:
                    start_service(old, e, max(60, c.left()))
            remove_image(reg, new.get("image"))
        except Exception as rb:  # noqa: BLE001
            common.log("update rollback of %s failed: %r" % (mid, rb))
            e.update(status="failed", enabled=False,
                     last_error=("update failed and rollback failed: " + err.message)[:2000])
            op.finish(False, err.message)
            raise Fail("E_ROLLBACK_FAILED", "update failed (%s) and rollback failed" % err.message)
        e["last_error"] = ("update to %s failed: %s" % (version, err.message))[:2000]
        op.finish(False, err.message)
        save_registry(reg)
        # Le code d'origine est gardé ; une erreur interne devient « retour arrière fait ».
        code = "E_HEALTH_ROLLED_BACK" if err.code == "E_INTERNAL" else err.code
        raise Fail(code, "update of %s to %s failed, previous version kept: %s" % (mid, version, err.message), err.output)
    e.update(manifest=new, options=options, testbed=tb, last_error=None)
    remove_image(reg, old.get("image"))
    apply_sysctl(reg)
    if old["type"] == "service":
        op.step("route", 90)
        route(reg)
    op.finish(True, "updated to %s" % version)
    return {"id": mid, "previous": old["version"], "version": new["version"], "backup": bool(bdir)}


# --------------------------------------------------------------------------
# refresh-catalog
# --------------------------------------------------------------------------

def act_refresh_catalog(c):
    out = catalogverify.refresh()
    try:
        reg = load_registry()
        mods = catalogverify.installed_index().get("modules") or []
        ups = []
        for mid, e in sorted(reg["modules"].items()):
            cands = [m["version"] for m in mods if m.get("id") == mid
                     and isinstance(m.get("version"), str) and vkey(m["version"]) > vkey(e["manifest"]["version"])]
            if cands:
                ups.append({"id": mid, "installed": e["manifest"]["version"], "available": max(cands, key=vkey)})
        out["updates"] = ups
    except Fail:
        out["updates"] = []
    return out
