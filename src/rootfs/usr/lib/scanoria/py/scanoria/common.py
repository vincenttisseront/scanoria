# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Vincent Tisseront
"""Fonctions communes : chemins, JSON strict, écriture atomique, sous-processus.

Mode test (tests sans root) : SCANORIA_TEST_ROOT=<répertoire absolu> préfixe
tous les chemins de l'appliance ; les commandes système non sûres sont
remplacées par des bouchons (journal dans <racine>/test-commands.log), sauf
celles fournies dans SCANORIA_TEST_BIN. Seul root peut fixer l'environnement
des services : ce mode n'ouvre aucun accès à la console.
"""

import datetime
import json
import os
import re
import signal
import stat
import subprocess
import sys
import tempfile

# --------------------------------------------------------------------------
# Racines
# --------------------------------------------------------------------------

TEST_ROOT = os.environ.get("SCANORIA_TEST_ROOT", "")
if TEST_ROOT:
    if not os.path.isabs(TEST_ROOT) or not os.path.isdir(TEST_ROOT):
        sys.stderr.write("scanoria: SCANORIA_TEST_ROOT must be an existing absolute directory\n")
        sys.exit(2)
    TEST_ROOT = os.path.realpath(TEST_ROOT)
TEST_BIN = os.environ.get("SCANORIA_TEST_BIN", "") if TEST_ROOT else ""

# .../usr/lib/scanoria/py/scanoria/common.py -> .../usr/lib/scanoria
LIB_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SBIN_DIR = os.path.normpath(os.path.join(LIB_DIR, "..", "..", "sbin"))
SHARE_DIR = os.path.normpath(os.path.join(LIB_DIR, "..", "..", "share", "scanoria"))


def p(path):
    """Chemin sur l'appliance (préfixé en mode test)."""
    return TEST_ROOT + path if TEST_ROOT else path


ETC = p("/etc/scanoria")
VARLIB = p("/var/lib/scanoria")
REQ = VARLIB + "/requests"
RUN = p("/run/scanoria")
OPT = p("/opt/scanoria")
PUBKEY = ETC + "/update-pubkey.pem"
STATE_FILE = RUN + "/state.json"
CURRENT_FILE = RUN + "/helper-current.json"
UPDATE_CHECK_FILE = VARLIB + "/updates/check.json"
UPDATE_ALERT_FILE = VARLIB + "/updates/alert.json"
UPDATE_SKIP_FILE = VARLIB + "/updates/skip-version.json"
SELFTEST_LAST = VARLIB + "/selftest/last.json"

SEMVER_RE = re.compile(r"(0|[1-9][0-9]{0,3})\.(0|[1-9][0-9]{0,3})\.(0|[1-9][0-9]{0,3})\Z")
UUID4_RE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\Z")
FQDN_RE = re.compile(r"([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]([a-z0-9-]{0,61}[a-z0-9])?\Z")

REQUEST_TYPES = (
    "set-hostname", "set-admin-networks", "issue-certificate", "import-certificate",
    "check-update", "apply-update", "rollback-update", "set-update-policy", "run-selftest",
    "check-dns",
    "refresh-catalog", "install-modules", "uninstall-module", "set-module-state", "update-module",
    "set-ai-endpoint", "refresh-feeds",
    "backup-module", "restore-module",
    "reset-service-admin",
    "package-dates",
    "export-bundle", "import-bundle", "set-mirror", "trust-key",
)
REJECT_CODES = frozenset((
    "E_INVALID_NAME", "E_NOT_REGULAR_FILE", "E_BAD_OWNER", "E_TOO_LARGE", "E_INVALID_JSON",
    "E_UNKNOWN_TYPE", "E_SCHEMA", "E_ID_MISMATCH", "E_DUPLICATE_ID", "E_STALE", "E_INVALID_PARAM",
))
ERROR_CODES = frozenset((
    "E_PRECONDITION", "E_LOCKOUT", "E_NETWORK", "E_NOT_FOUND", "E_SIGNATURE", "E_CHECKSUM",
    "E_ARCHIVE", "E_VERSION", "E_DISK_SPACE", "E_CERT_INVALID", "E_CERT_NAMES",
    "E_CERT_KEY_MISMATCH", "E_CERT_EXPIRED", "E_NO_PREVIOUS", "E_HEALTH_ROLLED_BACK",
    "E_ROLLBACK_FAILED", "E_TIMEOUT", "E_INTERNAL",
    "E_RESOURCES", "E_DEPENDENCY", "E_CONFLICT", "E_LICENSE", "E_TESTBED",
    "E_AI_URL", "E_AI_UNRESOLVED", "E_AI_FORBIDDEN_ADDRESS", "E_AI_CA",
    "E_FEED_UNAVAILABLE",
    "E_SERVICE_RESOURCES", "E_BACKUP_FAILED", "E_BACKUP_NOT_FOUND", "E_BACKUP_INVALID",
    "E_SONAR_UNAVAILABLE", "E_SONAR_ADMIN", "E_SONAR_API",
    "E_DTRACK_UNAVAILABLE", "E_DTRACK_ADMIN", "E_DTRACK_API",
    "E_EXPORT_FAILED",
    "E_BUNDLE_INVALID", "E_BUNDLE_SIGNATURE", "E_BUNDLE_UNTRUSTED", "E_BUNDLE_CHECKSUM",
    "E_BUNDLE_ARCHIVE", "E_BUNDLE_IMAGE", "E_BUNDLE_FEED", "E_BUNDLE_SOURCE",
    "E_MIRROR_URL", "E_MIRROR_UNRESOLVED", "E_MIRROR_FORBIDDEN_ADDRESS", "E_MIRROR_CA",
    "E_MIRROR_UNTRUSTED", "E_MIRROR_UNREACHABLE",
    "E_KEY_INVALID",
))
ALL_CODES = frozenset(("OK",)) | REJECT_CODES | ERROR_CODES


class Fail(Exception):
    """Échec avec un code de la liste fermée (ARCHITECTURE § 5.5)."""

    def __init__(self, code, message, output=None):
        super().__init__(message)
        self.code = code if code in ALL_CODES else "E_INTERNAL"
        self.message = str(message)[:2000]
        self.output = output or {}


def log(msg):
    sys.stderr.write("scanoria: %s\n" % msg)
    sys.stderr.flush()


# --------------------------------------------------------------------------
# Temps et versions
# --------------------------------------------------------------------------

def now():
    return datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)


def iso(dt):
    return dt.astimezone(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_iso(s):
    m = re.fullmatch(r"(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d{1,6})?Z", s)
    if not m:
        raise ValueError("bad timestamp")
    return datetime.datetime(*map(int, m.groups()), tzinfo=datetime.timezone.utc)


def parse_version(v):
    if not isinstance(v, str) or not SEMVER_RE.match(v):
        raise ValueError("bad version")
    return tuple(int(x) for x in v.split("."))


def read_text(path, limit=4096):
    try:
        with open(path, "rb") as f:
            return f.read(limit).decode("utf-8", "strict").strip()
    except (OSError, UnicodeDecodeError):
        return None


def installed_version(link="current"):
    v = read_text(OPT + "/" + link + "/VERSION", 64)
    return v if v and SEMVER_RE.match(v) else None


# --------------------------------------------------------------------------
# JSON strict
# --------------------------------------------------------------------------

class JsonError(ValueError):
    pass


def _no_dup(pairs):
    d = {}
    for k, v in pairs:
        if k in d:
            raise JsonError("duplicate key")
        d[k] = v
    return d


def _bad_const(name):
    raise JsonError("invalid constant " + name)


def _check_strings(obj):
    stack = [obj]
    while stack:
        o = stack.pop()
        if isinstance(o, str):
            o.encode("utf-8")  # refuse les demi-paires de substitution
        elif isinstance(o, dict):
            for k, v in o.items():
                k.encode("utf-8")
                stack.append(v)
        elif isinstance(o, list):
            stack.extend(o)


MAX_JSON_DEPTH = 32


def _check_depth(text, limit=MAX_JSON_DEPTH):
    """Refuse une imbrication > limit avant l'analyse (parcours linéaire,
    indépendant de la limite de récursion de la version de Python)."""
    depth = 0
    in_str = False
    esc = False
    for ch in text:
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
        elif ch == '"':
            in_str = True
        elif ch in "[{":
            depth += 1
            if depth > limit:
                raise JsonError("nesting too deep")
        elif ch in "]}":
            depth -= 1


def loads_strict(data):
    """JSON UTF-8 sans BOM, sans clé dupliquée, sans NaN/Infinity,
    imbrication limitée à MAX_JSON_DEPTH."""
    if isinstance(data, bytes):
        if data.startswith(b"\xef\xbb\xbf"):
            raise JsonError("BOM")
        try:
            data = data.decode("utf-8", "strict")
        except UnicodeDecodeError as e:
            raise JsonError("not UTF-8") from e
    _check_depth(data)
    try:
        obj = json.loads(data, object_pairs_hook=_no_dup, parse_constant=_bad_const)
        _check_strings(obj)
    except (ValueError, RecursionError, UnicodeEncodeError) as e:
        raise JsonError(str(e)[:200]) from e
    return obj


def load_json_file(path, limit):
    with open(path, "rb") as f:
        data = f.read(limit + 1)
    if len(data) > limit:
        raise JsonError("file too large")
    return loads_strict(data)


def dumps(obj):
    return json.dumps(obj, ensure_ascii=False, indent=2) + "\n"


# --------------------------------------------------------------------------
# Comptes et écriture atomique
# --------------------------------------------------------------------------

def scanoria_ids():
    """(uid, gid) du compte scanoria (mode test : SCANORIA_TEST_OWNER_UID ou l'appelant)."""
    if TEST_ROOT:
        uid = os.environ.get("SCANORIA_TEST_OWNER_UID", "")
        return (int(uid) if uid.isdigit() else os.getuid(), os.getgid())
    import pwd
    pw = pwd.getpwnam("scanoria")
    return (pw.pw_uid, pw.pw_gid)


def web_gid():
    """Groupe de nginx (www-data) : les fichiers servis lui sont réservés (0640/0750)."""
    if TEST_ROOT:
        return os.getgid()
    import grp
    return grp.getgrnam("www-data").gr_gid


def web_readable(path, directory=False):
    """root:www-data, 0750 pour un répertoire, 0640 pour un fichier ; jamais un lien."""
    if os.path.islink(path):
        raise Fail("E_INTERNAL", "refusing a symbolic link: %s" % path)
    os.chmod(path, 0o750 if directory else 0o640)
    if not TEST_ROOT:
        os.chown(path, 0, web_gid())


def shared_dir(path):
    """Crée ou rétablit un répertoire d'état lu par la console : root:scanoria 0750.

    Un simple os.makedirs sous l'UMask du helper laisserait root:root 0750 et la
    console (utilisateur scanoria) ne pourrait pas y entrer : le fichier publié
    paraîtrait absent. tmpfiles.d crée ces répertoires à l'installation ; ce
    rattrapage couvre une appliance installée avant leur ajout. Un lien
    symbolique est refusé."""
    try:
        os.mkdir(path, 0o750)
    except FileExistsError:
        pass
    # Descripteur ouvert sans suivre de lien : droits posés sur le répertoire
    # lui-même, sans fenêtre entre la vérification et le changement.
    try:
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except OSError:
        raise Fail("E_INTERNAL", "%s is not a directory" % path)
    try:
        st = os.fstat(fd)
        if stat.S_IMODE(st.st_mode) != 0o750:
            os.fchmod(fd, 0o750)
        if not TEST_ROOT:
            gid = scanoria_ids()[1]
            if st.st_uid != 0 or st.st_gid != gid:
                os.fchown(fd, 0, gid)
    finally:
        os.close(fd)


def atomic_write(path, data, mode=0o640, group_scanoria=True):
    """Écrit path atomiquement (root, groupe scanoria si demandé)."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    d = os.path.dirname(path)
    fd, tmp = tempfile.mkstemp(dir=d, prefix="." + os.path.basename(path) + ".")
    try:
        os.fchmod(fd, mode)
        if not TEST_ROOT:
            os.fchown(fd, 0, scanoria_ids()[1] if group_scanoria else 0)
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.rename(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    try:
        dfd = os.open(d, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)
    except OSError:
        pass


def write_json(path, obj, mode=0o640, group_scanoria=True):
    atomic_write(path, dumps(obj), mode, group_scanoria)


# --------------------------------------------------------------------------
# Sous-processus (toujours un tableau d'arguments, jamais de shell)
# --------------------------------------------------------------------------

SYSTEM_CMDS = {
    "openssl": "/usr/bin/openssl",
    "curl": "/usr/bin/curl",
    "zstd": "/usr/bin/zstd",
    "systemctl": "/usr/bin/systemctl",
    "nginx": "/usr/sbin/nginx",
    "nft": "/usr/sbin/nft",
    "runuser": "/usr/sbin/runuser",
    "pg_dump": "/usr/bin/pg_dump",
    "pg_restore": "/usr/bin/pg_restore",
    "psql": "/usr/bin/psql",
    "createdb": "/usr/bin/createdb",
    "dropdb": "/usr/bin/dropdb",
    "hostnamectl": "/usr/bin/hostnamectl",
    "systemd-sysusers": "/usr/bin/systemd-sysusers",
    "systemd-tmpfiles": "/usr/bin/systemd-tmpfiles",
    "systemd-run": "/usr/bin/systemd-run",
    "timedatectl": "/usr/bin/timedatectl",
    "getent": "/usr/bin/getent",
    "ip": "/usr/sbin/ip",
    "resolvectl": "/usr/bin/resolvectl",
    "podman": "/usr/bin/podman",
    "sysctl": "/usr/sbin/sysctl",
    "skopeo": "/usr/bin/skopeo",
}
# Commandes sans effet sur le système, exécutées réellement en mode test.
TEST_PASSTHROUGH = ("openssl", "zstd")


def resolve(name):
    """Chemin de la commande, ou None (bouchon en mode test)."""
    if name == "node":
        real = OPT + "/node/bin/node"
    elif name.startswith("scanoria-"):
        real = os.path.join(SBIN_DIR, name)
    else:
        real = SYSTEM_CMDS[name]
    if not TEST_ROOT:
        return real
    if TEST_BIN and os.path.isfile(os.path.join(TEST_BIN, name)):
        return os.path.join(TEST_BIN, name)
    if name.startswith("scanoria-"):
        return real
    if name in TEST_PASSTHROUGH:
        import shutil
        return shutil.which(name)
    return None


def child_env(extra=None):
    env = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"}
    for k in ("SCANORIA_TEST_ROOT", "SCANORIA_TEST_BIN", "SCANORIA_TEST_OWNER_UID",
              "SCANORIA_STEP_FILE", "SCANORIA_TEST_NOW"):
        if k in os.environ and (TEST_ROOT or not k.startswith("SCANORIA_TEST")):
            env[k] = os.environ[k]
    if TEST_ROOT and "PATH" in os.environ:
        env["PATH"] = os.environ["PATH"]
    if extra:
        env.update(extra)
    return env


class Result:
    def __init__(self, rc, out=b"", err=b""):
        self.returncode, self.stdout, self.stderr = rc, out, err

    @property
    def text(self):
        return self.stdout.decode("utf-8", "replace")


def run(name, args=(), *, input=None, timeout=600, env=None, stdout_limit=8 << 20, cwd="/",
        stderr_tail=0):
    """Lance une commande connue ; stderr va au journal.

    stderr_tail > 0 : stderr est aussi recopié (borné) dans le journal, et ses
    derniers octets sont rendus dans Result.stderr pour le diagnostic."""
    exe = resolve(name)
    argv = [str(a) for a in args]
    if exe is None:
        with open(p("/test-commands.log"), "a", encoding="utf-8") as f:
            f.write(json.dumps([name] + argv, separators=(",", ":")) + "\n")
        return Result(0)
    try:
        proc = subprocess.Popen(
            [exe] + argv, stdin=subprocess.PIPE if input is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE if stderr_tail else None,
            env=child_env(env), cwd=cwd, start_new_session=True, close_fds=True)
    except OSError as e:
        return Result(127, b"", str(e).encode())
    try:
        out, err = proc.communicate(input=input, timeout=timeout)
    except subprocess.TimeoutExpired:
        kill_group(proc)
        raise Fail("E_TIMEOUT", "%s timed out after %ss" % (name, timeout))
    if stderr_tail:
        err = err or b""
        try:
            sys.stderr.buffer.write(err[-(64 << 10):])
            sys.stderr.flush()
        except (OSError, ValueError, AttributeError):
            pass
        return Result(proc.returncode, out[:stdout_limit], err[-stderr_tail:])
    return Result(proc.returncode, out[:stdout_limit])


def kill_group(proc):
    for sig in (signal.SIGTERM, signal.SIGKILL):
        try:
            os.killpg(proc.pid, sig)
        except OSError:
            pass
        try:
            proc.wait(timeout=10)
            return
        except subprocess.TimeoutExpired:
            continue


def run_protocol(name, args=(), *, timeout=600, input=None, env=None):
    """Lance une commande scanoria-* qui répond {code, message, output} sur stdout."""
    r = run(name, args, timeout=timeout, input=input, env=env)
    try:
        obj = loads_strict(r.stdout)
        if not isinstance(obj, dict) or obj.get("code") not in ALL_CODES:
            raise JsonError("bad protocol object")
    except JsonError:
        raise Fail("E_INTERNAL", "%s failed (exit %d)" % (name, r.returncode))
    out = obj.get("output") if isinstance(obj.get("output"), dict) else {}
    msg = obj.get("message") if isinstance(obj.get("message"), str) else ""
    if obj["code"] != "OK":
        raise Fail(obj["code"], msg, out)
    return out, msg


def emit(code, message, output=None):
    """Réponse d'une commande au protocole {code, message, output} ; code de sortie."""
    sys.stdout.write(json.dumps({"code": code, "message": message[:2000],
                                 "output": output or {}}, ensure_ascii=False) + "\n")
    sys.stdout.flush()
    return 0 if code == "OK" else 1


# --------------------------------------------------------------------------
# Étape courante d'une demande (lue par scanoria-state)
# --------------------------------------------------------------------------

def set_step(step):
    path = os.environ.get("SCANORIA_STEP_FILE", "")
    if path != CURRENT_FILE or not os.path.exists(path):
        return
    try:
        cur = load_json_file(path, 4096)
        cur["step"] = step
        write_json(path, cur)
    except (OSError, JsonError):
        return
    publish_state()


def publish_state():
    try:
        run("scanoria-state", (), timeout=60)
    except Fail:
        pass
