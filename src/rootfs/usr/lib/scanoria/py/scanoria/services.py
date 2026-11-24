# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Vincent Tisseront
"""Modules permanents (« service » et « runner ») : secrets générés, réseau
propre, réglages noyau et limites, relevés de consommation (contrats 10 et 11
de la 0.4, CLAUDE.md § 3.2).

Secrets : chaque nom déclaré dans service.secrets (et « db-password » d'office
si needs.postgres) est un fichier root 0600 tiré au hasard par le helper,
jamais par la console :
    /var/lib/scanoria/modules/<id>/secrets/<nom>
Il est transmis au conteneur par un secret Podman « scanoria-mod-<id>-<nom> »,
monté en /run/secrets/<nom> et, si demandé, injecté dans une variable. Aucune
valeur ne passe par un fichier d'unité, un argument visible ou la base.

Réseau : chaque module permanent a un réseau Podman propre, dans un /24 fixe
du bloc déclaré par share/scanoria/modules/services-network.conf. La passerelle
(première adresse) est l'adresse par laquelle le module joint PostgreSQL.

Réglages noyau : liste blanche fermée. Les clés du noyau vont dans
/etc/sysctl.d/60-scanoria-<id>.conf ; une valeur n'est jamais baissée (ni sous
celle d'un autre module, ni sous la valeur courante du système). nofile et
nproc sont des limites de l'unité (Ulimit=).
"""

import ipaddress
import os
import re
import secrets as _secrets
import shutil

from . import common
from .common import Fail

MODULES_DIR = common.VARLIB + "/modules"
SYSCTL_DIR = common.p("/etc/sysctl.d")
SYSCTL_LEGACY = SYSCTL_DIR + "/60-scanoria-modules.conf"
SYSCTL_PREFIX = "60-scanoria-"
PODMAN_PREFIX = "scanoria-mod-"

ID_RE = re.compile(r"[a-z0-9][a-z0-9-]{1,40}\Z")
SECRET_NAME_RE = re.compile(r"[a-z][a-z0-9-]{0,40}\Z")
SECRET_ENV_RE = re.compile(r"(?!LD_|PATH\Z|HOME\Z)[A-Z][A-Z0-9_]{0,63}\Z")
SECRET_VALUE_RE = re.compile(r"[0-9a-f]{48}\Z")
DB_SECRET = "db-password"
MAX_SECRETS = 16

# Réglages du noyau autorisés : (minimum, maximum).
KERNEL_ALLOWED = {
    "vm.max_map_count": (65530, 1 << 30),
    "fs.file-max": (8192, 1 << 31),
    "fs.inotify.max_user_watches": (8192, 1 << 24),
    "fs.inotify.max_user_instances": (128, 1 << 16),
    "net.core.somaxconn": (128, 65535),
}
# Limites de l'unité (Ulimit=), même valeur souple et dure.
ULIMIT_ALLOWED = {
    "nofile": (1024, 1 << 20),
    "nproc": (512, 1 << 22),
}


# --------------------------------------------------------------------------
# Identifiants et chemins
# --------------------------------------------------------------------------

def check_id(mid):
    if not isinstance(mid, str) or not ID_RE.match(mid):
        raise Fail("E_INVALID_PARAM", "invalid module id")
    return mid


def module_dir(mid):
    return os.path.join(MODULES_DIR, check_id(mid))


def secrets_dir(mid):
    return os.path.join(module_dir(mid), "secrets")


def secret_path(mid, name):
    """Fichier root 0600 d'un secret du module (lu par le helper seulement)."""
    if not isinstance(name, str) or not SECRET_NAME_RE.match(name):
        raise Fail("E_INVALID_PARAM", "invalid secret name")
    return os.path.join(secrets_dir(mid), name)


def podman_secret(mid, name):
    return "%s%s-%s" % (PODMAN_PREFIX, check_id(mid), name)


# --------------------------------------------------------------------------
# Secrets
# --------------------------------------------------------------------------

def secrets_of(m):
    """[(nom, variable ou None)] déclarés par le manifeste, db-password compris."""
    svc = m.get("service") or {}
    raw = svc.get("secrets") or []
    if not isinstance(raw, list) or len(raw) > MAX_SECRETS:
        raise Fail("E_INVALID_PARAM", "invalid secrets declaration")
    out = []
    for item in raw:
        if isinstance(item, str):
            name, env = item, None
        elif isinstance(item, dict) and set(item) <= {"name", "env"}:
            name, env = item.get("name"), item.get("env")
        else:
            raise Fail("E_INVALID_PARAM", "invalid secret declaration")
        if not isinstance(name, str) or not SECRET_NAME_RE.match(name):
            raise Fail("E_INVALID_PARAM", "invalid secret name")
        if env is not None and (not isinstance(env, str) or not SECRET_ENV_RE.match(env)):
            raise Fail("E_INVALID_PARAM", "invalid secret variable")
        out.append((name, env))
    names = [n for n, _ in out]
    if len(set(names)) != len(names):
        raise Fail("E_INVALID_PARAM", "duplicate secret name")
    envs = [e for _, e in out if e]
    if len(set(envs)) != len(envs):
        raise Fail("E_INVALID_PARAM", "duplicate secret variable")
    if (m.get("needs") or {}).get("postgres") and DB_SECRET not in names:
        out.insert(0, (DB_SECRET, None))
    elif DB_SECRET in names and not (m.get("needs") or {}).get("postgres"):
        raise Fail("E_INVALID_PARAM", "db-password is reserved to modules using PostgreSQL")
    return out


def read_secret(mid, name):
    """Valeur d'un secret généré, ou None (absent ou altéré)."""
    path = secret_path(mid, name)
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError:
        return None
    try:
        st = os.fstat(fd)
        if not os.path.stat.S_ISREG(st.st_mode) or st.st_size > 4096:
            return None
        data = os.read(fd, 4096).decode("ascii", "replace").strip()
    finally:
        os.close(fd)
    return data or None


def ensure_secrets(m):
    """Crée les secrets manquants (une valeur gardée avec les données est reprise).
    Retourne la liste des noms créés par cet appel."""
    mid = m["id"]
    d = secrets_dir(mid)
    os.makedirs(module_dir(mid), mode=0o700, exist_ok=True)
    os.makedirs(d, mode=0o700, exist_ok=True)
    os.chmod(d, 0o700)
    created = []
    for name, _ in secrets_of(m):
        cur = read_secret(mid, name)
        if cur is not None and SECRET_VALUE_RE.match(cur):
            continue
        common.atomic_write(secret_path(mid, name), _secrets.token_hex(24), 0o600, group_scanoria=False)
        created.append(name)
    return created


def register_podman_secrets(m):
    """(Re)crée les secrets Podman du module depuis les fichiers root."""
    mid = m["id"]
    for name, _ in secrets_of(m):
        path = secret_path(mid, name)
        if not os.path.isfile(path):
            raise Fail("E_INTERNAL", "secret %s of %s missing" % (name, mid))
        r = common.run("podman", ["secret", "create", "--replace", podman_secret(mid, name), path], timeout=120)
        if r.returncode != 0:
            raise Fail("E_INTERNAL", "podman secret of %s could not be created" % mid)


def unregister_podman_secrets(m):
    for name, _ in secrets_of(m):
        common.run("podman", ["secret", "rm", podman_secret(m["id"], name)], timeout=120)


def remove_module_dir(mid):
    """Supprime les secrets et données du helper pour ce module (désinstallation sans conservation)."""
    shutil.rmtree(module_dir(mid), ignore_errors=True)


# --------------------------------------------------------------------------
# Réseau propre du module
# --------------------------------------------------------------------------

def _pool():
    conf = {}
    path = os.path.join(common.SHARE_DIR, "modules", "services-network.conf")
    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                key, sep, value = line.partition("=")
                if sep and not key.lstrip().startswith("#"):
                    conf[key.strip()] = value.strip()
        net = ipaddress.ip_network(conf.get("pool", ""))
    except (OSError, ValueError):
        net = ipaddress.ip_network("10.90.0.0/16")
    if net.version != 4 or not net.is_private or net.prefixlen > 23:
        raise Fail("E_INTERNAL", "invalid services network pool")
    return net


def subnet(index):
    nets = _pool().subnets(new_prefix=24)
    for i, n in enumerate(nets):
        if i == index:
            return n
    raise Fail("E_RESOURCES", "no free module network")


def gateway(index):
    return str(subnet(index).network_address + 1)


def alloc_subnet(reg, mid):
    """Index du /24 du module (gardé dans le registre)."""
    e = reg["modules"].get(mid) or {}
    cur = e.get("subnet")
    if isinstance(cur, int) and not isinstance(cur, bool) and cur >= 0:
        return cur
    used = {x.get("subnet") for k, x in reg["modules"].items() if k != mid}
    count = 2 ** (24 - _pool().prefixlen)
    for i in range(count):
        if i not in used:
            return i
    raise Fail("E_RESOURCES", "no free module network")


# --------------------------------------------------------------------------
# Réglages noyau et limites
# --------------------------------------------------------------------------

def requirements(m):
    """(réglages noyau, limites d'unité) validés contre la liste blanche."""
    req = (m.get("needs") or {}).get("sysctl") or {}
    if not isinstance(req, dict):
        raise Fail("E_RESOURCES", "%s: invalid sysctl requirement" % m["id"])
    kernel, ulimits = {}, {}
    for k, v in req.items():
        allowed = KERNEL_ALLOWED.get(k) or ULIMIT_ALLOWED.get(k)
        if allowed is None:
            raise Fail("E_RESOURCES", "%s: kernel setting %s is not allowed" % (m["id"], k))
        lo, hi = allowed
        if not isinstance(v, int) or isinstance(v, bool) or not lo <= v <= hi:
            raise Fail("E_RESOURCES", "%s: kernel setting %s out of range" % (m["id"], k))
        (kernel if k in KERNEL_ALLOWED else ulimits)[k] = v
    if ulimits and m.get("type") not in ("service", "runner"):
        raise Fail("E_RESOURCES", "%s: unit limits are only for permanent modules" % m["id"])
    return kernel, ulimits


def _current(key):
    """Valeur courante d'un réglage du noyau, ou None."""
    r = common.run("sysctl", ["-n", key], timeout=30)
    t = r.text.strip()
    return int(t) if r.returncode == 0 and t.isdigit() else None


def sysctl_files():
    try:
        names = os.listdir(SYSCTL_DIR)
    except FileNotFoundError:
        return []
    return sorted(n for n in names if n.startswith(SYSCTL_PREFIX) and n.endswith(".conf")
                  and ID_RE.match(n[len(SYSCTL_PREFIX):-5] or "x") and n != os.path.basename(SYSCTL_LEGACY))


def apply_sysctl(manifests):
    """Un fichier par module qui en exige ; valeur = maximum des modules et du système.
    Les fichiers des modules absents sont retirés ; aucune valeur courante n'est baissée."""
    want = {}
    per_module = {}
    for m in manifests:
        kernel, _ = requirements(m)
        if kernel:
            per_module[m["id"]] = kernel
            for k, v in kernel.items():
                want[k] = max(v, want.get(k, 0))
    current = {k: _current(k) for k in want}
    os.makedirs(SYSCTL_DIR, mode=0o755, exist_ok=True)
    keep = set()
    for mid, kernel in sorted(per_module.items()):
        name = "%s%s.conf" % (SYSCTL_PREFIX, mid)
        keep.add(name)
        text = "# Généré par scanoria-helper pour le module %s : ne pas modifier.\n" % mid
        for k in sorted(kernel):
            text += "%s = %d\n" % (k, max(want[k], current[k] or 0))
        common.atomic_write(os.path.join(SYSCTL_DIR, name), text, 0o644, group_scanoria=False)
    for name in sysctl_files():
        if name not in keep:
            os.unlink(os.path.join(SYSCTL_DIR, name))
    if os.path.exists(SYSCTL_LEGACY):
        os.unlink(SYSCTL_LEGACY)
    for k in sorted(want):
        if current[k] is not None and current[k] >= want[k]:
            continue
        if common.run("sysctl", ["-q", "-w", "%s=%d" % (k, want[k])], timeout=60).returncode != 0:
            raise Fail("E_RESOURCES", "kernel setting %s could not be applied" % k)
    return {mid: sorted(k) for mid, k in per_module.items()}


# --------------------------------------------------------------------------
# Relevés de consommation (contrat 11)
# --------------------------------------------------------------------------

CGROUP_DIR = common.p("/sys/fs/cgroup/system.slice")
VOLUMES_DIR = common.p("/var/lib/containers/storage/volumes")
USAGE_PREV = common.RUN + "/modules-usage.json"
DISK_EVERY_S = 900


def _read_int_file(path, key=None):
    """Entier d'un fichier de cgroup (ou de la ligne « key valeur »), ou None."""
    try:
        with open(path, encoding="ascii") as f:
            text = f.read(65536)
    except (OSError, UnicodeDecodeError):
        return None
    if key is None:
        t = text.strip()
        return int(t) if t.isdigit() else None
    for line in text.splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[0] == key and parts[1].isdigit():
            return int(parts[1])
    return None


def _cgroup(mid):
    """(mémoire Mo, temps CPU µs) de l'unité scanoria-mod-<id>.service, ou (0, None) si arrêtée."""
    d = os.path.join(CGROUP_DIR, PODMAN_PREFIX + mid + ".service")
    mem = _read_int_file(os.path.join(d, "memory.current"))
    if mem is None:
        return 0, None
    inactive = _read_int_file(os.path.join(d, "memory.stat"), "inactive_file") or 0
    return max(0, mem - inactive) // (1 << 20), _read_int_file(os.path.join(d, "cpu.stat"), "usage_usec")


def _volume_mb(volume):
    path = os.path.join(VOLUMES_DIR, volume, "_data")
    total = 0
    for dirpath, _, files in os.walk(path):
        for f in files:
            try:
                total += os.lstat(os.path.join(dirpath, f)).st_blocks * 512
            except OSError:
                pass
    return total // (1 << 20)


def _db_mb(dbname):
    r = common.run("runuser", ["-u", "postgres", "--", "/usr/bin/psql", "-X", "-A", "-t", "-d", "postgres",
                               "-c", "SELECT pg_database_size('%s')" % dbname], timeout=60)
    t = r.text.strip()
    return int(t) // (1 << 20) if r.returncode == 0 and t.isdigit() else 0


def usage(reg, now=None):
    """Relevé de chaque module permanent installé : [{id, usage}] (contrat 11).

    memory_mb : mémoire de l'unité hors cache de fichiers inactif ; cpu_pct :
    moyenne depuis le relevé précédent (100 = un processeur plein ; None au
    premier relevé ou après un redémarrage du module) ; disk_mb : volumes et
    base du module, recalculé au plus tous les DISK_EVERY_S."""
    import time
    from . import pgadmin, quadlet
    t = time.time() if now is None else now
    try:
        prev = common.load_json_file(USAGE_PREV, 1 << 20)
        if not isinstance(prev, dict):
            prev = {}
    except (OSError, common.JsonError):
        prev = {}
    at = common.iso(common.now())
    out, keep = [], {}
    for mid, e in sorted(reg.get("modules", {}).items()):
        m = e.get("manifest") or {}
        if m.get("type") not in ("service", "runner") or not ID_RE.match(mid):
            continue
        p = prev.get(mid) if isinstance(prev.get(mid), dict) else {}
        mem, cpu_us = _cgroup(mid)
        cpu = None
        if cpu_us is not None and isinstance(p.get("cpu_us"), int) and isinstance(p.get("t"), (int, float)):
            dt = t - p["t"]
            if dt > 0 and cpu_us >= p["cpu_us"]:
                cpu = round((cpu_us - p["cpu_us"]) / 1e6 / dt * 100, 2)
        elif cpu_us is None:
            cpu = 0.0
        disk, disk_t = p.get("disk_mb"), p.get("disk_t")
        if not isinstance(disk, int) or not isinstance(disk_t, (int, float)) or t - disk_t >= DISK_EVERY_S or t < disk_t:
            disk, disk_t = 0, t
            try:
                for name, _ in quadlet.volumes(m):
                    disk += _volume_mb(quadlet.volume_name(mid, name))
            except Fail:
                pass
            if (m.get("needs") or {}).get("postgres"):
                disk += _db_mb(pgadmin.db_name(mid))
        keep[mid] = {"cpu_us": cpu_us, "t": t, "disk_mb": disk, "disk_t": disk_t}
        out.append({"id": mid, "usage": {"memory_mb": mem, "cpu_pct": cpu, "disk_mb": disk, "at": at}})
    try:
        os.makedirs(common.RUN, mode=0o750, exist_ok=True)
        common.write_json(USAGE_PREV, keep, 0o600, group_scanoria=False)
    except OSError:
        pass
    return out
