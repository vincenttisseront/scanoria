# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Vincent Tisseront
"""Sauvegarde et restauration des modules permanents (contrat 10 de la 0.4,
CLAUDE.md § 4.3 et § 10) : demandes backup-module et restore-module, et
sauvegarde préalable de update-module.

Une sauvegarde est un répertoire root 0700 :
  /var/lib/scanoria/backups/modules/<id>/<AAAAMMJJTHHMMSSZ>/
      db.dump              pg_dump -Fc de la base mod_<id> (si needs.postgres)
      volume-<nom>.tar     un par volume de service.backup (module arrêté)
      manifest.json        écrit en dernier : version du module, empreinte de
                           l'image, taille et SHA-256 de chaque fichier
Un répertoire sans manifest.json est une sauvegarde interrompue : il n'est
jamais restauré et il est retiré au passage suivant. La restauration vérifie
chaque empreinte avant d'arrêter le module, puis restaure et attend la santé.
Rétention : les KEEP sauvegardes les plus récentes de chaque module.

backup_all() est le point d'entrée de la future sauvegarde globale (1.0).
"""

import hashlib
import os
import re
import shutil
import stat
import subprocess

from . import common, pgadmin, quadlet, services
from .common import Fail

ROOT = common.VARLIB + "/backups/modules"
KEEP = 3
STAMP_RE = re.compile(r"[0-9]{8}T[0-9]{6}Z(-[0-9])?\Z")
FILE_RE = re.compile(r"(db\.dump|volume-[a-z0-9][a-z0-9-]{0,30}\.tar)\Z")
REASONS = ("manual", "update", "scheduled")
MANIFEST = "manifest.json"
MAX_MANIFEST = 64 * 1024


# --------------------------------------------------------------------------
# Sous-processus avec fichier en entrée ou en sortie (jamais en mémoire)
# --------------------------------------------------------------------------

def run_to_file(name, args, dest, timeout):
    """Comme common.run, mais la sortie va dans dest (créé en 0600, O_EXCL)."""
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


def run_from_file(name, args, src, timeout):
    """Comme common.run, mais l'entrée standard est le fichier src (ouvert par root)."""
    exe = common.resolve(name)
    if exe is None:
        common.run(name, list(args) + ["<" + os.path.basename(src)], timeout=timeout)
        return 0
    fd = os.open(src, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as inp:
        try:
            p = subprocess.run([exe] + list(args), stdin=inp, stdout=subprocess.DEVNULL, env=common.child_env(),
                               timeout=timeout, cwd="/", close_fds=True, check=False)
        except subprocess.TimeoutExpired:
            raise Fail("E_TIMEOUT", "%s timed out" % name)
    return p.returncode


# --------------------------------------------------------------------------
# Inventaire
# --------------------------------------------------------------------------

def module_root(mid):
    return os.path.join(ROOT, services.check_id(mid))


def _sha256(path):
    h = hashlib.sha256()
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as f:
        st = os.fstat(f.fileno())
        if not stat.S_ISREG(st.st_mode):
            raise Fail("E_BACKUP_INVALID", "not a regular file")
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest(), st.st_size


def backup_volumes(m):
    """Volumes à sauvegarder : service.backup (noms), sinon tous les volumes déclarés."""
    vols = [n for n, _ in quadlet.volumes(m)]
    wanted = (m.get("service") or {}).get("backup")
    if wanted is None:
        return vols
    if not isinstance(wanted, list) or len(wanted) > 32:
        raise Fail("E_INVALID_PARAM", "invalid backup declaration")
    for n in wanted:
        if n not in vols:
            raise Fail("E_INVALID_PARAM", "backup of an undeclared volume")
    return [n for n in vols if n in wanted]


def read_manifest(mid, stamp):
    """Manifeste validé d'une sauvegarde complète ; Fail sinon."""
    if not isinstance(stamp, str) or not STAMP_RE.match(stamp):
        raise Fail("E_INVALID_PARAM", "invalid backup id")
    d = os.path.join(module_root(mid), stamp)
    try:
        st = os.lstat(d)
    except FileNotFoundError:
        raise Fail("E_BACKUP_NOT_FOUND", "backup %s of %s not found" % (stamp, mid))
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != os.getuid():
        raise Fail("E_BACKUP_INVALID", "backup directory is not trusted")
    try:
        man = common.load_json_file(os.path.join(d, MANIFEST), MAX_MANIFEST)
    except FileNotFoundError:
        raise Fail("E_BACKUP_INVALID", "backup %s is incomplete" % stamp)
    except (OSError, common.JsonError):
        raise Fail("E_BACKUP_INVALID", "backup manifest unreadable")
    ok = (isinstance(man, dict) and man.get("version") == 1 and man.get("module") == mid
          and isinstance(man.get("module_version"), str) and man.get("reason") in REASONS
          and isinstance(man.get("files"), list) and isinstance(man.get("created_at"), str))
    if not ok:
        raise Fail("E_BACKUP_INVALID", "backup manifest malformed")
    names = set()
    for f in man["files"]:
        if not (isinstance(f, dict) and isinstance(f.get("name"), str) and FILE_RE.match(f["name"])
                and isinstance(f.get("sha256"), str) and re.fullmatch(r"[0-9a-f]{64}", f["sha256"])
                and isinstance(f.get("size"), int) and f["size"] >= 0) or f["name"] in names:
            raise Fail("E_BACKUP_INVALID", "backup manifest malformed")
        names.add(f["name"])
    return d, man


def list_backups(mid):
    """Sauvegardes complètes, la plus récente en premier (pour l'état publié)."""
    try:
        names = os.listdir(module_root(mid))
    except (FileNotFoundError, NotADirectoryError):
        return []
    out = []
    for stamp in sorted((n for n in names if STAMP_RE.match(n)), reverse=True):
        try:
            _, man = read_manifest(mid, stamp)
        except Fail:
            continue
        vols = [f["name"][7:-4] for f in man["files"] if f["name"].startswith("volume-")]
        out.append({"id": stamp, "created_at": man["created_at"], "module_version": man["module_version"][:64],
                    "reason": man["reason"], "size_bytes": sum(f["size"] for f in man["files"]),
                    "database": any(f["name"] == "db.dump" for f in man["files"]), "volumes": vols})
    return out[:20]


def prune(mid, keep=KEEP):
    """Garde les keep sauvegardes complètes les plus récentes ; retire les interrompues."""
    root = module_root(mid)
    try:
        names = sorted((n for n in os.listdir(root) if STAMP_RE.match(n)), reverse=True)
    except FileNotFoundError:
        return
    complete = 0
    for n in names:
        path = os.path.join(root, n)
        if os.path.islink(path):
            os.unlink(path)
            continue
        good = os.path.isfile(os.path.join(path, MANIFEST))
        if good and complete < keep:
            complete += 1
            continue
        shutil.rmtree(path, ignore_errors=True)


# --------------------------------------------------------------------------
# Sauvegarde
# --------------------------------------------------------------------------

def _new_dir(mid):
    root = module_root(mid)
    os.makedirs(ROOT, mode=0o700, exist_ok=True)
    os.makedirs(root, mode=0o700, exist_ok=True)
    if os.path.islink(root) or not os.path.isdir(root):
        raise Fail("E_BACKUP_FAILED", "backup directory is not trusted")
    base = common.now().strftime("%Y%m%dT%H%M%SZ")
    for suffix in [""] + ["-%d" % i for i in range(1, 10)]:
        d = os.path.join(root, base + suffix)
        try:
            os.mkdir(d, 0o700)
            return d, base + suffix
        except FileExistsError:
            continue
    raise Fail("E_BACKUP_FAILED", "too many backups in the same second")


def create(m, entry, reason, stop, start, timeout=1800):
    """Sauvegarde complète. stop(), start() : arrêt et reprise du module autour
    de la copie des volumes (start n'est appelé que si le module tournait).
    Retourne l'identifiant de la sauvegarde."""
    if reason not in REASONS:
        raise Fail("E_INVALID_PARAM", "invalid backup reason")
    mid = m["id"]
    d, stamp = _new_dir(mid)
    try:
        if (m.get("needs") or {}).get("postgres"):
            pgadmin.dump(mid, os.path.join(d, "db.dump"), timeout=timeout)
        vols = backup_volumes(m)
        if vols:
            was_running = stop()
            try:
                for name in vols:
                    if common.run("podman", ["volume", "export", "--output", os.path.join(d, "volume-%s.tar" % name),
                                             quadlet.volume_name(mid, name)], timeout=timeout).returncode != 0:
                        raise Fail("E_BACKUP_FAILED", "volume %s of %s could not be saved" % (name, mid))
            finally:
                if was_running:
                    start()
        files = []
        for name in sorted(os.listdir(d)):
            if not FILE_RE.match(name):
                raise Fail("E_BACKUP_FAILED", "unexpected file in the backup")
            digest, size = _sha256(os.path.join(d, name))
            files.append({"name": name, "sha256": digest, "size": size})
        man = {"version": 1, "module": mid, "module_version": m["version"], "image": m.get("image"),
               "type": m["type"], "reason": reason, "created_at": common.iso(common.now()), "files": files}
        common.write_json(os.path.join(d, MANIFEST), man, 0o600, group_scanoria=False)
    except BaseException:
        shutil.rmtree(d, ignore_errors=True)
        raise
    prune(mid)
    return stamp


def verify(mid, stamp):
    """Vérifie toutes les empreintes d'une sauvegarde ; retourne (répertoire, manifeste)."""
    d, man = read_manifest(mid, stamp)
    listed = {f["name"] for f in man["files"]}
    present = {n for n in os.listdir(d) if n != MANIFEST}
    if listed != present:
        raise Fail("E_BACKUP_INVALID", "backup files do not match the manifest")
    for f in man["files"]:
        digest, size = _sha256(os.path.join(d, f["name"]))
        if digest != f["sha256"] or size != f["size"]:
            raise Fail("E_BACKUP_INVALID", "checksum mismatch for %s" % f["name"])
    return d, man


def restore_data(m, d, man, timeout=1800):
    """Remet la base et les volumes d'une sauvegarde vérifiée (module arrêté)."""
    mid = m["id"]
    names = {f["name"] for f in man["files"]}
    if "db.dump" in names:
        if not (m.get("needs") or {}).get("postgres"):
            raise Fail("E_BACKUP_INVALID", "backup has a database but the module has none")
        pgadmin.restore(mid, os.path.join(d, "db.dump"), timeout=timeout)
    declared = {n for n, _ in quadlet.volumes(m)}
    for name in sorted(names):
        if not name.startswith("volume-"):
            continue
        vol = name[7:-4]
        if vol not in declared:
            raise Fail("E_BACKUP_INVALID", "backup has an undeclared volume")
        vname = quadlet.volume_name(mid, vol)
        common.run("podman", ["volume", "rm", "--force", vname], timeout=300)
        if common.run("podman", ["volume", "create", vname], timeout=300).returncode != 0 or \
                common.run("podman", ["volume", "import", vname, os.path.join(d, name)],
                           timeout=timeout).returncode != 0:
            raise Fail("E_BACKUP_FAILED", "volume %s of %s could not be restored" % (vol, mid))


# --------------------------------------------------------------------------
# Sauvegarde globale (1.0)
# --------------------------------------------------------------------------

def backup_all(reg, stop, start, reason="scheduled"):
    """Sauvegarde chaque module permanent installé ; {id: identifiant ou erreur}."""
    out = {}
    for mid, e in sorted(reg["modules"].items()):
        m = e["manifest"]
        if m["type"] not in ("service", "runner"):
            continue
        try:
            out[mid] = {"backup": create(m, e, reason, lambda mid=mid: stop(mid), lambda mid=mid: start(mid))}
        except Fail as err:
            out[mid] = {"error": err.code}
    return out
