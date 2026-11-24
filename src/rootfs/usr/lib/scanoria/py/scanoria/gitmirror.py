# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Vincent Tisseront
"""Miroir Git local d'un projet (V2, contrat 22 de la 0.6).

Un dépôt nu par projet, /var/lib/scanoria/git-mirrors/<project_id>.git, tenu à
jour par le conteneur git-fetch de chaque analyse, qui ne récupère que les
nouveaux objets ; le commit voulu est ensuite extrait dans le répertoire propre
de l'analyse (read-tree et checkout-index avec un index temporaire : aucun
hook, aucun filtre, aucun sous-module, aucun lien symbolique).

La configuration du dépôt analysé n'est jamais lue : le miroir est créé ici
(squelette de dépôt nu écrit par le runner), et avant chaque usage le runner
réécrit sa configuration, retire hooks/, info/attributes, les alternates et
tout ce qu'un dépôt nu n'a pas à contenir. Un miroir qui contient un lien
symbolique ou un fichier spécial, dépasse la taille maximale ou dont
l'extraction échoue comme celle d'un dépôt corrompu est supprimé puis recréé
par un clone superficiel. Un verrou par projet sérialise les analyses d'un
même projet et la purge.

Le miroir est retiré avec son projet : le worker publie la liste des projets
existants (scans/live-projects.json, contrat 8) et le runner supprime les
miroirs des projets disparus (purge_orphans).
"""

import contextlib
import errno
import fcntl
import hashlib
import os
import shutil
import stat
import time

from . import common

MIRRORS = common.VARLIB + "/git-mirrors"
MAX_MIRROR_BYTES = 8 << 30
LOCK_TIMEOUT_S = 3600
# Liste des projets publiée par le worker : trop ancienne, elle n'est pas
# crue (aucune suppression sur une information périmée).
LIVE_MAX_AGE_S = 3600
MAX_LIVE = 2 << 20
# Un miroir utilisé depuis moins de ce délai n'est jamais purgé (projet créé
# entre deux publications de la liste).
PURGE_GRACE_S = 6 * 3600
NOBODY = 65534

CONFIG = (b"[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n\tbare = true\n"
          b"\tsymlinks = false\n\tfsmonitor = false\n\thooksPath = /dev/null\n"
          b"[gc]\n\tauto = 0\n")
HEAD = b"ref: refs/heads/scanoria\n"
# Entrées admises à la racine d'un dépôt nu ; tout le reste est retiré.
ALLOWED_TOP = {"HEAD", "config", "objects", "refs", "packed-refs", "shallow", "FETCH_HEAD",
               "description", "info", "logs"}
REMOVED = ("hooks", "info/attributes", "info/grafts", "info/sparse-checkout", "objects/info/alternates",
           "objects/info/http-alternates", "commondir", "gitdir", "config.worktree", "worktrees", "modules",
           "branches", "remotes")


class MirrorError(Exception):
    def __init__(self, code, message):
        super().__init__(message)
        self.code, self.message = code, message


def path_of(project_id):
    if not isinstance(project_id, str) or not common.UUID4_RE.match(project_id):
        raise MirrorError("E_GITMIRROR_PROJECT", "invalid project id")
    return os.path.join(MIRRORS, project_id + ".git")


def _meta_path(project_id):
    return os.path.join(MIRRORS, project_id + ".json")


def _lock_path(project_id):
    return os.path.join(MIRRORS, project_id + ".lock")


def url_key(url):
    return hashlib.sha256(url.encode("utf-8")).hexdigest()


def ref_key(ref):
    """Nom de référence sûr pour une branche ou une étiquette demandée."""
    return hashlib.sha256(ref.encode("utf-8")).hexdigest()[:16]


def ensure_root():
    os.makedirs(MIRRORS, mode=0o700, exist_ok=True)
    st = os.lstat(MIRRORS)
    if not stat.S_ISDIR(st.st_mode):
        raise MirrorError("E_GITMIRROR_LAYOUT", "%s is not a directory" % MIRRORS)
    os.chmod(MIRRORS, 0o700)


@contextlib.contextmanager
def locked(project_id, timeout=LOCK_TIMEOUT_S):
    """Verrou exclusif du miroir d'un projet (entre analyses, et avec la purge)."""
    ensure_root()
    path_of(project_id)
    fd = os.open(_lock_path(project_id), os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        deadline = time.monotonic() + timeout
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except OSError as e:
                if e.errno not in (errno.EAGAIN, errno.EACCES) or time.monotonic() > deadline:
                    raise MirrorError("E_GITMIRROR_BUSY", "the Git mirror of the project is busy")
                time.sleep(0.5)
        yield
    finally:
        os.close(fd)


def read_meta(project_id):
    try:
        m = common.load_json_file(_meta_path(project_id), 64 << 10)
    except (OSError, common.JsonError, common.Fail):
        return {}
    return m if isinstance(m, dict) else {}


def write_meta(project_id, meta):
    common.write_json(_meta_path(project_id), meta, 0o600, group_scanoria=False)


def _tree_ok(root):
    """(sain, octets) : aucun lien ni fichier spécial, taille bornée ; ne suit aucun lien."""
    total = 0
    for d, dirs, names in os.walk(root, followlinks=False):
        for n in dirs:
            if os.path.islink(os.path.join(d, n)):
                return False, total
        for n in names:
            try:
                st = os.lstat(os.path.join(d, n))
            except OSError:
                return False, total
            if not stat.S_ISREG(st.st_mode):
                return False, total
            total += st.st_size
            if total > MAX_MIRROR_BYTES:
                return False, total
    return True, total


def _give(path):
    """Le miroir appartient à l'utilisateur du conteneur git-fetch (65534), à lui seul."""
    from . import testbed
    testbed._give_to_container(path)


def _write(path, data, mode=0o600):
    tmp = path + ".scanoria-tmp"
    with contextlib.suppress(FileNotFoundError):
        os.unlink(tmp)
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, mode)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
    os.replace(tmp, path)


def _create(path):
    os.mkdir(path, 0o700)
    for d in ("objects", "objects/info", "objects/pack", "refs", "refs/heads", "refs/tags"):
        os.mkdir(os.path.join(path, d), 0o700)
    _write(os.path.join(path, "HEAD"), HEAD)
    _write(os.path.join(path, "config"), CONFIG)


def discard(project_id):
    """Supprime le miroir d'un projet (et son état) ; sans effet s'il n'existe pas."""
    p = path_of(project_id)
    if os.path.lexists(p):
        if os.path.isdir(p) and not os.path.islink(p):
            shutil.rmtree(p, ignore_errors=True)
        else:
            os.unlink(p)
    with contextlib.suppress(FileNotFoundError):
        os.unlink(_meta_path(project_id))


def prepare(project_id, url):
    """Miroir sain du projet, créé si besoin ; à appeler sous verrou.

    Retourne (chemin, état) où état vaut « created » ou « reused »."""
    ensure_root()
    p = path_of(project_id)
    meta = read_meta(project_id)
    state = "reused"
    reason = None
    if not os.path.lexists(p):
        reason = "absent"
    elif os.path.islink(p) or not os.path.isdir(p):
        reason = "not a directory"
    elif meta.get("url_sha256") != url_key(url):
        reason = "repository URL changed"
    else:
        ok, _ = _tree_ok(p)
        if not ok:
            reason = "unexpected content"
    if reason:
        if reason != "absent":
            common.log("git mirror of %s recreated: %s" % (project_id, reason))
        discard(project_id)
        _create(p)
        meta = {"url_sha256": url_key(url), "created_at": common.iso(common.now())}
        state = "created"
    sanitize(p)
    meta["used_at"] = common.iso(common.now())
    write_meta(project_id, meta)
    return p, state


def sanitize(p):
    """Configuration réécrite, et retrait de tout ce qui pourrait faire exécuter ou détourner git."""
    for rel in REMOVED:
        q = os.path.join(p, rel)
        if os.path.isdir(q) and not os.path.islink(q):
            shutil.rmtree(q, ignore_errors=True)
        elif os.path.lexists(q):
            os.unlink(q)
    for n in os.listdir(p):
        if n not in ALLOWED_TOP:
            q = os.path.join(p, n)
            if os.path.isdir(q) and not os.path.islink(q):
                shutil.rmtree(q, ignore_errors=True)
            else:
                os.unlink(q)
    for d in ("objects", "objects/info", "objects/pack", "refs"):
        q = os.path.join(p, d)
        if not os.path.isdir(q) or os.path.islink(q):
            raise MirrorError("E_GITMIRROR_CORRUPT", "the Git mirror lost its %s directory" % d)
    _write(os.path.join(p, "config"), CONFIG)
    _write(os.path.join(p, "HEAD"), HEAD)
    _give(p)


def note_tree(project_id, files, size):
    """Taille du dernier arbre extrait (choix du tmpfs de l'analyse suivante, V9)."""
    meta = read_meta(project_id)
    if meta:
        meta.update(last_tree_bytes=int(size), last_tree_files=int(files))
        write_meta(project_id, meta)


def last_tree_bytes(project_id):
    v = read_meta(project_id).get("last_tree_bytes") if project_id else None
    return v if isinstance(v, int) and not isinstance(v, bool) and v >= 0 else None


# --------------------------------------------------------------------------
# Purge des miroirs des projets supprimés
# --------------------------------------------------------------------------

def live_projects(path, now=None):
    """Projets existants publiés par le worker, ou None si la liste est absente,
    illisible, mal formée ou trop ancienne (aucune purge alors)."""
    now = now or time.time()
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except OSError:
        return None
    with os.fdopen(fd, "rb") as f:
        st = os.fstat(f.fileno())
        if not stat.S_ISREG(st.st_mode) or st.st_size > MAX_LIVE or now - st.st_mtime > LIVE_MAX_AGE_S:
            return None
        if not common.TEST_ROOT and st.st_uid != common.scanoria_ids()[0]:
            return None
        os.set_blocking(f.fileno(), True)
        data = f.read(MAX_LIVE + 1)
    try:
        doc = common.loads_strict(data)
    except common.JsonError:
        return None
    ids = doc.get("projects") if isinstance(doc, dict) and doc.get("schema") == 1 else None
    if not isinstance(ids, list) or not all(isinstance(i, str) and common.UUID4_RE.match(i) for i in ids):
        return None
    return set(ids)


def purge_orphans(live, extra=(), now=None):
    """Supprime les miroirs (et caches de projet, extra : fonctions(project_id))
    des projets absents de live ; retourne les projets purgés."""
    if live is None:
        return []
    now = now or time.time()
    try:
        names = os.listdir(MIRRORS)
    except OSError:
        return []
    gone = set()
    for n in names:
        pid = n.rsplit(".", 1)[0]
        if common.UUID4_RE.match(pid) and pid not in live:
            gone.add(pid)
    done = []
    for pid in sorted(gone):
        used = read_meta(pid).get("used_at")
        try:
            age = now - common.parse_iso(used).timestamp() if isinstance(used, str) else PURGE_GRACE_S + 1
        except (ValueError, AttributeError):
            age = PURGE_GRACE_S + 1
        if age < PURGE_GRACE_S:
            continue
        try:
            with locked(pid, timeout=5):
                discard(pid)
                for f in extra:
                    f(pid)
        except MirrorError:
            continue
        with contextlib.suppress(FileNotFoundError):
            os.unlink(_lock_path(pid))
        done.append(pid)
        common.log("git mirror of deleted project %s removed" % pid)
    return done


# --------------------------------------------------------------------------
# Session d'une analyse
# --------------------------------------------------------------------------

class Session:
    """Miroir utilisé par une analyse : celui du projet (verrou tenu de l'entrée à
    la sortie), ou, sans projet connu, un miroir jetable dans l'espace de travail."""

    def __init__(self, project_id, url, ws):
        valid = isinstance(project_id, str) and common.UUID4_RE.match(project_id) is not None
        self.project_id = project_id if valid else None
        self.url, self.ws = url, ws
        self.path, self.state = None, None
        self._lock = None

    def __enter__(self):
        if self.project_id is None:
            self.path = os.path.join(self.ws, "mirror")
            if os.path.lexists(self.path):
                shutil.rmtree(self.path, ignore_errors=True)
            _create(self.path)
            sanitize(self.path)
            self.state = "created"
            return self
        self._lock = locked(self.project_id)
        self._lock.__enter__()
        try:
            self.path, self.state = prepare(self.project_id, self.url)
        except BaseException:
            self._lock.__exit__(None, None, None)
            self._lock = None
            raise
        return self

    def recreate(self):
        """Miroir corrompu : supprimé puis recréé vide (le clone suivant est superficiel)."""
        if self.project_id is None:
            shutil.rmtree(self.path, ignore_errors=True)
            _create(self.path)
            sanitize(self.path)
        else:
            discard(self.project_id)
            self.path, self.state = prepare(self.project_id, self.url)
        self.state = "created"

    def __exit__(self, *exc):
        if self._lock is not None:
            self._lock.__exit__(None, None, None)
            self._lock = None
        return False
