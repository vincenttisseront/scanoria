# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Vincent Tisseront
"""Bases de vulnérabilités des modules feed (CLAUDE.md § 9) : téléchargement
par le helper root, bascule atomique et état publié.

Sources (déclarées par le manifeste signé, feed.source) :
- « https » (osv-db) : une archive all.zip par écosystème, posée dans la
  disposition lue par OSV-Scanner hors ligne : <base>/osv-scalibr/<éco>/all.zip ;
- « oci » (trivy-db) : client minimal de distribution OCI (jeton anonyme,
  manifeste, couche), empreinte SHA-256 de la couche vérifiée, extraction sûre
  (fichiers ordinaires seulement, aucun lien ni chemin sortant) dans la
  disposition lue par « trivy --cache-dir » : <base>/db/trivy.db et
  <base>/db/metadata.json.

Rien de téléchargé n'est exécuté et aucun conteneur n'a de réseau : seul curl
(HTTPS, certificat vérifié, tailles et délais bornés, proxy de
/etc/environment s'il existe) sort de l'appliance.

Disposition sur disque :
  /var/lib/scanoria/feeds/<id>               lien relatif vers la version active
  /var/lib/scanoria/feeds/.store/<id>/<v>/   versions (active et précédente)
  /var/lib/scanoria/feeds/.store/<id>/status.json
Une nouvelle version est construite à côté, puis le lien est remplacé par
rename(2) : une analyse en cours garde l'ancienne base, une base valide n'est
jamais cassée par un échec. Fichiers 0644 et répertoires 0755 (root), lus
en lecture seule par l'utilisateur 65534 des conteneurs.
"""

import gzip
import hashlib
import json
import os
import re
import secrets
import shutil
import tarfile
import urllib.parse
import zipfile

from . import catalogverify, common
from .common import Fail

FEEDS = common.VARLIB + "/feeds"
STORE = FEEDS + "/.store"
ENV_FILE = common.p("/etc/environment")
MAX_OSV_ZIP = 1 << 30
MAX_OSV_ENTRIES = 5_000_000
MAX_MANIFEST = 1 << 20
MAX_TOKEN_DOC = 64 << 10
MAX_OCI_LAYER = 2 << 30
MAX_TRIVY_EXTRACTED = 6 << 30
MAX_METADATA = 64 << 10
DEFAULT_TIMEOUT = 3000
TRIVY_LAYER_TYPE = "application/vnd.aquasec.trivy.db.layer.v1.tar+gzip"
TRIVY_FILES = ("trivy.db", "metadata.json")
MANIFEST_TYPES = ("application/vnd.oci.image.manifest.v1+json",
                  "application/vnd.docker.distribution.manifest.v2+json")
ECOSYSTEM_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9.:-]{0,39}\Z")
OCI_REF_RE = re.compile(
    r"(?P<host>[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?(:[0-9]{1,5})?)"
    r"/(?P<repo>[a-z0-9]+([._/-][a-z0-9]+){0,20})"
    r"(:(?P<tag>[A-Za-z0-9_][A-Za-z0-9._-]{0,127})|@(?P<digest>sha256:[0-9a-f]{64}))\Z")
DIGEST_RE = re.compile(r"sha256:([0-9a-f]{64})\Z")
TOKEN_RE = re.compile(r"[A-Za-z0-9._~+/=-]{1,8192}\Z")
VERSION_DIR_RE = re.compile(r"[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}\Z")
PROXY_RE = re.compile(r"https?://[A-Za-z0-9._~%!$&'()*+,;=:@-]{1,255}/?\Z")
NO_PROXY_RE = re.compile(r"[A-Za-z0-9.,:*/_ -]{0,1000}\Z")
CURL_REASONS = {
    5: "proxy unreachable", 6: "host name does not resolve", 7: "connection refused or unreachable",
    28: "timed out", 35: "TLS handshake failed", 47: "too many redirects", 52: "empty reply",
    56: "connection reset", 60: "certificate not trusted", 63: "download larger than allowed",
}


# --------------------------------------------------------------------------
# Lecture du manifeste
# --------------------------------------------------------------------------

def is_declarative(m):
    """Feed sans image : sa base est téléchargée par le helper (ce module)."""
    return m.get("type") == "feed" and not m.get("image")


def _check_id(mid):
    if not isinstance(mid, str) or not catalogverify.MODULE_ID_RE.match(mid):
        raise Fail("E_INVALID_PARAM", "invalid feed id")
    return mid


def source_of(m):
    src = (m.get("feed") or {}).get("source")
    if not isinstance(src, dict) or src.get("kind") not in ("https", "oci") or not isinstance(src.get("ref"), str):
        raise Fail("E_PRECONDITION", "feed %s declares no supported source" % m.get("id"))
    return src["kind"], src["ref"]


def sources_of(m):
    """ref puis ses sources de secours (feed.source.mirrors), dans l'ordre."""
    kind, ref = source_of(m)
    mirrors = (m["feed"]["source"].get("mirrors") or [])
    if not isinstance(mirrors, list) or len(mirrors) > 4 or not all(isinstance(x, str) for x in mirrors):
        raise Fail("E_PRECONDITION", "feed %s declares invalid mirrors" % m.get("id"))
    return kind, [ref] + [x for x in mirrors if x != ref]


def host_of(kind, ref):
    if kind == "oci":
        mm = OCI_REF_RE.match(ref)
        return mm.group("host") if mm else "?"
    return urllib.parse.urlsplit(ref).netloc or "?"


def source_host(m):
    """Hôtes joints pour télécharger la base (message d'erreur)."""
    try:
        kind, refs = sources_of(m)
    except Fail:
        return "?"
    return ", ".join(dict.fromkeys(host_of(kind, r) for r in refs))


# --------------------------------------------------------------------------
# Téléchargement (curl, HTTPS seul)
# --------------------------------------------------------------------------

def proxy_env():
    """https_proxy et no_proxy de /etc/environment, s'ils sont valides."""
    env = {}
    try:
        with open(ENV_FILE, encoding="utf-8") as f:
            lines = f.read(64 << 10).splitlines()
    except (OSError, UnicodeDecodeError):
        return env
    for line in lines:
        key, sep, value = line.strip().partition("=")
        if not sep:
            continue
        key, value = key.strip(), value.strip().strip("'\"")
        if key.lower() == "https_proxy" and PROXY_RE.match(value):
            env["https_proxy"] = value
        elif key.lower() == "no_proxy" and NO_PROXY_RE.match(value):
            env["no_proxy"] = value
    return env


def user_agent():
    return "scanoria-appliance/%s" % (common.installed_version() or "0.0.0")


class DownloadError(Exception):
    pass


def curl(url, dest, max_size, timeout, headers=(), dump_header=None):
    """Télécharge url dans dest ; retourne le code HTTP. DownloadError si le réseau échoue."""
    if not isinstance(url, str) or not url.startswith("https://") or len(url) > 2048:
        raise DownloadError("only https URLs are allowed")
    timeout = max(10, int(timeout))
    args = ["--proto", "=https", "--proto-redir", "=https", "--tlsv1.2", "--silent",
            "--connect-timeout", "20", "--max-time", str(timeout),
            "--speed-limit", "1024", "--speed-time", "120",
            "--max-filesize", str(max_size), "--location", "--max-redirs", "5",
            "--user-agent", user_agent(), "--output", dest, "--write-out", "%{http_code}"]
    for h in headers:
        args += ["--header", h]
    if dump_header:
        args += ["--dump-header", dump_header]
    args.append(url)
    r = common.run("curl", args, timeout=timeout + 60, env=proxy_env())
    if r.returncode != 0:
        raise DownloadError(CURL_REASONS.get(r.returncode, "network error (curl %d)" % r.returncode))
    try:
        code = int(r.text.strip()[-3:])
    except ValueError:
        raise DownloadError("no HTTP answer")
    if os.path.exists(dest) and os.path.getsize(dest) > max_size:
        raise DownloadError("download larger than allowed")
    return code


def _expect_200(code, what):
    if code != 200:
        raise DownloadError("%s: HTTP %d" % (what, code))


# --------------------------------------------------------------------------
# Source https : OSV par écosystème
# --------------------------------------------------------------------------

def ecosystems_of(m, options):
    ecos = (options or {}).get("ecosystems")
    if ecos is None:
        props = (m.get("options") or {}).get("properties") or {}
        ecos = (props.get("ecosystems") or {}).get("default")
    if not isinstance(ecos, list) or not ecos or len(ecos) > 64:
        raise Fail("E_INVALID_PARAM", "feed %s: no ecosystem to download" % m["id"])
    out = []
    for e in ecos:
        # « . » et « .. » exclus : le nom devient un répertoire.
        if not isinstance(e, str) or not ECOSYSTEM_RE.match(e) or set(e) <= {"."}:
            raise Fail("E_INVALID_PARAM", "invalid ecosystem name")
        if e not in out:
            out.append(e)
    return out


def fetch_osv(m, ref, options, work, deadline):
    if not ref.startswith("https://") or ref.count("{ecosystem}") != 1:
        raise Fail("E_PRECONDITION", "feed %s: invalid source template" % m["id"])
    details = {}
    for eco in ecosystems_of(m, options):
        d = os.path.join(work, "osv-scalibr", eco)
        os.makedirs(d, mode=0o755, exist_ok=True)
        dest = os.path.join(d, "all.zip")
        url = ref.replace("{ecosystem}", urllib.parse.quote(eco, safe=""))
        try:
            _expect_200(curl(url, dest, MAX_OSV_ZIP, deadline.left()), eco)
        except DownloadError as e:
            raise DownloadError("%s: %s" % (eco, e))
        try:
            with zipfile.ZipFile(dest) as z:
                n = len(z.infolist())
        except (zipfile.BadZipFile, OSError):
            raise DownloadError("%s: not a zip archive" % eco)
        if n == 0 or n > MAX_OSV_ENTRIES:
            raise DownloadError("%s: unexpected number of entries (%d)" % (eco, n))
        details[eco] = n
    return {"ecosystems": details}


# --------------------------------------------------------------------------
# Source oci : trivy-db
# --------------------------------------------------------------------------

def parse_oci_ref(ref):
    mm = OCI_REF_RE.match(ref or "")
    if not mm:
        raise Fail("E_PRECONDITION", "invalid OCI reference")
    return mm.group("host"), mm.group("repo"), mm.group("digest") or mm.group("tag")


def _bearer_challenge(header_file):
    """Paramètres du dernier défi « WWW-Authenticate: Bearer » reçu."""
    try:
        with open(header_file, "rb") as f:
            text = f.read(64 << 10).decode("latin-1")
    except OSError:
        return None
    found = None
    for line in text.splitlines():
        k, sep, v = line.partition(":")
        if sep and k.strip().lower() == "www-authenticate" and v.strip().lower().startswith("bearer "):
            found = dict(re.findall(r'([A-Za-z]+)="([^"]{0,1024})"', v))
    return found


def _token(work, chal, repo, deadline):
    realm = (chal or {}).get("realm", "")
    if not realm.startswith("https://") or "?" in realm:
        raise DownloadError("registry asks for an unsupported authentication")
    q = {"scope": "repository:%s:pull" % repo}
    if chal.get("service"):
        q["service"] = chal["service"]
    dest = os.path.join(work, "token.json")
    _expect_200(curl(realm + "?" + urllib.parse.urlencode(q), dest, MAX_TOKEN_DOC, min(120, deadline.left())),
                "registry token")
    try:
        doc = common.load_json_file(dest, MAX_TOKEN_DOC)
    except (OSError, common.JsonError):
        raise DownloadError("registry token unreadable")
    os.unlink(dest)
    tok = doc.get("token") or doc.get("access_token") if isinstance(doc, dict) else None
    if not isinstance(tok, str) or not TOKEN_RE.match(tok):
        raise DownloadError("registry token invalid")
    # Jeton passé par un fichier (jamais dans l'argv), lu par curl « --header @fichier ».
    hfile = os.path.join(work, "auth.header")
    fd = os.open(hfile, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w", encoding="ascii") as f:
        f.write("Authorization: Bearer %s\n" % tok)
    return "@" + hfile


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _get_manifest(work, host, repo, ref, deadline):
    url = "https://%s/v2/%s/manifests/%s" % (host, repo, ref)
    dest, hdr = os.path.join(work, "manifest.json"), os.path.join(work, "manifest.headers")
    accept = "Accept: " + ", ".join(MANIFEST_TYPES)
    code = curl(url, dest, MAX_MANIFEST, min(120, deadline.left()), headers=[accept], dump_header=hdr)
    auth = None
    if code == 401:
        auth = _token(work, _bearer_challenge(hdr), repo, deadline)
        code = curl(url, dest, MAX_MANIFEST, min(120, deadline.left()), headers=[accept, auth])
    _expect_200(code, "manifest")
    with open(dest, "rb") as f:
        raw = f.read(MAX_MANIFEST + 1)
    if ref.startswith("sha256:") and "sha256:" + hashlib.sha256(raw).hexdigest() != ref:
        raise DownloadError("manifest digest mismatch")
    try:
        man = common.loads_strict(raw)
    except common.JsonError:
        raise DownloadError("manifest is not valid JSON")
    if not isinstance(man, dict) or not isinstance(man.get("layers"), list):
        raise DownloadError("unsupported manifest (an image index is not supported)")
    return man, auth


def _pick_layer(man):
    layers = [x for x in man["layers"] if isinstance(x, dict)]
    pick = [x for x in layers if x.get("mediaType") == TRIVY_LAYER_TYPE]
    if not pick and len(layers) == 1:
        pick = layers
    if len(pick) != 1:
        raise DownloadError("manifest has no database layer")
    layer = pick[0]
    dm = DIGEST_RE.match(layer.get("digest") or "")
    size = layer.get("size")
    if not dm or not isinstance(size, int) or isinstance(size, bool) or not 0 < size <= MAX_OCI_LAYER:
        raise DownloadError("invalid database layer")
    return layer["digest"], dm.group(1), size


def extract_trivy(archive, dest):
    """Extrait db.tar.gz dans dest/db : trivy.db et metadata.json, fichiers ordinaires seulement."""
    dbdir = os.path.join(dest, "db")
    os.makedirs(dbdir, mode=0o755, exist_ok=False)
    seen, total = set(), 0
    try:
        with tarfile.open(archive, "r:gz") as tf:
            for i, mem in enumerate(tf):
                if i >= 100:
                    raise DownloadError("too many entries in the database archive")
                parts = [x for x in mem.name.split("/") if x not in ("", ".")]
                if mem.isdir() and not parts:
                    continue
                if (not mem.isreg() or len(parts) != 1 or mem.name.startswith("/")
                        or parts[0] not in TRIVY_FILES or parts[0] in seen):
                    raise DownloadError("unexpected entry in the database archive: %r" % mem.name[:100])
                total += mem.size
                if total > MAX_TRIVY_EXTRACTED:
                    raise DownloadError("database archive too large once extracted")
                seen.add(parts[0])
                src = tf.extractfile(mem)
                fd = os.open(os.path.join(dbdir, parts[0]), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                             0o644)
                with os.fdopen(fd, "wb") as out, src:
                    shutil.copyfileobj(src, out, 1 << 20)
    except (tarfile.TarError, gzip.BadGzipFile, EOFError, OSError, zlib_error()) as e:
        raise DownloadError("database archive unreadable (%s)" % type(e).__name__)
    if seen != set(TRIVY_FILES):
        raise DownloadError("database archive lacks %s" % ", ".join(sorted(set(TRIVY_FILES) - seen)))
    meta_path = os.path.join(dbdir, "metadata.json")
    try:
        meta = common.load_json_file(meta_path, MAX_METADATA)
    except (OSError, common.JsonError):
        raise DownloadError("metadata.json unreadable")
    if not isinstance(meta, dict) or not isinstance(meta.get("Version"), int):
        raise DownloadError("metadata.json has no schema version")
    # Comme « trivy --download-db-only » : date de téléchargement enregistrée.
    meta["DownloadedAt"] = common.iso(common.now())
    tmp = meta_path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(meta, f)
    os.replace(tmp, meta_path)
    return meta


def zlib_error():
    import zlib
    return zlib.error


def fetch_oci(ref, work, deadline):
    host, repo, tag = parse_oci_ref(ref)
    man, auth = _get_manifest(work, host, repo, tag, deadline)
    digest, hexd, size = _pick_layer(man)
    blob = os.path.join(work, "layer.tar.gz")
    url = "https://%s/v2/%s/blobs/%s" % (host, repo, digest)
    # Le jeton ne suit pas une redirection vers un autre hôte (comportement de curl).
    _expect_200(curl(url, blob, size, deadline.left(), headers=[auth] if auth else []), "database layer")
    if os.path.getsize(blob) != size:
        raise DownloadError("database layer has an unexpected size")
    if sha256_file(blob) != hexd:
        raise DownloadError("database layer digest mismatch")
    data = os.path.join(work, "data")
    os.mkdir(data, 0o755)
    meta = extract_trivy(blob, data)
    os.unlink(blob)
    for name in ("manifest.json", "manifest.headers", "auth.header"):
        try:
            os.unlink(os.path.join(work, name))
        except FileNotFoundError:
            pass
    return {"layer": digest, "schema": meta.get("Version"), "upstream_updated_at": meta.get("UpdatedAt")}


# --------------------------------------------------------------------------
# Versions, bascule et état
# --------------------------------------------------------------------------

RETRY_DELAYS = (0, 15, 60)


def _retriable(reason):
    """Panne passagère : limite de débit, erreur serveur ou réseau."""
    return bool(re.search(r"HTTP (429|5[0-9][0-9])\b|timed out|refused|reset|empty reply|no HTTP answer|resolve",
                          reason))


def fetch_any(m, options, work, deadline):
    """Essaie ref puis chaque source de secours, avec relances espacées sur les pannes
    passagères ; retourne (détails, répertoire des données)."""
    import time
    kind, refs = sources_of(m)
    errors = []
    for ref in refs:
        for delay in RETRY_DELAYS:
            if delay:
                if deadline.end - time.monotonic() < delay + 60:
                    break
                time.sleep(0 if common.TEST_ROOT else delay)
            shutil.rmtree(work, ignore_errors=True)
            os.mkdir(work, 0o700)
            try:
                if kind == "https":
                    if not ref.startswith("https://"):
                        raise DownloadError("source is not https")
                    return dict(fetch_osv(m, ref, options, work, deadline), source=ref), work
                return dict(fetch_oci(ref, work, deadline), source=ref), os.path.join(work, "data")
            except DownloadError as e:
                common.log("feed %s: %s: %s" % (m["id"], host_of(kind, ref), e))
                last = "%s: %s" % (host_of(kind, ref), e)
                if not _retriable(str(e)):
                    break
        errors.append(last)
    raise DownloadError("; ".join(errors))


class Deadline:
    def __init__(self, seconds):
        import time
        self._time = time
        self.end = time.monotonic() + max(30, int(seconds))

    def left(self):
        left = int(self.end - self._time.monotonic())
        if left < 10:
            raise DownloadError("timed out")
        return left


def store_dir(mid):
    return os.path.join(STORE, _check_id(mid))


def link_path(mid):
    return os.path.join(FEEDS, _check_id(mid))


def status_file(mid):
    return os.path.join(store_dir(mid), "status.json")


def _dirs():
    for d in (FEEDS, STORE):
        os.makedirs(d, mode=0o755, exist_ok=True)
        os.chmod(d, 0o755)


def _readable(root):
    """Lecture seule pour tous (65534 dans les conteneurs), propriétaire root."""
    for base, dirs, files in os.walk(root):
        os.chmod(base, 0o755)
        for n in files:
            path = os.path.join(base, n)
            st = os.lstat(path)
            if not os.path.isfile(path) or os.path.islink(path):
                raise DownloadError("unexpected file type in the new database")
            if not common.TEST_ROOT and (st.st_uid != 0 or st.st_gid != 0):
                os.chown(path, 0, 0, follow_symlinks=False)
            os.chmod(path, 0o644)


def _du_mb(root):
    total = 0
    for base, _, files in os.walk(root):
        for n in files:
            total += os.lstat(os.path.join(base, n)).st_size
    return round(total / (1 << 20), 1)


def has_data(mid):
    """Vrai si la base active existe et n'est pas vide."""
    lp = link_path(mid)
    try:
        return os.path.isdir(lp) and any(True for _ in os.scandir(lp))
    except OSError:
        return False


def swap(mid, newdir):
    """Le lien <feeds>/<id> pointe désormais vers newdir (rename(2), atomique) ;
    retourne le nom de la version remplacée, ou None."""
    lp = link_path(mid)
    previous = os.path.basename(os.readlink(lp)) if os.path.islink(lp) else None
    if os.path.isdir(lp) and not os.path.islink(lp):
        # Répertoire réel laissé par une version antérieure (0.2 à 0.3.3) : rangé
        # dans le magasin, retiré au prochain nettoyage.
        os.rename(lp, os.path.join(store_dir(mid), "legacy-" + secrets.token_hex(4)))
    tmp = os.path.join(FEEDS, ".%s.%s.link" % (mid, secrets.token_hex(4)))
    os.symlink(os.path.relpath(newdir, FEEDS), tmp)
    os.replace(tmp, lp)
    return previous


def prune(mid, previous=None):
    """Garde la version active et la précédente ; retire le reste (et les essais avortés)."""
    sd = store_dir(mid)
    try:
        active = os.path.basename(os.path.realpath(link_path(mid)))
        names = os.listdir(sd)
    except OSError:
        return
    keep = {active}
    if previous and VERSION_DIR_RE.match(previous):
        keep.add(previous)
    for n in names:
        if n == "status.json" or n in keep:
            continue
        path = os.path.join(sd, n)
        if os.path.isdir(path) and not os.path.islink(path):
            shutil.rmtree(path, ignore_errors=True)


def read_status(mid):
    try:
        st = common.load_json_file(status_file(mid), 64 << 10)
    except (OSError, common.JsonError, Fail):
        return None
    return st if isinstance(st, dict) else None


def write_status(mid, st):
    os.makedirs(store_dir(mid), mode=0o755, exist_ok=True)
    common.write_json(status_file(mid), st, 0o644, group_scanoria=False)


def public_status(mid):
    """{id, updated_at, size_mb, status, error, checked_at} publié dans l'état des modules."""
    st = read_status(mid) or {}
    ready = has_data(mid)
    status = st.get("status") if st.get("status") in ("ok", "stale", "failed") else None
    if not ready:
        status = "missing"
    elif status is None:
        status = "ok"
    return {"id": mid, "updated_at": st.get("updated_at") if ready else None,
            "size_mb": st.get("size_mb") if ready else None, "status": status,
            "error": st.get("error"), "checked_at": st.get("checked_at")}


def refresh(m, options=None, timeout=DEFAULT_TIMEOUT):
    """Télécharge la base du feed m et l'active. Fail(E_FEED_UNAVAILABLE) en cas d'échec,
    la base précédente restant active."""
    mid = _check_id(m.get("id"))
    if not is_declarative(m):
        raise Fail("E_PRECONDITION", "%s is not a downloadable feed" % mid)
    kind, _ = source_of(m)
    _dirs()
    sd = store_dir(mid)
    os.makedirs(sd, mode=0o755, exist_ok=True)
    os.chmod(sd, 0o755)
    need_mb = (m.get("resources") or {}).get("disk_mb")
    if isinstance(need_mb, int) and not isinstance(need_mb, bool):
        vfs = os.statvfs(sd)
        if vfs.f_bavail * vfs.f_frsize < need_mb * (1 << 20):
            raise Fail("E_DISK_SPACE", "not enough disk space for database %s (%d MB needed)" % (mid, need_mb))
    prev = read_status(mid) or {}
    work = os.path.join(sd, ".tmp-" + secrets.token_hex(6))
    started = common.iso(common.now())
    try:
        deadline = Deadline(timeout)
        details, data = fetch_any(m, options, work, deadline)
        _readable(data)
        size = _du_mb(data)
        final = os.path.join(sd, "%s-%s" % (common.now().strftime("%Y%m%dT%H%M%SZ"), secrets.token_hex(4)))
        os.rename(data, final)
        previous = swap(mid, final)
    except (DownloadError, OSError) as e:
        reason = str(e) if isinstance(e, DownloadError) else "local error (%s)" % (e.strerror or type(e).__name__)
        st = dict(prev, checked_at=started, error=reason[:500],
                  status="stale" if has_data(mid) else "failed")
        write_status(mid, st)
        raise Fail("E_FEED_UNAVAILABLE",
                   "database %s cannot be downloaded from the appliance (%s); check access to %s "
                   "or wait for the offline import (0.6)" % (mid, reason, source_host(m)),
                   {"feed": mid, "host": source_host(m), "reason": reason[:500]})
    finally:
        shutil.rmtree(work, ignore_errors=True)
    st = {"id": mid, "source": kind, "updated_at": common.iso(common.now()), "checked_at": started,
          "size_mb": size, "status": "ok", "error": None, "details": details}
    write_status(mid, st)
    prune(mid, previous)
    return public_status(mid)


def remove(mid):
    """Retire la base (lien, versions et état) : désinstallation ou retour arrière."""
    lp = link_path(mid)
    if os.path.islink(lp):
        os.unlink(lp)
    elif os.path.isdir(lp):
        shutil.rmtree(lp, ignore_errors=True)
    shutil.rmtree(store_dir(mid), ignore_errors=True)


def require_ready(manifest):
    """Chaque feed de requires.feeds a une base ; sinon E_FEED_UNAVAILABLE (jamais un code 127)."""
    for fid in (manifest.get("requires") or {}).get("feeds") or []:
        if not has_data(fid):
            raise Fail("E_FEED_UNAVAILABLE", "database %s is empty: %s cannot run without it; "
                       "update the database from the Catalog" % (fid, manifest.get("id")), {"feed": fid})
