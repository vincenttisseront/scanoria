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
  <base>/db/metadata.json ;
- « https » au format « grype-db » (grype-db, 0.5) : la liste publiée par
  Anchore (latest.json, schéma v6) donne l'archive et son empreinte SHA-256,
  vérifiée avant tout usage ; l'archive est ensuite préparée par « grype db
  import » (feed.hydrate : index de la base reconstruits, import.json écrit)
  dans un conteneur jetable confiné, sans réseau, de l'image épinglée du
  manifeste, puis rangée dans la disposition de GRYPE_DB_CACHE_DIR :
  <base>/6/vulnerability.db et <base>/6/import.json ;
- « https » au format epss-csv (EPSS de FIRST, CSV compressé) ou kev-json
  (catalogue KEV de la CISA) : un seul fichier, validé ligne par ligne, puis
  normalisé en <base>/export.jsonl.gz. Le manifeste déclare alors
  « feed.export: {format: jsonl.gz} » et le helper publie ce fichier pour la
  console dans /var/lib/scanoria/feeds-export/<id>.jsonl.gz (contrat 17 de la
  0.5, root:scanoria 0640, écriture atomique). La console ne lit jamais
  /var/lib/scanoria/feeds/.

Rien de téléchargé n'est exécuté (seule une image épinglée lit une base, hors
réseau) et aucun conteneur n'a de réseau : seul curl
(HTTPS, certificat vérifié, tailles et délais bornés, proxy de
/etc/environment s'il existe) sort de l'appliance.

Disposition sur disque :
  /var/lib/scanoria/feeds/<id>               lien relatif vers la version active
  /var/lib/scanoria/feeds/.store/<id>/<v>/   versions (active et précédente)
  /var/lib/scanoria/feeds/.store/<id>/status.json
Une nouvelle version est construite à côté, puis le lien est remplacé par
rename(2) : une analyse déjà lancée garde la base qu'elle a montée (la version
précédente est conservée jusqu'à la bascule suivante), et une base valide n'est
jamais cassée par un échec. Intégrité : HTTPS avec certificat vérifié et, pour
trivy-db, empreinte de la couche annoncée par le manifeste ; aucune signature
de l'éditeur n'existe pour ces bases (les lots hors ligne signés arrivent en 0.6). Fichiers 0640 et répertoires 0750 (root:65534), lus
en lecture seule par l'utilisateur 65534:65534 des conteneurs, et par lui seul.
"""

import gzip
import hashlib
import json
import os
import re
import secrets
import shutil
import stat
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
GRYPE_FORMAT = "grype-db"
GRYPE_MODEL = "6"
GRYPE_FILES = ("vulnerability.db", "import.json")
MAX_LISTING = 64 << 10
MAX_GRYPE_ARCHIVE = 2 << 30
MAX_GRYPE_DB = 8 << 30
# Nom publié par Anchore : vulnerability-db_v6.1.4_2026-11-24T04:16:48Z_1764000000.tar.zst
GRYPE_ARCHIVE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+:-]{0,200}\.tar\.(zst|gz|xz)\Z")
GRYPE_SCHEMA_RE = re.compile(r"v?6\.[0-9]{1,4}\.[0-9]{1,4}\Z")
HYDRATE_TIMEOUT = 1800
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
        os.makedirs(d, mode=0o700, exist_ok=True)
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


def _auth_params(text):
    """Paramètres clé="valeur" d'un défi d'authentification, sans expression rationnelle."""
    out = {}
    for part in text.split(","):
        key, sep, value = part.strip().partition("=")
        value = value.strip()
        if sep and key.isalpha() and len(value) >= 2 and value[0] == value[-1] == '"' and len(value) <= 1026:
            out[key.lower()] = value[1:-1]
    return out


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
            found = _auth_params(v.strip()[len("bearer "):])
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
    os.makedirs(dbdir, mode=0o700, exist_ok=False)
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
                             0o600)
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
    os.mkdir(data, 0o700)
    meta = extract_trivy(blob, data)
    os.unlink(blob)
    for name in ("manifest.json", "manifest.headers", "auth.header"):
        try:
            os.unlink(os.path.join(work, name))
        except FileNotFoundError:
            pass
    return {"layer": digest, "schema": meta.get("Version"), "upstream_updated_at": meta.get("UpdatedAt")}


# --------------------------------------------------------------------------
# Source https au format grype-db (Grype, 0.5)
# --------------------------------------------------------------------------

def grype_listing(path):
    """Contrôle de latest.json : (archive, empreinte hexadécimale, schéma, date de construction)."""
    try:
        doc = common.load_json_file(path, MAX_LISTING)
    except (OSError, common.JsonError, Fail):
        raise DownloadError("listing unreadable")
    if not isinstance(doc, dict):
        raise DownloadError("listing is not an object")
    if doc.get("status") not in (None, "active"):
        raise DownloadError("listing status is %r" % str(doc.get("status"))[:20])
    name, checksum, schema_v = doc.get("path"), doc.get("checksum"), doc.get("schemaVersion")
    if not isinstance(name, str) or not GRYPE_ARCHIVE_RE.match(name) or ".." in name:
        raise DownloadError("listing has an invalid archive path")
    dm = DIGEST_RE.match(checksum) if isinstance(checksum, str) else None
    if not dm:
        raise DownloadError("listing has no sha256 checksum")
    if not isinstance(schema_v, str) or not GRYPE_SCHEMA_RE.match(schema_v):
        raise DownloadError("unsupported database schema %r" % str(schema_v)[:20])
    built = doc.get("built") if isinstance(doc.get("built"), str) and len(doc["built"]) <= 40 else None
    return name, dm.group(1), schema_v, built


def hydrate_spec(m):
    h = (m.get("feed") or {}).get("hydrate")
    if not isinstance(h, dict) or not isinstance(h.get("image"), str) or \
            not catalogverify.IMAGE_RE.match(h["image"]):
        raise Fail("E_PRECONDITION", "feed %s declares no valid hydrate image" % m.get("id"))
    cmd = h.get("command")
    catalogverify._check_command(cmd, m.get("id"))
    env = h.get("env") or {}
    if not isinstance(env, dict) or any(not isinstance(k, str) or not catalogverify.ENV_KEY_RE.match(k)
                                        or not isinstance(v, str) or len(v) > 500 for k, v in env.items()):
        raise Fail("E_PRECONDITION", "feed %s declares an invalid hydrate env" % m.get("id"))
    mem = h.get("memory_mb") if isinstance(h.get("memory_mb"), int) and not isinstance(h.get("memory_mb"), bool) \
        else 2048
    t = h.get("timeout_s") if isinstance(h.get("timeout_s"), int) and not isinstance(h.get("timeout_s"), bool) \
        else HYDRATE_TIMEOUT
    return {"id": "%s-hydrate" % m["id"], "image": h["image"], "command": list(cmd), "env": dict(env),
            "resources": {"min_ram_mb": max(128, min(mem, 16384)), "min_cpu": 1},
            "timeout": max(30, min(t, 7200))}


def hydrate(spec, dbdir, deadline):
    """« grype db import » de l'image épinglée, confiné et sans réseau, sur dbdir monté en /db."""
    from . import testbed
    if common.run("podman", ["image", "exists", spec["image"]], timeout=60).returncode != 0:
        r = common.run("podman", ["pull", "--quiet", spec["image"]], timeout=min(1200, deadline.left()))
        if r.returncode != 0:
            raise DownloadError("cannot pull the image that prepares the database")
    testbed._give_to_container(dbdir)
    rc, hint = testbed.run_confined(spec, spec["command"], [(dbdir, "/db", "rw")],
                                   timeout=min(spec["timeout"], deadline.left()), env=spec["env"], with_stderr=True)
    if rc != 0:
        raise DownloadError("database preparation failed (exit %d)%s" % (rc, (": " + hint[-200:]) if hint else ""))


def collect_grype(cache, data):
    """Copie <cache>/6/{vulnerability.db, import.json} dans data/6 : fichiers ordinaires seulement."""
    src = os.path.join(cache, GRYPE_MODEL)
    if not os.path.isdir(src) or os.path.islink(src):
        raise DownloadError("prepared database not found")
    dst = os.path.join(data, GRYPE_MODEL)
    os.makedirs(dst, mode=0o700)
    total = 0
    for n in GRYPE_FILES:
        p = os.path.join(src, n)
        try:
            fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        except OSError:
            raise DownloadError("prepared database lacks %s" % n)
        with os.fdopen(fd, "rb") as f:
            st = os.fstat(f.fileno())
            if not stat_isreg(st) or st.st_size == 0:
                raise DownloadError("prepared database: %s is not a regular file" % n)
            total += st.st_size
            if total > MAX_GRYPE_DB:
                raise DownloadError("prepared database too large")
            os.set_blocking(f.fileno(), True)
            out = os.open(os.path.join(dst, n), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(out, "wb") as o:
                shutil.copyfileobj(f, o, 1 << 20)
    try:
        meta = common.load_json_file(os.path.join(dst, "import.json"), MAX_METADATA)
    except (OSError, common.JsonError, Fail):
        raise DownloadError("import.json unreadable")
    if not isinstance(meta, dict) or not str(meta.get("digest", "")).startswith("xxh64:"):
        raise DownloadError("import.json has no database digest")
    return meta


def stat_isreg(st):
    import stat as _stat
    return _stat.S_ISREG(st.st_mode)


def fetch_grype(m, ref, work, deadline):
    listing = os.path.join(work, "latest.json")
    _expect_200(curl(ref, listing, MAX_LISTING, min(120, deadline.left())), "listing")
    name, hexd, schema_v, built = grype_listing(listing)
    # Archive à côté de la liste (chemin relatif publié par Anchore), même hôte, HTTPS.
    url = urllib.parse.urljoin(ref, urllib.parse.quote(name))
    if urllib.parse.urlsplit(url).netloc != urllib.parse.urlsplit(ref).netloc:
        raise DownloadError("archive is not next to its listing")
    spec = hydrate_spec(m)
    dbdir = os.path.join(work, "db")
    os.mkdir(dbdir, 0o700)
    archive = os.path.join(dbdir, "archive.tar.zst")
    _expect_200(curl(url, archive, MAX_GRYPE_ARCHIVE, deadline.left()), "database archive")
    if sha256_file(archive) != hexd:
        raise DownloadError("database archive checksum mismatch")
    os.mkdir(os.path.join(dbdir, "cache"), 0o700)   # GRYPE_DB_CACHE_DIR, créé d'avance
    hydrate(spec, dbdir, deadline)
    data = os.path.join(work, "data")
    os.mkdir(data, 0o700)
    meta = collect_grype(os.path.join(dbdir, "cache"), data)
    shutil.rmtree(dbdir, ignore_errors=True)
    os.unlink(listing)
    return {"archive": "sha256:" + hexd, "schema": schema_v, "upstream_updated_at": built,
            "client": meta.get("client_version") if isinstance(meta.get("client_version"), str) else None}, data


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
                    if (m.get("feed") or {}).get("format") == GRYPE_FORMAT:
                        details, data = fetch_grype(m, ref, work, deadline)
                        return dict(details, source=ref), data
                    if feed_format(m) in INTEL_FORMATS:
                        return dict(fetch_intel(m, ref, work, deadline), source=ref), os.path.join(work, "data")
                    return dict(fetch_osv(m, ref, options, work, deadline), source=ref), work
                return dict(fetch_oci(ref, work, deadline), source=ref), os.path.join(work, "data")
            except (TypeError, KeyError, ValueError, AttributeError) as e:
                # Document distant inattendu (types JSON hostiles) : refusé, jamais E_INTERNAL.
                e = DownloadError("unexpected answer (%s)" % type(e).__name__)
                common.log("feed %s: %s: %s" % (m["id"], host_of(kind, ref), e))
                last = "%s: %s" % (host_of(kind, ref), e)
                break
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
        os.makedirs(d, mode=0o700, exist_ok=True)
        os.chmod(d, 0o700)


# Groupe des conteneurs scanners (utilisateur 65534:65534, § 6.4) : la base leur
# est lisible par le groupe seulement, jamais par les autres comptes de l'appliance.
FEED_GID = 65534
DIR_MODE = 0o750
FILE_MODE = 0o640


def _give(path):
    # En root, toujours (y compris en mode test, b18-live) ; un test sans root
    # ne peut pas changer de groupe.
    if os.geteuid() == 0:
        os.chown(path, 0, FEED_GID, follow_symlinks=False)


def _readable(root):
    """Lecture seule pour le groupe des conteneurs (65534), propriétaire root."""
    for base, dirs, files in os.walk(root):
        _give(base)
        os.chmod(base, DIR_MODE)
        for n in files:
            path = os.path.join(base, n)
            if not os.path.isfile(path) or os.path.islink(path):
                raise DownloadError("unexpected file type in the new database")
            _give(path)
            os.chmod(path, FILE_MODE)


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
        legacy = os.path.join(store_dir(mid), "legacy-" + secrets.token_hex(4))
        os.rename(lp, legacy)
    else:
        legacy = None
    tmp = os.path.join(FEEDS, ".%s.%s.link" % (mid, secrets.token_hex(4)))
    try:
        os.symlink(os.path.relpath(newdir, FEEDS), tmp)
        os.replace(tmp, lp)
    except OSError:
        if os.path.lexists(tmp):
            os.unlink(tmp)
        if legacy and not os.path.lexists(lp):
            os.rename(legacy, lp)
        raise
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
    os.makedirs(store_dir(mid), mode=0o700, exist_ok=True)
    common.write_json(status_file(mid), st, 0o600, group_scanoria=False)


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


SHRINK_RATIO = 0.5


def check_shrink(prev, details, size_mb):
    """Refuse une base nettement plus petite que la base active (réponse dégradée,
    miroir incomplet) : la bonne base est gardée et l'échec signalé."""
    if prev.get("status") not in ("ok", "stale"):
        return
    old_eco = (prev.get("details") or {}).get("ecosystems") or {}
    for eco, n in (details.get("ecosystems") or {}).items():
        old = old_eco.get(eco)
        if isinstance(old, int) and old > 0 and n < old * SHRINK_RATIO:
            raise DownloadError("%s: %d entries instead of %d, new database refused" % (eco, n, old))
    old_rows = (prev.get("details") or {}).get("rows")
    rows = details.get("rows")
    if isinstance(old_rows, int) and old_rows > 0 and isinstance(rows, int) and rows < old_rows * SHRINK_RATIO:
        raise DownloadError("%d entries instead of %d, new database refused" % (rows, old_rows))
    old_size = prev.get("size_mb")
    if (details.get("layer") or details.get("archive")) and isinstance(old_size, (int, float)) and old_size > 0 \
            and size_mb < old_size * SHRINK_RATIO:
        raise DownloadError("database shrank from %s MB to %s MB, new database refused" % (old_size, size_mb))


def refresh(m, options=None, timeout=DEFAULT_TIMEOUT):
    """Télécharge la base du feed m et l'active. Fail(E_FEED_UNAVAILABLE) en cas d'échec,
    la base précédente restant active."""
    mid = _check_id(m.get("id"))
    if not is_declarative(m):
        raise Fail("E_PRECONDITION", "%s is not a downloadable feed" % mid)
    kind, _ = source_of(m)
    _dirs()
    sd = store_dir(mid)
    os.makedirs(sd, mode=0o700, exist_ok=True)
    os.chmod(sd, 0o700)
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
        check_shrink(prev, details, size)
        final = os.path.join(sd, "%s-%s" % (common.now().strftime("%Y%m%dT%H%M%SZ"), secrets.token_hex(4)))
        os.rename(data, final)
        previous = swap(mid, final)
        st = {"id": mid, "source": kind, "updated_at": common.iso(common.now()), "checked_at": started,
              "size_mb": size, "status": "ok", "error": None, "details": details}
        write_status(mid, st)
        prune(mid, previous)
    except (DownloadError, OSError) as e:
        reason = str(e) if isinstance(e, DownloadError) else "local error (%s)" % (e.strerror or type(e).__name__)
        st = dict(prev, checked_at=started, error=reason[:500],
                  status="stale" if has_data(mid) else "failed")
        try:
            write_status(mid, st)
        except OSError:
            pass
        raise Fail("E_FEED_UNAVAILABLE",
                   "database %s cannot be downloaded from the appliance (%s); check access to %s "
                   "or wait for the offline import (0.6)" % (mid, reason, source_host(m)),
                   {"feed": mid, "host": source_host(m), "reason": reason[:500]})
    finally:
        shutil.rmtree(work, ignore_errors=True)
    if export_format(m):
        publish_export(mid)
    return public_status(mid)


def remove(mid):
    """Retire la base (lien, versions et état) : désinstallation ou retour arrière."""
    lp = link_path(mid)
    if os.path.islink(lp):
        os.unlink(lp)
    elif os.path.isdir(lp):
        shutil.rmtree(lp, ignore_errors=True)
    shutil.rmtree(store_dir(mid), ignore_errors=True)
    remove_export(mid)


def require_ready(manifest):
    """Chaque feed de requires.feeds a une base ; sinon E_FEED_UNAVAILABLE (jamais un code 127)."""
    for fid in (manifest.get("requires") or {}).get("feeds") or []:
        if not has_data(fid):
            raise Fail("E_FEED_UNAVAILABLE", "database %s is empty: %s cannot run without it; "
                       "update the database from the Catalog" % (fid, manifest.get("id")), {"feed": fid})


# --------------------------------------------------------------------------
# Renseignement sur les vulnérabilités (0.5, H3) : EPSS et KEV, export pour la
# console (contrat 17)
# --------------------------------------------------------------------------

EXPORT_DIR = common.VARLIB + "/feeds-export"
EXPORT_FILE = "export.jsonl.gz"
INTEL_FORMATS = ("epss-csv", "kev-json")
MAX_EPSS_GZ = 64 << 20
MAX_EPSS_CSV = 512 << 20
MAX_EPSS_ROWS = 2_000_000
MAX_KEV_JSON = 64 << 20
MAX_KEV_ROWS = 200_000
MAX_CSV_LINE = 4096
CVE_RE = re.compile(r"CVE-[0-9]{4}-[0-9]{4,12}\Z")
DAY_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}\Z")
EPSS_META_RE = re.compile(r"#model_version:([A-Za-z0-9._-]{1,40}),score_date:([0-9]{4}-[0-9]{2}-[0-9]{2})")


def feed_format(m):
    return (m.get("feed") or {}).get("format")


def export_format(m):
    """« jsonl.gz » si le manifeste demande l'export pour la console, sinon None."""
    exp = (m.get("feed") or {}).get("export")
    if exp is None:
        return None
    if not isinstance(exp, dict) or exp.get("format") != "jsonl.gz":
        raise Fail("E_PRECONDITION", "feed %s declares an unsupported export" % m.get("id"))
    return "jsonl.gz"


def _unit(text, what, line):
    """Nombre dans [0, 1], écrit en décimal simple (aucun nan, inf ni exposant hostile)."""
    if not re.match(r"[0-9]{0,2}(\.[0-9]{1,12})?([eE]-?[0-9]{1,2})?\Z", text) or not re.search(r"[0-9]", text):
        raise DownloadError("line %d: invalid %s value" % (line, what))
    v = float(text)
    if not 0.0 <= v <= 1.0:
        raise DownloadError("line %d: %s out of range" % (line, what))
    return v


def parse_epss(path, out):
    """CSV EPSS compressé (« #model_version:…,score_date:… », puis cve,epss,percentile).

    Écrit une ligne {vuln_id, epss, epss_percentile} par CVE dans out ; retourne
    les détails. Toute ligne invalide refuse le fichier entier : la base
    précédente reste active."""
    seen = set()
    meta = {}
    header = None
    total = 0
    try:
        with gzip.open(path, "rb") as f, gzip.GzipFile(out, "wb", mtime=0) as w:
            for n, raw in enumerate(iter(lambda: f.readline(MAX_CSV_LINE + 1), b""), start=1):
                total += len(raw)
                if total > MAX_EPSS_CSV:
                    raise DownloadError("EPSS file too large once uncompressed")
                if len(raw) > MAX_CSV_LINE:
                    raise DownloadError("line %d: too long" % n)
                try:
                    text = raw.decode("ascii").strip()
                except UnicodeDecodeError:
                    raise DownloadError("line %d: not ASCII" % n)
                if not text:
                    continue
                if text.startswith("#"):
                    mm = EPSS_META_RE.match(text)
                    if header is None and mm:
                        meta = {"model_version": mm.group(1), "score_date": mm.group(2)}
                    continue
                cols = [c.strip() for c in text.split(",")]
                if header is None:
                    header = [c.lower() for c in cols]
                    if not {"cve", "epss", "percentile"} <= set(header):
                        raise DownloadError("EPSS header lacks cve, epss or percentile")
                    idx = (header.index("cve"), header.index("epss"), header.index("percentile"))
                    continue
                if len(cols) != len(header):
                    raise DownloadError("line %d: %d columns instead of %d" % (n, len(cols), len(header)))
                cve = cols[idx[0]].upper()
                if not CVE_RE.match(cve):
                    raise DownloadError("line %d: invalid CVE identifier" % n)
                if cve in seen:
                    raise DownloadError("line %d: duplicate %s" % (n, cve))
                seen.add(cve)
                if len(seen) > MAX_EPSS_ROWS:
                    raise DownloadError("too many EPSS rows")
                row = {"vuln_id": cve, "epss": _unit(cols[idx[1]], "epss", n),
                       "epss_percentile": _unit(cols[idx[2]], "percentile", n)}
                w.write((json.dumps(row, separators=(",", ":")) + "\n").encode("ascii"))
    except (OSError, EOFError, zlib_error()) as e:
        if isinstance(e, DownloadError):
            raise
        raise DownloadError("EPSS file unreadable (%s)" % type(e).__name__)
    if header is None or not seen:
        raise DownloadError("EPSS file has no scores")
    return dict(meta, rows=len(seen))


def _valid_day(text):
    import datetime
    if not isinstance(text, str) or not DAY_RE.match(text):
        return False
    try:
        datetime.date.fromisoformat(text)
    except ValueError:
        return False
    return True


def parse_kev(path, out):
    """Catalogue KEV de la CISA (JSON) → une ligne {vuln_id, kev: true, kev_added} par CVE."""
    try:
        doc = common.load_json_file(path, MAX_KEV_JSON)
    except (OSError, common.JsonError):
        raise DownloadError("KEV catalog is not valid JSON")
    if not isinstance(doc, dict) or not isinstance(doc.get("vulnerabilities"), list):
        raise DownloadError("KEV catalog has no vulnerability list")
    vulns = doc["vulnerabilities"]
    if not vulns or len(vulns) > MAX_KEV_ROWS:
        raise DownloadError("KEV catalog has an unexpected number of entries (%d)" % len(vulns))
    count = doc.get("count")
    if isinstance(count, int) and not isinstance(count, bool) and count != len(vulns):
        raise DownloadError("KEV catalog announces %d entries but lists %d" % (count, len(vulns)))
    rows = {}
    for i, v in enumerate(vulns):
        if not isinstance(v, dict):
            raise DownloadError("KEV entry %d is not an object" % i)
        cve = v.get("cveID")
        if not isinstance(cve, str) or not CVE_RE.match(cve.strip().upper()):
            raise DownloadError("KEV entry %d: invalid CVE identifier" % i)
        added = v.get("dateAdded")
        if not _valid_day(added):
            raise DownloadError("KEV entry %d: invalid dateAdded" % i)
        cve = cve.strip().upper()
        # Une CVE listée deux fois garde sa première date d'ajout.
        if cve not in rows or added < rows[cve]:
            rows[cve] = added
    with gzip.GzipFile(out, "wb", mtime=0) as w:
        for cve in sorted(rows):
            w.write((json.dumps({"vuln_id": cve, "kev": True, "kev_added": rows[cve]},
                                separators=(",", ":")) + "\n").encode("ascii"))
    version = doc.get("catalogVersion")
    return {"rows": len(rows),
            "catalog_version": version if isinstance(version, str) and len(version) <= 40 else None}


def fetch_intel(m, ref, work, deadline):
    """Source https d'un seul fichier (EPSS ou KEV) → <work>/data/export.jsonl.gz."""
    fmt = feed_format(m)
    if "{" in ref:
        raise Fail("E_PRECONDITION", "feed %s: invalid source" % m["id"])
    dest = os.path.join(work, "download")
    _expect_200(curl(ref, dest, MAX_EPSS_GZ if fmt == "epss-csv" else MAX_KEV_JSON, deadline.left()), fmt)
    data = os.path.join(work, "data")
    os.mkdir(data, 0o700)
    out = os.path.join(data, EXPORT_FILE)
    details = parse_epss(dest, out) if fmt == "epss-csv" else parse_kev(dest, out)
    os.unlink(dest)
    return details


def export_path(mid):
    return os.path.join(EXPORT_DIR, "%s.jsonl.gz" % _check_id(mid))


def publish_export(mid):
    """Copie l'export de la base active vers feeds-export/<id>.jsonl.gz (root:scanoria
    0640, rename(2) atomique). E_EXPORT_FAILED si la copie échoue : la base reste
    active et la console garde l'import précédent."""
    src = os.path.join(link_path(mid), EXPORT_FILE)
    try:
        fd = os.open(src, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError:
        raise Fail("E_EXPORT_FAILED", "database %s has no export for the console" % mid, {"feed": mid})
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_size > MAX_EPSS_GZ * 4:
            raise Fail("E_EXPORT_FAILED", "database %s: unexpected export file" % mid, {"feed": mid})
        with os.fdopen(fd, "rb") as f:
            fd = None
            data = f.read(MAX_EPSS_GZ * 4 + 1)
        common.shared_dir(EXPORT_DIR)
        common.atomic_write(export_path(mid), data, 0o640, group_scanoria=True)
    except OSError as e:
        raise Fail("E_EXPORT_FAILED", "database %s cannot be exported for the console (%s)"
                   % (mid, e.strerror or type(e).__name__), {"feed": mid})
    finally:
        if fd is not None:
            os.close(fd)
    return export_path(mid)


def remove_export(mid):
    try:
        os.unlink(export_path(mid))
    except FileNotFoundError:
        pass
