# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Vincent Tisseront
"""Lots hors ligne signés (chantier A de la 0.6, contrat 19, CLAUDE.md § 9).

  export-bundle   une appliance connectée écrit, sous /var/lib/scanoria/bundles/,
                  scanoria-bundle-<horodatage>.tar : manifest.json,
                  manifest.json.sig (Ed25519 détachée, base64, sur les octets du
                  manifeste, clé de l'appliance) puis les fichiers déclarés ;
  import-bundle   une appliance hors ligne vérifie et applique un lot téléversé.

Contenu d'un lot (chemins fixes, tous déclarés dans le manifeste avec leur
SHA-256 et leur taille) :
  catalog/SHA256SUMS, catalog/SHA256SUMS.sig, catalog/catalog-index.json
      l'index officiel, à l'octet près : sa signature officielle (clé épinglée
      update-pubkey.pem) porte sur ces octets, il voyage donc comme fichier ;
      le manifeste en garde le numéro et l'empreinte ;
  testbeds/testbed-<id>-<version>.tar.zst   bancs d'essai (F12) des scanners ;
  feeds/<id>.tar     la base active d'un module feed, telle que l'appliance
                     l'a téléchargée (même disposition que feeds.py) ;
  images/<id>-<version>.oci.tar   image du module dans une disposition OCI
                     (oci-layout, index.json, blobs/sha256/…) qui garde
                     l'empreinte épinglée : l'index multi-architecture
                     d'origine et la seule instance de l'architecture de la
                     machine. « podman save » ne convient pas : il réécrit le
                     manifeste et l'image chargée n'est plus trouvée par
                     <dépôt>@sha256:<empreinte> (mesuré, podman 4.9) ; l'export
                     relit donc le registre avec skopeo (--preserve-digests).

Import (rien n'est installé : le catalogue montre ensuite les modules
disponibles hors ligne, et l'installation reste une action confirmée) :
  1. l'archive est lue en flux, sans jamais être extraite par tarfile : le
     premier membre doit être manifest.json (16 Mio au plus), le second sa
     signature ; la signature est vérifiée avec une clé du magasin root
     (offline.trusted_key) avant toute autre lecture du manifeste ;
  2. chaque membre suivant doit être un fichier ordinaire déclaré, à son
     chemin exact, de la taille déclarée, une seule fois ; il est recopié en
     calculant son SHA-256. Lien, répertoire, chemin « .. », membre non
     déclaré, doublon, archive tronquée : refus ;
  3. l'index du lot est vérifié avec la clé officielle épinglée, et chaque
     image doit y figurer avec la même empreinte : un lot n'introduit jamais
     une image inconnue du catalogue officiel ; chaque banc d'essai doit y
     figurer avec la même empreinte ; chaque base doit être un module feed
     de l'index ;
  4. tout est vérifié avant le premier changement ; puis catalogue (s'il est
     plus récent), bancs d'essai, images (skopeo vers le stockage de podman,
     puis contrôle « podman image exists ») et bases (bascule atomique de
     feeds.py, date d'origine conservée : l'âge mesuré par G16 reste celui du
     téléchargement initial ; une base plus ancienne que la base active n'est
     jamais appliquée).
"""

import base64
import hashlib
import io
import json
import os
import platform
import re
import secrets
import shutil
import stat
import tarfile

from . import catalogverify, common, feeds, offline, schema, selfupdate
from .common import Fail, set_step

BUNDLES = common.VARLIB + "/bundles"
WORK = BUNDLES + "/.work"
TESTBEDS = catalogverify.CATALOG_DIR + "/testbeds"
UPLOADS = selfupdate.UPLOADS
UPLOAD_NAME = "bundle.tar"

FORMAT = 1
MAX_MANIFEST = 16 << 20
MAX_SIG = 200
MAX_BUNDLE = 64 << 30
MAX_FILE = 16 << 30
MAX_ENTRIES = 1024
MAX_LAYOUT_ENTRIES = 512
MAX_FEED_ENTRIES = 200_000
MAX_INDEX_JSON = 64 << 10
MAX_IMAGE_MANIFEST = 4 << 20
DEFAULT_KEEP = 2

BUNDLE_RE = re.compile(r"scanoria-bundle-([0-9]{8}T[0-9]{6}Z)\.tar\Z", re.ASCII)
HEX_RE = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
DIGEST_RE = re.compile(r"sha256:([0-9a-f]{64})\Z", re.ASCII)
CATALOG_FILES = ("catalog/SHA256SUMS", "catalog/SHA256SUMS.sig", "catalog/catalog-index.json")
PATH_RES = (
    re.compile(r"catalog/(SHA256SUMS|SHA256SUMS\.sig|catalog-index\.json)\Z", re.ASCII),
    re.compile(r"testbeds/testbed-[a-z0-9][a-z0-9-]{1,40}-[0-9A-Za-z][0-9A-Za-z.+_-]{0,63}\.tar\.zst\Z", re.ASCII),
    re.compile(r"feeds/[a-z0-9][a-z0-9-]{1,40}\.tar\Z", re.ASCII),
    re.compile(r"images/[a-z0-9][a-z0-9-]{1,40}-[0-9A-Za-z][0-9A-Za-z.+_-]{0,63}\.oci\.tar\Z", re.ASCII),
)
INDEX_TYPES = ("application/vnd.oci.image.index.v1+json",
               "application/vnd.docker.distribution.manifest.list.v2+json")
MANIFEST_TYPES = ("application/vnd.oci.image.manifest.v1+json",
                  "application/vnd.docker.distribution.manifest.v2+json")


def declared_path_ok(path):
    return isinstance(path, str) and ".." not in path and any(r.match(path) for r in PATH_RES)


def _sha256_file(path):
    return selfupdate.sha256_file(path)


def _mkdir_private(path):
    os.makedirs(path, mode=0o700, exist_ok=True)
    os.chmod(path, 0o700)


def _new_work(tag):
    _mkdir_private(BUNDLES)
    os.chmod(BUNDLES, 0o750)
    if not common.TEST_ROOT:
        os.chown(BUNDLES, 0, common.scanoria_ids()[1])
    _mkdir_private(WORK)
    d = os.path.join(WORK, "%s-%s" % (tag, secrets.token_hex(6)))
    os.mkdir(d, 0o700)
    return d


def _free_bytes(path):
    v = os.statvfs(path)
    return v.f_bavail * v.f_frsize


def host_arch():
    """Architecture de la machine au sens OCI (amd64, arm64…)."""
    m = platform.machine().lower()
    return {"x86_64": "amd64", "amd64": "amd64", "aarch64": "arm64", "arm64": "arm64"}.get(m, m)


def image_ref(image):
    """(dépôt sans étiquette, empreinte « sha256:… ») d'une image épinglée du catalogue."""
    if not isinstance(image, str) or not catalogverify.IMAGE_RE.match(image):
        raise Fail("E_BUNDLE_IMAGE", "image is not pinned by digest")
    name, digest = image.rsplit("@", 1)
    last = name.rsplit("/", 1)
    if ":" in last[-1]:
        name = name[:name.rfind(":")]
    return name, digest


def _json_bytes(raw, limit, what):
    if len(raw) > limit:
        raise Fail("E_BUNDLE_IMAGE", "%s too large" % what)
    try:
        obj = common.loads_strict(raw)
    except common.JsonError:
        raise Fail("E_BUNDLE_IMAGE", "%s is not valid JSON" % what)
    if not isinstance(obj, dict):
        raise Fail("E_BUNDLE_IMAGE", "%s is not an object" % what)
    return obj


def _descriptor(d, what):
    if not isinstance(d, dict):
        raise Fail("E_BUNDLE_IMAGE", "%s: invalid descriptor" % what)
    m = DIGEST_RE.match(d.get("digest") or "") if isinstance(d.get("digest"), str) else None
    size = d.get("size")
    if not m or not isinstance(size, int) or isinstance(size, bool) or not 0 <= size <= MAX_FILE:
        raise Fail("E_BUNDLE_IMAGE", "%s: invalid descriptor" % what)
    return m.group(1), size


def pick_instance(top, arch=None):
    """Instance linux/<arch> d'un index multi-architecture : (empreinte hex, taille)."""
    arch = arch or host_arch()
    found = []
    for d in top.get("manifests") or []:
        plat = d.get("platform") if isinstance(d, dict) else None
        if isinstance(plat, dict) and plat.get("os") == "linux" and plat.get("architecture") == arch \
                and plat.get("variant") in (None, "v8"):
            found.append(_descriptor(d, "index entry"))
    if not found:
        raise Fail("E_BUNDLE_IMAGE", "image has no linux/%s instance" % arch)
    return found[0]


# --------------------------------------------------------------------------
# Disposition OCI d'une image (contrôle complet, partagé par l'import et le miroir)
# --------------------------------------------------------------------------

def _hash_copy(src, dst_path, limit):
    """Copie le flux src dans dst_path (création exclusive, 0600) ; retourne (sha256, taille)."""
    h, n = hashlib.sha256(), 0
    fd = os.open(dst_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as out:
        while True:
            chunk = src.read(1 << 20)
            if not chunk:
                break
            n += len(chunk)
            if n > limit:
                raise Fail("E_BUNDLE_ARCHIVE", "member larger than declared")
            h.update(chunk)
            out.write(chunk)
    return h.hexdigest(), n


def extract_layout(tar_path, dest):
    """Extrait une archive de disposition OCI : oci-layout, index.json et
    blobs/sha256/<hex> seulement, fichiers ordinaires, chaque blob vérifié par
    son nom. Retourne {hex: taille}."""
    os.mkdir(dest, 0o700)
    os.mkdir(os.path.join(dest, "blobs"), 0o700)
    os.mkdir(os.path.join(dest, "blobs", "sha256"), 0o700)
    blobs, seen = {}, set()
    try:
        with tarfile.open(tar_path, "r:") as tf:
            for i, mem in enumerate(tf):
                if i >= MAX_LAYOUT_ENTRIES:
                    raise Fail("E_BUNDLE_IMAGE", "too many entries in an image archive")
                name = mem.name
                if mem.isdir() and name.rstrip("/") in ("blobs", "blobs/sha256"):
                    continue
                if not mem.isreg() or name in seen or ".." in name or name.startswith("/"):
                    raise Fail("E_BUNDLE_IMAGE", "unexpected entry in an image archive: %r" % name[:80])
                seen.add(name)
                src = tf.extractfile(mem)
                if name in ("oci-layout", "index.json"):
                    if mem.size > MAX_INDEX_JSON:
                        raise Fail("E_BUNDLE_IMAGE", "%s too large" % name)
                    _hash_copy(src, os.path.join(dest, name), MAX_INDEX_JSON)
                    continue
                parts = name.split("/")
                if len(parts) != 3 or parts[:2] != ["blobs", "sha256"] or not HEX_RE.match(parts[2]):
                    raise Fail("E_BUNDLE_IMAGE", "unexpected entry in an image archive: %r" % name[:80])
                digest, size = _hash_copy(src, os.path.join(dest, name), MAX_FILE)
                if digest != parts[2]:
                    raise Fail("E_BUNDLE_CHECKSUM", "image blob %s… does not match its digest" % parts[2][:12])
                blobs[digest] = size
    except (tarfile.TarError, EOFError, OSError) as e:
        if isinstance(e, Fail):
            raise
        raise Fail("E_BUNDLE_ARCHIVE", "image archive unreadable (%s)" % type(e).__name__)
    for n in ("oci-layout", "index.json"):
        if n not in seen:
            raise Fail("E_BUNDLE_IMAGE", "image archive lacks %s" % n)
    return blobs


def check_layout(dest, blobs, digest):
    """Disposition extraite : index.json désigne l'empreinte épinglée ; l'image
    (index puis une instance, ou manifeste seul) est complète ; aucun blob en
    trop. Retourne l'empreinte hexadécimale de l'instance chargée."""
    want = DIGEST_RE.match(digest or "")
    if not want:
        raise Fail("E_BUNDLE_IMAGE", "invalid image digest")
    with open(os.path.join(dest, "index.json"), "rb") as f:
        idx = _json_bytes(f.read(MAX_INDEX_JSON + 1), MAX_INDEX_JSON, "index.json")
    if idx.get("schemaVersion") != 2 or not isinstance(idx.get("manifests"), list) or len(idx["manifests"]) != 1:
        raise Fail("E_BUNDLE_IMAGE", "index.json must reference exactly one image")
    top_hex, top_size = _descriptor(idx["manifests"][0], "index.json")
    if top_hex != want.group(1):
        raise Fail("E_BUNDLE_IMAGE", "image archive does not carry the pinned digest")
    if blobs.get(top_hex) != top_size:
        raise Fail("E_BUNDLE_IMAGE", "pinned manifest missing from the image archive")
    used = {top_hex}

    def load(hexd):
        with open(os.path.join(dest, "blobs", "sha256", hexd), "rb") as f:
            return _json_bytes(f.read(MAX_IMAGE_MANIFEST + 1), MAX_IMAGE_MANIFEST, "image manifest")

    top = load(top_hex)
    inst_hex = top_hex
    if isinstance(top.get("manifests"), list):
        present = []
        for d in top["manifests"]:
            h, size = _descriptor(d, "index entry")
            if h in blobs:
                if blobs[h] != size:
                    raise Fail("E_BUNDLE_IMAGE", "image instance has an unexpected size")
                present.append(h)
        if len(present) != 1:
            raise Fail("E_BUNDLE_IMAGE", "image archive must carry exactly one instance")
        inst_hex = present[0]
        used.add(inst_hex)
        inst = load(inst_hex)
    else:
        inst = top
    if not isinstance(inst.get("layers"), list) or not inst.get("config"):
        raise Fail("E_BUNDLE_IMAGE", "unsupported image manifest")
    for d in [inst["config"]] + inst["layers"]:
        h, size = _descriptor(d, "layer")
        if blobs.get(h) != size:
            raise Fail("E_BUNDLE_IMAGE", "image archive lacks a layer or its configuration")
        used.add(h)
    extra = set(blobs) - used
    if extra:
        raise Fail("E_BUNDLE_IMAGE", "image archive carries an undeclared blob (%s…)" % sorted(extra)[0][:12])
    return inst_hex


def load_layout(dest, image, timeout):
    """Charge la disposition vérifiée dans le stockage de podman sous <dépôt>@<empreinte>."""
    repo, digest = image_ref(image)
    r = common.run("skopeo", ["copy", "--quiet", "--preserve-digests", "oci:" + dest,
                              "containers-storage:%s@%s" % (repo, digest)], timeout=timeout, stderr_tail=400)
    if r.returncode != 0:
        raise Fail("E_BUNDLE_IMAGE", "image %s could not be loaded (%s)" % (
            repo, (r.stderr or b"").decode("utf-8", "replace").strip()[-200:] or "skopeo %d" % r.returncode))
    if common.run("podman", ["image", "exists", "%s@%s" % (repo, digest)], timeout=60).returncode != 0:
        raise Fail("E_BUNDLE_IMAGE", "image %s is not found by its digest once loaded" % repo)


# --------------------------------------------------------------------------
# Export d'une image (appliance connectée : relit le registre)
# --------------------------------------------------------------------------

def _skopeo_env():
    env = feeds.proxy_env()
    if "https_proxy" in env:
        env["HTTPS_PROXY"] = env["https_proxy"]
    if "no_proxy" in env:
        env["NO_PROXY"] = env["no_proxy"]
    return env


def _inspect_raw(ref, timeout):
    r = common.run("skopeo", ["inspect", "--raw", "--retry-times", "2", "docker://" + ref],
                   timeout=timeout, env=_skopeo_env(), stdout_limit=MAX_IMAGE_MANIFEST + 1, stderr_tail=400)
    if r.returncode != 0:
        raise Fail("E_BUNDLE_SOURCE", "registry unreachable for %s" % ref.split("@")[0])
    return r.stdout


def remote_plan(image, timeout=120):
    """(octets du manifeste épinglé, instance hex ou None, taille totale estimée)."""
    repo, digest = image_ref(image)
    raw = _inspect_raw("%s@%s" % (repo, digest), timeout)
    if "sha256:" + hashlib.sha256(raw).hexdigest() != digest:
        raise Fail("E_BUNDLE_SOURCE", "registry returned another manifest for %s" % repo)
    top = _json_bytes(raw, MAX_IMAGE_MANIFEST, "image manifest")
    inst_hex, inst_raw = None, raw
    if isinstance(top.get("manifests"), list):
        inst_hex, _ = pick_instance(top)
        inst_raw = _inspect_raw("%s@sha256:%s" % (repo, inst_hex), timeout)
        if hashlib.sha256(inst_raw).hexdigest() != inst_hex:
            raise Fail("E_BUNDLE_SOURCE", "registry returned another instance for %s" % repo)
    inst = _json_bytes(inst_raw, MAX_IMAGE_MANIFEST, "image manifest")
    total = len(raw) + len(inst_raw)
    for d in [inst.get("config")] + list(inst.get("layers") or []):
        total += _descriptor(d, "layer")[1]
    return raw, inst_hex, total


def _tar_add(tf, path, arcname, mtime):
    info = tarfile.TarInfo(arcname)
    st = os.stat(path)
    info.size, info.mode, info.mtime = st.st_size, 0o644, mtime
    info.uid = info.gid = 0
    info.uname = info.gname = "root"
    with open(path, "rb") as f:
        tf.addfile(info, f)


def export_image(image, dest_tar, work, timeout):
    """Écrit l'archive de disposition OCI de image dans dest_tar ; retourne sa taille."""
    repo, digest = image_ref(image)
    raw, inst_hex, _ = remote_plan(image, timeout=min(timeout, 300))
    src = "%s@sha256:%s" % (repo, inst_hex) if inst_hex else "%s@%s" % (repo, digest)
    d = os.path.join(work, "dir-" + secrets.token_hex(4))
    r = common.run("skopeo", ["copy", "--quiet", "--retry-times", "2", "--preserve-digests",
                              "docker://" + src, "dir:" + d], timeout=timeout, env=_skopeo_env(), stderr_tail=400)
    if r.returncode != 0:
        raise Fail("E_BUNDLE_SOURCE", "cannot download the image of %s" % repo)
    lay = os.path.join(work, "layout-" + secrets.token_hex(4))
    os.makedirs(os.path.join(lay, "blobs", "sha256"), mode=0o700)
    blobs = os.path.join(lay, "blobs", "sha256")
    top_hex = DIGEST_RE.match(digest).group(1)
    with open(os.path.join(blobs, top_hex), "wb") as f:
        f.write(raw)
    if inst_hex:
        os.rename(os.path.join(d, "manifest.json"), os.path.join(blobs, inst_hex))
    else:
        os.unlink(os.path.join(d, "manifest.json"))
    for n in os.listdir(d):
        if HEX_RE.match(n):
            os.rename(os.path.join(d, n), os.path.join(blobs, n))
    shutil.rmtree(d, ignore_errors=True)
    top = _json_bytes(raw, MAX_IMAGE_MANIFEST, "image manifest")
    mt = top.get("mediaType") if isinstance(top.get("mediaType"), str) else (
        INDEX_TYPES[0] if "manifests" in top else MANIFEST_TYPES[0])
    with open(os.path.join(lay, "oci-layout"), "w", encoding="ascii") as f:
        f.write('{"imageLayoutVersion":"1.0.0"}')
    with open(os.path.join(lay, "index.json"), "w", encoding="ascii") as f:
        json.dump({"schemaVersion": 2, "manifests": [{"mediaType": mt, "digest": digest, "size": len(raw)}]},
                  f, separators=(",", ":"))
    present = {n: os.path.getsize(os.path.join(blobs, n)) for n in os.listdir(blobs)}
    check_layout(lay, present, digest)   # l'export ne produit jamais ce que l'import refuserait
    with tarfile.open(dest_tar, "w", format=tarfile.PAX_FORMAT) as tf:
        _tar_add(tf, os.path.join(lay, "oci-layout"), "oci-layout", 0)
        _tar_add(tf, os.path.join(lay, "index.json"), "index.json", 0)
        for n in sorted(present):
            _tar_add(tf, os.path.join(blobs, n), "blobs/sha256/" + n, 0)
    shutil.rmtree(lay, ignore_errors=True)
    return os.path.getsize(dest_tar)


# --------------------------------------------------------------------------
# Bases (feeds) : archive de la base active, et extraction contrôlée
# --------------------------------------------------------------------------

def tar_feed(mid, dest_tar):
    base = os.path.realpath(feeds.link_path(mid))
    store = os.path.realpath(feeds.store_dir(mid))
    if not base.startswith(store + os.sep) or not feeds.has_data(mid):
        raise Fail("E_BUNDLE_FEED", "database %s has no active version" % mid)
    with tarfile.open(dest_tar, "w", format=tarfile.PAX_FORMAT) as tf:
        for root, dirs, files in os.walk(base):
            dirs.sort()
            for n in sorted(files):
                path = os.path.join(root, n)
                if os.path.islink(path) or not os.path.isfile(path):
                    raise Fail("E_BUNDLE_FEED", "database %s holds an unexpected file" % mid)
                _tar_add(tf, path, os.path.relpath(path, base), 0)
    return os.path.getsize(dest_tar)


# Fichiers attendus dans une base, selon sa source (feeds.py).
def feed_layout_ok(m, root):
    fmt = (m.get("feed") or {}).get("format")
    kind = ((m.get("feed") or {}).get("source") or {}).get("kind")
    has = lambda rel: os.path.isfile(os.path.join(root, rel))  # noqa: E731
    if fmt == feeds.GRYPE_FORMAT:
        return all(has(os.path.join(feeds.GRYPE_MODEL, n)) for n in feeds.GRYPE_FILES)
    if fmt in feeds.INTEL_FORMATS:
        return has(feeds.EXPORT_FILE)
    if kind == "oci":
        return all(has(os.path.join("db", n)) for n in feeds.TRIVY_FILES)
    eco = os.path.join(root, "osv-scalibr")
    if not os.path.isdir(eco):
        return False
    import zipfile
    found = False
    for e in os.listdir(eco):
        z = os.path.join(eco, e, "all.zip")
        if not os.path.isfile(z):
            return False
        try:
            with zipfile.ZipFile(z) as zf:
                if not zf.infolist():
                    return False
        except (zipfile.BadZipFile, OSError):
            return False
        found = True
    return found


def extract_feed(tar_path, dest, limit):
    """Extrait une base : répertoires et fichiers ordinaires, chemins relatifs sans « .. »."""
    os.mkdir(dest, 0o700)
    total = 0
    try:
        with tarfile.open(tar_path, "r:") as tf:
            for i, mem in enumerate(tf):
                if i >= MAX_FEED_ENTRIES:
                    raise Fail("E_BUNDLE_FEED", "too many entries in a database archive")
                parts = [x for x in mem.name.split("/") if x not in ("", ".")]
                if not parts or mem.name.startswith("/") or ".." in parts \
                        or any(not re.match(r"[A-Za-z0-9._+:-]{1,200}\Z", x) for x in parts):
                    raise Fail("E_BUNDLE_FEED", "unexpected path in a database archive: %r" % mem.name[:80])
                target = os.path.join(dest, *parts)
                if mem.isdir():
                    os.makedirs(target, mode=0o700, exist_ok=True)
                    continue
                if not mem.isreg():
                    raise Fail("E_BUNDLE_FEED", "database archive holds a link or a special file")
                total += mem.size
                if total > limit:
                    raise Fail("E_BUNDLE_FEED", "database archive larger once extracted than declared")
                os.makedirs(os.path.dirname(target), mode=0o700, exist_ok=True)
                _hash_copy(tf.extractfile(mem), target, limit)
    except (tarfile.TarError, EOFError, OSError) as e:
        if isinstance(e, Fail):
            raise
        raise Fail("E_BUNDLE_ARCHIVE", "database archive unreadable (%s)" % type(e).__name__)


# --------------------------------------------------------------------------
# Manifeste
# --------------------------------------------------------------------------

def check_manifest(man):
    """Schéma, puis cohérence : chemins déclarés une fois, entrées uniques."""
    errs = schema.load("schemas", "bundle-manifest").errors(man)
    if errs:
        raise Fail("E_BUNDLE_INVALID", "manifest does not match its schema: %s" % "; ".join(errs[:3]))
    declared = {}
    entries = [dict(e, _kind="catalog") for e in man["catalog"]["files"]]
    entries += [dict(e, _kind="testbed") for e in man["testbeds"]]
    entries += [dict(e, _kind="feed") for e in man["feeds"]]
    entries += [dict(e, _kind="image") for e in man["images"]]
    for e in entries:
        p = e["path"]
        if not declared_path_ok(p) or p in declared:
            raise Fail("E_BUNDLE_INVALID", "invalid or duplicate path %r in the manifest" % p[:80])
        declared[p] = (e["sha256"], e["size_bytes"])
    if sorted(f["path"] for f in man["catalog"]["files"]) != sorted(CATALOG_FILES):
        raise Fail("E_BUNDLE_INVALID", "manifest must declare the three catalog files")
    if len(declared) > MAX_ENTRIES:
        raise Fail("E_BUNDLE_INVALID", "too many files in the bundle")
    for key, field in (("feeds", "id"), ("images", "module"), ("testbeds", "module")):
        ids = [e[field] for e in man[key]]
        if len(set(ids)) != len(ids):
            raise Fail("E_BUNDLE_INVALID", "duplicate %s entry in the manifest" % key)
    return declared


def read_signed_manifest(raw, sig_text, expected_fp=None):
    """Manifeste vérifié : signature par une clé du magasin root, puis schéma.

    expected_fp : empreinte imposée (miroir déclaré) ; sinon celle annoncée par
    le manifeste, qui doit être dans le magasin."""
    if len(raw) > MAX_MANIFEST:
        raise Fail("E_BUNDLE_INVALID", "manifest too large")
    try:
        man = common.loads_strict(raw)
    except common.JsonError:
        raise Fail("E_BUNDLE_INVALID", "manifest is not valid JSON")
    signer = man.get("signer") if isinstance(man, dict) else None
    fp = signer.get("fingerprint") if isinstance(signer, dict) else None
    if not isinstance(fp, str) or not offline.FP_RE.match(fp):
        raise Fail("E_BUNDLE_INVALID", "manifest names no signer")
    if expected_fp is not None and fp != expected_fp:
        raise Fail("E_BUNDLE_UNTRUSTED", "bundle signed by another key than the declared one")
    key = offline.trusted_key(fp)
    if key is None:
        raise Fail("E_BUNDLE_UNTRUSTED", "bundle signed by a key that is not trusted (%s…)" % fp[:16],
                   {"signer_fingerprint": fp})
    tmp = os.path.join(common.RUN, ".manifest-%s.json" % secrets.token_hex(4))
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(raw)
        sig = sig_text.decode("ascii", "replace").strip() if isinstance(sig_text, bytes) else ""
        if not offline.verify(key, tmp, sig):
            raise Fail("E_BUNDLE_SIGNATURE", "invalid bundle signature", {"signer_fingerprint": fp})
    finally:
        os.unlink(tmp)
    declared = check_manifest(man)
    if man["signer"]["public_key"] != base64.b64encode(key).decode("ascii"):
        raise Fail("E_BUNDLE_INVALID", "manifest signer key differs from the trusted key")
    return man, declared


# --------------------------------------------------------------------------
# Vérification et application (lot téléversé ou miroir)
# --------------------------------------------------------------------------

class Selection:
    """Parties d'un manifeste à vérifier et appliquer (tout, pour un lot)."""

    def __init__(self, feeds_ids=None, images=None, testbeds=None, catalog=True):
        self.feeds_ids, self.images, self.testbeds, self.catalog = feeds_ids, images, testbeds, catalog

    def has(self, kind, key):
        sel = {"feed": self.feeds_ids, "image": self.images, "testbed": self.testbeds}[kind]
        return sel is None or key in sel


def verify_staged(work, man, sel, deadline):
    """Tout ce qui est sélectionné, contrôlé avant le premier changement. Retourne le plan."""
    set_step("bundle-verify")
    cat = os.path.join(work, "catalog")
    idx, raw, sums = catalogverify.verify_index(cat, man["catalog"]["version"])
    if hashlib.sha256(raw).hexdigest() != man["catalog"]["index_sha256"]:
        raise Fail("E_BUNDLE_CHECKSUM", "catalog index differs from the manifest")
    by_key = {(m["id"], m["version"]): m for m in idx.get("modules") or []}
    plan = {"index": idx, "raw": raw, "testbeds": [], "images": [], "feeds": []}
    for tb in man["testbeds"]:
        if not sel.has("testbed", tb["module"]):
            continue
        m = by_key.get((tb["module"], tb["version"]))
        name = os.path.basename(tb["path"])
        if m is None or m.get("testbed_archive") != name or m.get("testbed_sha256") != tb["sha256"] \
                or sums.get(name) != tb["sha256"]:
            raise Fail("E_BUNDLE_CHECKSUM", "testbed of %s is not the one of the official catalog" % tb["module"])
        plan["testbeds"].append((os.path.join(work, tb["path"]), name))
    for im in man["images"]:
        if not sel.has("image", im["module"]):
            continue
        m = by_key.get((im["module"], im["version"]))
        if m is None or not isinstance(m.get("image"), str) or image_ref(m["image"]) != image_ref(im["image"]) \
                or image_ref(m["image"])[1] != im["digest"]:
            raise Fail("E_BUNDLE_IMAGE", "image of %s %s is not in the official catalog with this digest"
                       % (im["module"], im["version"]), {"module": im["module"]})
        deadline_check(deadline)
        dest = os.path.join(work, "layout-%s" % im["module"])
        blobs = extract_layout(os.path.join(work, im["path"]), dest)
        check_layout(dest, blobs, im["digest"])
        plan["images"].append((im, m["image"], dest))
    for fe in man["feeds"]:
        if not sel.has("feed", fe["id"]):
            continue
        m = by_key.get((fe["id"], fe["version"]))
        if m is None or not feeds.is_declarative(m):
            raise Fail("E_BUNDLE_FEED", "database %s %s is not a feed of the official catalog"
                       % (fe["id"], fe["version"]), {"feed": fe["id"]})
        deadline_check(deadline)
        sd = feeds.store_dir(fe["id"])
        feeds._dirs()
        os.makedirs(sd, mode=0o700, exist_ok=True)
        dest = os.path.join(sd, ".import-" + secrets.token_hex(6))
        try:
            extract_feed(os.path.join(work, fe["path"]), dest, MAX_FILE)
            if not feed_layout_ok(m, dest):
                raise Fail("E_BUNDLE_FEED", "database %s does not have the expected layout" % fe["id"],
                           {"feed": fe["id"]})
        except BaseException:
            shutil.rmtree(dest, ignore_errors=True)
            raise
        plan["feeds"].append((fe, m, dest))
    return plan


def deadline_check(deadline):
    if deadline is not None and deadline.left() < 15:
        raise Fail("E_TIMEOUT", "bundle processing ran out of time")


def install_catalog(work, man, raw):
    """Publie l'index du lot s'il est plus récent que l'index installé."""
    n, cur = man["catalog"]["version"], catalogverify.installed_number()
    if n < cur or (n == cur and catalogverify.installed_index() is not None):
        return False
    common.shared_dir(catalogverify.CATALOG_DIR)
    for name in ("SHA256SUMS", "SHA256SUMS.sig"):
        with open(os.path.join(work, "catalog", name), "rb") as f:
            common.atomic_write(os.path.join(catalogverify.CATALOG_DIR, name), f.read(), 0o640)
    common.atomic_write(catalogverify.INDEX_FILE, raw, 0o640)
    try:
        repo = catalogverify.source_repo()
    except Fail:
        repo = selfupdate.source_repo()
    common.write_json(catalogverify.SOURCE_FILE, {"repo": repo, "tag": "catalog-v%d" % n,
                                                  "checked_at": common.iso(common.now())})
    return True


def apply_plan(plan, man, work, timeout_left):
    """Applique un plan vérifié ; retourne le compte rendu."""
    out = {"catalog": {"version": man["catalog"]["version"], "installed": False},
           "testbeds": [], "images": [], "feeds": []}
    if work is not None:
        set_step("bundle-catalog")
        out["catalog"]["installed"] = install_catalog(work, man, plan["raw"])
    os.makedirs(TESTBEDS, mode=0o750, exist_ok=True)
    for path, name in plan["testbeds"]:
        with open(path, "rb") as f:
            common.atomic_write(os.path.join(TESTBEDS, name), f.read(), 0o640, group_scanoria=False)
        out["testbeds"].append(name)
    for im, image, dest in plan["images"]:
        set_step("bundle-image")
        load_layout(dest, image, timeout=max(60, timeout_left()))
        out["images"].append({"module": im["module"], "version": im["version"], "digest": im["digest"]})
    for fe, m, dest in plan["feeds"]:
        set_step("bundle-feed")
        out["feeds"].append(apply_feed(fe, m, dest))
    from . import dtmirror
    dtmirror.sync_all()
    return out


def apply_feed(fe, m, dest):
    """Bascule atomique de la base importée (date d'origine gardée) ; une base plus
    ancienne que la base active n'est jamais appliquée."""
    mid = fe["id"]
    prev = feeds.read_status(mid) or {}
    cur = prev.get("updated_at") if feeds.has_data(mid) else None
    if isinstance(cur, str) and cur >= fe["updated_at"]:
        shutil.rmtree(dest, ignore_errors=True)
        return {"id": mid, "updated_at": cur, "applied": False, "reason": "not-newer"}
    feeds._readable(dest)
    final = os.path.join(feeds.store_dir(mid), "%s-%s" % (common.now().strftime("%Y%m%dT%H%M%SZ"),
                                                         secrets.token_hex(4)))
    os.rename(dest, final)
    previous = feeds.swap(mid, final)
    st = {"id": mid, "source": "bundle", "updated_at": fe["updated_at"], "checked_at": common.iso(common.now()),
          "size_mb": feeds._du_mb(final), "status": "ok", "error": None,
          "details": fe.get("details") if isinstance(fe.get("details"), dict) else {}}
    feeds.write_status(mid, st)
    feeds.prune(mid, previous)
    if feeds.export_format(m):
        feeds.publish_export(mid)
    return {"id": mid, "updated_at": fe["updated_at"], "applied": True, "reason": None}


# --------------------------------------------------------------------------
# import-bundle
# --------------------------------------------------------------------------

class HashingReader(io.RawIOBase):
    def __init__(self, f):
        self.f, self.h, self.n = f, hashlib.sha256(), 0

    def readable(self):
        return True

    def readinto(self, b):
        data = self.f.read(len(b))
        self.h.update(data)
        self.n += len(data)
        b[:len(data)] = data
        return len(data)


def open_upload(upload_id):
    if not isinstance(upload_id, str) or not common.UUID4_RE.match(upload_id):
        raise Fail("E_INVALID_PARAM", "invalid upload id")
    d = os.path.join(UPLOADS, upload_id)
    try:
        dst = os.lstat(d)
    except FileNotFoundError:
        raise Fail("E_NOT_FOUND", "upload not found")
    if not stat.S_ISDIR(dst.st_mode):
        raise Fail("E_BUNDLE_ARCHIVE", "invalid upload directory")
    try:
        fd = os.open(os.path.join(d, UPLOAD_NAME), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        raise Fail("E_NOT_FOUND", "%s missing from the upload" % UPLOAD_NAME)
    except OSError:
        raise Fail("E_BUNDLE_ARCHIVE", "upload is not a regular file")
    st = os.fstat(fd)
    if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
        os.close(fd)
        raise Fail("E_BUNDLE_ARCHIVE", "upload is not a regular file")
    if st.st_size > MAX_BUNDLE:
        os.close(fd)
        raise Fail("E_BUNDLE_ARCHIVE", "bundle too large")
    os.set_blocking(fd, True)
    return d, os.fdopen(fd, "rb"), st.st_size


def _read_member(tf, mem, limit, name):
    if mem is None or mem.name != name or not mem.isreg():
        raise Fail("E_BUNDLE_ARCHIVE", "bundle must start with manifest.json then manifest.json.sig")
    if mem.size > limit:
        raise Fail("E_BUNDLE_INVALID", "%s too large" % name)
    return tf.extractfile(mem).read(limit + 1)


def stage_tar(f, work):
    """Lit le lot en flux ; retourne (manifeste vérifié, sha256 de l'archive)."""
    reader = HashingReader(f)
    try:
        with tarfile.open(fileobj=io.BufferedReader(reader, 1 << 20), mode="r|") as tf:
            raw = _read_member(tf, tf.next(), MAX_MANIFEST, "manifest.json")
            sig = _read_member(tf, tf.next(), MAX_SIG, "manifest.json.sig")
            man, declared = read_signed_manifest(raw, sig)
            seen = set()
            # tf.next() et non « for mem in tf » : l'itération repartirait des
            # deux membres déjà lus (manifest.json, sa signature).
            while True:
                mem = tf.next()
                if mem is None:
                    break
                name = mem.name
                if name not in declared or name in seen:
                    raise Fail("E_BUNDLE_ARCHIVE", "undeclared or duplicate member %r" % name[:80])
                if not mem.isreg():
                    raise Fail("E_BUNDLE_ARCHIVE", "member %r is not a regular file" % name[:80])
                want_sha, want_size = declared[name]
                if mem.size != want_size:
                    raise Fail("E_BUNDLE_ARCHIVE", "member %r does not have its declared size" % name[:80])
                seen.add(name)
                target = os.path.join(work, name)
                os.makedirs(os.path.dirname(target), mode=0o700, exist_ok=True)
                sha, _ = _hash_copy(tf.extractfile(mem), target, want_size)
                if sha != want_sha:
                    raise Fail("E_BUNDLE_CHECKSUM", "member %r does not match its declared SHA-256" % name[:80])
            missing = sorted(set(declared) - seen)
            if missing:
                raise Fail("E_BUNDLE_ARCHIVE", "bundle lacks %s" % missing[0])
            while reader.f.read(1 << 20):
                pass
    except (tarfile.TarError, EOFError, OSError, ValueError) as e:
        if isinstance(e, Fail):
            raise
        raise Fail("E_BUNDLE_ARCHIVE", "bundle archive unreadable or truncated (%s)" % type(e).__name__)
    return man, reader.h.hexdigest()


def act_import_bundle(c):
    up_dir, f, size = open_upload(c.params["upload_id"])
    work = None
    try:
        _mkdir_private(BUNDLES)
        if _free_bytes(BUNDLES) < size * 2 + (512 << 20):
            raise Fail("E_DISK_SPACE", "not enough disk space to import this bundle (%d MB)" % (size >> 20))
        work = _new_work("import")
        set_step("bundle-read")
        with f:
            man, sha = stage_tar(f, work)
        deadline = feeds.Deadline(c.left())
        plan = verify_staged(work, man, Selection(), deadline)
        out = apply_plan(plan, man, work, c.left)
        out.update(sha256=sha, size_bytes=size, signer_fingerprint=man["signer"]["fingerprint"],
                   created_at=man["created_at"], modules=man["modules"])
        offline.publish_status({"last_import": {"at": common.iso(common.now()), "sha256": sha,
                                                "signer_fingerprint": man["signer"]["fingerprint"],
                                                "created_at": man["created_at"],
                                                "catalog_version": man["catalog"]["version"],
                                                "feeds": [x["id"] for x in out["feeds"] if x["applied"]],
                                                "images": [x["module"] for x in out["images"]]}})
        return out
    finally:
        if not f.closed:
            f.close()
        if work:
            shutil.rmtree(work, ignore_errors=True)
        shutil.rmtree(up_dir, ignore_errors=True)


# --------------------------------------------------------------------------
# export-bundle
# --------------------------------------------------------------------------

def closure(idx_modules, wanted, installed):
    """Modules demandés et leurs dépendances (G1) : [(manifeste, raison)]."""
    def best(mid):
        cands = [m for m in idx_modules if m["id"] == mid]
        if not cands:
            raise Fail("E_NOT_FOUND", "module %s not in the catalog" % mid)
        ver = installed.get(mid)
        exact = [m for m in cands if m["version"] == ver]
        from .modules import vkey
        return exact[0] if exact else max(cands, key=lambda m: vkey(m["version"]))

    out, seen, todo = [], set(), [(w, "requested") for w in wanted]
    while todo:
        mid, why = todo.pop(0)
        if mid in seen:
            continue
        seen.add(mid)
        m = best(mid)
        out.append((m, why))
        req = m.get("requires") or {}
        for key in ("modules", "feeds"):
            for d in req.get(key) or []:
                if isinstance(d, str) and catalogverify.MODULE_ID_RE.match(d):
                    todo.append((d, "dependency"))
        if len(out) > 64:
            raise Fail("E_DEPENDENCY", "too many modules in the bundle")
    return out


def _installed_versions():
    from . import modules
    try:
        reg = modules.load_registry()
    except Fail:
        return {}, {}
    return {k: e["manifest"]["version"] for k, e in reg["modules"].items()}, reg


def export_plan(wanted):
    from . import modules
    mods = modules.catalog()
    installed, reg = _installed_versions()
    items = closure(mods, wanted, installed)
    plan = {"feeds": [], "images": [], "testbeds": []}
    for m, why in items:
        if feeds.is_declarative(m):
            plan["feeds"].append((m, why))
            continue
        if isinstance(m.get("image"), str):
            plan["images"].append((m, why))
        if isinstance(m.get("testbed_archive"), str):
            plan["testbeds"].append((m, why))
    return items, plan, reg


def estimate(wanted, timeout):
    items, plan, _ = export_plan(wanted)
    total, images, feeds_out = 0, [], []
    for m, why in plan["feeds"]:
        st = feeds.public_status(m["id"])
        mb = st.get("size_mb") if st.get("status") != "missing" else (m.get("resources") or {}).get("disk_mb")
        b = int(float(mb or 0) * (1 << 20))
        total += b
        feeds_out.append({"id": m["id"], "version": m["version"], "estimated_bytes": b,
                          "present": st.get("status") != "missing", "updated_at": st.get("updated_at"),
                          "reason": why})
    for m, why in plan["images"]:
        _, _, b = remote_plan(m["image"], timeout=min(120, timeout))
        total += b
        images.append({"module": m["id"], "version": m["version"], "estimated_bytes": b, "reason": why})
    total += len(plan["testbeds"]) * (1 << 20)
    return {"dry_run": True, "modules": [m["id"] for m, _ in items], "feeds": feeds_out, "images": images,
            "testbeds": len(plan["testbeds"]), "estimated_bytes": total,
            "free_bytes": _free_bytes(common.VARLIB)}


def bundle_name(ts):
    return "scanoria-bundle-%s.tar" % ts.strftime("%Y%m%dT%H%M%SZ")


def _entry(work, rel, **extra):
    path = os.path.join(work, rel)
    return dict(extra, path=rel, sha256=_sha256_file(path), size_bytes=os.path.getsize(path))


def build_bundle(wanted, c, scheduled=False):
    """Construit et signe un lot ; retourne le compte rendu (fichier sous BUNDLES)."""
    from . import testbed
    items, plan, _ = export_plan(wanted)
    work = _new_work("export")
    try:
        os.mkdir(os.path.join(work, "catalog"), 0o700)
        for name in ("SHA256SUMS", "SHA256SUMS.sig", "catalog-index.json"):
            shutil.copyfile(os.path.join(catalogverify.CATALOG_DIR, name), os.path.join(work, "catalog", name))
        with open(os.path.join(work, "catalog", "catalog-index.json"), "rb") as fi:
            raw = fi.read()
        idx = common.loads_strict(raw)
        cat_files = [_entry(work, p) for p in CATALOG_FILES]
        man_tb, man_feeds, man_images = [], [], []
        os.mkdir(os.path.join(work, "testbeds"), 0o700)
        for m, _ in plan["testbeds"]:
            set_step("export-testbed")
            rel = "testbeds/" + m["testbed_archive"]
            testbed.fetch_archive(m, os.path.join(work, rel))
            man_tb.append(_entry(work, rel, module=m["id"], version=m["version"]))
        os.mkdir(os.path.join(work, "feeds"), 0o700)
        for m, _ in plan["feeds"]:
            set_step("export-feed")
            if not feeds.has_data(m["id"]):
                feeds.refresh(m, None, timeout=c.left())
            st = feeds.read_status(m["id"]) or {}
            rel = "feeds/%s.tar" % m["id"]
            tar_feed(m["id"], os.path.join(work, rel))
            details = st.get("details") if isinstance(st.get("details"), dict) else {}
            man_feeds.append(_entry(work, rel, id=m["id"], version=m["version"],
                                    updated_at=st.get("updated_at") or common.iso(common.now()),
                                    details=json.loads(json.dumps(details))))
        os.mkdir(os.path.join(work, "images"), 0o700)
        for m, _ in plan["images"]:
            set_step("export-image")
            rel = "images/%s-%s.oci.tar" % (m["id"], m["version"])
            export_image(m["image"], os.path.join(work, rel), work, timeout=c.left())
            man_images.append(_entry(work, rel, module=m["id"], version=m["version"], image=m["image"],
                                     digest=image_ref(m["image"])[1]))
        info = offline.appliance_key_info()
        if info is None:
            offline.ensure_key()
            info = offline.appliance_key_info()
        now = common.now()
        man = {"format": FORMAT, "created_at": common.iso(now),
               "signer": {"fingerprint": info["fingerprint"], "public_key": info["public_key"]},
               "appliance_version": common.installed_version() or "0.0.0",
               "modules": [m["id"] for m, _ in items],
               "catalog": {"version": idx["version"], "index_sha256": hashlib.sha256(raw).hexdigest(),
                           "files": cat_files},
               "testbeds": man_tb, "feeds": man_feeds, "images": man_images}
        check_manifest(man)
        mpath = os.path.join(work, "manifest.json")
        with open(mpath, "w", encoding="utf-8") as f:
            f.write(json.dumps(man, ensure_ascii=False, indent=1, sort_keys=True) + "\n")
        with open(os.path.join(work, "manifest.json.sig"), "w", encoding="ascii") as f:
            f.write(offline.sign(mpath) + "\n")
        set_step("export-write")
        name = bundle_name(now)
        part = os.path.join(BUNDLES, "." + name + ".part")
        mtime = int(now.timestamp())
        with tarfile.open(part, "w", format=tarfile.PAX_FORMAT) as tf:
            _tar_add(tf, mpath, "manifest.json", mtime)
            _tar_add(tf, os.path.join(work, "manifest.json.sig"), "manifest.json.sig", mtime)
            for e in cat_files + man_tb + man_feeds + man_images:
                _tar_add(tf, os.path.join(work, e["path"]), e["path"], mtime)
        os.chmod(part, 0o640)
        if not common.TEST_ROOT:
            os.chown(part, 0, common.scanoria_ids()[1])
        final = os.path.join(BUNDLES, name)
        os.rename(part, final)
        sha = _sha256_file(final)
        common.write_json(final[:-4] + ".json", {
            "name": name, "created_at": man["created_at"], "size_bytes": os.path.getsize(final), "sha256": sha,
            "signer_fingerprint": info["fingerprint"], "modules": man["modules"],
            "feeds": [{"id": e["id"], "updated_at": e["updated_at"]} for e in man_feeds],
            "images": [e["module"] for e in man_images], "catalog_version": idx["version"],
            "scheduled": scheduled}, 0o640)
        # F17 : le dernier lot, découpé, est servi par le point de miroir.
        from . import mirror
        try:
            mirror.publish(work)
            work = None
        except Fail as e:
            common.log("mirror publication skipped: %s" % e.message)
        return {"dry_run": False, "name": name, "sha256": sha, "size_bytes": os.path.getsize(final),
                "created_at": man["created_at"], "signer_fingerprint": info["fingerprint"],
                "modules": man["modules"], "feeds": [e["id"] for e in man_feeds],
                "images": [e["module"] for e in man_images], "testbeds": len(man_tb),
                "catalog_version": idx["version"]}
    finally:
        if work:
            shutil.rmtree(work, ignore_errors=True)


def rotate(keep):
    """Garde les keep lots les plus récents (fichier .tar et sa fiche .json)."""
    names = sorted((n for n in os.listdir(BUNDLES) if BUNDLE_RE.match(n)), reverse=True)
    removed = []
    for n in names[keep:]:
        for p in (os.path.join(BUNDLES, n), os.path.join(BUNDLES, n[:-4] + ".json")):
            try:
                os.unlink(p)
            except FileNotFoundError:
                pass
        removed.append(n)
    return removed


def list_exports():
    out = []
    try:
        names = sorted((n for n in os.listdir(BUNDLES) if BUNDLE_RE.match(n)), reverse=True)
    except FileNotFoundError:
        return out
    for n in names[:20]:
        try:
            meta = common.load_json_file(os.path.join(BUNDLES, n[:-4] + ".json"), 1 << 20)
        except (OSError, common.JsonError):
            continue
        if isinstance(meta, dict) and meta.get("name") == n:
            out.append({k: meta.get(k) for k in ("name", "created_at", "size_bytes", "sha256", "signer_fingerprint",
                                                 "modules", "feeds", "images", "catalog_version", "scheduled")})
    return out


def act_export_bundle(c):
    prm = c.params
    if "schedule" in prm:
        s = dict(prm["schedule"], last_run_at=offline.load_schedule().get("last_run_at"))
        if s["enabled"] and not s["modules"]:
            raise Fail("E_INVALID_PARAM", "a scheduled export needs at least one module")
        offline.save_schedule(s)
        offline.publish_status()
        return {"schedule": s}
    if prm.get("scheduled"):
        return scheduled_export(c)
    wanted = prm["modules"]
    if prm.get("dry_run"):
        return estimate(wanted, c.left())
    _mkdir_private(BUNDLES)
    est = estimate(wanted, c.left())
    if est["estimated_bytes"] * 2 + (512 << 20) > _free_bytes(BUNDLES):
        raise Fail("E_DISK_SPACE", "not enough disk space for this bundle (about %d MB needed)"
                   % (est["estimated_bytes"] * 2 >> 20), {"estimated_bytes": est["estimated_bytes"]})
    out = build_bundle(wanted, c)
    out["removed"] = rotate(prm.get("keep", offline.load_schedule().get("keep", DEFAULT_KEEP)))
    offline.publish_status()
    return out


def scheduled_export(c):
    """Export périodique (minuteur quotidien) : seulement s'il est activé et dû."""
    s = offline.load_schedule()
    if not s["enabled"] or not s["modules"]:
        return {"skipped": "disabled"}
    last = s.get("last_run_at")
    if last:
        try:
            age = (common.now() - common.parse_iso(last)).total_seconds()
        except ValueError:
            age = None
        if age is not None and 0 <= age < s["every_days"] * 86400 - 3600:
            return {"skipped": "not-due"}
    out = build_bundle(s["modules"], c, scheduled=True)
    out["removed"] = rotate(s["keep"])
    s["last_run_at"] = common.iso(common.now())
    offline.save_schedule(s)
    offline.publish_status()
    return out
