# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Vincent Tisseront
"""scanoria-selfupdate : mises à jour signées de l'appliance (F18, ARCHITECTURE § 6).

  scanoria-selfupdate check [--channel stable|prerelease] [--json]
  scanoria-selfupdate apply --version X.Y.Z | --upload-id UUID
  scanoria-selfupdate rollback --expected-current X.Y.Z --expected-target X.Y.Z
  scanoria-selfupdate install-local DIR
  scanoria-selfupdate verify DIR [--version X.Y.Z]

Réponse sur la sortie standard : {"code", "message", "output"} (protocole du
helper). Ordre de vérification (§ 6.4) : signature Ed25519 de SHA256SUMS avec
la clé épinglée /etc/scanoria/update-pubkey.pem, puis empreintes, puis
release.json (schéma, version strictement supérieure, min_upgrade_from,
node_major), espace disque, archive. Extraction contrôlée (fichiers réguliers
et répertoires seulement), sauvegarde de la base, bascule current/previous,
santé, retour arrière automatique.
"""

import fcntl
import hashlib
import os
import re
import secrets
import shutil
import stat
import subprocess
import sys
import tarfile
import time

from . import common, schema
from .common import Fail, set_step

GITHUB_API = "https://api.github.com"
GITHUB = "https://github.com"
REPO_RE = re.compile(r"[A-Za-z0-9-]{1,39}/[A-Za-z0-9._-]{1,100}\Z")
SUMS_LINE_RE = re.compile(
    r"([0-9a-f]{64})  (release\.json|scanoria-((?:0|[1-9][0-9]{0,3})\.(?:0|[1-9][0-9]{0,3})\.(?:0|[1-9][0-9]{0,3}))\.tar\.zst)\Z")
ROOTFS_ALLOWED_RE = re.compile(
    r"usr/(sbin/scanoria-[a-z0-9][a-z0-9-]*|lib/scanoria/.+|share/scanoria/.+"
    r"|lib/systemd/system/scanoria-[A-Za-z0-9@._-]+|lib/sysusers\.d/scanoria\.conf"
    r"|lib/tmpfiles\.d/scanoria\.conf)\Z")
EXEC_PREFIXES = ("rootfs/usr/sbin/", "rootfs/usr/lib/scanoria/", "webui/")

MAX_SUMS = 4096
SIG_SIZE = 64
MAX_RELEASE_JSON = 128 * 1024
MAX_ARCHIVE = 1 << 30
MAX_EXTRACTED = 4 << 30
MAX_MEMBERS = 200000
MAX_API = 2 << 20

RELEASES = common.OPT + "/releases"
UPDATES = common.VARLIB + "/updates"
STAGING = UPDATES + "/staging"
BACKUPS = common.VARLIB + "/backups/pre-update"
UPLOADS = common.VARLIB + "/uploads"


# Temps à garder, une fois la console arrêtée, pour déployer, migrer, vérifier
# la santé et, au besoin, revenir en arrière (restauration de la base comprise).
POST_STOP_RESERVE = 1500


def deadline():
    """Échéance murale passée par le helper (SCANORIA_UPDATE_DEADLINE) ; None sinon."""
    t = os.environ.get("SCANORIA_UPDATE_DEADLINE", "")
    return int(t) if t.isdigit() else None


def budget(cap, need=POST_STOP_RESERVE):
    """Délai alloué à une étape d'avant le point de non-retour : au plus cap, et
    jamais au point d'entamer la réserve d'après arrêt. E_TIMEOUT sinon."""
    d = deadline()
    if d is None:
        return cap
    left = d - int(time.time()) - need
    if left < 30:
        raise Fail("E_TIMEOUT", "not enough time left to install and roll back safely")
    return min(cap, left)


def health_timeout():
    t = os.environ.get("SCANORIA_TEST_HEALTH_TIMEOUT", "") if common.TEST_ROOT else ""
    return int(t) if t.isdigit() else 120


# --------------------------------------------------------------------------
# Outils
# --------------------------------------------------------------------------

def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def mkdir_private(path):
    os.makedirs(path, mode=0o700, exist_ok=True)
    os.chmod(path, 0o700)


def new_staging(tag):
    mkdir_private(STAGING)
    d = os.path.join(STAGING, "%s-%s" % (tag, secrets.token_hex(6)))
    os.mkdir(d, 0o700)
    return d


def source_repo():
    try:
        repo = common.load_json_file(os.path.join(common.SHARE_DIR, "update-source.json"), 4096).get("repo")
    except (OSError, common.JsonError, AttributeError):
        repo = None
    if not isinstance(repo, str) or not REPO_RE.match(repo):
        raise Fail("E_PRECONDITION", "update source not configured")
    return repo


def user_agent():
    return "scanoria-appliance/%s" % (common.installed_version() or "0.0.0")


def curl(url, dest, max_size, follow=True, accept=None, timeout=60):
    """Téléchargement HTTPS seul ; retourne (code HTTP, URL de redirection). 0 = réseau."""
    args = ["--proto", "=https", "--proto-redir", "=https", "--tlsv1.2", "--silent",
            "--connect-timeout", "10", "--max-time", str(timeout), "--max-filesize", str(max_size),
            "--user-agent", user_agent(), "--output", dest,
            "--write-out", "%{http_code} %{redirect_url}"]
    if follow:
        args += ["--location", "--max-redirs", "5"]
    if accept:
        args += ["--header", "Accept: " + accept]
    args.append(url)
    r = common.run("curl", args, timeout=timeout + 30)
    if r.returncode == 63:
        raise Fail("E_ARCHIVE", "download larger than expected")
    if r.returncode != 0:
        return 0, ""
    parts = r.text.strip().split(" ", 1)
    try:
        code = int(parts[0])
    except ValueError:
        return 0, ""
    if os.path.exists(dest) and os.path.getsize(dest) > max_size:
        raise Fail("E_ARCHIVE", "download larger than expected")
    return code, parts[1] if len(parts) > 1 else ""


def tag_version(tag):
    if isinstance(tag, str) and tag.startswith("v") and common.SEMVER_RE.match(tag[1:]):
        return tag[1:]
    return None


def rejected(name):
    return isinstance(name, str) and name.startswith("[rejected]")


# --------------------------------------------------------------------------
# Recherche de la dernière version
# --------------------------------------------------------------------------

def api_get(tmp, path):
    dest = os.path.join(tmp, "api.json")
    code, _ = curl(GITHUB_API + path, dest, MAX_API, accept="application/vnd.github+json", timeout=30)
    if code != 200:
        return code, None
    try:
        return code, common.load_json_file(dest, MAX_API)
    except (OSError, common.JsonError):
        return 0, None


def from_release_obj(repo, rel):
    if not isinstance(rel, dict) or rel.get("draft") is not False or rejected(rel.get("name")):
        return None
    v = tag_version(rel.get("tag_name"))
    if v is None:
        return None
    pub = rel.get("published_at")
    try:
        pub = common.iso(common.parse_iso(pub)) if isinstance(pub, str) else None
    except ValueError:
        pub = None
    return {"version": v, "published_at": pub, "prerelease": rel.get("prerelease") is True,
            "source_url": "%s/%s/releases/tag/v%s" % (GITHUB, repo, v)}


def latest_stable_fallback(repo, tmp):
    code, loc = curl("%s/%s/releases/latest" % (GITHUB, repo), os.path.join(tmp, "latest.html"),
                     MAX_API, follow=False, timeout=30)
    if code == 0:
        raise Fail("E_NETWORK", "GitHub unreachable")
    m = re.fullmatch(r"https://github\.com/([A-Za-z0-9-]{1,39}/[A-Za-z0-9._-]{1,100})/releases/tag/(v[0-9.]+)", loc)
    if code in (301, 302, 303, 307, 308) and m and m.group(1).lower() == repo.lower():
        v = tag_version(m.group(2))
        if v:
            return {"version": v, "published_at": None, "prerelease": False,
                    "source_url": "%s/%s/releases/tag/v%s" % (GITHUB, repo, v)}
    return None


def atom_entries(repo, tmp):
    """Entrées du flux public des releases : [(version, titre, mise à jour, tag)]."""
    import xml.etree.ElementTree as ET
    dest = os.path.join(tmp, "releases.atom")
    code, _ = curl("%s/%s/releases.atom" % (GITHUB, repo), dest, 1 << 20, timeout=30)
    if code != 200:
        raise Fail("E_NETWORK", "GitHub unreachable (releases feed HTTP %d)" % code)
    with open(dest, "rb") as f:
        data = f.read()
    if b"<!DOCTYPE" in data or b"<!ENTITY" in data:
        raise Fail("E_NETWORK", "unexpected releases feed")
    ns = "{http://www.w3.org/2005/Atom}"
    try:
        root = ET.fromstring(data)
    except ET.ParseError:
        raise Fail("E_NETWORK", "unreadable releases feed")
    entries = []
    for e in root.findall(ns + "entry"):
        title = (e.findtext(ns + "title") or "").strip()
        for link in e.findall(ns + "link"):
            href = link.get("href") or ""
            m = re.fullmatch(r"https://github\.com/([^/]+/[^/]+)/releases/tag/(v[0-9.]+)", href)
            if not m or m.group(1).lower() != repo.lower():
                continue
            v = tag_version(m.group(2))
            if v:
                upd = (e.findtext(ns + "updated") or "").strip()
                try:
                    upd = common.iso(common.parse_iso(re.sub(r"\+00:00$", "Z", upd)))
                except ValueError:
                    upd = None
                entries.append((v, title, upd, m.group(2)))
    return entries


def latest_atom_fallback(repo, tmp):
    best = None
    for v, title, upd, tag in atom_entries(repo, tmp):
        if rejected(title):
            continue
        if best is None or common.parse_version(v) > common.parse_version(best["version"]):
            best = {"version": v, "published_at": upd, "prerelease": None,
                    "source_url": "%s/%s/releases/tag/%s" % (GITHUB, repo, tag)}
    return best


def best_release(repo, objs, stable_only):
    """Plus haute version vX.Y.Z d'une liste de releases de l'API."""
    cands = [r for r in (from_release_obj(repo, o) for o in objs) if r]
    if stable_only:
        cands = [r for r in cands if not r["prerelease"]]
    return max(cands, key=lambda r: common.parse_version(r["version"]), default=None)


def find_latest(repo, channel, tmp):
    if channel == "stable":
        code, obj = api_get(tmp, "/repos/%s/releases/latest" % repo)
        if code == 200:
            rel = from_release_obj(repo, obj)
            if rel is not None:
                return None if rel["prerelease"] else rel
            # releases/latest désigne une release qui n'est pas une version de
            # la console (index du catalogue catalog-v<N>) : on parcourt la liste.
            code, obj = api_get(tmp, "/repos/%s/releases?per_page=50" % repo)
            if code == 200 and isinstance(obj, list):
                return best_release(repo, obj, True)
            return None
        if code == 404:
            return None
        return latest_stable_fallback(repo, tmp)
    code, obj = api_get(tmp, "/repos/%s/releases?per_page=20" % repo)
    if code == 200 and isinstance(obj, list):
        return best_release(repo, obj, False)
    if code == 404:
        return None
    return latest_atom_fallback(repo, tmp)


def check_offered(repo, version, channel, tmp):
    """La release vX.Y.Z est-elle toujours proposée sur ce canal ? Une signature
    valide ne suffit pas : une candidate rejetée reste signée (seul son titre
    change). Refuse un brouillon, une release « [rejected] », et une
    pré-version sur le canal stable (E_VERSION)."""
    code, obj = api_get(tmp, "/repos/%s/releases/tags/v%s" % (repo, version))
    if code == 200:
        if not isinstance(obj, dict) or obj.get("draft") is not False:
            raise Fail("E_VERSION", "release v%s is not published" % version)
        if rejected(obj.get("name")):
            raise Fail("E_VERSION", "release v%s was rejected" % version)
        if tag_version(obj.get("tag_name")) != version:
            raise Fail("E_VERSION", "unexpected release tag")
        if channel == "stable" and obj.get("prerelease") is not False:
            raise Fail("E_VERSION", "release v%s is a prerelease; the update channel is stable" % version)
        return
    if code == 404:
        raise Fail("E_NOT_FOUND", "release v%s not found" % version)
    # Limite de débit de l'API (403/429) ou API injoignable : adresses publiques.
    if channel == "stable":
        rel = latest_stable_fallback(repo, tmp)
        if rel is None or rel["version"] != version:
            raise Fail("E_VERSION", "release v%s is not the latest stable release" % version)
        return
    for v, title, _, _ in atom_entries(repo, tmp):
        if v == version:
            if rejected(title):
                raise Fail("E_VERSION", "release v%s was rejected" % version)
            return
    raise Fail("E_VERSION", "release v%s is not offered on the prerelease channel" % version)


def fetch_signed(repo, version, dest_dir):
    base = "%s/%s/releases/download/v%s/" % (GITHUB, repo, version)
    for name, limit in (("SHA256SUMS", MAX_SUMS), ("SHA256SUMS.sig", SIG_SIZE),
                        ("release.json", MAX_RELEASE_JSON)):
        code, _ = curl(base + name, os.path.join(dest_dir, name), limit)
        if code == 404:
            raise Fail("E_NOT_FOUND", "release asset %s not found" % name)
        if code != 200:
            raise Fail("E_NETWORK", "cannot download %s (HTTP %d)" % (name, code))


# --------------------------------------------------------------------------
# Vérifications
# --------------------------------------------------------------------------

def verify_signature(d):
    sums, sig = os.path.join(d, "SHA256SUMS"), os.path.join(d, "SHA256SUMS.sig")
    if not os.path.isfile(common.PUBKEY):
        raise Fail("E_PRECONDITION", "pinned public key missing")
    if not os.path.isfile(sums) or os.path.getsize(sums) > MAX_SUMS:
        raise Fail("E_SIGNATURE", "SHA256SUMS missing or too large")
    if not os.path.isfile(sig) or os.path.getsize(sig) != SIG_SIZE:
        raise Fail("E_SIGNATURE", "SHA256SUMS.sig must be a raw 64-byte Ed25519 signature")
    r = common.run("openssl", ["pkeyutl", "-verify", "-pubin", "-inkey", common.PUBKEY,
                               "-rawin", "-in", sums, "-sigfile", sig], timeout=30)
    if r.returncode != 0 or "Signature Verified Successfully" not in r.text:
        raise Fail("E_SIGNATURE", "invalid signature")


def verify_meta(d, expected_version=None, require_sig=True):
    """Signature, SHA256SUMS, release.json. Retourne (release, nom de l'archive)."""
    if require_sig or os.path.exists(os.path.join(d, "SHA256SUMS.sig")):
        verify_signature(d)
    else:
        common.log("no signature next to the bundle: integrity checked by SHA256SUMS only")
    try:
        with open(os.path.join(d, "SHA256SUMS"), "rb") as f:
            text = f.read(MAX_SUMS + 1).decode("ascii")
    except (OSError, UnicodeDecodeError):
        raise Fail("E_CHECKSUM", "unreadable SHA256SUMS")
    lines = text.split("\n")
    if len(lines) != 3 or lines[2] != "":
        raise Fail("E_CHECKSUM", "SHA256SUMS must hold exactly two lines")
    sums = {}
    for ln in lines[:2]:
        m = SUMS_LINE_RE.match(ln)
        if not m or m.group(2) in sums:
            raise Fail("E_CHECKSUM", "malformed SHA256SUMS line")
        sums[m.group(2)] = m.group(1)
    archive = [n for n in sums if n != "release.json"]
    if "release.json" not in sums or len(archive) != 1:
        raise Fail("E_CHECKSUM", "SHA256SUMS must list release.json and the archive")
    archive = archive[0]
    rj = os.path.join(d, "release.json")
    if not os.path.isfile(rj) or os.path.getsize(rj) > MAX_RELEASE_JSON:
        raise Fail("E_CHECKSUM", "release.json missing or too large")
    if sha256_file(rj) != sums["release.json"]:
        raise Fail("E_CHECKSUM", "release.json checksum mismatch")
    try:
        rel = common.load_json_file(rj, MAX_RELEASE_JSON)
    except common.JsonError:
        raise Fail("E_CHECKSUM", "release.json is not valid JSON")
    if not schema.load("schemas", "release").valid(rel):
        raise Fail("E_CHECKSUM", "release.json does not match its schema")
    if rel["archive"] != archive or archive != "scanoria-%s.tar.zst" % rel["release"] \
            or rel["tag"] != "v" + rel["release"] or rel["archive_sha256"] != sums[archive]:
        raise Fail("E_CHECKSUM", "release.json inconsistent with SHA256SUMS")
    if expected_version is not None and rel["release"] != expected_version:
        raise Fail("E_VERSION", "release.json is for another version")
    return rel, archive


def node_major():
    r = common.run("node", ["--version"], timeout=30)
    m = re.fullmatch(r"v([0-9]+)\.[0-9]+\.[0-9]+", r.text.strip())
    return int(m.group(1)) if m else None


def check_version(rel, installed):
    new = common.parse_version(rel["release"])
    if installed is not None:
        cur = common.parse_version(installed)
        if new <= cur:
            raise Fail("E_VERSION", "version %s is not newer than %s" % (rel["release"], installed))
        if common.parse_version(rel["min_upgrade_from"]) > cur:
            raise Fail("E_VERSION", "version %s requires at least %s" % (rel["release"], rel["min_upgrade_from"]))
    nm = node_major()
    if nm != rel["node_major"]:
        raise Fail("E_VERSION", "release needs Node.js %d (installed: %s); a new ISO is required"
                   % (rel["node_major"], nm))


def free_bytes(path):
    while not os.path.exists(path):
        path = os.path.dirname(path)
    v = os.statvfs(path)
    return v.f_bavail * v.f_frsize


def check_space(rel):
    size = rel["archive_size"]
    if free_bytes(common.OPT) < 3 * size + (256 << 20) or free_bytes(common.VARLIB) < size + (512 << 20):
        raise Fail("E_DISK_SPACE", "not enough free disk space")


def verify_archive(path, rel):
    if not os.path.isfile(path) or os.path.getsize(path) != rel["archive_size"]:
        raise Fail("E_CHECKSUM", "archive size mismatch")
    if sha256_file(path) != rel["archive_sha256"]:
        raise Fail("E_CHECKSUM", "archive checksum mismatch")


# --------------------------------------------------------------------------
# Extraction contrôlée (§ 6.3)
# --------------------------------------------------------------------------

def _member_rel(name, prefix):
    if "\\" in name or any(ord(c) < 32 or ord(c) == 127 for c in name):
        raise Fail("E_ARCHIVE", "invalid member name")
    if name.startswith("/"):
        raise Fail("E_ARCHIVE", "absolute path in archive")
    parts = name.rstrip("/").split("/")
    if parts and parts[0] == ".":
        parts = parts[1:]
    if not parts or parts[0] != prefix:
        raise Fail("E_ARCHIVE", "member outside %s/" % prefix)
    if any(x in ("", ".", "..") for x in parts):
        raise Fail("E_ARCHIVE", "path traversal in archive")
    return "/".join(parts[1:])


# Arborescence d'une version : root:scanoria, rien pour les autres (la console,
# utilisateur scanoria, la lit et l'exécute ; personne d'autre n'en a besoin).
RELEASE_DIR_MODE = 0o750
RELEASE_EXEC_MODE = 0o750
RELEASE_FILE_MODE = 0o640


def _release_gid():
    """Groupe scanoria, ou None avant la création du compte : à la première
    installation (install-local), post_deploy crée le compte après l'extraction
    et _group_release corrige alors le groupe de l'arborescence."""
    try:
        return common.scanoria_ids()[1]
    except KeyError:
        return None


def _own_release(fd, mode):
    os.fchmod(fd, mode)
    if not common.TEST_ROOT:
        gid = _release_gid()
        os.fchown(fd, 0, 0 if gid is None else gid)


def _group_release(path):
    """Passe une version extraite en root:scanoria (sans suivre de lien)."""
    if common.TEST_ROOT:
        return
    gid = common.scanoria_ids()[1]
    os.lchown(path, 0, gid)
    for dirpath, dirnames, filenames in os.walk(path):
        for n in dirnames + filenames:
            os.lchown(os.path.join(dirpath, n), 0, gid)


def _contained(base_real, rel):
    """Chemin absolu de rel sous base_real, refusé s'il en sort (Zip Slip),
    en plus des contrôles de _member_rel."""
    target = os.path.realpath(os.path.join(base_real, rel)) if rel else base_real
    if target != base_real and not target.startswith(base_real + os.sep):
        raise Fail("E_ARCHIVE", "path traversal in archive")
    return target


def _mkdirs_release(base_real, path):
    """Crée les répertoires de path sous base_real, root:scanoria 0750."""
    path = _contained(base_real, os.path.relpath(path, base_real) if path != base_real else "")
    todo = []
    cur = path
    while cur != base_real and not os.path.lexists(cur):
        todo.append(cur)
        cur = os.path.dirname(cur)
    for d in reversed(todo):
        os.mkdir(d, 0o700)
        fd = os.open(d, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            _own_release(fd, RELEASE_DIR_MODE)
        finally:
            os.close(fd)


def extract(archive, version, dest_parent=None):
    dest_parent = dest_parent or RELEASES
    os.makedirs(dest_parent, mode=0o755, exist_ok=True)
    final = os.path.join(dest_parent, version)
    tmp = final + ".tmp"
    shutil.rmtree(tmp, ignore_errors=True)
    os.mkdir(tmp, 0o700)
    tmp_real = os.path.realpath(tmp)
    fd = os.open(tmp_real, os.O_RDONLY | os.O_DIRECTORY)
    try:
        _own_release(fd, RELEASE_DIR_MODE)
    finally:
        os.close(fd)
    prefix = "scanoria-" + version
    zstd = common.resolve("zstd")
    if zstd is None:
        raise Fail("E_INTERNAL", "zstd missing")
    proc = subprocess.Popen([zstd, "-dc", "-q", "--", archive], stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL, env=common.child_env())
    total = count = 0
    try:
        with tarfile.open(fileobj=proc.stdout, mode="r|") as tf:
            for m in tf:
                count += 1
                if count > MAX_MEMBERS:
                    raise Fail("E_ARCHIVE", "too many members")
                rel = _member_rel(m.name, prefix)
                target = _contained(tmp_real, rel)
                if m.isdir():
                    _mkdirs_release(tmp_real, target)
                    continue
                if not m.isreg() or not rel:
                    raise Fail("E_ARCHIVE", "links and special files are not allowed")
                total += m.size
                if total > MAX_EXTRACTED:
                    raise Fail("E_ARCHIVE", "archive expands too much")
                parent = os.path.dirname(target)
                _mkdirs_release(tmp_real, parent)
                if os.path.islink(parent) or not os.path.isdir(parent):
                    raise Fail("E_ARCHIVE", "invalid directory in archive")
                execok = (m.mode & 0o111) and rel.startswith(EXEC_PREFIXES)
                fmode = RELEASE_EXEC_MODE if execok else RELEASE_FILE_MODE
                try:
                    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                except FileExistsError:
                    raise Fail("E_ARCHIVE", "duplicate member in archive")
                src = tf.extractfile(m)
                with os.fdopen(fd, "wb") as out:
                    _own_release(out.fileno(), fmode)
                    shutil.copyfileobj(src, out, 1 << 20)
        # tarfile s'arrête au marqueur de fin d'archive : le reste du flux
        # (bourrage de bloc tar) doit être lu, sinon zstd, encore en train
        # d'écrire son dernier bloc, meurt de SIGPIPE à la fermeture du tube.
        drained = 0
        while True:
            chunk = proc.stdout.read(1 << 16)
            if not chunk:
                break
            drained += len(chunk)
            if drained > (1 << 20):
                raise Fail("E_ARCHIVE", "trailing data after end of archive")
    except (tarfile.TarError, EOFError, OSError) as e:
        shutil.rmtree(tmp, ignore_errors=True)
        raise Fail("E_ARCHIVE", "unreadable archive: %s" % type(e).__name__)
    except Fail:
        shutil.rmtree(tmp, ignore_errors=True)
        raise
    finally:
        if proc.stdout:
            proc.stdout.close()
        # zstd peut encore être en train de se terminer : on l'attend avant de
        # le tuer (un kill immédiat donnait « zstd failed » au hasard). Sur
        # erreur, la fermeture du tube l'arrête de toute façon (SIGPIPE).
        try:
            proc.wait(timeout=60)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
    if proc.returncode != 0:
        shutil.rmtree(tmp, ignore_errors=True)
        raise Fail("E_ARCHIVE", "zstd failed")
    for f in ("VERSION", "webui/VERSION"):
        if common.read_text(os.path.join(tmp, f), 64) != version:
            shutil.rmtree(tmp, ignore_errors=True)
            raise Fail("E_ARCHIVE", "%s does not contain %s" % (f, version))
    for f in ("rootfs", "webui/server/index.mjs", "webui/migrate.mjs"):
        if not os.path.exists(os.path.join(tmp, f)):
            shutil.rmtree(tmp, ignore_errors=True)
            raise Fail("E_ARCHIVE", "%s missing from bundle" % f)
    if os.path.lexists(final):
        shutil.rmtree(final)
    os.rename(tmp, final)
    return final


# --------------------------------------------------------------------------
# Déploiement (§ 3.3), liens, base, services, santé
# --------------------------------------------------------------------------

def rootfs_files(rootfs):
    out = []
    for dirpath, dirnames, filenames in os.walk(rootfs):
        dirnames[:] = [d for d in dirnames if not os.path.islink(os.path.join(dirpath, d))]
        for fn in filenames:
            full = os.path.join(dirpath, fn)
            rel = os.path.relpath(full, rootfs)
            st = os.lstat(full)
            if not stat.S_ISREG(st.st_mode) or not ROOTFS_ALLOWED_RE.match(rel):
                common.log("ignored in rootfs: %r" % rel)
                continue
            out.append(rel)
    return sorted(out)


def read_manifest():
    try:
        with open(common.p("/usr/share/scanoria/MANIFEST"), encoding="utf-8") as f:
            return [ln[1:] for ln in f.read().splitlines() if ln.startswith("/")]
    except OSError:
        return []


def deploy_rootfs(release_dir):
    rootfs = os.path.join(release_dir, "rootfs")
    files = rootfs_files(rootfs)
    old = read_manifest()
    for rel in files:
        src = os.path.join(rootfs, rel)
        dst = common.p("/" + rel)
        os.makedirs(os.path.dirname(dst), mode=0o755, exist_ok=True)
        mode = 0o755 if os.stat(src).st_mode & 0o111 else 0o644
        tmp = os.path.join(os.path.dirname(dst), ".%s.scanoria-new" % os.path.basename(dst))
        if os.path.lexists(tmp):
            os.unlink(tmp)
        shutil.copyfile(src, tmp, follow_symlinks=False)
        os.chmod(tmp, mode)
        os.replace(tmp, dst)
    keep = set(files)
    for rel in old:
        if rel in keep or not ROOTFS_ALLOWED_RE.match(rel):
            continue
        dst = common.p("/" + rel)
        try:
            if stat.S_ISREG(os.lstat(dst).st_mode):
                os.unlink(dst)
        except FileNotFoundError:
            pass
    manifest = "".join("/%s\n" % r for r in sorted(keep | {"usr/share/scanoria/MANIFEST"}))
    common.atomic_write(common.p("/usr/share/scanoria/MANIFEST"), manifest, 0o644, group_scanoria=False)


def post_deploy():
    common.run("systemd-sysusers", ["/usr/lib/sysusers.d/scanoria.conf"], timeout=120)
    common.run("systemd-tmpfiles", ["--create", "/usr/lib/tmpfiles.d/scanoria.conf"], timeout=120)
    if os.path.isdir("/run/systemd/system") or common.TEST_ROOT:
        common.run("systemctl", ["daemon-reload"], timeout=120)


UNITS_LIST = "/usr/share/scanoria/units.list"
UNIT_RE = re.compile(r"^scanoria-[a-z0-9-]{1,48}\.(service|timer|path)$")


def listed_units():
    """Unités de units.list (version déployée), noms validés."""
    try:
        with open(common.p(UNITS_LIST), encoding="utf-8") as f:
            lines = [ln.strip() for ln in f]
    except FileNotFoundError:
        return []
    return [u for u in lines if u and not u.startswith("#") and UNIT_RE.match(u)]


def sync_units(restart=True):
    """Active les unités de la version déployée (une version peut en ajouter)
    et redémarre ses services pour charger le nouveau code. Sans effet avant
    la fin du premier démarrage, qui les active lui-même. Une unité absente
    ou en échec est journalisée sans faire échouer la mise à jour : la santé
    de la console reste le critère du retour arrière."""
    if not os.path.exists(common.VARLIB + "/firstboot.done"):
        return []
    done = []
    for unit in listed_units():
        if common.run("systemctl", ["cat", unit], timeout=60).returncode != 0:
            common.log("unit %s not installed, skipped" % unit)
            continue
        r = common.run("systemctl", ["enable", "--now", unit], timeout=300)
        if r.returncode == 0 and restart and unit.endswith(".service"):
            r = common.run("systemctl", ["try-restart", unit], timeout=300)
        if r.returncode != 0:
            common.log("unit %s could not be started" % unit)
            continue
        done.append(unit)
    return done


def set_link(name, version):
    path = os.path.join(common.OPT, name)
    if version is None:
        if os.path.islink(path):
            os.unlink(path)
        return
    tmp = os.path.join(common.OPT, ".%s.tmp" % name)
    if os.path.lexists(tmp):
        os.unlink(tmp)
    os.symlink("releases/" + version, tmp)
    os.replace(tmp, path)


def _pg(args, stdin_path=None, stdout_path=None, timeout=1800):
    """Commande PostgreSQL lancée en postgres (runuser), entrée/sortie sur fichier."""
    exe = common.resolve("runuser")
    if exe is None:  # mode test : bouchon
        common.run("runuser", ["-u", "postgres", "--"] + args)
        if stdout_path:
            with open(stdout_path, "wb") as f:
                f.write(b"test dump\n")
        return
    fin = open(stdin_path, "rb") if stdin_path else subprocess.DEVNULL
    fout = open(stdout_path, "wb") if stdout_path else subprocess.DEVNULL
    try:
        r = subprocess.run([exe, "-u", "postgres", "--"] + args, stdin=fin, stdout=fout,
                           env=common.child_env(), cwd="/", timeout=timeout)
    except subprocess.TimeoutExpired:
        raise Fail("E_TIMEOUT", "%s timed out" % args[0])
    finally:
        for f in (fin, fout):
            if hasattr(f, "close"):
                f.close()
    if r.returncode != 0:
        raise Fail("E_INTERNAL", "%s failed" % os.path.basename(args[0]))


def backup_db(cur, new, timeout=1800):
    mkdir_private(BACKUPS)
    dump = os.path.join(BACKUPS, cur + ".dump")
    tmp = dump + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    os.close(fd)
    _pg([common.SYSTEM_CMDS["pg_dump"], "--format=custom", "--dbname=scanoria"], stdout_path=tmp,
        timeout=timeout)
    os.replace(tmp, dump)
    common.write_json(os.path.join(BACKUPS, cur + ".json"),
                      {"version": cur, "next": new, "created_at": common.iso(common.now())},
                      0o600, group_scanoria=False)
    return dump


def restore_db(dump):
    if not os.path.isfile(dump):
        raise Fail("E_PRECONDITION", "database backup missing")
    _pg([common.SYSTEM_CMDS["dropdb"], "--if-exists", "scanoria"])
    _pg([common.SYSTEM_CMDS["createdb"], "--owner=scanoria", "--encoding=UTF8",
         "--locale=en_US.UTF-8", "--template=template0", "scanoria"])
    _pg([common.SYSTEM_CMDS["pg_restore"], "--exit-on-error", "--dbname=scanoria"], stdin_path=dump)


def console(action):
    r = common.run("systemctl", [action, "scanoria-console.service"], timeout=300)
    if r.returncode != 0:
        raise Fail("E_INTERNAL", "systemctl %s scanoria-console failed" % action)


def health(version):
    end = time.monotonic() + health_timeout()
    ok = False
    while True:
        r = common.run("curl", ["--silent", "--max-time", "5", "--proto", "=http",
                                "http://127.0.0.1:3000/api/health"], timeout=30)
        try:
            h = common.loads_strict(r.stdout)
            ok = isinstance(h, dict) and h.get("status") == "ok" and h.get("version") == version
        except common.JsonError:
            ok = False
        if ok or time.monotonic() > end:
            break
        time.sleep(2)
    if not ok:
        raise Fail("E_INTERNAL", "console health check failed")
    r = common.run("scanoria-selftest", ["--json", "--quick"], timeout=300)
    if r.returncode != 0:
        raise Fail("E_INTERNAL", "selftest --quick failed after update")


def write_alert(message, version):
    mkdir_private(UPDATES)
    common.write_json(common.UPDATE_ALERT_FILE, {"code": "E_ROLLBACK_FAILED", "message": message[:2000],
                                                 "at": common.iso(common.now()), "version": version})


def clear_alert():
    try:
        os.unlink(common.UPDATE_ALERT_FILE)
    except FileNotFoundError:
        pass


def cleanup(keep_versions):
    keep = {v for v in keep_versions if v}
    try:
        for n in os.listdir(RELEASES):
            if n not in keep:
                shutil.rmtree(os.path.join(RELEASES, n), ignore_errors=True)
    except FileNotFoundError:
        pass
    prev = common.installed_version("previous")
    try:
        for n in os.listdir(BACKUPS):
            if prev is None or n not in (prev + ".dump", prev + ".json"):
                os.unlink(os.path.join(BACKUPS, n))
    except FileNotFoundError:
        pass
    shutil.rmtree(STAGING, ignore_errors=True)


class UpdateLock:
    def __enter__(self):
        os.makedirs(common.RUN, exist_ok=True)
        self.fd = os.open(common.RUN + "/update.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            os.close(self.fd)
            raise Fail("E_PRECONDITION", "another update operation is running")
        return self

    def __exit__(self, *exc):
        os.close(self.fd)


# --------------------------------------------------------------------------
# Commandes
# --------------------------------------------------------------------------

def read_policy():
    try:
        pol = common.load_json_file(common.ETC + "/update.json", 1 << 16)
    except (OSError, common.JsonError):
        pol = {}
    return pol if isinstance(pol, dict) else {}


def cmd_check(channel):
    pol = read_policy()
    channel = channel or (pol.get("channel") if pol.get("channel") in ("stable", "prerelease") else "stable")
    installed = common.installed_version()
    rec = {"checked_at": common.iso(common.now()), "channel": channel, "code": "OK",
           "latest_version": None, "available": False, "notes_md": None,
           "published_at": None, "source_url": None}
    mkdir_private(UPDATES)
    tmp = new_staging("check")
    try:
        repo = source_repo()
        found = find_latest(repo, channel, tmp)
        if found:
            fetch_signed(repo, found["version"], tmp)
            rel, _ = verify_meta(tmp, found["version"])
            rec.update(latest_version=rel["release"], notes_md=rel["notes_md"],
                       published_at=found["published_at"], source_url=found["source_url"])
            try:
                rec["available"] = installed is None or \
                    common.parse_version(rel["release"]) > common.parse_version(installed)
            except ValueError:
                rec["available"] = False
    except Fail as e:
        rec["code"] = e.code
        common.write_json(common.UPDATE_CHECK_FILE, rec)
        raise
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    common.write_json(common.UPDATE_CHECK_FILE, rec)
    out = dict(rec, current_version=installed)
    del out["code"]
    return out


def copy_upload(upload_id, dest):
    """Copie les fichiers téléversés (propriétaire scanoria, fichiers réguliers) dans dest."""
    if not common.UUID4_RE.match(upload_id):
        raise Fail("E_INVALID_PARAM", "invalid upload id")
    d = os.path.join(UPLOADS, upload_id)
    try:
        st = os.lstat(d)
    except FileNotFoundError:
        raise Fail("E_NOT_FOUND", "upload not found")
    uid = common.scanoria_ids()[0]
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != uid:
        raise Fail("E_PRECONDITION", "invalid upload directory")
    dfd = os.open(d, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        names = os.listdir(dfd)
        archives = [n for n in names if re.fullmatch(r"scanoria-[0-9.]+\.tar\.zst", n)]
        if len(archives) != 1:
            raise Fail("E_NOT_FOUND", "exactly one scanoria-X.Y.Z.tar.zst expected in the upload")
        limits = {"SHA256SUMS": MAX_SUMS, "SHA256SUMS.sig": SIG_SIZE,
                  "release.json": MAX_RELEASE_JSON, archives[0]: MAX_ARCHIVE}
        for n, limit in limits.items():
            try:
                fd = os.open(n, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dfd)
            except FileNotFoundError:
                raise Fail("E_NOT_FOUND", "%s missing from the upload" % n)
            except OSError:
                raise Fail("E_PRECONDITION", "%s is not a regular file" % n)
            with os.fdopen(fd, "rb") as src:
                fs = os.fstat(src.fileno())
                if not stat.S_ISREG(fs.st_mode) or fs.st_nlink != 1 or fs.st_uid != uid:
                    raise Fail("E_PRECONDITION", "%s is not a regular file owned by scanoria" % n)
                if fs.st_size > limit:
                    raise Fail("E_ARCHIVE", "%s is too large" % n)
                ofd = os.open(os.path.join(dest, n), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                with os.fdopen(ofd, "wb") as out:
                    shutil.copyfileobj(src, out, 1 << 20)
    finally:
        os.close(dfd)
    return d


def auto_rollback(cur, old_prev, dump, new):
    """Retour arrière automatique après un échec d'installation."""
    set_step("rollback")
    try:
        common.run("systemctl", ["stop", "scanoria-console.service"], timeout=300)
        restore_db(dump)
        set_link("current", cur)
        set_link("previous", old_prev)
        deploy_rootfs(os.path.join(RELEASES, cur))
        post_deploy()
        console("start")
        health(cur)
        sync_units()
    except Fail as e:
        msg = "automatic rollback to %s failed: %s" % (cur, e.message)
        write_alert(msg, cur)
        raise Fail("E_ROLLBACK_FAILED", msg)
    shutil.rmtree(os.path.join(RELEASES, new), ignore_errors=True)


def cmd_apply(version=None, upload_id=None):
    cur = common.installed_version()
    if cur is None:
        raise Fail("E_PRECONDITION", "no installed release")
    old_prev = common.installed_version("previous")
    set_step("download")
    stg = new_staging("apply")
    try:
        return _apply(cur, old_prev, stg, version, upload_id)
    finally:
        shutil.rmtree(stg, ignore_errors=True)


def _apply(cur, old_prev, stg, version, upload_id):
    upload_dir = None
    if version is not None:
        repo = source_repo()
        pol = read_policy()
        channel = pol.get("channel") if pol.get("channel") in ("stable", "prerelease") else "stable"
        check_offered(repo, version, channel, stg)
        fetch_signed(repo, version, stg)
    else:
        upload_dir = copy_upload(upload_id, stg)
    set_step("verify")
    rel, archive_name = verify_meta(stg, version)
    new = rel["release"]
    check_version(rel, cur)
    check_space(rel)
    archive = os.path.join(stg, archive_name)
    if version is not None:
        code, _ = curl("%s/%s/releases/download/v%s/%s" % (GITHUB, source_repo(), new, archive_name),
                       archive, rel["archive_size"], timeout=budget(1200, POST_STOP_RESERVE + 600))
        if code != 200:
            raise Fail("E_NETWORK" if code != 404 else "E_NOT_FOUND", "cannot download the archive")
    verify_archive(archive, rel)
    set_step("extract")
    extract(archive, new)
    set_step("backup")
    try:
        dump = backup_db(cur, new, timeout=budget(1800))
        # Point de non-retour : ne pas arrêter la console sans le temps de revenir en arrière.
        budget(0)
    except Fail:
        shutil.rmtree(os.path.join(RELEASES, new), ignore_errors=True)
        raise
    try:
        set_step("stop")
        console("stop")
        set_step("deploy")
        deploy_rootfs(os.path.join(RELEASES, new))
        set_link("previous", cur)
        set_link("current", new)
        post_deploy()
        set_step("migrate")
        console("start")
        set_step("start")
        set_step("health")
        health(new)
    except Fail as e:
        common.log("update to %s failed (%s), rolling back" % (new, e.message))
        auto_rollback(cur, old_prev, dump, new)
        raise Fail("E_HEALTH_ROLLED_BACK", "update to %s failed (%s); %s restored" % (new, e.message, cur),
                   {"from_version": cur, "to_version": new, "rolled_back": True})
    set_step("services")
    sync_units()
    set_step("cleanup")
    cleanup((new, cur))
    if upload_dir:
        shutil.rmtree(upload_dir, ignore_errors=True)
    clear_alert()
    try:
        os.unlink(common.UPDATE_CHECK_FILE)
    except FileNotFoundError:
        pass
    return {"from_version": cur, "to_version": new, "rolled_back": False}


def cmd_rollback(expected_current, expected_target):
    cur, prev = common.installed_version(), common.installed_version("previous")
    if prev is None:
        raise Fail("E_NO_PREVIOUS", "no previous version")
    if cur != expected_current or prev != expected_target:
        raise Fail("E_PRECONDITION", "installed versions changed since the request")
    dump = os.path.join(BACKUPS, prev + ".dump")
    if not os.path.isfile(dump):
        raise Fail("E_PRECONDITION", "database backup of %s missing" % prev)
    budget(0, need=POST_STOP_RESERVE)  # assez de temps pour aller jusqu'au bout
    try:
        set_step("stop")
        console("stop")
        set_step("restore")
        restore_db(dump)
        set_step("deploy")
        set_link("current", prev)
        set_link("previous", None)
        deploy_rootfs(os.path.join(RELEASES, prev))
        post_deploy()
        set_step("start")
        console("start")
        set_step("health")
        health(prev)
        sync_units()
    except Fail as e:
        msg = "rollback to %s failed: %s" % (prev, e.message)
        write_alert(msg, prev)
        raise Fail("E_ROLLBACK_FAILED", msg)
    cleanup((prev,))
    clear_alert()
    # Version abandonnée par l'administrateur : la mise à jour automatique ne la
    # réinstalle pas (ni rien d'inférieur) ; seule une version plus récente passe.
    mkdir_private(UPDATES)
    common.write_json(common.UPDATE_SKIP_FILE, {"version": cur, "at": common.iso(common.now())},
                      0o640)
    return {"from_version": cur, "to_version": prev}


def cmd_install_local(d):
    if os.path.lexists(os.path.join(common.OPT, "current")):
        raise Fail("E_PRECONDITION", "already installed: /opt/scanoria/current exists")
    rel, archive_name = verify_meta(d, None, require_sig=False)
    archive = os.path.join(d, archive_name)
    verify_archive(archive, rel)
    if os.path.exists(common.OPT + "/node/bin/node") or common.TEST_ROOT:
        check_version(rel, None)
    os.makedirs(common.OPT, mode=0o755, exist_ok=True)
    final = extract(archive, rel["release"])
    deploy_rootfs(final)
    set_link("current", rel["release"])
    post_deploy()
    _group_release(final)
    return {"installed": rel["release"]}


def cmd_verify(d, version):
    rel, archive_name = verify_meta(d, version)
    verify_archive(os.path.join(d, archive_name), rel)
    return {"release": rel["release"], "archive": archive_name, "archive_sha256": rel["archive_sha256"]}


USAGE = """usage: scanoria-selfupdate check [--channel stable|prerelease] [--json]
       scanoria-selfupdate apply --version X.Y.Z | --upload-id UUID
       scanoria-selfupdate rollback --expected-current X.Y.Z --expected-target X.Y.Z
       scanoria-selfupdate install-local DIR
       scanoria-selfupdate verify DIR [--version X.Y.Z]
"""


def _opts(args, allowed):
    if len(args) % 2:
        raise Fail("E_INVALID_PARAM", "bad options")
    o = dict(zip(args[::2], args[1::2]))
    if len(o) * 2 != len(args) or not set(o) <= allowed:
        raise Fail("E_INVALID_PARAM", "bad options")
    return o


def _semver(v):
    if v is None or not common.SEMVER_RE.match(v):
        raise Fail("E_INVALID_PARAM", "invalid version")
    return v


def main(argv):
    if not common.TEST_ROOT and os.geteuid() != 0:
        sys.stderr.write("scanoria-selfupdate: root required\n")
        return 2
    os.umask(0o022)
    if not argv:
        sys.stderr.write(USAGE)
        return 2
    cmd, args = argv[0], argv[1:]
    try:
        if cmd == "check":
            args = [a for a in args if a != "--json"]
            o = _opts(args, {"--channel"})
            ch = o.get("--channel")
            if ch not in (None, "stable", "prerelease"):
                raise Fail("E_INVALID_PARAM", "invalid channel")
            with UpdateLock():
                out = cmd_check(ch)
            return common.emit("OK", "update check done", out)
        if cmd == "apply":
            o = _opts(args, {"--version", "--upload-id"})
            if len(o) != 1:
                raise Fail("E_INVALID_PARAM", "exactly one of --version, --upload-id")
            with UpdateLock():
                out = cmd_apply(_semver(o["--version"]) if "--version" in o else None, o.get("--upload-id"))
            return common.emit("OK", "update installed", out)
        if cmd == "rollback":
            o = _opts(args, {"--expected-current", "--expected-target"})
            with UpdateLock():
                out = cmd_rollback(_semver(o.get("--expected-current")), _semver(o.get("--expected-target")))
            return common.emit("OK", "previous version restored", out)
        if cmd == "install-local" and len(args) == 1:
            with UpdateLock():
                out = cmd_install_local(os.path.abspath(args[0]))
            return common.emit("OK", "installed", out)
        if cmd == "verify" and args:
            o = _opts(args[1:], {"--version"})
            v = _semver(o["--version"]) if "--version" in o else None
            return common.emit("OK", "release verified", cmd_verify(os.path.abspath(args[0]), v))
    except Fail as e:
        return common.emit(e.code, e.message, e.output)
    sys.stderr.write(USAGE)
    return 2
