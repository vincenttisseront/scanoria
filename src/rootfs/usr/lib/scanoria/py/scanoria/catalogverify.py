# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Vincent Tisseront
"""Index du catalogue : téléchargement, vérification et publication (demande refresh-catalog).

Source : la dernière release « catalog-v<N> » du dépôt public (API GitHub sans
jeton ; repli sur le flux releases.atom en cas de limite de débit ou d'API
injoignable). Fichiers : SHA256SUMS, SHA256SUMS.sig (Ed25519 brut, même clé et
même procédé que le lot de mise à jour), catalog-index.json.

Rien n'est publié tant que tout n'est pas vérifié : signature, empreinte de
l'index, schéma catalog-index.schema.json, contrôles propres au moteur
(identifiants, images épinglées par empreinte, unicité), numéro N de l'index
égal au tag et jamais inférieur à celui de l'index installé. La publication
(/var/lib/scanoria/catalog/catalog-index.json, root:scanoria 0640) est atomique.
"""

import os
import re
import shutil
import xml.etree.ElementTree as ET

from . import common, schema, selfupdate
from .common import Fail, set_step

CATALOG_DIR = common.VARLIB + "/catalog"
INDEX_FILE = CATALOG_DIR + "/catalog-index.json"
SOURCE_FILE = CATALOG_DIR + "/source.json"
OVERRIDE_FILE = common.ETC + "/catalog.json"

MAX_SUMS = 64 * 1024
MAX_INDEX = 8 << 20
MAX_TAG = 999999999
SIG_SIZE = 64

TAG_RE = re.compile(r"catalog-v([1-9][0-9]{0,8})\Z")
SUMS_LINE_RE = re.compile(
    r"([0-9a-f]{64})  (catalog-index\.json|testbed-[a-z0-9][a-z0-9-]{1,40}-[0-9A-Za-z][0-9A-Za-z.+_-]{0,63}\.tar\.zst)\Z")
MODULE_ID_RE = re.compile(r"[a-z0-9][a-z0-9-]{1,40}\Z")
MODULE_VERSION_RE = re.compile(r"[0-9A-Za-z][0-9A-Za-z.+_-]{0,63}\Z")
IMAGE_RE = re.compile(
    r"[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?(:[0-9]{1,5})?/[a-z0-9]([a-z0-9._/-]{0,253}[a-z0-9])?"
    r"(:[A-Za-z0-9_][A-Za-z0-9_.-]{0,127})?@sha256:[0-9a-f]{64}\Z", re.ASCII)
ENV_KEY_RE = re.compile(r"(?!LD_|PATH\Z|HOME\Z)[A-Z][A-Z0-9_]{0,63}\Z")
TYPES = ("scanner", "service", "feed", "runner")
RESTRICTIONS = ("none", "private-code-forbidden", "no-redistribution", "other")


# --------------------------------------------------------------------------
# Source
# --------------------------------------------------------------------------

def source_repo():
    """Dépôt de l'index : /etc/scanoria/catalog.json {"repo"} s'il existe, sinon le
    dépôt des mises à jour de la console (aucun réglage nécessaire)."""
    try:
        obj = common.load_json_file(OVERRIDE_FILE, 4096)
    except FileNotFoundError:
        return selfupdate.source_repo()
    except (OSError, common.JsonError):
        raise Fail("E_PRECONDITION", "unreadable %s" % OVERRIDE_FILE)
    repo = obj.get("repo") if isinstance(obj, dict) else None
    if not isinstance(repo, str) or not selfupdate.REPO_RE.match(repo):
        raise Fail("E_PRECONDITION", "invalid catalog source")
    return repo


def tag_number(tag):
    m = TAG_RE.match(tag) if isinstance(tag, str) else None
    return int(m.group(1)) if m else None


API_PAGES = 5


def _latest_from_api(tmp, repo):
    """Parcourt jusqu'à API_PAGES pages de 30 releases, jusqu'à trouver une catalog-v<N>."""
    best, code = None, 0
    for page in range(1, API_PAGES + 1):
        suffix = "" if page == 1 else "&page=%d" % page
        code, obj = selfupdate.api_get(tmp, "/repos/%s/releases?per_page=30%s" % (repo, suffix))
        if code != 200 or not isinstance(obj, list):
            return (code if page == 1 else 200), best
        for rel in obj:
            if not isinstance(rel, dict) or rel.get("draft") is not False or selfupdate.rejected(rel.get("name")):
                continue
            n = tag_number(rel.get("tag_name"))
            if n is not None and (best is None or n > best):
                best = n
        if best is not None or len(obj) < 30:
            break
    return 200, best


def _latest_from_atom(tmp, repo):
    dest = os.path.join(tmp, "releases.atom")
    code, _ = selfupdate.curl("%s/%s/releases.atom" % (selfupdate.GITHUB, repo), dest, 1 << 20, timeout=30)
    if code == 0:
        raise Fail("E_NETWORK", "GitHub unreachable")
    if code != 200:
        raise Fail("E_NETWORK", "releases feed HTTP %d" % code)
    with open(dest, "rb") as f:
        data = f.read()
    if b"<!DOCTYPE" in data or b"<!ENTITY" in data:
        raise Fail("E_NETWORK", "unexpected releases feed")
    ns = "{http://www.w3.org/2005/Atom}"
    try:
        root = ET.fromstring(data)
    except ET.ParseError:
        raise Fail("E_NETWORK", "unreadable releases feed")
    best = None
    prefix = "%s/%s/releases/tag/" % (selfupdate.GITHUB, repo)
    for e in root.findall(ns + "entry"):
        if selfupdate.rejected((e.findtext(ns + "title") or "").strip()):
            continue
        for link in e.findall(ns + "link"):
            href = link.get("href") or ""
            if href.lower().startswith(prefix.lower()):
                n = tag_number(href[len(prefix):])
                if n is not None and (best is None or n > best):
                    best = n
    return best


def find_latest(tmp, repo):
    """Numéro N de la dernière release catalog-v<N> publiée, ou Fail."""
    code, best = _latest_from_api(tmp, repo)
    if code == 200:
        if best is None:
            raise Fail("E_NOT_FOUND", "no catalog release found")
        return best
    if code == 404:
        raise Fail("E_NOT_FOUND", "repository or releases not found")
    best = _latest_from_atom(tmp, repo)  # 403/429 ou API injoignable
    if best is None:
        raise Fail("E_NOT_FOUND", "no catalog release found")
    return best


def download_url(repo, n, name):
    return "%s/%s/releases/download/catalog-v%d/%s" % (selfupdate.GITHUB, repo, n, name)


def fetch(tmp, repo, n):
    for name, limit in (("SHA256SUMS", MAX_SUMS), ("SHA256SUMS.sig", SIG_SIZE),
                        ("catalog-index.json", MAX_INDEX)):
        code, _ = selfupdate.curl(download_url(repo, n, name), os.path.join(tmp, name), limit)
        if code == 404:
            raise Fail("E_NOT_FOUND", "catalog asset %s not found" % name)
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
        raise Fail("E_SIGNATURE", "invalid catalog signature")


def parse_sums(path):
    try:
        with open(path, "rb") as f:
            text = f.read(MAX_SUMS + 1).decode("ascii")
    except (OSError, UnicodeDecodeError):
        raise Fail("E_CHECKSUM", "unreadable SHA256SUMS")
    if not text.endswith("\n"):
        raise Fail("E_CHECKSUM", "SHA256SUMS must end with a newline")
    sums = {}
    for ln in text[:-1].split("\n"):
        m = SUMS_LINE_RE.match(ln)
        if not m or m.group(2) in sums:
            raise Fail("E_CHECKSUM", "malformed SHA256SUMS line")
        sums[m.group(2)] = m.group(1)
    if "catalog-index.json" not in sums:
        raise Fail("E_CHECKSUM", "SHA256SUMS does not list catalog-index.json")
    return sums


def _index_validator():
    """Schéma de l'index (fourni par le chantier catalogue). Échec fermé s'il manque.
    En mode test, une copie posée sous la racine de test est prioritaire."""
    if common.TEST_ROOT:
        alt = common.p("/usr/share/scanoria/schemas/catalog-index.schema.json")
        if os.path.isfile(alt):
            return schema.Validator(common.load_json_file(alt, 1 << 20))
    try:
        return schema.load("schemas", "catalog-index")
    except FileNotFoundError:
        raise Fail("E_PRECONDITION", "catalog index schema missing")


def _check_command(cmd, what):
    if not isinstance(cmd, list) or not 1 <= len(cmd) <= 64:
        raise Fail("E_CHECKSUM", "%s: invalid command" % what)
    for a in cmd:
        if not isinstance(a, str) or not 0 < len(a) <= 1024 or "\x00" in a:
            raise Fail("E_CHECKSUM", "%s: invalid command argument" % what)


def check_module(m):
    """Contrôles propres au moteur, indépendants du schéma (défense en profondeur)."""
    if not isinstance(m, dict):
        raise Fail("E_CHECKSUM", "module entry must be an object")
    mid, ver = m.get("id"), m.get("version")
    if not isinstance(mid, str) or not MODULE_ID_RE.match(mid):
        raise Fail("E_CHECKSUM", "invalid module id")
    if not isinstance(ver, str) or not MODULE_VERSION_RE.match(ver):
        raise Fail("E_CHECKSUM", "%s: invalid version" % mid)
    what = "%s %s" % (mid, ver)
    if m.get("type") not in TYPES:
        raise Fail("E_CHECKSUM", "%s: invalid type" % what)
    # Un feed est déclaratif en 0.2 (sans image) ; tout autre module a une image.
    if (m["type"] != "feed" or m.get("image") is not None) and \
            (not isinstance(m.get("image"), str) or not IMAGE_RE.match(m["image"])):
        raise Fail("E_CHECKSUM", "%s: image must be pinned by digest" % what)
    lic = m.get("license")
    if not isinstance(lic, dict) or lic.get("restrictions") not in RESTRICTIONS:
        raise Fail("E_CHECKSUM", "%s: invalid license" % what)
    if m["type"] == "scanner":
        scan = m.get("scan")
        if not isinstance(scan, dict):
            raise Fail("E_CHECKSUM", "%s: scanner without scan" % what)
        _check_command(scan.get("command"), what)
        if scan.get("sbom_command") is not None:   # 0.5, contrat 14
            _check_command(scan["sbom_command"], what)
        for flag in ("requires_sbom", "prefers_sbom", "service_optional"):
            if not isinstance(scan.get(flag, False), bool):
                raise Fail("E_CHECKSUM", "%s: invalid scan.%s" % (what, flag))
        env = scan.get("env") or {}
        if not isinstance(env, dict) or any(not isinstance(k, str) or not ENV_KEY_RE.match(k)
                                            or not isinstance(v, str) or len(v) > 1024 or "\x00" in v
                                            for k, v in env.items()):
            raise Fail("E_CHECKSUM", "%s: invalid scan.env" % what)
        codes = scan.get("exit_codes_ok", [0, 1])
        if not isinstance(codes, list) or not codes or any(
                not isinstance(x, int) or isinstance(x, bool) or not 0 <= x <= 255 or x in (125, 126, 127)
                for x in codes):
            raise Fail("E_CHECKSUM", "%s: invalid scan.exit_codes_ok" % what)
    if m["type"] == "service" and (m.get("service") or {}).get("variants"):
        from . import variants
        try:
            variants.declared(m)
        except Fail as f:
            raise Fail("E_CHECKSUM", "%s: %s" % (what, f.message))
    h = m.get("health")
    if isinstance(h, dict) and "command" in h:
        _check_command(h["command"], what)
    tb = m.get("testbed_sha256")
    if tb is not None and not (isinstance(tb, str) and re.fullmatch(r"[0-9a-f]{64}", tb)):
        raise Fail("E_CHECKSUM", "%s: invalid testbed_sha256" % what)


def verify_index(d, expected_n):
    """Vérifie le contenu de d ; retourne (index, octets de l'index, empreintes)."""
    verify_signature(d)
    sums = parse_sums(os.path.join(d, "SHA256SUMS"))
    ipath = os.path.join(d, "catalog-index.json")
    if not os.path.isfile(ipath) or os.path.getsize(ipath) > MAX_INDEX:
        raise Fail("E_CHECKSUM", "catalog-index.json missing or too large")
    if selfupdate.sha256_file(ipath) != sums["catalog-index.json"]:
        raise Fail("E_CHECKSUM", "catalog-index.json checksum mismatch")
    with open(ipath, "rb") as f:
        raw = f.read()
    try:
        idx = common.loads_strict(raw)
    except common.JsonError:
        raise Fail("E_CHECKSUM", "catalog-index.json is not valid JSON")
    v = _index_validator()
    errs = v.errors(idx)
    if errs:
        raise Fail("E_CHECKSUM", "catalog index does not match its schema: %s" % "; ".join(errs[:3]))
    if not isinstance(idx, dict) or idx.get("schema") != 1:
        raise Fail("E_CHECKSUM", "unsupported catalog index format")
    n = idx.get("version")
    if not isinstance(n, int) or isinstance(n, bool) or n != expected_n:
        raise Fail("E_VERSION", "index number differs from the release tag")
    seen = set()
    for m in idx.get("modules") or []:
        check_module(m)
        key = (m["id"], m["version"])
        if key in seen:
            raise Fail("E_CHECKSUM", "duplicate module %s %s" % key)
        seen.add(key)
        arch = m.get("testbed_archive")
        if arch is not None and arch != "testbed-%s-%s.tar.zst" % key:
            raise Fail("E_CHECKSUM", "%s %s: unexpected testbed archive name" % key)
        if arch is not None and sums.get(arch) != m.get("testbed_sha256"):
            raise Fail("E_CHECKSUM", "%s %s: testbed checksum differs from SHA256SUMS" % key)
    return idx, raw, sums


def installed_index():
    try:
        idx = common.load_json_file(INDEX_FILE, MAX_INDEX)
    except FileNotFoundError:
        return None
    except (OSError, common.JsonError):
        common.log("installed catalog index unreadable: it will be replaced")
        return None
    return idx if isinstance(idx, dict) else None


def installed_number():
    idx = installed_index()
    n = idx.get("version") if idx else None
    return n if isinstance(n, int) and not isinstance(n, bool) else 0


def source_info():
    try:
        s = common.load_json_file(SOURCE_FILE, 4096)
    except (OSError, common.JsonError):
        return None
    if not isinstance(s, dict) or not isinstance(s.get("repo"), str) \
            or not selfupdate.REPO_RE.match(s["repo"]) or tag_number(s.get("tag")) is None:
        return None
    return s


# --------------------------------------------------------------------------
# Demande refresh-catalog
# --------------------------------------------------------------------------

def refresh():
    from . import mirror
    if mirror.configured():
        # Appliance miroir déclarée (F17) : index pris dans son dernier lot signé,
        # vérifié par la clé épinglée du catalogue comme un téléchargement direct.
        return mirror.refresh_catalog()
    repo = source_repo()
    common.shared_dir(CATALOG_DIR)
    tmp = selfupdate.new_staging("catalog")
    try:
        set_step("catalog-find")
        n = find_latest(tmp, repo)
        cur = installed_number()
        if n < cur:
            raise Fail("E_VERSION", "catalog-v%d is older than the installed index (%d)" % (n, cur))
        set_step("catalog-download")
        fetch(tmp, repo, n)
        set_step("catalog-verify")
        idx, raw, _ = verify_index(tmp, n)
        changed = n != cur
        if changed or installed_index() is None:
            set_step("catalog-publish")
            # Signature et empreintes gardées à côté : preuve de l'origine de l'index publié.
            for name in ("SHA256SUMS", "SHA256SUMS.sig"):
                with open(os.path.join(tmp, name), "rb") as f:
                    common.atomic_write(os.path.join(CATALOG_DIR, name), f.read(), 0o640)
            common.atomic_write(INDEX_FILE, raw, 0o640)
        common.write_json(SOURCE_FILE, {"repo": repo, "tag": "catalog-v%d" % n,
                                        "checked_at": common.iso(common.now())})
        return {"version": n, "previous": cur or None, "changed": changed,
                "modules": len(idx.get("modules") or []), "packs": len(idx.get("packs") or [])}
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
