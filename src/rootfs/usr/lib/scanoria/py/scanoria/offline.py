# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Vincent Tisseront
"""Clé de l'appliance, magasin des clés de confiance et état « hors ligne »
(chantier A de la 0.6, contrat 19, CLAUDE.md § 9).

Clé de l'appliance : paire Ed25519 générée par le helper au premier besoin
(premier démarrage, ou première demande traitée) si elle est absente, dans
/etc/scanoria/keys/appliance.ed25519 (root, 0600, répertoire 0700). Elle signe
les lots hors ligne exportés par cette appliance. La console ne lit jamais la
clé privée : seules la clé publique brute (32 octets, base64) et son empreinte
(SHA-256 de la clé brute, hexadécimal) sont publiées, dans l'état
(appliance_key) et dans /var/lib/scanoria/offline/status.json.

Magasin des clés de confiance : /etc/scanoria/trusted-keys/<empreinte>.pub
(root, 0600), une clé publique brute en base64 par fichier. Il n'est rempli
que par la demande trust-key, déposée après la confirmation d'un
administrateur dans une modale de la console. La table trusted_keys de la
console n'en est que le reflet affiché : l'import d'un lot ne consulte que ce
magasin. Retirer une clé efface son fichier.

Toute la cryptographie passe par openssl (pkey, pkeyutl -rawin) : aucune
implémentation maison.
"""

import base64
import hashlib
import os
import re
import secrets
import shutil
import stat
import tempfile

from . import common, schema
from .common import Fail

KEYS_DIR = common.ETC + "/keys"
APPLIANCE_KEY = KEYS_DIR + "/appliance.ed25519"
TRUST_DIR = common.ETC + "/trusted-keys"
OFFLINE_DIR = common.VARLIB + "/offline"
STATUS_FILE = OFFLINE_DIR + "/status.json"
SCHEDULE_FILE = common.ETC + "/bundle-export.json"

# En-tête DER (SubjectPublicKeyInfo) d'une clé publique Ed25519, suivi des 32 octets bruts.
SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")
PUB_B64_RE = re.compile(r"[A-Za-z0-9+/]{43}=\Z", re.ASCII)
FP_RE = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
SIG_SIZE = 64
MAX_TRUSTED = 32


# --------------------------------------------------------------------------
# Clés publiques brutes
# --------------------------------------------------------------------------

def fingerprint(raw):
    return hashlib.sha256(raw).hexdigest()


def decode_public(b64):
    """32 octets d'une clé publique Ed25519 en base64 canonique ; Fail sinon."""
    if not isinstance(b64, str) or not PUB_B64_RE.match(b64):
        raise Fail("E_KEY_INVALID", "public key must be 32 bytes in base64")
    raw = base64.b64decode(b64, validate=True)
    if len(raw) != 32 or base64.b64encode(raw).decode("ascii") != b64:
        raise Fail("E_KEY_INVALID", "public key is not in canonical base64")
    return raw


def public_pem(raw):
    body = base64.b64encode(SPKI_PREFIX + raw).decode("ascii")
    return "-----BEGIN PUBLIC KEY-----\n%s\n-----END PUBLIC KEY-----\n" % body


def _private_dir(path):
    os.makedirs(path, mode=0o700, exist_ok=True)
    st = os.lstat(path)
    if not stat.S_ISDIR(st.st_mode):
        raise Fail("E_INTERNAL", "%s is not a directory" % path)
    os.chmod(path, 0o700)


# --------------------------------------------------------------------------
# Clé de l'appliance
# --------------------------------------------------------------------------

def _read_key_file():
    try:
        fd = os.open(APPLIANCE_KEY, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or st.st_size > 4096:
            raise Fail("E_INTERNAL", "appliance key is not a regular file")
        return os.read(fd, 4097)
    finally:
        os.close(fd)


def ensure_key():
    """Crée la clé de l'appliance si elle manque ; retourne True si elle vient d'être créée."""
    if _read_key_file() is not None:
        return False
    _private_dir(KEYS_DIR)
    tmp = os.path.join(KEYS_DIR, ".appliance.%s.tmp" % secrets.token_hex(4))
    old = os.umask(0o077)
    try:
        r = common.run("openssl", ["genpkey", "-algorithm", "ed25519", "-out", tmp], timeout=60)
        if r.returncode != 0 or not os.path.isfile(tmp):
            raise Fail("E_INTERNAL", "cannot generate the appliance key")
        os.chmod(tmp, 0o600)
        try:
            # Jamais d'écrasement : une clé apparue entre-temps est gardée.
            os.link(tmp, APPLIANCE_KEY)
        except FileExistsError:
            return False
        return True
    finally:
        os.umask(old)
        if os.path.lexists(tmp):
            os.unlink(tmp)


def appliance_public():
    """(clé publique brute, empreinte) de l'appliance, ou (None, None) si absente."""
    if _read_key_file() is None:
        return None, None
    r = common.run("openssl", ["pkey", "-in", APPLIANCE_KEY, "-pubout", "-outform", "DER"], timeout=30)
    der = r.stdout
    if r.returncode != 0 or len(der) != 44 or not der.startswith(SPKI_PREFIX):
        raise Fail("E_INTERNAL", "appliance key unreadable")
    raw = der[len(SPKI_PREFIX):]
    return raw, fingerprint(raw)


def appliance_key_info():
    """{public_key, fingerprint} publié dans l'état ; None si la clé n'existe pas encore."""
    try:
        raw, fp = appliance_public()
    except Fail as e:
        common.log("appliance key: %s" % e.message)
        return None
    if raw is None:
        return None
    return {"public_key": base64.b64encode(raw).decode("ascii"), "fingerprint": fp}


def sign(path):
    """Signature Ed25519 détachée (base64) des octets de path, par la clé de l'appliance."""
    ensure_key()
    fd, sig = tempfile.mkstemp(prefix=".sig-", dir=common.RUN)
    os.close(fd)
    try:
        r = common.run("openssl", ["pkeyutl", "-sign", "-inkey", APPLIANCE_KEY, "-rawin",
                                   "-in", path, "-out", sig], timeout=60)
        with open(sig, "rb") as f:
            data = f.read(SIG_SIZE + 1)
        if r.returncode != 0 or len(data) != SIG_SIZE:
            raise Fail("E_INTERNAL", "cannot sign with the appliance key")
        return base64.b64encode(data).decode("ascii")
    finally:
        os.unlink(sig)


def verify(raw_public, path, sig_b64):
    """Vrai si sig_b64 est une signature Ed25519 valide des octets de path."""
    try:
        sig = base64.b64decode(sig_b64, validate=True) if isinstance(sig_b64, str) else b""
    except ValueError:
        return False
    if len(sig) != SIG_SIZE or len(raw_public) != 32:
        return False
    tmp = tempfile.mkdtemp(prefix="verify-", dir=common.RUN)
    try:
        pem, sf = os.path.join(tmp, "pub.pem"), os.path.join(tmp, "sig.bin")
        with open(pem, "w", encoding="ascii") as f:
            f.write(public_pem(raw_public))
        with open(sf, "wb") as f:
            f.write(sig)
        r = common.run("openssl", ["pkeyutl", "-verify", "-pubin", "-inkey", pem, "-rawin",
                                   "-in", path, "-sigfile", sf], timeout=60)
        return r.returncode == 0 and "Signature Verified Successfully" in r.text
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# --------------------------------------------------------------------------
# Magasin des clés de confiance
# --------------------------------------------------------------------------

def trusted_path(fp):
    if not isinstance(fp, str) or not FP_RE.match(fp):
        raise Fail("E_KEY_INVALID", "invalid key fingerprint")
    return os.path.join(TRUST_DIR, fp + ".pub")


def trusted_key(fp):
    """Clé publique brute de confiance d'empreinte fp, ou None (absente, retirée ou altérée)."""
    path = trusted_path(fp)
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError:
        return None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or st.st_size > 128 \
                or (not common.TEST_ROOT and st.st_uid != 0):
            return None
        text = os.read(fd, 129).decode("ascii", "replace").strip()
    finally:
        os.close(fd)
    try:
        raw = decode_public(text)
    except Fail:
        return None
    return raw if fingerprint(raw) == fp else None


def trusted_list():
    try:
        names = sorted(os.listdir(TRUST_DIR))
    except FileNotFoundError:
        return []
    out = []
    for n in names:
        fp = n[:-4] if n.endswith(".pub") else ""
        if FP_RE.match(fp) and trusted_key(fp) is not None:
            out.append(fp)
    return out


def act_trust_key(c):
    prm = c.params
    _private_dir(TRUST_DIR)
    if prm["action"] == "remove":
        path = trusted_path(prm["fingerprint"])
        existed = os.path.lexists(path)
        if existed:
            os.unlink(path)
        publish_status()
        return {"action": "remove", "fingerprint": prm["fingerprint"], "removed": existed}
    raw = decode_public(prm["public_key"])
    fp = fingerprint(raw)
    if fp != prm["fingerprint"]:
        # L'administrateur a confirmé une empreinte précise : jamais une autre clé.
        raise Fail("E_KEY_INVALID", "fingerprint does not match the public key")
    if fp not in trusted_list() and len(trusted_list()) >= MAX_TRUSTED:
        raise Fail("E_KEY_INVALID", "too many trusted keys (%d at most)" % MAX_TRUSTED)
    path = trusted_path(fp)
    if os.path.lexists(path) and not os.path.isfile(path):
        os.unlink(path)
    common.atomic_write(path, prm["public_key"] + "\n", 0o600, group_scanoria=False)
    publish_status()
    return {"action": "add", "fingerprint": fp, "public_key": prm["public_key"]}


# --------------------------------------------------------------------------
# État publié pour la console
# --------------------------------------------------------------------------

def _json(path, default=None):
    try:
        return common.load_json_file(path, 1 << 20)
    except (OSError, common.JsonError):
        return default


def load_schedule():
    """Export périodique : {enabled, every_days, keep, modules} (désactivé par défaut)."""
    s = _json(SCHEDULE_FILE)
    if isinstance(s, dict) and schema.load("schemas", "bundle-schedule").valid(s):
        return s
    return dict(DEFAULT_SCHEDULE)


DEFAULT_SCHEDULE = {"enabled": False, "every_days": 7, "keep": 2, "modules": [], "last_run_at": None}


def save_schedule(s):
    common.write_json(SCHEDULE_FILE, s, 0o640)


def publish_status(extra=None):
    """Écrit /var/lib/scanoria/offline/status.json (root:scanoria 0640), conforme à son schéma."""
    from . import bundle, mirror, dtmirror
    prev = _json(STATUS_FILE, {}) or {}
    st = {
        "version": 1,
        "updated_at": common.iso(common.now()),
        "appliance_key": appliance_key_info(),
        "trusted_keys": trusted_list(),
        "bundles": bundle.list_exports(),
        "last_import": prev.get("last_import") if isinstance(prev.get("last_import"), dict) else None,
        "mirror": mirror.client_status(),
        "publication": mirror.publication_status(),
        "schedule": load_schedule(),
        "dtrack": dtmirror.status(),
    }
    if extra:
        st.update(extra)
    errs = schema.load("schemas", "offline-status").errors(st)
    if errs:
        common.log("offline status does not match its schema: %s" % "; ".join(errs[:3]))
        return None
    common.shared_dir(OFFLINE_DIR)
    common.write_json(STATUS_FILE, st, 0o640)
    return st
