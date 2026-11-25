# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Vincent Tisseront
"""Signature du rapport de release par la clé de l'appliance (chantier A de
la 0.8, contrat 37, CLAUDE.md § 7.3).

La console construit le rapport canonique (webui/server/release/canonical.ts)
et le dépose en entier dans la demande sign-release-report (params.content_b64,
6 Mio au plus, seul type avec sign-attestation à dépasser 128 Kio). Le helper ne
fait confiance à rien :
- base64 strict (alphabet, remplissage), taille revérifiée après décodage ;
- JSON strict (common.loads_strict), puis forme canonique recalculée ici :
  octet pour octet identique, sinon refus (E_SIGN_CANONICAL) ;
- « schema » attendu pour le type demandé, « scan_id » égal à celui de la
  demande, empreinte SHA-256 recalculée et égale à params.sha256 ;
- seulement ensuite, signature Ed25519 de ces octets par offline.sign.
Il ne signe jamais une empreinte seule venue de la console. La clé privée ne
quitte jamais ce processus : la sortie est {signature, key_fingerprint, sha256}.

canonical_bytes et check_canonical servent aussi à sign-attestation (chantier D).
"""

import base64
import binascii
import hashlib
import json
import os
import re
import tempfile

from . import common, offline
from .common import Fail

MAX_CONTENT = 4 * 1024 * 1024
B64_RE = re.compile(r"(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?\Z", re.ASCII)
KEY_RE = re.compile(r"[\x20-\x7e]{1,128}\Z", re.ASCII)
SAFE_INT = 2 ** 53 - 1
SCHEMAS = {"release-report": "scanoria-release-report/1"}


def _check_values(v, depth=0):
    """Restrictions de la forme canonique (mêmes que canonical.ts)."""
    if depth > 30:
        raise Fail("E_SIGN_CANONICAL", "too deep")
    if isinstance(v, bool) or v is None or isinstance(v, str):
        return
    if isinstance(v, int):
        if abs(v) > SAFE_INT:
            raise Fail("E_SIGN_CANONICAL", "integer out of range")
        return
    if isinstance(v, float):
        raise Fail("E_SIGN_CANONICAL", "non-integer number")
    if isinstance(v, list):
        for x in v:
            _check_values(x, depth + 1)
        return
    if isinstance(v, dict):
        for k, x in v.items():
            if not KEY_RE.match(k):
                raise Fail("E_SIGN_CANONICAL", "invalid key")
            _check_values(x, depth + 1)
        return
    raise Fail("E_SIGN_CANONICAL", "unsupported value")


def canonical_bytes(obj):
    """Octets canoniques : clés triées, sans espaces, UTF-8 (identique à canonical.ts)."""
    _check_values(obj)
    try:
        return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                          allow_nan=False).encode("utf-8", "strict")
    except (ValueError, UnicodeEncodeError) as e:
        raise Fail("E_SIGN_CANONICAL", "not representable: %s" % str(e)[:100]) from e


def check_canonical(raw):
    """Objet JSON de raw si raw est exactement sa forme canonique ; Fail sinon."""
    try:
        obj = common.loads_strict(raw)
    except common.JsonError as e:
        raise Fail("E_SIGN_CANONICAL", "invalid JSON: %s" % e) from e
    if not isinstance(obj, dict):
        raise Fail("E_SIGN_CANONICAL", "content must be an object")
    if canonical_bytes(obj) != raw:
        raise Fail("E_SIGN_CANONICAL", "content is not in canonical form")
    return obj


def decode_content(b64):
    """Base64 strict (alphabet et remplissage), taille revérifiée après décodage."""
    if not isinstance(b64, str) or len(b64) > (MAX_CONTENT + 2) // 3 * 4:
        raise Fail("E_SIGN_TOO_LARGE", "content too large")
    if not b64 or not B64_RE.match(b64):
        raise Fail("E_SIGN_ENCODING", "content is not strict base64")
    try:
        raw = base64.b64decode(b64, validate=True)
    except (binascii.Error, ValueError) as e:
        raise Fail("E_SIGN_ENCODING", "content is not strict base64") from e
    if len(raw) > MAX_CONTENT:
        raise Fail("E_SIGN_TOO_LARGE", "content too large")
    if base64.b64encode(raw).decode("ascii") != b64:
        raise Fail("E_SIGN_ENCODING", "non-canonical base64")
    return raw


def sign_bytes(raw):
    """(signature base64, empreinte de la clé) de raw, par la clé de l'appliance."""
    try:
        offline.ensure_key()
        _, fp = offline.appliance_public()
    except Fail as e:
        raise Fail("E_SIGN_KEY", "appliance key unavailable: %s" % e.message) from e
    if fp is None:
        raise Fail("E_SIGN_KEY", "appliance key unavailable")
    fd, path = tempfile.mkstemp(prefix=".sign-", dir=common.RUN)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(raw)
        try:
            sig = offline.sign(path)
        except Fail as e:
            raise Fail("E_SIGN_KEY", e.message) from e
    finally:
        os.unlink(path)
    return sig, fp


def act_sign_release_report(c):
    prm = c.params
    if prm["kind"] != "release-report":
        raise Fail("E_SIGN_SCHEMA", "unexpected kind")
    raw = decode_content(prm["content_b64"])
    if hashlib.sha256(raw).hexdigest() != prm["sha256"]:
        raise Fail("E_SIGN_DIGEST", "sha256 does not match the content")
    obj = check_canonical(raw)
    if obj.get("schema") != SCHEMAS["release-report"]:
        raise Fail("E_SIGN_SCHEMA", "unexpected schema")
    if obj.get("scan_id") != prm["scan_id"]:
        raise Fail("E_SIGN_SCAN", "scan_id differs from the request")
    sig, fp = sign_bytes(raw)
    common.log("release report of scan %s signed (%s)" % (prm["scan_id"], prm["sha256"][:12]))
    return {"kind": "release-report", "scan_id": prm["scan_id"], "sha256": prm["sha256"],
            "signature": sig, "key_fingerprint": fp}
