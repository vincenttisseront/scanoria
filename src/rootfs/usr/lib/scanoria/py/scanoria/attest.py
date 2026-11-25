# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Vincent Tisseront
"""Attestations J9 côté root (0.8, chantier D, contrat 37).

Demande sign-attestation : {scan_id, kind: "attestation", sha256, content_b64}.
La console envoie la déclaration in-toto (Statement v1) elle-même, jamais une
empreinte seule. Le helper ne fait confiance à rien :
  - base64 strict, 64 Kio au plus une fois décodé ;
  - JSON strict (common.loads_strict) et canonique (clés triées, aucun espace,
    aucun nombre non entier) : les octets signés sont ceux qui ont été relus ;
  - SHA-256 recalculé, égal à params.sha256 ;
  - forme exacte de la déclaration : _type in-toto v1, un sujet unique désigné
    par une empreinte sha256, predicateType Scanoria, prédicat dont scan_id
    est celui de la demande et dont le verdict vaut « passed » (aucune
    attestation n'est jamais signée pour un verdict défavorable) ;
  - relevé root du rapport de release signé (release.record_signed_report,
    chantier A) : le verdict « passed », le commit, le tag et l'empreinte du
    rapport viennent de ce que le helper a lui-même signé, jamais de la
    console seule. Sans relevé, aucune attestation ;
puis signe la PAE DSSE (payloadType in-toto) avec la clé de l'appliance par
offline.sign. La clé privée ne quitte jamais ce processus ; la sortie ne porte
que la signature et l'empreinte de la clé publique.
"""

import base64
import binascii
import hashlib
import json
import os
import re
import stat
import tempfile

from . import common, offline
from .common import Fail

PAYLOAD_TYPE = "application/vnd.in-toto+json"
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
PREDICATE_TYPE = "https://github.com/vincenttisseront/scanoria/attestation/release-verdict/v1"
MAX_CONTENT = 64 * 1024

SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
COMMIT_RE = re.compile(r"[0-9a-f]{40,64}\Z")
NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/@-]{0,499}\Z")
B64_RE = re.compile(r"(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?\Z")
REPORT_URL_RE = re.compile(r"https://[A-Za-z0-9.-]{1,253}(:[0-9]{1,5})?/[A-Za-z0-9._~/%-]{0,300}\Z")
TAG_RE = re.compile(r"[A-Za-z0-9._/+-]{1,255}\Z")
UUID_RE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z")
TIME_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")

SIGNED_DIR = common.VARLIB + "/release/signed"
MAX_LEDGER = 16 * 1024
LEDGER_KEYS = {"scan_id", "report_sha256", "commit_sha", "tag", "verdict", "key_fingerprint", "signed_at"}

PREDICATE_KEYS = {"scan_id", "project_id", "verdict", "commit_sha", "ref", "tag", "report_sha256", "report_url", "evaluated_at"}
OPTIONAL_KEYS = {"tag", "report_sha256", "report_url"}


def pae(payload_type, payload):
    """Pre-Authentication Encoding de DSSE v1 (octets signés)."""
    t = payload_type.encode("utf-8")
    return b"DSSEv1 %d %s %d %s" % (len(t), t, len(payload), payload)


def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _no_float(obj):
    if isinstance(obj, float):
        raise Fail("E_ATTEST_CANONICAL", "non-integer number in statement")
    if isinstance(obj, dict):
        for v in obj.values():
            _no_float(v)
    elif isinstance(obj, list):
        for v in obj:
            _no_float(v)


def decode(content_b64):
    if not isinstance(content_b64, str) or len(content_b64) > (MAX_CONTENT * 4) // 3 + 4 or not B64_RE.match(content_b64):
        raise Fail("E_ATTEST_ENCODING", "content is not strict base64")
    try:
        raw = base64.b64decode(content_b64, validate=True)
    except (binascii.Error, ValueError) as e:
        raise Fail("E_ATTEST_ENCODING", "content is not strict base64") from e
    if not raw or len(raw) > MAX_CONTENT:
        raise Fail("E_ATTEST_ENCODING", "content is empty or too large")
    return raw


def _str(v, rx):
    return isinstance(v, str) and bool(rx.match(v))


def check_statement(raw, scan_id):
    """Relit la déclaration ; lève Fail au moindre écart. Rend l'objet."""
    try:
        obj = common.loads_strict(raw)
    except common.JsonError as e:
        raise Fail("E_ATTEST_CANONICAL", "statement is not strict JSON") from e
    _no_float(obj)
    if canonical(obj) != raw:
        raise Fail("E_ATTEST_CANONICAL", "statement is not canonical JSON")
    if not isinstance(obj, dict) or set(obj) != {"_type", "subject", "predicateType", "predicate"}:
        raise Fail("E_ATTEST_STATEMENT", "unexpected statement keys")
    if obj["_type"] != STATEMENT_TYPE or obj["predicateType"] != PREDICATE_TYPE:
        raise Fail("E_ATTEST_STATEMENT", "unexpected statement or predicate type")
    subj = obj["subject"]
    if not isinstance(subj, list) or len(subj) != 1 or not isinstance(subj[0], dict) or set(subj[0]) != {"name", "digest"}:
        raise Fail("E_ATTEST_SUBJECT", "exactly one subject {name, digest} is required")
    s = subj[0]
    if not _str(s["name"], NAME_RE) or ".." in s["name"]:
        raise Fail("E_ATTEST_SUBJECT", "invalid subject name")
    if not isinstance(s["digest"], dict) or set(s["digest"]) != {"sha256"} or not _str(s["digest"]["sha256"], SHA256_RE):
        raise Fail("E_ATTEST_SUBJECT", "subject digest must be a single sha256")
    p = obj["predicate"]
    if not isinstance(p, dict) or not (PREDICATE_KEYS - OPTIONAL_KEYS) <= set(p) <= PREDICATE_KEYS:
        raise Fail("E_ATTEST_STATEMENT", "unexpected predicate keys")
    if p["scan_id"] != scan_id:
        raise Fail("E_ATTEST_SCAN", "predicate scan_id differs from the request")
    if p["verdict"] != "passed":
        # Contrat 40 : jamais d'attestation pour un verdict défavorable.
        raise Fail("E_ATTEST_VERDICT", "only a passed verdict can be attested")
    if not _str(p["project_id"], UUID_RE):
        raise Fail("E_ATTEST_STATEMENT", "invalid project_id")
    if not _str(p["commit_sha"], COMMIT_RE) or not _str(p["ref"], TAG_RE) or not _str(p["evaluated_at"], TIME_RE):
        raise Fail("E_ATTEST_STATEMENT", "invalid commit, ref or time")
    if p.get("tag") is not None and not _str(p["tag"], TAG_RE):
        raise Fail("E_ATTEST_STATEMENT", "invalid tag")
    if p.get("report_sha256") is not None and not _str(p["report_sha256"], SHA256_RE):
        raise Fail("E_ATTEST_STATEMENT", "invalid report_sha256")
    if p.get("report_url") is not None and not _str(p["report_url"], REPORT_URL_RE):
        raise Fail("E_ATTEST_STATEMENT", "invalid report_url")
    return obj


def read_signed_report(scan_id):
    """Relevé écrit par le helper à la signature du rapport de release.

    Fichier régulier appartenant à root, jamais un lien ; lève Fail si absent
    ou mal formé.
    """
    if not _str(scan_id, UUID_RE):
        raise Fail("E_ATTEST_SCAN", "invalid scan_id")
    path = os.path.join(SIGNED_DIR, scan_id + ".json")
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0))
    except OSError as e:
        raise Fail("E_ATTEST_REPORT", "no signed release report for this scan") from e
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or (not common.TEST_ROOT and st.st_uid != 0) or st.st_mode & 0o022:
            raise Fail("E_ATTEST_REPORT", "signed report record is not a root-owned file")
        with os.fdopen(fd, "rb") as f:
            fd = -1
            data = f.read(MAX_LEDGER + 1)
    finally:
        if fd >= 0:
            os.close(fd)
    if len(data) > MAX_LEDGER:
        raise Fail("E_ATTEST_REPORT", "signed report record too large")
    try:
        rec = common.loads_strict(data)
    except common.JsonError as e:
        raise Fail("E_ATTEST_REPORT", "signed report record is not strict JSON") from e
    if not isinstance(rec, dict) or not {"scan_id", "report_sha256", "commit_sha", "tag", "verdict"} <= set(rec) <= LEDGER_KEYS:
        raise Fail("E_ATTEST_REPORT", "unexpected signed report record")
    if rec["scan_id"] != scan_id:
        raise Fail("E_ATTEST_REPORT", "signed report record is for another scan")
    return rec


def check_ledger(pred):
    """Le prédicat doit reprendre exactement ce que le helper a signé."""
    rec = read_signed_report(pred["scan_id"])
    if rec["verdict"] != "passed":
        raise Fail("E_ATTEST_VERDICT", "the signed release report is not passed")
    if pred.get("report_sha256") is None or rec["report_sha256"] != pred["report_sha256"]:
        raise Fail("E_ATTEST_REPORT", "report_sha256 differs from the signed release report")
    if rec["commit_sha"] != pred["commit_sha"] or rec["tag"] != pred.get("tag"):
        raise Fail("E_ATTEST_REPORT", "commit or tag differs from the signed release report")


def act_sign_attestation(c):
    prm = c.params
    if prm.get("kind") != "attestation":
        raise Fail("E_ATTEST_STATEMENT", "unexpected kind")
    raw = decode(prm.get("content_b64"))
    digest = hashlib.sha256(raw).hexdigest()
    if digest != prm.get("sha256"):
        raise Fail("E_ATTEST_DIGEST", "content digest differs from the request")
    stmt = check_statement(raw, prm.get("scan_id"))
    check_ledger(stmt["predicate"])
    fd, path = tempfile.mkstemp(prefix=".dsse-", dir=common.RUN)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(pae(PAYLOAD_TYPE, raw))
        try:
            signature = offline.sign(path)
            _, key_fp = offline.appliance_public()
        except Fail as e:
            raise Fail("E_ATTEST_KEY", "appliance key unavailable") from e
        if not key_fp:
            raise Fail("E_ATTEST_KEY", "appliance key unavailable")
    finally:
        os.unlink(path)
    return {
        "kind": "attestation",
        "sha256": digest,
        "subject_digest": "sha256:" + stmt["subject"][0]["digest"]["sha256"],
        "payload_type": PAYLOAD_TYPE,
        "signature": signature,
        "key_fingerprint": key_fp,
    }
