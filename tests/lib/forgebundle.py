# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Vincent Tisseront
"""Lots hors ligne piégés pour b25 (tests seulement).

  forgebundle.py image DIR            fausse image OCI : DIR/manifest.json, DIR/<hex> (config, couche) ;
                                      affiche l'empreinte du manifeste
  forgebundle.py forge GOOD OUT KEY TRAP
      relit le lot GOOD, applique le piège TRAP, re-signe le manifeste avec la
      clé privée KEY (PEM Ed25519) et écrit OUT. Pièges : none, badsig, signer
      (signataire = KEY), image-unknown, sha, dotdot-member, dotdot-path,
      symlink, extra, duplicate, truncated, big-manifest, order, missing.
"""

import base64
import hashlib
import io
import json
import os
import subprocess
import sys
import tarfile
import tempfile

SPKI = bytes.fromhex("302a300506032b6570032100")


def image(d):
    os.makedirs(d, exist_ok=True)
    blobs = []
    for content in (b'{"architecture":"amd64","os":"linux","config":{}}', b"couche factice de l'image\n"):
        h = hashlib.sha256(content).hexdigest()
        with open(os.path.join(d, h), "wb") as f:
            f.write(content)
        blobs.append({"digest": "sha256:" + h, "size": len(content)})
    man = {"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json",
           "config": dict(blobs[0], mediaType="application/vnd.oci.image.config.v1+json"),
           "layers": [dict(blobs[1], mediaType="application/vnd.oci.image.layer.v1.tar")]}
    raw = json.dumps(man, separators=(",", ":")).encode()
    with open(os.path.join(d, "manifest.json"), "wb") as f:
        f.write(raw)
    print("sha256:" + hashlib.sha256(raw).hexdigest())


def read(path):
    members = []
    with tarfile.open(path, "r:") as tf:
        for m in tf:
            members.append((m.name, tf.extractfile(m).read()))
    return members


def public_raw(key):
    der = subprocess.run(["openssl", "pkey", "-in", key, "-pubout", "-outform", "DER"],
                         check=True, capture_output=True).stdout
    assert der.startswith(SPKI)
    return der[len(SPKI):]


def sign(key, data):
    with tempfile.TemporaryDirectory() as t:
        src, sig = os.path.join(t, "m"), os.path.join(t, "s")
        with open(src, "wb") as f:
            f.write(data)
        subprocess.run(["openssl", "pkeyutl", "-sign", "-inkey", key, "-rawin", "-in", src, "-out", sig], check=True)
        with open(sig, "rb") as f:
            return base64.b64encode(f.read()).decode()


def add(tf, name, data, kind=tarfile.REGTYPE, target=""):
    info = tarfile.TarInfo(name)
    info.type, info.mode = kind, 0o644
    if kind == tarfile.SYMTYPE:
        info.linkname = target
        tf.addfile(info)
        return
    info.size = len(data)
    tf.addfile(info, io.BytesIO(data))


def forge(good, out, key, trap):
    members = dict(read(good))
    man = json.loads(members["manifest.json"])
    files = [(n, d) for n, d in read(good) if n not in ("manifest.json", "manifest.json.sig")]
    if trap == "signer":
        raw = public_raw(key)
        man["signer"] = {"fingerprint": hashlib.sha256(raw).hexdigest(), "public_key": base64.b64encode(raw).decode()}
    elif trap == "image-unknown":
        other = "sha256:" + hashlib.sha256(b"autre image").hexdigest()
        im = man["images"][0]
        im["digest"], im["image"] = other, im["image"].rsplit("@", 1)[0] + "@" + other
    elif trap == "sha":
        man["feeds"][0]["sha256"] = hashlib.sha256(b"autre base").hexdigest()
    elif trap == "dotdot-path":
        man["feeds"][0]["path"] = "feeds/../../evade.tar"
    raw = json.dumps(man, indent=1, sort_keys=True).encode() + b"\n"
    sig = (sign(key, raw) + "\n").encode()
    if trap == "badsig":
        b = bytearray(base64.b64decode(sig))
        b[5] ^= 0xFF
        sig = (base64.b64encode(bytes(b)).decode() + "\n").encode()
    if trap == "big-manifest":
        raw = b" " * ((16 << 20) + 1)
    with tarfile.open(out, "w", format=tarfile.PAX_FORMAT) as tf:
        if trap == "order":
            add(tf, "manifest.json.sig", sig)
            add(tf, "manifest.json", raw)
        else:
            add(tf, "manifest.json", raw)
            add(tf, "manifest.json.sig", sig)
        for i, (n, d) in enumerate(files):
            if trap == "symlink" and n.startswith("feeds/"):
                add(tf, n, b"", tarfile.SYMTYPE, "/etc/passwd")
                continue
            if trap == "missing" and n.startswith("feeds/"):
                continue
            add(tf, n, d)
            if trap == "duplicate" and i == 0:
                add(tf, n, d)
        if trap == "dotdot-member":
            add(tf, "../evade.txt", b"x")
        if trap == "extra":
            add(tf, "notes.txt", b"fichier non declare")
    if trap == "truncated":
        size = os.path.getsize(out)
        with open(out, "r+b") as f:
            f.truncate(size // 2)


if __name__ == "__main__":
    if sys.argv[1] == "image":
        image(sys.argv[2])
    else:
        forge(*sys.argv[2:6])
