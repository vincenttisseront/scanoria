#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Vincent Tisseront
"""Faux serveur HTTPS de bases de vulnérabilités pour tests/b18-feeds.sh.

  fakefeeds.py serve CERT KEY PORTFILE DIR
  fakefeeds.py layer OUT MODE      (fabrique une couche trivy-db, saine ou piégée)

Sert, depuis DIR :
- /osv/<écosystème>/all.zip           → DIR/osv/<écosystème>/all.zip ;
- /v2/aquasec/trivy-db/manifests/2    → DIR/manifest.json, après un jeton
  anonyme (401 + WWW-Authenticate: Bearer, puis /token) ;
- /v2/aquasec/trivy-db/blobs/<digest> → redirection 307 vers /storage/<digest>,
  servi depuis DIR/blob.
Le fichier DIR/mode règle les pannes : « down » (500 partout), sinon normal.
"""

import http.server
import io
import json
import os
import ssl
import sys
import tarfile

TOKEN = "jeton-anonyme-de-test"


def layer(out, mode):
    meta = json.dumps({"Version": 2, "UpdatedAt": "2026-11-24T00:00:00Z", "NextUpdate": "2026-11-25T00:00:00Z"}).encode()
    db = b"SQLite format 3\x00" + os.urandom(4096)
    with tarfile.open(out, "w:gz") as t:
        def add(name, data, kind=tarfile.REGTYPE, link=""):
            i = tarfile.TarInfo(name)
            i.size, i.type, i.linkname = (len(data) if kind == tarfile.REGTYPE else 0), kind, link
            t.addfile(i, io.BytesIO(data) if kind == tarfile.REGTYPE else None)
        if mode == "symlink":
            add("trivy.db", b"", tarfile.SYMTYPE, "/etc/passwd")
            add("metadata.json", meta)
        elif mode == "dotdot":
            add("../evade.db", db)
            add("trivy.db", db)
            add("metadata.json", meta)
        elif mode == "extra":
            add("trivy.db", db)
            add("metadata.json", meta)
            add("autre/fichier", b"x")
        elif mode == "nometa":
            add("trivy.db", db)
        else:
            add("trivy.db", db)
            add("metadata.json", meta)


class Handler(http.server.BaseHTTPRequestHandler):
    base = None

    def log_message(self, *a):
        pass

    def send(self, code, body=b"", headers=None):
        self.send_response(code)
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def file(self, path):
        try:
            with open(path, "rb") as f:
                self.send(200, f.read())
        except OSError:
            self.send(404)

    def do_GET(self):
        d = self.base
        mode = open(os.path.join(d, "mode")).read().strip() if os.path.exists(os.path.join(d, "mode")) else ""
        if mode == "down":
            return self.send(500)
        p = self.path
        if p.startswith("/osv/"):
            parts = p.split("/")
            if len(parts) == 4 and parts[3] == "all.zip" and ".." not in parts:
                return self.file(os.path.join(d, "osv", parts[2], "all.zip"))
            return self.send(404)
        if p.startswith("/token?"):
            return self.send(200, json.dumps({"token": TOKEN}).encode())
        if p.startswith("/v2/"):
            if self.headers.get("Authorization") != "Bearer " + TOKEN:
                realm = "https://%s/token" % self.headers.get("Host")
                return self.send(401, b"{}", {"WWW-Authenticate":
                                              'Bearer realm="%s",service="test",scope="repository:aquasec/trivy-db:pull"' % realm})
            if p == "/v2/aquasec/trivy-db/manifests/2":
                return self.file(os.path.join(d, "manifest.json"))
            if p.startswith("/v2/aquasec/trivy-db/blobs/"):
                return self.send(307, b"", {"Location": "/storage/" + p.rsplit("/", 1)[1]})
            return self.send(404)
        if p.startswith("/storage/"):
            return self.file(os.path.join(d, "blob"))
        self.send(404)


def serve(cert, key, portfile, base):
    Handler.base = base
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    with open(portfile + ".tmp", "w") as f:
        f.write(str(srv.server_address[1]))
    os.rename(portfile + ".tmp", portfile)
    srv.serve_forever()


if __name__ == "__main__":
    if sys.argv[1] == "serve":
        serve(*sys.argv[2:6])
    elif sys.argv[1] == "layer":
        layer(sys.argv[2], sys.argv[3])
    else:
        sys.exit(2)
