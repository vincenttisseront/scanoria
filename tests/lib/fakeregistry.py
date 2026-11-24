#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Vincent Tisseront
"""Faux registres de paquets en HTTPS pour tests/b22-package-dates.sh.

  fakeregistry.py serve CERT KEY PORTFILE LOGFILE

Un seul serveur, un préfixe par écosystème (SCANORIA_TEST_PKGDATES_BASE) :
/npm, /pypi, /cargo, /golang, /maven, /gem, /nuget, /composer. Réponses
normales pour les paquets « bon », piégées pour les autres :
- npm « geant » : document plus grand que la limite ;
- npm « casse » : JSON invalide ;
- npm « ailleurs » : redirection 302 vers un autre hôte ;
- npm « lent » : réponse après le délai ;
- npm « datebizarre » : date mal formée ;
- npm « surcharge » : 429 (erreur passagère, jamais mise en cache).
Chaque chemin demandé est ajouté à LOGFILE.
"""

import http.server
import json
import ssl
import sys
import time
import urllib.parse

DATE = "2026-11-20T08:00:00.000Z"


class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def send(self, code, body, ctype="application/json", headers=()):
        data = body if isinstance(body, bytes) else json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        for k, v in headers:
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        with open(self.server.logfile, "a") as f:
            f.write(self.path + "\n")
        path = urllib.parse.unquote(self.path)
        if path.startswith("/npm/"):
            name = path[len("/npm/"):]
            if name == "geant":
                return self.send(200, b"{" + b" " * (33 << 20) + b"}")
            if name == "casse":
                return self.send(200, b"{pas du json")
            if name == "ailleurs":
                return self.send(302, b"", headers=[("Location", "https://192.0.2.1/npm/bon")])
            if name == "lent":
                time.sleep(25)
                return self.send(200, {"time": {"1.0.0": DATE}})
            if name == "surcharge":
                return self.send(429, {"error": "too many requests"})
            if name == "datebizarre":
                return self.send(200, {"time": {"1.0.0": "hier soir"}})
            if name in ("bon", "@exemple/outil"):
                return self.send(200, {"name": name, "time": {"1.0.0": DATE, "2.0.0": "2026-11-23T10:00:00Z"}})
            return self.send(404, {"error": "not found"})
        if path == "/pypi/pypi/bon/1.0.0/json":
            return self.send(200, {"urls": [{"upload_time_iso_8601": "2026-11-21T09:00:00.123456Z"},
                                            {"upload_time_iso_8601": "2026-11-22T09:00:00Z"}]})
        if path == "/cargo/api/v1/crates/bon/1.0.0":
            return self.send(200, {"version": {"num": "1.0.0", "created_at": "2026-11-19T07:00:00.5+00:00"}})
        if path == "/golang/github.com/!exemple/bon/@v/v1.0.0.info":
            return self.send(200, {"Version": "v1.0.0", "Time": "2026-11-18T06:00:00Z"})
        if path.startswith("/maven/solrsearch/select"):
            return self.send(200, {"response": {"docs": [{"g": "org.exemple", "a": "bon", "v": "1.0.0", "timestamp": 1763625600000}]}})
        if path == "/gem/api/v1/versions/bon.json":
            return self.send(200, [{"number": "1.0.0", "platform": "ruby", "created_at": "2026-11-17T05:00:00.000Z"}])
        if path == "/nuget/v3/registration5-semver1/bon/1.0.0.json":
            return self.send(200, {"published": "2026-11-16T04:00:00+00:00"})
        if path == "/composer/p2/exemple/bon.json":
            return self.send(200, {"packages": {"exemple/bon": [{"version": "v1.0.0", "time": "2026-11-15T03:00:00+00:00"}]}})
        return self.send(404, {"error": "not found"})


class Server(http.server.ThreadingHTTPServer):
    def handle_error(self, request, client_address):
        pass                                  # client qui coupe (taille dépassée, délai) : attendu


def main():
    _, cmd, cert, key, portfile, logfile = sys.argv
    assert cmd == "serve"
    srv = Server(("127.0.0.1", 0), H)
    srv.logfile = logfile
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    with open(portfile, "w") as f:
        f.write(str(srv.server_address[1]))
    srv.serve_forever()


if __name__ == "__main__":
    main()
