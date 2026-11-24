# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Vincent Tisseront
"""Faux serveur Dependency-Track pour tests/b19-sbom.sh (boucle locale, sans réseau).

  python3 fake_dtrack.py ETAT.json PORT.txt JOURNAL.jsonl

Reproduit les seuls points d'accès utilisés par l'appliance (dtrack.py et
dtrack_upload.py), avec leurs formes réelles : connexion par formulaire qui
rend un JWT en texte, changement de mot de passe imposé au premier accès,
équipes, droits et clés d'API, envoi de SBOM en base64 suivi d'un jeton de
traitement, recherche de projet et export de l'inventaire.

ETAT.json (relu à chaque requête, réécrit après chaque changement) :
  up                false : api/version répond 503
  admin_password    mot de passe admin courant
  force_change      true : connexion refusée « FORCE_PASSWORD_CHANGE »
  teams             [{uuid, name, permissions: [{name}], apiKeys: [clé]}]
  projects          {nom@version: {uuid, components}}
  processing        nombre de réponses « processing: true » avant la fin
  reject_bom        true : PUT api/v1/bom répond 400
Les clés et jetons sont aléatoires (jamais un motif connu de secret).
"""

import base64
import json
import os
import secrets
import sys
import urllib.parse
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

STATE, PORT_FILE, LOG = sys.argv[1:4]
JWTS = set()


def load():
    with open(STATE) as f:
        return json.load(f)


def save(st):
    tmp = STATE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(st, f)
    os.replace(tmp, STATE)


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def reply(self, code, body=None, text=None):
        data = text.encode() if text is not None else (json.dumps(body).encode() if body is not None else b"")
        self.send_response(code)
        self.send_header("Content-Type", "text/plain" if text is not None else "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def body(self):
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(n) if n else b""
        if self.headers.get("Content-Type", "").startswith("application/x-www-form-urlencoded"):
            return {k: v[0] for k, v in urllib.parse.parse_qs(raw.decode()).items()}
        return json.loads(raw.decode()) if raw else None

    def who(self, st):
        key = self.headers.get("X-Api-Key")
        if key:
            team = next((t for t in st["teams"] if key in t["apiKeys"]), None)
            return ("team", team) if team else (None, None)
        auth = self.headers.get("Authorization", "")
        if auth.startswith("Bearer ") and auth[7:] in JWTS:
            return ("admin", None)
        return (None, None)

    def handle_any(self, method):
        st = load()
        u = urllib.parse.urlsplit(self.path)
        p, q = u.path.lstrip("/"), dict(urllib.parse.parse_qsl(u.query))
        body = self.body() if method in ("POST", "PUT") else None
        kind, team = self.who(st)
        with open(LOG, "a") as f:
            f.write(json.dumps({"m": method, "p": p, "q": q, "auth": kind,
                                "key_header": bool(self.headers.get("X-Api-Key"))}) + "\n")
        perms = {x["name"] for x in team["permissions"]} if team else set()

        def need(perm):
            if kind == "admin" or perm in perms:
                return False
            self.reply(403 if kind else 401)
            return True

        if p == "api/version":
            return self.reply(200, {"version": "4.14.7"}) if st.get("up", True) else self.reply(503)
        if p == "api/v1/user/login" and method == "POST":
            if body.get("username") != "admin" or body.get("password") != st["admin_password"]:
                return self.reply(401, text="INVALID_CREDENTIALS")
            if st.get("force_change"):
                return self.reply(401, text="FORCE_PASSWORD_CHANGE")
            jwt = ".".join(base64.urlsafe_b64encode(secrets.token_bytes(12)).decode().rstrip("=") for _ in range(3))
            JWTS.add(jwt)
            return self.reply(200, text=jwt)
        if p == "api/v1/user/forceChangePassword" and method == "POST":
            if body.get("password") != st["admin_password"] or body.get("newPassword") != body.get("confirmPassword") \
                    or body.get("newPassword") == body.get("password"):
                return self.reply(401, text="INVALID_CREDENTIALS")
            st["admin_password"], st["force_change"] = body["newPassword"], False
            save(st)
            return self.reply(200, text="")
        if p == "api/v1/user/self":
            if kind != "admin":
                return self.reply(401)
            if method == "GET":
                return self.reply(200, {"username": "admin", "fullname": "Administrator", "email": "admin@exemple.test"})
            if body.get("newPassword") != body.get("confirmPassword") or body.get("username") != "admin":
                return self.reply(400)
            st["admin_password"] = body["newPassword"]
            save(st)
            return self.reply(200, {"username": "admin"})
        if p == "api/v1/team":
            if kind != "admin":
                return self.reply(401)
            if method == "GET":
                return self.reply(200, [{k: v for k, v in t.items() if k != "apiKeys"} for t in st["teams"]])
            t = {"uuid": str(uuid.uuid4()), "name": body["name"], "permissions": [], "apiKeys": []}
            st["teams"].append(t)
            save(st)
            return self.reply(201, {k: v for k, v in t.items() if k != "apiKeys"})
        if p.startswith("api/v1/permission/") and method == "POST":
            if kind != "admin":
                return self.reply(401)
            _, _, _, perm, _, tid = p.split("/")
            t = next((x for x in st["teams"] if x["uuid"] == tid), None)
            if t is None:
                return self.reply(404)
            if any(x["name"] == perm for x in t["permissions"]):
                return self.reply(304)
            t["permissions"].append({"name": perm})
            save(st)
            return self.reply(200, t)
        if p.startswith("api/v1/team/") and p.endswith("/key") and method == "PUT":
            if kind != "admin":
                return self.reply(401)
            t = next((x for x in st["teams"] if x["uuid"] == p.split("/")[3]), None)
            if t is None:
                return self.reply(404)
            key = "odt_" + secrets.token_hex(4) + "_" + secrets.token_hex(16)
            t["apiKeys"].append(key)
            save(st)
            return self.reply(201, {"key": key, "maskedKey": key[:8] + "****"})
        if p == "api/v1/project" and method == "GET":
            if need("VIEW_PORTFOLIO"):
                return None
            return self.reply(200, [{"uuid": v["uuid"], "name": k} for k, v in st["projects"].items()][:1])
        if p == "api/v1/bom" and method == "PUT":
            if need("BOM_UPLOAD") or (not body.get("autoCreate") or need("PROJECT_CREATION_UPLOAD")):
                return None
            if st.get("reject_bom"):
                return self.reply(400)
            doc = json.loads(base64.b64decode(body["bom"]))
            key = "%s@%s" % (body["projectName"], body["projectVersion"])
            proj = st["projects"].setdefault(key, {"uuid": str(uuid.uuid4()), "components": []})
            proj["components"] = [{"type": "library", "bom-ref": str(uuid.uuid4()), **{k: c[k] for k in ("name", "version", "purl", "licenses") if k in c}}
                                  for c in doc.get("components", [])]
            st["left"] = st.get("processing", 0)
            save(st)
            return self.reply(200, {"token": str(uuid.uuid4())})
        if p.startswith("api/v1/event/token/"):
            if kind is None:
                return self.reply(401)
            left = st.get("left", 0)
            st["left"] = max(0, left - 1)
            save(st)
            return self.reply(200, {"processing": left > 0})
        if p == "api/v1/project/lookup":
            if need("VIEW_PORTFOLIO"):
                return None
            proj = st["projects"].get("%s@%s" % (q.get("name"), q.get("version")))
            return self.reply(200, {"uuid": proj["uuid"], "name": q["name"]}) if proj else self.reply(404)
        if p.startswith("api/v1/bom/cyclonedx/project/"):
            if need("VIEW_PORTFOLIO"):
                return None
            pid = p.rsplit("/", 1)[1]
            proj = next((v for v in st["projects"].values() if v["uuid"] == pid), None)
            if proj is None or q.get("variant") != "inventory":
                return self.reply(404)
            if self.headers.get("Accept") != "application/vnd.cyclonedx+json":
                return self.reply(406)  # comme le vrai service
            return self.reply(200, {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": proj["components"]})
        return self.reply(404)

    def do_GET(self):
        self.handle_any("GET")

    def do_POST(self):
        self.handle_any("POST")

    def do_PUT(self):
        self.handle_any("PUT")


srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
with open(PORT_FILE + ".tmp", "w") as f:
    f.write(str(srv.server_address[1]))
os.replace(PORT_FILE + ".tmp", PORT_FILE)
srv.serve_forever()
