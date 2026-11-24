# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Vincent Tisseront
"""Faux serveur SonarQube pour tests/b17-sonarqube.sh (sans réseau, boucle locale).

  python3 fake_sonar.py ETAT.json PORT.txt JOURNAL.jsonl

ETAT.json (relu à chaque requête, réécrit après chaque changement) :
  status            UP | STARTING | DB_MIGRATION_NEEDED | DOWN
  starting          nombre de réponses STARTING avant UP
  admin_password    mot de passe admin courant
  tokens            {jeton: {login, name}}
  users, perms, settings, visibility
  ce                SUCCESS | FAILED | PENDING (tâche de calcul)
  issues_total      nombre d'issues générées (pagination)
  fixtures          répertoire des réponses enregistrées (issues-1.json…)
Les jetons générés sont aléatoires (jamais un motif connu de secret).
"""

import base64
import json
import os
import re
import secrets
import sys
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

STATE, PORT_FILE, LOG = sys.argv[1:4]
POLICY = (re.compile(r"[A-Z]"), re.compile(r"[a-z]"), re.compile(r"[0-9]"), re.compile(r"[^A-Za-z0-9]"))


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

    def _who(self, st):
        auth = self.headers.get("Authorization", "")
        if auth.startswith("Basic "):
            try:
                login, pw = base64.b64decode(auth[6:]).decode().split(":", 1)
            except Exception:  # noqa: BLE001
                return None
            if login == "admin" and pw == st["admin_password"]:
                return "admin"
            return None
        if auth.startswith("Bearer "):
            t = st["tokens"].get(auth[7:])
            return t["login"] if t else None
        return None

    def _send(self, code, obj=None):
        body = json.dumps(obj).encode() if obj is not None else b""
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _handle(self, method):
        u = urllib.parse.urlsplit(self.path)
        q = dict(urllib.parse.parse_qsl(u.query))
        if method == "POST":
            n = int(self.headers.get("Content-Length") or 0)
            q.update(urllib.parse.parse_qsl(self.rfile.read(n).decode()))
        st = load()
        who = self._who(st)
        path = u.path.lstrip("/")
        with open(LOG, "a") as f:
            f.write(json.dumps({"m": method, "p": path, "who": who,
                                "keys": sorted(k for k in q if k not in ("password", "previousPassword"))}) + "\n")
        if path == "api/system/status":
            if st.get("starting", 0) > 0:
                st["starting"] -= 1
                save(st)
                return self._send(200, {"status": "STARTING", "version": "26.11.0.134175"})
            return self._send(200, {"status": st["status"], "version": "26.11.0.134175"})
        if path == "api/system/migrate_db" and method == "POST":
            st["status"] = "UP"
            st["migrated"] = True
            save(st)
            return self._send(200, {"state": "MIGRATION_RUNNING"})
        if path == "api/authentication/validate":
            return self._send(200, {"valid": who is not None})
        if who is None:
            return self._send(401, {"errors": [{"msg": "Authentication required"}]})
        admin_only = ("api/users/", "api/permissions/", "api/user_tokens/", "api/settings/", "api/projects/")
        if path.startswith(admin_only) and who != "admin":
            return self._send(403, {"errors": [{"msg": "Insufficient privileges"}]})
        if path == "api/users/change_password" and method == "POST":
            if q.get("login") != "admin" or q.get("previousPassword") != st["admin_password"]:
                return self._send(400, {"errors": [{"msg": "wrong previous password"}]})
            pw = q.get("password", "")
            if len(pw) < 12 or not all(r.search(pw) for r in POLICY):
                return self._send(400, {"errors": [{"msg": "password policy"}]})
            st["admin_password"] = pw
            save(st)
            return self._send(204)
        if path == "api/users/search":
            users = [{"login": x, "name": x} for x in st["users"] if q.get("q", "") in x]
            return self._send(200, {"paging": {"pageIndex": 1, "pageSize": 50, "total": len(users)}, "users": users})
        if path == "api/users/create" and method == "POST":
            st["users"].append(q["login"])
            save(st)
            return self._send(200, {"user": {"login": q["login"], "local": True}})
        if path == "api/permissions/add_user" and method == "POST":
            st["perms"].append([q["login"], q["permission"]])
            save(st)
            return self._send(204)
        if path == "api/user_tokens/revoke" and method == "POST":
            st["tokens"] = {k: v for k, v in st["tokens"].items()
                            if not (v["login"] == q.get("login") and v["name"] == q.get("name"))}
            save(st)
            return self._send(204)
        if path == "api/user_tokens/generate" and method == "POST":
            tok = "fake_" + secrets.token_hex(20)
            st["tokens"][tok] = {"login": q["login"], "name": q["name"]}
            st["generated"] = st.get("generated", 0) + 1
            save(st)
            return self._send(200, {"login": q["login"], "name": q["name"], "token": tok})
        if path == "api/settings/set" and method == "POST":
            st["settings"][q["key"]] = q["value"]
            save(st)
            return self._send(204)
        if path == "api/projects/update_default_visibility" and method == "POST":
            st["visibility"] = q["projectVisibility"]
            save(st)
            return self._send(204)
        if path == "api/ce/task":
            return self._send(200, {"task": {"id": q.get("id"), "status": st.get("ce", "SUCCESS")}})
        if path in ("api/issues/search", "api/hotspots/search", "api/rules/search"):
            return self._send(200, self._page(st, path, q))
        return self._send(404, {"errors": [{"msg": "unknown"}]})

    def _page(self, st, path, q):
        name = {"api/issues/search": "issues", "api/hotspots/search": "hotspots", "api/rules/search": "rules"}[path]
        with open(os.path.join(st["fixtures"], name + "-1.json")) as f:
            base = json.load(f)
        total = st.get(name + "_total")
        if name == "rules" or total is None:
            return base
        p, ps = int(q.get("p", 1)), int(q.get("ps", 100))
        tpl = base[name][0]
        items = []
        for i in range((p - 1) * ps, min(total, p * ps)):
            it = dict(tpl)
            it["key"] = "K%07d" % i
            it["line"] = 1 + i % 20
            items.append(it)
        base[name] = items
        base["paging"] = {"pageIndex": p, "pageSize": ps, "total": total}
        return base

    def do_GET(self):
        self._handle("GET")

    def do_POST(self):
        self._handle("POST")


srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
with open(PORT_FILE + ".tmp", "w") as f:
    f.write(str(srv.server_address[1]))
os.replace(PORT_FILE + ".tmp", PORT_FILE)
srv.serve_forever()
