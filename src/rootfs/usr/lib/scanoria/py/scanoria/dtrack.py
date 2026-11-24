# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Vincent Tisseront
"""Mise en service automatique de Dependency-Track (chantier A de la 0.5, principe 8).

Appelé par provision.run après la santé du service (installation, réactivation,
mise à jour, restauration), sur le port local publié par le moteur :
  - attend que l'API réponde (api/version) ;
  - remplace le mot de passe « admin » par défaut (changement imposé au premier
    accès) par une valeur aléatoire, écrite seulement dans le fichier root 0600
    admin-password (jamais affichée, jamais en base) ;
  - crée l'équipe « Scanoria (analyses) », lui donne les seuls droits
    BOM_UPLOAD, PROJECT_CREATION_UPLOAD et VIEW_PORTFOLIO, et lui crée une clé
    d'API, fichier root 0600 scan-token lu par le runner (contrat 12) pour le
    module dtrack-upload. La clé n'est renouvelée que si elle ne vaut plus.
reset_admin : nouveau mot de passe admin (demande reset-service-admin).

Dependency-Track n'a pas d'inscription libre ; aucun fournisseur externe n'est
configuré (OIDC en 1.0). Ses miroirs de vulnérabilités (NVD, OSV, EPSS) et ses
analyseurs de dépôts de paquets utilisent la sortie Internet déclarée par le
manifeste (service.egress) ; sans Internet, ils restent vides jusqu'au mode
hors ligne de la 0.6.
"""

import json
import os
import re
import secrets
import time
import urllib.error
import urllib.parse
import urllib.request

from . import common
from .common import Fail

ADMIN = "admin"
DEFAULT_ADMIN_PASSWORD = "admin"
TEAM_NAME = "Scanoria (analyses)"
PERMISSIONS = ("BOM_UPLOAD", "PROJECT_CREATION_UPLOAD", "VIEW_PORTFOLIO")
ADMIN_FILE = "admin-password"
SCAN_TOKEN_FILE = "scan-token"
HTTP_TIMEOUT = 30
MAX_RESPONSE = 4 << 20
UUID_RE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z")
JWT_RE = re.compile(r"[A-Za-z0-9_-]{4,4000}\.[A-Za-z0-9_-]{4,8000}\.[A-Za-z0-9_-]{4,4000}\Z")
E_UNAVAILABLE, E_ADMIN, E_API = "E_DTRACK_UNAVAILABLE", "E_DTRACK_ADMIN", "E_DTRACK_API"


class Http:
    """Client minimal de l'API Dependency-Track sur la boucle locale (aucun mandataire)."""

    def __init__(self, port):
        if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
            raise Fail("E_INVALID_PARAM", "invalid service port")
        self.base = "http://127.0.0.1:%d/" % port
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def call(self, method, path, form=None, body=None, jwt=None, key=None, params=None):
        """(code HTTP, JSON, texte brut) ; form = formulaire, body = JSON."""
        url = self.base + path
        if params:
            url += "?" + urllib.parse.urlencode(params)
        headers = {"Accept": "application/json, text/plain"}
        data = None
        if form is not None:
            data = urllib.parse.urlencode(form).encode()
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        elif body is not None:
            data = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        if jwt:
            headers["Authorization"] = "Bearer " + jwt
        if key:
            headers["X-Api-Key"] = key
        req = urllib.request.Request(url, data=data, method=method, headers=headers)
        try:
            with self.opener.open(req, timeout=HTTP_TIMEOUT) as r:
                code, raw = r.status, r.read(MAX_RESPONSE + 1)
        except urllib.error.HTTPError as e:
            code, raw = e.code, e.read(65536)
        except (urllib.error.URLError, OSError):
            return 0, None, ""
        if len(raw) > MAX_RESPONSE:
            return code, None, ""
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            return code, None, ""
        try:
            return code, json.loads(text) if text else None, text
        except ValueError:
            return code, None, text


def _provision():
    from . import provision
    return provision


def wait_up(http, deadline):
    while True:
        code, v, _ = http.call("GET", "api/version")
        if code == 200 and isinstance(v, dict):
            return v.get("version") if isinstance(v.get("version"), str) else None
        if time.monotonic() > deadline:
            raise Fail(E_UNAVAILABLE, "Dependency-Track API did not answer in time")
        _provision()._sleep(5)


def login(http, password):
    """Jeton de session (JWT), « force » si le mot de passe doit être changé, ou None."""
    code, _, text = http.call("POST", "api/v1/user/login", form={"username": ADMIN, "password": password})
    text = text.strip()
    if code == 200 and JWT_RE.match(text):
        return text
    if code == 401 and "FORCE_PASSWORD_CHANGE" in text:
        return "force"
    return None


def new_password():
    return "Dt#" + secrets.token_hex(16) + "-" + secrets.token_urlsafe(12).replace("-", "x").replace("_", "y") + "9a"


def _force_change(http, old, new):
    code, _, _ = http.call("POST", "api/v1/user/forceChangePassword",
                           form={"username": ADMIN, "password": old, "newPassword": new, "confirmPassword": new})
    if code not in (200, 204):
        raise Fail(E_API, "Dependency-Track API user/forceChangePassword failed (HTTP %d)" % code)


def _self_change(http, jwt, new):
    code, me, _ = http.call("GET", "api/v1/user/self", jwt=jwt)
    if code != 200 or not isinstance(me, dict):
        raise Fail(E_API, "Dependency-Track API user/self failed (HTTP %d)" % code)
    body = {k: me.get(k) for k in ("username", "fullname", "email") if isinstance(me.get(k), str)}
    body.update({"newPassword": new, "confirmPassword": new})
    code, _, _ = http.call("POST", "api/v1/user/self", body=body, jwt=jwt)
    if code not in (200, 204):
        raise Fail(E_API, "Dependency-Track API user/self (password) failed (HTTP %d)" % code)


def admin_session(http, sdir):
    """JWT de l'administrateur ; remplace le mot de passe par défaut au premier passage."""
    p = _provision()
    path = os.path.join(sdir, ADMIN_FILE)
    pending = path + ".new"
    for cand, file in ((p.read_secret(path, p.PASSWORD_RE), None), (p.read_secret(pending, p.PASSWORD_RE), pending)):
        if not cand:
            continue
        jwt = login(http, cand)
        if jwt and jwt != "force":
            if file:  # changement fait mais fichier non remplacé (arrêt brutal) : on termine
                os.replace(pending, path)
            return jwt
    if login(http, DEFAULT_ADMIN_PASSWORD) is None:
        raise Fail(E_ADMIN, "the Dependency-Track admin password is unknown to the appliance: reset it")
    pw = new_password()
    p.write_secret(pending, pw)  # écrit avant le changement : jamais de mot de passe perdu
    _force_change(http, DEFAULT_ADMIN_PASSWORD, pw)
    jwt = login(http, pw)
    if not jwt or jwt == "force":
        raise Fail(E_API, "Dependency-Track refused the new admin password")
    os.replace(pending, path)
    return jwt


def key_valid(http, key):
    code, _, _ = http.call("GET", "api/v1/project", key=key, params={"pageSize": "1", "pageNumber": "1"})
    return code == 200


def scan_team(http, jwt):
    """uuid de l'équipe d'analyse, créée au besoin avec ses seuls droits."""
    code, teams, _ = http.call("GET", "api/v1/team", jwt=jwt)
    if code != 200 or not isinstance(teams, list):
        raise Fail(E_API, "Dependency-Track API team (list) failed (HTTP %d)" % code)
    team = next((t for t in teams if isinstance(t, dict) and t.get("name") == TEAM_NAME), None)
    if team is None:
        code, team, _ = http.call("PUT", "api/v1/team", body={"name": TEAM_NAME}, jwt=jwt)
        if code not in (200, 201) or not isinstance(team, dict):
            raise Fail(E_API, "Dependency-Track API team (create) failed (HTTP %d)" % code)
    uuid = team.get("uuid")
    if not isinstance(uuid, str) or not UUID_RE.match(uuid):
        raise Fail(E_API, "Dependency-Track returned a malformed team")
    have = {x.get("name") for x in team.get("permissions") or [] if isinstance(x, dict)}
    for perm in PERMISSIONS:
        if perm in have:
            continue
        code, _, _ = http.call("POST", "api/v1/permission/%s/team/%s" % (perm, uuid), jwt=jwt)
        if code not in (200, 201, 304):
            raise Fail(E_API, "Dependency-Track API permission %s failed (HTTP %d)" % (perm, code))
    return uuid


def scan_key(http, jwt, team, sdir):
    """Clé d'API de l'équipe d'analyse ; True si elle vient d'être créée."""
    p = _provision()
    path = os.path.join(sdir, SCAN_TOKEN_FILE)
    cur = p.read_secret(path, p.TOKEN_RE)
    if cur and key_valid(http, cur):
        return False
    code, r, _ = http.call("PUT", "api/v1/team/%s/key" % team, jwt=jwt)
    key = r.get("key") if isinstance(r, dict) else None
    if code not in (200, 201) or not isinstance(key, str) or not p.TOKEN_RE.match(key):
        raise Fail(E_API, "Dependency-Track did not return a usable API key (HTTP %d)" % code)
    p.write_secret(path, key)
    return True


def provision(m, info):
    p = _provision()
    info = info or {}
    http = Http(info.get("host_port"))
    sdir = p.secrets_dir(m["id"], info)
    version = wait_up(http, p._deadline(info))
    try:
        jwt = admin_session(http, sdir)
    except Fail as f:
        # Mot de passe admin changé à la main : sans conséquence tant que la clé d'analyse vaut.
        key = p.read_secret(os.path.join(sdir, SCAN_TOKEN_FILE), p.TOKEN_RE)
        if f.code == E_ADMIN and key and key_valid(http, key):
            common.log("provision: Dependency-Track admin password changed outside the appliance; API key kept")
            return {"version": version, "token_renewed": False, "admin_known": False}
        raise
    renewed = scan_key(http, jwt, scan_team(http, jwt), sdir)
    common.log("provision: Dependency-Track %s ready (phase %s%s)" % (version or "?", info.get("phase", "?"),
                                                                     ", API key renewed" if renewed else ""))
    return {"version": version, "token_renewed": renewed, "admin_known": True}


def reset_admin(http, sdir, deadline):
    """Nouveau mot de passe admin ; renvoie la valeur (déposée une fois par l'appelant)."""
    p = _provision()
    wait_up(http, deadline)
    path = os.path.join(sdir, ADMIN_FILE)
    cur = p.read_secret(path, p.PASSWORD_RE)
    jwt = login(http, cur) if cur else None
    if not jwt or jwt == "force":
        raise Fail(E_ADMIN, "the current Dependency-Track admin password is unknown to the appliance")
    pw = new_password()
    pending = path + ".new"
    p.write_secret(pending, pw)
    _self_change(http, jwt, pw)
    os.replace(pending, path)
    return pw
