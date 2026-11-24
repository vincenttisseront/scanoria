# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Vincent Tisseront
"""Mise en service automatique des modules « service » (principe 8, chantier B de la 0.4).

Appelé par modules.py après la santé du service et avant le banc d'essai, à
l'installation, à la réactivation et après une mise à jour :
    provision.run(manifest, info)
info = {host_port, secrets_dir, network, timeout, phase}. Ne fait rien pour un
module sans mise en service. Un Fail déclenche le retour arrière du moteur.

SonarQube Community Build :
  - attend l'état UP (migration de base lancée si une mise à jour l'exige) ;
  - remplace le mot de passe « admin » par défaut par une valeur aléatoire,
    écrite seulement dans un fichier root 0600 (jamais affichée, jamais en base) ;
  - crée l'utilisateur local « scanoria-scan » (droits globaux : analyse et
    création de projets) et son jeton d'analyse, fichier root 0600 scan-token
    lu par le runner (contrat 12) ;
  - force l'authentification et rend les nouveaux projets privés ; le quality
    gate SonarQube reste celui par défaut, le verdict restant celui de Scanoria.
Les comptes locaux n'ont pas d'inscription libre ; aucun fournisseur externe
n'est configuré (OIDC en 1.0).

reset_admin(mid) : nouveau mot de passe admin, déposé une seule fois dans
/run/scanoria/oneshot/<id de demande> (mémoire vive, root:scanoria 0640) ; la
console le lit une seule fois, juste après la fin de la demande. Le fichier est
effacé au plus tard ONESHOT_TTL_S après son dépôt : minuteur systemd transitoire
posé à l'écriture, purge à chaque passage du helper, et tmpfiles en dernier
recours.
"""

import base64
import json
import os
import re
import secrets
import stat
import time
import urllib.error
import urllib.parse
import urllib.request

from . import common
from .common import Fail

ADMIN = "admin"
DEFAULT_ADMIN_PASSWORD = "admin"
SCAN_USER = "scanoria-scan"
TOKEN_NAME = "scanoria-analyses"
ADMIN_FILE = "admin-password"
SCAN_TOKEN_FILE = "scan-token"
HTTP_TIMEOUT = 30
MAX_RESPONSE = 4 << 20
ONESHOT = common.RUN + "/oneshot"
ONESHOT_TTL_S = 120   # la console lit la valeur dès la fin de la demande
PASSWORD_RE = re.compile(r"[A-Za-z0-9#%+=_.-]{20,128}\Z")
TOKEN_RE = re.compile(r"[A-Za-z0-9_]{10,200}\Z")


def run(m, info):
    """Point d'entrée appelé par le moteur des services ; sans effet hors des modules connus."""
    fn = PROVISIONERS.get(m.get("id")) if isinstance(m, dict) else None
    if fn is None:
        return None
    return fn(m, info)


def secrets_dir(mid, info=None):
    d = (info or {}).get("secrets_dir")
    if isinstance(d, str) and os.path.isabs(d):
        return d
    try:
        from . import services
        return os.path.dirname(services.secret_path(mid, SCAN_TOKEN_FILE))
    except (ImportError, AttributeError):
        return os.path.join(common.VARLIB, "modules", mid, "secrets")


def new_password():
    """Mot de passe conforme à la politique de SonarQube (≥ 12, majuscule, minuscule, chiffre, spécial)."""
    return "Sq#" + secrets.token_hex(16) + "-" + secrets.token_urlsafe(12).replace("-", "x").replace("_", "y") + "9a"


def read_secret(path, regex):
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_NOCTTY)
    except OSError:
        return None
    with os.fdopen(fd, "rb") as f:
        st = os.fstat(f.fileno())
        if not stat.S_ISREG(st.st_mode) or stat.S_IMODE(st.st_mode) & 0o077:
            return None
        data = f.read(1025)
    try:
        v = data.decode("ascii").strip()
    except UnicodeDecodeError:
        return None
    return v if regex.match(v) else None


def write_secret(path, value):
    os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
    common.atomic_write(path, value + "\n", 0o600, group_scanoria=False)


# --------------------------------------------------------------------------
# Client HTTP minimal (boucle locale, aucun mandataire)
# --------------------------------------------------------------------------

class Http:
    def __init__(self, port):
        if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
            raise Fail("E_INVALID_PARAM", "invalid service port")
        self.base = "http://127.0.0.1:%d/" % port
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def call(self, method, path, params=None, auth=None):
        """(code HTTP, JSON ou None) ; auth = (identifiant, mot de passe) ou jeton."""
        data = None
        url = self.base + path
        if params and method == "GET":
            url += "?" + urllib.parse.urlencode(params)
        elif params:
            data = urllib.parse.urlencode(params).encode()
        headers = {"Accept": "application/json"}
        if isinstance(auth, tuple):
            headers["Authorization"] = "Basic " + base64.b64encode(("%s:%s" % auth).encode()).decode()
        elif isinstance(auth, str):
            headers["Authorization"] = "Bearer " + auth
        if data is not None:
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        req = urllib.request.Request(url, data=data, method=method, headers=headers)
        try:
            with self.opener.open(req, timeout=HTTP_TIMEOUT) as r:
                code, body = r.status, r.read(MAX_RESPONSE + 1)
        except urllib.error.HTTPError as e:
            code, body = e.code, e.read(65536)
        except (urllib.error.URLError, OSError):
            return 0, None
        if not body or len(body) > MAX_RESPONSE:
            return code, None
        try:
            return code, json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            return code, None


def _deadline(info, default=900):
    t = (info or {}).get("timeout")
    t = t if isinstance(t, (int, float)) and not isinstance(t, bool) and t > 0 else default
    return time.monotonic() + min(t, 3000)


def _sleep(s):
    time.sleep(0.05 if common.TEST_ROOT else s)


# --------------------------------------------------------------------------
# SonarQube
# --------------------------------------------------------------------------

def sonar_wait_up(http, deadline):
    """Attend l'état UP ; lance la migration de base si elle est demandée."""
    migrated = False
    while True:
        code, st = http.call("GET", "api/system/status")
        status = st.get("status") if isinstance(st, dict) else None
        if code == 200 and status == "UP":
            return st.get("version") if isinstance(st.get("version"), str) else None
        if status == "DB_MIGRATION_NEEDED" and not migrated:
            http.call("POST", "api/system/migrate_db")
            migrated = True
        if status in ("DOWN", "DB_MIGRATION_NEEDED_NOT_SUPPORTED") or time.monotonic() > deadline:
            raise Fail("E_SONAR_UNAVAILABLE", "SonarQube did not become UP (status %s)" % (status or "unknown"))
        _sleep(5)


def _valid(http, auth):
    code, r = http.call("GET", "api/authentication/validate", auth=auth)
    return code == 200 and isinstance(r, dict) and r.get("valid") is True


def _must(result, what):
    code, body = result
    if code not in (200, 204):
        raise Fail("E_SONAR_API", "SonarQube API %s failed (HTTP %d)" % (what, code))
    return body


def sonar_admin(http, sdir):
    """Mot de passe admin connu de l'appliance ; remplace le mot de passe par défaut."""
    path = os.path.join(sdir, ADMIN_FILE)
    pending = path + ".new"
    cur = read_secret(path, PASSWORD_RE)
    if cur and _valid(http, (ADMIN, cur)):
        return cur
    nxt = read_secret(pending, PASSWORD_RE)
    if nxt and _valid(http, (ADMIN, nxt)):
        # Changement fait mais fichier non remplacé (arrêt brutal) : on termine.
        os.replace(pending, path)
        return nxt
    if not _valid(http, (ADMIN, DEFAULT_ADMIN_PASSWORD)):
        raise Fail("E_SONAR_ADMIN", "the SonarQube admin password is unknown to the appliance: reset it")
    pw = new_password()
    write_secret(pending, pw)  # écrit avant le changement : jamais de mot de passe perdu
    _must(http.call("POST", "api/users/change_password",
                    {"login": ADMIN, "previousPassword": DEFAULT_ADMIN_PASSWORD, "password": pw},
                    auth=(ADMIN, DEFAULT_ADMIN_PASSWORD)), "users/change_password")
    os.replace(pending, path)
    return pw


def sonar_scan_user(http, admin):
    auth = (ADMIN, admin)
    _, r = http.call("GET", "api/users/search", {"q": SCAN_USER}, auth=auth)
    users = r.get("users") if isinstance(r, dict) else None
    if not any(isinstance(u, dict) and u.get("login") == SCAN_USER for u in users or []):
        _must(http.call("POST", "api/users/create", {"login": SCAN_USER, "name": "Scanoria (analyses)",
                                                     "password": new_password(), "local": "true"}, auth=auth),
              "users/create")
    for perm in ("scan", "provisioning"):
        _must(http.call("POST", "api/permissions/add_user", {"login": SCAN_USER, "permission": perm}, auth=auth),
              "permissions/add_user")


def sonar_token(http, admin, sdir, renew=False):
    path = os.path.join(sdir, SCAN_TOKEN_FILE)
    cur = read_secret(path, TOKEN_RE)
    if cur and not renew and _valid(http, cur):
        return False
    auth = (ADMIN, admin)
    http.call("POST", "api/user_tokens/revoke", {"login": SCAN_USER, "name": TOKEN_NAME}, auth=auth)
    r = _must(http.call("POST", "api/user_tokens/generate",
                        {"login": SCAN_USER, "name": TOKEN_NAME, "type": "USER_TOKEN"}, auth=auth),
              "user_tokens/generate")
    tok = r.get("token") if isinstance(r, dict) else None
    if not isinstance(tok, str) or not TOKEN_RE.match(tok):
        raise Fail("E_SONAR_API", "SonarQube returned a malformed analysis token")
    write_secret(path, tok)
    return True


def sonar_settings(http, admin):
    auth = (ADMIN, admin)
    _must(http.call("POST", "api/settings/set", {"key": "sonar.forceAuthentication", "value": "true"}, auth=auth),
          "settings/set")
    _must(http.call("POST", "api/projects/update_default_visibility", {"projectVisibility": "private"}, auth=auth),
          "projects/update_default_visibility")
    fqdn = _appliance_fqdn()
    if fqdn:
        # Liens corrects dans l'interface de SonarQube (facultatif).
        http.call("POST", "api/settings/set", {"key": "sonar.core.serverBaseURL",
                                               "value": "https://sonarqube.%s" % fqdn}, auth=auth)


def _appliance_fqdn():
    try:
        from . import routing
        f = routing.appliance_fqdn()
    except Exception:  # noqa: BLE001 — réglage cosmétique
        return None
    return f if isinstance(f, str) and common.FQDN_RE.match(f) else None


def provision_sonarqube(m, info):
    info = info or {}
    http = Http(info.get("host_port"))
    sdir = secrets_dir(m["id"], info)
    version = sonar_wait_up(http, _deadline(info))
    try:
        admin = sonar_admin(http, sdir)
    except Fail as f:
        # Mot de passe admin changé à la main : sans conséquence tant que le jeton d'analyse vaut.
        tok = read_secret(os.path.join(sdir, SCAN_TOKEN_FILE), TOKEN_RE)
        if f.code == "E_SONAR_ADMIN" and tok and _valid(http, tok):
            common.log("provision: SonarQube admin password changed outside the appliance; analysis token kept")
            return {"version": version, "token_renewed": False, "admin_known": False}
        raise
    sonar_scan_user(http, admin)
    renewed = sonar_token(http, admin, sdir)
    sonar_settings(http, admin)
    common.log("provision: SonarQube %s ready (phase %s%s)" % (version or "?", info.get("phase", "?"),
                                                              ", analysis token renewed" if renewed else ""))
    return {"version": version, "token_renewed": renewed, "admin_known": True}


def _provision_dtrack(m, info):
    from . import dtrack
    return dtrack.provision(m, info)


PROVISIONERS = {"sonarqube": provision_sonarqube, "dependency-track": _provision_dtrack}

# Secrets créés par la mise en service et liés au contenu de la base du
# service (mot de passe admin, jeton) : sauvegardés et restaurés avec elle.
# Le mot de passe de la base (db-password) n'y est pas : il suit le rôle
# PostgreSQL, que pg_restore ne change pas.
DATA_SECRETS = {"sonarqube": (ADMIN_FILE, SCAN_TOKEN_FILE), "dependency-track": (ADMIN_FILE, SCAN_TOKEN_FILE)}


def data_secrets(mid):
    return DATA_SECRETS.get(mid, ())


# --------------------------------------------------------------------------
# reset-service-admin
# --------------------------------------------------------------------------

def purge_oneshot(now=None):
    now = now or time.time()
    try:
        names = os.listdir(ONESHOT)
    except OSError:
        return
    for n in names:
        p = os.path.join(ONESHOT, n)
        try:
            if now - os.lstat(p).st_mtime >= ONESHOT_TTL_S:
                os.unlink(p)
        except OSError:
            pass


def write_oneshot(request_id, value):
    """Dépose une valeur à lire une seule fois par la console (mémoire vive, root:scanoria 0640)."""
    if not common.UUID4_RE.match(request_id or ""):
        raise Fail("E_INVALID_PARAM", "invalid request id")
    os.makedirs(ONESHOT, mode=0o750, exist_ok=True)
    if not common.TEST_ROOT:
        os.chown(ONESHOT, 0, common.scanoria_ids()[1])
        os.chmod(ONESHOT, 0o750)
    path = os.path.join(ONESHOT, request_id + ".json")
    common.write_json(path, {"password": value}, 0o640)
    if common.TEST_ROOT:
        return
    # Effacement programmé, indépendant du helper (qui s'arrête après la demande).
    try:
        r = common.run("systemd-run", ["--quiet", "--collect", "--unit", "scanoria-oneshot-" + request_id,
                                       "--on-active=%ds" % ONESHOT_TTL_S, "--timer-property=AccuracySec=1s",
                                       "/usr/bin/rm", "-f", "--", path], timeout=30)
        if r.returncode != 0:
            common.log("cannot schedule the removal of a one-shot value: purged at the next helper run")
    except Exception as e:  # noqa: BLE001 (repli : purge au prochain passage du helper)
        common.log("cannot schedule the removal of a one-shot value: %r" % e)


def act_reset_service_admin(c):
    """Nouveau mot de passe admin d'un service, affiché une seule fois par la console."""
    mid = c.params["id"]
    purge_oneshot()
    if mid not in RESETTERS:
        raise Fail("E_PRECONDITION", "module %s has no administrator account managed by the appliance" % mid)
    from . import modules
    reg = modules.load_registry()
    e = reg["modules"].get(mid)
    if not isinstance(e, dict) or e.get("status") != "healthy" or not e.get("enabled"):
        raise Fail("E_PRECONDITION", "module %s is not installed, healthy and enabled" % mid)
    sdir = secrets_dir(mid)
    deadline = time.monotonic() + max(30, min(c.left(), 300))
    pw = RESETTERS[mid](e.get("host_port"), sdir, deadline)
    write_oneshot(c.req["id"], pw)
    return {"id": mid, "login": ADMIN, "oneshot": True}


def _reset_sonar(port, sdir, deadline):
    http = Http(port)
    sonar_wait_up(http, deadline)
    cur = read_secret(os.path.join(sdir, ADMIN_FILE), PASSWORD_RE)
    if not cur or not _valid(http, (ADMIN, cur)):
        raise Fail("E_SONAR_ADMIN", "the current SonarQube admin password is unknown to the appliance")
    pw = new_password()
    pending = os.path.join(sdir, ADMIN_FILE + ".new")
    write_secret(pending, pw)
    _must(http.call("POST", "api/users/change_password",
                    {"login": ADMIN, "previousPassword": cur, "password": pw}, auth=(ADMIN, cur)),
          "users/change_password")
    os.replace(pending, os.path.join(sdir, ADMIN_FILE))
    return pw


def _reset_dtrack(port, sdir, deadline):
    from . import dtrack
    return dtrack.reset_admin(dtrack.Http(port), sdir, deadline)


# Réinitialisation du mot de passe admin, par module mis en service.
RESETTERS = {"sonarqube": _reset_sonar, "dependency-track": _reset_dtrack}
