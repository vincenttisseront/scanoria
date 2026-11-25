# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Vincent Tisseront
"""Modules d'analyse par IA reliés au relais de scanoria-ai (0.7, contrat 31).

Un scanner qui déclare scan.network: ai-relay garde --network=none : il ne
joint jamais Ollama, ni aucun réseau. Le runner lui monte en lecture seule :
  - le socket Unix du relais (/run/scanoria-ai/relay.sock), servi en HTTPS par
    scanoria-ai avec le certificat ai-relay.<nom> de l'AC interne ;
  - le pont de l'appliance (scan-tools/ai-relay/bridge.py), qui écoute dans le
    conteneur sur 127.0.0.1:8443 et relaie octet par octet chaque connexion
    vers ce socket : le TLS va de l'outil au relais, sans rien de clair ;
  - l'AC interne (/run/scanoria-relay/ca.pem) et un /etc/hosts où
    ai-relay.<nom> désigne 127.0.0.1 ;
  - le jeton éphémère, dans un secret Podman lu par le pont, qui le passe à
    l'outil par OPENAI_API_KEY : jamais en argument ni dans « podman inspect ».
Le jeton est lié à l'analyse, au projet et au module ; son empreinte et sa
portée sont écrites dans /run/scanoria-relay/tokens (root:scanoria-ai 0750,
fichiers 0640), seul endroit que le relais consulte. Il est retiré à la fin
du module, et expire de lui-même au-delà du délai du module.

Avant de lancer le conteneur, le runner interroge le relais
(GET /v1/relay/check) : sans connecteur, sans modèle, disjoncteur ouvert, ou
projet « aucun envoi à l'IA », le module est « skipped », ce qui n'est pas
une erreur au sens de G13 (l'IA n'entre jamais dans un verdict).
"""

import hashlib
import json
import os
import re
import secrets as _secrets
import socket
import ssl
import time

from . import common
from .common import Fail

NETWORK = "ai-relay"
SOCKET = common.p("/run/scanoria-ai/relay.sock")
TOKEN_DIR = common.p("/run/scanoria-relay/tokens")
CA_CERT = common.VARLIB + "/public/scanoria-ca.crt"
BRIDGE_DIR = common.p("/usr/lib/scanoria/scan-tools/ai-relay")
AI_GROUP = "scanoria-ai"
PORT = 8443
MOUNT = "/run/scanoria-relay"
BRIDGE_MOUNT = "/scanoria-relay"
TOKEN_NAME = "relay-token"
MODEL_ALIAS = "scanoria"
NOBODY = 65534
PYTHON_RE = re.compile(r"(python3|/[A-Za-z0-9._/-]{1,120}/python3(\.[0-9]{1,2})?)\Z")
SECRET_RE = re.compile(r"scanoria-relay-[0-9a-f]{16}\Z")
TOKEN_FILE_RE = re.compile(r"[0-9a-f]{64}\.json\Z")
UUID_RE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z")
MODULE_RE = re.compile(r"[a-z0-9][a-z0-9-]{1,40}\Z")
# Codes de résultat du runner réservés au chantier E (scan-result, 0.7).
E_RELAY_UNAVAILABLE, E_RELAY_OPT_OUT, E_RELAY_TOKEN = "E_RELAY_UNAVAILABLE", "E_RELAY_OPT_OUT", "E_RELAY_TOKEN"
CHECK_TIMEOUT_S = 15
# Marge après le délai du module : le jeton n'expire pas pendant que le conteneur s'arrête.
TOKEN_MARGIN_S = 300


class Unavailable(Exception):
    """Relais indisponible ou refus : code du runner et message (module « skipped »)."""

    def __init__(self, code, message):
        super().__init__(message)
        self.code, self.message = code, str(message)[:2000]


def uses_relay(m):
    return ((m or {}).get("scan") or {}).get("network") == NETWORK


def relay_host(fqdn=None):
    """Nom TLS du relais : ai-relay.<nom de l'appliance> (contrainte de nom DNS de l'AC interne)."""
    if fqdn is None:
        from . import routing
        fqdn = routing.appliance_fqdn()
    if not fqdn:
        raise Unavailable(E_RELAY_UNAVAILABLE, "appliance name not set: the AI relay has no certificate")
    return "ai-relay." + fqdn


def python_of(m):
    """Interpréteur de l'image qui lance le pont (scan.relay_python, python3 par défaut)."""
    py = ((m or {}).get("scan") or {}).get("relay_python") or "python3"
    if not isinstance(py, str) or not PYTHON_RE.match(py) or ".." in py:
        raise Unavailable("E_MODULE_INVALID", "invalid scan.relay_python")
    return py


def wrap_command(m, cmd):
    """Commande lancée sous le pont : il écoute, lance l'outil, rend son code de sortie."""
    return [python_of(m), "-I", BRIDGE_MOUNT + "/bridge.py", "--"] + list(cmd)


def bridge_ready():
    path = os.path.join(BRIDGE_DIR, "bridge.py")
    return os.path.isfile(path) and not os.path.islink(path) and not os.path.islink(BRIDGE_DIR)


def _ai_gid():
    if common.TEST_ROOT:
        return os.getgid()
    import grp
    try:
        return grp.getgrnam(AI_GROUP).gr_gid
    except KeyError:
        raise Unavailable(E_RELAY_UNAVAILABLE, "the scanoria-ai account is missing")


def ensure_token_dir():
    """/run/scanoria-relay/tokens : root:scanoria-ai 0750 (le relais lit, n'écrit jamais)."""
    gid = _ai_gid()
    for d in (os.path.dirname(TOKEN_DIR), TOKEN_DIR):
        os.makedirs(d, mode=0o750, exist_ok=True)
        st = os.lstat(d)
        if not os.path.isdir(d) or os.path.islink(d):
            raise Fail("E_INTERNAL", "relay token directory is not a directory")
        if not common.TEST_ROOT:
            os.chown(d, 0, gid)
            if st.st_uid != 0:
                raise Fail("E_INTERNAL", "relay token directory not owned by root")
        os.chmod(d, 0o750)
    return gid


def token_hash(token):
    return hashlib.sha256(token.encode("ascii")).hexdigest()


def write_token(token, record):
    gid = ensure_token_dir()
    path = os.path.join(TOKEN_DIR, token_hash(token) + ".json")
    tmp = path + ".tmp-" + _secrets.token_hex(4)
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o640)
    try:
        with os.fdopen(fd, "w", encoding="ascii") as f:
            json.dump(record, f, separators=(",", ":"))
        if not common.TEST_ROOT:
            os.chown(tmp, 0, gid)
        os.chmod(tmp, 0o640)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    return path


def purge_tokens(now=None, everything=False):
    """Jetons expirés (arrêt brutal du runner) : retirés à chaque module ; tous
    au démarrage du runner (everything), puisqu'aucun module ne tourne encore."""
    now = int(now if now is not None else time.time())
    try:
        names = os.listdir(TOKEN_DIR)
    except OSError:
        return 0
    n = 0
    for name in names:
        path = os.path.join(TOKEN_DIR, name)
        try:
            if not TOKEN_FILE_RE.match(name):
                if ".tmp-" in name:
                    os.unlink(path)
                continue
            with open(path, encoding="ascii") as f:
                rec = json.loads(f.read(4096))
            if everything or not isinstance(rec, dict) or not isinstance(rec.get("expires_at"), int) \
                    or rec["expires_at"] <= now:
                os.unlink(path)
                n += 1
        except (OSError, ValueError):
            try:
                os.unlink(path)
                n += 1
            except OSError:
                pass
    return n


def _hosts_file(workdir, host):
    path = os.path.join(workdir, "relay-hosts")
    with open(path, "w", encoding="ascii") as f:
        f.write("127.0.0.1\tlocalhost %s\n::1\tlocalhost ip6-localhost\n" % host)
    os.chmod(path, 0o644)
    return path


def check(token, host, timeout=CHECK_TIMEOUT_S):
    """Vérification préalable (GET /v1/relay/check) ; renvoie le modèle, ou lève Unavailable."""
    if not os.path.exists(SOCKET):
        raise Unavailable(E_RELAY_UNAVAILABLE, "the AI relay is not running (no AI connector, or scanoria-ai stopped)")
    ctx = ssl.create_default_context(cafile=CA_CERT) if os.path.isfile(CA_CERT) else None
    if ctx is None:
        raise Unavailable(E_RELAY_UNAVAILABLE, "internal CA missing: the AI relay cannot be verified")
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    raw = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    raw.settimeout(timeout)
    try:
        raw.connect(SOCKET)
        with ctx.wrap_socket(raw, server_hostname=host) as s:
            s.sendall(("GET /v1/relay/check HTTP/1.1\r\nHost: %s\r\nAuthorization: Bearer %s\r\n"
                       "Accept: application/json\r\nConnection: close\r\n\r\n" % (host, token)).encode("ascii"))
            data = b""
            while len(data) < 65536:
                try:
                    chunk = s.recv(8192)
                except OSError:
                    if data:
                        break   # fermeture abrupte après la réponse : elle est validée plus bas
                    raise
                if not chunk:
                    break
                data += chunk
    except (OSError, ssl.SSLError) as e:
        raise Unavailable(E_RELAY_UNAVAILABLE, "the AI relay did not answer: %s" % e.__class__.__name__)
    finally:
        raw.close()
    head, _, body = data.partition(b"\r\n\r\n")
    m = re.match(rb"HTTP/1\.[01] ([0-9]{3}) ", head)
    status = int(m.group(1)) if m else 0
    try:
        doc = json.loads(body.decode("utf-8", "replace") or "{}")
    except ValueError:
        doc = {}
    code = ((doc.get("error") or {}).get("code") if isinstance(doc, dict) else None) or ""
    if status == 200 and isinstance(doc, dict) and doc.get("ready") is True:
        model = doc.get("model")
        return model if isinstance(model, str) and len(model) <= 260 else None
    if status == 403:
        raise Unavailable(E_RELAY_OPT_OUT, "project marked « no data sent to AI »: AI module not run")
    if status == 401:
        raise Unavailable(E_RELAY_TOKEN, "the AI relay refused the analysis token")
    reason = re.sub(r"[^a-z_]", "", str(code))[:40] or ("HTTP %d" % status)
    raise Unavailable(E_RELAY_UNAVAILABLE, "the AI relay is unavailable (%s)" % reason)


class Lease:
    """Jeton, secret Podman, montages et variables d'un module relié au relais ; à fermer après le conteneur."""

    def __init__(self, m, *, project_id, scan_id, timeout_s, workdir, purpose="scan"):
        mid = m["id"]
        if not MODULE_RE.match(mid):
            raise Unavailable("E_MODULE_INVALID", "invalid module id")
        if purpose == "scan" and not (isinstance(project_id, str) and UUID_RE.match(project_id)):
            raise Unavailable("E_PROJECT_UNKNOWN", "the project of this scan is unknown to the runner")
        if scan_id is not None and not (isinstance(scan_id, str) and UUID_RE.match(scan_id)):
            scan_id = None
        self.m, self.purpose, self.workdir = m, purpose, workdir
        self.record = {"v": 1, "purpose": purpose, "module_id": mid,
                       "project_id": project_id if purpose == "scan" else None, "scan_id": scan_id,
                       "expires_at": int(time.time()) + int(timeout_s) + TOKEN_MARGIN_S}
        self.token = "scr_" + _secrets.token_urlsafe(48)
        self.secret = "scanoria-relay-%s" % _secrets.token_hex(8)
        self.token_path = None
        self.secret_created = False
        self.hosts = None
        self.host = None
        self.model = None

    def __enter__(self):
        try:
            if not bridge_ready():
                raise Unavailable("E_MODULE_INVALID", "appliance tool ai-relay is missing: update the appliance")
            python_of(self.m)
            self.host = relay_host()
            self.token_path = write_token(self.token, self.record)
            self.model = check(self.token, self.host)
            self.hosts = _hosts_file(self.workdir, self.host)
            tmp = os.path.join(common.RUN, "relay-secret-%s" % self.secret)
            os.makedirs(os.path.dirname(tmp), mode=0o750, exist_ok=True)
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            try:
                with os.fdopen(fd, "w", encoding="ascii") as f:
                    f.write(self.token)
                self.secret_created = True
                r = common.run("podman", ["secret", "create", self.secret, tmp], timeout=60)
            finally:
                os.unlink(tmp)
            if r.returncode != 0:
                raise Unavailable(E_RELAY_TOKEN, "cannot create the podman secret of the relay token")
        except BaseException:
            self.__exit__()
            raise
        return self

    def args(self):
        base = "https://%s:%d/v1" % (self.host, PORT)
        ca = MOUNT + "/ca.pem"
        return ["--secret", "%s,type=mount,target=%s,uid=%d,gid=%d,mode=400" % (self.secret, TOKEN_NAME, NOBODY, NOBODY),
                "--volume", "%s:%s/relay.sock:ro" % (SOCKET, MOUNT),
                "--volume", "%s:%s:ro" % (CA_CERT, ca),
                "--volume", "%s:/etc/hosts:ro" % self.hosts,
                "--volume", "%s:%s:ro" % (BRIDGE_DIR, BRIDGE_MOUNT),
                "--env", "OPENAI_BASE_URL=" + base,
                "--env", "OPENAI_API_BASE=" + base,
                "--env", "SCANORIA_AI_MODEL=" + MODEL_ALIAS,
                "--env", "SCANORIA_RELAY_PORT=%d" % PORT,
                "--env", "SSL_CERT_FILE=" + ca,
                "--env", "REQUESTS_CA_BUNDLE=" + ca,
                "--env", "NODE_EXTRA_CA_CERTS=" + ca]

    def __exit__(self, *exc):
        if self.token_path:
            try:
                os.unlink(self.token_path)
            except OSError:
                pass
            self.token_path = None
        if self.secret_created:
            try:
                common.run("podman", ["secret", "rm", self.secret], timeout=60)
            except Exception as e:  # noqa: BLE001 (repris par remove_orphan_secrets au démarrage)
                common.log("runner: cannot remove podman secret %s: %r" % (self.secret, e))
            self.secret_created = False
        if self.hosts:
            try:
                os.unlink(self.hosts)
            except OSError:
                pass
            self.hosts = None
        return False


def remove_orphan_secrets():
    """Au démarrage du runner : secrets Podman de jeton du relais laissés par un arrêt brutal."""
    try:
        r = common.run("podman", ["secret", "ls", "--format", "{{.Name}}"], timeout=60)
    except Exception as e:  # noqa: BLE001
        common.log("runner: cannot list podman secrets: %r" % e)
        return
    if r.returncode != 0:
        return
    for name in r.text.split():
        if SECRET_RE.match(name):
            try:
                common.run("podman", ["secret", "rm", name], timeout=60)
            except Exception as e:  # noqa: BLE001
                common.log("runner: cannot remove podman secret %s: %r" % (name, e))
