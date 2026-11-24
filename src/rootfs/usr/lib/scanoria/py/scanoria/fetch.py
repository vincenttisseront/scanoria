# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Vincent Tisseront
"""Récupération de la source d'une analyse (ARCHITECTURE § 12.4, CLAUDE.md § 6.4).

Dépôt Git : cloné dans un conteneur jetable du module système git-fetch, sans
capacité, système de fichiers en lecture seule sauf la destination, sur un
réseau podman dédié (scanoria-fetch) dont la sortie est fermée par nftables,
sauf vers les adresses de la forge résolues ici par le runner et pour la seule
durée du clone. Aucun DNS dans le conteneur (--dns=none, --add-host). Aucun
hook, filtre, sous-module ni lien symbolique ; seuls https et ssh sont permis.
Le jeton passe par une variable d'environnement héritée (jamais dans l'URL,
l'argv ni le journal) ; la clé SSH par un tmpfs, fichier 0400.

Archive téléversée : uploads/<upload_id>/source.{zip,tar,tar.gz}, reconnue par
son en-tête, extraite sans lien, sans chemin sortant ni fichier spécial, avec
des tailles bornées ; ce qui est écarté est listé dans source.skipped (G15).

L'arbre obtenu est ensuite borné (taille d'un fichier, taille totale, nombre
de fichiers) ; les fichiers écartés sont supprimés et listés.
"""

import ipaddress
import json
import os
import re
import shutil
import socket
import stat
import subprocess
import tarfile
import threading
import time
import zipfile

from . import common, testbed
from .common import Fail

NOBODY = testbed.NOBODY
NETWORK = "scanoria-fetch"
BRIDGE = "scanoria-fetch0"
SUBNET = ipaddress.ip_network("10.89.250.0/24")
GATEWAY = "10.89.250.1"
NFT_TABLE = "scanoria_fetch"
NFT_TEMPLATE = os.path.join(common.SHARE_DIR, "nftables", "scanoria-fetch.nft")
CRED_DIR = common.RUN + "/runner-cred"

FETCH_TIMEOUT = 1800
FETCH_MEMORY_MB = 1024
MAX_FILE_BYTES = 100 << 20
MAX_TREE_BYTES = 4 << 30
MAX_FILES = 200000
MAX_SKIPPED = 1000
MAX_UPLOAD = 600 << 20           # la console borne à 512 Mio
MAX_DECLARED = 16 << 30          # somme des tailles déclarées, fichiers écartés compris
EXTRACT_BUDGET_S = 900
MAX_LOG = 1 << 20
MAX_CLONE_BYTES = 8 << 30        # dépôt Git (/git) et arbre extrait (/src) réunis
MIN_FREE_BYTES = 2 << 30         # espace libre minimal gardé sur /var/lib/scanoria
WATCH_EVERY_S = 5

HOST_RE = re.compile(r"[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*\Z")
SHA_RE = re.compile(r"[0-9a-f]{40}([0-9a-f]{24})?\Z")
REF_RE = re.compile(r"[A-Za-z0-9._/-]{1,255}\Z")


class SourceError(Exception):
    """Échec de récupération, avec sa classe G12 (infra | input)."""

    def __init__(self, code, cls, message):
        super().__init__(message)
        self.code, self.cls, self.message = code, cls, str(message)[:2000]

    def as_error(self):
        return {"code": self.code, "class": self.cls, "message": self.message}


# --------------------------------------------------------------------------
# Masquage des secrets
# --------------------------------------------------------------------------

def secret_values(credential):
    """Valeurs à retirer de tout journal : le jeton et ses encodages usuels."""
    if not isinstance(credential, dict) or credential.get("kind") != "token":
        return []
    import base64
    import urllib.parse
    tok = credential["token"]
    user = credential.get("username") or "oauth2"
    vals = {tok, urllib.parse.quote(tok, safe=""),
            base64.b64encode(("%s:%s" % (user, tok)).encode()).decode()}
    return sorted((v for v in vals if v), key=len, reverse=True)


def redact(text, values):
    for v in values:
        text = text.replace(v, "***")
    return text


# --------------------------------------------------------------------------
# Adresse de la forge
# --------------------------------------------------------------------------

def parse_url(url):
    """(hôte, port) d'une URL https://, ssh:// ou scp (utilisateur@hôte:chemin)."""
    if not isinstance(url, str) or len(url) > 2048 or any(c in url for c in "\x00\r\n\t "):
        raise SourceError("E_SOURCE_URL", "input", "invalid repository URL")
    m = re.match(r"https://([^/?#@:]+)(?::([0-9]{1,5}))?/[^?#@]*\Z", url)
    if m:
        host, port = m.group(1), int(m.group(2) or 443)
    else:
        m = re.match(r"ssh://[A-Za-z0-9._-]+@([^/?#@:]+)(?::([0-9]{1,5}))?/[^?#]*\Z", url) or \
            re.match(r"[A-Za-z0-9._-]+@([^/?#@:]+):(?!/)()[^?#]+\Z", url)
        if not m:
            raise SourceError("E_SOURCE_URL", "input", "only https:// and ssh repository URLs are allowed")
        host, port = m.group(1), int(m.group(2) or 22)
    if not HOST_RE.match(host) or not 1 <= port <= 65535:
        raise SourceError("E_SOURCE_URL", "input", "invalid repository host or port")
    return host.lower(), port


def _forbidden(ip):
    return (ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified
            or ip.is_reserved or ip in SUBNET or ip == ipaddress.ip_address("255.255.255.255"))


# Seul port des adresses de l'appliance joignable par une récupération : le proxy
# inverse (forge installée comme module, servie par <libellé>.<appliance>).
APPLIANCE_PORT = 443


def local_addresses():
    """Adresses IPv4 des interfaces de l'appliance."""
    if common.TEST_ROOT and "SCANORIA_TEST_LOCAL_ADDRS" in os.environ:
        return set(a for a in os.environ["SCANORIA_TEST_LOCAL_ADDRS"].split(",") if a)
    try:
        r = common.run("ip", ["-j", "-4", "addr", "show"], timeout=10)
        links = json.loads(r.stdout or b"[]")
    except (Fail, ValueError):
        return set()
    out = set()
    for link in links if isinstance(links, list) else []:
        for a in (link.get("addr_info") or []) if isinstance(link, dict) else []:
            if isinstance(a, dict) and isinstance(a.get("local"), str):
                out.add(a["local"])
    return out


def _test_resolution(host):
    """Mode test seulement : SCANORIA_TEST_RESOLVE="hôte=ip;hôte=ip"."""
    for part in os.environ.get("SCANORIA_TEST_RESOLVE", "").split(";"):
        name, _, ip = part.partition("=")
        if name.strip().lower() == host:
            return [ip.strip()]
    return None


def resolve(host, port):
    """Adresses IPv4 autorisées de la forge (résolues par le runner, pas par le conteneur)."""
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        literal = None
    if literal is not None:
        addrs = [str(literal)]
    else:
        addrs = _test_resolution(host) if common.TEST_ROOT else None
        if addrs is None:
            try:
                infos = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_STREAM)
            except (socket.gaierror, UnicodeError, OSError):
                raise SourceError("E_SOURCE_RESOLVE", "infra", "cannot resolve the forge host %s" % host)
            addrs = [i[4][0] for i in infos]
    out = []
    local = local_addresses()
    for a in addrs:
        try:
            ip = ipaddress.ip_address(a)
        except ValueError:
            continue
        if ip.version != 4:
            continue
        if _forbidden(ip):
            raise SourceError("E_SOURCE_ADDRESS", "input",
                              "forge host %s resolves to a forbidden address (%s)" % (host, ip))
        if str(ip) in local and port != APPLIANCE_PORT:
            raise SourceError("E_SOURCE_ADDRESS", "input",
                              "forge host %s is this appliance: only port %d is allowed" % (host, APPLIANCE_PORT))
        if str(ip) not in out:
            out.append(str(ip))
    if not out:
        raise SourceError("E_SOURCE_RESOLVE", "infra", "no IPv4 address for the forge host %s" % host)
    return out[:8]


# --------------------------------------------------------------------------
# Réseau de récupération (podman + nftables)
# --------------------------------------------------------------------------

_net_lock = threading.Lock()
_ips_in_use = set()


def _nft(args, input=None):
    r = common.run("nft", args, input=input, timeout=60)
    return r.returncode == 0


def ensure_network():
    """Réseau podman dédié et table nftables (créés au premier besoin, idempotent)."""
    with _net_lock:
        if common.run("podman", ["network", "exists", NETWORK], timeout=60).returncode != 0:
            r = common.run("podman", ["network", "create", "--driver", "bridge", "--subnet", str(SUBNET),
                                      "--gateway", GATEWAY, "--interface-name", BRIDGE, "--disable-dns",
                                      NETWORK], timeout=120)
            if r.returncode != 0:
                raise SourceError("E_FETCH_NETWORK", "infra", "cannot create the fetch network")
        # La table n'est chargée que si elle manque : jamais de « delete table »,
        # qui effacerait les autorisations des récupérations en cours.
        if not _nft(["list", "table", "inet", NFT_TABLE]):
            with open(NFT_TEMPLATE, encoding="utf-8") as f:
                rules = f.read().replace("@SUBNET@", str(SUBNET))
            if not _nft(["-f", "-"], input=rules.encode()):
                raise SourceError("E_FETCH_NETWORK", "infra", "cannot load the fetch firewall table")


def _alloc_ip():
    with _net_lock:
        for host in list(SUBNET.hosts())[9:250]:
            ip = str(host)
            if ip not in _ips_in_use:
                _ips_in_use.add(ip)
                return ip
    raise SourceError("E_FETCH_NETWORK", "infra", "no free address on the fetch network")


def _free_ip(ip):
    with _net_lock:
        _ips_in_use.discard(ip)


def _elements(src_ip, addrs, port):
    return "{ %s }" % ", ".join("%s . %s . %d" % (src_ip, a, port) for a in addrs)


def allow(src_ip, addrs, port):
    if not _nft(["add", "element", "inet", NFT_TABLE, "allow4", _elements(src_ip, addrs, port)]):
        raise SourceError("E_FETCH_NETWORK", "infra", "cannot open the firewall towards the forge")


def revoke(src_ip, addrs, port):
    _nft(["delete", "element", "inet", NFT_TABLE, "allow4", _elements(src_ip, addrs, port)])


def reset_network():
    """Au démarrage du runner : aucune autorisation ni aucun conteneur de récupération hérités."""
    if _nft(["list", "table", "inet", NFT_TABLE]):
        _nft(["flush", "set", "inet", NFT_TABLE, "allow4"])
    r = common.run("podman", ["ps", "--all", "--quiet", "--filter", "name=^scanoria-(fetch|scan)-"], timeout=60)
    ids = [i for i in r.text.split() if re.fullmatch(r"[0-9a-f]{12,64}", i)]
    if ids:
        common.run("podman", ["rm", "--force", "--ignore", "--time", "0"] + ids, timeout=120)


# --------------------------------------------------------------------------
# Clone Git confiné
# --------------------------------------------------------------------------

# Script lancé par /bin/sh dans l'image git-fetch ; arguments : URL, ref,
# commit attendu (ou vide), profondeur (« 1 » ou vide pour l'historique complet).
# La source est dans /src, le dépôt dans /git (fichier /src/.git : « gitdir: /git »),
# pour que les scanners sans historique ne voient jamais les objets Git.
FETCH_SCRIPT = r"""set -eu
url=$1; ref=$2; want=$3; depth=$4
set -- ; [ -n "$depth" ] && set -- --depth="$depth"
git init -q --separate-git-dir=/git /src
cd /src
git remote add origin "$url"
git fetch -q --no-tags --no-recurse-submodules "$@" origin "$ref"
git checkout -q --detach FETCH_HEAD
if [ -n "$want" ] && [ "$(git rev-parse HEAD)" != "$want" ]; then
  git fetch -q --no-tags --no-recurse-submodules "$@" origin "$want" || true
  git checkout -q --detach "$want"
fi
echo "commit=$(git rev-parse HEAD)"
"""

# Configuration imposée à chaque appel de git (variables GIT_CONFIG_*), en plus
# de GIT_CONFIG_NOSYSTEM et GIT_CONFIG_GLOBAL=/dev/null : aucun hook, aucun
# protocole hors https/ssh, aucun lien symbolique, aucun sous-module.
GIT_CONFIG = (
    ("core.hooksPath", "/dev/null"),
    ("core.symlinks", "false"),
    ("core.fsmonitor", "false"),
    ("protocol.allow", "never"),
    ("protocol.https.allow", "always"),
    ("protocol.ssh.allow", "always"),
    ("submodule.recurse", "false"),
    ("fetch.recurseSubmodules", "false"),
    ("http.followRedirects", "false"),
    ("init.defaultBranch", "scanoria"),
    ("advice.detachedHead", "false"),
    ("credential.helper", ""),
)
CRED_HELPER = ('!f() { test "$1" = get || return 0; '
               'printf "username=%s\\npassword=%s\\n" "$SCANORIA_GIT_USER" "$SCANORIA_GIT_TOKEN"; }; f')
SSH_COMMAND = ("ssh -F /dev/null -i /cred/id_key -o IdentitiesOnly=yes -o BatchMode=yes "
               "-o UserKnownHostsFile=/cred/known_hosts -o StrictHostKeyChecking=yes "
               "-o ProxyCommand=none -o PermitLocalCommand=no -o ConnectTimeout=30")


def git_env(credential):
    """(variables passées par nom à podman, valeurs gardées hors de l'argv)."""
    cfg = list(GIT_CONFIG)
    env = {"HOME": "/tmp", "GIT_TERMINAL_PROMPT": "0", "GIT_ASKPASS": "/bin/false",
           "SSH_ASKPASS": "/bin/false", "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
           "GIT_LFS_SKIP_SMUDGE": "1", "GIT_PROTOCOL_FROM_USER": "0"}
    secret = {}
    if isinstance(credential, dict) and credential.get("kind") == "token":
        cfg.append(("credential.helper", CRED_HELPER))
        secret["SCANORIA_GIT_TOKEN"] = credential["token"]
        secret["SCANORIA_GIT_USER"] = credential.get("username") or "oauth2"
    if isinstance(credential, dict) and credential.get("kind") == "ssh-key":
        env["GIT_SSH_COMMAND"] = SSH_COMMAND
    else:
        env["GIT_SSH_COMMAND"] = "/bin/false"
    env["GIT_CONFIG_COUNT"] = str(len(cfg))
    for i, (k, v) in enumerate(cfg):
        env["GIT_CONFIG_KEY_%d" % i] = k
        env["GIT_CONFIG_VALUE_%d" % i] = v
    return env, secret


def _write_cred(job_id, credential):
    """Clé SSH et known_hosts dans un tmpfs (/run), 0400, propriétaire 65534."""
    if not isinstance(credential, dict) or credential.get("kind") != "ssh-key":
        return None
    os.makedirs(CRED_DIR, mode=0o700, exist_ok=True)
    d = os.path.join(CRED_DIR, job_id)
    os.mkdir(d, 0o700)
    key = credential["private_key"]
    if not key.endswith("\n"):
        key += "\n"
    for name, data in (("id_key", key), ("known_hosts", credential["known_hosts"].rstrip("\n") + "\n")):
        fd = os.open(os.path.join(d, name), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(data)
    testbed._give_to_container(d)
    os.chmod(d, 0o500)
    return d


def _classify(log_text):
    t = log_text.lower()
    if "host key verification failed" in t or "remote host identification has changed" in t:
        return "E_SOURCE_HOSTKEY", "input", "SSH host key of the forge does not match the known_hosts entry"
    for pat in ("authentication failed", "could not read username", "permission denied",
                "http 401", "http 403", "invalid credentials", "terminal prompts disabled"):
        if pat in t:
            return "E_SOURCE_AUTH", "input", "authentication refused by the forge"
    for pat in ("not found", "couldn't find remote ref", "does not appear to be a git repository",
                "unable to read tree", "reference is not a tree", "did not match any", "not our ref",
                "unadvertised object", "pathspec"):
        if pat in t:
            return "E_SOURCE_NOT_FOUND", "input", "repository, branch or commit not found"
    for pat in ("connection refused", "timed out", "failed to connect", "connection reset",
                "could not connect", "network is unreachable", "no route to host", "early eof",
                "the remote end hung up", "ssl", "tls", "gnutls"):
        if pat in t:
            return "E_SOURCE_NETWORK", "infra", "the forge cannot be reached"
    return "E_SOURCE_FETCH", "input", "the repository cannot be fetched"


def _container_ready(registry_modules):
    e = registry_modules.get("git-fetch")
    if not isinstance(e, dict) or e.get("status") != "healthy" or e.get("enabled") is not True:
        raise SourceError("E_FETCH_MODULE_MISSING", "input",
                          "system module git-fetch is not installed, healthy and enabled")
    m = e["manifest"]
    from . import catalogverify
    try:
        catalogverify.check_module(m)
    except Fail:
        raise SourceError("E_FETCH_MODULE_MISSING", "input", "system module git-fetch is invalid")
    if common.run("podman", ["image", "exists", m["image"]], timeout=60).returncode != 0:
        raise SourceError("E_IMAGE_MISSING", "infra", "image of the git-fetch module is missing")
    return m


def _ca_bundle():
    """Magasin de confiance du système (AC d'entreprise ajoutées par update-ca-certificates)."""
    path = common.p("/etc/ssl/certs/ca-certificates.crt")
    return path if os.path.isfile(path) else None


def fetch_git(job, ws, registry_modules, history, log_path, secrets):
    """Clone la source dans ws/src (et ws/git) ; retourne le commit."""
    src = job["source"]
    host, port = parse_url(src["url"])
    if not REF_RE.match(src["ref"]) or src["ref"].startswith("-") or ".." in src["ref"]:
        raise SourceError("E_SOURCE_REF", "input", "invalid ref")
    want = src.get("commit") or ""
    if want and not SHA_RE.match(want):
        raise SourceError("E_SOURCE_REF", "input", "invalid commit")
    m = _container_ready(registry_modules)
    addrs = resolve(host, port)
    ensure_network()
    for d in ("src", "git"):
        os.mkdir(os.path.join(ws, d), 0o700)
        testbed._give_to_container(os.path.join(ws, d))
    cred_dir = _write_cred(job["id"], src.get("credential"))
    ip = _alloc_ip()
    name = "scanoria-fetch-%s" % job["id"][:8] + "-" + os.urandom(3).hex()
    env, secret_env = git_env(src.get("credential"))
    mounts = [(os.path.join(ws, "src"), "/src", "rw"), (os.path.join(ws, "git"), "/git", "rw")]
    if cred_dir:
        mounts.append((cred_dir, "/cred", "ro"))
    ca = _ca_bundle()
    if ca:
        mounts.append((ca, "/etc/scanoria-ca.crt", "ro"))
        env["GIT_SSL_CAINFO"] = "/etc/scanoria-ca.crt"
    manifest = dict(m, resources={"min_ram_mb": FETCH_MEMORY_MB, "min_cpu": 1})
    args = [a for a in testbed.confined_args(manifest, mounts, name=name) if a != "--network=none"]
    args += ["--network", NETWORK, "--ip", ip, "--dns=none", "--add-host", "%s:%s" % (host, addrs[0]),
             "--timeout", str(FETCH_TIMEOUT)]
    for k in sorted(env):
        args += ["--env", "%s=%s" % (k, env[k])]
    for k in sorted(secret_env):
        args += ["--env", k]           # valeur héritée de l'environnement : jamais dans l'argv
    depth = "1" if history == "shallow" else ""
    args += ["--entrypoint", '["/bin/sh"]', m["image"], "-c", FETCH_SCRIPT, "git-fetch",
             src["url"], src["ref"], want, depth]
    allowed = False
    try:
        allow(ip, addrs, port)
        allowed = True
        rc, out, timed_out = run_logged(args, log_path, FETCH_TIMEOUT + 60, secret_env, secrets,
                                        watch=lambda: storage_check(ws))
    finally:
        if allowed:
            revoke(ip, addrs, port)
        _free_ip(ip)
        common.run("podman", ["rm", "--force", "--ignore", "--time", "0", name], timeout=120)
        if cred_dir:
            shutil.rmtree(cred_dir, ignore_errors=True)
    if isinstance(timed_out, SourceError):
        raise timed_out
    if timed_out:
        raise SourceError("E_SOURCE_TIMEOUT", "infra", "fetching the repository timed out")
    if rc in (125, 126, 127):
        raise SourceError("E_PODMAN", "infra", "the fetch container could not start (exit %d)" % rc)
    if rc != 0:
        code, cls, msg = _classify(_read_log(log_path))
        raise SourceError(code, cls, msg)
    # Dernière ligne « commit= » : le script l'écrit en dernier, après toute sortie de git.
    found = re.findall(r"^commit=([0-9a-f]{40,64})$", out, re.M)
    if not found:
        raise SourceError("E_SOURCE_FETCH", "input", "fetched commit unknown")
    if want and found[-1] != want:
        raise SourceError("E_SOURCE_NOT_FOUND", "input", "requested commit not found")
    return found[-1]


def disk_free(path):
    if common.TEST_ROOT and "SCANORIA_TEST_FREE_MB" in os.environ:
        return int(os.environ["SCANORIA_TEST_FREE_MB"]) << 20
    st = os.statvfs(path)
    return st.f_bavail * st.f_frsize


def tree_usage(root):
    """Octets occupés sous root, sans suivre de lien."""
    total = 0
    for d, _dirs, names in os.walk(root, followlinks=False):
        for n in names:
            try:
                total += os.lstat(os.path.join(d, n)).st_blocks * 512
            except OSError:
                pass
    return total


def storage_check(ws):
    """Borne le stockage d'une récupération en cours ; SourceError si elle doit s'arrêter."""
    if disk_free(ws) < MIN_FREE_BYTES:
        return SourceError("E_DISK_FULL", "infra", "not enough free space left on the appliance")
    if tree_usage(ws) > MAX_CLONE_BYTES:
        return SourceError("E_SOURCE_TOO_LARGE", "input",
                           "repository exceeds %d GiB" % (MAX_CLONE_BYTES >> 30))
    return None


def _read_log(path):
    try:
        with open(path, "rb") as f:
            return f.read(MAX_LOG).decode("utf-8", "replace")
    except OSError:
        return ""


def run_logged(args, log_path, timeout, env=None, secrets=(), watch=None):
    """Lance podman ; journal (stdout+stderr) borné à MAX_LOG et masqué ; (rc, stdout, délai dépassé).

    watch : appelée toutes les WATCH_EVERY_S secondes ; une valeur non nulle arrête
    le conteneur et est rendue à la place de « délai dépassé »."""
    exe = common.resolve("podman")
    if exe is None:
        with open(common.p("/test-commands.log"), "a", encoding="utf-8") as f:
            f.write(json.dumps(["podman"] + args, separators=(",", ":")) + "\n")
        return 0, "", False
    proc = subprocess.Popen([exe] + list(args), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, env=common.child_env(env), cwd="/",
                            start_new_session=True, close_fds=True)
    chunks, size = [], [0]

    def pump():
        while True:
            b = proc.stdout.read(65536)
            if not b:
                break
            if size[0] < MAX_LOG * 2:
                chunks.append(b)
                size[0] += len(b)
    t = threading.Thread(target=pump, daemon=True)
    t.start()
    timed_out = False
    deadline = time.monotonic() + timeout
    while True:
        try:
            proc.wait(timeout=max(0.1, min(WATCH_EVERY_S, deadline - time.monotonic())))
            break
        except subprocess.TimeoutExpired:
            if time.monotonic() >= deadline:
                timed_out = True
            elif watch is not None:
                timed_out = watch() or False
            if timed_out:
                common.kill_group(proc)
                break
    t.join(10)
    text = redact(b"".join(chunks).decode("utf-8", "replace"), secrets)
    if len(text.encode()) > MAX_LOG:
        text = text.encode()[:MAX_LOG].decode("utf-8", "ignore") + "\n[journal tronqué à 1 Mo]\n"
    fd = os.open(log_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(text)
    return (proc.returncode if not timed_out else -1), text, timed_out


# --------------------------------------------------------------------------
# Archive téléversée
# --------------------------------------------------------------------------

UPLOAD_NAMES = ("source.zip", "source.tar", "source.tar.gz")


def _open_dir(name, dir_fd=None):
    fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=dir_fd)
    st = os.fstat(fd)
    if (st.st_uid != _upload_owner() or stat.S_IMODE(st.st_mode) & 0o022) and not common.TEST_ROOT:
        os.close(fd)
        raise OSError("unexpected owner or mode")
    return fd


def _upload_owner():
    return common.scanoria_ids()[0]


def _open_upload(upload_id):
    """Ouvre l'archive par descripteurs de répertoire : aucun lien suivi, à aucun niveau."""
    if not common.UUID4_RE.match(upload_id or ""):
        raise SourceError("E_ARCHIVE_MISSING", "input", "invalid upload id")
    top = d = None
    try:
        try:
            top = _open_dir(os.path.join(common.VARLIB, "uploads"))
            d = _open_dir(upload_id, dir_fd=top)
        except OSError:
            raise SourceError("E_ARCHIVE_MISSING", "input", "uploaded archive not found")
        names = [n for n in os.listdir(d) if n in UPLOAD_NAMES]
        if len(names) != 1:
            raise SourceError("E_ARCHIVE_MISSING", "input", "uploaded archive not found")
        try:
            fd = os.open(names[0], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_NOCTTY | os.O_CLOEXEC,
                         dir_fd=d)
        except OSError:
            raise SourceError("E_ARCHIVE_INVALID", "input", "uploaded archive is not a regular file")
    finally:
        for x in (d, top):
            if x is not None:
                os.close(x)
    f = os.fdopen(fd, "rb")
    st = os.fstat(f.fileno())
    ok = stat.S_ISREG(st.st_mode) and st.st_size <= MAX_UPLOAD and st.st_nlink == 1
    if ok and not common.TEST_ROOT:
        ok = st.st_uid == _upload_owner() and not stat.S_IMODE(st.st_mode) & 0o022
    if not ok:
        f.close()
        raise SourceError("E_ARCHIVE_INVALID", "input",
                          "uploaded archive is not a regular private file of scanoria or is too large")
    os.set_blocking(f.fileno(), True)
    return f


class _Tree:
    """Écriture bornée d'un arbre extrait (root, sans jamais suivre de lien)."""

    def __init__(self, dest):
        os.mkdir(dest, 0o700)
        self.base = os.path.realpath(dest)
        self.files = 0
        self.bytes = 0
        self.declared = 0
        self.skipped = []
        self.deadline = time.monotonic() + EXTRACT_BUDGET_S

    def skip(self, path, reason):
        if len(self.skipped) < MAX_SKIPPED:
            self.skipped.append({"path": path[:1024], "reason": reason})

    def tick(self, size=0):
        self.declared += max(0, size)
        if self.declared > MAX_DECLARED or time.monotonic() > self.deadline:
            raise SourceError("E_ARCHIVE_INVALID", "input", "archive too large or too slow to extract")

    def admit(self, rel, size):
        """True si le fichier peut être écrit ; sinon l'ajoute à skipped."""
        if size > MAX_FILE_BYTES:
            self.skip(rel, "size")
            return False
        if self.files >= MAX_FILES or self.bytes + size > MAX_TREE_BYTES:
            self.skip(rel, "limit")
            return False
        return True

    def mkdirs(self, rel):
        try:
            testbed._mkdirs(self.base, rel)
        except Fail:
            raise SourceError("E_ARCHIVE_UNSAFE", "input", "path conflict in the archive")

    def write(self, rel, stream, size):
        self.mkdirs(os.path.dirname(rel))
        try:
            fd = os.open(os.path.join(self.base, rel), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        except FileExistsError:
            raise SourceError("E_ARCHIVE_UNSAFE", "input", "duplicate entry in the archive")
        written = 0
        with os.fdopen(fd, "wb") as out:
            while True:
                b = stream.read(1 << 20)
                if not b:
                    break
                written += len(b)
                if written > size:
                    raise SourceError("E_ARCHIVE_INVALID", "input", "archive entry larger than declared")
                out.write(b)
                if time.monotonic() > self.deadline:
                    raise SourceError("E_ARCHIVE_INVALID", "input", "archive too slow to extract")
        self.files += 1
        self.bytes += written


def _safe_rel(name):
    """Chemin relatif sûr (ni absolu, ni « .. », ni « \\ ») ; sinon archive piégée."""
    if isinstance(name, str) and name.strip("./") == "" and ".." not in name and "\x00" not in name:
        return None                      # racine de l'archive (« ./ ») : rien à écrire
    rel = testbed._member_path(name)
    if rel is None:
        raise SourceError("E_ARCHIVE_UNSAFE", "input", "unsafe path in the archive: %s" % str(name)[:200])
    return rel


def _extract_tar(f, tree):
    try:
        tf = tarfile.open(fileobj=f, mode="r:*")
    except (tarfile.TarError, OSError, EOFError):
        raise SourceError("E_ARCHIVE_INVALID", "input", "archive is not a valid tar file")
    with tf:
        try:
            for i, m in enumerate(tf):
                tree.tick(m.size if m.isreg() else 0)
                if i >= MAX_FILES * 2:
                    raise SourceError("E_ARCHIVE_INVALID", "input", "too many entries in the archive")
                rel = _safe_rel(m.name)
                if rel is None:
                    continue
                if m.isdir():
                    tree.mkdirs(rel)
                elif m.issym() or m.islnk():
                    tree.skip(rel, "symlink")
                elif not m.isreg():
                    tree.skip(rel, "special")
                elif tree.admit(rel, m.size):
                    tree.write(rel, tf.extractfile(m), m.size)
        except (tarfile.TarError, OSError, EOFError, ValueError) as e:
            if isinstance(e, SourceError):
                raise
            raise SourceError("E_ARCHIVE_INVALID", "input", "archive is corrupted")


def _extract_zip(f, tree):
    try:
        zf = zipfile.ZipFile(f)
    except (zipfile.BadZipFile, OSError, ValueError):
        raise SourceError("E_ARCHIVE_INVALID", "input", "archive is not a valid zip file")
    with zf:
        infos = zf.infolist()
        if len(infos) > MAX_FILES * 2:
            raise SourceError("E_ARCHIVE_INVALID", "input", "too many entries in the archive")
        for info in infos:
            tree.tick(info.file_size)
            rel = _safe_rel(info.filename)
            if rel is None:
                continue
            mode = (info.external_attr >> 16) & 0o170000
            if info.is_dir():
                tree.mkdirs(rel)
            elif mode == stat.S_IFLNK:
                tree.skip(rel, "symlink")
            elif mode not in (0, stat.S_IFREG):
                tree.skip(rel, "special")
            elif tree.admit(rel, info.file_size):
                try:
                    with zf.open(info) as s:
                        tree.write(rel, s, info.file_size)
                except (zipfile.BadZipFile, RuntimeError, OSError, EOFError, NotImplementedError):
                    raise SourceError("E_ARCHIVE_INVALID", "input", "archive entry cannot be read")


def extract_upload(upload_id, ws):
    """Extrait l'archive dans ws/src ; retourne (fichiers, octets, écartés)."""
    f = _open_upload(upload_id)
    with f:
        head = f.read(512)
        f.seek(0)
        tree = _Tree(os.path.join(ws, "src"))
        if head.startswith(b"PK\x03\x04") or head.startswith(b"PK\x05\x06"):
            _extract_zip(f, tree)
        elif head.startswith(b"\x1f\x8b") or head[257:262] == b"ustar":
            _extract_tar(f, tree)
        else:
            raise SourceError("E_ARCHIVE_INVALID", "input", "archive format not recognised (zip, tar, tar.gz)")
    testbed._give_to_container(os.path.join(ws, "src"))
    return tree.files, tree.bytes, tree.skipped


# --------------------------------------------------------------------------
# Bornes de l'arbre récupéré (Git)
# --------------------------------------------------------------------------

def bound_tree(root):
    """Parcourt root sans suivre de lien ; supprime ce qui dépasse ; (fichiers, octets, écartés)."""
    files = total = 0
    skipped = []

    def skip(rel, reason):
        if len(skipped) < MAX_SKIPPED:
            skipped.append({"path": rel[:1024], "reason": reason})
    for d, dirs, names in os.walk(root, topdown=True, followlinks=False):
        reld = os.path.relpath(d, root)
        for n in sorted(dirs):
            p = os.path.join(d, n)
            if os.path.islink(p):
                skip(os.path.normpath(os.path.join(reld, n)), "symlink")
                os.unlink(p)
                dirs.remove(n)
        dirs.sort()
        for n in sorted(names):
            p = os.path.join(d, n)
            rel = os.path.normpath(os.path.join(reld, n))
            if reld == "." and n == ".git":
                continue
            st = os.lstat(p)
            if stat.S_ISLNK(st.st_mode):
                reason = "symlink"
            elif not stat.S_ISREG(st.st_mode):
                reason = "special"
            elif st.st_size > MAX_FILE_BYTES:
                reason = "size"
            elif files >= MAX_FILES or total + st.st_size > MAX_TREE_BYTES:
                reason = "limit"
            else:
                files += 1
                total += st.st_size
                continue
            skip(rel, reason)
            os.unlink(p)
    return files, total, skipped
