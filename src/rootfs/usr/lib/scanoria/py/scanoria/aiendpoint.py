# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Vincent Tisseront
"""Connecteur IA : serveur Ollama externe (CLAUDE.md § 3.5, I1).

Demande set-ai-endpoint (helper root) :
  - valide l'adresse : https, ou http avec allow_insecure (sans jeton) ; port ;
    ni identifiants, ni requête, ni fragment, ni chemin ;
  - résout elle-même le nom (DNS seulement, jamais /etc/hosts) et refuse toute
    adresse de bouclage, de lien local, de multidiffusion, réservée, non
    spécifiée ou de l'appliance : une seule adresse interdite suffit ;
  - épingle les adresses dans /etc/scanoria/ai.json ;
  - charge la table nftables « inet scanoria_ai » : sortie vers ces adresses
    et ce port seulement, pour l'UID de scanoria-ai seulement (meta skuid),
    tout le reste refusé pour cet UID ; enabled: false referme la règle ;
  - redémarre scanoria-ai, qui relit sa configuration.

Commandes root (run.py ai-setup …) :
  prestart  ExecStartPre=+ de scanoria-ai.service : table nftables (fermée
            sans connecteur), rôle PostgreSQL et droits (ai-grants.sql),
            copie des fichiers lus par le service dans /run/scanoria-ai ;
  check     relance horaire : nouvelle résolution comparée aux adresses
            épinglées (un changement est signalé, jamais appliqué), et
            serveur candidat ollama.<domaine> sans connecteur.
            Écrit /run/scanoria/ai-status.json.
"""

import ipaddress
import json
import os
import re
import shutil
import stat
import sys

from . import common, netutil, schema
from . import dns as dnscheck
from .common import Fail

AI_CONF = common.ETC + "/ai.json"
AI_CA = common.ETC + "/ai-ca.pem"
NFT_FILE = common.ETC + "/nftables/ai.nft"
STATUS_FILE = common.RUN + "/ai-status.json"
RUNTIME_DIR = common.p("/run/scanoria-ai")
# Clé dédiée au seul jeton IA (webui/server/ai/token.ts) : jamais secret.key,
# qui ouvre aussi les jetons de forge et les clés SSH.
AI_TOKEN_KEY = common.VARLIB + "/console/ai-token.key"
GRANTS_SQL = common.SHARE_DIR + "/sql/ai-grants.sql"
AI_USER = "scanoria-ai"
TABLE = "scanoria_ai"
MAX_ADDRESSES = 8
URL_RE = re.compile(
    r"(https?)://(\[[0-9a-f:.]{2,45}\]|[a-z0-9.-]{1,253})(?::([0-9]{1,5}))?/?\Z", re.ASCII)
CANDIDATE_LABEL = "ollama"
CANDIDATE_PORT = 11434
VERSION_RE = re.compile(r"[0-9A-Za-z][0-9A-Za-z.+_-]{0,63}\Z", re.ASCII)


# --------------------------------------------------------------------------
# Adresse du serveur
# --------------------------------------------------------------------------

def parse_url(url, allow_insecure, token):
    """(schéma, hôte, port, adresse IP littérale ou None) ; Fail E_AI_URL sinon."""
    if not isinstance(url, str) or len(url) > 300 or url != url.strip():
        raise Fail("E_AI_URL", "invalid server address")
    m = URL_RE.match(url.lower())
    if not m or url.lower() != url:
        raise Fail("E_AI_URL", "address must be scheme://host[:port] in lower case, without path")
    scheme, host, port = m.group(1), m.group(2), m.group(3)
    if scheme == "http" and not allow_insecure:
        raise Fail("E_AI_URL", "http requires an explicit allow_insecure")
    if scheme == "http" and token:
        raise Fail("E_AI_URL", "a bearer token requires https")
    port = int(port) if port else (443 if scheme == "https" else 80)
    if not 1 <= port <= 65535:
        raise Fail("E_AI_URL", "invalid port")
    literal = None
    if host.startswith("["):
        try:
            literal = ipaddress.ip_address(host[1:-1])
        except ValueError:
            literal = None
        if literal is None or literal.version != 6 or literal.scope_id:
            raise Fail("E_AI_URL", "invalid IPv6 literal")
        host = str(literal)
    else:
        try:
            literal = ipaddress.ip_address(host)
        except ValueError:
            literal = None
        if literal is None and not netutil.check_fqdn(host):
            raise Fail("E_AI_URL", "host must be a fully qualified name or an IP address")
        if literal is not None and str(literal) != host:
            raise Fail("E_AI_URL", "IP address must be in canonical form")
    return scheme, host, port, literal


def forbidden(addr, own):
    """Raison du refus d'une adresse, ou None."""
    if addr.version == 6 and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped
    if addr.version == 6 and addr.sixtofour is not None:
        # 6to4 (2002::/16) : jamais un serveur Ollama d'entreprise, et peut encapsuler 127.0.0.1.
        return "reserved"
    if addr.version == 6 and addr.teredo is not None:
        return "reserved"
    if addr.is_loopback:
        return "loopback"
    if addr.is_link_local:
        return "link-local"
    if addr.is_multicast:
        return "multicast"
    if addr.is_unspecified or addr.is_reserved:
        return "reserved"
    if addr.version == 4 and addr in ipaddress.ip_network("0.0.0.0/8"):
        return "reserved"
    if str(addr) in own:
        return "appliance"
    return None


def local_addresses(timeout=30):
    """Toutes les adresses de l'appliance (toutes interfaces) ; échoue fermé si illisibles."""
    r = common.run("ip", ["-j", "addr", "show"], timeout=timeout)
    own = set()
    try:
        if r.returncode != 0:
            raise ValueError("ip addr failed")
        for link in json.loads(r.text):
            for info in link.get("addr_info") or []:
                a = netutil.parse_address(str(info.get("local", "")))
                if a is not None:
                    own.add(str(a))
    except (ValueError, TypeError, AttributeError):
        raise Fail("E_INTERNAL", "cannot list the appliance addresses")
    if not own:
        raise Fail("E_INTERNAL", "cannot list the appliance addresses")
    own.update(dnscheck.appliance_addresses().values())
    return own


def resolve(host, literal, timeout=20):
    """Adresses autorisées de host (triées) ; Fail si une seule est interdite ou si aucune."""
    if literal is not None:
        found = [literal]
    else:
        found = []
        for rtype in ("A", "AAAA"):
            for s in dnscheck.lookup(host, rtype, timeout):
                a = netutil.parse_address(s)
                if a is not None and a not in found:
                    found.append(a)
    if not found:
        raise Fail("E_AI_UNRESOLVED", "server name does not resolve")
    if len(found) > MAX_ADDRESSES:
        raise Fail("E_AI_UNRESOLVED", "server name resolves to too many addresses")
    own = local_addresses()
    for a in found:
        why = forbidden(a, own)
        if why:
            raise Fail("E_AI_FORBIDDEN_ADDRESS", "server resolves to a forbidden address (%s)" % why,
                       {"address": str(a), "reason": why})
    return sorted((str(a) for a in found), key=lambda s: (":" in s, s))


def check_ca(pem):
    from .helper import pem_ok  # import local : helper importe ce module
    if not pem_ok(pem) or "-----BEGIN CERTIFICATE-----" not in pem or "PRIVATE KEY" in pem:
        raise Fail("E_AI_CA", "CA must be one or more PEM certificates")
    r = common.run("openssl", ["x509", "-noout"], input=pem.encode("ascii"), timeout=30)
    if r.returncode != 0:
        raise Fail("E_AI_CA", "CA certificate cannot be parsed")


# --------------------------------------------------------------------------
# Configuration épinglée et pare-feu
# --------------------------------------------------------------------------

DISABLED = {"version": 1, "enabled": False}


def load_conf():
    """Configuration épinglée, ou DISABLED si absente ou incohérente (échec fermé)."""
    try:
        conf = common.load_json_file(AI_CONF, 64 * 1024)
    except (OSError, common.JsonError):
        return dict(DISABLED)
    if not schema.load("schemas", "ai-endpoint").valid(conf):
        common.log("ai.json does not match its schema: connector treated as disabled")
        return dict(DISABLED)
    return conf


def ai_uid():
    if common.TEST_ROOT:
        v = os.environ.get("SCANORIA_TEST_AI_UID", "")
        return int(v) if v.isdigit() else 64990
    import pwd
    return pwd.getpwnam(AI_USER).pw_uid


def render_nft(conf, uid):
    """Table inet scanoria_ai : sortie de scanoria-ai limitée au serveur épinglé."""
    lines = [
        "# Généré par scanoria-helper (set-ai-endpoint) : ne pas modifier.",
        "table inet %s" % TABLE,
        "delete table inet %s" % TABLE,
        "table inet %s {" % TABLE,
        "\tchain output {",
        "\t\ttype filter hook output priority filter; policy accept;",
    ]
    if conf.get("enabled"):
        port = int(conf["port"])
        v4 = [a for a in conf["addresses"] if ":" not in a]
        v6 = [a for a in conf["addresses"] if ":" in a]
        if v4:
            lines.append("\t\tmeta skuid %d ip daddr { %s } tcp dport %d accept" % (uid, ", ".join(v4), port))
        if v6:
            lines.append("\t\tmeta skuid %d ip6 daddr { %s } tcp dport %d accept" % (uid, ", ".join(v6), port))
    lines += ["\t\tmeta skuid %d counter reject" % uid, "\t}", "}", ""]
    return "\n".join(lines)


def apply_nft(conf):
    text = render_nft(conf, ai_uid())
    os.makedirs(os.path.dirname(NFT_FILE), mode=0o700, exist_ok=True)
    tmp = NFT_FILE + ".new"
    common.atomic_write(tmp, text, 0o600, group_scanoria=False)
    try:
        if common.run("nft", ["-c", "-f", tmp], timeout=60).returncode != 0:
            raise Fail("E_INTERNAL", "AI ruleset rejected by nft -c")
        if common.run("nft", ["-f", tmp], timeout=60).returncode != 0:
            raise Fail("E_INTERNAL", "AI ruleset could not be loaded")
        os.rename(tmp, NFT_FILE)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def set_ca(data):
    if data is not None:
        common.atomic_write(AI_CA, data, 0o640)
    elif os.path.exists(AI_CA):
        os.unlink(AI_CA)


def act_set_ai_endpoint(c):
    prm = c.params
    previous = load_conf()
    if not prm["enabled"]:
        common.write_json(AI_CONF, dict(DISABLED))
        apply_nft(DISABLED)
        common.run("systemctl", ["try-restart", "scanoria-ai.service"], timeout=c.left())
        write_status(check_status(DISABLED))
        return {"enabled": False, "previous_url": previous.get("url")}
    token = bool(prm.get("token", False))
    insecure = bool(prm.get("allow_insecure", False))
    scheme, host, port, literal = parse_url(prm.get("url"), insecure, token)
    ca = prm.get("ca_pem")
    if ca is not None:
        if scheme != "https":
            raise Fail("E_AI_URL", "a CA is only meaningful with https")
        check_ca(ca)
    # Vérification du certificat désactivée (certificat autosigné) : https seulement,
    # et jamais avec une AC fournie (elle ne servirait à rien et masquerait l'erreur).
    skip_verify = bool(prm.get("skip_tls_verify", False))
    if skip_verify:
        if scheme != "https":
            raise Fail("E_AI_URL", "skipping certificate verification is only meaningful with https")
        if ca is not None:
            raise Fail("E_AI_URL", "a CA cannot be combined with skipping certificate verification")
    common.set_step("pin")
    addresses = resolve(host, literal, timeout=min(20, c.left()))
    conf = {
        "version": 1, "enabled": True, "url": prm["url"].rstrip("/"), "scheme": scheme,
        "host": host, "port": port, "addresses": addresses, "insecure": scheme == "http",
        "token": token, "ca": ca is not None, "tls_verify": not skip_verify, "literal": literal is not None,
        "pinned_at": common.iso(common.now()),
    }
    if not schema.load("schemas", "ai-endpoint").valid(conf):
        raise Fail("E_INTERNAL", "pinned configuration does not match its schema")
    common.set_step("firewall")
    previous_ca = None
    if os.path.isfile(AI_CA):
        with open(AI_CA, "rb") as f:
            previous_ca = f.read(65536)
    set_ca(ca.encode("ascii") if ca is not None else None)
    common.write_json(AI_CONF, conf)
    try:
        apply_nft(conf)
    except Fail:
        common.write_json(AI_CONF, previous)
        set_ca(previous_ca)
        try:
            apply_nft(previous)
        except Fail:
            apply_nft(DISABLED)
        raise
    common.run("systemctl", ["restart", "scanoria-ai.service"], timeout=c.left())
    write_status(check_status(conf))
    return {"enabled": True, "url": conf["url"], "host": host, "port": port,
            "addresses": addresses, "insecure": conf["insecure"], "token": token, "ca": conf["ca"],
            "tls_verify": conf["tls_verify"]}


# --------------------------------------------------------------------------
# Contrôle horaire : résolution et serveur candidat
# --------------------------------------------------------------------------

def check_resolution(conf):
    """Compare une nouvelle résolution aux adresses épinglées (jamais appliquée)."""
    if not conf.get("enabled"):
        return None
    try:
        literal = ipaddress.ip_address(conf["host"]) if conf.get("literal") else None
        now = resolve(conf["host"], literal)
        error = None
    except Fail as e:
        now, error = [], e.code
    return {"pinned": conf["addresses"], "current": now, "changed": now != conf["addresses"],
            "error": error}


def discover_candidate(timeout=5):
    """Serveur ollama.<domaine de l'appliance> qui résout et répond à /api/version."""
    try:
        fqdn = (common.load_json_file(common.ETC + "/appliance.json", 4096) or {}).get("fqdn")
    except (OSError, common.JsonError):
        return None
    if not netutil.check_fqdn(fqdn) or fqdn.count(".") < 2:
        return None
    host = "%s.%s" % (CANDIDATE_LABEL, fqdn.split(".", 1)[1])
    try:
        addresses = resolve(host, None, timeout=10)
    except Fail:
        return None
    for scheme in ("https", "http"):
        url = "%s://%s:%d" % (scheme, host, CANDIDATE_PORT)
        args = ["-sS", "--max-time", str(timeout), "--max-filesize", "4096", "--proto", "=" + scheme,
                "--resolve", "%s:%d:%s" % (host, CANDIDATE_PORT, addresses[0]), url + "/api/version"]
        r = common.run("curl", args, timeout=timeout + 5, stdout_limit=4096)
        if r.returncode != 0:
            continue
        try:
            v = common.loads_strict(r.stdout).get("version")
        except (common.JsonError, AttributeError):
            continue
        if isinstance(v, str) and VERSION_RE.match(v):
            return {"url": url, "version": v, "addresses": addresses, "insecure": scheme == "http"}
    return None


def check_status(conf):
    return {"version": 1, "checked_at": common.iso(common.now()), "enabled": bool(conf.get("enabled")),
            "resolution": check_resolution(conf),
            "candidate": None if conf.get("enabled") else discover_candidate()}


def write_status(status):
    if not schema.load("schemas", "ai-status").valid(status):
        raise Fail("E_INTERNAL", "AI status does not match its schema")
    os.makedirs(os.path.dirname(STATUS_FILE), mode=0o750, exist_ok=True)
    common.write_json(STATUS_FILE, status)


# --------------------------------------------------------------------------
# Démarrage de scanoria-ai (ExecStartPre=+)
# --------------------------------------------------------------------------

def ensure_db_role():
    """Rôle "scanoria-ai" et droits (idempotent), par le superutilisateur postgres."""
    r = common.run("runuser", ["-u", "postgres", "--", common.SYSTEM_CMDS["psql"], "-X", "-q",
                               "-v", "ON_ERROR_STOP=1", "-d", "scanoria", "-f", GRANTS_SQL], timeout=120)
    if r.returncode != 0:
        raise Fail("E_INTERNAL", "PostgreSQL role or grants for scanoria-ai could not be applied")


def read_token_key():
    """Clé du jeton IA, lue sans suivre de lien (le répertoire appartient à la console).

    Ouverte avec O_NOFOLLOW puis contrôlée sur le descripteur : fichier
    régulier, un seul lien, exactement 32 octets. Sinon : None (rien copié).
    """
    try:
        fd = os.open(AI_TOKEN_KEY, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except OSError:
        return None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or st.st_size != 32:
            return None
        data = os.read(fd, 33)
        return data if len(data) == 32 else None
    finally:
        os.close(fd)


def install_runtime(conf):
    """Fichiers lus par le service, copiés dans /run/scanoria-ai (propriétaire scanoria-ai)."""
    os.makedirs(RUNTIME_DIR, mode=0o700, exist_ok=True)
    uid = ai_uid()
    wanted = {"ai.json": (common.dumps(conf).encode("utf-8"), 0o400)}
    if conf.get("enabled") and conf.get("ca") and os.path.isfile(AI_CA):
        with open(AI_CA, "rb") as f:
            wanted["ca.pem"] = (f.read(65536), 0o400)
    if conf.get("enabled") and conf.get("token"):
        key = read_token_key()
        if key is not None:
            wanted["ai-token.key"] = (key, 0o400)
    for name in os.listdir(RUNTIME_DIR):
        if name not in wanted:
            path = os.path.join(RUNTIME_DIR, name)
            if os.path.isdir(path) and not os.path.islink(path):
                shutil.rmtree(path)
            else:
                os.unlink(path)
    for name, (data, mode) in wanted.items():
        path = os.path.join(RUNTIME_DIR, name)
        tmp = path + ".new"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, mode)
        try:
            os.write(fd, data)
            if not common.TEST_ROOT:
                os.fchown(fd, uid, uid)
        finally:
            os.close(fd)
        os.rename(tmp, path)
    return sorted(wanted)


def cmd_prestart():
    conf = load_conf()
    apply_nft(conf)
    ensure_db_role()
    files = install_runtime(conf)
    return {"enabled": bool(conf.get("enabled")), "files": files}


def cmd_check():
    status = check_status(load_conf())
    write_status(status)
    return status


def main(argv):
    if len(argv) != 1 or argv[0] not in ("prestart", "check"):
        sys.stderr.write("usage: scanoria-ai-setup prestart | check\n")
        return 2
    if not common.TEST_ROOT and os.geteuid() != 0:
        sys.stderr.write("scanoria-ai-setup: root required\n")
        return 2
    try:
        out = cmd_prestart() if argv[0] == "prestart" else cmd_check()
    except Fail as e:
        return common.emit(e.code, e.message, e.output)
    sys.stdout.write(json.dumps(out, sort_keys=True) + "\n")
    return 0
