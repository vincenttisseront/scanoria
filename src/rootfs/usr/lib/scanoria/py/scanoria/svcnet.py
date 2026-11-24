# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Vincent Tisseront
"""Scanners reliés à un service (contrat 12 de la 0.4).

Un scanner qui déclare scan.network: service:<id> (sonar-scanner →
sonarqube) est la seule exception à --network=none hors DAST :
  - le module <id> doit être un service installé, sain et actif ;
  - le conteneur est rattaché au seul réseau interne scanoria-mod-<id>_scan
    (Internal=true : ni passerelle, ni sortie), où il joint le service par son
    nom de conteneur scanoria-mod-<id> ;
  - le jeton d'analyse, créé par le helper à la mise en service (provision.py),
    est lu dans un fichier root 0600 et passé par un secret Podman monté en
    /run/secrets/scan-token, jamais en argument ni en variable visible ;
  - la clé de projet du service vient du projet Scanoria (scanoria-<uuid court>).
scan.tool monte en lecture seule l'outil livré avec l'appliance
(/usr/lib/scanoria/scan-tools/<tool>) sur /scanoria.
scan.refs: default-branch limite le module à la branche par défaut du projet ;
scan.refs_feature: branches l'étend aux autres branches quand le service a la
fonction « branches » active (variante du module, plugin de branches de SonarQube) : la
branche est alors transmise par SCANORIA_BRANCH.
"""

import os
import re
import stat

from . import common
from .common import Fail


class Unavailable(Exception):
    """Service, jeton ou outil indisponible : code d'erreur du runner (scan-result) et message."""

    def __init__(self, code, message):
        super().__init__(message)
        self.code, self.message = code, str(message)[:2000]

SERVICE_RE = re.compile(r"service:([a-z0-9][a-z0-9-]{1,40})\Z")
TOOL_RE = re.compile(r"[a-z0-9][a-z0-9-]{0,40}\Z")
TOKEN_RE = re.compile(r"[A-Za-z0-9_]{10,200}\Z")
UUID_RE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\Z")
REF_RE = re.compile(r"(?!-)(?!.*(\.\.|//|@\{))[A-Za-z0-9._/-]{1,255}\Z")
TOOLS = common.p("/usr/lib/scanoria/scan-tools")
# Codes d'erreur du runner (scan-result) : propres à ce fichier, hors liste fermée du helper.
E_MODULE_INVALID, E_SERVICE_MISSING, E_SERVICE_TOKEN = "E_MODULE_INVALID", "E_SERVICE_MISSING", "E_SERVICE_TOKEN"
TOKEN_NAME = "scan-token"
TESTBED_KEY = "scanoria-testbed"
# Réseau interne Internal=true (ni passerelle, ni sortie) : le service y répond en HTTP.
INTERNAL_SCHEME = "http"
NOBODY = 65534


def service_of(m):
    """Identifiant du service visé par scan.network, ou None (réseau « none » ou « target »)."""
    net = (m.get("scan") or {}).get("network", "none")
    if net in ("none", "target"):
        return None
    mm = SERVICE_RE.match(net) if isinstance(net, str) else None
    if not mm:
        raise Unavailable(E_MODULE_INVALID, "invalid scan.network")
    return mm.group(1)


def network_name(sid):
    return "scanoria-mod-%s_scan" % sid


def container_name(sid):
    return "scanoria-mod-%s" % sid


def secret_path(sid, name):
    """Fichier d'un secret de service (moteur des services, contrat 10)."""
    try:
        from . import services
        return services.secret_path(sid, name)
    except (ImportError, AttributeError):
        return os.path.join(common.VARLIB, "modules", sid, "secrets", name)


def project_key(project_id):
    """Clé du projet dans le service : scanoria-<12 premiers chiffres hexadécimaux de l'uuid>."""
    if not isinstance(project_id, str) or not UUID_RE.match(project_id):
        return None
    return "scanoria-" + project_id.replace("-", "")[:12]


def _branch(ref):
    return ref[len("refs/heads/"):] if ref.startswith("refs/heads/") else ref


def service_features(reg, m):
    """Fonctions actives du service visé par m (manifeste effectif du registre)."""
    from . import variants
    try:
        sid = service_of(m)
    except Unavailable:
        return set()
    e = (reg.get("modules") or {}).get(sid) if sid else None
    return variants.active_features(e.get("manifest")) if isinstance(e, dict) else set()


def _short(ref):
    for p in ("refs/heads/", "refs/tags/"):
        if ref.startswith(p):
            return ref[len(p):]
    return ref


def branch_of(m, source, features=()):
    """Branche à transmettre (SCANORIA_BRANCH) : None pour la branche par défaut,
    pour un module sans scan.refs_feature ou un service sans cette fonction."""
    scan = m.get("scan") or {}
    feat = scan.get("refs_feature")
    if scan.get("refs") != "default-branch" or not isinstance(feat, str) or feat not in features:
        return None
    if source.get("kind") != "git":
        return None
    ref, default = source.get("ref"), source.get("default_branch")
    if not isinstance(ref, str) or not REF_RE.match(ref) or ref.startswith("refs/") and not \
            ref.startswith(("refs/heads/", "refs/tags/")):
        return None
    # Branche par défaut inconnue : impossible de savoir si ref l'est, rien n'est transmis.
    if not isinstance(default, str) or not REF_RE.match(default) or _branch(ref) == _branch(default):
        return None
    name = _short(ref)
    return name if REF_RE.match(name) and not name.endswith((".", "/")) else None


def refs_skip(m, source, features=()):
    """Raison de « skipped » si scan.refs l'impose et que la référence n'est pas la branche par défaut."""
    scan = m.get("scan") or {}
    if scan.get("refs", "any") != "default-branch":
        return None
    feat = scan.get("refs_feature")
    if branch_of(m, source, features) is not None:
        return None
    if source.get("kind") != "git":
        return "default branch only: an uploaded archive is not the default branch"
    ref, default = source.get("ref"), source.get("default_branch")
    if not isinstance(default, str) or not REF_RE.match(default):
        return "default branch only: the default branch of the project is unknown"
    if not isinstance(ref, str) or _branch(ref) != _branch(default):
        if isinstance(feat, str):
            return "default branch only (%s): %s is not active on the service" % (_branch(default), feat)
        return "default branch only (%s)" % _branch(default)
    return None


def read_token(sid):
    """Jeton d'analyse du service : fichier régulier root 0600, sans lien, de forme attendue."""
    path = secret_path(sid, TOKEN_NAME)
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_NOCTTY)
    except OSError:
        raise Unavailable(E_SERVICE_TOKEN, "analysis token of %s is missing" % sid)
    with os.fdopen(fd, "rb") as f:
        st = os.fstat(f.fileno())
        if not stat.S_ISREG(st.st_mode) or stat.S_IMODE(st.st_mode) & 0o077 or \
                (not common.TEST_ROOT and st.st_uid != 0):
            raise Unavailable(E_SERVICE_TOKEN, "analysis token of %s has unsafe permissions" % sid)
        data = f.read(513)
    try:
        tok = data.decode("ascii").strip()
    except UnicodeDecodeError:
        tok = ""
    if not TOKEN_RE.match(tok):
        raise Unavailable(E_SERVICE_TOKEN, "analysis token of %s is malformed" % sid)
    return tok


def resolve(reg, m):
    """Service joignable pour le scanner m : {service, network, url, token} ; lève Fail sinon."""
    sid = service_of(m)
    if sid is None:
        return None
    e = (reg.get("modules") or {}).get(sid)
    sm = e.get("manifest") if isinstance(e, dict) else None
    if not isinstance(sm, dict) or sm.get("type") != "service" or e.get("status") != "healthy" \
            or e.get("enabled") is not True:
        raise Unavailable(E_SERVICE_MISSING, "service %s is not installed, healthy and enabled" % sid)
    port = (sm.get("service") or {}).get("port")
    if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
        raise Unavailable(E_SERVICE_MISSING, "service %s has no valid port" % sid)
    return {"service": sid, "network": network_name(sid), "token": read_token(sid),
            "url": "%s://%s:%d" % (INTERNAL_SCHEME, container_name(sid), port)}


def tool_mount(m):
    """[(hôte, /scanoria, ro)] si le scanner déclare scan.tool ; lève Fail si l'outil manque."""
    tool = (m.get("scan") or {}).get("tool")
    if tool is None:
        return []
    if not isinstance(tool, str) or not TOOL_RE.match(tool):
        raise Unavailable(E_MODULE_INVALID, "invalid scan.tool")
    d = os.path.join(TOOLS, tool)
    if not os.path.isdir(d) or os.path.islink(d):
        raise Unavailable(E_MODULE_INVALID, "appliance tool %s is missing: update the appliance" % tool)
    return [(d, "/scanoria", "ro")]


class Attachment:
    """Secret Podman du jeton et arguments « podman run » ; à fermer après le conteneur."""

    def __init__(self, svc, key, budget_s=None):
        import secrets as _s
        self.svc, self.key = svc, key
        self.secret = "scanoria-scan-%s" % _s.token_hex(8)
        self.created = False
        self.budget_s = budget_s

    def __enter__(self):
        tmp = os.path.join(common.RUN, "scan-secret-%s" % self.secret)
        os.makedirs(os.path.dirname(tmp), mode=0o750, exist_ok=True)
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            with os.fdopen(fd, "w", encoding="ascii") as f:
                f.write(self.svc["token"])
            # Marqué avant la création : une création interrompue (délai) est
            # quand même suivie d'une suppression à la sortie.
            self.created = True
            r = common.run("podman", ["secret", "create", self.secret, tmp], timeout=60)
        except BaseException:
            self.__exit__()
            raise
        finally:
            os.unlink(tmp)
        if r.returncode != 0:
            self.__exit__()
            self.created = False
            raise Unavailable(E_SERVICE_TOKEN, "cannot create the podman secret of the analysis token")
        self.created = True
        return self

    def args(self):
        out = ["--network=" + self.svc["network"],
               "--secret", "%s,type=mount,target=%s,uid=%d,gid=%d,mode=400" % (self.secret, TOKEN_NAME, NOBODY, NOBODY),
               "--env", "SCANORIA_SERVICE_URL=" + self.svc["url"],
               "--env", "SCANORIA_PROJECT_KEY=" + self.key]
        if self.budget_s:
            out += ["--env", "SCANORIA_BUDGET_S=%d" % int(self.budget_s)]
        branch = self.svc.get("branch")
        if branch:
            if not isinstance(branch, str) or not REF_RE.match(branch):
                raise Unavailable(E_MODULE_INVALID, "invalid branch name")
            out += ["--env", "SCANORIA_BRANCH=" + branch]
        return out

    def __exit__(self, *exc):
        if self.created:
            try:
                common.run("podman", ["secret", "rm", self.secret], timeout=60)
            except Exception as e:  # noqa: BLE001 (repris par remove_orphan_secrets au démarrage)
                common.log("runner: cannot remove podman secret %s: %r" % (self.secret, e))
        return False


SECRET_RE = re.compile(r"scanoria-scan-[0-9a-f]{16}\Z")


def remove_orphan_secrets():
    """Au démarrage du runner (aucune analyse en cours) : secrets Podman de jeton
    laissés par un arrêt brutal, supprimés."""
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


def network_args(args, extra):
    """Remplace --network=none de confined_args par les arguments du service."""
    if "--network=none" not in args:
        raise Fail("E_INTERNAL", "confined arguments without --network=none")
    i = args.index("--network=none")
    return args[:i] + extra + args[i + 1:]
