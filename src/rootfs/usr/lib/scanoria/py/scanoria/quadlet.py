# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Vincent Tisseront
"""Unités Quadlet des modules permanents (types service et runner).

Un module <id> produit, dans /etc/containers/systemd/ :
  scanoria-mod-<id>.network          réseau propre au module, /24 fixe (services.py),
                                     passerelle = accès à PostgreSQL ;
  scanoria-mod-<id>_scan.network     (type service) réseau interne sans sortie,
                                     où le runner rattache les scanners reliés
                                     au service (contrat 12) ;
  scanoria-mod-<id>-<nom>.volume     un par volume déclaré (service.volumes) ;
  scanoria-mod-<id>.container        le conteneur, publié sur 127.0.0.1 seulement.
Les secrets générés par le helper (services.py) sont passés par des secrets
Podman, jamais écrits dans une unité. Le générateur Quadlet de systemd en tire
scanoria-mod-<id>.service. Un module
désactivé garde ses fichiers sans section [Install] : il ne démarre plus au
démarrage de la machine.

Toutes les valeurs viennent de l'index signé mais sont revalidées ici par des
motifs fermés : aucune ne peut ajouter de ligne ni de directive.
"""

import os
import re

from . import common
from .common import Fail

UNIT_DIR = common.p("/etc/containers/systemd")
MODULE_ETC = common.ETC + "/modules"
PREFIX = "scanoria-mod-"

ID_RE = re.compile(r"[a-z0-9][a-z0-9-]{1,40}\Z")
VOL_NAME_RE = re.compile(r"[a-z0-9][a-z0-9-]{0,30}\Z")
PATH_RE = re.compile(r"/[A-Za-z0-9._/-]{1,200}\Z")
ENV_KEY_RE = re.compile(r"(?!LD_|PATH\Z|HOME\Z)[A-Z][A-Z0-9_]{0,63}\Z")
ENV_VALUE_RE = re.compile(r"[A-Za-z0-9._:/@%+=,~-]{0,1024}\Z")
SECRET_RE = re.compile(r"scanoria-mod-[a-z0-9][a-z0-9-]{1,40}-[a-z][a-z0-9-]{0,40}\Z")
SECRET_SHORT_RE = re.compile(r"[a-z][a-z0-9-]{0,40}\Z")
PLACEHOLDER_RE = re.compile(r"\{([a-z_]{1,32}|opt\.[a-z0-9_]{1,40})\}")


def volume_name(mid, name):
    """Nom du volume podman (et du fichier .volume sans extension) d'un module."""
    return "%s%s_%s" % (PREFIX, mid, name)


def unit_name(mid):
    return PREFIX + mid + ".service"


def _need(regex, value, what):
    if not isinstance(value, str) or not regex.match(value) or ".." in value.split("/"):
        raise Fail("E_INVALID_PARAM", "invalid %s" % what)
    return value


def render_env(templates, values):
    """Remplace {clé} et {opt.nom} ; refuse une valeur hors du jeu de caractères sûr."""
    out = []
    if not isinstance(templates, dict):
        return out
    for k in sorted(templates):
        _need(ENV_KEY_RE, k, "environment variable name")
        tpl = templates[k]
        if not isinstance(tpl, str) or len(tpl) > 1024:
            raise Fail("E_INVALID_PARAM", "invalid environment template for %s" % k)

        def sub(m):
            key = m.group(1)
            if key not in values:
                raise Fail("E_INVALID_PARAM", "unknown placeholder {%s}" % key)
            return str(values[key])
        val = PLACEHOLDER_RE.sub(sub, tpl)
        if not ENV_VALUE_RE.match(val):
            raise Fail("E_INVALID_PARAM", "unsafe value for environment variable %s" % k)
        out.append("%s=%s" % (k, val))
    return out


def volumes(manifest):
    svc = manifest.get("service") or {}
    res = []
    for v in svc.get("volumes") or []:
        if not isinstance(v, dict):
            raise Fail("E_INVALID_PARAM", "invalid volume declaration")
        res.append((_need(VOL_NAME_RE, v.get("name"), "volume name"), _need(PATH_RE, v.get("path"), "volume path")))
    if len({n for n, _ in res}) != len(res):
        raise Fail("E_INVALID_PARAM", "duplicate volume name")
    return res


def render(manifest, host_port, enabled, has_env, subnet=None, secrets=(), ulimits=None, trust=None, hosts=()):
    """Contenu des fichiers Quadlet : {nom de fichier: texte}.

    subnet : ipaddress.IPv4Network du réseau du module (None : laissé à Podman) ;
    secrets : [(nom du secret Podman, nom court, variable ou None)] ;
    ulimits : {nofile|nproc: valeur} déjà validées (services.requirements) ;
    trust : (secret Podman, chemin absolu) d'un magasin de certificats monté en
    lecture seule (dtmirror, 0.6) ; hosts : [(nom, adresse IPv4)] ajoutés au
    /etc/hosts du conteneur."""
    mid = _need(ID_RE, manifest.get("id"), "module id")
    image = manifest.get("image")
    from .catalogverify import IMAGE_RE
    _need(IMAGE_RE, image, "image")
    svc = manifest.get("service") or {}
    port = svc.get("port")
    if manifest.get("type") == "service":
        if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
            raise Fail("E_INVALID_PARAM", "invalid service port")
        if not isinstance(host_port, int) or not 1024 <= host_port <= 65535:
            raise Fail("E_INVALID_PARAM", "invalid host port")
    res = manifest.get("resources") or {}
    ram = res.get("min_ram_mb") if isinstance(res.get("min_ram_mb"), int) else 512
    base = PREFIX + mid
    net = "[Network]\nNetworkName=%s\n" % base
    if subnet is not None:
        net += "Subnet=%s\nGateway=%s\n" % (subnet, subnet.network_address + 1)
    files = {base + ".network": net}
    is_service = manifest.get("type") == "service"
    if is_service:
        files[base + "_scan.network"] = "[Network]\nNetworkName=%s_scan\nInternal=true\n" % base
    lines = [
        "# Généré par scanoria-helper : ne pas modifier.",
        "[Unit]",
        "Description=Scanoria module %s" % mid,
        "Wants=network-online.target",
        "After=network-online.target" + (" postgresql.service" if (manifest.get("needs") or {}).get("postgres") else ""),
        "",
        "[Container]",
        "ContainerName=%s" % base,
        "Image=%s" % image,
        "Pull=never",
        "Network=%s.network" % base,
    ] + (["Network=%s_scan.network" % base] if is_service else []) + [
        "NoNewPrivileges=true",
        "DropCapability=ALL",
        "PodmanArgs=--memory=%dm --pids-limit=4096" % max(256, int(ram) * 2),
    ]
    if manifest.get("type") == "service":
        lines.append("PublishPort=127.0.0.1:%d:%d" % (host_port, port))
    for name, path in volumes(manifest):
        vfile = volume_name(mid, name) + ".volume"
        files[vfile] = "[Volume]\nVolumeName=%s\n" % volume_name(mid, name)
        lines.append("Volume=%s:%s" % (vfile, path))
    for pname, short, env in secrets:
        _need(SECRET_RE, pname, "secret name")
        _need(SECRET_SHORT_RE, short, "secret name")
        if env is None:
            lines.append("Secret=%s,type=mount,target=%s" % (pname, short))
        else:
            _need(ENV_KEY_RE, env, "secret variable")
            lines.append("Secret=%s,type=env,target=%s" % (pname, env))
    if trust is not None:
        pname, target = trust
        _need(SECRET_RE, pname, "secret name")
        _need(PATH_RE, target, "trust store path")
        lines.append("Secret=%s,type=mount,target=%s,mode=0444" % (pname, target))
    for name, addr in hosts:
        from . import netutil
        import ipaddress
        if not netutil.check_fqdn(name):
            raise Fail("E_INVALID_PARAM", "invalid host name")
        try:
            ip = ipaddress.IPv4Address(addr)
        except (ipaddress.AddressValueError, ValueError, TypeError):
            raise Fail("E_INVALID_PARAM", "invalid host address")
        # Clé AddHost= absente du Quadlet de Podman 4.9 : option passée telle quelle.
        lines.append("PodmanArgs=--add-host=%s:%s" % (name, ip))
    for k in sorted(ulimits or {}):
        v = ulimits[k]
        if k not in ("nofile", "nproc") or not isinstance(v, int) or isinstance(v, bool) or not 1 <= v <= 1 << 22:
            raise Fail("E_INVALID_PARAM", "invalid unit limit")
        lines.append("Ulimit=%s=%d:%d" % (k, v, v))
    if has_env:
        lines.append("EnvironmentFile=%s/%s/env" % (MODULE_ETC, mid))
    lines += ["", "[Service]", "Restart=on-failure", "TimeoutStartSec=900"]
    if enabled:
        lines += ["", "[Install]", "WantedBy=multi-user.target"]
    files[base + ".container"] = "\n".join(lines) + "\n"
    return files


def existing_files(mid):
    try:
        names = os.listdir(UNIT_DIR)
    except FileNotFoundError:
        return []
    base = PREFIX + mid
    # « _ » ne peut figurer ni dans un id ni dans un nom de volume : aucun
    # fichier d'un autre module (« dt » et « dt-api ») ne correspond.
    return sorted(n for n in names if n in (base + ".container", base + ".network", base + "_scan.network")
                  or (n.startswith(base + "_") and n.endswith(".volume")))


ENV_KEY = "env"  # clé du fichier d'environnement dans un instantané


def snapshot(mid):
    """Contenu actuel des unités et du fichier d'environnement du module (retour arrière)."""
    snap = {}
    for n in existing_files(mid):
        with open(os.path.join(UNIT_DIR, n), "rb") as f:
            snap[n] = f.read()
    try:
        with open(os.path.join(MODULE_ETC, mid, "env"), "rb") as f:
            snap[ENV_KEY] = f.read()
    except FileNotFoundError:
        snap[ENV_KEY] = None
    return snap


def restore(mid, snap):
    """Remet un instantané pris par snapshot()."""
    units = {k: v for k, v in snap.items() if k != ENV_KEY}
    write(mid, units)
    envf = os.path.join(MODULE_ETC, mid, "env")
    if snap.get(ENV_KEY) is not None:
        os.makedirs(os.path.dirname(envf), mode=0o700, exist_ok=True)
        common.atomic_write(envf, snap[ENV_KEY], 0o600, group_scanoria=False)
    elif os.path.exists(envf):
        os.unlink(envf)


def write(mid, files):
    """Remplace les fichiers du module par files (les autres sont retirés)."""
    os.makedirs(UNIT_DIR, mode=0o755, exist_ok=True)
    for n in existing_files(mid):
        if n not in files:
            os.unlink(os.path.join(UNIT_DIR, n))
    for n, text in files.items():
        common.atomic_write(os.path.join(UNIT_DIR, n), text, 0o644, group_scanoria=False)


def remove(mid):
    write(mid, {})


def write_env(mid, lines):
    d = os.path.join(MODULE_ETC, mid)
    os.makedirs(d, mode=0o700, exist_ok=True)
    common.atomic_write(os.path.join(d, "env"), "\n".join(lines) + "\n", 0o600, group_scanoria=False)
