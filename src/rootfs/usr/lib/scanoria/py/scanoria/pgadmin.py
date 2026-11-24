# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Vincent Tisseront
"""Bases PostgreSQL des modules (contrat 10 de la 0.4, CLAUDE.md § 3.2).

Pour un manifeste needs.postgres: true, le helper crée le rôle et la base
« mod_<id> » (tirets changés en « _ »), avec le mot de passe tiré au hasard
dans le secret « db-password » du module (services.secret_path). L'accès réseau
est limité par pg_hba au seul sous-réseau du module, en scram-sha-256 :

  /etc/postgresql/16/main/conf.d/scanoria_modules.conf
      listen_addresses = '*' (écrit au premier module qui en a besoin ; le
      pare-feu de l'appliance ne laisse entrer le port 5432 que depuis les
      réseaux des modules, et pg_hba n'accepte que ces réseaux) ;
  /etc/postgresql/16/main/scanoria-modules-hba.conf
      une ligne « host mod_<id> mod_<id> <sous-réseau> scram-sha-256 » par
      module, incluse par pg_hba.conf (include_if_exists, PostgreSQL 16).

Aucune valeur n'est interpolée dans du SQL sans être passée par un motif
fermé ; le mot de passe est transmis par une variable psql, jamais en
argument visible.
"""

import ipaddress
import os
import re

from . import common, services
from .common import Fail

PG_ETC = common.p("/etc/postgresql/16/main")
CONF_FILE = PG_ETC + "/conf.d/scanoria_modules.conf"
HBA_FILE = PG_ETC + "/pg_hba.conf"
HBA_INCLUDE = PG_ETC + "/scanoria-modules-hba.conf"
INCLUDE_LINE = "include_if_exists scanoria-modules-hba.conf"
DB_RE = re.compile(r"mod_[a-z0-9][a-z0-9_]{1,40}\Z")


def db_name(mid):
    name = "mod_" + services.check_id(mid).replace("-", "_")
    if not DB_RE.match(name):
        raise Fail("E_INVALID_PARAM", "invalid database name")
    return name


def psql(sql, variables=None, timeout=300):
    args = ["-u", "postgres", "--", "/usr/bin/psql", "-X", "-q", "-v", "ON_ERROR_STOP=1", "-d", "postgres"]
    script = "".join("\\set %s '%s'\n" % (k, v) for k, v in sorted((variables or {}).items())) + sql
    r = common.run("runuser", args, input=script.encode(), timeout=timeout)
    if r.returncode != 0:
        raise Fail("E_INTERNAL", "PostgreSQL command failed")
    return r


def _give_to_postgres(path):
    """Fichiers de pg_hba lisibles par PostgreSQL seul (postgres:postgres 0640)."""
    if os.geteuid() != 0:
        return
    import pwd
    try:
        pw = pwd.getpwnam("postgres")
    except KeyError:
        raise Fail("E_PRECONDITION", "PostgreSQL account missing")
    os.chown(path, pw.pw_uid, pw.pw_gid)


def _ensure_hba_include():
    try:
        with open(HBA_FILE, encoding="utf-8") as f:
            text = f.read()
    except FileNotFoundError:
        text = ""
    if INCLUDE_LINE in text.splitlines():
        return False
    if text and not text.endswith("\n"):
        text += "\n"
    text += "# Scanoria : accès des modules (une ligne par module, générées par scanoria-helper).\n"
    text += INCLUDE_LINE + "\n"
    os.makedirs(PG_ETC, mode=0o755, exist_ok=True)
    common.atomic_write(HBA_FILE, text, 0o640, group_scanoria=False)
    _give_to_postgres(HBA_FILE)
    return True


def _ensure_listen():
    want = "# Généré par scanoria-helper : modules qui utilisent PostgreSQL.\nlisten_addresses = '*'\n"
    try:
        with open(CONF_FILE, encoding="utf-8") as f:
            if f.read() == want:
                return False
    except FileNotFoundError:
        pass
    os.makedirs(os.path.dirname(CONF_FILE), mode=0o755, exist_ok=True)
    common.atomic_write(CONF_FILE, want, 0o644, group_scanoria=False)
    return True


def write_hba(entries):
    """entries : {id du module: sous-réseau (ipaddress)} ; réécrit le fichier inclus."""
    lines = ["# Généré par scanoria-helper : ne pas modifier."]
    for mid in sorted(entries):
        net = entries[mid]
        if not isinstance(net, ipaddress.IPv4Network) or not net.is_private:
            raise Fail("E_INTERNAL", "invalid module network")
        name = db_name(mid)
        lines.append("host %s %s %s scram-sha-256" % (name, name, net))
    os.makedirs(PG_ETC, mode=0o755, exist_ok=True)
    common.atomic_write(HBA_INCLUDE, "\n".join(lines) + "\n", 0o640, group_scanoria=False)
    _give_to_postgres(HBA_INCLUDE)


def apply_access(reg):
    """Accès réseau des modules à PostgreSQL d'après le registre ; recharge ou redémarre."""
    entries = {}
    for mid, e in reg["modules"].items():
        m = e.get("manifest") or {}
        if (m.get("needs") or {}).get("postgres") and isinstance(e.get("subnet"), int):
            entries[mid] = services.subnet(e["subnet"])
    write_hba(entries)
    restart = False
    if entries:
        restart = _ensure_listen()
    _ensure_hba_include()
    action = "restart" if restart else "reload"
    if common.run("systemctl", [action, "postgresql.service"], timeout=300).returncode != 0:
        raise Fail("E_INTERNAL", "PostgreSQL %s failed" % action)


def ensure_database(m):
    """Crée (ou reprend, si ses données ont été gardées) le rôle et la base du module.
    Retourne True si la base vient d'être créée."""
    mid = m["id"]
    name = db_name(mid)
    pw = services.read_secret(mid, services.DB_SECRET)
    if pw is None or not services.SECRET_VALUE_RE.match(pw):
        raise Fail("E_INTERNAL", "database password of %s missing" % mid)
    r = common.run("runuser", ["-u", "postgres", "--", "/usr/bin/psql", "-X", "-A", "-t", "-d", "postgres",
                               "-c", "SELECT 1 FROM pg_database WHERE datname = '%s'" % name], timeout=120)
    existed = r.text.strip() == "1"
    psql("SELECT format('CREATE ROLE %I LOGIN', :'name') WHERE NOT EXISTS "
         "(SELECT FROM pg_roles WHERE rolname = :'name')\\gexec\n"
         "SELECT format('ALTER ROLE %I LOGIN PASSWORD %L', :'name', :'pw')\\gexec\n"
         "SELECT format('CREATE DATABASE %I OWNER %I', :'name', :'name') WHERE NOT EXISTS "
         "(SELECT FROM pg_database WHERE datname = :'name')\\gexec\n"
         "SELECT format('REVOKE ALL ON DATABASE %I FROM PUBLIC', :'name')\\gexec\n",
         {"name": name, "pw": pw})
    return not existed


def drop_database(mid):
    name = db_name(mid)
    psql("SELECT format('DROP DATABASE IF EXISTS %I WITH (FORCE)', :'name')\\gexec\n"
         "SELECT format('DROP ROLE IF EXISTS %I', :'name')\\gexec\n", {"name": name})


def dump(mid, dest, timeout=1800):
    """pg_dump -Fc de la base du module dans dest (0600)."""
    from . import backup
    rc = backup.run_to_file("runuser", ["-u", "postgres", "--", "/usr/bin/pg_dump", "-Fc", db_name(mid)],
                            dest, timeout=timeout)
    if rc != 0:
        raise Fail("E_BACKUP_FAILED", "database backup of %s failed" % mid)


def restore(mid, src, timeout=1800):
    """Remplace le contenu de la base par une sauvegarde pg_dump -Fc."""
    name = db_name(mid)
    psql("SELECT format('DROP DATABASE IF EXISTS %I WITH (FORCE)', :'name')\\gexec\n"
         "SELECT format('CREATE DATABASE %I OWNER %I', :'name', :'name')\\gexec\n"
         "SELECT format('REVOKE ALL ON DATABASE %I FROM PUBLIC', :'name')\\gexec\n", {"name": name})
    from . import backup
    rc = backup.run_from_file("runuser", ["-u", "postgres", "--", "/usr/bin/pg_restore", "--no-owner",
                                          "--role", name, "-d", name], src, timeout=timeout)
    if rc != 0:
        raise Fail("E_BACKUP_FAILED", "database restore of %s failed" % mid)
