# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Vincent Tisseront
"""Aiguillage des modules « service » par nom (CLAUDE.md § 3.4).

  apply(fqdn, services)  régénère /etc/nginx/scanoria.d/ et recharge nginx
  resync()               rejoue la dernière liste avec le nom actuel
  sites_status()         cohérence des sites avec modules/state.json (selftest)

Chaque service actif répond sur <libellé>.<fqdn> (proxy vers 127.0.0.1:<port>),
un service désactivé et tout autre <libellé>.<fqdn> sont redirigés vers la page
« module indisponible » de la console. Les fichiers sont générés depuis
/usr/share/scanoria/nginx/modules/*.tmpl, avec des valeurs validées sur une
liste fermée de caractères ([a-z0-9.-]) : aucune donnée n'est insérée sans ce
contrôle. Remplacement atomique fichier par fichier, « nginx -t », puis
rechargement ; si « nginx -t » échoue, l'ancien contenu du répertoire est remis.

Appelé sous le verrou du helper (actions de modules, check-dns).
"""

import os
import re
import stat

from . import common, netutil
from .common import Fail

SITES_DIR = common.p("/etc/nginx/scanoria.d")
TEMPLATES = os.path.join(common.SHARE_DIR, "nginx", "modules")
SITES_FILE = common.VARLIB + "/routing/sites.json"
STATE_MODULES = common.VARLIB + "/modules/state.json"

ID_RE = re.compile(r"[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?\Z", re.ASCII)
LABEL_RE = re.compile(r"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\Z", re.ASCII)
SITE_RE = re.compile(r"module-([a-z0-9][a-z0-9-]{0,63})\.conf\Z", re.ASCII)
CATCHALL = "00-catchall.conf"
# Sites de l'appliance elle-même (0.6, chantier A) : miroir F17 et bases servies
# aux modules permanents. Libellés réservés, jamais attribués à un module.
MIRROR_SITE = "10-mirror.conf"
FEEDS_SITE = "10-feeds-mirror.conf"
EXTRA_SITES = (MIRROR_SITE, FEEDS_SITE)
RESERVED_LABELS = frozenset(("mirror", "feeds"))
MARK_RE = re.compile(r"# scanoria-route: id=(\S+) mode=(proxy|unavailable|catchall|static) host=(\S+) "
                     r"port=(\S+) fqdn=(\S+)$", re.ASCII | re.MULTILINE)
# Ports de la console et des services système, jamais attribués à un module.
RESERVED_PORTS = frozenset((3000, 5432))
PORT_MIN, PORT_MAX = 1024, 65535
MAX_SERVICES = 200
SAFE_RE = re.compile(r"[a-z0-9.-]{1,253}\Z", re.ASCII)
ALLOW_RE = re.compile(r"(-|[0-9]{1,3}(\.[0-9]{1,3}){3}/[0-9]{1,2})\Z", re.ASCII)
PLACEHOLDER_RE = re.compile(r"@[A-Z_]+@")


def _safe(value):
    """Dernier rempart avant insertion dans un gabarit nginx."""
    s = str(value)
    if not SAFE_RE.match(s):
        raise Fail("E_INVALID_PARAM", "unsafe value for nginx template")
    return s


def validate(fqdn, services):
    """Liste normalisée [{id, hostname, port, enabled}] ou Fail(E_INVALID_PARAM)."""
    if not netutil.check_fqdn(fqdn):
        raise Fail("E_INVALID_PARAM", "invalid appliance name")
    if not isinstance(services, list) or len(services) > MAX_SERVICES:
        raise Fail("E_INVALID_PARAM", "services must be a list of at most %d items" % MAX_SERVICES)
    out, ids, labels, ports = [], set(), set(), set()
    for s in services:
        if not isinstance(s, dict) or set(s) != {"id", "hostname", "port", "enabled"}:
            raise Fail("E_INVALID_PARAM", "service must have exactly id, hostname, port, enabled")
        sid, label, port, enabled = s["id"], s["hostname"], s["port"], s["enabled"]
        if not isinstance(sid, str) or not ID_RE.match(sid):
            raise Fail("E_INVALID_PARAM", "invalid module id")
        if not isinstance(label, str) or not LABEL_RE.match(label) or label in RESERVED_LABELS:
            raise Fail("E_INVALID_PARAM", "invalid hostname label for %s" % sid)
        if len(label) + 1 + len(fqdn) > 253:
            raise Fail("E_INVALID_PARAM", "name too long for %s" % sid)
        if type(port) is not int or not PORT_MIN <= port <= PORT_MAX or port in RESERVED_PORTS:
            raise Fail("E_INVALID_PARAM", "invalid port for %s" % sid)
        if type(enabled) is not bool:
            raise Fail("E_INVALID_PARAM", "enabled must be a boolean for %s" % sid)
        if sid in ids or label in labels or (enabled and port in ports):
            raise Fail("E_INVALID_PARAM", "duplicate id, hostname or port: %s" % sid)
        ids.add(sid)
        labels.add(label)
        if enabled:
            ports.add(port)
        out.append({"id": sid, "hostname": label, "port": port, "enabled": enabled})
    return sorted(out, key=lambda x: x["id"])


def _template(name):
    with open(os.path.join(TEMPLATES, name), encoding="utf-8") as f:
        return f.read()


def _render(name, fqdn, tls, sid="-", host="-", port="-", allow="-"):
    if not ALLOW_RE.match(allow):
        raise Fail("E_INVALID_PARAM", "unsafe value for nginx template")
    text = _template(name).replace("@ALLOW@", allow)
    for key, val in (("@ID@", sid), ("@HOST@", host), ("@PORT@", port),
                     ("@FQDN_RE@", _safe(fqdn).replace(".", "\\.")), ("@FQDN@", fqdn)):
        text = text.replace(key, val if key == "@FQDN_RE@" else _safe(val))
    text = text.replace("@TLS@\n", tls)
    if not os.path.exists("/proc/net/if_inet6"):  # IPv6 désactivé : pas d'écoute [::]
        text = "".join(ln for ln in text.splitlines(True) if "listen [::]" not in ln)
    if PLACEHOLDER_RE.search(text):
        raise Fail("E_INTERNAL", "unresolved placeholder in %s" % name)
    return text


def render(fqdn, services):
    """{nom de fichier: contenu} pour la liste validée."""
    tls = "".join(ln for ln in _template("tls.inc.tmpl").splitlines(True) if not ln.startswith("#"))
    files = {CATCHALL: _render("catchall.conf.tmpl", fqdn, tls)}
    for s in services:
        tmpl = "proxy.conf.tmpl" if s["enabled"] else "unavailable.conf.tmpl"
        files["module-%s.conf" % s["id"]] = _render(
            tmpl, fqdn, tls, s["id"], "%s.%s" % (s["hostname"], fqdn), str(s["port"]))
    files.update(extra_sites(fqdn, tls))
    return files


def extra_sites(fqdn, tls):
    """Miroir F17 (dès qu'un lot est publié) et bases servies aux modules (Dependency-Track installé)."""
    from . import dtmirror, mirror
    out = {}
    if mirror.published():
        out[MIRROR_SITE] = _render("mirror.conf.tmpl", fqdn, tls, host="mirror.%s" % fqdn)
    if dtmirror.dt_installed():
        # Réseau de Dependency-Track seul (adresse validée ici, jamais lue telle quelle) ;
        # sans réseau connu, personne : « 127.0.0.1/32 » ne passe ni nftables ni un module.
        import ipaddress
        sub = dtmirror.dt_subnet()
        allow = str(ipaddress.IPv4Network(sub)) if sub else "127.0.0.1/32"
        if not os.path.isfile(common.ETC + "/pki/feeds/fullchain.pem"):
            dtmirror.ensure_tls()
        out[FEEDS_SITE] = _render("feeds-mirror.conf.tmpl", fqdn, tls, port=str(dtmirror.PORT), allow=allow)
    return out


def _sites_dir():
    os.makedirs(SITES_DIR, mode=0o755, exist_ok=True)
    st = os.lstat(SITES_DIR)
    if not stat.S_ISDIR(st.st_mode) or (not common.TEST_ROOT and st.st_uid != 0) \
            or st.st_mode & 0o022:
        raise Fail("E_PRECONDITION", "%s is not a root-owned directory writable by root only" % SITES_DIR)


def _managed(name):
    return name == CATCHALL or name in EXTRA_SITES or SITE_RE.match(name) is not None


def _snapshot():
    """Contenu actuel des fichiers gérés (fichiers réguliers seulement)."""
    snap = {}
    for n in os.listdir(SITES_DIR):
        if not _managed(n):
            continue
        path = os.path.join(SITES_DIR, n)
        st = os.lstat(path)
        if stat.S_ISREG(st.st_mode):
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            with os.fdopen(fd, "rb") as f:
                snap[n] = f.read()
        else:  # lien ou autre : jamais suivi, toujours retiré
            snap[n] = None
    return snap


def _install(files, snap):
    for n, data in files.items():
        if snap.get(n) != (data.encode("utf-8") if isinstance(data, str) else data):
            path = os.path.join(SITES_DIR, n)
            if snap.get(n, b"") is None:  # lien ou fichier spécial : retiré, jamais suivi
                os.unlink(path)
            common.atomic_write(path, data, 0o644, group_scanoria=False)
    for n in snap:
        if n not in files:
            os.unlink(os.path.join(SITES_DIR, n))


def _restore(snap):
    for n in os.listdir(SITES_DIR):
        if _managed(n) and snap.get(n) is None:
            try:
                os.unlink(os.path.join(SITES_DIR, n))
            except OSError:  # répertoire planté : laissé tel quel, nginx -t le refusera
                pass
    for n, data in snap.items():
        if data is not None:
            common.atomic_write(os.path.join(SITES_DIR, n), data, 0o644, group_scanoria=False)


def _routes(fqdn, services):
    return [{"id": s["id"], "hostname": "%s.%s" % (s["hostname"], fqdn),
             "url": "https://%s.%s/" % (s["hostname"], fqdn)} for s in services if s["enabled"]]


def appliance_fqdn():
    try:
        f = common.load_json_file(common.ETC + "/appliance.json", 1 << 16).get("fqdn")
    except (OSError, common.JsonError, AttributeError):
        return None
    return f if netutil.check_fqdn(f) else None


def apply(fqdn, services, timeout=120):
    """Régénère les sites des modules ; retourne [{id, hostname, url}] des services actifs.

    fqdn None : nom lu dans /etc/scanoria/appliance.json. services : liste complète
    des modules service (actifs et désactivés) ; un module absent perd son site."""
    if fqdn is None:
        fqdn = appliance_fqdn()
        if fqdn is None:
            raise Fail("E_PRECONDITION", "appliance name not set")
    services = validate(fqdn, services)
    files = render(fqdn, services)
    _sites_dir()
    snap = _snapshot()
    try:
        _install(files, snap)
    except OSError as e:  # disque plein, entrée inattendue : rien à moitié appliqué
        _restore(snap)
        raise Fail("E_INTERNAL", "cannot write module sites (%s); previous sites restored"
                   % e.strerror) from e
    r = common.run("nginx", ["-t", "-q"], timeout=timeout)
    if r.returncode != 0:
        _restore(snap)
        raise Fail("E_INTERNAL", "nginx configuration test failed; previous module sites restored")
    r = common.run("systemctl", ["try-reload-or-restart", "nginx.service"], timeout=timeout)
    if r.returncode != 0:
        _restore(snap)
        common.run("systemctl", ["try-reload-or-restart", "nginx.service"], timeout=timeout)
        raise Fail("E_INTERNAL", "nginx reload failed; previous module sites restored")
    common.shared_dir(os.path.dirname(SITES_FILE))
    common.write_json(SITES_FILE, {"fqdn": fqdn, "applied_at": common.iso(common.now()),
                                   "services": services})
    # Vérification automatique (principe 8) : unités activées une fois (appliance
    # mise à jour depuis une version qui ne les avait pas), contrôle DNS lancé en
    # arrière-plan ; il attend la fin de la demande en cours (verrou du helper).
    common.run("systemctl", ["enable", "--now", "--quiet", "scanoria-dns-check.timer",
                             "scanoria-dns-check.path"], timeout=timeout)
    common.run("systemctl", ["start", "--no-block", "scanoria-dns-check.service"], timeout=timeout)
    return _routes(fqdn, services)


def recorded():
    """Dernière application réussie {fqdn, applied_at, services} ou None."""
    try:
        rec = common.load_json_file(SITES_FILE, 1 << 20)
    except (OSError, common.JsonError):
        return None
    if not isinstance(rec, dict) or not isinstance(rec.get("services"), list):
        return None
    return rec


def resync(timeout=120):
    """Rejoue la dernière liste si le nom de l'appliance a changé ou si aucun site
    n'a encore été généré. Retourne True si nginx a été régénéré."""
    fqdn = appliance_fqdn()
    if fqdn is None:
        return False
    rec = recorded()
    if rec is None and any(m.get("route") for m in (_state_services() or {}).values()):
        # Liste perdue alors que des modules sont routés : ne jamais effacer leurs
        # sites ; le moteur des modules la republie à sa prochaine opération.
        raise Fail("E_PRECONDITION", "routing/sites.json missing while modules are routed")
    if rec is not None and rec.get("fqdn") == fqdn and os.path.isfile(os.path.join(SITES_DIR, CATCHALL)):
        return False
    apply(fqdn, rec["services"] if rec else [], timeout)
    return True


# --------------------------------------------------------------------------
# Contrôle de cohérence (scanoria-selftest, routing.sites)
# --------------------------------------------------------------------------

def _read_marks():
    marks = {}
    try:
        names = os.listdir(SITES_DIR)
    except OSError:
        return marks
    for n in names:
        if not _managed(n):
            continue
        path = os.path.join(SITES_DIR, n)
        if os.path.islink(path) or not os.path.isfile(path):
            marks[n] = None
            continue
        try:
            with open(path, encoding="utf-8") as f:
                m = MARK_RE.search(f.read(8192))
        except (OSError, UnicodeDecodeError):
            m = None
        marks[n] = m.groups() if m else None
    return marks


def _state_services():
    try:
        st = common.load_json_file(STATE_MODULES, 4 << 20)
    except FileNotFoundError:
        return {}
    except (OSError, common.JsonError):
        return None
    mods = st.get("modules") if isinstance(st, dict) else None
    if not isinstance(mods, list):
        return None
    return {m.get("id"): m for m in mods if isinstance(m, dict) and m.get("type") == "service"}


def _route_label(route, fqdn):
    host = route.get("hostname") if isinstance(route, dict) else None
    if not isinstance(host, str):
        return None
    return host[:-len(fqdn) - 1] if host.endswith("." + fqdn) else host


def _check_module(sid, mod, marks, fqdn, problems):
    mark = marks.get("module-%s.conf" % sid)
    route = mod.get("route")
    if route:
        label = _route_label(route, fqdn)
        if mark is None or mark[1] != "proxy":
            problems.append("%s: routed in state but no active site" % sid)
        elif mark[2] != "%s.%s" % (label, fqdn):
            problems.append("%s: site name %s differs from route" % (sid, mark[2]))
    elif mark is not None and mark[1] == "proxy" and mod.get("enabled") is False:
        problems.append("%s: disabled but still proxied" % sid)


def sites_status():
    """(statut selftest, message, détails) : sites cohérents avec modules/state.json."""
    fqdn = appliance_fqdn()
    if fqdn is None:
        return "skip", "appliance name not set", None
    mods = _state_services()
    if mods is None:
        return "fail", "modules/state.json unreadable", None
    marks = _read_marks()
    problems = []
    for n, mark in sorted(marks.items()):
        if mark is None:
            problems.append("%s: not a generated site" % n)
        elif mark[4] != fqdn:
            problems.append("%s: generated for %s" % (n, mark[4]))
        elif n in EXTRA_SITES:
            if mark[1] != "static" or n != {"mirror": MIRROR_SITE, "feeds": FEEDS_SITE}.get(mark[0]):
                problems.append("%s: does not match its file name" % n)
        elif n != CATCHALL and n != "module-%s.conf" % mark[0]:
            problems.append("%s: does not match its file name" % n)
        elif n != CATCHALL and mark[0] not in mods:
            problems.append("%s: module %s not installed" % (n, mark[0]))
    for sid, mod in sorted(mods.items(), key=lambda kv: str(kv[0])):
        _check_module(sid, mod, marks, fqdn, problems)
    if (mods or marks) and CATCHALL not in marks:
        problems.append("catch-all site missing")
    details = {"sites": len(marks), "services": len(mods)}
    if problems:
        details["problems"] = problems[:20]
        return "fail", "; ".join(problems[:5])[:500], details
    mod_sites = len([n for n in marks if n not in EXTRA_SITES]) - 1
    if not marks:
        return "pass", "no module site yet", details
    return "pass", "%d module site(s) consistent with installed modules" % mod_sites, details
