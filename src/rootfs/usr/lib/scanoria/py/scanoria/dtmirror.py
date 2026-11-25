# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Vincent Tisseront
"""Dependency-Track hors ligne et sortie fermée des services (chantier A de la 0.6).

Jusqu'à la 0.5, Dependency-Track tenait ses propres miroirs de vulnérabilités
par la passerelle de Podman, sans filtrage. Désormais :

1. Sortie fermée. La table nftables « inet scanoria_svc_egress » rejette, au
   crochet forward, tout ce qui sort du sous-réseau d'un module permanent qui
   ne déclare aucun hôte dans service.egress (cas de Dependency-Track depuis
   la 0.6). Le trafic vers l'appliance elle-même (PostgreSQL, miroir local des
   bases) passe par le crochet input et n'est pas touché. Fichier
   /etc/scanoria/nftables/svc-egress.nft, rechargé au démarrage par
   scanoria-firewall.

2. Bases servies par l'appliance. Les bases des modules feed déjà tenues à
   jour par le helper (téléchargement, lot signé ou miroir F17) sont recopiées,
   en lecture seule, sous /var/lib/scanoria-feeds-mirror et servies par nginx
   en HTTPS sur le port PORT, sous le nom feeds.<nom de l'appliance>
   (certificat de l'AC interne, scanoria-ca issue-feeds), joignable depuis le
   seul réseau de Dependency-Track (règle d'entrée de la table ci-dessus et
   allow nginx). Le conteneur résout ce nom vers la passerelle de son réseau
   (AddHost) et fait confiance à l'AC interne par son magasin Java : copie du
   cacerts de son image, AC ajoutée par le keytool de cette même image, monté
   en lecture seule par un secret Podman (truststore) :
     /osv/<écosystème>/all.zip          base osv-db (mêmes fichiers qu'OSV) ;
     /osv/<écosystème>/modified_id.csv  vide : Dependency-Track ne fait alors
                                        aucune mise à jour incrémentale et
                                        relit all.zip à chaque miroir complet,
                                        tous les 5 jours (comportement amont) ;
     /epss/epss_scores-current.csv.gz   base epss, au format de FIRST.
   La mise en service (dtrack.py) règle Dependency-Track sur ces adresses
   (google.osv.base.url, google.osv.enabled, epss.feeds.url).

3. Sources qui ne peuvent pas être servies, coupées et signalées dans la
   console comme trous de couverture (SOURCES) :
     nvd         aucune base NVD dans l'appliance (OSV couvre les écosystèmes
                 de paquets des SBOM ; la correspondance par CPE manque) ;
     ghsa        GitHub Advisories exige un jeton GitHub (API GraphQL) ; ces
                 avis arrivent quand même par OSV (identifiants GHSA-) ;
     ossindex    service en ligne de Sonatype, avec compte ;
     repositories  métadonnées des registres de paquets (dernière version
                 d'un composant) : interrogation en ligne, sans équivalent
                 hors ligne.
"""

import gzip
import hashlib
import json
import os
import re
import secrets
import shutil
import ssl
import tempfile

from . import common
from .common import Fail

DT_ID = "dependency-track"
ROOT = common.p("/var/lib/scanoria-feeds-mirror")
PORT = 9790
NFT_FILE = common.ETC + "/nftables/svc-egress.nft"
TABLE = "scanoria_svc_egress"
STATUS = common.VARLIB + "/offline/dtrack-sources.json"
FEEDS_LABEL = "feeds"
CA_CERT = common.ETC + "/pki/ca/ca.crt"
TRUST_SECRET = "truststore"
TRUST_ALIAS = "scanoria-appliance-ca"
MAX_TRUSTSTORE = 400 << 10          # sous la limite des secrets Podman (512 Kio)
JAVA_HOME_RE = re.compile(r"/[A-Za-z0-9._/-]{1,120}\Z")
# Magasin Java de l'image + AC interne, par le keytool de l'image elle-même
# (même format et même version de Java que Dependency-Track). « changeit » est
# le mot de passe public, documenté, du cacerts des JDK : le magasin ne
# contient que des certificats publics.
TRUST_SCRIPT = (
    'set -eu; cp "$JAVA_HOME/lib/security/cacerts" /out/cacerts; '
    'keytool -importcert -noprompt -keystore /out/cacerts -storepass changeit '
    '-alias %(alias)s -file /in/ca.crt > /dev/null 2>&1; '
    'keytool -list -v -keystore /out/cacerts -storepass changeit -alias %(alias)s > /out/list.txt; '
    'printf %%s "$JAVA_HOME" > /out/java_home' % {"alias": TRUST_ALIAS})
GAPS = (
    {"id": "nvd", "reason": "no-feed"},
    {"id": "ghsa", "reason": "token-required"},
    {"id": "ossindex", "reason": "online-service"},
    {"id": "repositories", "reason": "online-service"},
)


def _registry():
    from . import modules
    try:
        return modules.load_registry()
    except Fail:
        return {"modules": {}}


def dt_installed(reg=None):
    return DT_ID in (reg or _registry())["modules"]


def gateway(reg=None):
    from . import services
    e = (reg or _registry())["modules"].get(DT_ID) or {}
    return services.gateway(e["subnet"]) if isinstance(e.get("subnet"), int) else None


def dt_subnet(reg=None):
    """Réseau de Dependency-Track (seul autorisé à joindre le miroir), ou None."""
    from . import services
    e = (reg or _registry())["modules"].get(DT_ID) or {}
    return str(services.subnet(e["subnet"])) if isinstance(e.get("subnet"), int) else None


def feeds_host(fqdn):
    return "%s.%s" % (FEEDS_LABEL, fqdn)


def _fqdn():
    from . import routing
    fqdn = routing.appliance_fqdn()
    if fqdn is None:
        raise Fail("E_PRECONDITION", "appliance name not set")
    return fqdn


# --------------------------------------------------------------------------
# TLS du miroir : certificat de l'AC interne et magasin Java du conteneur
# --------------------------------------------------------------------------

def ensure_tls(timeout=120):
    """Certificat feeds.<nom> émis ou renouvelé par l'AC interne (scanoria-ca)."""
    out, _ = common.run_protocol("scanoria-ca", ["issue-feeds", "--fqdn", _fqdn()], timeout=timeout)
    return out


def _ca_sha256():
    try:
        with open(CA_CERT, encoding="ascii") as f:
            der = ssl.PEM_cert_to_DER_cert(f.read(64 << 10))
    except (OSError, ValueError, UnicodeDecodeError):
        raise Fail("E_PRECONDITION", "internal CA missing")
    return hashlib.sha256(der).hexdigest()


def _trust_meta_path(mid):
    from . import services
    return os.path.join(services.secrets_dir(mid), TRUST_SECRET + ".json")


def _read_trust_meta(mid):
    try:
        meta = common.load_json_file(_trust_meta_path(mid), 1 << 16)
    except (OSError, common.JsonError):
        return None
    return meta if isinstance(meta, dict) else None


def _listed_sha256(text):
    m = re.search(r"SHA256:\s*([0-9A-Fa-f:]{95})", text)
    return m.group(1).replace(":", "").lower() if m else None


def build_truststore(m, timeout=600):
    """Construit le magasin Java (si l'AC ou l'image ont changé) ; True s'il a été refait."""
    from . import services
    mid = m["id"]
    want = {"ca_sha256": _ca_sha256(), "image": m["image"]}
    meta = _read_trust_meta(mid) or {}
    path = services.secret_path(mid, TRUST_SECRET)
    if all(meta.get(k) == v for k, v in want.items()) and JAVA_HOME_RE.match(str(meta.get("java_home"))) \
            and os.path.isfile(path) and not os.path.islink(path):
        return False
    os.makedirs(services.secrets_dir(mid), mode=0o700, exist_ok=True)
    work = tempfile.mkdtemp(prefix=".truststore-", dir=services.module_dir(mid))
    try:
        indir, outdir = os.path.join(work, "in"), os.path.join(work, "out")
        os.mkdir(indir, 0o700)
        os.mkdir(outdir, 0o700)
        shutil.copyfile(CA_CERT, os.path.join(indir, "ca.crt"))
        r = common.run("podman", [
            "run", "--rm", "--pull=never", "--network=none", "--read-only", "--cap-drop=ALL",
            "--security-opt=no-new-privileges", "--user", "0:0", "--memory=512m", "--pids-limit=256",
            "--entrypoint", "/bin/sh", "-v", indir + ":/in:ro", "-v", outdir + ":/out",
            m["image"], "-c", TRUST_SCRIPT], timeout=timeout, stderr_tail=400)
        if r.returncode != 0:
            raise Fail("E_INTERNAL", "Java trust store of %s could not be built (%s)" % (
                mid, (r.stderr or b"").decode("utf-8", "replace").strip()[-200:] or "podman %d" % r.returncode))
        store = os.path.join(outdir, "cacerts")
        with open(os.path.join(outdir, "java_home"), encoding="ascii") as f:
            java_home = f.read(200)
        with open(os.path.join(outdir, "list.txt"), encoding="utf-8", errors="replace") as f:
            listed = _listed_sha256(f.read(64 << 10))
        if not JAVA_HOME_RE.match(java_home) or ".." in java_home.split("/"):
            raise Fail("E_INTERNAL", "unexpected JAVA_HOME in the image of %s" % mid)
        if listed != want["ca_sha256"]:
            raise Fail("E_INTERNAL", "internal CA not found in the trust store of %s" % mid)
        if os.path.islink(store) or not os.path.isfile(store) or not 0 < os.path.getsize(store) <= MAX_TRUSTSTORE:
            raise Fail("E_INTERNAL", "unexpected trust store size for %s" % mid)
        with open(store, "rb") as f:
            common.atomic_write(path, f.read(), 0o600, group_scanoria=False)
    except (OSError, UnicodeDecodeError) as e:
        raise Fail("E_INTERNAL", "Java trust store of %s could not be built (%s)" % (mid, e.__class__.__name__))
    finally:
        shutil.rmtree(work, ignore_errors=True)
    common.write_json(_trust_meta_path(mid), dict(want, java_home=java_home, built_at=common.iso(common.now())),
                      0o600)
    return True


def register_truststore(m):
    from . import services
    mid = m["id"]
    name = services.podman_secret(mid, TRUST_SECRET)
    common.run("podman", ["secret", "rm", name], timeout=120)
    if common.run("podman", ["secret", "create", name, services.secret_path(mid, TRUST_SECRET)],
                  timeout=120).returncode != 0:
        raise Fail("E_INTERNAL", "podman secret of %s could not be created" % mid)


def unregister_truststore(m):
    from . import services
    if m.get("id") == DT_ID:
        common.run("podman", ["secret", "rm", services.podman_secret(DT_ID, TRUST_SECRET)], timeout=120)


def unit_extras(m, entry, timeout=600):
    """Pour Dependency-Track (avant d'écrire ses unités) : certificat du miroir,
    magasin Java monté en lecture seule et nom du miroir vers la passerelle.
    Autres modules : rien. Retourne {trust: (secret, cible), hosts: [(nom, ip)]}."""
    from . import services
    if m.get("id") != DT_ID:
        return {}
    if not isinstance(entry.get("subnet"), int):
        raise Fail("E_INTERNAL", "Dependency-Track has no module network")
    ensure_tls()
    build_truststore(m, timeout=timeout)
    register_truststore(m)
    java_home = (_read_trust_meta(m["id"]) or {}).get("java_home")
    return {"trust": (services.podman_secret(m["id"], TRUST_SECRET), java_home + "/lib/security/cacerts"),
            "hosts": [(feeds_host(_fqdn()), str(services.gateway(entry["subnet"])))]}


def refresh_tls(reg=None, timeout=600):
    """Renouvellement (cert-renew) et changement d'AC : certificat refait au besoin ;
    magasin reconstruit et Dependency-Track redémarré si l'AC a changé."""
    reg = reg or _registry()
    e = reg["modules"].get(DT_ID)
    if not e:
        return None
    out = ensure_tls()
    m = e.get("manifest") or {}
    if m.get("image") and build_truststore(dict(m, id=DT_ID), timeout=timeout):
        register_truststore(dict(m, id=DT_ID))
        common.run("systemctl", ["try-restart", "scanoria-mod-%s.service" % DT_ID], timeout=300)
    return out


# --------------------------------------------------------------------------
# Sortie des modules permanents
# --------------------------------------------------------------------------

def render_egress(reg):
    from . import services
    lines = ["# Généré par scanoria-helper : sortie fermée des modules permanents (0.6).",
             "table inet %s" % TABLE, "delete table inet %s" % TABLE, "table inet %s {" % TABLE,
             "\tchain forward {", "\t\ttype filter hook forward priority filter - 4; policy accept;"]
    closed = []
    for mid, e in sorted(reg["modules"].items()):
        m = e.get("manifest") or {}
        if m.get("type") not in ("service", "runner") or not isinstance(e.get("subnet"), int):
            continue
        if (m.get("service") or {}).get("egress"):
            continue
        lines.append("\t\tip saddr %s counter reject" % services.subnet(e["subnet"]))
        closed.append(mid)
    lines.append("\t}")
    # Miroir des bases (PORT) : réservé au réseau de Dependency-Track ; tout
    # autre réseau de module est rejeté avant nginx (qui le refuse aussi).
    dt = dt_subnet(reg)
    lines += ["\tchain input {", "\t\ttype filter hook input priority filter - 4; policy accept;",
              ("\t\tiifname \"podman*\" tcp dport %d ip saddr != %s counter drop" % (PORT, dt)) if dt
              else ("\t\tiifname \"podman*\" tcp dport %d counter drop" % PORT),
              "\t}", "}", ""]
    return "\n".join(lines), closed


def apply_egress(reg):
    """Recharge la table de sortie (appelé à chaque changement des modules permanents)."""
    text, closed = render_egress(reg)
    os.makedirs(os.path.dirname(NFT_FILE), mode=0o700, exist_ok=True)
    tmp = NFT_FILE + ".new"
    common.atomic_write(tmp, text, 0o600, group_scanoria=False)
    try:
        if common.run("nft", ["-c", "-f", tmp], timeout=60).returncode != 0 or \
                common.run("nft", ["-f", tmp], timeout=60).returncode != 0:
            raise Fail("E_INTERNAL", "egress ruleset of the modules could not be loaded")
        os.rename(tmp, NFT_FILE)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)
    return closed


# --------------------------------------------------------------------------
# Bases servies à Dependency-Track
# --------------------------------------------------------------------------

def _publish_file(src_open, rel):
    """Écrit ROOT/rel de façon atomique (0644) depuis un flux."""
    dst = os.path.join(ROOT, rel)
    _web_dirs(os.path.dirname(dst))
    tmp = "%s.%s.tmp" % (dst, secrets.token_hex(4))
    with src_open() as src, open(tmp, "wb") as out:
        shutil.copyfileobj(src, out, 1 << 20)
    common.web_readable(tmp)
    os.replace(tmp, dst)


def _web_dirs(path):
    """Répertoires de ROOT jusqu'à path, lisibles par nginx seulement (root:www-data 0750)."""
    os.makedirs(path, mode=0o750, exist_ok=True)
    while True:
        common.web_readable(path, directory=True)
        if os.path.abspath(path) == os.path.abspath(ROOT):
            break
        path = os.path.dirname(path)


def sync_osv():
    from . import feeds
    base = os.path.join(feeds.link_path("osv-db"), "osv-scalibr")
    ecos = []
    if feeds.has_data("osv-db") and os.path.isdir(base):
        for eco in sorted(os.listdir(base)):
            z = os.path.join(base, eco, "all.zip")
            if not os.path.isfile(z) or os.path.islink(z):
                continue
            _publish_file(lambda z=z: open(z, "rb"), os.path.join("osv", eco, "all.zip"))
            _publish_file(lambda: open(os.devnull, "rb"), os.path.join("osv", eco, "modified_id.csv"))
            ecos.append(eco)
    keep = set(ecos)
    osv_dir = os.path.join(ROOT, "osv")
    if os.path.isdir(osv_dir):
        for eco in os.listdir(osv_dir):
            if eco not in keep:
                shutil.rmtree(os.path.join(osv_dir, eco), ignore_errors=True)
    st = feeds.read_status("osv-db") or {}
    return {"id": "osv", "available": bool(ecos), "ecosystems": ecos,
            "updated_at": st.get("updated_at") if ecos else None, "reason": None if ecos else "feed-missing"}


def sync_epss():
    from . import feeds
    exp = os.path.join(feeds.link_path("epss"), feeds.EXPORT_FILE)
    if not feeds.has_data("epss") or not os.path.isfile(exp):
        try:
            os.unlink(os.path.join(ROOT, "epss", "epss_scores-current.csv.gz"))
        except FileNotFoundError:
            pass
        return {"id": "epss", "available": False, "ecosystems": [], "updated_at": None, "reason": "feed-missing"}
    st = feeds.read_status("epss") or {}
    det = st.get("details") if isinstance(st.get("details"), dict) else {}
    model = det.get("model_version") if isinstance(det.get("model_version"), str) else "unknown"
    day = det.get("score_date") if isinstance(det.get("score_date"), str) else (st.get("updated_at") or "")[:10]
    dst = os.path.join(ROOT, "epss", "epss_scores-current.csv.gz")
    _web_dirs(os.path.dirname(dst))
    tmp = dst + ".%s.tmp" % secrets.token_hex(4)
    with gzip.open(exp, "rb") as src, gzip.GzipFile(tmp, "wb", mtime=0) as out:
        out.write(("#model_version:%s,score_date:%sT00:00:00+0000\ncve,epss,percentile\n" % (model, day)).encode())
        for line in src:
            row = json.loads(line)
            out.write(("%s,%.5f,%.5f\n" % (row["vuln_id"], row["epss"], row["epss_percentile"])).encode("ascii"))
    common.web_readable(tmp)
    os.replace(tmp, dst)
    return {"id": "epss", "available": True, "ecosystems": [], "updated_at": st.get("updated_at"), "reason": None}


def sync_all():
    """Après toute mise à jour d'une base : recopie pour Dependency-Track s'il est installé."""
    reg = _registry()
    if not dt_installed(reg):
        if os.path.isdir(ROOT):
            shutil.rmtree(ROOT, ignore_errors=True)
        return None
    try:
        _web_dirs(ROOT)
        sources = [sync_osv(), sync_epss()]
    except (OSError, ValueError, KeyError, TypeError) as e:
        common.log("Dependency-Track feed mirror not updated: %r" % e)
        return None
    prev = _read_status() or {}
    st = {"synced_at": common.iso(common.now()), "port": PORT, "sources": sources,
          "gaps": [dict(g) for g in GAPS], "configured_at": prev.get("configured_at"),
          "configure_error": prev.get("configure_error")}
    _write_status(st)
    return st


def _read_status():
    try:
        s = common.load_json_file(STATUS, 1 << 20)
    except (OSError, common.JsonError):
        return None
    return s if isinstance(s, dict) else None


def _write_status(st):
    common.shared_dir(os.path.dirname(STATUS))
    common.write_json(STATUS, st, 0o640)


def status():
    if not dt_installed():
        return None
    return _read_status()


def properties(host, sources):
    osv = next((s for s in sources if s["id"] == "osv"), {})
    epss = next((s for s in sources if s["id"] == "epss"), {})
    base = "https://%s:%d" % (host, PORT)
    props = [
        ("vuln-source", "google.osv.base.url", base + "/osv/"),
        ("vuln-source", "google.osv.enabled", ";".join(osv.get("ecosystems") or [])),
        ("vuln-source", "epss.feeds.url", base + "/epss"),
        ("vuln-source", "epss.enabled", "true" if epss.get("available") else "false"),
        ("vuln-source", "nvd.enabled", "false"),
        ("vuln-source", "nvd.api.enabled", "false"),
        ("vuln-source", "github.advisories.enabled", "false"),
        ("scanner", "ossindex.enabled", "false"),
    ]
    return [{"groupName": g, "propertyName": p, "propertyValue": v} for g, p, v in props]


def configure(http, jwt):
    """Règle Dependency-Track sur les bases de l'appliance (appelé par dtrack.provision).

    Au mieux : un échec est journalisé et affiché dans la console, il ne fait
    pas échouer la mise en service (les analyses de l'appliance n'en dépendent pas)."""
    st = sync_all() or {"sources": [], "gaps": [dict(g) for g in GAPS], "port": PORT}
    gw = gateway()
    error = None
    if gw is None:
        error = "no module network"
    else:
        try:
            code, _, _ = http.call("POST", "api/v1/configProperty/aggregate",
                                   body=properties(feeds_host(_fqdn()), st["sources"]), jwt=jwt)
        except Fail as e:
            code, error = 0, e.message[:200]
        if error is None and code not in (200, 201, 304):
            error = "HTTP %d" % code
    st.update(configured_at=None if error else common.iso(common.now()), configure_error=error,
              synced_at=st.get("synced_at") or common.iso(common.now()))
    _write_status(st)
    if error:
        common.log("Dependency-Track vulnerability sources not configured: %s" % error)
    return error is None
