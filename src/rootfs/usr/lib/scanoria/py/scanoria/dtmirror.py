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
   sur le port PORT, joignable depuis les seuls réseaux des modules (pare-feu
   et allow nginx) :
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
import json
import os
import secrets
import shutil

from . import common
from .common import Fail

DT_ID = "dependency-track"
ROOT = common.p("/var/lib/scanoria-feeds-mirror")
PORT = 9790
NFT_FILE = common.ETC + "/nftables/svc-egress.nft"
TABLE = "scanoria_svc_egress"
STATUS = common.VARLIB + "/offline/dtrack-sources.json"
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
    lines += ["\t}", "}", ""]
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


def properties(gw, sources):
    osv = next((s for s in sources if s["id"] == "osv"), {})
    epss = next((s for s in sources if s["id"] == "epss"), {})
    base = "http://%s:%d" % (gw, PORT)
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
            code, _, _ = http.call("POST", "api/v1/configProperty/aggregate", body=properties(gw, st["sources"]),
                                   jwt=jwt)
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
