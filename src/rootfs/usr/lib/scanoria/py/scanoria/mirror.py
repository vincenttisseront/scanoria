# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Vincent Tisseront
"""Appliance miroir (F17, chantier A de la 0.6).

Côté appliance connectée (publication) : après chaque export, le dernier lot
signé est servi découpé, en lecture seule, sous https://mirror.<nom>/v1/ :
manifest.json, manifest.json.sig puis chaque fichier à son chemin dans le lot
(catalog/…, feeds/<id>.tar, images/…, testbeds/…). Choix d'un nom plutôt que
d'un chemin de la console : le point de miroir n'a ni session ni cookie de la
console, il est servi directement par nginx depuis le disque (aucun code de la
console sur ce chemin), et le certificat générique *.<nom> le couvre déjà, de
même que l'enregistrement DNS générique (§ 3.4). Il est joignable depuis les
réseaux d'administration, comme la console. Fichiers 0644 sous
/var/lib/scanoria-mirror (hors de /var/lib/scanoria, que nginx ne traverse
pas) : leur contenu est public (catalogue, images publiques, bases publiques).

Côté appliance hors ligne (client, demande set-mirror) : l'administrateur
déclare l'adresse du miroir et l'empreinte de la clé attendue, qui doit déjà
être dans le magasin des clés de confiance (trust-key). Le helper :
  - valide l'adresse (https seulement, sans chemin), résout lui-même le nom et
    refuse toute adresse de bouclage, de lien local, réservée ou de
    l'appliance (mêmes règles que le connecteur IA) ;
  - épingle les adresses dans /etc/scanoria/mirror.json et charge la table
    nftables « inet scanoria_mirror » : sortie vers ces adresses et ce port
    seulement, pour l'UID de scanoria-mirror seulement (meta skuid) ;
  - télécharge toujours comme scanoria-mirror (runuser), avec curl
    --resolve vers une adresse épinglée : un changement de résolution
    n'élargit jamais la règle ;
  - vérifie tout comme un lot (signature par la clé déclarée, index officiel,
    SHA-256, empreintes d'images) avant la moindre bascule.
Une fois le miroir déclaré, refresh-catalog et refresh-feeds passent par lui,
et l'installation d'un module y prend l'image et le banc d'essai qui manquent.
"""

import ipaddress
import os
import re
import secrets
import shutil
import stat

from . import aiendpoint, bundle, common, offline, schema
from .common import Fail, set_step

CONF = common.ETC + "/mirror.json"
CA_FILE = common.ETC + "/mirror-ca.pem"
NFT_FILE = common.ETC + "/nftables/mirror.nft"
STAGE = common.VARLIB + "/mirror-client"
TABLE = "scanoria_mirror"
USER = "scanoria-mirror"
PUBLIC = common.p("/var/lib/scanoria-mirror")
CURRENT = PUBLIC + "/v1"
URL_RE = re.compile(r"https://([a-z0-9.-]{1,253}|\[[0-9a-f:.]{2,45}\])(?::([0-9]{1,5}))?/?\Z", re.ASCII)
MAX_ADDRESSES = 8
DISABLED = {"version": 1, "enabled": False}
SNAP_RE = re.compile(r"\.snap-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}\Z", re.ASCII)


# --------------------------------------------------------------------------
# Configuration du client
# --------------------------------------------------------------------------

def parse_url(url):
    if not isinstance(url, str) or url != url.strip().lower():
        raise Fail("E_MIRROR_URL", "mirror address must be https://host[:port] in lower case")
    m = URL_RE.match(url)
    if not m:
        raise Fail("E_MIRROR_URL", "mirror address must be https://host[:port], without path")
    host, port = m.group(1), int(m.group(2) or 443)
    if not 1 <= port <= 65535:
        raise Fail("E_MIRROR_URL", "invalid port")
    literal = None
    if host.startswith("["):
        try:
            literal = ipaddress.ip_address(host[1:-1])
        except ValueError:
            raise Fail("E_MIRROR_URL", "invalid IPv6 literal")
        host = str(literal)
    else:
        try:
            literal = ipaddress.ip_address(host)
        except ValueError:
            literal = None
        if literal is not None and str(literal) != host:
            raise Fail("E_MIRROR_URL", "IP address must be in canonical form")
    from . import netutil
    if literal is None and not netutil.check_fqdn(host):
        raise Fail("E_MIRROR_URL", "host must be a fully qualified name or an IP address")
    return host, port, literal


def resolve(host, literal):
    try:
        return aiendpoint.resolve(host, literal)
    except Fail as e:
        code = {"E_AI_UNRESOLVED": "E_MIRROR_UNRESOLVED", "E_AI_FORBIDDEN_ADDRESS": "E_MIRROR_FORBIDDEN_ADDRESS"}
        raise Fail(code.get(e.code, e.code), e.message.replace("server", "mirror"), e.output)


def load_conf():
    try:
        conf = common.load_json_file(CONF, 64 << 10)
    except (OSError, common.JsonError):
        return dict(DISABLED)
    if not schema.load("schemas", "mirror-config").valid(conf):
        common.log("mirror.json does not match its schema: mirror treated as disabled")
        return dict(DISABLED)
    return conf


def configured():
    return bool(load_conf().get("enabled"))


def mirror_uid():
    if common.TEST_ROOT:
        v = os.environ.get("SCANORIA_TEST_MIRROR_UID", "")
        return int(v) if v.isdigit() else 64991
    import pwd
    return pwd.getpwnam(USER).pw_uid


def render_nft(conf, uid):
    lines = ["# Généré par scanoria-helper (set-mirror) : ne pas modifier.",
             "table inet %s" % TABLE, "delete table inet %s" % TABLE, "table inet %s {" % TABLE,
             "\tchain output {", "\t\ttype filter hook output priority filter; policy accept;"]
    if conf.get("enabled"):
        v4 = [a for a in conf["addresses"] if ":" not in a]
        v6 = [a for a in conf["addresses"] if ":" in a]
        if v4:
            lines.append("\t\tmeta skuid %d ip daddr { %s } tcp dport %d accept" % (uid, ", ".join(v4), conf["port"]))
        if v6:
            lines.append("\t\tmeta skuid %d ip6 daddr { %s } tcp dport %d accept" % (uid, ", ".join(v6), conf["port"]))
    lines += ["\t\tmeta skuid %d counter reject" % uid, "\t}", "}", ""]
    return "\n".join(lines)


def apply_nft(conf):
    text = render_nft(conf, mirror_uid())
    os.makedirs(os.path.dirname(NFT_FILE), mode=0o700, exist_ok=True)
    tmp = NFT_FILE + ".new"
    common.atomic_write(tmp, text, 0o600, group_scanoria=False)
    try:
        if common.run("nft", ["-c", "-f", tmp], timeout=60).returncode != 0:
            raise Fail("E_INTERNAL", "mirror ruleset rejected by nft -c")
        if common.run("nft", ["-f", tmp], timeout=60).returncode != 0:
            raise Fail("E_INTERNAL", "mirror ruleset could not be loaded")
        os.rename(tmp, NFT_FILE)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def _restore(previous, previous_ca):
    common.write_json(CONF, previous)
    if previous_ca is not None:
        common.atomic_write(CA_FILE, previous_ca, 0o640)
    elif os.path.exists(CA_FILE):
        os.unlink(CA_FILE)
    try:
        apply_nft(previous)
    except Fail:
        apply_nft(DISABLED)


def act_set_mirror(c):
    prm = c.params
    previous = load_conf()
    if not prm["enabled"]:
        common.write_json(CONF, dict(DISABLED))
        apply_nft(DISABLED)
        if os.path.exists(CA_FILE):
            os.unlink(CA_FILE)
        offline.publish_status()
        return {"enabled": False, "previous_url": previous.get("url")}
    host, port, literal = parse_url(prm["url"])
    fp = prm["fingerprint"]
    if offline.trusted_key(fp) is None:
        raise Fail("E_MIRROR_UNTRUSTED", "add the mirror key to the trusted keys first", {"fingerprint": fp})
    ca = prm.get("ca_pem")
    if ca is not None:
        try:
            aiendpoint.check_ca(ca)
        except Fail as e:
            raise Fail("E_MIRROR_CA", e.message)
    set_step("pin")
    addresses = resolve(host, literal)
    conf = {"version": 1, "enabled": True, "url": prm["url"].rstrip("/"), "host": host, "port": port,
            "addresses": addresses, "literal": literal is not None, "fingerprint": fp, "ca": ca is not None,
            "pinned_at": common.iso(common.now())}
    if not schema.load("schemas", "mirror-config").valid(conf):
        raise Fail("E_INTERNAL", "pinned mirror configuration does not match its schema")
    previous_ca = None
    if os.path.isfile(CA_FILE):
        with open(CA_FILE, "rb") as f:
            previous_ca = f.read(65536)
    set_step("firewall")
    if ca is not None:
        common.atomic_write(CA_FILE, ca.encode("ascii"), 0o640)
    elif os.path.exists(CA_FILE):
        os.unlink(CA_FILE)
    common.write_json(CONF, conf)
    try:
        apply_nft(conf)
        set_step("mirror-check")
        man, _ = fetch_manifest(conf, timeout=min(120, c.left()))
    except Fail:
        _restore(previous, previous_ca)
        offline.publish_status()
        raise
    write_check(conf, man, None)
    offline.publish_status()
    return {"enabled": True, "url": conf["url"], "host": host, "port": port, "addresses": addresses,
            "fingerprint": fp, "manifest": summary(man)}


# --------------------------------------------------------------------------
# Téléchargements (UID scanoria-mirror, adresse épinglée)
# --------------------------------------------------------------------------

CHECK_FILE = common.VARLIB + "/offline/mirror-check.json"


def summary(man):
    return {"created_at": man["created_at"], "catalog_version": man["catalog"]["version"],
            "feeds": [{"id": f["id"], "updated_at": f["updated_at"]} for f in man["feeds"]],
            "images": [i["module"] for i in man["images"]]}


def write_check(conf, man, error):
    common.shared_dir(offline.OFFLINE_DIR)
    common.write_json(CHECK_FILE, {"checked_at": common.iso(common.now()), "url": conf.get("url"),
                                   "manifest": summary(man) if man else None, "error": error})


def _stage_dir():
    os.makedirs(STAGE, mode=0o711, exist_ok=True)
    os.chmod(STAGE, 0o711)
    d = os.path.join(STAGE, secrets.token_hex(8))
    os.mkdir(d, 0o700)
    if not common.TEST_ROOT:
        os.chown(d, mirror_uid(), mirror_uid())
    return d


def fetch(conf, rel, dest, limit, timeout):
    """Télécharge <url>/v1/<rel> dans dest (root) ; retourne (sha256, taille)."""
    if rel not in ("manifest.json", "manifest.json.sig") and not bundle.declared_path_ok(rel):
        raise Fail("E_MIRROR_UNREACHABLE", "invalid mirror path")
    d = _stage_dir()
    try:
        out = os.path.join(d, "file")
        host = conf["host"] if not conf.get("literal") else conf["addresses"][0]
        addr = conf["addresses"][0]
        url = "https://%s:%d/v1/%s" % ("[%s]" % host if ":" in host else host, conf["port"], rel)
        args = ["-u", USER, "--", common.SYSTEM_CMDS["curl"], "--proto", "=https", "--tlsv1.2", "--silent",
                "--connect-timeout", "20", "--max-time", str(max(10, int(timeout))),
                "--max-filesize", str(limit), "--max-redirs", "0", "--noproxy", "*",
                "--output", out, "--write-out", "%{http_code}"]
        if not conf.get("literal"):
            # Nom épinglé sur l'adresse approuvée ; une adresse littérale est déjà dans l'URL.
            args[-4:-4] = ["--resolve", "%s:%d:%s" % (host, conf["port"], "[%s]" % addr if ":" in addr else addr)]
        if conf.get("ca"):
            args += ["--cacert", CA_FILE]
        args.append(url)
        r = common.run("runuser", args, timeout=int(timeout) + 60)
        code = r.text.strip()[-3:]
        if r.returncode != 0 or code != "200":
            raise Fail("E_MIRROR_UNREACHABLE", "mirror did not serve %s (%s)" % (
                rel, "HTTP " + code if code.isdigit() and code != "000" else "curl %d" % r.returncode),
                {"path": rel})
        try:
            fd = os.open(out, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        except OSError:
            raise Fail("E_MIRROR_UNREACHABLE", "mirror download of %s missing" % rel)
        with os.fdopen(fd, "rb") as f:
            st = os.fstat(f.fileno())
            if not stat.S_ISREG(st.st_mode) or st.st_size > limit:
                raise Fail("E_MIRROR_UNREACHABLE", "mirror served an unexpected %s" % rel)
            os.set_blocking(f.fileno(), True)
            os.makedirs(os.path.dirname(dest), mode=0o700, exist_ok=True)
            return bundle._hash_copy(f, dest, limit)
    finally:
        shutil.rmtree(d, ignore_errors=True)


def fetch_manifest(conf, timeout=120):
    work = bundle._new_work("mcheck")
    try:
        fetch(conf, "manifest.json", os.path.join(work, "m"), bundle.MAX_MANIFEST, timeout)
        fetch(conf, "manifest.json.sig", os.path.join(work, "s"), bundle.MAX_SIG, timeout)
        with open(os.path.join(work, "m"), "rb") as f:
            raw = f.read(bundle.MAX_MANIFEST + 1)
        with open(os.path.join(work, "s"), "rb") as f:
            sig = f.read(bundle.MAX_SIG + 1)
        return bundle.read_signed_manifest(raw, sig, expected_fp=conf["fingerprint"])
    finally:
        shutil.rmtree(work, ignore_errors=True)


def sync(sel, timeout):
    """Télécharge depuis le miroir ce que sel désigne, vérifie tout, puis applique."""
    from . import feeds
    conf = load_conf()
    if not conf.get("enabled"):
        raise Fail("E_PRECONDITION", "no mirror declared")
    deadline = feeds.Deadline(timeout)
    try:
        set_step("mirror-manifest")
        man, declared = fetch_manifest(conf, timeout=min(120, deadline.left()))
    except Fail as e:
        write_check(conf, None, e.message)
        raise
    work = bundle._new_work("mirror")
    try:
        wanted = list(bundle.CATALOG_FILES)
        wanted += [t["path"] for t in man["testbeds"] if sel.has("testbed", t["module"])]
        wanted += [f["path"] for f in man["feeds"] if sel.has("feed", f["id"])]
        wanted += [i["path"] for i in man["images"] if sel.has("image", i["module"])]
        for rel in wanted:
            set_step("mirror-download")
            sha, size = fetch(conf, rel, os.path.join(work, rel), declared[rel][1], deadline.left())
            if (sha, size) != declared[rel]:
                raise Fail("E_BUNDLE_CHECKSUM", "mirror file %s does not match the signed manifest" % rel)
        plan = bundle.verify_staged(work, man, sel, deadline)
        out = bundle.apply_plan(plan, man, work, deadline.left)
        write_check(conf, man, None)
        return man, out
    finally:
        shutil.rmtree(work, ignore_errors=True)


def refresh_catalog(timeout=300):
    from . import catalogverify
    before = catalogverify.installed_number()
    man, out = sync(bundle.Selection(feeds_ids=set(), images=set(), testbeds=set()), timeout)
    idx = catalogverify.installed_index() or {}
    n = catalogverify.installed_number()
    return {"version": n, "previous": before or None, "changed": n != before,
            "modules": len(idx.get("modules") or []), "packs": len(idx.get("packs") or []), "source": "mirror"}


def refresh_feed(m, timeout):
    from . import feeds
    mid = m["id"]
    conf = load_conf()
    try:
        man, _ = fetch_manifest(conf, timeout=min(120, timeout))
        if not any(f["id"] == mid for f in man["feeds"]):
            raise Fail("E_FEED_UNAVAILABLE", "the mirror has no database %s" % mid, {"feed": mid})
        sync(bundle.Selection(feeds_ids={mid}, images=set(), testbeds=set()), timeout)
    except Fail as e:
        prev = feeds.read_status(mid) or {}
        st = dict(prev, checked_at=common.iso(common.now()), error=e.message[:500],
                  status="stale" if feeds.has_data(mid) else "failed")
        feeds.write_status(mid, st)
        if e.code == "E_FEED_UNAVAILABLE":
            raise
        raise Fail("E_FEED_UNAVAILABLE", "database %s cannot be updated from the mirror (%s)" % (mid, e.message),
                   {"feed": mid, "host": conf.get("host"), "reason": e.message[:500]})
    return feeds.public_status(mid)


def fetch_image(m, timeout):
    """Image du module m prise sur le miroir ; False si aucun miroir ou image absente."""
    if not configured():
        return False
    conf = load_conf()
    man, _ = fetch_manifest(conf, timeout=min(120, timeout))
    digest = bundle.image_ref(m["image"])[1]
    if not any(i["module"] == m["id"] and i["digest"] == digest for i in man["images"]):
        return False
    sync(bundle.Selection(feeds_ids=set(), images={m["id"]}, testbeds=set()), timeout)
    return True


def fetch_testbed(m, timeout=300):
    """Banc d'essai du module m pris sur le miroir (rangé dans catalog/testbeds) ; False sinon."""
    if not configured():
        return False
    sync(bundle.Selection(feeds_ids=set(), images=set(), testbeds={m["id"]}), timeout)
    return os.path.isfile(os.path.join(bundle.TESTBEDS, m["testbed_archive"]))


def client_status():
    conf = load_conf()
    if not conf.get("enabled"):
        return None
    try:
        chk = common.load_json_file(CHECK_FILE, 1 << 20)
    except (OSError, common.JsonError):
        chk = None
    return {"url": conf["url"], "addresses": conf["addresses"], "fingerprint": conf["fingerprint"],
            "pinned_at": conf["pinned_at"], "ca": conf["ca"],
            "last_check": chk if isinstance(chk, dict) else None}


# --------------------------------------------------------------------------
# Publication (appliance connectée)
# --------------------------------------------------------------------------

def _public_tree(root):
    for base, dirs, files in os.walk(root):
        os.chmod(base, 0o755)
        if not common.TEST_ROOT:
            os.chown(base, 0, 0)
        for n in files:
            p = os.path.join(base, n)
            if os.path.islink(p) or not os.path.isfile(p):
                os.unlink(p)
                continue
            os.chmod(p, 0o644)
            if not common.TEST_ROOT:
                os.chown(p, 0, 0)


def publish(work):
    """Le répertoire de travail d'un export devient le contenu servi (déplacé, sans copie)."""
    os.makedirs(PUBLIC, mode=0o755, exist_ok=True)
    os.chmod(PUBLIC, 0o755)
    for n in os.listdir(work):
        if n not in ("manifest.json", "manifest.json.sig", "catalog", "testbeds", "feeds", "images"):
            p = os.path.join(work, n)
            shutil.rmtree(p, ignore_errors=True) if os.path.isdir(p) and not os.path.islink(p) else os.unlink(p)
    snap = os.path.join(PUBLIC, ".snap-%s-%s" % (common.now().strftime("%Y%m%dT%H%M%SZ"), secrets.token_hex(4)))
    os.rename(work, snap)
    _public_tree(snap)
    tmp = os.path.join(PUBLIC, ".v1.%s" % secrets.token_hex(4))
    os.symlink(os.path.basename(snap), tmp)
    os.replace(tmp, CURRENT)
    for n in os.listdir(PUBLIC):
        if SNAP_RE.match(n) and n != os.path.basename(snap):
            shutil.rmtree(os.path.join(PUBLIC, n), ignore_errors=True)
    ensure_site()
    return snap


def ensure_site():
    """Site nginx mirror.<nom> (routing.render l'ajoute dès qu'un lot est publié)."""
    from . import modules
    try:
        modules.route(modules.load_registry())
    except Fail as e:
        common.log("mirror site not applied: %s" % e.message)


def published():
    return os.path.isfile(os.path.join(CURRENT, "manifest.json"))


def publication_status():
    if not published():
        return None
    try:
        man = common.load_json_file(os.path.join(CURRENT, "manifest.json"), bundle.MAX_MANIFEST)
    except (OSError, common.JsonError):
        return None
    from . import routing
    fqdn = routing.appliance_fqdn()
    return {"url": "https://mirror.%s" % fqdn if fqdn else None, "created_at": man.get("created_at"),
            "catalog_version": (man.get("catalog") or {}).get("version"),
            "feeds": [f.get("id") for f in man.get("feeds") or []],
            "images": [i.get("module") for i in man.get("images") or []]}
