# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Vincent Tisseront
"""Dates de publication des versions de paquets (H5, quarantaine).

Demande « package-dates » : un lot d'au plus 2 000 purl. Pour chacun, le
helper interroge le registre public de son écosystème en HTTPS (npm, PyPI,
crates.io, proxy Go, Maven Central, RubyGems, NuGet, Packagist) et rend
{"dates": {purl: "AAAA-MM-JJTHH:MM:SSZ" | null}}.

Le helper ne fait confiance à rien :
- chaque purl est analysé strictement (type connu, nom et version au jeu de
  caractères borné) ; un purl hostile ou d'un écosystème inconnu donne null ;
- l'URL est construite ici, composants encodés, vers un hôte fixe par
  écosystème ; aucune redirection n'est suivie (une réponse 3xx donne null) ;
- curl : HTTPS seul, certificat vérifié, taille et délai bornés, proxy de
  /etc/environment s'il existe ; la réponse est lue en JSON strict et seule
  une date bien formée en est retenue ;
- cache root /var/lib/scanoria/cache/package-dates : une date trouvée est
  définitive (une version publiée ne change pas de date), une absence est
  gardée un jour (404 ou réponse inexploitable), une erreur réseau ou une
  erreur passagère du registre (429, 5xx) jamais.
Sans Internet, tout est null : la demande réussit quand même (la console le
signale dans la couverture, G15). Durée bornée : ce qui n'a pas été cherché à
l'échéance, ou en erreur passagère, reste null et compté dans « unfinished » :
la console redépose une demande pour ces purl (deux fois au plus).
"""

import concurrent.futures
import datetime
import hashlib
import json
import os
import re
import shutil
import tempfile
import time
import urllib.parse

from . import common, feeds

CACHE = common.VARLIB + "/cache/package-dates"
MAX_PURLS = 2000
MAX_DOC = {"npm": 32 << 20}          # document complet d'un paquet npm (toutes les versions)
DEFAULT_MAX_DOC = 4 << 20
REQUEST_TIMEOUT = 20
BUDGET_S = 300                       # durée maximale d'une demande
WORKERS = 6
NEGATIVE_TTL = 86400
OFFLINE_AFTER = 3                    # erreurs réseau consécutives avant de conclure « hors ligne »
NETWORK_REASONS = ("proxy unreachable", "host name does not resolve", "connection refused or unreachable",
                   "timed out", "TLS handshake failed")

PURL_RE = re.compile(r"pkg:([a-z][a-z0-9.+-]{0,31})/([^?#@]{1,512})@([^?#@]{1,256})(?:\?[^#]{0,512})?(?:#.{0,256})?\Z")
NAME_PART_RE = re.compile(r"[A-Za-z0-9._~!$*+,;=:@ -]{1,214}\Z")
VERSION_RE = re.compile(r"[A-Za-z0-9.+_~:!-]{1,128}\Z")
DATE_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,9})?(Z|[+-][0-9]{2}:?[0-9]{2})?\Z")

REGISTRIES = {
    "npm": "https://registry.npmjs.org",
    "pypi": "https://pypi.org",
    "cargo": "https://crates.io",
    "golang": "https://proxy.golang.org",
    "maven": "https://search.maven.org",
    "gem": "https://rubygems.org",
    "nuget": "https://api.nuget.org",
    "composer": "https://repo.packagist.org",
}


def _base(kind):
    # Mode test seulement : tous les registres sont servis par un faux serveur local.
    if common.TEST_ROOT and os.environ.get("SCANORIA_TEST_PKGDATES_BASE"):
        return os.environ["SCANORIA_TEST_PKGDATES_BASE"].rstrip("/") + "/" + kind
    return REGISTRIES[kind]


def _q(s):
    return urllib.parse.quote(s, safe="")


def parse_purl(purl):
    """(type, [segments du nom], version) ou None si le purl n'est pas sûr."""
    if not isinstance(purl, str) or len(purl) > 1024:
        return None
    m = PURL_RE.match(purl)
    if not m:
        return None
    kind, path, version = m.group(1), m.group(2), m.group(3)
    if kind not in REGISTRIES:
        return None
    try:
        parts = [urllib.parse.unquote(x, errors="strict") for x in path.split("/")]
        version = urllib.parse.unquote(version, errors="strict")
    except UnicodeDecodeError:
        return None
    if not parts or len(parts) > 8 or any(not NAME_PART_RE.match(x) or x in (".", "..") for x in parts):
        return None
    if not VERSION_RE.match(version) or version in (".", ".."):
        return None
    if kind in ("npm", "maven", "composer") and len(parts) > 2:
        return None
    if kind in ("pypi", "cargo", "gem", "nuget") and len(parts) != 1:
        return None
    if kind in ("maven", "composer") and len(parts) != 2:
        return None
    return kind, parts, version


def _go_escape(path):
    """Encodage des chemins de module du proxy Go : majuscule → « ! » + minuscule."""
    return "".join("!" + c.lower() if "A" <= c <= "Z" else c for c in path)


def lookup_url(kind, parts, version):
    b = _base(kind)
    if kind == "npm":
        name = "/".join(parts)
        return b + "/" + (_q(name) if name.startswith("@") else _q(parts[0]))
    if kind == "pypi":
        return "%s/pypi/%s/%s/json" % (b, _q(parts[0]), _q(version))
    if kind == "cargo":
        return "%s/api/v1/crates/%s/%s" % (b, _q(parts[0]), _q(version))
    if kind == "golang":
        mod = "/".join(_q(_go_escape(p)) for p in parts)
        return "%s/%s/@v/%s.info" % (b, mod, _q(_go_escape(version)))
    if kind == "maven":
        q = 'g:"%s" AND a:"%s" AND v:"%s"' % (parts[0], parts[1], version)
        return "%s/solrsearch/select?q=%s&rows=1&wt=json" % (b, _q(q))
    if kind == "gem":
        return "%s/api/v1/versions/%s.json" % (b, _q(parts[0]))
    if kind == "nuget":
        return "%s/v3/registration5-semver1/%s/%s.json" % (b, _q(parts[0].lower()), _q(version.lower()))
    if kind == "composer":
        return "%s/p2/%s/%s.json" % (b, _q(parts[0].lower()), _q(parts[1].lower()))
    return None


def norm_date(value):
    """Date ISO 8601 → « AAAA-MM-JJTHH:MM:SSZ » (UTC), ou None."""
    if isinstance(value, (int, float)) and not isinstance(value, bool) and 0 < value < 4e12:
        d = datetime.datetime.fromtimestamp(value / 1000, tz=datetime.timezone.utc)   # Maven : millisecondes
    elif isinstance(value, str) and len(value) <= 40 and DATE_RE.match(value):
        v = value.replace("Z", "+00:00")
        if re.search(r"[+-][0-9]{4}\Z", v):
            v = v[:-2] + ":" + v[-2:]
        v = re.sub(r"(\.[0-9]{6})[0-9]+", r"\1", v)
        try:
            d = datetime.datetime.fromisoformat(v)
        except ValueError:
            return None
        if d.tzinfo is None:
            d = d.replace(tzinfo=datetime.timezone.utc)
    else:
        return None
    if not 1990 <= d.year <= 2100:
        return None
    return d.astimezone(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def extract(kind, parts, version, doc):
    """Date de publication tirée de la réponse du registre (JSON déjà lu), ou None."""
    if not isinstance(doc, (dict, list)):
        return None
    if kind == "npm":
        t = doc.get("time") if isinstance(doc, dict) else None
        return norm_date(t.get(version)) if isinstance(t, dict) else None
    if kind == "pypi":
        urls = doc.get("urls") if isinstance(doc, dict) else None
        dates = [norm_date(u.get("upload_time_iso_8601")) for u in urls or [] if isinstance(u, dict)]
        dates = [d for d in dates if d]
        return min(dates) if dates else None
    if kind == "cargo":
        v = doc.get("version") if isinstance(doc, dict) else None
        return norm_date(v.get("created_at")) if isinstance(v, dict) and v.get("num") == version else None
    if kind == "golang":
        return norm_date(doc.get("Time")) if isinstance(doc, dict) and doc.get("Version") == version else None
    if kind == "maven":
        docs = (doc.get("response") or {}).get("docs") if isinstance(doc, dict) else None
        if isinstance(docs, list) and docs and isinstance(docs[0], dict) and docs[0].get("v") == version:
            return norm_date(docs[0].get("timestamp"))
        return None
    if kind == "gem":
        for v in doc if isinstance(doc, list) else []:
            if isinstance(v, dict) and v.get("number") == version and v.get("platform") in (None, "ruby"):
                return norm_date(v.get("created_at"))
        return None
    if kind == "nuget":
        return norm_date(doc.get("published")) if isinstance(doc, dict) else None
    if kind == "composer":
        pk = (doc.get("packages") or {}).get("/".join(parts).lower()) if isinstance(doc, dict) else None
        for v in pk if isinstance(pk, list) else []:
            if isinstance(v, dict) and v.get("version") in (version, "v" + version):
                return norm_date(v.get("time"))
        return None
    return None


class Network(Exception):
    pass


class Transient(Exception):
    """Erreur passagère du registre (429, 5xx) : ni résultat ni cache."""


def fetch_json(url, kind, work):
    """Réponse JSON d'un registre ; None si absente ou invalide ; Network si le réseau échoue."""
    max_size = MAX_DOC.get(kind, DEFAULT_MAX_DOC)
    fd, dest = tempfile.mkstemp(dir=work)
    os.close(fd)
    args = ["--disable", "--proto", "=https", "--tlsv1.2", "--silent", "--connect-timeout", "10",
            "--max-time", str(REQUEST_TIMEOUT), "--max-filesize", str(max_size), "--max-redirs", "0",
            "--user-agent", feeds.user_agent(), "--header", "Accept: application/json",
            "--output", dest, "--write-out", "%{http_code}", url]
    try:
        r = common.run("curl", args, timeout=REQUEST_TIMEOUT + 30, env=feeds.proxy_env())
        if r.returncode != 0:
            reason = feeds.CURL_REASONS.get(r.returncode, "")
            if reason in NETWORK_REASONS:
                raise Network(reason)
            return None                       # taille dépassée, réponse vide… : rien de retenu
        try:
            code = int(r.text.strip()[-3:])
        except ValueError:
            return None
        if code == 429 or code >= 500:
            raise Transient(str(code))
        if code != 200 or os.path.getsize(dest) > max_size:
            return None                       # 3xx (redirection jamais suivie), 404
        with open(dest, "rb") as f:
            data = f.read(max_size + 1)
        try:
            return common.loads_strict(data)
        except common.JsonError:
            return None
    finally:
        try:
            os.unlink(dest)
        except OSError:
            pass


# --------------------------------------------------------------------------
# Cache
# --------------------------------------------------------------------------

def _cache_path(purl):
    return os.path.join(CACHE, hashlib.sha256(purl.encode("utf-8")).hexdigest() + ".json")


def cache_get(purl, now):
    """(trouvé, date) : trouvé est False si le cache n'a rien d'utilisable."""
    p = _cache_path(purl)
    try:
        fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError:
        return False, None
    try:
        with os.fdopen(fd, "rb") as f:
            obj = common.loads_strict(f.read(4096))
    except (OSError, common.JsonError):
        return False, None
    if not isinstance(obj, dict) or obj.get("purl") != purl:
        return False, None
    date = obj.get("published_at")
    if isinstance(date, str) and norm_date(date) == date:
        return True, date
    checked = obj.get("checked_at")
    if date is None and isinstance(checked, (int, float)) and 0 <= now - checked < NEGATIVE_TTL:
        return True, None
    return False, None


def cache_put(purl, date, now):
    try:
        common.atomic_write(_cache_path(purl), json.dumps({"purl": purl, "published_at": date, "checked_at": int(now)}),
                            mode=0o600, group_scanoria=False)
    except OSError as e:
        common.log("package-dates: cache not written: %s" % e)


def _cache_ready():
    try:
        os.makedirs(CACHE, mode=0o700, exist_ok=True)
        st = os.lstat(CACHE)
        if not os.path.isdir(CACHE) or os.path.islink(CACHE):
            return False
        if not common.TEST_ROOT and st.st_uid != 0:
            return False
        os.chmod(CACHE, 0o700)
        return True
    except OSError:
        return False


# --------------------------------------------------------------------------
# Demande
# --------------------------------------------------------------------------

def lookup(purls, deadline_s=BUDGET_S):
    """{purl: date | None} et statistiques ; ne lève jamais pour une erreur de registre."""
    now = time.time()
    end = time.monotonic() + deadline_s
    use_cache = _cache_ready()
    dates, todo = {}, []
    stats = {"cached": 0, "looked_up": 0, "unsupported": 0, "offline": False, "unfinished": 0}
    for purl in purls:
        dates[purl] = None
        parsed = parse_purl(purl)
        if parsed is None:
            stats["unsupported"] += 1
            continue
        if use_cache:
            hit, d = cache_get(purl, now)
            if hit:
                dates[purl] = d
                stats["cached"] += 1
                continue
        todo.append((purl, parsed))
    if not todo:
        return dates, stats
    work = tempfile.mkdtemp(prefix="pkgdates-", dir=common.p("/run/scanoria") if os.path.isdir(common.p("/run/scanoria")) else None)
    state = {"network_errors": 0}

    def one(item):
        purl, (kind, parts, version) = item
        if state["network_errors"] >= OFFLINE_AFTER or time.monotonic() > end:
            return purl, None, "skipped"
        url = lookup_url(kind, parts, version)
        try:
            doc = fetch_json(url, kind, work)
        except (Network, common.Fail):
            state["network_errors"] += 1
            return purl, None, "network"
        except Transient:
            state["network_errors"] = 0
            return purl, None, "skipped"
        state["network_errors"] = 0
        return purl, extract(kind, parts, version, doc), "done"

    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=WORKERS) as pool:
            for purl, d, how in pool.map(one, todo):
                if how == "done":
                    dates[purl] = d
                    stats["looked_up"] += 1
                    if use_cache:
                        cache_put(purl, d, now)
                elif how == "skipped":
                    stats["unfinished"] += 1
    finally:
        shutil.rmtree(work, ignore_errors=True)
    stats["offline"] = state["network_errors"] >= OFFLINE_AFTER
    return dates, stats


def act_package_dates(c):
    purls = c.params["purls"][:MAX_PURLS]
    budget = max(10, min(BUDGET_S, int(c.left()) - 30))
    dates, stats = lookup(purls, budget)
    return {"dates": dates, "stats": stats}
