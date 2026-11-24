# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Vincent Tisseront
"""Envoi du SBOM d'une analyse à Dependency-Track (module dtrack-upload, 0.5).

Lancé par scanoria-runner dans le conteneur jetable du module (image python),
rattaché au seul réseau interne du service Dependency-Track (contrat 12 de la
0.4), après le module qui produit le SBOM (contrat 14) :
  1. attend que l'API réponde (api/version) ;
  2. envoie le SBOM (PUT api/v1/bom) sur le projet SCANORIA_PROJECT_KEY,
     version SCANORIA_REF, créé automatiquement s'il n'existe pas ;
  3. attend la fin de son traitement (api/v1/event/token/<jeton>) ;
  4. relit le projet (api/v1/project/lookup) et son inventaire
     (api/v1/bom/cyclonedx/project/<uuid>), puis écrit un CycloneDX 1.6 borné
     qui porte l'identifiant du projet (propriété scanoria:dtrack:project),
     pour le lien de la console.

Usage : dtrack_upload.py /sbom/sbom.cdx.json /out/<fichier>.cdx.json
La clé d'API arrive par un secret Podman monté en fichier, jamais en argument
ni dans la sortie. Codes de sortie : 0 succès, 2 usage, 3 service
indisponible, 4 envoi refusé ou traitement inachevé, 5 relecture impossible,
6 SBOM absent ou invalide.
"""

import base64
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

TOKEN_FILE = os.environ.get("SCANORIA_TOKEN_FILE", "/run/secrets/scan-token")
OUT_DIR = os.environ.get("SCANORIA_OUT_DIR", "/out")
SBOM_DIR = os.environ.get("SCANORIA_SBOM_DIR", "/sbom")
# Réseau interne Internal=true du service, sans sortie : HTTP en clair (contrat 12).
HOST_RE = re.compile(r"http:/{2}[a-z0-9][a-z0-9._-]{0,100}(:[0-9]{1,5})?\Z")
PROJECT_KEY_RE = re.compile(r"scanoria-([0-9a-f]{12}|testbed)\Z")
REF_RE = re.compile(r"[A-Za-z0-9._/-]{1,200}\Z")
UUID_RE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z")
TOKEN_RE = re.compile(r"[A-Za-z0-9_]{10,200}\Z")
MAX_SBOM = 64 << 20
MAX_RESPONSE = 64 << 20
MAX_COMPONENTS = 50_000
HTTP_TIMEOUT = 60
TEXT_MAX = 512


class Failure(Exception):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


def log(msg):
    sys.stderr.write("dtrack-upload: %s\n" % msg)
    sys.stderr.flush()


class Api:
    def __init__(self, host, key):
        self.host, self.key = host.rstrip("/"), key
        # Aucun mandataire : le conteneur n'a de toute façon qu'un réseau interne.
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def call(self, method, path, params=None, body=None, fail=5, accept="application/json"):
        url = "%s/%s" % (self.host, path)
        if params:
            url += "?" + urllib.parse.urlencode(params)
        data = json.dumps(body).encode("utf-8") if body is not None else None
        headers = {"X-Api-Key": self.key, "Accept": accept}
        if data is not None:
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(url, data=data, method=method, headers=headers)
        try:
            with self.opener.open(req, timeout=HTTP_TIMEOUT) as r:
                raw = r.read(MAX_RESPONSE + 1)
        except urllib.error.HTTPError as e:
            raise Failure(fail, "%s answered HTTP %d" % (path.split("?")[0], e.code))
        except (urllib.error.URLError, OSError) as e:
            raise Failure(3, "%s unreachable (%s)" % (path.split("?")[0], getattr(e, "reason", e)))
        if len(raw) > MAX_RESPONSE:
            raise Failure(fail, "%s response too large" % path.split("?")[0])
        if not raw:
            return None
        try:
            return json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            raise Failure(fail, "%s did not return JSON" % path.split("?")[0])


def wait_up(api, deadline):
    while True:
        try:
            v = api.call("GET", "api/version", fail=3)
            if isinstance(v, dict):
                return v.get("version") if isinstance(v.get("version"), str) else None
        except Failure as f:
            if time.monotonic() > deadline:
                raise Failure(3, "Dependency-Track is not available: %s" % f)
        if time.monotonic() > deadline:
            raise Failure(3, "Dependency-Track is not available")
        time.sleep(3)


def read_sbom(path):
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError:
        raise Failure(6, "SBOM missing")
    with os.fdopen(fd, "rb") as f:
        os.set_blocking(f.fileno(), True)
        raw = f.read(MAX_SBOM + 1)
    if len(raw) > MAX_SBOM:
        raise Failure(6, "SBOM too large")
    try:
        doc = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise Failure(6, "SBOM is not valid JSON")
    if not isinstance(doc, dict) or doc.get("bomFormat") != "CycloneDX":
        raise Failure(6, "SBOM is not CycloneDX")
    return raw


def upload(api, key, version, raw):
    r = api.call("PUT", "api/v1/bom", body={"projectName": key, "projectVersion": version, "autoCreate": True,
                                            "bom": base64.b64encode(raw).decode("ascii")}, fail=4)
    token = r.get("token") if isinstance(r, dict) else None
    if not isinstance(token, str) or not UUID_RE.match(token):
        raise Failure(4, "no processing token returned")
    return token


def wait_processed(api, token, deadline):
    delay = 1
    while True:
        r = api.call("GET", "api/v1/event/token/" + token, fail=4)
        if isinstance(r, dict) and r.get("processing") is False:
            return
        if time.monotonic() > deadline:
            raise Failure(4, "SBOM still being processed at the deadline")
        time.sleep(delay)
        delay = min(5, delay + 1)


def _text(v, n=TEXT_MAX):
    return v[:n] if isinstance(v, str) and v else None


def _licenses(c):
    out = []
    for item in c.get("licenses") or []:
        if not isinstance(item, dict):
            continue
        if _text(item.get("expression")):
            out.append({"expression": _text(item["expression"])})
            continue
        lic = item.get("license") if isinstance(item.get("license"), dict) else {}
        if _text(lic.get("id"), 128):
            out.append({"license": {"id": _text(lic["id"], 128)}})
        elif _text(lic.get("name"), 128):
            out.append({"license": {"name": _text(lic["name"], 128)}})
    return out[:20]


def inventory(doc, project_uuid, version):
    """CycloneDX 1.6 borné : composants (nom, version, purl, licences) et identifiant du projet."""
    comps = []

    def visit(items, depth):
        for c in items or []:
            if len(comps) >= MAX_COMPONENTS or depth > 8:
                return
            if not isinstance(c, dict) or not _text(c.get("name")):
                continue
            out = {"type": c.get("type") if isinstance(c.get("type"), str) else "library", "name": _text(c["name"])}
            for k in ("version", "purl", "bom-ref"):
                if _text(c.get(k), 1024):
                    out[k] = _text(c[k], 1024)
            lic = _licenses(c)
            if lic:
                out["licenses"] = lic
            comps.append(out)
            visit(c.get("components"), depth + 1)

    visit(doc.get("components") if isinstance(doc, dict) else None, 0)
    return {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
            "metadata": {"tools": {"components": [{"type": "application", "name": "Dependency-Track",
                                                   "version": version or "unknown"}]},
                         "properties": [{"name": "scanoria:dtrack:project", "value": project_uuid}]},
            "components": comps}


def main(argv):
    if len(argv) != 2 or os.path.dirname(argv[1]) != OUT_DIR or os.path.dirname(argv[0]) != SBOM_DIR \
            or not re.fullmatch(r"[A-Za-z0-9._-]{1,100}", os.path.basename(argv[1])):
        log("usage: dtrack_upload.py %s/sbom.cdx.json %s/<file>.cdx.json" % (SBOM_DIR, OUT_DIR))
        return 2
    host = os.environ.get("SCANORIA_SERVICE_URL", "")
    key = os.environ.get("SCANORIA_PROJECT_KEY", "")
    ref = os.environ.get("SCANORIA_REF", "testbed")
    if not HOST_RE.match(host) or not PROJECT_KEY_RE.match(key) or not REF_RE.match(ref):
        log("invalid SCANORIA_SERVICE_URL, SCANORIA_PROJECT_KEY or SCANORIA_REF")
        return 2
    try:
        with open(TOKEN_FILE, encoding="ascii") as f:
            token = f.read(512).strip()
    except (OSError, UnicodeDecodeError):
        token = ""
    if not TOKEN_RE.match(token):
        log("API key missing or malformed")
        return 3
    try:
        budget = int(os.environ.get("SCANORIA_BUDGET_S", "840"))
    except ValueError:
        budget = 840
    deadline = time.monotonic() + max(60, budget)
    try:
        raw = read_sbom(argv[0])
        api = Api(host, token)
        version = wait_up(api, min(deadline, time.monotonic() + 300))
        log("Dependency-Track %s is up, sending the SBOM to %s %s" % (version or "?", key, ref))
        wait_processed(api, upload(api, key, ref, raw), deadline)
        project = api.call("GET", "api/v1/project/lookup", {"name": key, "version": ref})
        uuid = project.get("uuid") if isinstance(project, dict) else None
        if not isinstance(uuid, str) or not UUID_RE.match(uuid):
            raise Failure(5, "project not found after the upload")
        doc = api.call("GET", "api/v1/bom/cyclonedx/project/" + uuid,
                       {"format": "JSON", "variant": "inventory", "download": "false"},
                       # Seul type rendu par cet export (application/json : HTTP 406).
                       accept="application/vnd.cyclonedx+json")
        out = inventory(doc, uuid, version)
        tmp = os.path.join(OUT_DIR, ".dtrack.tmp")
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(out, f, ensure_ascii=False)
        os.replace(tmp, argv[1])
        log("%d component(s) in Dependency-Track project %s" % (len(out["components"]), uuid))
        return 0
    except Failure as f:
        log(str(f))
        return f.code


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
