# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Vincent Tisseront
"""SBOM d'une analyse, partagé entre modules (contrat 14 de la 0.5).

Un module dont la sortie déclarée est « cyclonedx » et qui ne lit pas lui-même
de SBOM (Syft) le produit ; les modules qui déclarent l'entrée « sbom » le
lisent ensuite, en lecture seule, sur /sbom/sbom.cdx.json :
  - scan.sbom_command : argv lancé à la place de scan.command quand le SBOM
    existe (Grype : « grype sbom:/sbom/sbom.cdx.json ») ; sans SBOM, le module
    garde sa commande habituelle (Grype analyse alors /src lui-même) ;
  - scan.requires_sbom : le module ne fait rien d'autre que lire le SBOM
    (dtrack-upload) ; sans SBOM, il est « skipped » avec sa raison.
Le runner lance d'abord les producteurs, puis les consommateurs, sans changer
l'ordre des modules dans le résultat. Le SBOM est une copie validée (G2) de la
sortie publiée dans results/<id>/, déposée dans l'espace de travail de
l'analyse (supprimé à la fin) et donnée à l'utilisateur des conteneurs.
"""

import os
import re
import shutil

from . import testbed
from .common import Fail

MOUNT = "/sbom"
FILE = "sbom.cdx.json"
E_SBOM_MISSING = "E_SBOM_MISSING"
REF_LABEL_RE = re.compile(r"[A-Za-z0-9._/-]{1,200}\Z")


def consumes(m):
    """Le module lit le SBOM de l'analyse (entrée « sbom » déclarée)."""
    scan = m.get("scan") or {}
    return "sbom" in (scan.get("inputs") or []) and (scan.get("requires_sbom") is True
                                                     or bool(scan.get("sbom_command")))


def required(m):
    return (m.get("scan") or {}).get("requires_sbom") is True


def command_of(m, options):
    """scan.sbom_command rendu avec les options (G3), ou None."""
    cmd = (m.get("scan") or {}).get("sbom_command")
    if not cmd:
        return None
    return testbed.render_command(cmd, options)


def ordered(runnable):
    """Producteurs (et modules indépendants) d'abord, consommateurs ensuite ; ordre stable."""
    return sorted(runnable, key=lambda es: 1 if consumes(es[1]["manifest"]) else 0)


def sbom_dir(ws):
    return os.path.join(ws, "sbom")


def available(ws):
    """Répertoire à monter sur /sbom s'il contient le SBOM de l'analyse, sinon None."""
    d = sbom_dir(ws)
    p = os.path.join(d, FILE)
    if os.path.isdir(d) and not os.path.islink(d) and os.path.isfile(p) and not os.path.islink(p):
        return d
    return None


def offer(ws, published):
    """Dépose une copie du premier SBOM produit (déjà validé par le runner) ; sans effet ensuite."""
    d = sbom_dir(ws)
    if os.path.lexists(d):
        return False
    tmp = d + ".tmp"
    shutil.rmtree(tmp, ignore_errors=True)
    os.mkdir(tmp, 0o700)
    try:
        src = os.open(published, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(src, "rb") as f, open(os.path.join(tmp, FILE), "xb") as out:
            if f.seek(0, os.SEEK_END) > testbed.MAX_OUTPUT:
                raise Fail("E_TESTBED", "SBOM too large")
            f.seek(0)
            shutil.copyfileobj(f, out, 1 << 20)
        os.chmod(os.path.join(tmp, FILE), 0o400)
        testbed._give_to_container(tmp)
        os.rename(tmp, d)
    except (OSError, Fail):
        shutil.rmtree(tmp, ignore_errors=True)
        return False
    return True


def ref_label(source):
    """Version du projet dans un service : la référence (branche ou étiquette) ou « archive »."""
    if source.get("kind") != "git":
        return "archive"
    ref = source.get("ref") or ""
    for prefix in ("refs/heads/", "refs/tags/"):
        if ref.startswith(prefix):
            ref = ref[len(prefix):]
    ref = ref.strip("/")
    return ref if REF_LABEL_RE.match(ref) and ".." not in ref else "unknown"
