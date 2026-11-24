# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Vincent Tisseront
"""Variantes d'image d'un module « service » (service.variants du manifeste).

Une variante est la même application, à la même version (base_version égale à
la version du module), dans une image épinglée par empreinte qui ajoute une
extension tierce : pour SonarQube Community Build, le plugin
sonarqube-community-branch-plugin (analyse des branches et des PR).

Elle est choisie par une option booléenne du module (activée par défaut :
principe 8). Elle n'est retenue que si elle est compatible, c'est-à-dire si
sa version partage la version majeure et mineure du module (règle du plugin) ;
sinon l'image d'origine est gardée et la fonction est déclarée indisponible,
avec sa raison, dans l'état publié.

Le manifeste « effectif » (stocké dans le registre, utilisé pour tirer l'image,
écrire les unités et retirer les images orphelines) est une copie du manifeste
du catalogue dont l'image est celle de la variante et qui porte
« active_variant ». Les fichiers qu'une variante dépose dans un volume
(« leaves ») sont retirés quand elle n'est plus active, avant le démarrage de
l'image d'origine : un plugin laissé sans son agent Java empêcherait SonarQube
de démarrer.
"""

import copy
import os
import re
import stat

from . import common, quadlet
from .common import Fail

FEATURE_RE = re.compile(r"[a-z][a-z0-9_]{0,30}\Z")
OPTION_RE = re.compile(r"[a-z][a-z0-9_]{0,30}\Z")
LEAF_DIR_RE = re.compile(r"[A-Za-z0-9._-]{1,64}\Z")
LEAF_PREFIX_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{2,80}\Z")
MAX_VARIANTS = 4


def major_minor(version):
    parts = str(version).split(".")
    return tuple(parts[:2]) if len(parts) >= 2 else None


def declared(m):
    """Variantes déclarées, revalidées (défense en profondeur, en plus du schéma)."""
    from .catalogverify import IMAGE_RE
    vs = (m.get("service") or {}).get("variants") or []
    if not isinstance(vs, list) or len(vs) > MAX_VARIANTS:
        raise Fail("E_INVALID_PARAM", "%s: invalid service.variants" % m.get("id"))
    seen = set()
    for v in vs:
        if not isinstance(v, dict) or not OPTION_RE.match(str(v.get("option", ""))) \
                or not FEATURE_RE.match(str(v.get("feature", ""))) \
                or not isinstance(v.get("image"), str) or not IMAGE_RE.match(v["image"]) \
                or not isinstance(v.get("version"), str) or not isinstance(v.get("base_version"), str):
            raise Fail("E_INVALID_PARAM", "%s: invalid service variant" % m.get("id"))
        if v["option"] in seen:
            raise Fail("E_INVALID_PARAM", "%s: two variants for option %s" % (m.get("id"), v["option"]))
        seen.add(v["option"])
        if v["option"] != v["feature"] or v["feature"] not in optional_features(m):
            raise Fail("E_INVALID_PARAM", "%s: variant feature %s is not in service.features" % (m.get("id"), v["feature"]))
        for leaf in v.get("leaves") or []:
            if not isinstance(leaf, dict) or not LEAF_DIR_RE.match(str(leaf.get("dir", ""))) \
                    or not LEAF_PREFIX_RE.match(str(leaf.get("prefix", ""))) \
                    or leaf["dir"] in (".", "..") \
                    or leaf.get("volume") not in [n for n, _ in quadlet.volumes(m)]:
                raise Fail("E_INVALID_PARAM", "%s: invalid variant leaves" % m.get("id"))
    return vs


def incompatibility(m, v):
    """Raison pour laquelle la variante v ne convient pas au module m, ou None."""
    if v["base_version"] != m.get("version"):
        return "variant built on %s, module is %s" % (v["base_version"], m.get("version"))
    if major_minor(v["version"]) is None or major_minor(v["version"]) != major_minor(m.get("version")):
        return "%s %s is not compatible with %s" % (v["feature"], v["version"], m.get("version"))
    return None


def optional_features(m):
    """service.features : fonctions optionnelles du module, chacune portée par
    l'option booléenne du même nom et fournie par une variante."""
    fs = (m.get("service") or {}).get("features") or []
    props = ((m.get("options") or {}).get("properties")) or {}
    if not isinstance(fs, list) or len(fs) > MAX_VARIANTS or any(
            not isinstance(f, str) or not FEATURE_RE.match(f) or not OPTION_RE.match(f)
            or (props.get(f) or {}).get("type") != "boolean" for f in fs):
        raise Fail("E_INVALID_PARAM", "%s: invalid service.features" % m.get("id"))
    return fs


def features(m, options):
    """État de chaque fonction optionnelle : {feature: {active, version, code, reason}}.
    code : null (active), « disabled » (option fausse), « incompatible » (variante
    déclarée mais d'une autre version), « unavailable » (aucune variante encore)."""
    out = {}
    for f in optional_features(m):
        wanted = (options or {}).get(f) is True
        cands = [v for v in declared(m) if v["feature"] == f]
        ok = [v for v in cands if incompatibility(m, v) is None]
        if not wanted:
            out[f] = {"active": False, "version": None, "code": "disabled", "reason": "disabled by option %s" % f}
        elif ok:
            out[f] = {"active": True, "version": ok[0]["version"], "code": None, "reason": None}
        elif cands:
            out[f] = {"active": False, "version": None, "code": "incompatible",
                      "reason": incompatibility(m, cands[0])}
        else:
            out[f] = {"active": False, "version": None, "code": "unavailable",
                      "reason": "no compatible version is available yet for %s" % m.get("version")}
    return out


def select(m, options):
    """Variante retenue pour ces options, ou None."""
    for v in declared(m):
        if (options or {}).get(v["option"]) is True and incompatibility(m, v) is None:
            return v
    return None


def effective(m, options):
    """Manifeste stocké et exécuté : image de la variante retenue, ou celui du catalogue."""
    if m.get("type") != "service":
        return m
    v = select(m, options)
    out = copy.deepcopy(m)
    out.pop("active_variant", None)
    if v is not None:
        out["image"] = v["image"]
        out["active_variant"] = {"feature": v["feature"], "version": v["version"], "option": v["option"]}
    return out


def active_features(m):
    """Fonctions actives d'un manifeste effectif (registre)."""
    v = m.get("active_variant") if isinstance(m, dict) else None
    return {v["feature"]} if isinstance(v, dict) and isinstance(v.get("feature"), str) else set()


def volume_mountpoint(volume):
    r = common.run("podman", ["volume", "inspect", "--format", "{{.Mountpoint}}", volume],
                   timeout=60, stdout_limit=8192)
    path = (r.stdout or b"").decode("utf-8", "replace").strip() if r.returncode == 0 else ""
    if not path:
        return None
    if not os.path.isabs(path):
        raise Fail("E_INVALID_PARAM", "unexpected mount point for volume %s" % volume)
    return common.p(path)


def remove_leaves(m, previous=None):
    """Retire les fichiers des variantes inactives (préfixe dans un répertoire
    d'un volume), sans suivre aucun lien : le volume est écrit par le conteneur.
    previous : manifeste remplacé (mise à jour), dont les variantes comptent
    aussi, car la nouvelle version peut ne plus en déclarer aucune. Retourne
    les noms retirés."""
    keep = (m.get("active_variant") or {}).get("feature")
    removed = []
    leaves = []
    for src in ([previous] if isinstance(previous, dict) else []) + [m]:
        for v in declared(src):
            if v["feature"] != keep:
                leaves += [lf for lf in v.get("leaves") or [] if lf not in leaves]
    vols = [n for n, _ in quadlet.volumes(m)]
    for leaf in leaves:
        if leaf["volume"] not in vols:
            continue
        root = volume_mountpoint(quadlet.volume_name(m["id"], leaf["volume"]))
        if root is None:
            continue
        removed += _remove_in(root, leaf)
    if removed:
        common.log("%s: removed files of inactive variants: %s" % (m["id"], ", ".join(removed)))
    return removed


def _remove_in(root, leaf):
    """Fichiers « prefix* » de root/dir, ouverts par descripteurs sans suivre de
    lien. Un répertoire remplacé par un lien (ou absent) est ignoré, jamais suivi."""
    out = []
    try:
        vfd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except OSError:
        return out
    try:
        try:
            dfd = os.open(leaf["dir"], os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=vfd)
        except OSError as e:
            if not isinstance(e, FileNotFoundError):
                common.log("%s in a volume is not a plain directory: ignored (%s)" % (leaf["dir"], e))
            return out
        try:
            for name in os.listdir(dfd):
                if not name.startswith(leaf["prefix"]):
                    continue
                st = os.stat(name, dir_fd=dfd, follow_symlinks=False)
                if stat.S_ISDIR(st.st_mode):
                    continue
                # unlink ne suit pas un lien : seul le lien est retiré.
                os.unlink(name, dir_fd=dfd)
                out.append("%s/%s" % (leaf["dir"], name))
        finally:
            os.close(dfd)
    finally:
        os.close(vfd)
    return out
