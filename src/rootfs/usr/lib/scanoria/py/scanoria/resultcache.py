# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Vincent Tisseront
"""Résultats réutilisés (0.6, V4, contrat 21) : côté runner.

Clé d'une sortie : SHA-256 du JSON canonique (clés triées, sans espaces)
  {v: 1, module_id, image_digest,
   input: {kind: "tree", tree_sha} | {kind: "sbom", sbom_sha256},
   feeds: [{id, version}] triées par id, options_sha256}
où « tree_sha » est l'empreinte du contenu de /src (applicability.inspect),
« version » d'une base est « <version du module feed>@<date de sa dernière
mise à jour> » (une base plus récente change donc la clé) et options_sha256
couvre les options résolues (G3), la commande effectivement lancée (donc
l'entrée lue : dépôt ou SBOM) et l'environnement du manifeste.

Le runner calcule la clé de chaque module réutilisable et la publie dans le
résultat (cache_key) : la console range alors la sortie validée sous
/var/lib/scanoria/console/result-cache/<clé>/ (meta.json + <type>.json). Avant
de lancer un module, le runner cherche cette entrée ; il la relit sans suivre
de lien, la revalide (G2) et la recopie dans les résultats de la tâche
(reused_from). Toute anomalie vaut absence : le module tourne normalement.

Jamais réutilisables : tâche sans « cache » (analyse d'essai F13), module qui
lit l'historique Git, module relié à un service (sonar-scanner, envoi à
Dependency-Track : effets de bord), réseau autre que « none », image non
épinglée, base sans date, SBOM monté sans être l'entrée du module.
"""

import hashlib
import json
import os
import re
import stat

from . import common, svcnet, testbed

KEY_RE = re.compile(r"[0-9a-f]{64}\Z")
FILE_RE = re.compile(r"(sarif|cyclonedx)\.json\Z")
MAX_META = 16 << 10


def cache_root():
    """Cache de la console ; SCANORIA_RESULT_CACHE en mode test seulement."""
    v = os.environ.get("SCANORIA_RESULT_CACHE", "") if common.TEST_ROOT else ""
    return v if v and os.path.isabs(v) else common.VARLIB + "/console/result-cache"


def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def sha256_hex(data):
    return hashlib.sha256(data).hexdigest()


def compute_key(module_id, image_digest, input_, feeds, options_sha256):
    """Clé du contrat 21 (fonction pure, testée par b28)."""
    doc = {"v": 1, "module_id": module_id, "image_digest": image_digest, "input": input_,
           "feeds": sorted(({"id": f["id"], "version": f["version"]} for f in feeds), key=lambda f: f["id"]),
           "options_sha256": options_sha256}
    return sha256_hex(canonical(doc))


def options_sha256(options, command, env):
    return sha256_hex(canonical({"options": options, "command": list(command), "env": dict(env or {})}))


def file_sha256(path):
    h = hashlib.sha256()
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def key_for(job, m, spec, feeds, tree, sbom_file, sbom_mounted):
    """Clé du module, ou None s'il n'est pas réutilisable (voir l'en-tête)."""
    if job.get("cache") is not True:
        return None
    scan = m.get("scan") or {}
    if spec.get("history") or spec.get("service") or svcnet.service_of(m):
        return None
    if scan.get("network", "none") != "none":
        return None
    image = m.get("image") or ""
    digest = image.split("@", 1)[1] if "@sha256:" in image else None
    if not digest or not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
        return None
    fv = []
    for f in feeds or []:
        if not f.get("version") or not f.get("updated_at"):
            return None
        fv.append({"id": f["id"], "version": "%s@%s" % (f["version"], f["updated_at"])})
    if job["source"]["kind"] == "sbom":
        if not sbom_file:
            return None
        input_ = {"kind": "sbom", "sbom_sha256": file_sha256(sbom_file)}
    elif sbom_file:
        input_ = {"kind": "sbom", "sbom_sha256": file_sha256(sbom_file)}
    elif sbom_mounted or not tree:
        return None
    else:
        input_ = {"kind": "tree", "tree_sha": tree}
    cmd = spec["sbom_command"] if sbom_file and spec.get("sbom_command") else spec["command"]
    return compute_key(m["id"], digest, input_, fv, options_sha256(spec.get("options") or {}, cmd, scan.get("env")))


def _open_dir(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    st = os.fstat(fd)
    if not stat.S_ISDIR(st.st_mode) or (not common.TEST_ROOT and st.st_uid != common.scanoria_ids()[0]):
        os.close(fd)
        raise OSError("cache entry not owned by scanoria")
    return fd


def _read_at(dfd, name, limit):
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_NOCTTY, dir_fd=dfd)
    with os.fdopen(fd, "rb") as f:
        st = os.fstat(f.fileno())
        if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or st.st_size > limit:
            raise OSError("invalid cache file")
        os.set_blocking(f.fileno(), True)
        data = f.read(limit + 1)
    if len(data) > limit:
        raise OSError("cache file too large")
    return data


def reuse(key, m, mdir, mid, validate, write):
    """Sorties {type: « <mid>/<fichier> »} recopiées depuis l'entrée <key>, ou None.

    validate(data, declared, kind, version) lève common.Fail si la sortie est
    invalide (G2) ; write(dest, data) écrit une sortie publiée."""
    if not KEY_RE.match(key or ""):
        return None
    decl = m.get("outputs")
    if not isinstance(decl, dict) or not decl:
        return None
    try:
        dfd = _open_dir(os.path.join(cache_root(), key))
    except OSError:
        return None
    try:
        meta = common.loads_strict(_read_at(dfd, "meta.json", MAX_META))
        if not isinstance(meta, dict) or meta.get("v") != 1 or meta.get("key") != key or meta.get("module_id") != mid:
            return None
        files = meta.get("outputs")
        if not isinstance(files, dict) or set(files) != set(decl):
            return None
        staged, used = [], set()
        for kind, d in sorted(decl.items()):
            name = files.get(kind)
            if not isinstance(d, dict) or not isinstance(name, str) or not FILE_RE.match(name):
                return None
            data = _read_at(dfd, name, testbed.MAX_OUTPUT)
            validate(data, d.get("path"), kind, d.get("version"))
            fname = os.path.basename(d.get("path") or "")
            if fname in used:
                fname = "%s-%s" % (kind, fname)
            used.add(fname)
            staged.append((kind, fname, data))
    except (OSError, common.JsonError, common.Fail):
        return None
    finally:
        os.close(dfd)
    outputs = {}
    for kind, fname, data in staged:
        write(os.path.join(mdir, fname), data)
        outputs[kind] = "%s/%s" % (mid, fname)
    return outputs
