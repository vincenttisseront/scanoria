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

Le cache appartient à la console (compte scanoria) : le runner ne lui fait pas
confiance. Après chaque sortie neuve validée d'un module à clé, il écrit lui-même
une attestation root (ATTEST_DIR/<clé>.json, 0600 : empreinte SHA-256 de chaque
sortie) ; une entrée du cache n'est reprise que si chaque sortie a l'empreinte
attestée. Une console compromise ne peut donc ni forger ni vider une sortie.
Les outils d'appliance montés en /scanoria (scan.tool) entrent dans la clé par
l'empreinte de leur arbre : une mise à jour de l'appliance qui les change
invalide les sorties antérieures.

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
import time

from . import common, svcnet, testbed

KEY_RE = re.compile(r"[0-9a-f]{64}\Z")
FILE_RE = re.compile(r"(sarif|cyclonedx)\.json\Z")
MAX_META = 16 << 10
ATTEST_DIR = common.VARLIB + "/scans/cache-attest"   # seule arborescence inscriptible du runner (unité)
ATTEST_MAX_AGE_S = 180 * 86400


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


def options_sha256(options, command, env, tool_sha256=None):
    doc = {"options": options, "command": list(command), "env": dict(env or {})}
    if tool_sha256 is not None:
        doc["tool_sha256"] = tool_sha256
    return sha256_hex(canonical(doc))


def tree_sha256(root):
    """Empreinte d'un arbre d'outil d'appliance (chemins, modes et contenus) ; None si illisible."""
    h = hashlib.sha256()
    try:
        for base, dirs, files in os.walk(root):
            dirs.sort()
            for name in sorted(dirs + files):
                path = os.path.join(base, name)
                st = os.lstat(path)
                rel = os.path.relpath(path, root)
                if stat.S_ISREG(st.st_mode):
                    h.update(canonical([rel, st.st_mode & 0o7777, file_sha256(path)]))
                elif stat.S_ISDIR(st.st_mode):
                    h.update(canonical([rel, "dir"]))
                else:
                    return None      # lien ou fichier spécial : jamais réutilisable
    except OSError:
        return None
    return h.hexdigest()


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
    # G18 (0.7) : une analyse limitée aux fichiers modifiés d'une PR n'est jamais mise en cache.
    if scan.get("incremental") is True and job.get("changed_files") is not None:
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
    tool_sha = None
    if scan.get("tool") is not None:
        tool_sha = tree_sha256(os.path.join(svcnet.TOOLS, str(scan["tool"])))
        if tool_sha is None:
            return None
    cmd = spec["sbom_command"] if sbom_file and spec.get("sbom_command") else spec["command"]
    return compute_key(m["id"], digest, input_, fv,
                       options_sha256(spec.get("options") or {}, cmd, scan.get("env"), tool_sha))


def _attest_path(key):
    return os.path.join(ATTEST_DIR, key + ".json")


def attest(key, mid, published):
    """Attestation root d'une sortie neuve validée : {type: empreinte} ; published = {type: chemin}."""
    if not KEY_RE.match(key or "") or not published:
        return False
    doc = {"v": 1, "key": key, "module_id": mid,
           "sha256": {k: file_sha256(p) for k, p in sorted(published.items())}}
    try:
        os.mkdir(ATTEST_DIR, 0o700)
    except FileExistsError:
        pass
    st = os.lstat(ATTEST_DIR)
    if not stat.S_ISDIR(st.st_mode) or (not common.TEST_ROOT and st.st_uid != 0):
        raise OSError("attestation directory is not a root directory")
    os.chmod(ATTEST_DIR, 0o700)
    tmp = "%s.%s.tmp" % (_attest_path(key), os.urandom(4).hex())
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(canonical(doc))
    os.replace(tmp, _attest_path(key))
    return True


def _attested(key, mid):
    """{type: empreinte} attestée par le runner pour <key>, ou None."""
    try:
        dfd = os.open(ATTEST_DIR, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except OSError:
        return None
    try:
        st = os.fstat(dfd)
        if not common.TEST_ROOT and (st.st_uid != 0 or st.st_mode & 0o077):
            return None
        fd = os.open(key + ".json", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dfd)
        with os.fdopen(fd, "rb") as f:
            fst = os.fstat(f.fileno())
            if not stat.S_ISREG(fst.st_mode) or fst.st_nlink != 1 or fst.st_size > MAX_META \
                    or (not common.TEST_ROOT and fst.st_uid != 0):
                return None
            doc = common.loads_strict(f.read(MAX_META + 1))
    except (OSError, common.JsonError):
        return None
    finally:
        os.close(dfd)
    if not isinstance(doc, dict) or doc.get("v") != 1 or doc.get("key") != key or doc.get("module_id") != mid:
        return None
    sums = doc.get("sha256")
    return sums if isinstance(sums, dict) else None


def prune_attest(now=None):
    """Attestations orphelines (entrée du cache disparue) ou trop vieilles ; restes d'écriture de plus d'un jour."""
    now = time.time() if now is None else now
    try:
        names = os.listdir(ATTEST_DIR)
    except OSError:
        return 0
    removed = 0
    for name in names:
        path = os.path.join(ATTEST_DIR, name)
        try:
            age = now - os.lstat(path).st_mtime
            if name.endswith(".tmp"):
                drop = age > 86400
            else:
                key = name[:-5] if name.endswith(".json") else ""
                drop = not KEY_RE.match(key) or age > ATTEST_MAX_AGE_S \
                    or not os.path.isdir(os.path.join(cache_root(), key))
            if drop:
                os.unlink(path)
                removed += 1
        except OSError:
            continue
    return removed


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
    sums = _attested(key, mid)
    if sums is None or set(sums) != set(decl):
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
            if sha256_hex(data) != sums.get(kind):
                return None      # sortie différente de celle que le runner a validée
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
