# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Vincent Tisseront
"""Espace de travail d'une analyse : travail en mémoire et exclusions communes (V9).

Travail en mémoire : ws/src est un tmpfs quand l'arbre attendu et la RAM libre
le permettent. La taille est calculée, jamais au-delà d'une part de la mémoire
disponible qui mettrait les conteneurs en « oom » :
  budget = (MemAvailable − réserve) / 2, borné à TMPFS_MAX_MB,
  réserve = plus gros scanner de l'analyse + conteneur de récupération + marge.
Sous TMPFS_MIN_MB, ou si le dernier arbre extrait du projet (miroir V2) ne
tiendrait pas, l'analyse travaille sur disque. Un arbre plus gros que prévu
(ENOSPC à l'extraction) est repris sur disque : rien n'est perdu, le miroir
évite une seconde récupération.

Exclusions communes : répertoires de dépendances installées (node_modules,
vendor de Go ou de Composer, vendor/bundle de Ruby) et fichiers multimédias
ou polices, retirés de /src avant l'analyse et notés dans la couverture
(source.excluded, coverage.excluded : [{pattern, count}], G15). Les exécutables,
archives (jar, whl…) et modèles ne sont jamais exclus : des scanners les lisent.
"""

import os
import re
import shutil
import stat

from . import common

TMPFS_MAX_MB = 1024
TMPFS_MIN_MB = 64
SAFETY_MB = 512
# Marge sur la taille du dernier arbre extrait (fichiers ajoutés depuis, blocs).
GROWTH = 1.25

DEP_DIRS = ("node_modules",)
MEDIA_EXT = ("png", "jpg", "jpeg", "gif", "bmp", "ico", "webp", "tif", "tiff", "psd",
             "mp3", "mp4", "m4a", "mov", "avi", "mkv", "webm", "wav", "ogg", "flac",
             "woff", "woff2", "ttf", "otf", "eot")


def mem_available_mb():
    try:
        with open(common.p("/proc/meminfo"), encoding="ascii") as f:
            for ln in f:
                if ln.startswith("MemAvailable:"):
                    return int(ln.split()[1]) // 1024
    except (OSError, ValueError, IndexError):
        pass
    return 0


def tmpfs_size_mb(available_mb, biggest_module_mb, fetch_mb, last_tree_bytes=None):
    """Taille du tmpfs de ws/src en Mio, ou 0 pour travailler sur disque."""
    reserve = max(0, int(biggest_module_mb)) + max(0, int(fetch_mb)) + SAFETY_MB
    size = min(TMPFS_MAX_MB, (int(available_mb) - reserve) // 2)
    if size < TMPFS_MIN_MB:
        return 0
    if last_tree_bytes is not None and last_tree_bytes * GROWTH > size << 20:
        return 0
    return int(size)


def mount_tmpfs(path, size_mb):
    """Monte un tmpfs sur path (répertoire vide), propriété de l'utilisateur des conteneurs."""
    from . import testbed
    os.mkdir(path, 0o700)
    opts = "size=%dm,mode=0700,uid=%d,gid=%d,nosuid,nodev,noexec" % (size_mb, testbed.NOBODY, testbed.NOBODY)
    r = common.run("mount", ["-t", "tmpfs", "-o", opts, "scanoria-ws", path], timeout=60)
    if r.returncode != 0:
        os.rmdir(path)
        return False
    return True


def mounted_under(base):
    """Points de montage situés sous base (lecture de /proc/self/mountinfo)."""
    out = []
    try:
        with open(common.p("/proc/self/mountinfo"), encoding="utf-8", errors="replace") as f:
            for ln in f:
                parts = ln.split()
                if len(parts) > 4:
                    mp = parts[4].replace("\\040", " ")
                    if mp.startswith(base.rstrip("/") + "/"):
                        out.append(mp)
    except OSError:
        pass
    return sorted(out, key=len, reverse=True)


def unmount(path):
    if common.run("umount", [path], timeout=120).returncode != 0:
        common.run("umount", ["-l", path], timeout=120)


def unmount_all(base):
    for mp in mounted_under(base):
        unmount(mp)


def _count_files(root):
    n = 0
    for _d, _dirs, names in os.walk(root, followlinks=False):
        n += len(names)
    return n


def _is_vendor_deps(path):
    """vendor/ de dépendances installées seulement (Go, Composer, Bundler) ;
    un vendor/ de code propre au projet reste analysé."""
    for marker, kind in (("modules.txt", stat.S_ISREG), ("autoload.php", stat.S_ISREG),
                         ("bundle", stat.S_ISDIR)):
        try:
            if kind(os.lstat(os.path.join(path, marker)).st_mode):
                return True
        except OSError:
            continue
    return False


# Catégories dont les modules voient toujours l'arbre entier (décision de
# l'intégrateur, 0.6) : une exclusion décidée par le contenu du dépôt ne doit
# jamais cacher de code ni de secret à ces analyses (G13).
FULL_TREE_CATEGORIES = frozenset(("secrets", "sast"))
# Masques posés par analyse (montages imbriqués) ; au-delà, le reste est analysé.
MAX_MASKS = 200
SAFE_REL_RE = re.compile(r"[A-Za-z0-9._@+-]+(/[A-Za-z0-9._@+-]+)*\Z")


def common_exclusions(root):
    """Exclusions communes de root, sans rien retirer : (masques, [{pattern, count}]).

    masques : [(chemin relatif, "dir"|"file")] à masquer pour les modules hors
    FULL_TREE_CATEGORIES ; le décompte ne porte que sur ce qui est masqué."""
    counts = {}
    masks = []

    def add(rel, kind, pattern, n):
        if len(masks) >= MAX_MASKS or not SAFE_REL_RE.match(rel) or any(c.startswith("-") for c in rel.split("/")):
            return False
        masks.append((rel, kind))
        counts[pattern] = counts.get(pattern, 0) + n
        return True
    for d, dirs, names in os.walk(root, topdown=True, followlinks=False):
        dirs.sort()
        for n in list(dirs):
            p = os.path.join(d, n)
            if os.path.islink(p):
                continue
            if n in DEP_DIRS or (n == "vendor" and _is_vendor_deps(p)):
                if add(os.path.relpath(p, root), "dir", "**/%s/**" % n, _count_files(p)):
                    dirs.remove(n)
        for n in sorted(names):
            ext = n.rsplit(".", 1)[1].lower() if "." in n[1:] else ""
            if ext in MEDIA_EXT:
                p = os.path.join(d, n)
                try:
                    if stat.S_ISREG(os.lstat(p).st_mode):
                        add(os.path.relpath(p, root), "file", "**/*." + ext, 1)
                except OSError:
                    pass
    return masks, [{"pattern": k, "count": counts[k]} for k in sorted(counts)][:100]


def sees_full_tree(manifest):
    cats = manifest.get("categories") if isinstance(manifest, dict) else None
    return not isinstance(cats, list) or bool(FULL_TREE_CATEGORIES & set(cats))


def mask_mounts(ws, masks):
    """Montages en lecture seule qui masquent les exclusions sous /src (vide pour un
    répertoire, fichier vide pour un fichier), créés une fois par analyse."""
    if not masks:
        return []
    empty_dir = os.path.join(ws, "mask-dir")
    empty_file = os.path.join(ws, "mask-file")
    if not os.path.isdir(empty_dir):
        os.mkdir(empty_dir, 0o555)
    if not os.path.isfile(empty_file):
        fd = os.open(empty_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o444)
        os.close(fd)
    return [(empty_dir if kind == "dir" else empty_file, "/src/" + rel, "ro") for rel, kind in masks]
