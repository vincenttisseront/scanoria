# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Vincent Tisseront
"""F6 (0.7, chantier B) : copie du CODEOWNERS de la source analysée.

Après la récupération (conteneur git-fetch, ou extraction d'une archive), le
runner cherche le fichier CODEOWNERS aux emplacements standard de GitHub,
GitLab et Forgejo et le copie, tel quel et SANS RIEN EXÉCUTER, dans
results/<tâche>/codeowners.txt ; la console l'analyse (webui/server/findings/
codeowners.ts) et remplit findings.owners.

Principe 4 : la source est une donnée hostile. Chaque composant du chemin est
ouvert sans suivre de lien (O_NOFOLLOW, relatif au répertoire parent) ; seul un
fichier ordinaire, à lien unique, de 128 Kio au plus, encodé en UTF-8 et sans
octet nul est copié. Tout autre cas est ignoré sans erreur : l'affectation est
une aide, son absence ne change ni l'analyse ni le verdict.
"""

import os
import stat

from . import common

# Même ordre que CODEOWNERS_LOCATIONS (codeowners.ts) : le premier présent gagne.
LOCATIONS = (
    (".github", "CODEOWNERS"),
    ("CODEOWNERS",),
    ("docs", "CODEOWNERS"),
    (".gitlab", "CODEOWNERS"),
    (".forgejo", "CODEOWNERS"),
    (".gitea", "CODEOWNERS"),
)
MAX_BYTES = 128 * 1024
OUT_NAME = "codeowners.txt"


def _open_nofollow(root, parts):
    """Descripteur du fichier root/parts..., sans suivre aucun lien ; None sinon."""
    flags_dir = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    try:
        fd = os.open(root, flags_dir)
    except OSError:
        return None
    try:
        for name in parts[:-1]:
            nfd = os.open(name, flags_dir, dir_fd=fd)
            os.close(fd)
            fd = nfd
        return os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_NOCTTY | os.O_CLOEXEC, dir_fd=fd)
    except OSError:
        return None
    finally:
        os.close(fd)


def read_codeowners(src):
    """Contenu du premier CODEOWNERS acceptable de src (bytes), ou None."""
    for parts in LOCATIONS:
        fd = _open_nofollow(src, parts)
        if fd is None:
            continue
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or st.st_size > MAX_BYTES:
                return None
            data = os.read(fd, MAX_BYTES + 1)
        finally:
            os.close(fd)
        if len(data) > MAX_BYTES or b"\0" in data:
            return None
        try:
            data.decode("utf-8")
        except UnicodeDecodeError:
            return None
        return data
    return None


def capture(src, rdir):
    """Copie le CODEOWNERS de src dans rdir/codeowners.txt ; retourne True s'il a été copié. Ne lève jamais."""
    try:
        data = read_codeowners(src)
        if data is None:
            return False
        common.atomic_write(os.path.join(rdir, OUT_NAME), data, 0o640)
        return True
    except Exception as e:  # noqa: BLE001 — une aide : jamais un échec de l'analyse
        common.log("runner: CODEOWNERS not copied: %r" % (e,))
        return False
