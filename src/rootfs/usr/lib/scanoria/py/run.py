# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Vincent Tisseront
"""Point d'entrée des commandes Python : python3 -I run.py <commande> [arguments].

Lancé par les lanceurs bash de /usr/sbin ; -I isole de l'environnement
(PYTHONPATH, site utilisateur, répertoire courant), d'où l'ajout explicite du
seul répertoire de la bibliothèque.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))

COMMANDS = {
    "helper": "scanoria.helper",
    "selfupdate": "scanoria.selfupdate",
    "state": "scanoria.state",
    "selftest": "scanoria.selftest",
}


def main():
    if len(sys.argv) < 2 or sys.argv[1] not in COMMANDS:
        sys.stderr.write("run.py: unknown command\n")
        return 2
    import importlib
    mod = importlib.import_module(COMMANDS[sys.argv[1]])
    return mod.main(sys.argv[2:])


if __name__ == "__main__":
    sys.exit(main())
