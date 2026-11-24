# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Vincent Tisseront
"""Dépôts d'essai de la batterie de mesure (tests/bench), générés de façon
déterministe (graine fixe) au moment de la mesure, jamais versionnés : petit,
moyen et gros. Code Python et JavaScript, manifestes et fichiers de
verrouillage npm, Dockerfile, quelques fichiers Terraform. Aucune donnée
réelle (exemple.test) et aucun motif de secret.

  python3 -I gen.py <répertoire> <small|medium|large>
"""

import json
import os
import random
import sys

SIZES = {"small": (40, 5), "medium": (1500, 40), "large": (8000, 120)}
# Paquets npm courants, versions figées (dont minimist 1.2.5, vulnérabilité connue
# des bancs d'essai) : les outils SCA ont du travail réel.
PACKAGES = [("minimist", "1.2.5"), ("lodash", "4.17.21"), ("express", "4.18.2"), ("debug", "4.3.4"),
            ("ms", "2.1.3"), ("semver", "7.5.4"), ("uuid", "9.0.1"), ("chalk", "4.1.2"), ("commander", "11.1.0"),
            ("yargs", "17.7.2"), ("axios", "1.6.2"), ("qs", "6.11.2"), ("body-parser", "1.20.2"),
            ("cookie", "0.5.0"), ("send", "0.18.0"), ("mime", "1.6.0"), ("depd", "2.0.0"), ("inherits", "2.0.4"),
            ("safe-buffer", "5.2.1"), ("bytes", "3.1.2")]
WORDS = "analyse rapport module projet verdict base source sortie entree valeur liste table index".split()


def main(out, size):
    files, deps = SIZES[size]
    rnd = random.Random("scanoria-bench-%s" % size)
    os.makedirs(out, exist_ok=True)
    w = lambda rel, text: (os.makedirs(os.path.dirname(os.path.join(out, rel)) or out, exist_ok=True),
                           open(os.path.join(out, rel), "w").write(text))
    for i in range(files):
        d = "src/%s/%s" % (rnd.choice(WORDS), rnd.choice(WORDS))
        if i % 3 == 0:
            body = "".join("def %s_%d(x):\n    return x * %d\n\n" % (rnd.choice(WORDS), j, j) for j in range(rnd.randint(5, 40)))
            w("%s/m%d.py" % (d, i), "# Module d'essai %d\n" % i + body)
        else:
            body = "".join("export function %s%d(x) { return x + %d }\n" % (rnd.choice(WORDS), j, j) for j in range(rnd.randint(5, 40)))
            w("%s/m%d.js" % (d, i), "// Module d'essai %d\n" % i + body)
    chosen = PACKAGES[:min(deps, len(PACKAGES))]
    for n in range(max(1, deps // len(PACKAGES))):
        base = "." if n == 0 else "apps/a%d" % n
        pkg = {"name": "bench-%d" % n, "version": "1.0.0", "dependencies": {k: v for k, v in chosen}}
        lock = {"name": pkg["name"], "version": "1.0.0", "lockfileVersion": 3, "requires": True,
                "packages": {"": {"name": pkg["name"], "version": "1.0.0", "dependencies": pkg["dependencies"]}}}
        for k, v in chosen:
            lock["packages"]["node_modules/" + k] = {"version": v, "resolved": "https://registry.npmjs.org/%s/-/%s-%s.tgz" % (k, k, v)}
        w(base + "/package.json", json.dumps(pkg, indent=2) + "\n")
        w(base + "/package-lock.json", json.dumps(lock, indent=2) + "\n")
    w("Dockerfile", "FROM docker.io/library/alpine:3.20\nRUN adduser -D app\nUSER app\nCOPY src /app\n")
    w("infra/main.tf", 'resource "null_resource" "exemple" {\n  triggers = { nom = "analyse.exemple.test" }\n}\n')
    w("README.md", "Dépôt d'essai généré (%s).\n" % size)


if __name__ == "__main__":
    if len(sys.argv) != 3 or sys.argv[2] not in SIZES:
        sys.stderr.write(__doc__)
        sys.exit(2)
    main(sys.argv[1], sys.argv[2])
