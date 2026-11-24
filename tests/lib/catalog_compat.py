# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Vincent Tisseront
"""Valide un index du catalogue avec le vérificateur d'une version publiée.

Usage : python3 -I catalog_compat.py <arbre de la version> <version> <catalog-index.json>
L'arbre est une extraction (git archive) de src/rootfs/usr/lib/scanoria/py et
src/rootfs/usr/share/scanoria/schemas à l'étiquette de la version. Reprend les
contrôles de catalogverify.verify_index de cette version, sauf la signature
(l'index de la CI n'est pas signé) : schéma, check_module, doublons. Signale
ensuite les modules que cette version refusera d'installer (requires.appliance),
ce qui est le comportement attendu pour un module plus récent qu'elle.
Code de sortie : 0 si l'index est accepté, 1 sinon.
"""

import json
import os
import re
import sys


def main(tree, version, index_path):
    sys.path.insert(0, os.path.join(tree, "src/rootfs/usr/lib/scanoria/py"))
    from scanoria import catalogverify, common, schema  # noqa: E402 (version publiée)

    with open(os.path.join(tree, "src/rootfs/usr/share/scanoria/schemas/catalog-index.schema.json"), "rb") as f:
        validator = schema.Validator(json.loads(f.read()))
    with open(index_path, "rb") as f:
        idx = common.loads_strict(f.read())
    errs = validator.errors(idx)
    if errs:
        print("refusé par le schéma de la %s : %s" % (version, "; ".join(errs[:3])))
        return 1
    if idx.get("schema") != 1:
        print("format d'index inconnu de la %s" % version)
        return 1
    seen = set()
    for m in idx.get("modules") or []:
        try:
            catalogverify.check_module(m)
        except common.Fail as e:
            print("refusé par check_module de la %s : %s" % (version, e))
            return 1
        key = (m["id"], m["version"])
        if key in seen:
            print("module en double : %s %s" % key)
            return 1
        seen.add(key)
    newer = []
    num = tuple(int(x) for x in re.findall(r"\d+", version)[:3])
    for m in idx.get("modules") or []:
        spec = (m.get("requires") or {}).get("appliance") or ""
        for part in filter(None, (s.strip() for s in spec.split(","))):
            mm = re.fullmatch(r">=\s*(\d+)\.(\d+)\.(\d+)", part)
            if mm and tuple(int(x) for x in mm.groups()) > num:
                newer.append("%s (%s)" % (m["id"], spec))
    print("accepté par la %s : %d modules, %d réservés à une version plus récente%s"
          % (version, len(seen), len(newer), (" : " + ", ".join(newer)) if newer else ""))
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 4:
        print(__doc__.strip(), file=sys.stderr)
        sys.exit(2)
    sys.exit(main(*sys.argv[1:]))
