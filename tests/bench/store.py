# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Vincent Tisseront
"""Batterie de mesure : range dans le cache de résultats les sorties d'un
passage (les modules « ok » qui portent une cache_key), dans la disposition
que la console écrit (webui/server/scans/result-cache.ts, vérifiée par
tests/integration/cache-orchestration.test.ts) :
  <cache>/<clé>/meta.json   {v: 1, key, module_id, image_digest, outputs: {type: "<type>.json"}}
  <cache>/<clé>/<type>.json

  python3 -I store.py <results/<tâche>> <cache>
Affiche le nombre d'entrées rangées.
"""

import json
import os
import shutil
import sys


def main(rdir, cache):
    with open(os.path.join(rdir, "result.json")) as f:
        res = json.load(f)
    n = 0
    for m in res["modules"]:
        key = m.get("cache_key")
        if m["status"] != "ok" or not key or m.get("reused_from"):
            continue
        d = os.path.join(cache, key)
        os.makedirs(d, exist_ok=True)
        outs = {}
        for kind, rel in m["outputs"].items():
            shutil.copyfile(os.path.join(rdir, rel), os.path.join(d, kind + ".json"))
            outs[kind] = kind + ".json"
        with open(os.path.join(d, "meta.json"), "w") as f:
            json.dump({"v": 1, "key": key, "module_id": m["id"], "image_digest": m["image_digest"], "outputs": outs}, f)
        n += 1
    print(n)


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
