# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Vincent Tisseront
"""Convertit une sortie native enregistrée (modules/<id>/tests/native.json) en
SARIF avec les convertisseurs de sast_run.py ; utilisé par b31-sast.sh pour
vérifier modules/<id>/tests/converted.sarif (lu par les tests de la console)."""

import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "src", "rootfs", "usr", "lib", "scanoria", "scan-tools", "sast"))
import sast_run  # noqa: E402


def main(engine, native, out, *opts):
    with open(native, encoding="utf-8") as f:
        report = json.load(f)
    if engine == "bandit":
        doc = sast_run.convert_bandit(report)
    elif engine == "scorecard":
        doc = sast_run.convert_scorecard(report, sast_run.parse_min_score(opts))
    else:
        raise SystemExit("unknown engine %s" % engine)
    with open(out, "w", encoding="utf-8") as f:
        json.dump(doc, f, ensure_ascii=False, indent=1, sort_keys=True)
        f.write("\n")


if __name__ == "__main__":
    main(*sys.argv[1:])
