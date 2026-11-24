# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Vincent Tisseront
"""Batterie de mesure : résumé des durées et comparaison à la référence.

  python3 -I compare.py <mesures.json> <baseline.json> <rapport.md>

Une régression est une durée plus longue de plus de 15 % que la référence :
durée totale d'un dépôt (passage à froid ou avec le cache), ou durée d'un
outil dont la référence dépasse 5 s (en deçà, le bruit domine). Elle est
signalée, jamais bloquante : le code de sortie est toujours 0, et la ligne
« regression=true|false » est écrite sur la sortie standard (GITHUB_OUTPUT).
La référence n'est mise à jour que par une PR de l'intégrateur.
"""

import json
import sys

THRESHOLD = 0.15
MIN_MODULE_MS = 5000
REPOS = ("small", "medium", "large")
PASSES = (("cold", "à froid"), ("warm", "cache (V4)"))


def fmt(ms):
    return "—" if ms is None else ("%.1f s" % (ms / 1000.0))


def delta(cur, ref):
    if cur is None or not ref:
        return None
    return (cur - ref) / float(ref)


def compare(meas, base):
    lines, regressions = [], []
    lines.append("## Batterie de mesure des délais (2 vCPU / 4 Go)\n")
    lines.append("Référence : %s\n" % (base.get("measured_at") or "aucune (premier passage)"))
    lines.append("| Dépôt | Passage | Durée | Référence | Écart |")
    lines.append("|---|---|---|---|---|")
    for repo in REPOS:
        for p, label in PASSES:
            cur = ((meas.get("repos") or {}).get(repo) or {}).get(p) or {}
            ref = (((base.get("repos") or {}).get(repo) or {}).get(p) or {})
            d = delta(cur.get("total_ms"), ref.get("total_ms"))
            mark = "" if d is None else ("%+.0f %%" % (d * 100))
            if d is not None and d > THRESHOLD:
                mark += " ⚠️"
                regressions.append("%s, %s : %s au lieu de %s" % (repo, label, fmt(cur.get("total_ms")), fmt(ref.get("total_ms"))))
            lines.append("| %s | %s | %s | %s | %s |" % (repo, label, fmt(cur.get("total_ms")), fmt(ref.get("total_ms")), mark))
    lines.append("\n### Durée par outil (passage à froid)\n")
    mods = sorted({m for r in REPOS for m in (((meas.get("repos") or {}).get(r) or {}).get("cold") or {}).get("modules", {})})
    lines.append("| Outil | " + " | ".join(REPOS) + " |")
    lines.append("|---|" + "---|" * len(REPOS))
    for m in mods:
        cells = []
        for repo in REPOS:
            cur = ((((meas.get("repos") or {}).get(repo) or {}).get("cold") or {}).get("modules") or {}).get(m)
            ref = ((((base.get("repos") or {}).get(repo) or {}).get("cold") or {}).get("modules") or {}).get(m)
            d = delta(cur, ref) if ref and ref >= MIN_MODULE_MS else None
            cell = fmt(cur)
            if d is not None:
                cell += " (%+.0f %%%s)" % (d * 100, " ⚠️" if d > THRESHOLD else "")
                if d > THRESHOLD:
                    regressions.append("%s, %s : %s au lieu de %s" % (repo, m, fmt(cur), fmt(ref)))
            cells.append(cell)
        lines.append("| %s | %s |" % (m, " | ".join(cells)))
    reused = [(r, (((meas.get("repos") or {}).get(r) or {}).get("warm") or {}).get("reused", 0)) for r in REPOS]
    lines.append("\nSorties reprises du cache au second passage : " + ", ".join("%s %d" % x for x in reused) + ".")
    if regressions:
        lines.append("\n**Régression de plus de 15 % (signalée, non bloquante) :**\n")
        lines += ["- " + r for r in regressions]
    else:
        lines.append("\nAucune régression de plus de 15 %.")
    return "\n".join(lines) + "\n", regressions


def main(meas_path, base_path, out_path):
    with open(meas_path) as f:
        meas = json.load(f)
    try:
        with open(base_path) as f:
            base = json.load(f)
    except (OSError, ValueError):
        base = {}
    report, regressions = compare(meas, base)
    with open(out_path, "w") as f:
        f.write(report)
    print("regression=%s" % ("true" if regressions else "false"))
    return 0


if __name__ == "__main__":
    sys.exit(main(*sys.argv[1:4]))
