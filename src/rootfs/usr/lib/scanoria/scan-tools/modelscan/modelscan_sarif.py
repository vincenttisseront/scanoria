# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Vincent Tisseront
"""ModelScan → SARIF 2.1.0 (module modelscan, K8).

Usage (conteneur) : python3 -I modelscan_sarif.py /src /out/modelscan.json /out/modelscan.sarif

Lance ModelScan (Protect AI, Apache-2.0, livré tel quel dans vendor/ avec sa
dépendance tomlkit, MIT ; voir vendor/README.md) sur les sources, écrit son
rapport JSON natif (le même que « modelscan -r json »), puis le convertit en
SARIF 2.1.0 pour la console.

ModelScan ne charge jamais un modèle : il lit les opcodes d'un pickle
(pickletools.genops), la configuration JSON d'un modèle Keras ou H5 et le
protobuf d'un SavedModel. Rien du dépôt n'est exécuté.

Gravité (CLAUDE.md § 15, K8) : un fichier de modèle qui exécute du code au
chargement est « critical », quelle que soit la gravité propre de ModelScan :
  - pickle, PyTorch, NumPy : toute importation d'un global dangereux est
    appelée pendant le chargement (opcodes GLOBAL / STACK_GLOBAL puis REDUCE) ;
  - couche Lambda d'un modèle Keras, H5 ou SavedModel : code Python
    sérialisé, exécuté à la désérialisation du modèle.
  - opérateurs TensorFlow de lecture ou d'écriture de fichiers (ReadFile,
    WriteFile) : exécutés à l'inférence, pas au chargement → « high ».
La gravité d'origine de ModelScan est gardée dans properties.modelscan_severity.

Les erreurs de ModelScan (fichier illisible, dépendance absente, zip imbriqué)
deviennent des notifications d'exécution SARIF, jamais des résultats.
"""

import copy
import hashlib
import json
import os
import re
import sys

TOOL_VERSION = "1.0.0"
MAX_RESULTS = 10000
MAX_TEXT = 300
CTRL_RE = re.compile(r"[\x00-\x1f\x7f]")

# Scanners de ModelScan (nom court) → (règle, famille).
CODE_EXECUTION = "code-execution"
FILE_ACCESS = "file-access"
SCANNERS = {
    "PickleUnsafeOpScan": ("modelscan/pickle-unsafe-op", CODE_EXECUTION),
    "PyTorchUnsafeOpScan": ("modelscan/pytorch-unsafe-op", CODE_EXECUTION),
    "NumpyUnsafeOpScan": ("modelscan/numpy-unsafe-op", CODE_EXECUTION),
    "H5LambdaDetectScan": ("modelscan/h5-lambda", CODE_EXECUTION),
    "KerasLambdaDetectScan": ("modelscan/keras-lambda", CODE_EXECUTION),
    "SavedModelLambdaDetectScan": ("modelscan/savedmodel-lambda", CODE_EXECUTION),
    "SavedModelTensorflowOpScan": ("modelscan/tensorflow-unsafe-op", FILE_ACCESS),
}
UNKNOWN_SCANNER = ("modelscan/unsafe-op", CODE_EXECUTION)
FAMILIES = {
    # gravité normalisée, security-severity (SARIF), CWE
    CODE_EXECUTION: ("critical", "9.8", "CWE-502"),
    FILE_ACCESS: ("high", "8.0", "CWE-73"),
}
RULE_TEXT = {
    CODE_EXECUTION: (
        "Model file runs code when it is loaded",
        "Loading this model file imports and calls a Python function (pickle opcodes or a serialized "
        "Lambda layer): anyone who can change the file can run code on every machine that loads it. "
        "Use a format without code (safetensors, ONNX) or rebuild the model from trusted weights.",
    ),
    FILE_ACCESS: (
        "TensorFlow graph reads or writes files",
        "The saved graph contains file operations (ReadFile, WriteFile) that run during inference "
        "and can read or overwrite files on the machine that serves the model.",
    ),
}


def clean(value, limit=MAX_TEXT):
    """Texte d'un rapport (donnée hostile) : chaîne bornée, sans caractère de contrôle."""
    text = CTRL_RE.sub(" ", value if isinstance(value, str) else str(value or ""))
    return text[:limit]


def split_source(source):
    """« dossier/modele.zip:interne.pkl » → (chemin relatif sûr, membre de l'archive ou None)."""
    text = clean(source, 1024)
    member = None
    if ":" in text:
        text, member = text.split(":", 1)
    parts = [p for p in text.replace("\\", "/").split("/") if p not in ("", ".")]
    if not parts or any(p == ".." for p in parts):
        return None, None
    return "/".join(parts), (clean(member, 512) or None) if member is not None else None


def scanner_rule(scanner):
    short = clean(scanner, 120).rsplit(".", 1)[-1]
    return SCANNERS.get(short, UNKNOWN_SCANNER)


def fingerprint(*parts):
    return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()


def convert(report, modelscan_version="unknown"):
    """Rapport JSON natif de ModelScan → document SARIF 2.1.0 (dict)."""
    if not isinstance(report, dict):
        raise ValueError("rapport ModelScan invalide")
    issues = report.get("issues") if isinstance(report.get("issues"), list) else []
    errors = report.get("errors") if isinstance(report.get("errors"), list) else []
    results, rules, seen = [], {}, set()
    truncated = False
    dropped = 0
    for issue in issues:
        if not isinstance(issue, dict):
            continue
        path, member = split_source(issue.get("source"))
        if path is None:
            # Constat hors des sources : jamais publié tel quel, jamais perdu en silence.
            dropped += 1
            continue
        rule_id, family = scanner_rule(issue.get("scanner"))
        severity, score, cwe = FAMILIES[family]
        module = clean(issue.get("module"), 120)
        operator = clean(issue.get("operator"), 120)
        key = fingerprint(rule_id, path, member or "", module, operator)
        if key in seen:
            continue
        seen.add(key)
        if len(results) >= MAX_RESULTS:
            truncated = True
            break
        if rule_id not in rules:
            title, help_text = RULE_TEXT[family]
            rules[rule_id] = {
                "id": rule_id,
                "name": rule_id.split("/", 1)[1],
                "shortDescription": {"text": title},
                "fullDescription": {"text": help_text},
                "help": {"text": help_text},
                "defaultConfiguration": {"level": "error"},
                "properties": {
                    "tags": ["security", "model", "external/cwe/" + cwe.lower()],
                    "security-severity": score,
                    "precision": "high",
                },
            }
        where = path + (" (" + member + ")" if member else "")
        what = "%s.%s" % (module, operator) if module and operator else (module or operator or "?")
        results.append({
            "ruleId": rule_id,
            "level": "error",
            "message": {"text": "%s: unsafe operator %s in %s" % (RULE_TEXT[family][0], what, where)},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": path}}}],
            "partialFingerprints": {"modelscan/v1": key},
            "properties": {
                "severity": severity,
                "security-severity": score,
                "modelscan_severity": clean(issue.get("severity"), 16).upper() or None,
                "module": module,
                "operator": operator,
                "archive_member": member,
                "tags": ["security", "model"],
            },
        })
    notifications = []
    for err in errors[:200]:
        if not isinstance(err, dict):
            continue
        path, member = split_source(err.get("source")) if err.get("source") else (None, None)
        note = {
            "level": "error",
            "message": {"text": clean(err.get("category"), 40) + ": " + clean(err.get("description"))},
            "descriptor": {"id": "modelscan/" + (clean(err.get("category"), 40).lower() or "error")},
        }
        if path:
            note["locations"] = [{"physicalLocation": {"artifactLocation": {"uri": path}}}]
        notifications.append(note)
    if dropped:
        notifications.append({
            "level": "error",
            "message": {"text": "PATH: %d issue(s) outside the scanned sources were dropped" % dropped},
            "descriptor": {"id": "modelscan/path"},
        })
    # G13 : un fichier non lu (erreur de ModelScan) ou un constat écarté rend l'analyse
    # non concluante ; « aucun résultat » ne doit jamais masquer un échec.
    successful = not notifications
    summary = report.get("summary") if isinstance(report.get("summary"), dict) else {}
    scanned = summary.get("scanned") if isinstance(summary.get("scanned"), dict) else {}
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "modelscan",
                "version": clean(modelscan_version, 40),
                "informationUri": "https://github.com/protectai/modelscan",
                "rules": [rules[k] for k in sorted(rules)],
            }},
            "invocations": [{"executionSuccessful": successful, "toolExecutionNotifications": notifications}],
            "results": results,
            "properties": {
                "scanoria": {"truncated": truncated},
                "scanoria/modelscan": {
                    "converter": TOOL_VERSION,
                    "scanned": scanned.get("total_scanned", 0) if isinstance(scanned.get("total_scanned", 0), int) else 0,
                    "errors": len(errors),
                },
            },
        }],
    }


def write_json(path, doc):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    os.replace(tmp, path)


def scan(src):
    """Rapport natif de ModelScan pour src (vendor/ ajouté au chemin d'import)."""
    vendor = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vendor")
    if vendor not in sys.path:
        sys.path.insert(0, vendor)
    from modelscan._version import __version__  # noqa: E402 (chargé depuis vendor/)
    from modelscan.modelscan import ModelScan
    from modelscan.settings import DEFAULT_SETTINGS
    settings = copy.deepcopy(DEFAULT_SETTINGS)
    report = ModelScan(settings=settings).scan(src)
    return report, __version__


def run(src, out_json, out_sarif):
    """Analyse src, écrit le rapport natif puis le SARIF (écritures atomiques) ; 0 si réussi."""
    if not os.path.isdir(src):
        print("modelscan: sources introuvables", file=sys.stderr)
        return 2
    report, version = scan(src)
    write_json(out_json, report)
    sarif = convert(report, version)
    write_json(out_sarif, sarif)
    run0 = sarif["runs"][0]
    print("modelscan %s: %d fichiers de modèle lus, %d résultats, %d erreurs" % (
        version, run0["properties"]["scanoria/modelscan"]["scanned"], len(run0["results"]),
        run0["properties"]["scanoria/modelscan"]["errors"]))
    return 0


SRC_DIR = "/src"
OUT_DIR = "/out"
NAME_RE = re.compile(r"[A-Za-z0-9._-]{1,100}")


def out_path(arg, ext):
    """Chemin de sortie reconstruit sous OUT_DIR depuis un nom validé ; None si l'argument n'est pas /out/<nom><ext>."""
    if os.path.dirname(arg) != OUT_DIR:
        return None
    m = NAME_RE.fullmatch(os.path.basename(arg))
    if not m or not m.group(0).endswith(ext) or m.group(0) in (".", ".."):
        return None
    path = os.path.realpath(os.path.join(OUT_DIR, m.group(0)))
    return path if os.path.dirname(path) == os.path.realpath(OUT_DIR) else None


def main(argv):
    """Point d'entrée du conteneur : sources /src, sorties /out/<nom>.json et /out/<nom>.sarif."""
    if len(argv) == 2 and argv[1] == "--convert":
        # Conversion seule d'un rapport natif lu sur l'entrée standard (diagnostic) : SARIF sur la sortie standard.
        json.dump(convert(json.load(sys.stdin)), sys.stdout, ensure_ascii=False, sort_keys=True)
        return 0
    outs = [out_path(a, ext) for a, ext in zip(argv[2:4], (".json", ".sarif"))] if len(argv) == 4 else []
    if argv[1:2] != [SRC_DIR] or len(outs) != 2 or None in outs:
        print("usage: modelscan_sarif.py /src /out/<nom>.json /out/<nom>.sarif", file=sys.stderr)
        return 2
    return run(SRC_DIR, outs[0], outs[1])


if __name__ == "__main__":
    sys.exit(main(sys.argv))
