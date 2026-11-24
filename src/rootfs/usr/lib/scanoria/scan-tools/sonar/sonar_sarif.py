# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Vincent Tisseront
"""Conversion des issues et hotspots SonarQube vers SARIF 2.1.0 (module sonar-scanner).

Bibliothèque standard seulement : ce fichier tourne dans le conteneur jetable
du scanner (python3 de l'image officielle sonar-scanner-cli) et dans les tests
(tests/b17-sonarqube.sh) sur des réponses d'API enregistrées.

Tout ce qui vient de l'API est traité comme hostile : messages et étiquettes
dérivent du code analysé. Chaque champ est typé, borné et nettoyé des
caractères de contrôle ; un chemin hors du dépôt (absolu, « .. ») est écarté
sans faire échouer la conversion ; un résultat malformé est ignoré et compté.

Gravité native (properties.severity, lue par l'ingestion, table
scan.severity_map du manifeste) :
  - issue avec impacts (SonarQube 10.2+) : la plus forte gravité d'impact,
    blocker | high | medium | low | info ;
  - issue sans impacts : gravité historique, blocker | critical | major | minor | info ;
  - hotspot : probabilité de vulnérabilité, high | medium | low.
Catégorie : étiquette « scanoria-category:sast » pour une vulnérabilité, un
impact SECURITY ou un hotspot, « scanoria-category:quality » sinon.
"""

import re

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
MAX_RESULTS = 5000
MAX_TEXT = 2000
MAX_TAGS = 20
MAX_PATH = 1024

IMPACT_ORDER = ("BLOCKER", "HIGH", "MEDIUM", "LOW", "INFO")
LEGACY_SEVERITIES = ("BLOCKER", "CRITICAL", "MAJOR", "MINOR", "INFO")
HOTSPOT_PROBABILITIES = ("HIGH", "MEDIUM", "LOW")
LEVELS = {"blocker": "error", "critical": "error", "high": "error", "major": "warning", "medium": "warning",
          "minor": "note", "low": "note", "info": "note"}

RULE_RE = re.compile(r"[A-Za-z0-9_.:-]{1,200}\Z")
KEY_RE = re.compile(r"[A-Za-z0-9_.:-]{1,100}\Z")
TAG_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,49}\Z")
CTRL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f‪-‮⁦-⁩]")


def clean_text(v, limit=MAX_TEXT):
    """Texte sûr : chaîne, sans caractère de contrôle ni d'inversion bidirectionnelle, borné."""
    if not isinstance(v, str):
        return None
    v = CTRL_RE.sub("", v).strip()
    return v[:limit] if v else None


def _int(v, lo=1, hi=10_000_000):
    if isinstance(v, bool) or not isinstance(v, int) or not lo <= v <= hi:
        return None
    return v


def clean_path(path):
    """Chemin relatif au dépôt, ou None s'il sort du dépôt ou est malformé."""
    if not isinstance(path, str) or not path or len(path) > MAX_PATH:
        return None
    if path.startswith("/") or "\\" in path or CTRL_RE.search(path):
        return None
    parts = [p for p in path.split("/") if p not in ("", ".")]
    if not parts or any(p == ".." for p in parts):
        return None
    return "/".join(parts)


def component_paths(pages, project_key):
    """{clé de composant: chemin} depuis les listes components des réponses."""
    out = {}
    for page in pages:
        comps = page.get("components") if isinstance(page, dict) else None
        for c in comps if isinstance(comps, list) else []:
            if not isinstance(c, dict) or not isinstance(c.get("key"), str):
                continue
            p = clean_path(c.get("path"))
            if p is None:
                p = _path_from_key(c["key"], project_key)
            if p is not None:
                out[c["key"]] = p
    return out


def _path_from_key(key, project_key):
    prefix = project_key + ":"
    if isinstance(key, str) and key.startswith(prefix):
        return clean_path(key[len(prefix):])
    return None


def _region(item):
    tr = item.get("textRange") if isinstance(item.get("textRange"), dict) else {}
    start = _int(tr.get("startLine")) or _int(item.get("line"))
    if start is None:
        return None
    region = {"startLine": start}
    end = _int(tr.get("endLine"))
    if end is not None and end >= start:
        region["endLine"] = end
    sc = _int(tr.get("startOffset"), 0, 100_000)
    ec = _int(tr.get("endOffset"), 0, 100_000)
    if sc is not None:
        region["startColumn"] = sc + 1
        if ec is not None and (region.get("endLine", start) > start or ec >= sc):
            region["endColumn"] = ec + 1
    return region


def _tags(item):
    raw = item.get("tags")
    out = []
    for t in raw if isinstance(raw, list) else []:
        if isinstance(t, str) and TAG_RE.match(t) and t not in out:
            out.append(t)
        if len(out) >= MAX_TAGS:
            break
    return out


def issue_severity(issue):
    """Gravité native d'une issue (en minuscules) : impacts d'abord, sinon gravité historique."""
    impacts = issue.get("impacts")
    found = []
    for imp in impacts if isinstance(impacts, list) else []:
        sev = imp.get("severity") if isinstance(imp, dict) else None
        if sev in IMPACT_ORDER:
            found.append(IMPACT_ORDER.index(sev))
    if found:
        return IMPACT_ORDER[min(found)].lower()
    sev = issue.get("severity")
    return sev.lower() if sev in LEGACY_SEVERITIES else "major"


def issue_is_security(issue):
    if issue.get("type") == "VULNERABILITY":
        return True
    impacts = issue.get("impacts")
    return any(isinstance(i, dict) and i.get("softwareQuality") == "SECURITY"
               for i in (impacts if isinstance(impacts, list) else []))


def _location(path, region):
    phys = {"artifactLocation": {"uri": path}}
    if region:
        phys["region"] = region
    return [{"physicalLocation": phys}]


def _result(rule, sev, message, path, region, key, kind, category, tags):
    res = {
        "ruleId": rule,
        "level": LEVELS.get(sev, "warning"),
        "message": {"text": message},
        "locations": _location(path, region),
        "properties": {
            "severity": sev,
            "tags": tags + ["scanoria-category:" + category],
            "sonarKind": kind,
        },
    }
    if key:
        res["partialFingerprints"] = {"sonarqube/key/v1": key}
    return res


class Converter:
    """Accumule issues et hotspots puis produit le document SARIF."""

    def __init__(self, project_key, tool_version=None, max_results=MAX_RESULTS):
        self.project_key = project_key
        self.tool_version = clean_text(tool_version, 64)
        self.max_results = max_results
        self.results = []
        self.rules = {}
        self.skipped = 0
        self.outside = 0
        self.truncated = False
        self.total = 0

    def _room(self):
        if len(self.results) >= self.max_results:
            self.truncated = True
            return False
        return True

    def _rule(self, rule, tags=()):
        if rule not in self.rules:
            self.rules[rule] = {"id": rule, "name": rule, "tags": []}
        r = self.rules[rule]
        for t in tags:
            if t not in r["tags"] and len(r["tags"]) < MAX_TAGS:
                r["tags"].append(t)

    def add_issues(self, page):
        if not isinstance(page, dict):
            return
        paths = component_paths([page], self.project_key)
        for it in page.get("issues") if isinstance(page.get("issues"), list) else []:
            self.total += 1
            if not isinstance(it, dict):
                self.skipped += 1
                continue
            rule = it.get("rule")
            msg = clean_text(it.get("message"))
            if not isinstance(rule, str) or not RULE_RE.match(rule) or msg is None:
                self.skipped += 1
                continue
            comp = it.get("component")
            path = paths.get(comp) or _path_from_key(comp, self.project_key)
            if path is None:
                self.outside += 1
                continue
            if not self._room():
                continue
            key = it.get("key") if isinstance(it.get("key"), str) and KEY_RE.match(it["key"]) else None
            kind = it.get("type") if it.get("type") in ("BUG", "VULNERABILITY", "CODE_SMELL") else "ISSUE"
            category = "sast" if issue_is_security(it) else "quality"
            tags = _tags(it)
            self._rule(rule, tags)
            self.results.append(_result(rule, issue_severity(it), msg, path, _region(it), key, kind, category, tags))

    def add_hotspots(self, page):
        if not isinstance(page, dict):
            return
        paths = component_paths([page], self.project_key)
        for hs in page.get("hotspots") if isinstance(page.get("hotspots"), list) else []:
            self.total += 1
            if not isinstance(hs, dict):
                self.skipped += 1
                continue
            rule = hs.get("ruleKey")
            msg = clean_text(hs.get("message"))
            if not isinstance(rule, str) or not RULE_RE.match(rule) or msg is None:
                self.skipped += 1
                continue
            comp = hs.get("component")
            path = paths.get(comp) or _path_from_key(comp, self.project_key)
            if path is None:
                self.outside += 1
                continue
            if not self._room():
                continue
            prob = hs.get("vulnerabilityProbability")
            sev = prob.lower() if prob in HOTSPOT_PROBABILITIES else "medium"
            key = hs.get("key") if isinstance(hs.get("key"), str) and KEY_RE.match(hs["key"]) else None
            tags = ["security-hotspot"]
            cat = hs.get("securityCategory")
            if isinstance(cat, str) and TAG_RE.match(cat):
                tags.append(cat)
            self._rule(rule, tags)
            self.results.append(_result(rule, sev, msg, path, _region(hs), key, "SECURITY_HOTSPOT", "sast", tags))

    def add_rule_names(self, page):
        """Noms lisibles des règles (api/rules/search), facultatifs."""
        rules = page.get("rules") if isinstance(page, dict) else None
        for r in rules if isinstance(rules, list) else []:
            if not isinstance(r, dict) or r.get("key") not in self.rules:
                continue
            name = clean_text(r.get("name"), 300)
            if name:
                self.rules[r["key"]]["name"] = name

    def sarif(self):
        driver = {"name": "SonarQube", "informationUri": "https://www.sonarsource.com/products/sonarqube/",
                  "rules": []}
        if self.tool_version:
            driver["version"] = self.tool_version
        for rid in sorted(self.rules):
            r = self.rules[rid]
            rule = {"id": rid, "name": r["name"], "shortDescription": {"text": r["name"]}}
            if r["tags"]:
                rule["properties"] = {"tags": list(r["tags"])}
            driver["rules"].append(rule)
        run = {
            "tool": {"driver": driver},
            "results": self.results,
            "properties": {"scanoria": {"total": self.total, "kept": len(self.results), "truncated": self.truncated,
                                        "skipped": self.skipped, "outside": self.outside}},
        }
        return {"$schema": SARIF_SCHEMA, "version": "2.1.0", "runs": [run]}


def convert(project_key, issue_pages=(), hotspot_pages=(), rule_pages=(), tool_version=None,
            max_results=MAX_RESULTS):
    """Document SARIF 2.1.0 à partir des pages de réponses de l'API."""
    c = Converter(project_key, tool_version, max_results)
    for p in issue_pages:
        c.add_issues(p)
    for p in hotspot_pages:
        c.add_hotspots(p)
    for p in rule_pages:
        c.add_rule_names(p)
    return c.sarif()
