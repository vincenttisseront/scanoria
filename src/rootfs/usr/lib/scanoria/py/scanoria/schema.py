# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Vincent Tisseront
"""Validation JSON Schema 2020-12, sous-ensemble utilisé par les schémas Scanoria.

Mots-clés pris en charge : type, const, enum, pattern, minLength, maxLength,
minimum, maximum, properties, required, additionalProperties, items, minItems,
maxItems, uniqueItems, oneOf, anyOf, allOf, not, if/then/else. Annotations
ignorées : $schema, $id, $comment, title, description, default, examples.
Tout autre mot-clé fait échouer le chargement du schéma (échec fermé).

Différences volontaires avec ECMA-262 : « $ » d'un motif est traduit en \\Z
(Python accepterait sinon un saut de ligne final) et les motifs sont ASCII.
"""

import json
import os
import re

from . import common

ANNOTATIONS = {"$schema", "$id", "$comment", "title", "description", "default", "examples"}
KEYWORDS = {
    "type", "const", "enum", "pattern", "minLength", "maxLength", "minimum", "maximum",
    "properties", "required", "additionalProperties", "items", "minItems", "maxItems",
    "uniqueItems", "oneOf", "anyOf", "allOf", "not", "if", "then", "else",
} | ANNOTATIONS


class SchemaError(Exception):
    pass


def _translate(pattern):
    out, i, in_class = [], 0, False
    while i < len(pattern):
        c = pattern[i]
        if c == "\\":
            out.append(pattern[i:i + 2])
            i += 2
            continue
        if c == "[" and not in_class:
            in_class = True
        elif c == "]" and in_class:
            in_class = False
        elif c == "$" and not in_class:
            c = r"\Z"
        out.append(c)
        i += 1
    return re.compile("".join(out), re.ASCII)


def _canon(v):
    return json.dumps(v, sort_keys=True, ensure_ascii=False)


def _type_ok(t, v):
    if t == "object":
        return isinstance(v, dict)
    if t == "array":
        return isinstance(v, list)
    if t == "string":
        return isinstance(v, str)
    if t == "integer":
        return isinstance(v, int) and not isinstance(v, bool)
    if t == "number":
        return isinstance(v, (int, float)) and not isinstance(v, bool)
    if t == "boolean":
        return isinstance(v, bool)
    if t == "null":
        return v is None
    raise SchemaError("unknown type " + str(t))


def _eq(a, b):
    """Égalité JSON (true ≠ 1)."""
    if isinstance(a, bool) or isinstance(b, bool):
        return type(a) is type(b) and a == b
    if isinstance(a, (int, float)) and isinstance(b, (int, float)):
        return a == b
    return _canon(a) == _canon(b)


class Validator:
    def __init__(self, schema):
        self.schema = schema
        self._patterns = {}
        self._check(schema)

    def _check(self, s):
        if isinstance(s, bool):
            return
        if not isinstance(s, dict):
            raise SchemaError("schema must be an object")
        for k, v in s.items():
            if k not in KEYWORDS:
                raise SchemaError("unsupported keyword " + k)
            if k == "pattern":
                self._patterns[v] = _translate(v)
            elif k == "properties":
                for sub in v.values():
                    self._check(sub)
            elif k in ("items", "additionalProperties", "not", "if", "then", "else"):
                self._check(v)
            elif k in ("oneOf", "anyOf", "allOf"):
                for sub in v:
                    self._check(sub)

    def errors(self, value, s=None, path="$"):
        s = self.schema if s is None else s
        if s is True:
            return []
        if s is False:
            return [path + ": not allowed"]
        errs = []
        t = s.get("type")
        if t is not None:
            types = t if isinstance(t, list) else [t]
            if not any(_type_ok(x, value) for x in types):
                return [path + ": wrong type"]
        if "const" in s and not _eq(value, s["const"]):
            errs.append(path + ": const")
        if "enum" in s and not any(_eq(value, e) for e in s["enum"]):
            errs.append(path + ": enum")
        if isinstance(value, str):
            if "minLength" in s and len(value) < s["minLength"]:
                errs.append(path + ": too short")
            if "maxLength" in s and len(value) > s["maxLength"]:
                errs.append(path + ": too long")
            if "pattern" in s and not self._patterns[s["pattern"]].search(value):
                errs.append(path + ": pattern")
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            if "minimum" in s and value < s["minimum"]:
                errs.append(path + ": minimum")
            if "maximum" in s and value > s["maximum"]:
                errs.append(path + ": maximum")
        if isinstance(value, dict):
            props = s.get("properties", {})
            for r in s.get("required", []):
                if r not in value:
                    errs.append("%s: missing %s" % (path, r))
            for k, v in value.items():
                sub = path + "." + k
                if k in props:
                    errs.extend(self.errors(v, props[k], sub))
                elif "additionalProperties" in s:
                    errs.extend(self.errors(v, s["additionalProperties"], sub))
        if isinstance(value, list):
            if "minItems" in s and len(value) < s["minItems"]:
                errs.append(path + ": too few items")
            if "maxItems" in s and len(value) > s["maxItems"]:
                errs.append(path + ": too many items")
            if s.get("uniqueItems"):
                seen = set()
                for v in value:
                    c = _canon(v) + type(v).__name__
                    if c in seen:
                        errs.append(path + ": duplicate items")
                        break
                    seen.add(c)
            if "items" in s:
                for i, v in enumerate(value):
                    errs.extend(self.errors(v, s["items"], "%s[%d]" % (path, i)))
        for sub in s.get("allOf", []):
            errs.extend(self.errors(value, sub, path))
        if "anyOf" in s and not any(not self.errors(value, sub, path) for sub in s["anyOf"]):
            errs.append(path + ": anyOf")
        if "oneOf" in s and sum(1 for sub in s["oneOf"] if not self.errors(value, sub, path)) != 1:
            errs.append(path + ": oneOf")
        if "not" in s and not self.errors(value, s["not"], path):
            errs.append(path + ": not")
        if "if" in s:
            if not self.errors(value, s["if"], path):
                if "then" in s:
                    errs.extend(self.errors(value, s["then"], path))
            elif "else" in s:
                errs.extend(self.errors(value, s["else"], path))
        return errs

    def valid(self, value):
        return not self.errors(value)


_cache = {}


def load(kind, name):
    """kind : 'requests' ou 'schemas' ; name sans extension (liste fermée par l'appelant)."""
    key = (kind, name)
    if key not in _cache:
        if kind not in ("requests", "schemas") or not re.fullmatch(r"[a-z][a-z-]{0,40}", name):
            raise SchemaError("bad schema name")
        path = os.path.join(common.SHARE_DIR, kind, name + ".schema.json")
        _cache[key] = Validator(common.load_json_file(path, 1 << 20))
    return _cache[key]
