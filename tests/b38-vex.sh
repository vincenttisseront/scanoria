#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Vincent Tisseront
#
# b38-vex — VEX (0.8, H7), sans root ni conteneur ni base. Formats de
# webui/server/vex/format.ts (node --experimental-strip-types) :
#   - export : documents OpenVEX 0.2.0 et CycloneDX 1.6 rendus par la console
#     validés contre les SCHÉMAS OFFICIELS, épinglés par commit et empreinte
#     (dépôts openvex/spec et CycloneDX/specification, relevés le 2026-11-25),
#     pour tous les statuts et toutes les justifications ; forme canonique
#     stable (mêmes octets quel que soit l'ordre d'entrée) ; aller-retour sans
#     perte par la lecture stricte ;
#   - import : documents hostiles refusés EN ENTIER avec un code stable :
#     taille, profondeur, nombre de déclarations et de produits, identifiants
#     de vulnérabilité piégés (injection de commande, chemin, caractères de
#     contrôle et de direction), purl piégés (espace, saut de ligne, schéma
#     étranger, longueur), statuts et justifications inconnus, not_affected
#     sans justification, CycloneDX de version inconnue ; rien n'est exécuté.
# Dépendances : bash, curl, python3 et python3-jsonschema, node ≥ 22.6.

set -euo pipefail
export PYTHONDONTWRITEBYTECODE=1

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
TS="$ROOT/webui/server/vex/format.ts"
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
for t in curl python3 node sha256sum; do command -v "$t" > /dev/null || { echo "outil manquant : $t" >&2; exit 2; }; done
node --experimental-strip-types -e '' > /dev/null 2>&1 || { echo "node ≥ 22.6 requis (--experimental-strip-types)" >&2; exit 2; }

PASS=0
FAIL=0
ok() { PASS=$((PASS + 1)); printf 'ok   %s\n' "$1"; }
ko() { FAIL=$((FAIL + 1)); printf 'FAIL %s\n' "$1"; }
expect() {
	if [[ "$2" == "$3" ]]; then ok "$1"; else ko "$1 (obtenu « $2 », attendu « $3 »)"; fi
}

# --- schémas officiels, épinglés ---
OPENVEX_COMMIT=93139bd2c65390b504e47f82f11c50451289f93a
OPENVEX_SHA256=9373597734ed1d3ea5161a8b46d3866c4a8cfe76fd632fdd16aef01fb34b3238
CDX_COMMIT=5fee6af48d43c751dc6a5b31138f06af2b10bac5
CDX_BOM_SHA256=18f57f7482593bad9f21b4feed09084640cbeff419d62ad5090c5ceccca5b37d
CDX_SPDX_SHA256=4b345e2329f209f34e960ae2a8e7cb46a166907e6a45e94978565925dc47b359
CDX_JSF_SHA256=8bae002c25e723db7ee1f26afde680ae1a2b1a8f6b4b4b0fd65dc3becb090aae
S="$WORK/schemas"
mkdir -p "$S"
fetch() { # url fichier empreinte
	curl --proto '=https' --tlsv1.2 -fsSL --retry 3 -o "$S/$2" "$1"
	echo "$3  $S/$2" | sha256sum --check --strict --quiet
}
fetch "https://raw.githubusercontent.com/openvex/spec/$OPENVEX_COMMIT/openvex_json_schema.json" openvex.json "$OPENVEX_SHA256"
for f in bom-1.6.schema.json:$CDX_BOM_SHA256 spdx.schema.json:$CDX_SPDX_SHA256 jsf-0.82.schema.json:$CDX_JSF_SHA256; do
	fetch "https://raw.githubusercontent.com/CycloneDX/specification/$CDX_COMMIT/schema/${f%%:*}" "${f%%:*}" "${f##*:}"
done
ok "schémas OpenVEX 0.2.0 et CycloneDX 1.6 épinglés (commit et empreinte)"

# --- rendu par la console ---
OUT="$WORK/out"
mkdir -p "$OUT"
# shellcheck disable=SC2016 # code JavaScript littéral, rien à développer
(cd "$WORK" && node --no-warnings --experimental-strip-types --input-type=module -e '
import { writeFileSync } from "node:fs"
const m = await import(process.argv[1])
const out = process.argv[2]
const t = "2026-11-25T10:00:00Z"
const list = []
let i = 0
for (const status of m.VEX_STATUSES) {
  for (const justification of status === "not_affected" ? [...m.VEX_JUSTIFICATIONS, null] : [null]) {
    i++
    list.push({
      vuln_id: `CVE-2026-${String(1000 + i)}`, product: i % 2 ? "pkg:npm/%40scope/lib@2.0.0" : `pkg:pypi/exemple-${i}@1.${i}`,
      status, justification,
      impact_statement: status === "affected" || (status === "not_affected" && justification && i % 3 === 0) ? null : `Impact ${i} : « texte » accentué.`,
      action_statement: status === "affected" ? "Mettre à jour vers 2.0.1." : null,
      timestamp: t,
    })
  }
}
// Deux produits pour une même déclaration (groupés en une seule).
list.push({ ...list[0], product: "pkg:deb/debian/openssl@3.0.11?arch=amd64&distro=debian-12" })
const ov = m.renderOpenVex({ statements: list, timestamp: t })
const cdx = m.renderCycloneDxVex({ statements: list, timestamp: t })
writeFileSync(`${out}/openvex.json`, ov.canonical)
writeFileSync(`${out}/cdx.json`, cdx.canonical)
const shuffled = [...list].reverse()
const stable = m.renderOpenVex({ statements: shuffled, timestamp: t }).canonical === ov.canonical
  && m.renderCycloneDxVex({ statements: shuffled, timestamp: t }).canonical === cdx.canonical
const key = s => [s.vuln_id, s.product, s.status, s.justification, s.status === "affected" ? s.action_statement : s.impact_statement].join("|")
const norm = l => m.sortStatements(l).map(key).join("\n")
const roundOv = norm(m.parseVexDocument(ov.canonical).statements) === norm(list)
// CycloneDX ne distingue pas component_not_present de vulnerable_code_not_present (code_not_present).
const cdxSafe = l => l.map(s => ({ ...s, justification: s.justification === "component_not_present" ? "vulnerable_code_not_present" : s.justification }))
const roundCdx = norm(m.parseVexDocument(cdx.canonical).statements) === norm(cdxSafe(list))
console.log(JSON.stringify({ stable, roundOv, roundCdx, statements: list.length }))
' "$TS" "$OUT") > "$WORK/render.json"
r() { python3 -I -c 'import json, sys; print(json.load(open(sys.argv[1]))[sys.argv[2]])' "$WORK/render.json" "$1"; }
expect "forme canonique stable, quel que soit l'ordre d'entrée" "$(r stable)" "True"
expect "aller-retour OpenVEX sans perte" "$(r roundOv)" "True"
expect "aller-retour CycloneDX sans perte (au plus près des justifications)" "$(r roundCdx)" "True"

# --- validation contre les schémas officiels ---
VALIDATE="$WORK/validate.py"
cat > "$VALIDATE" << 'PY'
import json, sys
import jsonschema
kind, schemas, doc = sys.argv[1], sys.argv[2], json.load(open(sys.argv[3], encoding="utf-8"))
load = lambda n: json.load(open(f"{schemas}/{n}", encoding="utf-8"))
try:
    if kind == "openvex":
        jsonschema.Draft202012Validator(load("openvex.json")).validate(doc)
    else:
        bom = load("bom-1.6.schema.json")
        base = "http://cyclonedx.org/schema/"
        extra = {base + n: load(n) for n in ("spdx.schema.json", "jsf-0.82.schema.json")}
        try:
            from referencing import Registry, Resource
            reg = Registry().with_resources([(k, Resource.from_contents(v)) for k, v in extra.items()])
            jsonschema.Draft7Validator(bom, registry=reg).validate(doc)
        except ImportError:  # python3-jsonschema 4.10 (Ubuntu 24.04)
            resolver = jsonschema.RefResolver(base + "bom-1.6.schema.json", bom, store=extra)
            jsonschema.Draft7Validator(bom, resolver=resolver).validate(doc)
except jsonschema.ValidationError as e:
    print("invalide :", e.message[:300], list(e.absolute_path)[:8])
    sys.exit(1)
print("ok")
PY
if out=$(python3 -I -W ignore "$VALIDATE" openvex "$S" "$OUT/openvex.json" 2>&1); then ok "export OpenVEX conforme au schéma officiel ($(r statements) déclarations)"; else ko "export OpenVEX : $out"; fi
if out=$(python3 -I -W ignore "$VALIDATE" cdx "$S" "$OUT/cdx.json" 2>&1); then ok "export CycloneDX 1.6 conforme au schéma officiel"; else ko "export CycloneDX : $out"; fi
# Le validateur lui-même refuse un document fautif (le contrôle n'est pas vide).
python3 -I -c 'import json, sys; d = json.load(open(sys.argv[1])); d["statements"][0]["status"] = "maybe"; json.dump(d, open(sys.argv[2], "w"))' "$OUT/openvex.json" "$OUT/bad-openvex.json"
if python3 -I -W ignore "$VALIDATE" openvex "$S" "$OUT/bad-openvex.json" > /dev/null 2>&1; then ko "le schéma OpenVEX accepte un statut inconnu"; else ok "contrôle du schéma OpenVEX effectif (statut inconnu refusé)"; fi
python3 -I -c 'import json, sys; d = json.load(open(sys.argv[1])); d["vulnerabilities"][0]["analysis"]["state"] = "maybe"; json.dump(d, open(sys.argv[2], "w"))' "$OUT/cdx.json" "$OUT/bad-cdx.json"
if python3 -I -W ignore "$VALIDATE" cdx "$S" "$OUT/bad-cdx.json" > /dev/null 2>&1; then ko "le schéma CycloneDX accepte un état inconnu"; else ok "contrôle du schéma CycloneDX effectif (état inconnu refusé)"; fi

# --- import : documents hostiles ---
rm -f /tmp/scanoria-b38-pwn
# shellcheck disable=SC2016 # code JavaScript littéral, rien à développer
(cd "$WORK" && node --no-warnings --experimental-strip-types --input-type=module -e '
const m = await import(process.argv[1])
const ctx = "https://openvex.dev/ns/v0.2.0"
const st = (over = {}) => ({ vulnerability: { name: "CVE-2026-0001" }, products: [{ "@id": "pkg:npm/lib@1.0.0" }], status: "fixed", ...over })
const ov = (statements, extra = {}) => JSON.stringify({ "@context": ctx, "@id": "urn:x", author: "x", timestamp: "2026-11-01T00:00:00Z", version: 1, statements, ...extra })
const cdx = (vulns, extra = {}) => JSON.stringify({ bomFormat: "CycloneDX", specVersion: "1.6", version: 1, vulnerabilities: vulns, ...extra })
let deep = "x"
for (let i = 0; i < 50; i++) deep = [deep]
const cases = {
  "taille": "{\"a\":\"" + "x".repeat(m.VEX_LIMITS.maxBytes) + "\"}",
  "json": "{\"@context\":",
  "racine-tableau": "[]",
  "profondeur": ov([st({ status_notes: undefined, impact_statement: undefined, x: deep })]),
  "declarations": ov(Array.from({ length: m.VEX_LIMITS.maxStatements + 1 }, () => st())),
  "produits": ov([st({ products: Array.from({ length: m.VEX_LIMITS.maxProducts + 1 }, (_, i) => ({ "@id": `pkg:npm/l${i}@1` })) })]),
  "aucune-declaration": ov([]),
  "contexte-etranger": JSON.stringify({ "@context": "https://exemple.test/ns", statements: [st()] }),
  "vuln-commande": ov([st({ vulnerability: { name: "$(touch /tmp/scanoria-b38-pwn)" } })]),
  "vuln-chemin": ov([st({ vulnerability: { name: "../../etc/passwd" } })]),
  "vuln-controle": ov([st({ vulnerability: { name: "CVE-2026-0001\n" } })]),
  "vuln-direction": ov([st({ vulnerability: { name: "CVE-2026-‮1000" } })]),
  "vuln-absente": ov([st({ vulnerability: {} })]),
  "purl-espace": ov([st({ products: [{ "@id": "pkg:npm/lib 1.0.0" }] })]),
  "purl-saut": ov([st({ products: [{ "@id": "pkg:npm/lib@1\nX-Injected: 1" }] })]),
  "purl-schema": ov([st({ products: [{ "@id": "javascript:alert(1)" }] })]),
  "purl-long": ov([st({ products: [{ "@id": "pkg:npm/" + "a".repeat(600) }] })]),
  "purl-vide": ov([st({ products: [{ "@id": "pkg:npm/" }] })]),
  "purl-objet": ov([st({ products: [{ identifiers: { purl: { toString: "x" } } }] })]),
  "statut-inconnu": ov([st({ status: "exploitable" })]),
  "statut-casse": ov([st({ status: "FIXED" })]),
  "justification-inconnue": ov([st({ status: "not_affected", justification: "trust_me" })]),
  "not-affected-nu": ov([st({ status: "not_affected" })]),
  "texte-controle": ov([st({ impact_statement: "ok\u0007bip" })]),
  "texte-type": ov([st({ impact_statement: 42 })]),
  "cdx-version": cdx([], { specVersion: "9.9" }),
  "cdx-etat": cdx([{ id: "CVE-2026-0001", analysis: { state: "maybe" }, affects: [{ ref: "pkg:npm/lib@1" }] }]),
  "cdx-sans-analyse": cdx([{ id: "CVE-2026-0001", affects: [{ ref: "pkg:npm/lib@1" }] }]),
  "cdx-ref-inconnue": cdx([{ id: "CVE-2026-0001", analysis: { state: "resolved" }, affects: [{ ref: "urn:cdx:x/1#c" }] }]),
  "cdx-justification": cdx([{ id: "CVE-2026-0001", analysis: { state: "not_affected", justification: "because" }, affects: [{ ref: "pkg:npm/lib@1" }] }]),
  "format-inconnu": JSON.stringify({ spdxVersion: "SPDX-2.3" }),
}
const res = {}
for (const [name, text] of Object.entries(cases)) {
  try {
    m.parseVexDocument(text)
    res[name] = "accepted"
  }
  catch (e) {
    res[name] = e instanceof m.VexFormatError ? e.code : `crash:${e?.message}`
  }
}
// Un document sain passe, avec sa référence CycloneDX résolue par bom-ref.
const good = m.parseVexDocument(cdx([{ id: "GHSA-aaaa-bbbb-cccc", analysis: { state: "false_positive", detail: "Faux positif." }, affects: [{ ref: "c1" }] }],
  { components: [{ type: "library", "bom-ref": "c1", name: "lib", purl: "pkg:npm/lib@1.0.0" }] }))
res.good = `${good.format}:${good.statements[0].status}:${good.statements[0].product}`
console.log(JSON.stringify(res))
' "$TS") > "$WORK/hostile.json"
h() { python3 -I -c 'import json, sys; print(json.load(open(sys.argv[1]))[sys.argv[2]])' "$WORK/hostile.json" "$1"; }
expect "document trop grand refusé" "$(h taille)" "E_VEX_TOO_LARGE"
expect "JSON invalide refusé" "$(h json)" "E_VEX_JSON"
expect "racine qui n'est pas un objet refusée" "$(h racine-tableau)" "E_VEX_FORMAT"
expect "profondeur excessive refusée" "$(h profondeur)" "E_VEX_TOO_DEEP"
expect "trop de déclarations refusé" "$(h declarations)" "E_VEX_TOO_MANY"
expect "trop de produits refusé" "$(h produits)" "E_VEX_TOO_MANY"
expect "document sans déclaration refusé" "$(h aucune-declaration)" "E_VEX_FORMAT"
expect "contexte OpenVEX étranger refusé" "$(h contexte-etranger)" "E_VEX_FORMAT"
expect "identifiant porteur d'une commande refusé" "$(h vuln-commande)" "E_VEX_VULN_ID"
expect "identifiant en chemin refusé" "$(h vuln-chemin)" "E_VEX_VULN_ID"
expect "identifiant avec saut de ligne refusé" "$(h vuln-controle)" "E_VEX_VULN_ID"
expect "identifiant avec caractère de direction refusé" "$(h vuln-direction)" "E_VEX_VULN_ID"
expect "identifiant absent refusé" "$(h vuln-absente)" "E_VEX_VULN_ID"
expect "purl avec espace refusé" "$(h purl-espace)" "E_VEX_PRODUCT"
expect "purl avec saut de ligne refusé" "$(h purl-saut)" "E_VEX_PRODUCT"
expect "schéma étranger refusé" "$(h purl-schema)" "E_VEX_PRODUCT"
expect "purl trop long refusé" "$(h purl-long)" "E_VEX_PRODUCT"
expect "purl vide refusé" "$(h purl-vide)" "E_VEX_PRODUCT"
expect "purl qui n'est pas une chaîne refusé" "$(h purl-objet)" "E_VEX_PRODUCT"
expect "statut inconnu refusé" "$(h statut-inconnu)" "E_VEX_STATUS"
expect "statut en majuscules refusé" "$(h statut-casse)" "E_VEX_STATUS"
expect "justification inconnue refusée" "$(h justification-inconnue)" "E_VEX_JUSTIFICATION"
expect "not_affected sans justification ni impact refusé" "$(h not-affected-nu)" "E_VEX_JUSTIFICATION"
expect "texte avec caractère de contrôle refusé" "$(h texte-controle)" "E_VEX_FIELD"
expect "texte d'un autre type refusé" "$(h texte-type)" "E_VEX_FIELD"
expect "CycloneDX de version inconnue refusé" "$(h cdx-version)" "E_VEX_FORMAT"
expect "état CycloneDX inconnu refusé" "$(h cdx-etat)" "E_VEX_STATUS"
expect "vulnérabilité CycloneDX sans analyse refusée" "$(h cdx-sans-analyse)" "E_VEX_STATUS"
expect "référence CycloneDX non résolue refusée" "$(h cdx-ref-inconnue)" "E_VEX_PRODUCT"
expect "justification CycloneDX inconnue refusée" "$(h cdx-justification)" "E_VEX_JUSTIFICATION"
expect "format inconnu refusé" "$(h format-inconnu)" "E_VEX_FORMAT"
expect "document CycloneDX sain lu (bom-ref résolue, false_positive → not_affected)" "$(h good)" "cyclonedx:not_affected:pkg:npm/lib@1.0.0"
if [[ -e /tmp/scanoria-b38-pwn ]]; then ko "une commande d'un document a été exécutée"; else ok "rien d'un document n'est exécuté"; fi

echo "b38-vex : $PASS ok, $FAIL échec(s)"
[[ $FAIL -eq 0 ]]
