<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Vincent Tisseront
-->

# Catalogue des modules : index signé

L'index du catalogue liste les modules disponibles, leurs versions, leurs
empreintes d'images et les packs (CLAUDE.md § 4.3, F11). Il est construit à
partir du dépôt, signé, et publié en release GitHub **indépendamment de la
console**, sous le tag `catalog-v<N>`.

| Fichier | Rôle |
|---|---|
| `VERSION` | Numéro entier N de l'index. Toute PR qui modifie `modules/` ou `catalog/` après publication de `catalog-v<N>` doit l'augmenter (contrôlé par `catalog.yml`). |
| `packs.yaml` | Packs (F11) : ensembles de modules par technologie, plus la sélection conseillée (§ 5.3). |
| `schema/index.schema.json` | Schéma de `catalog-index.json`, copié tel quel dans `src/rootfs/usr/share/scanoria/schemas/catalog-index.schema.json` (b11 vérifie l'identité). |
| `schema/packs.schema.json` | Schéma de `packs.yaml`. |
| `schema/module.schema.json` | Schéma d'un manifeste (chantier modules). |
| `build.py` | Construction et vérification. |
| `tests/fixtures/` | Manifestes fictifs de la batterie `tests/b11-catalog.sh`. |

Les schémas restent dans le sous-ensemble de JSON Schema que valide
`scanoria/schema.py`, le validateur sans dépendance de l'appliance : pas de
`$ref`, `$defs`, `patternProperties` ni `format`. Un mot-clé inconnu fait
échouer la construction.

## Construire et vérifier

```sh
SOURCE_DATE_EPOCH=$(git log -1 --format=%ct) python3 catalog/build.py build   # → out/catalog/
python3 catalog/build.py verify out/catalog --no-signature
python3 catalog/build.py verify DOSSIER --pubkey update-pubkey.pem --expect-version N
```

Dépendances de construction : Python 3.12, PyYAML (paquet `python3-yaml`
d'Ubuntu 24.04) et `zstd`. `build.py` ne tourne qu'en CI ou sur un poste de
développement, jamais sur l'appliance. Le YAML est lu par un chargeur
restreint : pas d'alias ni de clé en double, booléens limités à `true`/`false`
(`yes`, `no`, `on` et `off` restent des chaînes), dates laissées en chaînes,
un seul document par fichier.

`build` refuse :

- un manifeste non conforme au schéma, ou dont l'`id` diffère du répertoire ;
- une dépendance introuvable, une base citée dans `requires.modules` ou un
  module ordinaire dans `requires.feeds`, un cycle, un conflit à l'intérieur
  de l'ensemble requis par un module ou par un pack, un conflit qui vise un
  module absent (G1) ;
- un pack qui cite un module absent ou une base (F11) ;
- deux modules qui déclarent le même libellé DNS (`hostname`) ;
- un scanner sans banc d'essai, un banc d'essai qui contient un lien, un
  fichier spécial ou un nom hors de `[A-Za-z0-9._+@-]` (F12).

## Contenu publié

| Actif | Contenu |
|---|---|
| `catalog-index.json` | `{schema: 1, version: N, generated_at, modules, packs}`. Chaque module est son manifeste normalisé en JSON, avec `requires` (`modules`, `feeds`, `appliance` facultatif) et `conflicts` toujours présents, plus `testbed_archive` et `testbed_sha256` (`null` sans banc d'essai). Modules triés par identifiant, packs dans l'ordre de `packs.yaml`. Clés triées, UTF-8. |
| `testbed-<id>-<version>.tar.zst` | Banc d'essai du module : tar USTAR sous un unique répertoire `testbed/`, fichiers et répertoires seulement, `root:root`, modes `0644`/`0755`, date fixe (`SOURCE_DATE_EPOCH`), ordre trié, compression `zstd -19 -T1`. |
| `SHA256SUMS` | `catalog-index.json` en première ligne, puis les archives triées. |
| `SHA256SUMS.sig` | Signature Ed25519 brute (64 octets) de `SHA256SUMS`, par `.github/scripts/sign-assets.sh` avec la clé de mise à jour (`update-pubkey.pem`) : même clé et même procédé que le lot de la console. |

Deux constructions du même commit donnent les mêmes octets (même version de
`zstd`).

## Publication : `.github/workflows/catalog.yml`

| Travail | Contenu |
|---|---|
| `build` | Construit deux fois et compare, puis vérifie. Sur PR, contrôle le numéro. Sur `main`, publie seulement si le tag `catalog-v<N>` n'existe pas ; s'il existe et que le contenu construit (date mise à part) diffère de la release, le travail échoue : augmenter `catalog/VERSION`. |
| `ci-green` | Attend `ci-ok` réussi sur le commit (CLAUDE.md § 16). |
| `sign` | Après `ci-green`. Environment `release` (limité à `main`, secret `UPDATE_SIGNING_KEY`). Signe `SHA256SUMS` et vérifie avec `update-pubkey.pem` versionné. |
| `publish` | Revérifie tout (aucun fichier hors de `SHA256SUMS`), contrôle que le numéro est libre (brouillons compris), crée la release `catalog-v<N>` marquée *not latest* (`releases/latest` reste la console) avec exactement les fichiers listés, puis retélécharge et vérifie depuis les adresses publiques. |

Un numéro publié n'est jamais reconstruit : pour republier, augmenter
`catalog/VERSION`. La vérification côté appliance (rafraîchissement du
catalogue) est faite par le service root.
