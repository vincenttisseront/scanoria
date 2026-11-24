<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Vincent Tisseront
-->

# Composants tiers livrés dans l'ISO

Scanoria est distribué sous [AGPL-3.0-or-later](LICENSE). L'ISO d'installation
et les lots de mise à jour contiennent aussi des **composants tiers, non
modifiés**, qui gardent chacun leur licence. Cette page les liste pour la
version 0.1.

Elle sert d'information : le texte qui fait foi est celui livré avec chaque
composant.

- Paquets du système : `/usr/share/doc/<paquet>/copyright` sur l'appliance.
- Node.js : `/opt/scanoria/node/LICENSE`.
- Dépendances npm de la console : le fichier `LICENSE` de chaque paquet, ou le
  champ `license` de son `package.json`.

## Système de base

L'ISO repose sur l'image officielle d'**Ubuntu Server** publiée par Canonical,
non modifiée à part la configuration d'installation ajoutée. Elle comprend des
milliers de paquets sous licences libres (GPL, LGPL, MIT, BSD, Apache…).
Chaque paquet porte sa licence dans `/usr/share/doc/<paquet>/copyright`.
Les sources sont disponibles sur les dépôts publics de la distribution.
Scanoria n'est ni affilié à Canonical ni approuvé par elle.

## Paquets ajoutés par l'appliance

Ces paquets sont listés dans `src/iso/packages.list` et embarqués hors ligne
dans l'ISO. La colonne « Licence principale » donne l'information ; le
fichier `copyright` du paquet fait foi.

| Composant | Paquets | Licence principale |
|---|---|---|
| PostgreSQL 16 | `postgresql-16`, `postgresql-client-16` | PostgreSQL License |
| nginx | `nginx` | BSD-2-Clause |
| Podman | `podman` | Apache-2.0 |
| shadow (uidmap) | `uidmap` | BSD-3-Clause (et GPL-2.0-or-later pour certains fichiers) |
| slirp4netns | `slirp4netns` | GPL-2.0-or-later |
| catatonit | `catatonit` | GPL-2.0-or-later |
| nftables | `nftables` | GPL-2.0-only |
| jq | `jq` | MIT |
| Zstandard | `zstd` | BSD-3-Clause OR GPL-2.0-only |
| OpenSSL 3 | `openssl` | Apache-2.0 |
| curl | `curl` | curl (licence de type MIT) |
| Certificats racines | `ca-certificates` | MPL-2.0 (données), GPL-2.0-or-later (scripts) |
| Python 3 | `python3` | PSF-2.0 |
| newt (whiptail) | `whiptail` | LGPL-2.0-only |
| console-setup, kbd | `console-setup`, `kbd` | GPL-2.0-or-later |
| Fuseaux horaires | `tzdata` | domaine public |
| Locales (glibc) | `locales` | LGPL-2.1-or-later |

Les dépendances que ces paquets tirent viennent elles aussi de la
distribution, chacune avec son fichier `copyright`.

## Node.js

**Node.js 22** est installé dans `/opt/scanoria/node`, depuis l'archive
officielle `nodejs.org`, épinglée par empreinte dans
`src/iso/node-release.env`. Licence **MIT**. Les composants inclus dans
Node.js (V8, libuv, OpenSSL, ICU, npm…) gardent leur propre licence, reprise
dans `/opt/scanoria/node/LICENSE`.

## Console web

La console est construite avec Nitro (`webui/.output`). Elle embarque une
partie des dépendances npm de production de `webui/package.json` :

| Composant | Licence |
|---|---|
| Nuxt, Nitro, h3 | MIT |
| Vue, Vue Router | MIT |
| Nuxt UI, @nuxtjs/i18n | MIT |
| Tailwind CSS | MIT |
| zod | MIT |
| node-postgres (`pg`) | MIT |
| Icônes Lucide (`@iconify-json/lucide`) | ISC |

Ce qui est réellement livré est la sortie Nitro : le code de la console,
regroupé, et les modules npm que le serveur charge à l'exécution
(`webui/server/node_modules/` du lot). Pour la 0.1, ce sont une cinquantaine
de paquets : 46 sous MIT, 2 sous ISC, 1 sous BSD-2-Clause et 1 sous
BSD-3-Clause (relevé sur la construction du 2026-11-23 ; leur `package.json`
et leur `LICENSE` voyagent avec eux dans le lot).

L'arbre complet des dépendances de production (`npm ls --omit=dev --all`),
utilisé seulement pendant la construction, compte environ 850 paquets. Ils
sont pour l'essentiel sous MIT, ISC, Apache-2.0, BSD-2-Clause, BSD-3-Clause
ou BlueOak-1.0.0, avec quelques paquets sous MPL-2.0, 0BSD, CC0-1.0,
CC-BY-4.0 ou Python-2.0. Aucun n'est sous une licence incompatible avec
l'AGPL-3.0-or-later.

## Modules du catalogue

Les outils du catalogue (scanners, SonarQube, Dependency-Track…) **ne sont pas
dans l'ISO** : ils s'installent après coup, chacun dans son conteneur, non
modifié. Chaque module déclare sa licence dans son manifeste, et la console
l'affiche. L'AGPL de l'appliance ne les couvre pas.

### Outils livrés avec l'appliance pour un module

Le module `modelscan` (0.6, K8) n'a pas d'image publiée par son auteur. Ses
sources Python sont donc livrées **non modifiées** dans l'ISO, sous
`/usr/lib/scanoria/scan-tools/modelscan/vendor/`, avec leurs textes de
licence ; elles ne servent que dans le conteneur du module, une fois celui-ci
installé.

| Composant | Version | Licence |
|---|---|---|
| ModelScan (Protect AI) | 0.8.8 | Apache-2.0 ; `modelscan/tools/` (picklescan) : MIT |
| tomlkit | 0.13.3 | MIT |

### Données de vulnérabilités

Les bases `epss` et `kev` ne sont pas dans l'ISO : l'appliance les télécharge
après installation du module correspondant.

| Données | Fournisseur | Conditions |
|---|---|---|
| EPSS (probabilité d'exploitation) | FIRST.org | Diffusion gratuite, sans inscription ; attribution demandée dans les produits : « EPSS, FIRST.org », affichée dans les Résultats et la page À propos |
| Known Exploited Vulnerabilities | CISA | CC0-1.0 |
