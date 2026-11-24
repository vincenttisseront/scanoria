<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Vincent Tisseront
-->

# Paquets livrés tels quels avec l'outil modelscan

Copie **non modifiée** des sources Python de deux archives PyPI, pour le
module `modelscan` (K8). Protect AI ne publie aucune image de conteneur, et
le conteneur d'analyse n'a pas de réseau : ces sources sont montées en
lecture seule avec l'outil (`/scanoria/vendor`).

| Paquet | Version | Licence | Archive (sdist) | SHA-256 de l'archive |
|---|---|---|---|---|
| modelscan | 0.8.8 | Apache-2.0 (`modelscan/tools/` : MIT) | `modelscan-0.8.8.tar.gz` | `34b134084370eb9832e0a7571297c3054ebfbff9f005992fe6f28ffc10135514` |
| tomlkit | 0.13.3 | MIT | `tomlkit-0.13.3.tar.gz` | `430cf247ee57df2b94ee3fbe588e71d362a941ebb545dec29b53961d61add2a1` |

Relevées le 2026-11-24 sur pypi.org. Les textes de licence sont dans
`licenses/`. `SHA256SUMS` liste chaque fichier copié ; `tests/b29-ouverture.sh`
vérifie qu'aucun n'a été retouché ni ajouté.

## Mise à jour

1. Télécharger les nouvelles archives sdist depuis PyPI et comparer leur
   SHA-256 à celui affiché par PyPI ;
2. remplacer `modelscan/` et `tomlkit/` par le contenu des archives, sans
   rien modifier, puis régénérer `SHA256SUMS`
   (`find modelscan tomlkit -type f | LC_ALL=C sort | xargs sha256sum`) ;
3. mettre à jour ce tableau, la version du manifeste `modules/modelscan/module.yaml`,
   `OPEN-SOURCE.md` et revérifier les licences.
