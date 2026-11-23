<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Vincent Tisseront
-->

# Contribuer à Scanoria

## Licence des contributions

Scanoria est distribué sous **GNU Affero General Public License v3.0 ou
ultérieure** (`AGPL-3.0-or-later`, voir [LICENSE](LICENSE)). En proposant une
contribution (PR, correctif, documentation), vous acceptez qu'elle soit
publiée **sous cette même licence**. Vous déclarez aussi avoir le droit de la
soumettre.

Chaque fichier source commence par :

```
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Vincent Tisseront
```

Mettez cet en-tête dans la syntaxe de commentaire du fichier. Un code repris
d'un tiers garde sa licence d'origine, qui doit être compatible avec l'AGPL.
Il est alors listé dans [OPEN-SOURCE.md](OPEN-SOURCE.md).

## Règles du dépôt

- **Aucune référence réelle** : ni nom d'hôte, ni domaine, ni adresse, ni
  client, ni secret. Les exemples utilisent `exemple.test` et les plages
  RFC 5737 (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`).
- **Aucun secret, même factice.** Les clés et certificats de test sont
  générés à l'exécution. gitleaks bloque la CI au moindre doute.
- **Interface** : textes en français et en anglais. Toutes les boîtes de
  dialogue sont des modales de la console, jamais `alert` ou `confirm`. Toute
  action longue affiche un indicateur d'attente.
- **Branches** : `feat/…` ou `fix/…` depuis `main` à jour. Jamais de push
  direct sur `main`.
- **Commits** en français, au présent, préfixés par `feat:`, `fix:`, `ci:`,
  `docs:` ou `test:`.
- **Tests** : chaque changement arrive avec ses tests ([docs/TESTING.md](docs/TESTING.md)).
  Une PR n'est fusionnée (en *squash*) que si `ci-ok`, CodeQL (`analyze`) et
  le quality gate de SonarQube Cloud sont verts.
- **Contrats** : un changement de protocole, de chemin ou de format modifie
  d'abord [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) et les schémas de
  `src/rootfs/usr/share/scanoria/`, dans la même PR.

## Avant d'ouvrir une PR

```bash
cd webui && npm ci && npm run lint && npm run typecheck && npm run test && npm run build
cd .. && .github/scripts/run-batteries.sh
.github/scripts/check-repo.sh && .github/scripts/lint-shell.sh && actionlint
```

Pour une vulnérabilité, ne passez pas par une PR publique : voir
[SECURITY.md](SECURITY.md).
