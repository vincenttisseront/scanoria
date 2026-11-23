<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Vincent Tisseront
-->

# Politique de sécurité / Security policy

## Signaler une vulnérabilité

Merci de **ne pas ouvrir de ticket public**. Utilisez le signalement privé de
GitHub : onglet *Security*, puis *Report a vulnerability*. Merci d'indiquer :

- la version concernée (*À propos* dans la console, ou `VERSION`) ;
- les étapes de reproduction ;
- l'impact estimé.

Ne joignez aucune donnée réelle (noms d'hôtes, adresses, secrets) : utilisez
`exemple.test` et les plages de documentation RFC 5737.

Un accusé de réception est envoyé sous 7 jours. Le correctif sort dans une
nouvelle version : les numéros ne sont jamais reconstruits. Il est annoncé dans
le `CHANGELOG.md` une fois publié.

## Reporting a vulnerability

Please **do not open a public issue**. Use GitHub private vulnerability
reporting: *Security* tab, then *Report a vulnerability*. Please include:

- the affected version;
- steps to reproduce;
- the expected impact.

Do not include real host names, addresses or secrets.

## Versions maintenues / Supported versions

Seule la dernière version stable (`releases/latest`) reçoit les correctifs.
Mettez à jour depuis la console (*Mises à jour*).

Only the latest stable release receives fixes.

Le modèle de sécurité est décrit dans [docs/SECURITE.md](docs/SECURITE.md).
