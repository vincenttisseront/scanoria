<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Vincent Tisseront
-->

# Sources livrées telles quelles avec l'outil vulnhuntr

Copie **non modifiée** du paquet Python `vulnhuntr/` du dépôt amont, pour le
module `vulnhuntr` (K3). Protect AI ne publie ni image de conteneur ni paquet
PyPI (le paquet PyPI du même nom est d'un autre auteur), et le conteneur
d'analyse n'a pas de réseau : ces sources sont montées en lecture seule avec
l'outil (`/scanoria/vendor`). Les dépendances sont dans l'image du module
(`modules/vulnhuntr/image/requirements.lock`).

| Projet | Version | Licence | Source |
|---|---|---|---|
| Vulnhuntr (Protect AI) | 0.1.0, commit `ead88c5adba4279dae5c56d65124c530a9a1c5ae` (2025-02-06) | AGPL-3.0 | dépôt `protectai/vulnhuntr`, branche `main` |

Relevé le 2026-11-25. Le texte de licence est dans `licenses/`. `SHA256SUMS`
liste chaque fichier copié ; `tests/b36-ia.sh` vérifie qu'aucun n'a été
retouché ni ajouté.
