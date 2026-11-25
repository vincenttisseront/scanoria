<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Vincent Tisseront
-->

# Banc d'essai de kics (piégé volontairement)

IaC inerte, jamais appliquée : groupe de sécurité ouvert sur le port 22 à tout
Internet, compartiment S3 en lecture publique (`infra/main.tf`), Dockerfile
sans `USER` en étiquette `latest` (`infra/Dockerfile`).
