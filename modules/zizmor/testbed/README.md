<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Vincent Tisseront
-->

# Banc d'essai de zizmor (piégé volontairement)

Workflow GitHub Actions inerte, jamais lancé (`.github/workflows/triage.yml`) :
déclencheur `pull_request_target` qui récupère le code de la PR, titre de la PR
injecté dans un script, action non épinglée par empreinte, droits `write-all`.
