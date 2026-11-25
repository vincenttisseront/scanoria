<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Vincent Tisseront
-->

# Banc d'essai de Bandit (piégé volontairement)

Code Python inerte, jamais exécuté (`svc/handlers.py`) : `subprocess` avec
`shell=True`, `pickle.loads`, `yaml.load` sans chargeur sûr.
