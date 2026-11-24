# Banc d'essai (Scanoria)

Projet piégé, volontairement : `package-lock.json` fige `minimist` 1.2.5,
vulnérable (CVE-2021-44906, GHSA-xvch-5gv4-984h). Ne jamais l'installer ni le
corriger : le banc d'essai (F12) et les canaris nocturnes (G14) vérifient que
le scanner trouve encore ce cas connu. Ces fichiers sont exclus des contrôles
du dépôt Scanoria lui-même (osv-scanner, dependency-review, SonarQube Cloud).
