# Banc d'essai du module fraim (K4)

- `app.py` : requête SQL construite par concaténation de l'entrée
  utilisateur ; le workflow « code » doit la relever (`fraim/code`).
- `main.tf` : seau de stockage ouvert en lecture et en écriture à tous, pour
  le workflow « iac » (non exigé par le banc : une seule attente, stable).
- `pr.diff` : la PR du banc (ajout de `app.py`), montée sur `/pr.diff` pour
  le workflow « risk_flagger ».

Code inerte : rien n'est exécuté, aucun nom réel.
