# Banc d'essai du module pr-agent (K2)

`pr.diff` est la PR du banc : elle ajoute `app.py`, dont la requête SQL est
construite par concaténation de l'entrée utilisateur. Le banc d'essai (F12,
I23) monte ce diff sur `/pr.diff` comme le runner pour une analyse de PR, et
attend au moins un point à revoir (`pr-agent/key-issue`). Code inerte : rien
n'est exécuté.
