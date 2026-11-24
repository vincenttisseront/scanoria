# Banc d'essai du module sonar-scanner

Petit dépôt **volontairement fautif**, analysé après l'installation (F12) et
chaque nuit (G14). Rien ici n'est un vrai secret ni du code destiné à tourner.

- `app/db.py` : mot de passe en dur, TLS non vérifié, MD5, auto-affectation,
  conditions identiques, assert toujours vrai (règles du profil par défaut de
  SonarQube), plus une requête SQL formatée et une variable inutilisée que ce
  profil ne relève pas.
