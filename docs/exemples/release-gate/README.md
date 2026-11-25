# Exemple : gate de release Scanoria

Fichiers d'exemple pour un dépôt qui fait passer ses releases par l'appliance
(`docs/RELEASING.md` § 7). Noms génériques seulement (`exemple.test`).

- `release.yml` : publie une version candidate (pré-version) à partir d'un tag ;
  l'appliance, en mode tiré, la détecte et pose le statut `scanoria/release-gate`.
- `promote.yml` : promotion manuelle d'une version candidate ; refusée tant que
  `scanoria/release-gate` n'est pas au vert sur le commit du tag, puis vérifie le
  rapport signé joint à la release avec `scanoria-verify`.
- `push-mode.yml` : variante en mode poussé, pour une CI qui joint l'appliance.

Variables du dépôt utilisées : `SCANORIA_URL` (par exemple
`https://analyse.exemple.test`), `SCANORIA_KEY_FINGERPRINT` (empreinte de la clé de
l'appliance, affichée dans la console) et, pour le mode poussé seulement,
`SCANORIA_PROJECT` et le secret `SCANORIA_TOKEN`.
