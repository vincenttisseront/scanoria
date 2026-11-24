# Banc d'essai gitleaks (Scanoria)

Dépôt piégé, volontairement : les valeurs de `config/app.yaml` et `.env` sont
**fausses**, générées au hasard pour le banc d'essai (F12), et ne donnent accès
à rien. Elles sont exclues de l'analyse gitleaks du dépôt Scanoria par
`.gitleaks.toml` (`modules/<id>/testbed/` seulement).
