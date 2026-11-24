# Banc d'essai git-fetch (Scanoria)

Petit arbre de fichiers ordinaire : le banc d'essai en fait un dépôt Git dans
le conteneur, le clone en profondeur 1 avec la configuration imposée par le
runner (aucun hook, aucun lien symbolique, protocoles limités), puis vérifie
que chaque fichier est revenu à l'identique.
