<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Vincent Tisseront
-->

# Scanoria

Appliance d'analyse de code **on-prem**, livrée sous forme d'ISO. Elle
s'administre depuis une seule console web, en français et en anglais.

À l'installation, l'appliance ne contient que la console. Les outils libres
ou gratuits d'analyse s'ajoutent ensuite depuis un catalogue modulaire :

- qualité ;
- secrets ;
- vulnérabilités des dépendances ;
- SAST ;
- IaC ;
- conteneurs ;
- SBOM ;
- DAST.

Chaque application installée répond sur son propre nom, par exemple
`sonarqube.analyse.exemple.test`.

> État : itération **0.1** (socle), en cours. Le catalogue arrive en 0.2.

## Installer

1. Télécharger les morceaux de l'ISO d'une [release](../../releases), les
   reconstituer et vérifier la signature ([docs/RELEASING.md](docs/RELEASING.md#3-actifs-dune-release)).
2. Démarrer une VM sur l'ISO. Il faut au moins **2 vCPU, 4 Go de RAM et
   40 Go de disque**. L'installation est automatique et **efface le disque**.
3. Au premier démarrage, l'assistant demande le réseau, le nom de
   l'appliance, le fuseau, le clavier et les mots de passe. Il affiche ensuite
   l'adresse de la console et l'empreinte de son autorité de certification.

Les mises à jour arrivent ensuite par la console, signées.

## Documentation

- [Architecture](docs/ARCHITECTURE.md)
- [Tests](docs/TESTING.md)
- [CI et publication](docs/CI-CD.md)
- [Publier une version](docs/RELEASING.md)
- [Sécurité](docs/SECURITE.md)
- [Composants tiers](OPEN-SOURCE.md)
- [Contribuer](CONTRIBUTING.md)
- [Signaler une vulnérabilité](SECURITY.md)

## Construire

```bash
./build.sh --iso      # Linux, Docker ou Podman
.\make-iso.ps1        # Windows, Docker Desktop ou Podman
```

La construction se fait toujours dans un conteneur neuf.

## Licence

[AGPL-3.0-or-later](LICENSE) © 2026 Vincent Tisseront. La page *À propos* de
la console renvoie vers le code source de la version installée. Chaque module
du catalogue garde sa propre licence.
