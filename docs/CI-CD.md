<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Vincent Tisseront
-->

# Intégration continue et publication

La CI tourne sur GitHub Actions, sur des runners standard `ubuntu-latest`. Le
dépôt est public, donc ces runners sont gratuits et sans quota. **Aucun runner
auto-hébergé** : une PR externe y exécuterait du code.

## 1. Workflows

| Fichier | Déclencheurs | Rôle |
|---|---|---|
| `.github/workflows/ci.yml` | PR, push sur `main` | Lint, secrets, vulnérabilités, console, batteries, construction de l'ISO, SonarQube Cloud. Le contrôle **`ci-ok`** résume l'ensemble. |
| `.github/workflows/codeql.yml` | PR, push sur `main`, chaque semaine | CodeQL JavaScript/TypeScript et workflows, dans un seul travail **`analyze`**. |
| `.github/workflows/iso.yml` | push sur `main`, à la demande, chaque semaine | **Test de démarrage** : construction, installation dans QEMU/KVM, premier démarrage, `scanoria-selftest`, `/api/health` ([TESTING.md](TESTING.md#4-test-de-démarrage-de-liso)). |
| `.github/workflows/release.yml` | push sur `main` qui modifie `VERSION`, à la demande | Version candidate signée, publiée en **pré-version** ([RELEASING.md](RELEASING.md)). |
| `.github/workflows/promote.yml` | à la demande, `repository_dispatch` `scanoria-validation` | Promotion d'une candidate en version stable, ou rejet. |
| `.github/dependabot.yml` | chaque semaine | Mises à jour npm (`webui/`) et des actions. |

## 2. Travaux de `ci.yml`

| Travail | Contenu |
|---|---|
| `lint` | `check-repo.sh` vérifie que `VERSION`, `webui/VERSION` et `package.json` concordent, que le CHANGELOG a sa section, que `update-pubkey.pem` correspond à l'empreinte épinglée, qu'aucune clé privée n'est suivie et que les actions sont épinglées par SHA. Puis shellcheck sur tous les scripts shell (`lint-shell.sh`), actionlint, et `test-release-chain.sh` (signature et vérification avec des clés jetables). |
| `gitleaks` | Tout l'historique de toutes les branches (`fetch-depth: 0`, `--log-opts=--all`), avec les règles par défaut et **sans exception** pour un fichier versionné (`.gitleaks.toml`). |
| `osv-scanner` | Vulnérabilités connues des dépendances verrouillées (`webui/package-lock.json`…). Les exceptions sont datées dans `osv-scanner.toml`. |
| `dependency-review` | PR seulement : refuse une dépendance ajoutée qui porte une vulnérabilité de gravité modérée ou plus. |
| `console` | Dans `webui/` : `npm ci`, `npm run lint`, `npm run typecheck`, `npm run test` avec couverture lcov, `npm run build`, puis `npm run test:e2e`. Le tout contre un service `postgres:16` épinglé par empreinte, en locale `en_US.UTF-8`, avec `DATABASE_URL`. |
| `batteries` | `tests/bNN-*.sh` sans root (`run-batteries.sh`), hors `*-live.sh` ; les batteries qui demandent les sorties de construction (`b21`) sont sautées sans `SCANORIA_OUT`. Puis `b03` et `b04` relancées en root, pour leurs contrôles `nginx -t` et `nft -c`. |
| `iso-build` | `./build.sh --iso` dans un conteneur `ubuntu:24.04` neuf, sans démarrage. Puis les batteries de construction `b2x` et `b3x` avec `SCANORIA_OUT` : `b21` contrôle le lot et l'ISO produits (dont `install-local` du lot réel dans une arborescence de test), `b30` signe et vérifie le lot réellement produit avec des clés jetables. Le lot non signé est conservé 7 jours en artefact. |
| `sonarqube` | Analyse SonarQube Cloud avec la couverture de `console`, et attente du **quality gate** (`sonar.qualitygate.wait`). Sur une PR venue d'un fork, le jeton est absent : l'analyse est sautée avec un avis, puis faite après fusion. Partout ailleurs (push sur `main`, PR interne), un `SONAR_TOKEN` absent fait échouer le travail, donc `ci-ok`. |
| `ci-ok` | `if: always()`. Échoue si un travail a échoué, a été annulé ou a été sauté, sauf `dependency-review` hors PR. |

Les exécutions dépassées d'une même PR sont annulées (`concurrency`). Sur `main`, chaque commit a son groupe (SHA) et sa CI n'est jamais annulée : `release.yml` et `promote.yml` exigent un `ci-ok` réussi sur le commit exact.

## 3. Sécurité de la chaîne

- **Actions épinglées par SHA** de commit, avec la version en commentaire.
  `check-repo.sh` refuse une action non épinglée. Dependabot les met à jour.
- **Outils téléchargés** (gitleaks, actionlint, osv-scanner, shellcheck) :
  version et empreinte SHA-256 dans `.github/tools.env`, vérifiées par
  `install-tools.sh`. Ce fichier se met à jour à la main, dans une PR.
- **Droits minimaux** : `permissions: {}` au niveau du workflow, puis droits
  explicites par travail. Seul `publish` (release) et `promote` écrivent
  (`contents: write`). `persist-credentials: false` sur chaque checkout.
- **Entrées non fiables** (titres, `client_payload`, entrées manuelles) :
  passées aux scripts par l'environnement, jamais interpolées dans le code,
  puis validées par expression régulière.
- **Clé de signature** : secret `UPDATE_SIGNING_KEY` de l'environment
  `release`, limité à `main`. Seuls les travaux `sign-bundle` et `sign-iso`
  le lisent ([RELEASING.md](RELEASING.md#4-signature)).

## 4. Secrets, environments, réglages du dépôt

| Élément | Où | Usage |
|---|---|---|
| `SONAR_TOKEN` | secret du dépôt | travail `sonarqube` |
| `UPDATE_SIGNING_KEY` | secret de l'environment `release` | signature (`release.yml`) |
| environment `release` | *Settings → Environments*, branches : `main` seulement | travaux de signature |
| protection de `main` | *Settings → Rules → Rulesets* | PR obligatoire ; contrôles requis `ci-ok`, `analyze` (CodeQL) et quality gate SonarQube Cloud ; ni force-push ni suppression |

Dans SonarQube Cloud, l'*Automatic Analysis* doit être désactivée. Vérifier
aussi l'organisation et la clé de projet de `sonar-project.properties` : ces
valeurs sont à confirmer à la création du projet.

## 5. Durées indicatives

`console` : environ 5 à 10 min. `iso-build` : 20 à 40 min, dont le
téléchargement de l'ISO de base, mis en cache par l'empreinte des fichiers
`src/iso/*.env`. `iso.yml` : 60 à 120 min, installation comprise. Le test de
démarrage n'est pas dans `ci-ok` : il serait trop long pour chaque PR. Il est
refait par `release.yml` avant toute publication.

## 6. Mettre à jour un outil

1. Relever la version et l'empreinte dans le fichier de sommes publié par le
   projet (`…_checksums.txt`, `…_SHA256SUMS`).
2. Modifier `.github/tools.env` dans une PR.
3. Pour une action : `git ls-remote https://github.com/<propriétaire>/<action> refs/tags/<tag> 'refs/tags/<tag>^{}'`.
   Prendre le SHA du commit (ligne `^{}` pour un tag annoté).
