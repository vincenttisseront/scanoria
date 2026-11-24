<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Vincent Tisseront
-->

# Écrire un module Scanoria

Un module est un dossier `modules/<id>/` du dépôt. Il décrit un outil d'analyse
(ou une base, un service, un exécuteur de CI) que l'appliance installe à la
demande depuis le catalogue (`CLAUDE.md` § 4). Il contient :

```
modules/<id>/
  module.yaml          manifeste, validé par catalog/schema/module.schema.json
  testbed/             banc d'essai piégé (type scanner, obligatoire)
  tests/recorded.sarif sortie native enregistrée sur le banc d'essai (scanner)
```

Le schéma est l'autorité : ce document l'explique, `tests/b10-modules.sh` le
fait respecter. Il n'utilise que le sous-ensemble de mots-clés que comprend le
validateur de l'appliance (`scanoria/schema.py`), sans `$ref` ni `format`, car le
même schéma sert à `catalog/build.py` et au service root.

**Principe 8 : automatique par défaut.** Un module doit fonctionner sans aucun
réglage : chaque option a un défaut sûr, et l'administrateur ne confirme que ce
qui est risqué ou irréversible (licence restrictive, désinstallation).

## 1. Modules livrés

| id | Type | Catégories | Version | Licence | Base requise |
|---|---|---|---|---|---|
| `gitleaks` | scanner | secrets | 8.30.1 | MIT | — |
| `osv-scanner` | scanner | sca | 2.7.1 | Apache-2.0 | `osv-db` |
| `trivy` | scanner | sca, iac, container, secrets | 0.76.2 | Apache-2.0 | `trivy-db` |
| `trivy-db` | feed | sca, container | format 2 | Apache-2.0 (données : conditions des sources) | — |
| `osv-db` | feed | sca | format 1 | CC-BY-4.0 | — |
| `epss` | feed (exporté pour la console) | sca | format 1 | EPSS de FIRST (gratuit, attribution) | — |
| `kev` | feed (exporté pour la console) | sca | format 1 | CC0-1.0 | — |
| `git-fetch` | scanner (système) | system | 2.54.1 | GPL-2.0-only (Git) | — |
| `syft` | scanner | sbom | 1.57.2 | Apache-2.0 | — |
| `grype` | scanner | sca, sbom | 0.122.1 | Apache-2.0 | `grype-db` |
| `grype-db` | feed | sca | schéma 6 | Apache-2.0 (données : conditions des sources) | — |
| `dependency-track` | service | sbom, sca, licenses | 4.14.7 | Apache-2.0 | — |
| `dtrack-upload` | scanner | sbom | 1.0.0 | PSF-2.0 (image Python ; script de l'appliance AGPL) | module `dependency-track` |

`git-fetch` est un **module système** (catégorie `system`) : il n'analyse rien,
n'entre dans aucun profil, et `scanoria-runner` l'utilise pour cloner les dépôts
(§ 4.2). Les scanners qui lisent un dépôt le déclarent dans `requires.modules` :
il est installé automatiquement avec eux (G1).

Versions, empreintes d'images et licences relevées sur les dépôts amont le
2026-11-24. Les trois outils produisent du SARIF 2.1.0 natif : aucun
convertisseur n'est nécessaire.

## 2. Le manifeste champ par champ

| Champ | Obligatoire | Rôle |
|---|---|---|
| `id` | oui | `^[a-z0-9][a-z0-9-]{1,40}$`, égal au nom du dossier |
| `name`, `description.fr`, `description.en` | `name` oui | affichage dans la console (bilingue) |
| `type` | oui | `scanner`, `service`, `feed` ou `runner` (§ 4.1) |
| `categories` | oui | parmi `quality`, `sast`, `secrets`, `sca`, `iac`, `container`, `sbom`, `dast`, `lint`, `licenses`, `vuln-management`, `ci` ; sert aux profils par couverture (G7) |
| `license` | oui | `spdx` (expression SPDX), `url` (https), `restrictions` (`none`, `private-code-forbidden`, `no-redistribution`, `other`), `verified_at` (date de vérification sur le dépôt amont), `notes` |
| `upstream` | oui | `homepage`, `source` (https) |
| `image` | sauf `feed` | `registre/chemin@sha256:<64 hex>` : registre explicite (pas de nom court), **aucune étiquette** |
| `version` | oui | version de l'outil (ou du format pour un `feed`), utilisable dans un nom de fichier |
| `resources` | oui | `min_ram_mb`, `min_cpu`, `disk_mb` : l'installation est refusée en dessous (§ 11) |
| `hostname` | `service` | libellé DNS (`sonarqube` → `sonarqube.<appliance>`) ; `null` sinon |
| `requires` | oui | `modules` (ids non `feed`), `feeds` (ids `feed`), `appliance` (`>=X.Y.Z`) — G1 |
| `conflicts` | non | ids incompatibles — G1 |
| `needs` | non | `sysctl` (liste blanche, posés et retirés par le module, plus `nofile`/`nproc` pour un module permanent), `postgres` (base dédiée, § 4.3) |
| `options` | oui | schéma des paramètres (§ 3) — G3 |
| `options_i18n` | non | traductions des titres et descriptions d'options |
| `scan` | `scanner` | exécution (§ 4) |
| `outputs` | `scanner` | sorties déclarées : `sarif: {path, version: "2.1.0"}` et/ou `cyclonedx: {path, version: "1.x"}` — G2 |
| `testbed` | `scanner` | banc d'essai (§ 5) — F12 |
| `service` | `service` | `{port, health_path, units, volumes, env, secrets, backup}` (§ 4.3) |
| `feed` | `feed` | `{format, mount, max_age_days, source: {kind: oci\|https, ref}, schedule}` |
| `health` | non | commande de santé dans l'image |
| `upgrade` | non | `{policy: on-demand}` : mise à jour détectée, appliquée à la demande, sauvegarde préalable |

Tout champ inconnu est refusé, à tous les niveaux.

## 3. Options (G3)

`options` est un schéma JSON de type `object`, `additionalProperties: false`.
Chaque propriété :

- porte un `type` parmi `string`, `integer`, `number`, `boolean`, `array`
  (tableau de chaînes, avec `items`) ;
- a **obligatoirement** un `default`, conforme à la propriété (contrôlé par b10) ;
- peut utiliser `enum`, `minimum`/`maximum`, `minLength`/`maxLength`, `pattern`,
  `minItems`/`maxItems`/`uniqueItems`, `title`, `description`. Rien d'autre :
  la console génère le formulaire à partir de ce sous-ensemble ;
- a un nom `^[a-z][a-z0-9_]{0,40}$`.

Les traductions vont dans `options_i18n.<nom>.{fr,en}.{title,description}` ;
`title` et `description` du schéma servent de repli.

Les options sont validées et enregistrées à l'installation. À chaque analyse,
`scanoria-runner` fusionne les options installées et celles de la tâche, les
revalide contre ce schéma, puis remplace `{opt.<nom>}` dans `scan.command` (et
`scan.history_command`) par la valeur : booléen `true`/`false`, liste jointe par
des virgules, jeu de caractères `[A-Za-z0-9._,:=/@+-]` seulement, et jamais une
valeur commençant par « - » à la place d'un argument qui n'en commençait pas un.
Le banc d'essai (§ 5) utilise les valeurs par défaut.

## 4. Exécution d'un scanner (§ 6.4)

`scan.command` est l'argv complet : `command[0]` est passé en `--entrypoint`,
le reste en arguments. Le moteur lance le conteneur ainsi :

- `--network=none` (`scan.network: none`) ; `target` est réservé aux modules
  `dast` et à leur cible autorisée (§ 6.5) ;
- `--read-only`, `--cap-drop=ALL`, `--security-opt=no-new-privileges`,
  utilisateur 65534, limites mémoire, CPU et PIDs, délai `scan.timeout_s` ;
- sources en lecture seule sur `/src`, `/out` écrivable, `/tmp` en tmpfs ;
- chaque base de `requires.feeds` en lecture seule sur `/feeds/<id>`
  (`feed.mount`) ;
- variables d'environnement de `scan.env` (noms `^[A-Z][A-Z0-9_]*$`).

Le sous-ensemble du schéma ne sait pas contraindre les **noms** de clés
(`scan.env`, `needs.sysctl`, noms d'options) : ces règles sont vérifiées par
`tests/lib/modcheck.py` à l'intégration, et doivent l'être aussi par le service
root avant usage (principe 4).

`scan.exit_codes_ok` liste les codes de sortie normaux (OSV-Scanner sort en 1
quand il trouve des vulnérabilités). Les chemins de `outputs` doivent figurer
dans la commande. Aucun appel réseau : les outils sont lancés en mode hors
ligne (`--offline-vulnerabilities`, `--skip-db-update`…), et gitleaks masque
les secrets (`--redact`) pour que **leur valeur n'apparaisse jamais** dans la
sortie (§ 6.3).

Disposition des bases fournies :

| Base | Montage | Contenu |
|---|---|---|
| `trivy-db` | `/feeds/trivy-db` | répertoire de cache Trivy : `db/trivy.db`, `db/metadata.json` |
| `osv-db` | `/feeds/osv-db` | `osv-scalibr/<écosystème>/all.zip` (export OSV) |
| `epss` | aucun conteneur | `export.jsonl.gz` : `{vuln_id, epss, epss_percentile}` par CVE |
| `kev` | aucun conteneur | `export.jsonl.gz` : `{vuln_id, kev: true, kev_added}` par CVE |

**Bases exportées pour la console (0.5, contrat 17).** Un `feed` peut déclarer
`feed.export: {format: jsonl.gz}`. Après chaque mise à jour réussie, le helper
copie l'export de la base active dans
`/var/lib/scanoria/feeds-export/<id>.jsonl.gz` (root:scanoria 0640, `rename(2)`
atomique) ; la console l'importe dans `vuln_intel` par lots, de façon
idempotente, et ne lit jamais `/var/lib/scanoria/feeds/`. Une copie impossible
rend `E_EXPORT_FAILED`, la base restant active. Les formats `epss-csv` (CSV
compressé de FIRST) et `kev-json` (catalogue de la CISA) sont validés ligne
par ligne : une seule ligne invalide (colonne manquante, valeur hors de
[0, 1], CVE mal formée, doublon, date impossible, nombre annoncé faux) refuse
tout le fichier et garde la base précédente. Ces bases ne sont requises par
aucun scanner : elles alimentent le quality gate (H3) et les Résultats.

En 0.2, les modules `feed` sont déclaratifs (manifeste seulement) : leur mise à
jour planifiée et les lots hors ligne signés arrivent en 0.6 (§ 9).

### 4.1 Historique Git et gravités (0.3)

| Champ de `scan` | Défaut | Rôle |
|---|---|---|
| `history` | `shallow` | `full` : le scanner lit l'historique Git. Le runner fait alors un clone complet ; une option booléenne `history` à `false` le désactive pour un projet. |
| `history_command` | — | argv lancé à la place de `command` quand l'historique est lu ; exige `history: full`. Le dépôt Git est monté en lecture seule sur `/git` (`/src/.git` contient `gitdir: /git`) ; sans historique, `/git` n'est pas monté. |
| `severity_map` | — | gravité native → `critical`…`info`, lue par l'ingestion (G5). |

gitleaks déclare `history: full` : `gitleaks git` parcourt tous les commits d'un
dépôt, `gitleaks dir` reste utilisé pour une archive.

### 4.2 scanoria-runner (ARCHITECTURE § 12)

Service root, file `/var/lib/scanoria/scans/jobs/incoming/` alimentée par
`scanoria-worker`. Pour chaque tâche :

1. **Contrôles** : fichier régulier du compte `scanoria`, 0600, lien unique,
   256 Kio au plus, JSON strict conforme à `scan-job.schema.json`, identifiant
   égal au nom du fichier. Le fichier est déplacé dans `jobs/work/`, lu, puis
   supprimé aussitôt. Refus : `result.json` avec `E_JOB_INVALID` (`input`).
2. **Plan vérifié** : chaque module doit être sain, actif et à la version
   demandée dans le registre ; image, commande, délai, limites, sorties et
   bases viennent du manifeste. Absent : `missing` (`E_MODULE_MISSING`,
   `input`) ; options hors schéma : `E_OPTIONS_INVALID` ; module système ou
   entrée non lue (`repo`, `archive`) : refusé ou `skipped`.
3. **Source** (`fetch.py`) :
   - dépôt Git : conteneur jetable de l'image `git-fetch`, sans capacité,
     racine en lecture seule, utilisateur 65534, sur le réseau podman
     `scanoria-fetch` (10.89.250.0/24 par défaut, déclaré dans `share/scanoria/runner/fetch-network.conf`, sans DNS) ; le runner résout lui-même
     l'hôte de la forge (adresses de bouclage, lien local, multidiffusion et
     réseau de récupération refusées), passe l'adresse par `--add-host`, et
     ouvre dans la table nftables `inet scanoria_fetch` le seul triplet
     (conteneur, forge, port) le temps du clone. Git sans configuration
     système ni globale, `core.hooksPath=/dev/null`, `core.symlinks=false`,
     protocoles `https` et `ssh` seulement, sans sous-module ni redirection,
     `--no-tags`, profondeur 1 sauf historique. Jeton : variable
     d'environnement héritée par podman (jamais dans l'argv ni l'URL), lue par
     un assistant d'identification en ligne ; `GIT_ASKPASS=/bin/false`. Clé
     SSH : tmpfs `/run/scanoria/runner-cred/<id>/`, 0400, avec `known_hosts`
     strict. AC du système (`/etc/ssl/certs/ca-certificates.crt`) montée pour
     les forges à certificat d'entreprise ;
   - archive : seul fichier de `uploads/<upload_id>/` (`source.zip`,
     `source.tar`, `source.tar.gz`), reconnu par son en-tête, extrait sans
     lien ni fichier spécial (listés dans `source.skipped`) ; un chemin absolu
     ou avec « .. » refuse l'archive (`E_ARCHIVE_UNSAFE`) ;
   - bornes : 100 Mio par fichier (`size`), 4 Gio et 200 000 fichiers au total
     (`limit`) ; les fichiers écartés sont supprimés et listés (G15).
4. **Modules** : conteneur confiné (`testbed.confined_args`), sources en
   lecture seule sur `/src`, `/out` propre au module ; durée, pic mémoire
   (`memory.peak`) et temps CPU (`cpu.stat`) relevés dans le cgroup du
   conteneur ; journal stdout+stderr borné à 1 Mio, jeton masqué.
5. **Sorties** (G2) : lues sans suivre de lien, validées (SARIF 2.1.0 ou
   CycloneDX), copiées dans `results/<id>/<module>/` (0640 root:scanoria) ;
   `result.json` est écrit en dernier, validé contre `scan-result.schema.json`.

Classes d'erreur (G12) :

| Classe | Codes |
|---|---|
| `infra` (relancée par le worker) | `E_MODULE_TIMEOUT`, `E_MODULE_OOM`, `E_IMAGE_MISSING`, `E_PODMAN`, `E_RUNNER_RESTARTED`, `E_RUNNER_INTERNAL`, `E_SOURCE_NETWORK`, `E_SOURCE_TIMEOUT`, `E_SOURCE_RESOLVE`, `E_FETCH_NETWORK`, `E_DISK_FULL` |
| `tool` | `E_TOOL_EXIT`, `E_INVALID_OUTPUT` |
| `input` | `E_JOB_INVALID`, `E_MODULE_MISSING`, `E_MODULE_INVALID`, `E_OPTIONS_INVALID`, `E_INPUT_UNSUPPORTED`, `E_NETWORK_UNSUPPORTED`, `E_SOURCE_URL`, `E_SOURCE_REF`, `E_SOURCE_ADDRESS`, `E_SOURCE_AUTH`, `E_SOURCE_HOSTKEY`, `E_SOURCE_NOT_FOUND`, `E_SOURCE_FETCH`, `E_SOURCE_TOO_LARGE`, `E_FETCH_MODULE_MISSING`, `E_ARCHIVE_MISSING`, `E_ARCHIVE_INVALID`, `E_ARCHIVE_UNSAFE` |

Capacité : `/run/scanoria/runner.json` `{slots, busy, updated_at}`, avec
`slots` = (RAM − 3 Go réservés − services permanents) ÷ max(limite du plus gros
scanner actif, 1 Go du clone), borné à 1…8 et au nombre de CPU. Au démarrage,
une tâche interrompue est publiée en `E_RUNNER_RESTARTED` ; les résultats sont
purgés après 24 h. `scanoria-selftest` contrôle `runner.alive`.

Bornes et reprise : une tâche n'est admise que s'il reste 2 Gio libres ; un
clone (`/git` et `/src` réunis) est arrêté au-delà de 8 Gio ou si l'espace libre
passe sous 2 Gio. Une forge qui résout vers l'appliance n'est joignable que
sur le port 443 (proxy inverse, forge installée comme module). Une tâche dont
l'identifiant est déjà en cours ou déjà publié est écartée sans résultat. Au
démarrage, l'ensemble nftables `allow4` est vidé et les conteneurs
`scanoria-fetch-*` / `scanoria-scan-*` orphelins sont retirés.

### 4.3 Modules permanents : `service` et `runner` (0.4)

Le service root prend tout en charge ; le manifeste ne déclare que le besoin.

- **Réseaux.** Chaque module permanent reçoit un sous-réseau /24 du bassin
  `10.90.0.0/16` (`/usr/share/scanoria/modules/services-network.conf`) :
  réseau `scanoria-mod-<id>` (passerelle `10.90.N.1`, joignable par le proxy
  et par PostgreSQL) et réseau **interne** `scanoria-mod-<id>_scan`, sans
  sortie, pour dialoguer avec les conteneurs d'analyse.
- **Base PostgreSQL** (`needs.postgres: true`). Rôle et base `mod_<id>`
  (tirets remplacés par `_`), propriétaire unique, `PUBLIC` révoqué. Accès
  ouvert seulement depuis le sous-réseau du module
  (`/etc/postgresql/16/main/scanoria-modules-hba.conf`, inclus par
  `pg_hba.conf`, `scram-sha-256`), et par nftables du bassin vers le port 5432.
  PostgreSQL écoute alors sur toutes les interfaces
  (`conf.d/scanoria_modules.conf`) : il redémarre une seule fois, au premier
  module qui en a besoin, puis un simple rechargement suffit.
- **Variables** (`service.env`) : non secrètes, gabarits `{db_host}` (la
  passerelle), `{db_port}`, `{db_name}`, `{db_user}`, `{db_url_jdbc}`,
  `{hostname}`, `{host_port}`, `{opt.<nom>}`. `{db_password}` est refusé.
- **Secrets** (`service.secrets`) : valeurs aléatoires générées par le helper,
  jamais par la console ni le catalogue, fichiers root `0600` dans
  `/var/lib/scanoria/modules/<id>/secrets/`, transmis par secret Podman
  `scanoria-mod-<id>-<nom>` : monté sur `/run/secrets/<nom>`, ou, avec
  `env`, injecté **seulement** dans cette variable (pas de montage).
  `db-password` est créé d'office pour un module `needs.postgres`.
- **Réglages noyau.** `vm.max_map_count`, `fs.file-max`, `fs.inotify.*`,
  `net.core.somaxconn` : un fichier `/etc/sysctl.d/60-scanoria-<id>.conf`
  par module, valeur = maximum des modules installés et de la valeur
  courante (jamais abaissée) ; `nofile`/`nproc` deviennent des `Ulimit=`
  de l'unité. Toute autre clé est refusée (`E_SERVICE_RESOURCES`).
- **Ressources.** Un module `service` trop gros pour la machine est refusé
  avec `E_SERVICE_RESOURCES` (ressource, besoin, disponible, modules déjà
  installés).
- **Préparation** (`provision`). Après la santé, à l'installation et à
  chaque activation, le helper appelle le crochet `provision.run(m, info)`
  du module s'il existe (`{host_port, secrets_dir, network, timeout,
  phase}`) : création d'un jeton, branchement OIDC… Son échec annule
  l'installation.
- **Sauvegarde** (`service.backup`, sinon tous les volumes). Dans
  `/var/lib/scanoria/backups/modules/<id>/<horodatage>/` : `db.dump`
  (`pg_dump -Fc`), `volume-<nom>.tar` (module arrêté le temps de la copie)
  et `manifest.json` écrit en dernier (version, image, motif, empreintes
  SHA-256). Les 3 dernières sont gardées ; une sauvegarde incomplète est
  écartée. Faite d'office avant chaque mise à jour (motif `update`) et à la
  demande depuis la console (`backup-module`).
- **Restauration** (`restore-module`, confirmée dans une modale). Le helper
  revérifie le manifeste et chaque empreinte, refuse une sauvegarde d'une
  autre version (`E_BACKUP_INVALID`), arrête le module, recrée la base et
  les volumes, puis attend la santé.
- **Mise à jour.** Sauvegarde, nouvelle image, santé ; en cas d'échec,
  restauration de la sauvegarde et retour aux unités précédentes. Le journal
  des étapes (`backup`, `pulled`, `failed:…`, `restored`, `previous`) est
  rendu dans le résultat de la demande.
- **Consommation** (`modules_usage` de `state.json`, F14) : mémoire et CPU
  lus dans le cgroup de l'unité, disque = volumes + base (recalculé toutes
  les 15 minutes). Le CPU est `null` au premier relevé.
- **Désinstallation** sans conservation des données : base, rôle, secrets,
  volumes, réglages noyau et sauvegardes sont supprimés.

### 4.4 Fonctions optionnelles et variantes d'image (plugin de branches)

Un service peut offrir une **fonction optionnelle** fournie par une extension
tierce, par exemple l'analyse des branches et des PR de SonarQube Community
Build par le plugin libre
[sonarqube-community-branch-plugin](https://github.com/mc1arke/sonarqube-community-branch-plugin)
(LGPL-3.0, non maintenu par SonarSource). Une variante doit être libre et
sans restriction (`license.restrictions: none`, principe 1).

- `service.features: [branches]` déclare la fonction ; l'option booléenne du
  même nom (`options.properties.branches`, **vraie par défaut**, principe 8)
  la porte.
- `service.variants[]` la fournit : `image` (épinglée par empreinte, même
  application avec l'extension), `version` (de l'extension), `base_version`
  (doit égaler `version` du module), `license`, `upstream`, et `leaves`
  (fichiers que la variante dépose dans un volume, par préfixe dans un
  répertoire : `{volume: extensions, dir: plugins, prefix: sonarqube-community-branch-plugin}`).
- **Compatibilité** : une variante n'est retenue que si sa `version` partage
  la version majeure.mineure du module (règle du plugin) et si `base_version`
  est la version du module. `catalog/build.py` refuse une variante
  incompatible ; le helper la revérifie.
- Le helper stocke un **manifeste effectif** : l'image de la variante retenue
  et `active_variant`. Sans variante compatible, l'image d'origine est gardée
  et l'état publié dit pourquoi (`features.<nom>.code` : `disabled`,
  `incompatible`, `unavailable`), affiché sur la fiche du module.
- Une variante publiée **après** la version du module (plugin sorti après
  SonarQube) s'applique comme une mise à jour à la même version, sauvegarde
  comprise ; la console la propose d'elle-même.
- Avant de démarrer une image sans la variante (option coupée, nouvelle
  version sans plugin compatible), les `leaves` des variantes de l'ancien et
  du nouveau manifeste sont retirés du volume, par descripteurs et sans suivre
  aucun lien : un plugin laissé sans son agent Java empêcherait SonarQube de
  démarrer.
- Côté scanner, `scan.refs: default-branch` + `scan.refs_feature: branches` :
  sur une autre branche, le module n'est lancé que si le service a la fonction
  active ; le runner passe alors `SCANORIA_BRANCH` (référence raccourcie :
  `refs/heads/` et `refs/tags/` retirés), et `sonar_scan.py` ajoute
  `sonar.branch.name` puis lit issues et hotspots sur cette branche.
  Une étiquette (`refs/tags/v1.2`) est analysée comme une branche du même nom.
  `sonar_scan.py` sait déjà passer `sonar.pullrequest.*` depuis
  `SCANORIA_PR_KEY`, `SCANORIA_PR_BRANCH` et `SCANORIA_PR_BASE`, mais le runner
  ne les fournit pas encore : les PR arrivent avec leur analyse incrémentale
  (G18, 0.7). Les appliances antérieures ignorent `refs_feature` et restent
  sur la branche par défaut.
- Une installation antérieure à l'option (sans état publié) prend le défaut
  de l'option : la variante devenue compatible est proposée en mise à jour,
  et les scanners qui dépendent du service (sonar-scanner) reprennent alors le
  manifeste du catalogue à version et image égales (`refresh_dependents`).

**Épingler une nouvelle version du plugin** : relever l'empreinte de
`docker.io/mc1arke/sonarqube-with-community-branch-plugin:<version SonarQube>-community`,
revérifier la licence, remplir le gabarit commenté de
`modules/sonarqube/module.yaml`, incrémenter `catalog/VERSION`. `b17-live`
éprouve alors la variante déclarée (sinon la dernière image publiée du plugin).

### 4.5 SBOM : Syft, Grype, Dependency-Track (0.5, contrat 14)

- **Enchaînement dans une analyse** (`sbom.py`). Les producteurs de SBOM
  (sortie `cyclonedx`) passent en premier ; le premier SBOM obtenu est copié
  dans `sbom/sbom.cdx.json` de l'espace de travail. Un module
  `scan.prefers_sbom` (Grype) lance alors `scan.sbom_command` avec ce SBOM
  monté sur `/src` à la place du dépôt, exactement comme en re-corrélation
  (contrat 16) ; sans SBOM, il analyse le dépôt (`scan.command`). Un module
  `requires_sbom` (dtrack-upload) lit le SBOM sur `/sbom` ; sans SBOM, il est
  sauté (`E_SBOM_MISSING`). OSV-Scanner et Trivy gardent leur commande
  habituelle dans une analyse : leur `sbom_command` ne sert qu'à la
  re-corrélation. Un module `service_optional` sans son service est sauté
  (`E_SERVICE_MISSING`). L'ordre de la tâche est gardé dans le résultat.
- **Syft** produit du CycloneDX 1.6, sans réseau. La console range le SBOM
  dans `sbom_components` (au plus 50 000 composants, purl normalisé, licences,
  dépendance directe ou transitive, chemins) ; un SBOM invalide rend le
  module `invalid-output`, jamais une ingestion partielle. Les composants
  sans purl utilisable sont comptés dans la couverture (G15,
  `coverage.sbom.ignored_no_purl` / `ignored_invalid_purl`). L'export
  CycloneDX de l'onglet SBOM est régénéré depuis cette table (les sorties du
  runner sont purgées après 24 h).
- **grype-db** : le helper lit `latest.json` d'Anchore, télécharge l'archive
  (empreinte vérifiée), puis la prépare par `grype db import` dans un
  conteneur confiné sans réseau ; rien de téléchargé n'est exécuté et la
  mise à jour automatique de Grype est coupée (`GRYPE_DB_AUTO_UPDATE=false`).
- **Dependency-Track** (`dtrack.<appliance>`) : PostgreSQL, santé sur
  `/api/version`, sauvegarde de la base. Mise en service par le helper : mot
  de passe `admin` remplacé (gardé en `secrets/admin-password`, 0600),
  équipe « Scanoria (analyses) » limitée à `BOM_UPLOAD`,
  `PROJECT_CREATION_UPLOAD` et `VIEW_PORTFOLIO`, clé d'API en
  `secrets/scan-token`. Le service a besoin d'Internet pour ses miroirs de
  vulnérabilités (`service.egress`, déclaratif) ; le miroir hors ligne vient
  avec la 0.6.
- **dtrack-upload** (`network: service:dependency-track`, contrat 12) envoie
  le SBOM par `PUT /api/v1/bom` : un projet Dependency-Track par projet
  Scanoria (`scanoria-<12 hex>`), version = référence analysée. Il relit
  l'inventaire et le rend en CycloneDX avec la propriété
  `scanoria:dtrack:project` : la console relie l'analyse au projet et affiche
  le lien. Sans Dependency-Track, il est sauté (`E_SERVICE_MISSING`).

## 5. Banc d'essai (F12)

`testbed/` est un petit dépôt **piégé volontairement** : faux secrets de forme
reconnaissable, dépendance vulnérable connue, IaC fautive. Après
l'installation, le moteur y lance le scanner et vérifie `testbed.expect` ; le
module n'est activé que si toutes les attentes passent. Les canaris nocturnes
(G14) rejoueront le même banc.

```yaml
testbed:
  path: testbed/
  expect:
    - { rule: CVE-2021-44906, category: sca, min: 1 }
```

Une attente compte les résultats SARIF dont `ruleId` vaut `rule` (obligatoire :
une attente sans règle passerait sur n'importe quel bruit). `category` est une
étiquette pour le rapport. `min` vaut au moins 1.

Règles du banc d'essai :

- fichiers ordinaires seulement (ni lien, ni fichier spécial), noms en
  `[A-Za-z0-9._+@-]`, chemin relatif au module ;
- faux secrets **générés au hasard**, d'un format qui n'est pas celui d'un
  fournisseur réel protégé par le blocage des poussées de GitHub, et jamais
  de clé privée PEM ;
- le banc est exclu des contrôles du dépôt Scanoria lui-même, **et de rien
  d'autre** : `.gitleaks.toml` (`^modules/[^/]+/testbed/`), osv-scanner
  (`--x-exclude`), SonarQube Cloud (`sonar.exclusions`). dependency-review ne
  sait pas exclure un chemin : son `allow-ghsas` vaut pour tout le dépôt, et
  `tests/b10-modules.sh` le borne en échouant si `minimist` 1.2.5 apparaît dans
  un fichier de verrouillage hors des bancs d'essai.

Bancs livrés :

| Module | Piège | Attendu |
|---|---|---|
| `gitleaks` | `.env` et `config/app.yaml` : deux clés d'API et un JWT factices | `generic-api-key` ≥ 2, `jwt` ≥ 1 |
| `osv-scanner` | `package-lock.json` : `minimist` 1.2.5 | `CVE-2021-44906` ≥ 1 |
| `trivy` | même verrouillage npm, et un `Dockerfile` sans `USER`, en `latest`, avec `ADD` d'une URL | `CVE-2021-44906` ≥ 1, `DS-0002` ≥ 1 |

`tests/recorded.sarif` est la sortie native de l'outil sur son banc, enregistrée
à l'intégration (chemins ramenés à `/src`). Elle permet de tester le contrat de
sortie et les attentes sans conteneur.

## 6. Licences

Chaque module garde **sa propre licence** : il tourne, non modifié, dans son
conteneur, et n'est pas couvert par l'AGPL de l'appliance. À l'intégration et à
chaque version majeure, revérifier la licence sur le dépôt amont et mettre à
jour `license.verified_at`. Une restriction autre que `none` est affichée dans
la console et bloque l'activation tant que l'administrateur ne l'a pas acceptée
(`accept_licenses`, principe 1). Exemple : CodeQL, `private-code-forbidden`.

## 7. Ajouter ou mettre à jour un module

1. Relever **en amont, le jour même**, la version, l'empreinte de l'index OCI
   multi-architecture (`docker-content-digest` du manifeste de l'étiquette) et
   la licence. Ne jamais reprendre une version ou une empreinte de mémoire.
2. Écrire `module.yaml`, le banc d'essai et ses attentes.
3. Lancer l'outil sur le banc et enregistrer `tests/recorded.sarif`.
4. `bash tests/b10-modules.sh` (sans conteneur) ; le job CI
   `modules-testbed-live` (`tests/b10-live.sh`) lance chaque scanner en
   conteneur Podman confiné sur son banc et vérifie le code de sortie, la
   conformité au schéma SARIF 2.1.0 officiel, les attentes et l'absence de
   valeur de secret dans la sortie.
5. Le catalogue (`catalog/`) reprend le module à sa prochaine publication.
