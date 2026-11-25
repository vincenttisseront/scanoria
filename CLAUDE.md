# Scanoria — appliance d'analyse de code on-prem — contexte projet

> Fichier de contexte du dépôt, à la racine sous le nom `CLAUDE.md`.
> Nom du produit : **Scanoria** (affiché), `scanoria` (commandes, paquets, chemins, base de données). Les décisions encore ouvertes sont listées en section 14.

## 1. Objet

Une **appliance ISO, construite sur Ubuntu Server 24.04 LTS**. Elle installe sur une VM ou un serveur de l'entreprise **tous les outils gratuits d'analyse de code**, administrés depuis **une seule console web** :

- qualité ;
- secrets ;
- vulnérabilités des dépendances ;
- SAST ;
- IaC ;
- conteneurs ;
- SBOM ;
- DAST.

**À l'installation, l'appliance ne contient que la console web.** Chaque outil s'ajoute ensuite selon le besoin depuis un **catalogue modulaire**, où l'on peut aussi le mettre à jour, le désactiver ou le retirer. Chaque application installée est **accessible par son nom** (`sonarqube.<appliance>`…).

L'appliance analyse les dépôts Git de l'entreprise, réunit les résultats dans un format commun et applique des **quality gates**. La CI définie pour chaque dépôt fait passer **chaque release par tous les outils installés** : la release n'est publiée que si l'appliance rend un verdict favorable (section 7).

Besoin d'origine : n'utiliser **que des outils gratuits**, en SaaS gratuit ou déployés on-prem. Les dépôts **privés** ne doivent pas dépendre de services payants : SonarQube Cloud et CodeQL sont gratuits seulement pour le code public.

Hors périmètre initial : la haute disponibilité (un seul nœud) et le multi-tenant. **Changement de périmètre assumé le 2026-11-24** : l'IA, d'abord limitée à un cas isolé, couvre désormais tous les usages où elle aide (demande de Vincent). Elle n'est en revanche **jamais embarquée** dans l'appliance : elle passe par un **connecteur vers un serveur Ollama externe** de l'entreprise (section 3.5), et ses fonctionnalités (I1–I26 et modules d'analyse IA K1–K11, section 15) aident sans jamais décider à la place d'une personne ni d'un quality gate. Sans connecteur, ou serveur injoignable, l'appliance fonctionne à l'identique, hors ligne compris.

## 2. Principes non négociables

1. **Logiciels libres ou gratuits uniquement.** Chaque module déclare sa licence dans son manifeste. Une licence qui interdit l'usage sur du code privé ou la redistribution est signalée dans la console et bloque l'activation tant qu'elle n'est pas acceptée explicitement (section 5).
2. **On-prem et hors ligne possible.** Une appliance sans Internet fonctionne avec des **lots hors ligne signés** : images des modules et bases de vulnérabilités.
3. **Code générique.** Aucun nom d'infrastructure, de domaine ni de client réel dans le dépôt. Les exemples utilisent `exemple.test` et les plages de documentation (RFC 5737). Aucun fournisseur n'est imposé quand un standard existe : LDAP/AD, OIDC, forge Git quelconque.
4. **Frontière de privilèges.** La console web tourne **sans privilège**. Elle **dépose des demandes** (fichiers JSON dans un répertoire de demandes) qu'un service **root** valide strictement puis exécute : installation de module, unités systemd, pare-feu, mises à jour. Elle **lit** l'état publié par ce service. Le service root ne fait confiance à rien dans la demande.
5. **Isolation des analyses.** Le code analysé n'est jamais exécuté par défaut, et chaque scanner tourne dans un **conteneur jetable et confiné** (section 6.4).
6. **Tout ce qui est livré est signé**, avec une clé Ed25519 dont la clé publique est épinglée dans l'appliance : mises à jour de l'appliance, index du catalogue, lots hors ligne. Images de conteneurs **épinglées par empreinte** (`@sha256:`), jamais par étiquette.
7. **Règles d'interface permanentes** :
   - toute action un peu longue affiche un **indicateur d'attente** ;
   - toutes les **boîtes de dialogue sont des modales de la console**, jamais `alert`/`confirm` ;
   - la console est en **français et anglais** dès le départ.
8. **Automatique par défaut, configuration minimale.** Tout ce qui peut être déduit l'est : dépôts découverts dans la forge, profils et modules proposés selon le contenu détecté, bases mises à jour, analyses planifiées, tickets et PR de remédiation créés sans intervention. Chaque fonctionnalité arrive **activée avec des défauts sûrs** ; un réglage n'existe que si aucun défaut ne convient, et la console montre toujours ce qui a été décidé automatiquement et pourquoi. Seules les actions irréversibles ou à risque (installation d'un module, DAST actif, suppression, exception) demandent une confirmation.

## 3. Architecture

```
┌──────────────────────────── appliance (Ubuntu Server 24.04) ─────────────────────────────┐
│  nftables ─ proxy inverse TLS (nginx) ─┬─ console (Nuxt 4, Node 22, utilisateur dédié)     │
│                                        ├─ interfaces web des modules « service »            │
│                                        │    (SonarQube, Dependency-Track, DefectDojo…)      │
│  PostgreSQL 16 ── base de la console + bases des modules qui le permettent                 │
│  scanoria-helper (root) ── demandes de la console : modules (Quadlet), pare-feu, MàJ      │
│  scanoria-worker ── file d'analyses (PostgreSQL) → conteneurs scanners jetables (Podman)  │
│  Podman + Quadlet ── un module = une ou plusieurs unités systemd générées                  │
│  scanoria-ai ── file de tâches IA (PostgreSQL) ──HTTPS──▶ serveur Ollama externe (option)  │
└────────────────────────────────────────────────────────────────────────────────────────────┘
```

### 3.1 ISO et installation
- On part de l'ISO officielle Ubuntu Server 24.04 et on y ajoute une configuration **autoinstall** (cloud-init / Subiquity). L'installation se fait sans intervention, puis un **assistant au premier démarrage** (console texte) demande le réseau, le nom, le fuseau, le clavier et le mot de passe administrateur.
- Construction **reproductible dans un conteneur `ubuntu:24.04` neuf**, jamais sur la machine hôte. Lanceurs fournis : `build.sh --iso` (Linux), et `make-iso.ps1` (Windows, Docker Desktop ou Podman).
- Les paquets Ubuntu nécessaires hors ligne voyagent dans l'ISO. **Aucune image de module n'est embarquée** : l'ISO installe la console seule (section 5.3). Pour une appliance sans Internet, un **lot hors ligne signé** apporte les images des modules choisis (section 9).
- La communication du produit ne mentionne pas la distribution sous-jacente : on parle d'« appliance », jamais d'« Ubuntu 24.04 ».

### 3.2 Socle système
- **PostgreSQL 16** (paquets Ubuntu) : base `scanoria` pour la console, et une base par module qui sait utiliser PostgreSQL (SonarQube, Dependency-Track, DefectDojo).
- **Podman + Quadlet** pour tous les modules. Pas de Docker ni de compose en production : chaque module produit des fichiers `.container` / `.network` / `.volume` relus par le générateur Quadlet, donc pilotés par systemd.
- **nginx** en proxy inverse, aiguillage **par nom** (section 3.4). TLS avec un certificat émis par une **AC interne de l'appliance** (créée à l'installation, exportable pour les postes), ou un certificat importé.
- **nftables** : accès d'administration restreint à des réseaux déclarés ; les conteneurs scanners n'ont aucun réseau.
- Réglages noyau exigés par certains modules (SonarQube : `vm.max_map_count ≥ 524288`, `fs.file-max`, limites `nofile`/`nproc`) : posés par le module à son installation, dans `/etc/sysctl.d/`, et retirés à sa désinstallation.

### 3.3 Console web
- **Nuxt 4 + Nuxt UI**, serveur Nitro, **PostgreSQL** (requêtes SQL explicites, migrations numérotées et testées), validation **zod** de toutes les entrées.
- Authentification : comptes locaux (PBKDF2), **LDAP/AD** (LDAPS), **OIDC**. Rôles `viewer` / `operator` / `admin`, avec **journal d'audit** consultable : une ligne cliquable ouvre le détail dans un panneau latéral.
- Sections :
  - **Tableau de bord** ;
  - **Projets** (dépôts) ;
  - **Analyses** (file, historique, journaux) ;
  - **Résultats** (unifiés, filtres, statut de tri) ;
  - **Quality gates** ;
  - **Catalogue** (modules) ;
  - **Mises à jour** ;
  - **Sauvegardes** ;
  - **Système** (réseau, TLS, utilisateurs, connecteur IA, journal d'audit, À propos et licence).
- **API REST** documentée (OpenAPI) et jetons d'API par projet pour la CI.

### 3.4 Accès aux applications par nom
- L'appliance a un nom complet, par exemple `analyse.exemple.test`. La **console** répond sur ce nom.
- Chaque module `service` déclare un **libellé** dans son manifeste (`sonarqube`, `dtrack`, `defectdojo`…) et répond sur `<libellé>.<nom de l'appliance>`, par exemple `sonarqube.analyse.exemple.test`.
- **DNS** : un enregistrement générique `*.<nom de l'appliance>` vers l'adresse de l'appliance, en plus de l'enregistrement du nom lui-même. La console affiche les enregistrements à créer, **vérifie la résolution** avant d'activer un module, et signale un nom qui ne résout pas.
- En option, l'appliance crée elle-même les enregistrements par **mise à jour dynamique RFC 2136 signée TSIG** vers le serveur DNS de l'entreprise (BIND, DDI…). Elle ne dépend d'aucun produit DNS particulier.
- **Certificat** : l'AC interne émet un certificat pour `<nom>` et `*.<nom>`, renouvelé automatiquement. Un certificat importé doit couvrir les deux noms, et la console le vérifie.
- Le proxy n'expose que les modules installés et actifs. Un module désactivé renvoie une page d'erreur de la console, jamais l'application.

### 3.5 Connecteur IA : Ollama externe
L'appliance n'héberge aucun modèle. Elle appelle l'**API HTTP d'un serveur Ollama** de l'entreprise (`/api/version`, `/api/tags`, `/api/show`, `/api/chat`, `/api/embed`), sur le réseau local, ce qui reste compatible avec une appliance sans Internet.

**Mise en service (une seule saisie obligatoire, une seule confirmation)**
- La seule saisie obligatoire est l'**adresse du serveur** (`https://ollama.exemple.test:11434`, ou `http://192.0.2.10:11434` sur un réseau de confiance, avec un avertissement affiché). Optionnel : un jeton porteur pour un proxy placé devant Ollama (Ollama n'a pas d'authentification propre), qui **impose HTTPS**, et une AC à faire confiance ; ou, pour un certificat autosigné, la **vérification du certificat désactivée** (case explicite, vérification active par défaut, avertissement affiché dans le formulaire, la modale d'activation et l'état du connecteur ; jamais en même temps qu'une AC). Le jeton est chiffré en base. La vérification de la connexion affiche un indicateur d'attente.
- La console propose d'elle-même un serveur candidat si `ollama.<domaine de l'appliance>` résout et répond à `/api/version`.
- **Activer le connecteur est une action à risque** (des extraits de code quittent l'appliance) : une modale unique montre ce qui sera envoyé, à qui, et ce qui ne l'est jamais. Une fois confirmée, la console dépose une demande `set-ai-endpoint` : le helper root valide l'adresse (schéma, port, aucune adresse de bouclage ni de l'appliance), **résout lui-même le nom et épingle les adresses obtenues**, puis ouvre dans nftables la sortie vers ces adresses et ce port seulement, **pour l'UID de `scanoria-ai` seulement** (`meta skuid`). La console n'appelle jamais Ollama directement. Un changement de résolution n'élargit jamais la règle : il est signalé et demande une nouvelle confirmation. Retirer le connecteur referme la règle.
- Tout le reste est **automatique** (principe 8) : découverte des modèles par `/api/tags` et `/api/show` (capacités `completion`, `embedding`, taille du contexte), choix du modèle par tâche, contexte dimensionné à la demande, toutes les fonctionnalités IA activées avec leurs défauts. La console affiche le modèle retenu pour chaque tâche et pourquoi ; l'administrateur peut le changer, sans y être obligé. Si aucun modèle d'embedding n'est présent, les fonctions qui en ont besoin passent en recherche lexicale et le signalent.

**Exécution**
- Le service `scanoria-ai` (utilisateur dédié, sans privilège) traite une **file de tâches IA** en PostgreSQL : priorité aux demandes interactives, puis aux précalculs (résultats `critical`/`high` nouveaux, résumés d'analyse). Concurrence 1 par défaut, délai par tâche, relance avec recul exponentiel, **disjoncteur** quand le serveur ne répond plus.
- **Cache** : une sortie est rattachée à l'empreinte de son entrée et à l'empreinte du modèle (`digest` de `/api/show`) ; elle est réutilisée tant que les deux sont inchangés.
- Réponses **structurées** : chaque tâche fixe un schéma JSON passé à Ollama (`format`) puis revalidé par zod ; une sortie invalide est rejetée, jamais affichée à moitié.
- Langue de sortie : celle de l'utilisateur (français ou anglais), comme le reste de la console.

**Garde-fous (non négociables)**
- **L'IA ne décide rien** : elle n'entre pas dans le calcul d'un verdict, ne change jamais un statut de tri, ne crée ni n'approuve d'exception, ne fusionne ni ne ferme rien, n'enregistre aucun réglage ni aucune règle. Ces décisions passent par un clic d'une personne qui a le rôle requis, via l'API normale et l'audit. Les seules **écritures automatiques** permises, toutes réversibles et marquées IA, sont : un texte joint à un objet que l'appliance publie déjà (commentaire de PR I13 et I25, description de ticket I26, annexe de release I6) et une PR **brouillon** de correctif vérifié (I4). L'indisponibilité de l'IA ne rend jamais un verdict non concluant (G13 ne s'applique pas à elle).
- **Rien de secret ne sort** : les valeurs des secrets trouvés sont remplacées par leur forme (type, longueur, jeu de caractères) avant tout envoi, ainsi que tout ce qui ressemble à un secret dans l'extrait. Les secrets de la console (jetons de forge, clés) ne sont jamais transmis.
- **Code analysé = données hostiles** : il est délimité dans l'invite comme donnée, jamais comme instruction ; le modèle n'a **aucun outil** à effets ; la sortie est échappée (aucun HTML, liens limités à la console et aux références connues CWE/CVE/OSV), **dans la console comme dans tout ce qui est publié vers une forge ou un gestionnaire de tickets**, où les mentions (`@…`, `#…`) et les images sont en plus neutralisées.
- **Aucune exécution** : les recherches dans le code faites pour l'IA (I11, I22) utilisent des analyseurs sans exécution, dans le conteneur confiné d'une analyse (section 6.4).
- **Traçabilité** : chaque texte IA porte la mention « proposé par IA », le modèle et son empreinte ; chaque appel est journalisé (tâche, projet, taille envoyée, durée), sans le contenu par défaut.
- Un projet peut être marqué **« aucun envoi à l'IA »** ; c'est le seul réglage IA par projet, et il peut être imposé par un profil verrouillé (G8). Rien d'un tel projet n'est envoyé, même comme exemple ou contexte d'un autre projet.
- **Cloisonnement** : le contexte envoyé pour un projet ne contient que des données de ce projet ; les fonctions transverses (I7, I8, I21, I26) n'envoient que des métadonnées (règle, gravité, chemin, composant), jamais du code d'un autre projet.
- **Modules d'analyse par IA (K1–K11)** : un module qui appelle un LLM ne joint **jamais Ollama directement**. Son conteneur n'a de réseau que vers un **relais local compatible OpenAI** tenu par `scanoria-ai`, qui applique les mêmes garde-fous (masquage des secrets, « aucun envoi à l'IA », cloisonnement, journal, cache, disjoncteur). Ses résultats sont marqués **« IA »**, de niveau informatif, et **n'entrent jamais dans le verdict** tant qu'une personne ayant le rôle requis ne les a pas confirmés ; confirmé, un résultat devient un résultat normal. Sans connecteur, ces modules sont indisponibles et rien d'autre ne change. Les modules sans LLM (K7, K8, analyse YARA de K5 et K6) sont des scanners ordinaires.
- La **connexion unique** est souhaitée : les modules qui savent faire de l'OIDC (SonarQube, Dependency-Track, DefectDojo) sont branchés sur le fournisseur d'identité configuré dans la console.

## 4. Catalogue modulaire

### 4.1 Types de modules
| Type | Rôle | Exécution |
|---|---|---|
| `scanner` | outil en ligne de commande lancé par analyse (gitleaks, Trivy…) | conteneur **jetable** par analyse, sans réseau |
| `service` | application web permanente (SonarQube, Dependency-Track…) | unités Quadlet permanentes, derrière le proxy |
| `feed` | base de données de vulnérabilités ou de règles, à jour hors ligne | tâche planifiée ou import d'un lot signé |
| `runner` | exécuteur de CI auto-hébergé (section 8) | unité Quadlet, réseau sortant vers la forge seulement |

### 4.2 Manifeste d'un module
Chaque module est un dossier `modules/<id>/` du dépôt, avec un `module.yaml` validé par un schéma JSON lors de la CI :

```yaml
id: trivy
name: Trivy
type: scanner                     # scanner | service | feed | runner
categories: [sca, iac, container, sbom, secrets]
license: { spdx: Apache-2.0, url: https://…, restrictions: none }   # restrictions : none | private-code-forbidden | no-redistribution | other
upstream: { homepage: https://…, source: https://… }
image: ghcr.io/…/trivy@sha256:…   # épinglée par empreinte ; l'étiquette n'est qu'informative
version: "x.y.z"
resources: { min_ram_mb: 512, min_cpu: 1, disk_mb: 2000 }
hostname: null                    # type service : libellé DNS de l'application (« sonarqube » → sonarqube.<appliance>)
needs: { feeds: [trivy-db], sysctl: {}, postgres: false }
scan:                             # type scanner seulement
  inputs: [repo, archive, image, sbom]
  command: ["trivy", "fs", "--format", "sarif", "--output", "/out/result.sarif", "/src"]
  outputs: { sarif: /out/result.sarif }          # ou cyclonedx, ou format natif + convertisseur
  timeout_s: 900
  network: none
service: null                     # type service : unités, ports internes, chemin de santé, sauvegarde, migration de version
health: { command: ["trivy", "--version"] }
upgrade: { policy: on-demand }    # mises à jour détectées, appliquées à la demande, avec sauvegarde préalable
```

### 4.3 Cycle de vie d'un module
1. **Catalogue** : un index JSON **signé** liste les modules disponibles, leurs versions et leurs empreintes d'images. La console l'affiche, avec la licence, les restrictions, les ressources nécessaires et la compatibilité avec la machine (RAM, disque, sysctl).
2. **Installation** : la demande est déposée par la console. Le service root contrôle la signature et les ressources, récupère l'image (registre ou lot hors ligne), génère les unités, crée la base si besoin, puis attend la santé du module. **Retour arrière** automatique si le module ne devient pas sain.
3. **Mise à jour** : détectée, puis **lancée à la demande**, toujours précédée d'une sauvegarde du module (base et volumes). Retour arrière en cas d'échec de santé.
4. **Désactivation / désinstallation** : la désinstallation propose de garder ou supprimer les données (modale explicite, irréversible).
5. **Sauvegarde / restauration** par module, incluse dans la sauvegarde globale.

## 5. Catalogue initial

Toutes les versions sont **à épingler au moment de l'intégration**. Ne jamais reprendre une version de mémoire. Licence et restrictions sont **à revérifier** sur le dépôt amont à chaque intégration et à chaque montée de version majeure.

### 5.1 Modules
| Module | Type | Catégories | Licence (à revérifier) | Contraintes à connaître |
|---|---|---|---|---|
| **SonarQube Community Build** | service | qualité, SAST | LGPL-3.0 | **Branche principale seulement, pas d'analyse de PR**, sauf avec la variante « plugin de branches » (communautaire, LGPL-3.0, activée dès qu'une version compatible est épinglée) ; PostgreSQL ; `vm.max_map_count` ; ≥ 4 Go RAM pour lui seul |
| **gitleaks** | scanner | secrets | MIT | historique complet ; configuration d'exceptions par projet |
| **TruffleHog** | scanner | secrets | AGPL-3.0 | **vérification active des secrets désactivée** (aucun appel réseau) |
| **OSV-Scanner** | scanner + feed | SCA | Apache-2.0 | base OSV hors ligne ; exceptions datées par projet |
| **Trivy** | scanner + feed | SCA, IaC, conteneurs, SBOM, secrets | Apache-2.0 | base `trivy-db` hors ligne |
| **Syft + Grype** | scanner + feed | SBOM, SCA | Apache-2.0 | base Grype hors ligne |
| **OWASP Dependency-Track** | service + feed | SBOM, SCA, licences | Apache-2.0 | PostgreSQL ; reçoit les SBOM CycloneDX des analyses ; miroirs de vulnérabilités hors ligne |
| **Semgrep CE** / **Opengrep** | scanner | SAST | moteur LGPL-2.1 | règles officielles Semgrep : **usage interne seulement, redistribution interdite** → jamais embarquées dans l'ISO, téléchargées par l'administrateur ; Opengrep + règles maison en alternative |
| **Checkov**, **KICS** | scanner | IaC | Apache-2.0 | Terraform, Kubernetes, Dockerfile, Ansible… |
| **ShellCheck**, **hadolint**, **actionlint** | scanner | lint | GPL-3.0 / GPL-3.0 / MIT | rapides, sans base |
| **Bandit** | scanner | SAST Python | Apache-2.0 | — |
| **OWASP ZAP** | scanner | DAST | Apache-2.0 | **cibles autorisées seulement** (section 6.5) |
| **Nuclei** | scanner + feed | DAST | MIT | idem ; modèles épinglés |
| **DefectDojo** | service | gestion des vulnérabilités | BSD-3-Clause | optionnel : la console fait déjà l'unification ; utile pour un suivi avancé et des exports |
| **CodeQL** | scanner | SAST | **propriétaire (conditions GitHub)** | **interdit sur du code privé** sans licence payante : proposé seulement pour les projets déclarés open source (licence OSI), désactivé par défaut |

### 5.2 Lien entre catégories et modules
Une analyse lance des **profils**, et chaque profil est un ensemble de modules :

- `rapide` : gitleaks, OSV-Scanner, ShellCheck, actionlint ;
- `complet` : `rapide`, plus Trivy, Semgrep/Opengrep, Checkov, Syft → Dependency-Track, SonarQube si installé ;
- `conteneur` : Trivy image, Grype ;
- `dast` : ZAP, Nuclei, sur une cible autorisée.

L'administrateur peut créer ses propres profils.

### 5.3 Installation de base : la console seule
L'ISO installe la console, PostgreSQL, nginx, Podman, le service root et le pare-feu. **Aucun module n'est préinstallé.**

Au premier accès, la console propose le catalogue, avec une **sélection conseillée** : gitleaks, OSV-Scanner, Trivy, Syft/Grype, ShellCheck, actionlint, Checkov. Ces modules sont légers et sans service permanent. Rien n'est installé sans confirmation.

Les modules `service` (SonarQube, Dependency-Track, DefectDojo) s'installent après le contrôle des ressources et du DNS. Un profil ne référence que des modules installés, et le profil `complet` prend **tous les modules installés et actifs**.

## 6. Analyses

### 6.1 Projets
Un projet est un **dépôt Git** (HTTPS + jeton ou SSH + clé de déploiement, secrets chiffrés en base) ou une **archive téléversée**. Branches suivies, profil par défaut, exceptions (chemins, règles, vulnérabilités acceptées avec **motif et date de fin**), et quality gate.

### 6.2 Déclenchement
- À la main depuis la console.
- Planifié : quotidien, ou à chaque nouveau commit par interrogation de la forge.
- Par **webhook** de la forge (GitHub, GitLab ou Forgejo, signature vérifiée).
- Depuis une CI par l'**API** : `POST /api/projects/:id/scans {ref, profile}`, puis attente du verdict. Un petit client `scanoria-scan` (binaire statique ou script) rend le code de sortie du quality gate.

### 6.3 Résultats unifiés
- Chaque scanner produit du **SARIF 2.1.0** (ou du CycloneDX pour les SBOM). Un convertisseur testé est fourni pour les outils qui ne le font pas.
- Les résultats sont normalisés en base :
  - outil, règle, gravité normalisée (`critical`, `high`, `medium`, `low`, `info`) ;
  - fichier et ligne, empreinte stable de déduplication ;
  - premier et dernier commit où le résultat est vu ;
  - statut de tri : `nouveau`, `confirmé`, `faux positif`, `accepté jusqu'au …`, `corrigé`.
- La valeur d'un **secret** trouvé n'est **jamais** stockée : seulement l'emplacement, le type et l'empreinte.
- **Quality gate** par projet : seuils sur le nouveau code (aucun secret, aucune vulnérabilité ≥ seuil hors exceptions datées, aucun résultat SAST `high`…). Verdict exposé dans l'API, en badge, et en statut de commit envoyé à la forge si un jeton est fourni.
- Exports : SARIF fusionné, CycloneDX, rapport PDF ou HTML par analyse, envoi vers DefectDojo si le module est installé.

### 6.4 Confinement des scanners
Chaque analyse se déroule ainsi :

1. Récupération depuis le **miroir Git local** du projet (V2), ou clone **superficiel** à défaut, dans un répertoire de travail propre à l'analyse (en mémoire pour un petit dépôt, V9).
2. Conteneur Podman jetable :
   - `--network=none` (sauf type `dast`, et modules d'analyse IA qui ne joignent que le relais de `scanoria-ai`, section 3.5) ;
   - `--read-only` avec les sources montées **en lecture seule** sur `/src` et un `/out` écrivable ;
   - `--cap-drop=ALL`, `--security-opt=no-new-privileges` ;
   - utilisateur non root, limites mémoire, CPU et PIDs, délai maximal.
3. Le répertoire est **supprimé** après l'analyse.

Aucun build ni script du dépôt analysé n'est lancé. Un profil « avec construction » éventuel demande une activation explicite par projet, et tourne dans un conteneur jetable distinct, sans secret.

### 6.5 DAST
- Les cibles sont déclarées par un administrateur : URL, propriétaire, attestation d'autorisation.
- Liste blanche appliquée au niveau réseau : le conteneur DAST ne peut joindre **que** la cible.
- Mode passif par défaut, mode actif seulement sur confirmation explicite.
- Rien n'est scanné en dehors des cibles déclarées.

## 7. Releases passées par tous les outils (gate de release)

### 7.1 Principe
Chaque dépôt déclare, dans sa CI, que **ses releases passent par l'appliance**. Le profil `release` exécute **tous les modules installés et actifs** applicables au dépôt : scanners, SonarQube sur la branche principale, Dependency-Track pour le SBOM, DAST si une cible de recette est déclarée. Le quality gate du projet décide.

Une release candidate qui échoue n'est **pas publiée**, et la raison est rattachée au commit.

### 7.2 Deux modes d'intégration
| Mode | Pour | Fonctionnement |
|---|---|---|
| **Tiré** (recommandé, aucune exposition de l'appliance) | forge hébergée hors du réseau (GitHub…) dont les runners ne peuvent pas joindre l'appliance | L'appliance **interroge la forge** (tags, pré-versions, PR marquées) selon un planning, analyse, puis publie un **statut de commit** `scanoria/release-gate` (succès ou échec, lien vers le rapport). La règle de protection de la branche ou la promotion exige ce statut. C'est le même schéma que la validation AWX d'Ipnoria : requêtes sortantes seulement. |
| **Poussé** | CI qui tourne dans le réseau (Forgejo Actions, runner auto-hébergé) | La CI appelle `scanoria-scan --profile release --ref <tag> --wait`, et le code de sortie du client reflète le verdict du quality gate. |

### 7.3 Preuves jointes à la release
- **Rapport d'analyse de release** au format JSON : outils et versions exactes (empreintes d'images), âge des bases de vulnérabilités, résultats par gravité, exceptions appliquées (avec motif et date de fin) et verdict.
- Le rapport est **signé** par la clé de l'appliance et téléversable comme fichier de la release, avec le SARIF fusionné et le SBOM CycloneDX.
- Une commande `scanoria-verify rapport.json` vérifie la signature et l'empreinte du commit analysé.

### 7.4 Exemple : Ipnoria
L'appliance s'insère dans la chaîne existante :

1. `release.yml` publie la version candidate ;
2. l'appliance, en mode tiré, analyse le tag et pose le statut `scanoria/release-gate` ;
3. `promote.yml` n'accepte la promotion qu'avec ce statut au vert, **en plus** du verdict de l'instance de dev pilotée par AWX.

## 8. CI on-prem (modules `runner`)
- **Runner GitHub Actions auto-hébergé.** À n'utiliser que pour des **dépôts privés de l'entreprise**, jamais pour un dépôt public : une PR externe exécuterait du code sur l'appliance. La facturation GitHub des runners auto-hébergés en dépôt privé a changé plusieurs fois en 2026 (frais par minute annoncés puis reportés) : **à vérifier** avant de recommander ce module.
- **Forgejo + Forgejo Actions** (option entièrement on-prem) : un miroir du dépôt sur une forge interne et un runner local. Aucune dépendance à une facturation tierce.
- Chaque runner tourne dans un conteneur isolé avec un réseau sortant limité à la forge. Les jobs ne voient pas les données des autres modules.

## 9. Hors ligne et bases de vulnérabilités
- Les modules `feed` maintiennent les bases (OSV, `trivy-db`, Grype, miroirs NVD/GHSA pour Dependency-Track, modèles Nuclei) :
  - mise à jour planifiée quand Internet est disponible ;
  - sinon, **import d'un lot hors ligne signé** produit par une appliance Scanoria connectée (« exporter les bases »).
- La console affiche l'**âge de chaque base**, avec une alerte au-delà d'un seuil (par défaut 7 jours). Une analyse faite avec une base trop ancienne le signale dans son verdict.

## 10. Mises à jour, sauvegarde, observabilité
- **Mises à jour de la console et des scripts de l'appliance par les releases GitHub** du dépôt :
  - l'appliance interroge les releases (quotidiennement ou sur demande) et affiche dans la console la version disponible et ses **notes de version** (section du `CHANGELOG.md`) ;
  - l'archive est **signée** (Ed25519, `SHA256SUMS` signé, clé publique épinglée) et vérifiée avant toute installation ;
  - le dépôt étant **public**, l'appliance interroge l'API GitHub **sans jeton** ; en cas de limite de débit (`403`/`429`), elle se replie sur les adresses publiques de la release. L'import manuel d'une archive signée reste possible pour une appliance sans Internet ;
  - installation **à la demande** ou **planifiée dans une fenêtre de maintenance** ; jamais automatique sans réglage explicite ;
  - **sauvegarde** de la base et des fichiers remplacés avant l'installation, migrations de schéma appliquées, test de santé, **retour arrière automatique** si la console ne redémarre pas ;
  - **retour à la version précédente en un clic** (N-1 conservée) ;
  - canaux **`stable`** (défaut, `releases/latest`) et **`prerelease`** (instance de validation, bêta-testeurs ; jamais une version candidate rejetée) ;
  - **l'index du catalogue** est publié de la même façon, signé, avec son propre numéro, et mis à jour indépendamment de la console ;
  - les paquets système suivent `apt` (mises à jour de sécurité Ubuntu) ; un changement de Node.js ou de base système passe par une nouvelle ISO ;
  - même chaîne de publication que pour Ipnoria : CI complète, version candidate, validation sur une instance de dev, puis promotion ; ici le gate de release de l'appliance elle-même s'y ajoute (section 7).
- **Sauvegardes** :
  - quotidiennes et à la demande, base de la console, bases et volumes des modules, configuration ;
  - chiffrées, rétention configurable ;
  - destination locale, partage SMB/NFS ou S3 compatible ;
  - restauration testée par la CI.
- **Santé** : une photographie JSON par minute (services, PostgreSQL, disques, certificats, âge des bases, file d'analyses). Commande `scanoria-selftest` pour les tests de fumée après installation ou mise à jour.

## 11. Dimensionnement indicatif
| Usage | vCPU | RAM | Disque |
|---|---|---|---|
| Console seule | 2 | 4 Go | 40 Go |
| + sélection conseillée (scanners) | 4 | 8 Go | 80 Go |
| + SonarQube + Dependency-Track | 8 | 24 Go | 200 Go |
| + DefectDojo + DAST + runner | 8–12 | 32 Go | 300 Go |

L'installation d'un module `service` est refusée, avec un message clair, si la machine n'a pas les ressources déclarées dans son manifeste.

## 12. Dépôt, construction, tests, CI
```
build.sh                 # --iso | --bundle (mise à jour) | --stage ; construit dans un conteneur ubuntu:24.04 neuf
make-iso.ps1             # lanceur Windows
src/iso/                 # autoinstall, scripts de fin d'installation
src/rootfs/              # fichiers déposés sur le système : services systemd, scripts root (scanoria-helper, -worker, -selfupdate, -selftest…)
modules/<id>/            # module.yaml, gabarits Quadlet, convertisseur SARIF éventuel, tests du module
catalog/                 # génération et signature de l'index du catalogue
webui/                   # console Nuxt 4 (app/, server/, tests/)
tests/bNN-*.sh           # batteries shell : sans root (CI) ou « -live » (machine de test root, vrais conteneurs)
docs/                    # ARCHITECTURE, MODULES, SECURITE, TESTING, RELEASING, CI-CD
```
- **Tests** :
  - unitaires et **bout en bout** de la console contre un vrai PostgreSQL 16, dans la locale de l'appliance (`en_US.UTF-8`) ;
  - pour chaque module : validation du manifeste par le schéma, conversion SARIF sur des **jeux d'essai** (dépôts piégés : faux secrets, dépendances vulnérables, IaC fautive), installation et désinstallation `-live` ;
  - pour le service root : demandes hostiles (injections, chemins `..`, liens symboliques).
  - pour l'IA : un **faux serveur Ollama** en CI (réponses enregistrées, pannes, lenteurs, sorties invalides), tests de **masquage des secrets** avant envoi, d'**injection d'invite** depuis le code analysé, et vérification que chaque fonction de la console marche à l'identique sans connecteur.
- **CI GitHub Actions, dépôt public** : runners standard **gratuits et sans quota**. La CI reste raisonnable (annulation des exécutions dépassées sur une même PR, caches npm et images), mais n'a pas à économiser les minutes.
- **Outils** : lint shell et workflows (shellcheck, actionlint), gitleaks sur tout l'historique, osv-scanner avec exceptions datées, **dependency-review** sur les PR, **CodeQL** (JavaScript/TypeScript et workflows), **SonarQube Cloud** (gratuit pour un dépôt public, quality gate bloquant), alertes et mises à jour **Dependabot**. À partir de la 0.8, le verdict de Scanoria sur son propre dépôt s'y ajoute.
- Actions épinglées par empreinte, droits minimaux par travail ; contrôle unique **`ci-ok`** qui résume la CI.
- **Protections** (disponibles gratuitement pour un dépôt public) :
  - **règle de protection de `main`** : PR obligatoire, contrôles requis `ci-ok`, CodeQL et quality gate SonarQube Cloud, pas de force-push ni de suppression ;
  - **environment `release`** limité à `main`, qui porte la clé de signature : seuls les travaux de publication la lisent ;
  - dans les workflows : publication refusée hors de `main`, numéros de version jamais reconstruits ;
  - **jamais de runner auto-hébergé** sur ce dépôt : une PR externe y exécuterait du code.
- **Dépôt public, mais non annoncé** : rien dans le dépôt ne doit trahir une infrastructure réelle (principe 3), et aucun secret n'y entre jamais ; gitleaks bloque la CI au moindre doute.

## 13. Itérations
Chaque fonctionnalité retenue de la section 15 (F1–F20, G1–G20, H1–H10, I1–I26, J1–J16, K1–K11, V1–V10) est rattachée à une itération.

| Version | Contenu |
|---|---|
| 0.1 | **Socle** : ISO (console seule), assistant de premier démarrage, console (auth locale, rôles, audit, À propos et licence), PostgreSQL, pare-feu, nom de l'appliance, AC interne et certificat `<nom>` / `*.<nom>`. **Mise à jour en ligne par les releases GitHub (F18)**, `scanoria-selftest`, chaîne de publication (CI, version candidate, validation, promotion) |
| 0.2 | **Moteur de modules** : manifeste, catalogue signé publié en release, service root, Quadlet, aiguillage par nom et vérification DNS. **Banc d'essai à l'installation (F12)**, **packs (F11)**, **dépendances et conflits de modules (G1)**, **paramètres de module typés (G3)**. Premiers scanners : gitleaks, OSV-Scanner, Trivy |
| 0.3 | **Analyses** : projets Git avec **assistant d'ajout (F1)**, file d'analyses, confinement, résultats SARIF unifiés, tri, quality gate, API et client CI. **Suivi des secrets jusqu'à révocation (F7)**, **paquets malveillants bloquants (H4)**. Profils : **profils par couverture (G7)**. Catalogue : **contrat de sortie vérifié (G2)**, **normalisation des gravités (G5)**. Fiabilité : **analyses reproductibles (G11)**, **relances distinguées (G12)**, **échec par défaut (G13)**, **couverture d'analyse (G15)**, **ordonnancement (G17)**, **empreintes stables (G19)**. IA : **connecteur Ollama externe (I1)**, **explication d'un résultat (I2)**, **verdict expliqué (I9)**, **banc d'essai IA (I23)** |
| 0.4 | **SonarQube Community Build** (PostgreSQL, sysctl, proxy, sauvegarde, mise à jour à la demande). **Consommation réelle par module (F14)**, **santé des analyses (G20)**. IA : **pré-tri assisté (I3)**, **résumé d'analyse (I5)**, **typage des secrets génériques (I14)**, **diagnostic des analyses en échec (I15)**, **traduction des messages des outils (I17)**, **retours et qualité mesurée (I24)** |
| 0.5 | **SBOM** : Syft → Dependency-Track. **Politique de licences (F8)**, **recherche transverse CVE / composant avec re-corrélation (F3)**, **recoupement entre outils (F16)**, **priorisation EPSS + KEV (H3)**, **quarantaine des nouvelles versions (H5)**. IA : **regroupement sémantique (I7)**, **atteignabilité assistée (I11)**, **explication des licences (I18)** |
| 0.6 | **Hors ligne et vigilance** : modules `feed`, lots signés, âge des bases. **Appliance miroir (F17)**, **mise à jour d'outil à l'essai (F13)**, **alertes sur l'appliance elle-même (F19)**, **canaris nocturnes (G14)**, **fraîcheur obligatoire (G16)**, **version de module figée par projet (G6)**. IA : **diagnostic de l'appliance (I16)**. **Résultats externes acceptés (J6)**. Analyse de l'IA : **ModelScan (K8)**. Délais : **images préchargées (V1)**, **miroir Git local (V2)**, **SBOM unique partagé (V3)**, **résultats réutilisés (V4)**, **ordonnancement par durée mesurée (V5)**, **outils lancés selon le contenu (V6)**, **bases partagées en lecture seule (V7)**, **travail en mémoire (V9)**, **cache SonarQube (V10)**, batterie de mesure des délais en CI |
| 0.7 | **SAST/IaC étendus** (Semgrep/Opengrep, Checkov, KICS, Bandit), profils personnalisés, webhooks et statuts de commit. **Tri en masse (F4)**, **exceptions soumises à approbation (F5)**, **affectation `CODEOWNERS` (F6)**, **analyse incrémentale des PR (G18)**, **jeux de règles gérés dans la console (G4)**, **héritage et verrouillage des profils (G8)**, **profil par déclencheur (G9)**, **aperçu d'un profil (G10)**, **audit des workflows CI (H1)**, **posture des dépôts (H2)**, **revue des dépendances en PR (H6)**. IA : **recherche en langage naturel (I8)**, **rédaction des exceptions (I10)**, **générateur de règles (I12)**, **commentaires de PR expliqués (I25)**. Intégration : **application de forge en un clic (J1)**, **reprise de l'existant (J5)**, **annotations ligne à ligne dans la PR (J7)**, **configuration en code (J8)**, **acceptation depuis la PR (J15)**. Outils d'analyse par IA et du code IA : **PR-Agent (K2)**, **Vulnhuntr (K3)**, **Fraim (K4)**, **Cisco MCP Scanner (K5)**, **Cisco Skill Scanner (K6)**, **Agentic Radar (K7)**, et le relais de `scanoria-ai`. Délais : **verdict défavorable anticipé (V8)** |
| 0.8 | **Gate de release** : profil `release`, modes tiré et poussé, rapport de release signé, `scanoria-verify`. **Comparaison entre releases (F2)**, **simulateur de quality gate (F9)**, **VEX (H7)**. Branchement sur Ipnoria. IA : **notes de sécurité de release (I6)**, **seuils de quality gate suggérés (I19)**. Intégration : **PR d'intégration automatique (J2)**, **modèles CI officiels (J3)**, **CI sans secret par OIDC (J4)**, **attestations pour le déploiement (J9)**. Déploiement après verdict favorable : **déclenchement de la CD existante (J11)**, **promotion GitOps (J12)**, **promotion dans le registre (J13)**, **chaîne autonome PR → scan → déploiement (J16)** |
| 0.9 | **Runners CI** (Forgejo Actions, runner GitHub pour dépôts privés). **Notifications et rapport mensuel (F10)**, **kit développeur (F20)**, **remédiation automatique (H8)**, **tickets synchronisés (H9)**. IA : **correctif proposé et vérifié (I4)**, **évaluation des PR de remédiation (I13)**, **rapport mensuel commenté (I20)**, **assistant « Demander à Scanoria » (I21)**, **tickets rédigés et dédupliqués (I26)** |
| 0.10 | **DAST** (ZAP, Nuclei) avec cibles autorisées ; DefectDojo optionnel. **Catalogue privé et SDK de scanner (F15)**, **surveillance du registre interne (H10)**. IA : **cartographie de la surface d'attaque (I22)**. **Recette éphémère et DAST avant production (J14)**. DAST des applications LLM : **garak (K9)**, **promptfoo (K10)** ; test d'intrusion par agent IA : **Xalgorix (K11)** |
| 1.0 | LDAP/AD, OIDC et connexion unique aux modules, sauvegardes distantes, durcissement, documentation complète. **Raccordement à la supervision (J10)** |

## 14. Décisions
**Prises**
- **Accès aux applications par nom** : `<libellé>.<nom de l'appliance>`, avec un DNS générique et un certificat générique (section 3.4).
- **Installation de base = console seule** : tout outil s'ajoute par le catalogue, et aucune image n'est embarquée dans l'ISO (section 5.3).
- **Releases passées par tous les outils** installés, via la CI de chaque dépôt (section 7).
- **Fonctionnalités F1 à F20, G1 à G20, H1 à H10, I1 à I26 et J1 à J16 retenues** (section 15), réparties dans les itérations (section 13).
- **Dépôt GitHub public, sans aucune communication** (« non publié ») : CI, CodeQL, SonarQube Cloud, protection de `main` et environments gratuits ; mises à jour des appliances sans jeton. Conséquences : sections 10 et 12.
- **Claude gère tout le cycle Git** : branches, commits, push, PR, merges, versions et suivi des publications, selon les règles de la section 16.
- **Mises à jour de la console par les releases GitHub** dès la 0.1 (section 10, F18).
- **Nom : Scanoria.** Pas de publication ni de communication publique pour l'instant : aucun nom de domaine à réserver.
- **Licence : AGPL-3.0-or-later**, titulaire Vincent Tisseront (comme Ipnoria). Conséquences à appliquer dès la 0.1 :
  - texte intégral dans `LICENSE` à la racine (visible sur GitHub), en-tête SPDX `AGPL-3.0-or-later` dans les fichiers sources, champ `license` du `package.json` ;
  - l'appliance s'utilise par le réseau : l'**article 13** impose d'offrir le code source aux utilisateurs. La page « À propos » affiche la licence et un **lien vers le code source de la version installée** (tag GitHub du dépôt public) ;
  - `OPEN-SOURCE.md` liste les composants tiers livrés dans l'ISO et leurs licences. Chaque module du catalogue garde **sa propre licence**, déclarée dans son manifeste et affichée dans la console : il tourne dans son conteneur, non modifié, et n'est pas couvert par l'AGPL de l'appliance ;
  - les contributions externes sont acceptées sous la même licence (mention dans `CONTRIBUTING.md`).

- **D4 — Forge intégrée en premier : Forgejo** (gratuit, tout on-prem). L'appliance sait d'abord analyser les dépôts d'une forge Forgejo ; GitHub, puis GitLab suivent. Le développement de Scanoria lui-même reste sur GitHub (section 12).
- **D6 — Planchers matériels** : console seule **2 vCPU / 4 Go / 40 Go**, installation refusée en dessous (section 11). Pour chaque module, son manifeste fait foi.
- **Automatique par défaut, configuration minimale** (principe 8, 2026-11-24) : exigence de Vincent en retenant H1–H10, applicable à toutes les fonctionnalités.
- **IA par un Ollama externe** (2026-11-24) : l'IA n'est plus hors périmètre ; aucun modèle embarqué, connecteur vers l'API HTTP d'un serveur Ollama de l'entreprise, une seule saisie obligatoire (l'adresse), activation confirmée une fois, puis tout automatique ; l'IA propose et explique, ne décide jamais ; appliance identique sans elle (section 3.5, I1–I26).
- **Signature des mises à jour : clé Ed25519**, clé publique versionnée dans `update-pubkey.pem` à la racine, épinglée dans l'appliance. La clé privée vit hors ligne et dans le secret `UPDATE_SIGNING_KEY` de l'environment `release` (limité à `main`) ; Claude ne la voit jamais.

- **Outils d'analyse par IA K1–K11 et optimisations des délais V1–V10** (2026-11-24, demande de Vincent). Glev.ai, demandé en exemple, est une plateforme commerciale en SaaS, non open source : écartée (ses apports sont déjà couverts par F16, I7, I11 et I26). Xalgorix (K11) ajouté le 2026-11-25 comme module DAST facultatif de la 0.10, avec les mêmes garde-fous. **Kodus (K1) écarté le 2026-11-25** (décision de Vincent, étude `docs/ETUDE-K1-KODUS.md`) : une partie du code sous licence propriétaire, un jeton d'écriture administrateur sur chaque dépôt, trop lourd pour le plancher D6 ; PR-Agent (K2) assure la revue IA des PR. Écartés aussi : Snyk agent-scan (compte et jeton Snyk obligatoires) et OSS-Fuzz-gen (modèles hébergés seulement, compile et exécute le code).

**Ouvertes**
- Aucune à ce jour.

## 15. Fonctionnalités retenues (F1–F20, G1–G20, H1–H10, I1–I26, J1–J16, K1–K11, V1–V10)

### Console
| # | Fonctionnalité | Ce qu'elle doit faire |
|---|---|---|
| F1 | Assistant d'ajout de dépôt | Détecte langages, gestionnaires de paquets, Dockerfile, Terraform/Kubernetes/Ansible, workflows CI ; propose les modules pertinents (installés ou à installer) et un profil ; rien n'est installé sans confirmation |
| F2 | Comparaison entre deux releases | Entre deux tags ou analyses : résultats introduits, corrigés, inchangés, par outil et par gravité ; exportable dans le rapport de release |
| F3 | Recherche transverse CVE / composant | « Qui utilise tel composant, telle version, tel CVE ? » sur tous les projets ; à chaque mise à jour d'une base, les SBOM existants sont recomparés **sans réanalyse** et les nouveaux projets touchés sont signalés |
| F4 | Règles de tri en masse | Règles par chemin, outil, règle ou gravité (ex. `tests/**` → faux positif), avec justification et date de fin obligatoires ; effet simulé avant application ; tracé dans l'audit |
| F5 | Exceptions soumises à approbation | Un opérateur demande, un administrateur approuve ou refuse ; échéance notifiée avant expiration ; une exception expirée redevient bloquante |
| F6 | Affectation par `CODEOWNERS` | Les résultats sont affectés aux responsables lus dans `CODEOWNERS` (ou une table de correspondance) ; vue « mes résultats » |
| F7 | Suivi des secrets jusqu'à révocation | États `à révoquer` → `révoqué` / `faux positif`, date et auteur ; relance tant qu'un secret n'est pas révoqué ; **jamais la valeur du secret** |
| F8 | Politique de licences | Listes de licences autorisées, à revoir ou interdites, appliquées aux SBOM ; violations intégrées au quality gate |
| F9 | Simulateur de quality gate | Rejoue des seuils candidats sur l'historique des analyses (« combien de releases auraient été bloquées ? ») avant de les enregistrer |
| F10 | Notifications et rapport mensuel | SMTP et webhook générique **signé** (HMAC) ; abonnements par projet et par événement ; rapport mensuel PDF (tendances, dette, délais de correction) |

### Catalogue
| # | Fonctionnalité | Ce qu'elle doit faire |
|---|---|---|
| F11 | Packs | Ensembles de modules par technologie (Node, Python, Java, IaC, conteneurs), installés en une opération avec contrôle global des ressources |
| F12 | Banc d'essai à l'installation | Chaque module livre un jeu d'essai piégé (faux secrets, dépendances vulnérables, IaC fautive) ; après installation, il est analysé et le résultat attendu est vérifié ; le module n'est activé que si le banc d'essai passe |
| F13 | Mise à jour d'outil à l'essai | La nouvelle version tourne en parallèle de l'ancienne sur les dernières analyses ; l'écart (nouveaux résultats, résultats disparus, durée) est affiché ; adoption ou abandon en un clic |
| F14 | Consommation réelle par module | RAM, CPU, disque et durée moyenne d'analyse mesurés ; modules inutilisés depuis N jours signalés, avec suggestion de retrait |
| F15 | Catalogue privé et SDK | Un kit pour empaqueter un scanner maison (manifeste, image, convertisseur SARIF, jeu d'essai) ; catalogue privé signé par une **clé de l'entreprise**, ajoutée explicitement par un administrateur, à côté du catalogue officiel |
| F16 | Recoupement entre outils | Un même problème trouvé par plusieurs outils (CVE + composant, règle CWE + emplacement) est fusionné, avec un indice de confiance selon le nombre d'outils qui le confirment |
| F17 | Appliance miroir | Une appliance connectée publie le catalogue, les images et les bases pour des appliances hors ligne : exportation périodique d'un lot signé, ou service de miroir interne |

### Plateforme
| # | Fonctionnalité | Ce qu'elle doit faire |
|---|---|---|
| F18 | Mises à jour par les releases GitHub | Voir section 10 : signature, notes de version, canaux, fenêtre de maintenance, sauvegarde, retour arrière automatique et retour à N-1 en un clic |
| F19 | Alertes sur l'appliance elle-même | SBOM de la console et des images de modules installées, recomparés chaque jour aux bases ; alerte « module X vulnérable, mise à jour disponible » |
| F20 | Kit développeur | Téléchargeable depuis la console : hook pre-commit gitleaks avec la configuration du projet, client `scanoria-scan` local, réglages de lecture SARIF dans l'éditeur |

### Fiabilité des analyses (G11–G20)
| # | Piste | Ce qu'elle doit faire |
|---|---|---|
| G11 | Analyses reproductibles | Chaque analyse enregistre commit, empreintes d'images, versions des bases et configuration ; bouton « rejouer à l'identique » |
| G12 | Relances distinguées | Les erreurs d'infrastructure (mémoire, délai, image absente) sont relancées automatiquement et ne sont jamais confondues avec « aucun résultat » |
| G13 | Échec par défaut | Un outil du profil absent, en erreur ou incomplet rend le verdict **non concluant**, donc bloquant, sauf exception explicite et datée |
| G14 | Canaris nocturnes | Le banc d'essai de F12 est rejoué chaque nuit sur tous les modules ; alerte si un outil ne détecte plus un cas connu |
| G15 | Couverture d'analyse | Rapport de ce qui n'a pas été analysé : fichiers ignorés, langages non couverts, fichier de verrouillage absent, taille maximale dépassée |
| G16 | Fraîcheur obligatoire | Au-delà d'un âge de base configurable, le verdict devient non concluant (et pas seulement signalé) |
| G17 | Ordonnancement | Priorités (release > PR > planifié), concurrence bornée selon la RAM, quotas par projet, aucune famine |
| G18 | Analyse incrémentale | Analyse limitée aux fichiers modifiés pour les PR, cache des dépendances résolues ; analyse complète chaque nuit |
| G19 | Empreintes stables | Empreinte de résultat fondée sur le contexte du code et non sur le numéro de ligne : un déplacement de code ne crée pas de « nouveau » résultat |
| G20 | Santé des analyses | Taux d'échec, durées et délais dépassés par outil ; journal complet de chaque analyse téléchargeable pour le diagnostic |


### Intégration au catalogue (G1–G6)
| # | Piste | Ce qu'elle doit faire |
|---|---|---|
| G1 | Dépendances et conflits de modules | Le manifeste déclare ce qu'il requiert (base `feed`, module `service`, version minimale de l'appliance) et ce avec quoi il est incompatible ; résolution automatique à l'installation, graphe affiché, retrait bloqué si un autre module en dépend |
| G2 | Contrat de sortie vérifié | Le manifeste déclare ses sorties (SARIF 2.1.0, CycloneDX 1.x) ; chaque sortie est validée contre le schéma à chaque analyse : sortie invalide ou vide inattendue = analyse non concluante (G13) |
| G3 | Paramètres de module typés | Le manifeste décrit ses options (schéma JSON) : la console génère le formulaire, valide les valeurs, applique des défauts globaux et des surcharges par projet |
| G4 | Jeux de règles gérés dans la console | Règles Opengrep/Semgrep, configuration gitleaks, politiques Checkov… stockés, versionnés et partagés entre projets ; historique et retour à une version antérieure |
| G5 | Normalisation des gravités éditable | Table de correspondance par module (gravité native → `critical`…`info`), éditable par l'administrateur, pour un quality gate cohérent entre outils ; toute modification tracée |
| G6 | Version de module épinglée par projet | Un projet peut figer la version d'un module (reproductibilité, audit) ; avertissement quand la version figée est retirée du catalogue ou vulnérable |

### Profils de scan (G7–G10)
| # | Piste | Ce qu'elle doit faire |
|---|---|---|
| G7 | Profils par couverture | Un profil exprime des **catégories** à couvrir (secrets, SCA, IaC, SAST…) plutôt qu'une liste d'outils : il se résout vers les modules installés ; un module ajouté y entre automatiquement ; une catégorie sans module est signalée comme trou de couverture |
| G8 | Héritage et verrouillage | Profil d'entreprise → profil d'équipe → profil de projet ; l'administrateur verrouille des exigences (ex. secrets obligatoire, seuil minimal) qu'un niveau inférieur ne peut pas assouplir |
| G9 | Profil par déclencheur | Pour chaque projet : profil PR (rapide), profil nocturne (complet), profil release (tous les modules + DAST si cible) ; configuré une fois, choisi selon l'événement |
| G10 | Aperçu d'un profil | Avant d'enregistrer : modules résolus, modules manquants à installer, durée et ressources estimées, couverture obtenue sur le dépôt (détection de F1) |

### Chaîne d'approvisionnement et automatisation (H1–H10)
Licences à revérifier à l'intégration (section 5). Toutes **actives par défaut**, sans réglage requis (principe 8).

| # | Fonctionnalité | Ce qu'elle doit faire |
|---|---|---|
| H1 | Audit des workflows CI | Module zizmor (MIT) : injection de script, `pull_request_target`, actions non épinglées, droits trop larges. Lancé automatiquement dès qu'un dépôt contient des workflows (détection F1) |
| H2 | Posture des dépôts | Module OpenSSF Scorecard (Apache-2.0) : protection de branche, revue, signatures, mainteneurs actifs ; score par projet calculé chaque semaine sans réglage, seuil par défaut dans le quality gate |
| H3 | Priorisation EPSS + KEV | Probabilité d'exploitation (EPSS, FIRST) et drapeau « exploitée activement » (catalogue CISA KEV) attachés à chaque CVE par un module `feed` hors ligne ; quality gate par défaut : bloquant si KEV ou EPSS au-dessus du seuil, même sous le seuil CVSS |
| H4 | Paquets malveillants bloquants | Avis `MAL-` d'OSV : release toujours bloquée, sans exception possible ; alerte immédiate sur tous les projets touchés (re-corrélation F3) |
| H5 | Quarantaine des nouvelles versions | Dépendance publiée depuis moins de N jours (défaut 7) : signalée en PR, bloquante en release ; levée automatique à l'échéance |
| H6 | Revue des dépendances en PR | Diff de SBOM base → PR : nouvelles dépendances, licence (F8), Scorecard (H2), âge (H5), scripts d'installation ; publié automatiquement en commentaire de PR dans la forge |
| H7 | VEX | Export et import OpenVEX / CycloneDX VEX générés depuis les exceptions motivées ; joints automatiquement au rapport de release signé (section 7.3) |
| H8 | Remédiation automatique | Module Renovate Community Edition (AGPL-3.0, on-prem) : PR de montée de version ouvertes automatiquement pour les dépendances vulnérables, priorisées par H3, chacune analysée par l'appliance |
| H9 | Tickets synchronisés | Résultat confirmé → ticket Forgejo, GitHub, GitLab ou Jira, créé automatiquement ; statut synchronisé dans les deux sens (ticket fermé → analyse de vérification) |
| H10 | Surveillance du registre interne | Images d'un registre d'entreprise (Harbor, Forgejo, registre OCI) découvertes et analysées en continu, réanalysées à chaque mise à jour des bases |

### IA via Ollama externe (I1–I26)
Toutes passent par le connecteur de la section 3.5 et en respectent les garde-fous. **Actives par défaut dès que le connecteur est activé**, sans autre réglage (principe 8) ; chacune se désactive seule si son banc d'essai (I23) échoue. Sans connecteur, elles sont masquées et rien d'autre ne change. Aucune ne remplace une fonctionnalité F, G ou H : elle l'explique, la prépare ou la rédige.

| # | Fonctionnalité | Ce qu'elle doit faire | Automatique / confirmation |
|---|---|---|---|
| I1 | Connecteur Ollama externe | Adresse seule à saisir, serveur candidat détecté (`ollama.<domaine>`), découverte et choix automatique des modèles par tâche, file `scanoria-ai`, cache par empreintes d'entrée et de modèle, disjoncteur, santé et latence dans la photographie de santé (section 10), journal des appels | Activation confirmée une fois (sortie de données) ; le reste automatique |
| I2 | Explication d'un résultat | Pour un résultat : ce que la règle détecte, pourquoi c'est un risque ici (extrait de code, CWE, CVE), impact probable, correction recommandée, références ; précalculée pour chaque nouveau résultat `critical`/`high`, à la demande pour les autres | Automatique |
| I3 | Pré-tri assisté | Indice « faux positif probable / à confirmer / vrai positif probable » avec justification citée (code de test, valeur factice, code mort, chemin non atteignable) ; affiché comme suggestion à côté du statut `nouveau` ; à partir de la 0.7, propose une règle F4 quand plusieurs résultats partagent la même raison | Suggestion automatique ; changer le statut reste un clic humain |
| I4 | Correctif proposé et vérifié | Diff minimal pour un résultat SAST, IaC, Dockerfile ou workflow ; **vérifié** en rejouant le scanner concerné sur le code corrigé, dans un conteneur jetable (section 6.4) : le résultat disparaît et aucun nouveau n'apparaît. Seul un correctif vérifié est proposé ; il peut ouvrir une **PR brouillon** marquée « proposé par IA » par le même client de forge que H9 (circuit propre, distinct de Renovate), jamais fusionnée par l'appliance | PR brouillon automatique si vérifiée ; la fusion reste humaine |
| I5 | Résumé d'analyse | Synthèse en quelques lignes de chaque analyse : ce qui a changé, les trois priorités, ce qui bloque, ce qui n'a pas été couvert (G15) ; en tête de la page d'analyse, puis dans les notifications dès la 0.9 (F10) | Automatique |
| I6 | Notes de sécurité de release | À partir de la comparaison F2 et du rapport de release : texte prêt à publier (corrigé, introduit, accepté avec motif), joint au rapport comme **annexe non signée** marquée IA, à côté du rapport signé inchangé | Automatique ; publication par la chaîne de release |
| I7 | Regroupement sémantique | Embeddings des résultats (règle, message, contexte) pour regrouper les problèmes semblables entre outils, fichiers et projets, au-delà du recoupement exact de F16 ; un groupe propose un tri commun, puis une règle F4 dès la 0.7 | Automatique ; action de tri confirmée |
| I8 | Recherche en langage naturel | Couche de langage naturel sur les filtres et sur F3 : « secrets dans les projets Python depuis un mois », « qui est touché par une faille de désérialisation ? » : traduit en **filtres structurés** de la console (jamais en SQL), affichés et modifiables avant exécution, limités aux droits de l'utilisateur ; indicateur d'attente | À la demande |
| I9 | Verdict expliqué | Pourquoi un quality gate bloque ou est non concluant, en clair, avec la liste ordonnée des actions qui le débloqueraient (corriger, puis selon les fonctions disponibles faire approuver une exception, rafraîchir une base) ; repris dans le statut de commit et la sortie de `scanoria-scan` | Automatique |
| I10 | Rédaction des exceptions | Pour une demande d'exception (F5) ou une justification VEX (H7) : motif rédigé à partir du contexte, date de fin proposée, et statut VEX suggéré (`not_affected`, `affected`…) dès la 0.8 ; l'opérateur relit et soumet, l'administrateur approuve comme d'habitude | Proposition automatique ; soumission et approbation humaines |
| I11 | Atteignabilité assistée | Pour une CVE de dépendance : recherche statique des imports et appels de la fonction vulnérable dans le dépôt, puis avis argumenté « appel probable / improbable » avec les emplacements ; alimente la priorité (avec H3) et la rédaction VEX (I10). **Ne lève jamais un blocage seule** | Automatique ; levée humaine |
| I12 | Générateur de règles | Depuis un résultat, un exemple de code ou une phrase : règle Opengrep/Semgrep, motif gitleaks ou politique Checkov, testée sur un exemple positif et un négatif générés, puis enregistrée dans les jeux de règles gérés (G4) | Enregistrement confirmé |
| I13 | Évaluation des PR de remédiation | Pour chaque PR de montée de version (H8) : résumé du changement, risques de rupture déduits du diff du lockfile, des notes de version disponibles hors ligne et des API utilisées par le projet ; publié dans la PR | Automatique |
| I14 | Typage des secrets génériques | Extension de F7 : les candidats à forte entropie sans type connu sont classés (mot de passe, jeton interne, clé privée, faux positif probable) à partir du **contexte seulement** : la valeur est remplacée par sa forme avant envoi ; alimente F7 | Automatique |
| I15 | Diagnostic des analyses en échec | Extension de G20 : lit le journal d'une analyse en échec (G12, G20) et en donne la cause probable (mémoire, délai, image, entrée invalide) et la correction ; propose d'appliquer un réglage de ressources quand il est sûr | Diagnostic automatique ; changement de réglage confirmé |
| I16 | Diagnostic de l'appliance | Extension de F19 et de la santé : explique en clair une alerte de santé, un échec de `scanoria-selftest`, de mise à jour ou d'installation de module, et propose l'action correspondante de la console | Diagnostic automatique ; action confirmée |
| I17 | Traduction des messages des outils | Messages et descriptions de règles des scanners (en anglais) traduits dans la langue de l'utilisateur, mis en cache par règle et par version d'outil ; le texte d'origine reste affiché | Automatique |
| I18 | Explication des licences | Pour une licence « à revoir » ou inhabituelle d'un SBOM (F8) : obligations principales, compatibilité avec la licence du projet, conditions d'usage à vérifier ; marqué comme aide, pas comme avis juridique | Automatique |
| I19 | Seuils de quality gate suggérés | À partir de l'historique, propose des seuils et exceptions de départ par projet, passés automatiquement dans le simulateur F9 avec leur effet (« N releases auraient été bloquées ») | Enregistrement confirmé |
| I20 | Rapport mensuel commenté | Le rapport F10 reçoit une analyse rédigée des tendances : projets qui se dégradent, dette qui vieillit, délais de correction, points d'attention du mois | Automatique |
| I21 | Assistant « Demander à Scanoria » | Panneau de questions dans la console sur un projet, une analyse, un résultat ou la documentation embarquée ; répond en citant les données sources (liens vers résultats, analyses, pages de doc) ; lecture seule, limité à ce que l'utilisateur a le droit de voir ; réponse affichée au fil de l'eau avec indicateur d'attente | À la demande ; aucune action |
| I22 | Cartographie de la surface d'attaque | À partir de la détection F1 et du code : frameworks, routes HTTP, points d'entrée et formulaires ; propose des cibles et chemins DAST (section 6.5) et un profil adapté | Proposition automatique ; déclaration d'une cible par un administrateur |
| I23 | Banc d'essai IA | Extension de F12 aux tâches IA : jeu d'essai de résultats connus (vrais et faux positifs, verdicts, puis correctifs attendus dès la 0.9) rejoué à l'activation et à chaque changement de modèle, puis chaque nuit avec les canaris G14 dès la 0.6 ; mesure par tâche ; une tâche sous son seuil est **désactivée automatiquement** et signalée | Automatique |
| I24 | Retours et qualité mesurée | 👍/👎 et correction sur chaque sortie IA ; les tris confirmés par des personnes servent d'exemples pour les résultats suivants **du même projet** (contexte local, sans réentraînement) ; taux d'accord IA/humain affiché par tâche et par modèle | Automatique |
| I25 | Commentaires de PR expliqués | Les nouveaux résultats d'une PR (G18) sont publiés dans le commentaire de forge avec leur explication courte (I2) et, dès la 0.9, le correctif vérifié s'il existe (I4), à côté de la revue des dépendances H6 | Automatique |
| I26 | Tickets rédigés et dédupliqués | Extension de H9 : les tickets de H9 reçoivent un titre et une description clairs (contexte, risque, correction) ; avant création, un ticket semblable déjà ouvert est cherché par similarité et le résultat y est rattaché plutôt que dupliqué | Automatique |

### Intégration aux forges, CI et outils existants (J1–J16)
Retenues le 2026-11-24 (demande de Vincent). Même principe que H1–H10 : **actives par défaut**, réglage minimal (principe 8) ; toute écriture dans une forge ou un réglage de dépôt reste soumise aux règles habituelles (confirmation pour ce qui est à risque).

| # | Fonctionnalité | Ce qu'elle doit faire |
|---|---|---|
| J1 | Application de forge en un clic | « Connecter GitHub / Forgejo / GitLab » : l'appliance crée elle-même son application (manifeste GitHub App, application OAuth Forgejo ou GitLab) avec les droits minimaux, webhooks et statuts de commit compris ; aucun jeton à copier. Les dépôts de l'organisation sont enrôlés automatiquement, nouveaux dépôts compris, avec le profil proposé par F1 ; un dépôt archivé est suspendu. En mode tiré (section 7.2), l'interrogation remplace les webhooks |
| J2 | PR d'intégration automatique | Pour chaque dépôt enrôlé, une PR ajoute l'étape Scanoria à la CI détectée (modèles J3) ; la règle de protection de branche exigeant `scanoria/release-gate` est **proposée**, appliquée seulement après confirmation d'un administrateur. Aucune PR n'est fusionnée par l'appliance |
| J3 | Modèles CI officiels | Action GitHub, action Forgejo, composant GitLab CI, *shared library* Jenkins, tâche Tekton : une ligne chacun, qui enveloppe `scanoria-scan` (verdict, SARIF, rapport) ; versionnés et épinglés par empreinte, testés en CI |
| J4 | CI sans secret par OIDC | En mode poussé, la CI présente son jeton OIDC (GitHub, GitLab, Forgejo) ; l'appliance vérifie la signature auprès de l'émetteur déclaré, l'audience et les revendications (dépôt, branche ou tag), puis rattache l'appel au projet. Plus de jeton d'API statique à créer ni à faire tourner ; le jeton par projet reste possible |
| J5 | Reprise de l'existant | Configurations présentes dans le dépôt (`.gitleaks.toml`, `.trivyignore`, `osv-scanner.toml`, `.semgrepignore`, `# nosec`, `sonar-project.properties`…) importées en exceptions avec le motif « importé » et une date de fin par défaut ; statuts de tri d'une instance SonarQube, Dependency-Track ou DefectDojo existante repris de même. Effet affiché avant application, tracé dans l'audit |
| J6 | Résultats externes acceptés | SARIF 2.1.0 et CycloneDX produits ailleurs (outil interne, outil commercial lancé en CI) téléversés par l'API ; validés contre le schéma (G2), normalisés (G5), marqués « externe » avec leur source, et pris en compte par le quality gate |
| J7 | Annotations ligne à ligne dans la PR | Les nouveaux résultats d'une PR (G18) sont posés sur les lignes du diff (annotations de check run GitHub, revue Forgejo ou GitLab), en complément du commentaire de synthèse (H6, I25) ; nombre borné, le reste renvoie à la console |
| J8 | Configuration en code | Fichier `.scanoria.yml` facultatif dans le dépôt : profil, exceptions (motif et date de fin obligatoires), chemins ignorés, dans les limites des verrous (G8) ; et export / import de toute la configuration de l'appliance (projets, profils, gates, jeux de règles) en YAML versionné, avec aperçu des écarts avant application. Les secrets n'y figurent jamais |
| J9 | Attestations pour le déploiement | Le verdict favorable est attaché à l'image OCI ou à l'artefact dans le registre comme **attestation signée** (in-toto, compatible cosign), avec l'empreinte du commit et le rapport de release ; une politique d'admission Kubernetes d'exemple (Kyverno) refuse toute image sans attestation valide ; `scanoria-verify` vérifie aussi les attestations |
| J10 | Raccordement à la supervision | Point `/metrics` Prometheus (santé, file d'analyses, âge des bases, verdicts), journal d'audit et alertes en **syslog RFC 5424** vers un SIEM, notifications natives Mattermost, Microsoft Teams et Matrix en plus du webhook signé de F10 |

**Déploiement en fin de CI (J11–J14)** : une fois le verdict favorable, la livraison passe par les outils de l'entreprise. **L'appliance ne détient jamais d'accès à la production** et ne déploie jamais elle-même (ni SSH, ni Ansible, ni `kubectl`) : elle déclenche, propose ou promeut. Retenues le 2026-11-24 ; J11 est le mode par défaut, les autres se choisissent par projet.

| # | Fonctionnalité | Ce qu'elle doit faire |
|---|---|---|
| J11 | Déclenchement de la CD existante | Après un verdict favorable (release ou branche configurée), l'appliance déclenche le déploiement déjà en place : `workflow_dispatch` GitHub ou Forgejo, déclencheur de pipeline GitLab, job Jenkins ; elle passe l'empreinte du commit et le lien du rapport, suit le résultat et le rattache à l'analyse. Mode par défaut, sans réglage au-delà de J1 ; aucune exécution si le verdict est défavorable ou non concluant |
| J12 | Promotion GitOps | L'appliance ouvre une PR dans le dépôt de déploiement (Argo CD, Flux) qui porte la nouvelle empreinte d'image (`@sha256:`) ; Argo CD ou Flux applique. Retour arrière par revert. Fusion humaine par défaut, automatique seulement si un administrateur l'autorise pour ce projet et cet environnement |
| J13 | Promotion dans le registre | L'image validée est copiée **par empreinte** d'un dépôt « candidat » vers un dépôt « validé » (Harbor, registre OCI), avec l'attestation J9 ; la politique d'admission n'accepte que les images validées. Indépendant de l'outil de déploiement, combinable avec J11 ou J12 |
| J14 | Recette éphémère et DAST avant production | La CD (J11) déploie d'abord dans un environnement de recette temporaire chez l'entreprise, déclaré comme cible autorisée (section 6.5) ; l'appliance y lance le DAST, puis ne déclenche la production que si le verdict reste favorable ; l'environnement est ensuite détruit par la CD |

**Acceptation en CI et chaîne autonome (J15–J16)** : retenues le 2026-11-24. Le code peut être écrit et poussé par un agent (Claude ou un autre bot) ; **l'acceptation d'un risque reste toujours humaine**, et **personne ne valide ses propres résultats**.

| # | Fonctionnalité | Ce qu'elle doit faire |
|---|---|---|
| J15 | Acceptation depuis la PR | Quand le gate bloque, le statut de commit et le commentaire de PR portent, pour chaque résultat bloquant, un lien « demander une exception » vers une modale de la console (motif et date de fin obligatoires, rédaction proposée par I10), ou une commande de commentaire `/scanoria accept <résultat> --until <date> --reason "…"` lue par J1. Le circuit est celui de F5 : demande, puis **approbation par un administrateur**, puis **réévaluation du verdict sans réanalyse**, statut mis à jour, CI débloquée. Règles fixes : le demandeur ne peut pas approuver ; **l'auteur du commit analysé ne peut pas approuver** une exception qui le concerne ; une identité **non humaine** (jeton d'API, jeton OIDC de CI J4, application de forge, compte déclaré « agent » ou « bot ») peut demander mais **jamais approuver** ; l'IA n'approuve jamais (section 3.5) ; H4 (`MAL-`) et les verrous G8 restent sans exception possible. Une acceptation faite dans un outil (« Accept » dans SonarQube, `# nosec`…) arrive comme **demande**, jamais comme approbation. Tout est tracé dans l'audit et repris dans le rapport de release (section 7.3) et le VEX (H7) |
| J16 | Chaîne autonome PR → scan → déploiement | Flux de bout en bout sans intervention quand tout est vert : un agent ou une personne ouvre une PR ; l'appliance l'analyse (profil PR, G9) et pose son statut ; la **fusion automatique native de la forge** (GitHub auto-merge, Forgejo « fusionner quand les contrôles passent ») fusionne quand les contrôles requis sont verts, l'appliance ne fusionnant jamais elle-même ; le tag ou la branche de release déclenche le profil `release` ; sur verdict favorable, J11 lance le déploiement (puis J12, J13 ou J14 selon le projet). Activé par projet en une case lors de J1/J2. Arrêt net à toute étape défavorable ou non concluante, avec la raison (I9) et le lien J15 si une exception est possible ; échec du déploiement rattaché à l'analyse et notifié (F10) |

### Outils d'analyse par IA et du code IA (K1–K11)
Retenus le 2026-11-24 (demande de Vincent). Licences vérifiées ce jour-là, **à revérifier** à l'intégration (section 5). Tous **actifs par défaut** dès que la détection F1 trouve de quoi les lancer, sans réglage (principe 8). Garde-fous de la section 3.5 : relais de `scanoria-ai`, résultats marqués « IA » hors verdict tant qu'ils ne sont pas confirmés, banc d'essai I23 (un module sous son seuil se désactive seul). Ils ne recoupent pas I1–I26 : ceux-ci expliquent et rédigent, les K **trouvent**.

| # | Module | Licence | IA | Ce qu'il doit faire |
|---|---|---|---|---|
| K1 | ~~**Kodus**~~ (écarté le 2026-11-25) | AGPL-3.0 et parties propriétaires (EE) | — | **Non intégré** (section 14) : la revue de code IA des PR est assurée par K2 |
| K2 | **PR-Agent** (`scanner`) | MIT d'après le dépôt, retour à Apache-2.0 annoncé : **à revérifier** | Ollama par LiteLLM et le relais | `describe` et `review` des PR sans service permanent ; revue IA des PR de l'appliance (K1 écarté), publiée par le client de forge (H6, I25) |
| K3 | **Vulnhuntr** (`scanner`) | AGPL-3.0 | Ollama (support « expérimental » amont : banc d'essai I23 obligatoire) | Suit les chaînes d'appel de l'entrée utilisateur à la sortie dans le code Python pour trouver des failles exploitables à distance ; sortie convertie en SARIF |
| K4 | **Fraim** (`scanner`) | MIT | Ollama par LiteLLM et le relais | Workflows d'analyse IA du code et de l'IaC, indicateur de risque de chaque PR |
| K5 | **Cisco MCP Scanner** (`scanner`) | Apache-2.0 | règles YARA hors ligne ; analyse LLM optionnelle par le relais ; jamais l'API Cisco ni VirusTotal | Configurations et définitions de serveurs MCP présentes dans le dépôt : empoisonnement d'outils, injection d'invite, droits excessifs |
| K6 | **Cisco Skill Scanner** (`scanner`) | Apache-2.0 | analyse statique et YARA-X hors ligne ; juge LLM optionnel par le relais ; pas d'appel OSV.dev en ligne | Paquets de skills d'agents : injection d'invite, exfiltration, code malveillant |
| K7 | **Agentic Radar** (`scanner`) | Apache-2.0 | aucune (analyse statique seule ; les commandes qui exigent OpenAI ne sont pas utilisées) | Inventaire des workflows d'agents (LangGraph, CrewAI, n8n, OpenAI Agents, AutoGen) : outils, serveurs MCP, graphe ; alimente I22 |
| K8 | **ModelScan** (`scanner`) | Apache-2.0 | aucune | Fichiers de modèles du dépôt ou d'une image (pickle, H5, SavedModel) qui exécutent du code au chargement ; bloquant par défaut |
| K9 | **garak** (`scanner`, type DAST) | Apache-2.0 | cible = application LLM de l'entreprise ; LLM d'appui par le relais | Sondes contre une application LLM **déclarée comme cible autorisée** (section 6.5) : injection d'invite, fuite de données, contournement ; mode passif par défaut |
| K10 | **promptfoo** (`scanner`, type DAST) | MIT | idem K9 | Red teaming des applications LLM de l'entreprise sur cible autorisée ; scénarios proposés par I22 |
| K11 | **Xalgorix** (`scanner`, type DAST, facultatif) | Apache-2.0 (à revérifier) | Ollama par le relais ; serveur de rappel Interactsh **interne** à l'appliance, jamais les serveurs publics | Agent IA de test d'intrusion contre une application qui tourne. Il ne vise **que l'environnement de recette éphémère déployé par la CD (J14)**, déclaré comme cible autorisée (section 6.5), **jamais la production** ; mode passif par défaut, actif sur confirmation ; résultats marqués « IA », hors verdict tant qu'une personne ne les a pas confirmés |

### Délais d'analyse (V1–V10)
Retenus le 2026-11-24. Référence : **2 vCPU / 4 Go** (D6). Gains estimés, **mesurés** par une batterie de référence en CI (conteneurs bornés à 2 vCPU / 4 Go, même jeu de dépôts à chaque version) ; une régression de plus de 15 % est signalée. Aucune optimisation n'affaiblit G11 (reproductibilité), G13 (échec par défaut) ni le confinement (section 6.4). Complètent G17 et G18.

| # | Optimisation | Ce qu'elle doit faire | Gain attendu |
|---|---|---|---|
| V1 | Images préchargées | Image récupérée et vérifiée (empreinte) à l'installation et à la mise à jour du module, jamais pendant une analyse ; une image absente est une erreur d'infrastructure (G12) | 10 à 60 s par outil au premier lancement |
| V2 | Miroir Git local | Un dépôt nu par projet, tenu à jour par récupération des seuls nouveaux objets (interrogation, webhook) ; chaque analyse en extrait le commit voulu dans son répertoire propre | 50 à 90 % du temps de récupération sur un gros dépôt |
| V3 | SBOM unique partagé | Syft produit une fois le SBOM CycloneDX de l'analyse ; Grype, Trivy, OSV-Scanner et Dependency-Track le relisent au lieu de résoudre chacun les dépendances | 30 à 50 % du volet dépendances |
| V4 | Résultats réutilisés | Résultat d'un outil rattaché à l'empreinte (arbre Git, image, versions des bases, configuration) : réutilisé tel quel si tout est identique, par exemple une release sur un commit déjà analysé ; l'analyse nocturne des têtes de branche remplit ce cache ; une base plus récente relance seulement la re-corrélation F3 | release quasi immédiate si le commit est connu |
| V5 | Ordonnancement par durée mesurée | Durées réelles par outil et par projet (F14) : les outils longs démarrent d'abord, les courts remplissent les creux, dans la limite de RAM de G17 | 20 à 35 % du temps total |
| V6 | Outils lancés selon le contenu | Un outil ne tourne que si des fichiers le concernent (pas de hadolint sans Dockerfile, pas de Checkov sans IaC) ; détection F1 mise en cache par arbre Git ; un outil écarté est noté dans la couverture (G15), jamais compté comme absent (G13) | 30 à 60 % sur un dépôt courant |
| V7 | Bases partagées en lecture seule | Bases de vulnérabilités décompressées une fois, montées en lecture seule dans chaque conteneur, remplacées de façon atomique hors analyse ; aucun téléchargement ni décompression par analyse | 5 à 30 s par outil |
| V8 | Verdict défavorable anticipé | Outils rapides d'abord (secrets, `MAL-`, linters) ; dès qu'un blocage certain est trouvé, le statut d'échec est publié, puis le rapport complet suit ; un verdict **favorable** attend toujours tous les outils (G13) | retour d'échec en moins d'une minute |
| V9 | Travail en mémoire | Répertoire de travail en tmpfs quand le dépôt et la RAM libre le permettent ; exclusions communes non analysées (`node_modules`, `vendor`, binaires, `.git` pour les outils sans historique), notées dans la couverture (G15) | 10 à 25 % des entrées-sorties |
| V10 | Cache SonarQube | Cache d'analyse par branche, JRE déjà dans l'image du scanner, service gardé démarré ; seuls les fichiers modifiés sont réanalysés en profondeur | 30 à 50 % de l'étape SonarQube, souvent la plus longue |

## 16. Consignes pour Claude Code dans ce dépôt
- Session principale : Sonnet 5.5 ; conseiller : Opus 5.5.
- Sous-agents **Haiku 5.5** :
  - `search` : explorer le dépôt ;
  - `grep` : trouver les points d'appel ;
  - `audit` : relire un diff, dans un worktree isolé.
- **Toutes les recherches dans le dépôt et tous les tests** sont confiés à ces sous-agents, pour garder le contexte principal léger. Ne relire soi-même que les extraits qu'ils désignent.
- Toujours répondre en **français**. Aucune référence à une infrastructure réelle dans le code ni dans les exemples.
- Travailler par **itérations** : une version = une PR = une section du `CHANGELOG.md`, avec ses tests. Ne jamais publier une version sans CI verte.

### Cycle Git géré par Claude
- **Branches** : une branche par itération ou correctif (`feat/…`, `fix/…`), depuis `main` à jour. **Jamais de commit ni de push direct sur `main`**, jamais de `--force` sur `main`.
- **Commits** : messages en français, au présent, préfixés (`feat:`, `fix:`, `ci:`, `docs:`, `test:`), avec les lignes d'attribution demandées par l'environnement.
- **Avant d'ouvrir la PR** : tests passés par le sous-agent de tests, diff relu par `audit`, corrections faites. La description résume le changement, les tests et les limites connues.
- **Merge** : en *squash*, **seulement** quand tous les contrôles requis sont verts sur le dernier commit de la PR (`ci-ok`, CodeQL, SonarQube Cloud), vérifiés par l'API et non supposés. La protection de `main` l'impose aussi. Jamais de merge d'une PR rouge, en attente ou dont un contrôle a été désactivé pour passer.
- **Version** : une PR de version modifie les deux fichiers `VERSION` et ajoute la section du `CHANGELOG.md`. Après le merge, Claude suit `release.yml` jusqu'à la pré-version, puis la promotion, et rapporte le résultat. Une version rejetée est corrigée par une nouvelle version (X.Y.Z+1) ; un numéro n'est jamais reconstruit.
- **Échec en CI** : Claude lit le journal, corrige sur la branche et repousse. Il ne contourne jamais un contrôle (pas de `continue-on-error` ajouté, pas d'exception de scanner sans motif ni date de fin) sans le dire et obtenir l'accord.
- **Toujours demander avant** : supprimer une branche distante autre que celle d'une PR fusionnée, réécrire l'historique publié, supprimer un tag ou une release, modifier les secrets, les réglages du dépôt, la protection de `main` ou la clé de signature, rendre le dépôt privé, ajouter un runner auto-hébergé.
- **Dépôt public** : relire chaque diff comme s'il était lu par un inconnu. Aucun nom d'hôte, domaine, adresse ou identifiant réel, aucun secret, même factice d'apparence réelle hors des jeux d'essai prévus.
- **Rapport** : après chaque merge ou publication, une ligne pour l'utilisateur (version, état de la CI, lien vers la release).
