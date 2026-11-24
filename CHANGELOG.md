<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Vincent Tisseront
-->

# Journal des modifications

Format : une section par version, la plus récente en tête. La section d'une
version sert aussi de notes de version dans la console (`release.json`,
champ `notes_md`). Les numéros suivent le versionnage sémantique et ne sont
jamais reconstruits : une version rejetée est remplacée par la suivante.

## 0.4.0 — non publiée

Applications permanentes : SonarQube s'installe depuis le catalogue. La
consommation, la santé des analyses et les fonctions IA de la 0.4 sont
arrivées en 0.3.3.

### Ajouté
- **Modules permanents** :
  - base PostgreSQL dédiée et cloisonnée par module ;
  - secrets générés par l'appliance ;
  - réglages noyau gérés ;
  - refus clair quand la machine manque de ressources ;
  - sauvegarde vérifiée avant chaque mise à jour, et à la demande ;
  - restauration depuis la console ;
  - retour arrière automatique d'une mise à jour ratée ;
  - consommation réelle de chaque module publiée (F14).
- **SonarQube Community Build**, installable depuis le catalogue sur
  `sonarqube.<appliance>`. Sa mise en service est automatique : mot de passe
  administrateur aléatoire, utilisateur et jeton d'analyse dédiés,
  authentification forcée, projets privés. La console réinitialise le mot de
  passe administrateur et ne l'affiche qu'une fois.
- **Module sonar-scanner** : la branche principale est analysée par
  SonarQube, et ses résultats qualité et SAST rejoignent les résultats
  unifiés. Le jeton n'est jamais exposé.
- Le runner d'analyses est durci par systemd.
- Contrôle en CI : le catalogue publié reste lisible par la dernière
  appliance publiée.
- Catalogue n° 6.

### Limites connues
- SonarQube Community Build n'analyse que la branche principale, jamais les
  PR. Les commentaires `// NOSONAR` du code analysé restent pris en compte.
- Le réseau interne des modules (`10.90.0.0/16`) peut chevaucher un réseau
  d'entreprise. Il se règle dans `services-network.conf`, sans interface
  pour l'instant.
- PostgreSQL redémarre une fois, au premier module qui utilise une base.
- Une restauration exige la version du module qui a fait la sauvegarde. Une
  désinstallation sans conservation des données supprime aussi les
  sauvegardes.
- Le mot de passe administrateur affiché est effacé deux minutes après son
  dépôt, et non dès sa lecture.

## 0.3.4 — 2026-11-24

Installation d'OSV-Scanner et de Trivy sur une appliance réelle.

### Corrigé
- **Bases de vulnérabilités jamais téléchargées** : les modules `osv-db` et
  `trivy-db` ne créaient qu'un dossier vide. OSV-Scanner et Trivy échouaient
  donc à leur banc d'essai (`E_TESTBED`, code 127), et l'installation de la
  sélection conseillée revenait en arrière. Le service système télécharge
  maintenant les bases avant le banc d'essai :
  - l'export OSV, par écosystème ;
  - `trivy-db`, par OCI, avec contrôle d'empreinte et extraction sûre.
  Le téléchargement se fait en HTTPS seulement, avec des tailles et des délais
  bornés, le proxy système pris en compte et une bascule atomique. Une base
  injoignable donne `E_FEED_UNAVAILABLE`, avec un message clair.
- **Diagnostic** : un banc d'essai en échec nomme désormais le module et
  donne la fin de l'erreur de l'outil.
- La CI installe maintenant OSV-Scanner et Trivy par le service système, à
  partir de bases vides et avec les vraies sources (`b18-live`). Elle ne
  pré-remplit plus aucune base, ce qui avait masqué le défaut.

### Ajouté
- Mise à jour quotidienne des bases (`scanoria-feeds-refresh.timer`).
  Âge de chaque base dans le Catalogue, avec un bouton « Mettre à jour
  maintenant ».
- Catalogue n° 3 : OSV-Scanner demande 1,5 Go de mémoire (pic mesuré
  d'environ 600 Mo sur npm), et `trivy-db` 4 Go de disque.
- Migration `008`.

### Limites connues
- Sans accès à Internet, l'installation de ces scanners échoue. Les lots
  hors ligne signés arrivent en 0.6.
- Un écosystème absent de la base OSV est seulement signalé par
  l'outil. Le rapport de couverture (G15) le reprendra.
- Les bases ne portent pas de signature de leur éditeur. Seules la version
  active et la précédente sont gardées.

## 0.3.3 — 2026-11-24

Correctif de l'installation des scanners, et premières fonctions de la 0.4
déjà terminées.

### Corrigé
- **Banc d'essai des scanners** : le conteneur tournait sans répertoire
  personnel. OSV-Scanner s'arrêtait alors en erreur (code 127) et son
  installation revenait en arrière. Les conteneurs reçoivent désormais
  `HOME` et `TMPDIR` sur leur `/tmp` jetable. Le banc d'essai de la CI
  reprend exactement les réglages de l'appliance, ce qui aurait révélé
  l'écart.

### Modifié
- **Menu latéral de la console** regroupé en sections (Analyse, Modules,
  Administration) et resserré. Les applications web des modules « service »
  installés et sains (SonarQube, Dependency-Track…) y apparaissent sous
  Modules, avec un lien vers leur nom. L'entrée de la page affichée reste
  en surbrillance sur ses sous-pages (une analyse, un module), et le menu
  replié affiche le nom de chaque entrée au survol.

### Ajouté
- **Consommation réelle par module** (F14) : mémoire, CPU, durées et nombre
  d'analyses des scanners. Les modules inutilisés depuis 30 jours sont
  signalés avec une suggestion de retrait, jamais automatique, et jamais
  pour un module requis par un autre.
- **Santé des analyses** (G20) : taux d'échec par outil et par classe,
  délais dépassés, mémoire épuisée, durées sur 7 et 30 jours, et analyses en
  échec récentes. Le journal complet d'un module est téléchargeable par les
  opérateurs, masqué et borné.
- **IA par un Ollama externe** :
  - pré-tri suggéré avec une justification citée, sans effet sur le statut
    (I3) ;
  - résumé de chaque analyse (I5) ;
  - type probable des secrets génériques, d'après le contexte seul (I14) ;
  - diagnostic des analyses en échec, avec le délai d'un module allongeable
    en un clic (I15) ;
  - traduction des règles des outils (I17) ;
  - avis 👍/👎, corrections et taux d'accord entre l'IA et les personnes
    (I24).
  Le jeton porteur du connecteur est pris en charge, chiffré par une clé
  dédiée. Le masquage des secrets est unifié et élargi, sans changer
  l'empreinte des résultats existants.
- Migrations `006` et `007`.

### Limites connues
- Les relevés des modules permanents s'afficheront avec le moteur des
  services de la 0.4. D'ici là : « aucun relevé ».
- IA : la mémoire d'un module reste un conseil, et un délai allongé
  s'applique à tous les projets. Le typage des secrets ne voit que le
  contexte et la longueur. La traduction d'une règle est partagée entre les
  projets, car elle ne contient aucune donnée de projet.

## 0.3.2 — 2026-11-24

Correctifs constatés sur une appliance de test.

### Corrigé
- **Catalogue vide** : les répertoires du catalogue et des modules étaient
  créés en `root:root`, donc illisibles par la console. La console refusait
  aussi les descriptions bilingues des manifestes et écartait ainsi tous les
  modules.
- **Interface** : indicateurs d'attente et rafraîchissement de l'affichage à
  la fin de chaque action envoyée au service système, sans recharger la
  page. L'état est publié avant le résultat de la demande.
- **Mises à jour** : les services ajoutés par une version (worker, runner,
  IA) sont activés avant le contrôle de santé. Avant, la santé échouait et la
  mise à jour revenait en arrière (`E_HEALTH_ROLLED_BACK`).

### À savoir avant de mettre à jour
- Une appliance 0.1 ou 0.2 ne peut pas passer seule à une 0.3.x : c'est son
  propre code qui extrait le lot et active les services. La réinstaller depuis
  l'ISO 0.3.2.

## 0.3.1 — 2026-11-24

Correctif de la 0.3.0, qui n'a pas reçu ce commit à temps.

### Corrigé
- **Demandes au service root refusées** : avec `ProtectSystem=strict`, le
  répertoire de dépôt et celui d'arrivée des demandes étaient deux montages
  distincts, et le renommage final échouait (`EXDEV`). Aucune action de la
  console vers le service root n'aboutissait : recherche de mise à jour,
  certificat, modules… Le worker avait le même défaut sur la file des
  analyses. Constaté sur une appliance 0.1.0.

### À savoir avant de mettre à jour
- Sur une appliance 0.1 à 0.3.0, ce défaut empêche aussi la console de
  demander la mise à jour. Réinstaller depuis l'ISO 0.3.1, ou appliquer
  d'abord la surcharge systemd provisoire, puis mettre à jour.

## 0.3.0 — 2026-11-24

Analyses : les dépôts de l'entreprise sont analysés par les modules installés,
les résultats réunis et triés, et un quality gate rend un verdict exploitable
par la CI. Première aide de l'IA par un serveur Ollama externe, optionnelle.

### Ajouté
- **Projets et forges** (F1) : forges Forgejo et GitHub vérifiées puis
  parcourues chaque heure, et projets découverts analysés à chaque commit.
  On ajoute aussi un projet par son URL (jeton, ou clé SSH avec clé d'hôte
  confirmée) ou par une archive. L'assistant d'ajout détecte langages,
  gestionnaires de paquets, IaC et workflows. Il propose profil, quality gate,
  planification et modules, sans rien installer sans confirmation. Les
  secrets sont chiffrés en base (AES-256-GCM).
- **File d'analyses** (`scanoria-worker`) : priorités release > PR >
  planifié, anti-famine et quotas par projet (G17). Le plan de chaque analyse
  est figé et peut être rejoué à l'identique (G11). Les erreurs
  d'infrastructure sont relancées et jamais confondues avec « aucun
  résultat » (G12). Section Analyses de la console et API `/api/scans`.
- **Exécution confinée** (`scanoria-runner`, root) : chaque demande est
  contrôlée comme hostile et le plan est vérifié. La récupération Git se fait
  dans un conteneur confiné, puis chaque scanner tourne dans un conteneur
  jetable sans réseau, avec ses bornes et ses mesures. Les sorties sont
  vérifiées contre leur contrat (G2) et l'analyse reprend après un
  redémarrage. gitleaks parcourt l'historique complet.
- **Résultats unifiés** : ingestion SARIF et CycloneDX bornée, empreintes
  stables (G19), gravités normalisées et éditables par l'administrateur avec
  audit (G5), et rapport de couverture (G15). Pour le tri, un résultat
  réapparu redevient `nouveau` et un résultat disparu passe `corrigé`. Les
  exceptions sont motivées, limitées à un an et révocables. Sections
  Résultats, Exceptions et Gravités.
- **Suivi des secrets** (F7) : états `à révoquer`, `révoqué` et
  `faux positif`, avec auteur et date. Ni la valeur ni l'extrait d'un secret
  ne sont jamais gardés.
- **Paquets malveillants** (H4) : un avis `MAL-` bloque toujours, sans
  exception ni faux positif possible.
- **Quality gate** : verdict `passed`, `failed` ou `inconclusive`, avec ses
  raisons ordonnées et les actions qui le débloqueraient. Un outil absent, en
  erreur ou incomplet rend le verdict non concluant (G13). Section Quality
  gates et page Intégration CI de chaque projet.
- **API pour la CI** : jetons par projet (seule leur empreinte est gardée),
  `POST /api/projects/:id/scans` et `GET /api/scans/:id/verdict`, badge
  désactivé par défaut. Client `scanoria-scan` qui rend 0 (passé), 1 (échec),
  2 (non concluant) ou 3 (erreur d'usage ou d'accès).
- **IA par un Ollama externe** (I1, I2, I9, I23) : seule l'adresse est à
  saisir, et l'activation se confirme une fois. Le service système résout et
  épingle le serveur, et n'ouvre la sortie que pour le service `scanoria-ai`.
  Les modèles sont choisis par tâche, avec la raison affichée. Chaque tâche
  passe un banc d'essai qui la désactive si elle échoue. Résultats et
  verdicts sont expliqués avec la mention « proposé par IA ». Rien de secret
  ne sort, le code analysé est traité comme donnée, et la console est
  identique sans connecteur.
- Migrations `003` à `005`.

### Corrigé
- **Extraction des mises à jour** : `zstd` était arrêté trop tôt, ce qui
  faisait échouer une mise à jour par `E_ARCHIVE`, au hasard ou à coup sûr
  avec un gros lot. Les mises à jour activent désormais les services ajoutés
  par une nouvelle version.

### À savoir avant de mettre à jour
- Une appliance 0.1 ou 0.2 extrait la mise à jour avec l'ancien code : le
  passage en ligne vers la 0.3 peut échouer par `E_ARCHIVE`. L'échec est
  propre et rien n'est modifié. Dans ce cas, réinstaller depuis l'ISO 0.3.

### Limites connues
- Forges : la console doit pouvoir joindre la forge, et un nom DNS interne
  non résolu n'est pas signalé. Une URL hors forge connue est analysée chaque
  jour, sans détection. Une branche supprimée n'est pas signalée. GitLab
  n'est pas encore pris en charge.
- Runner : IPv4 seulement. Le pic mémoire d'un scanner est parfois absent.
  Le service n'a pas encore de durcissement systemd.
- Résultats : deux secrets de même longueur sur une même ligne partagent une
  empreinte. Une nouvelle correspondance de gravité s'applique à l'analyse
  suivante.
- IA : le jeton porteur d'un proxy devant Ollama n'est pas encore accepté. Il
  arrive en 0.4, avec une copie plus restreinte de la clé de chiffrement pour
  `scanoria-ai`. Deux masquages des secrets coexistent et seront réunis.
- Limite de débit de l'API gardée en mémoire (remise à zéro au redémarrage).

## 0.2.0 — 2026-11-24

Moteur de modules : le catalogue signé, l'installation des outils depuis la
console et l'accès aux applications par leur nom.

### Ajouté
- **Format des modules** : manifeste `module.yaml` validé par
  `catalog/schema/module.schema.json` (dépendances et conflits, options typées
  avec défauts, sorties déclarées, banc d'essai) et guide `docs/MODULES.md`.
- **Premiers modules** : gitleaks, OSV-Scanner et Trivy, chacun avec son banc
  d'essai piégé ; bases `trivy-db` et `osv-db` déclarées.
- **Catalogue signé** (F11, G1) : index publié en release `catalog-v<N>`
  indépendamment de la console, avec manifestes normalisés, packs, bancs
  d'essai empaquetés de façon reproductible, dépendances et conflits contrôlés
  à la construction, `SHA256SUMS` signé Ed25519 avec la clé de mise à jour.
- **Moteur de modules** (service root, Podman et Quadlet) : installation,
  activation, désactivation, mise à jour et retrait depuis un catalogue
  vérifié et rafraîchi chaque jour. Dépendances et conflits résolus,
  ressources, licences et options contrôlées (G3) ; chaque scanner passe son
  banc d'essai confiné avant activation (F12) ; tout échec déclenche un retour
  arrière complet ; une mise à jour est toujours précédée d'une sauvegarde.
- **Accès aux modules par nom** : chaque application installée répond sur
  `<libellé>.<nom de l'appliance>` ; un module désactivé ou un nom inconnu
  affiche la page « application indisponible » de la console.
- **Vérification DNS automatique** de l'appliance, du joker `*.<nom>` et des
  noms des modules (toutes les heures, après un changement de nom ou de
  module) ; contrôle `routing.sites` dans `scanoria-selftest`.
- **Console, section Catalogue** : sélection conseillée au premier accès,
  packs, licences et restrictions, ressources et compatibilité, graphe des
  dépendances ; installation en une confirmation (dépendances et bases
  ajoutées automatiquement, raison affichée, licences à restriction acceptées
  explicitement) ; détail d'un module avec options générées depuis le
  manifeste, banc d'essai, activation, mise à jour et désinstallation en
  gardant ou supprimant les données ; état DNS avec vérification immédiate.
- Batteries `b10` à `b13` et jobs CI `modules-testbed-live` et `modules-live`
  (vrais conteneurs Podman).

### Corrigé
- Canal stable des mises à jour : la dernière version stable est trouvée même
  quand `releases/latest` désigne l'index du catalogue ; la promotion compare
  avec la plus haute version `vX.Y.Z` stable.

### Limites connues
- Aucune analyse de projet encore : les scanners installés ne servent qu'à leur
  banc d'essai jusqu'à la 0.3.
- Modules `service` (SonarQube…) prévus à partir de la 0.4 ; le moteur et
  l'aiguillage par nom sont prêts à les recevoir.

## 0.1.0 — 2026-11-24

Première version : le socle de l'appliance (console seule).

### Ajouté
- **Contrats** : `docs/ARCHITECTURE.md` (chemins de l'appliance, protocole des
  demandes au service root, format des releases, AC interne,
  `scanoria-selftest`) et schémas JSON des demandes, du résultat, de l'état
  publié, du rapport de tests de fumée et de `release.json`.
- **ISO d'installation** (`build.sh --iso`, `make-iso.ps1` pour Windows) :
  construite dans un conteneur `ubuntu:24.04` neuf épinglé par empreinte, à
  partir de l'image officielle vérifiée (signature GPG, puis empreinte
  épinglée) ; installation sans intervention (LVM), paquets hors ligne,
  Node.js 22 vérifié, clé publique de mise à jour épinglée, refus sous le
  plancher matériel (2 vCPU, 4 Go, 40 Go).
- **Assistant de premier démarrage** (console texte, français et anglais,
  retour arrière, jauge d'attente) : langue, clavier, réseau, nom, fuseau,
  mots de passe de la console et du compte `sysadmin`, réseaux
  d'administration ; base de données, AC, certificat, pare-feu, services,
  tests de fumée. Mode sans intervention sous QEMU pour le test de démarrage
  de la CI.
- **Lot de mise à jour** (`build.sh --bundle`) : archive reproductible,
  `release.json`, `SHA256SUMS` à deux lignes, `update-source.json` et
  `MANIFEST` générés.
- **Console web** (Nuxt 4, Nuxt UI, français et anglais) : tableau de bord,
  mises à jour (installation, planification, retour à N-1), système, TLS,
  utilisateurs, journal d'audit avec détail en panneau latéral, mon compte,
  À propos et licence avec le lien vers le code source de la version
  installée ; API REST documentée (`/api/openapi.json`) ; `GET /api/health`.
- **Comptes locaux** : PBKDF2-SHA256 (600 000 itérations, format PHC), rôles
  `viewer` / `operator` / `admin` appliqués côté serveur, dernier
  administrateur protégé, changement du mot de passe initial imposé.
- **Base de la console** : migrations numérotées (`migrate.mjs`, verrou
  consultatif, empreinte de chaque migration), schéma initial.
- **Service root `scanoria-helper`** (Python, bibliothèque standard) : file
  de demandes de la console, validation stricte par les schémas, résultats
  ingérés par la console ; `scanoria-ca` (AC interne à contrainte de nom,
  certificat `<nom>` et `*.<nom>`, import), `scanoria-firewall` (nftables),
  `scanoria-state`, `scanoria-selftest`, unités et timers systemd.
- **Mise à jour en ligne par les releases GitHub** (F18) : canaux `stable` et
  `prerelease`, API sans jeton avec repli, téléversement hors ligne,
  sauvegarde de la base, retour arrière automatique, retour à N-1, fenêtre de
  maintenance.
- **Chaîne de publication** : CI (`ci-ok` : lint, gitleaks, osv-scanner,
  dependency-review, console contre PostgreSQL 16, batteries shell,
  construction de l'ISO, SonarQube Cloud), CodeQL, Dependabot, test de
  démarrage de l'ISO sous QEMU/KVM, version candidate signée, promotion.
- Batteries shell `tests/b01`–`b04` (système), `b20`–`b21` (construction),
  `b30` (chaîne de signature) ; `OPEN-SOURCE.md`, `CONTRIBUTING.md`,
  `SECURITY.md`.

### Sécurité
- Console sans privilège (utilisateur `scanoria`, unité durcie, boucle locale
  seulement) ; tout changement système passe par une demande validée par le
  service root, sans shell ni interpolation.
- Demandes hostiles refusées : noms, liens symboliques et physiques, FIFO,
  propriétaire, taille, JSON piégé (clés en double, NaN, UTF-8 invalide),
  injections dans le nom, les réseaux et les PEM, identifiants rejoués,
  dates périmées ; anti-verrouillage du pare-feu.
- Mises à jour signées Ed25519 (`SHA256SUMS.sig`, clé publique épinglée),
  vérifiées avant toute installation ; rétrogradation refusée ; archives
  piégées refusées.
- Une version demandée à GitHub est revérifiée juste avant l'installation :
  ni brouillon, ni candidate `[rejected]` (toujours signée valablement), ni
  pré-version sur le canal `stable`. La mise à jour planifiée relance la
  vérification avant d'appliquer, et ne réinstalle jamais une version
  abandonnée par un retour à N-1.
- Mise à jour bornée par une échéance : la console n'est arrêtée que s'il
  reste le temps de déployer, vérifier et revenir en arrière.
- Analyse des PEM importés en temps linéaire (aucune expression régulière à
  retour arrière exponentiel dans le service root).
- Publication d'une version candidate seulement après un `ci-ok` réussi sur
  son commit ; SonarQube Cloud obligatoire hors PR de fork.
- Session : cookie `__Host-` httpOnly, Secure, SameSite=Strict, jeton CSRF,
  contrôle de l'origine, limite par adresse, verrouillage du compte après 5
  échecs ; journal d'audit en ajout seul, sans secret.
- TLS 1.2/1.3 seulement, en-têtes de sécurité (HSTS, X-Frame-Options…) ;
  pare-feu fermé par défaut, administration limitée aux réseaux déclarés.
- Aucun mot de passe en clair sur disque ni en argument ; aucune clé privée
  dans le dépôt, le lot ou l'ISO (contrôlé à la construction et par
  gitleaks) ; actions GitHub et outils épinglés par empreinte.

### Limites connues
- Rien n'a encore tourné sur une vraie appliance ni dans une VM : le test de
  démarrage de l'ISO (QEMU/KVM) et la publication ne s'exécutent que dans
  GitHub Actions.
- Une ISO pèse plus de 4 Go : elle est publiée en morceaux de moins de 2 Gio
  à réassembler (`docs/RELEASING.md`).
- La limite des tentatives de connexion est gardée en mémoire et repart à
  zéro au redémarrage de la console ; les notes de version sont affichées en
  texte brut.
- Toutes les demandes au service root sont réservées aux administrateurs,
  recherche de mise à jour et tests de fumée compris.
- `set-hostname` n'est pas atomique : si nginx échoue après la création de la
  nouvelle AC, il faut relancer la demande.
- Le budget de temps d'une mise à jour (3300 s) est une estimation : un
  retour arrière automatique exceptionnellement long (restauration d'une
  grosse base) peut encore être interrompu par l'arrêt forcé du helper.
- Pas de politique CSP posée par nginx (scripts en ligne de Nuxt).
