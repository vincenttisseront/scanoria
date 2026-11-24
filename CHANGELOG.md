<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Vincent Tisseront
-->

# Journal des modifications

Format : une section par version, la plus récente en tête. La section d'une
version sert aussi de notes de version dans la console (`release.json`,
champ `notes_md`). Les numéros suivent le versionnage sémantique et ne sont
jamais reconstruits : une version rejetée est remplacée par la suivante.

## 0.2.0 — non publiée

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
