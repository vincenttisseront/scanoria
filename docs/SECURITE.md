<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Vincent Tisseront
-->

# Sécurité de Scanoria

Ce document résume les choix de sécurité de l'appliance et de sa chaîne de
publication. Les contrats détaillés sont dans [ARCHITECTURE.md](ARCHITECTURE.md).
Pour signaler une vulnérabilité, voir [SECURITY.md](../SECURITY.md).

## 1. Appliance

- **Frontière de privilèges** : la console web tourne sans privilège, sous
  l'utilisateur `scanoria`. Pour toute action système, elle dépose une demande
  JSON, que `scanoria-helper` (root) valide strictement puis exécute :
  - liste fermée de types ;
  - schéma de chaque type ;
  - contrôles `lstat` (fichier régulier, un seul lien, bon propriétaire) ;
  - taille bornée.

  Le résultat rapporte un code d'une liste fermée, jamais un secret.
- **Configuration** : `/etc/scanoria` est écrit par le helper seul. Une mise à
  jour ne touche jamais `/etc`.
- **Accès réseau** : nftables n'ouvre l'administration (22, 80, 443) qu'aux
  réseaux déclarés.
- **TLS** : une AC interne (ECDSA P-256) émet le certificat de `<nom>` et
  `*.<nom>`. Ses `nameConstraints` la limitent au nom de l'appliance, ou à un
  certificat importé et vérifié.
- **Comptes** : mots de passe hachés en PBKDF2-SHA256 (600 000 itérations,
  format PHC). Pour les sessions, seule l'empreinte SHA-256 du jeton est en
  base. Un déclencheur interdit toute modification du journal d'audit, qui
  reste en ajout seul.
- **Mises à jour signées** : avant toute installation, la clé publique
  Ed25519 épinglée par l'ISO vérifie `SHA256SUMS`, puis les empreintes, puis
  `release.json`. Le helper refuse une rétrogradation, extrait l'archive sous
  contrôle (ni lien, ni chemin absolu, ni `..`) et sauvegarde la base
  avant l'installation. Il revient en arrière automatiquement si la console ne
  redémarre pas.
- **Sans jeton** : l'appliance interroge l'API publique de GitHub sans
  identifiant, en HTTPS seul.

### Relais IA des modules d'analyse par IA (0.7)

- Le conteneur d'un module d'IA reste en `--network=none` : il ne joint que le
  socket Unix du relais, monté en lecture seule, à travers un pont qui ne lit
  rien de ce qui passe ; le TLS (certificat `ai-relay.<nom>` de l'AC interne)
  va de l'outil au relais. Aucun réseau Podman, aucune règle nftables ajoutée.
- Jeton éphémère par module et par analyse, lié au projet ; jamais en argument
  ni en variable visible de `podman inspect` (secret Podman lu par le pont),
  masqué dans les journaux, retiré après le module.
- Le relais applique les garde-fous de CLAUDE.md § 3.5 à chaque requête :
  outils retirés, secrets masqués (messages système compris), consigne de
  l'appliance en tête, « aucun envoi à l'IA » et cloisonnement par projet,
  taille bornée, modèle choisi par l'appliance, journal sans contenu.
- Les résultats d'un module d'IA n'entrent dans aucun verdict sans
  confirmation d'une personne (compte humain, rôle operator ou plus, audit) ;
  un compte « agent » ou « bot » et un jeton d'API ne confirment jamais.

## 2. Dépôt et CI

- **Dépôt public, mais non annoncé** : aucun nom d'hôte, domaine, adresse ou
  identifiant réel. Les exemples utilisent `exemple.test` et les plages
  RFC 5737 ou RFC 3849.
- **Aucun secret versionné**, même factice. gitleaks parcourt tout
  l'historique avec ses règles par défaut, **sans exception** pour un fichier
  versionné. Les clés de test sont générées à l'exécution. Une valeur qui
  ressemble à une clé privée, même tronquée, se construit à l'exécution dans
  le test.
- **Chaîne d'approvisionnement** :
  - actions épinglées par SHA ;
  - outils téléchargés vérifiés par empreinte ;
  - image PostgreSQL de CI épinglée par empreinte ;
  - `dependency-review` sur les PR ;
  - osv-scanner, avec des exceptions datées et motivées ;
  - Dependabot ;
  - CodeQL (JavaScript/TypeScript et workflows) ;
  - SonarQube Cloud.
- **Droits minimaux** : `permissions: {}` par défaut, droits explicites par
  travail, `persist-credentials: false`. Aucun `pull_request_target`, aucun
  runner auto-hébergé.
- **Clé de signature** : secret `UPDATE_SIGNING_KEY` de l'environment
  `release`, limité à `main`. Seuls les travaux de signature le lisent ;
  ils vérifient que la clé correspond à `update-pubkey.pem` avant de signer,
  puis l'effacent. Toute signature est vérifiée avec la clé publique
  versionnée avant publication.
- **Publication** : refusée hors de `main`. Un numéro n'est jamais
  reconstruit. La promotion exige le statut de validation `scanoria/validation`
  et un `ci-ok` vert ([RELEASING.md](RELEASING.md)).

## 3. Limites connues (0.1)

- Changer de clé de signature n'est pas prévu : cela demande une nouvelle ISO.
- Le retour à N-1 restaure la base sauvegardée avant la mise à jour : les
  données écrites depuis sont perdues, et la console l'annonce.
- Le mode sans intervention du premier démarrage n'existe que sous QEMU, via
  fw_cfg ([TESTING.md](TESTING.md#4-test-de-démarrage-de-liso)).
