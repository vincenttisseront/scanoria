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

**Pourquoi aucune règle nftables.** Un module d'IA ne reçoit aucun réseau :
son conteneur est lancé en `--network=none`, comme tout scanner. Il n'y a donc
ni interface, ni route, ni adresse à filtrer, et rien à ouvrir dans nftables.
La seule sortie vers Ollama reste celle de `scanoria-ai` (règle `meta skuid`
du connecteur, inchangée). Un réseau Podman dédié aurait demandé une passerelle,
des règles de filtrage et un contrôle qu'aucun autre conteneur ne s'y attache :
le socket Unix supprime ces trois points.

**Ce que voit le conteneur**, en lecture seule, en plus de `/src` et `/out` :

- `/run/scanoria-relay/relay.sock` : le socket du relais, seul fichier monté
  du répertoire d'exécution de `scanoria-ai` (0700 sur l'hôte : aucun autre
  compte que root et `scanoria-ai` ne peut le joindre sur l'hôte) ;
- `/run/scanoria-relay/ca.pem` : le certificat public de l'AC interne ;
- `/scanoria-relay/bridge.py` : le pont de l'appliance ;
- `/etc/hosts` : `ai-relay.<nom>` vers `127.0.0.1`, rien d'autre ;
- `/run/secrets/relay-token` : son jeton éphémère (secret Podman, 0400,
  utilisateur 65534).

Il ne voit ni la clé du certificat, ni la configuration du connecteur, ni le
jeton porteur d'Ollama, ni la base, ni les jetons des autres modules (le
répertoire des jetons n'est pas monté).

**Ce que le pont permet.** Il écoute sur la boucle locale du conteneur
(`127.0.0.1:8443`) et recopie les octets de chaque connexion vers le socket
du relais, sans les lire ni les modifier : 32 connexions au plus, refermées
après 10 minutes sans échange. Il ne permet de joindre que le relais, qui
n'expose que `/v1/models`, `/v1/chat/completions`, `/v1/embeddings` et
`/v1/relay/check`, chacune après vérification du jeton. Le TLS (certificat
`ai-relay.<nom>`, vérifié par l'outil avec l'AC interne) va de l'outil au
relais : le pont ne voit que du chiffré.

**Jeton éphémère** par module et par analyse, lié au projet et au module, avec
une expiration au-delà du délai du module ; jamais en argument ni en variable
visible de `podman inspect` (secret Podman lu par le pont), masqué dans les
journaux, retiré après le module ; jetons et secrets orphelins purgés au
démarrage du runner.

**Garde-fous du relais** (CLAUDE.md § 3.5), à chaque requête : outils
retirés, secrets masqués (messages système et schéma JSON compris), consigne
de l'appliance en tête, « aucun envoi à l'IA » et cloisonnement par projet,
taille bornée, modèle choisi par l'appliance, journal sans contenu.

**Verdict** : les résultats d'un module d'IA n'entrent dans aucun verdict sans
confirmation d'une personne (compte humain, rôle operator ou plus, audit) ; un
compte « agent » ou « bot » et un jeton d'API ne confirment jamais. Une panne
de l'IA (relais, modèle, sortie invalide) ne rend jamais un verdict non
concluant : le module est « skipped », la panne figure dans la couverture de
l'analyse (G15, `ai-module-failed`) et dans la santé des analyses (G20).

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
