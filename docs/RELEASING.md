<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Vincent Tisseront
-->

# Publier une version

Chaîne : **CI complète → version candidate (pré-version) → validation sur
une instance de dev → promotion**. Un numéro n'est **jamais reconstruit** :
une candidate rejetée est remplacée par la version suivante (X.Y.Z+1).

## 1. Préparer la PR de version

Une PR de version :

- modifie les **deux** fichiers `VERSION` (racine et `webui/`) et la version
  de `webui/package.json` ;
- ajoute la section `## X.Y.Z` du `CHANGELOG.md`, qui devient les notes de
  version (champ `notes_md` de `release.json`, signé) ;
- ne fusionne que quand `ci-ok`, `analyze` (CodeQL) et le quality gate de
  SonarQube Cloud sont verts sur son dernier commit.

`check-repo.sh` refuse une incohérence entre les trois numéros, ou une section
absente.

## 2. Version candidate : `release.yml`

`release.yml` se déclenche quand un push sur `main` modifie `VERSION`. Il peut
aussi être relancé à la main, pour reprendre une publication interrompue
avant la création du tag.

| Travail | Contenu |
|---|---|
| `prepare` | Refuse hors de `main`. Lance `check-repo.sh`. **Refuse un tag `vX.Y.Z` ou une release qui existe déjà.** |
| `ci-green` | Attend (jusqu'à 170 min) le contrôle `ci-ok` de `ci.yml` sur ce même commit, qui tourne en parallèle. **Échec ou absence → aucune publication** (CLAUDE.md § 16). |
| `bundle` | `./build.sh --bundle` produit `scanoria-X.Y.Z.tar.zst`, `release.json` (avec `commit` égal au commit publié) et `SHA256SUMS` (deux lignes). |
| `sign-bundle` | Environment `release`. Signe `SHA256SUMS` et vérifie la signature avec `update-pubkey.pem` versionné. |
| `iso` | Vérifie le lot signé, puis construit l'ISO **autour du lot signé** (`SCANORIA_REUSE_BUNDLE=1`, sans reconstruction). Lance le **test de démarrage** dans QEMU/KVM, puis découpe l'ISO en morceaux de moins de 2 Gio. |
| `sign-iso` | Environment `release`. Signe `scanoria-X.Y.Z-amd64.iso.SHA256SUMS`. |
| `publish` | Après `ci-green`. Vérifie tout avec `update-pubkey.pem`, ISO comprise. Revérifie que le numéro est libre (brouillons compris). Crée la **pré-version** `vX.Y.Z` sur le commit construit, sans la marquer *latest*. Enfin, retélécharge les actifs depuis les adresses publiques et les vérifie comme le fera l'appliance. |

Notes de la pré-version : la section du CHANGELOG, suivie d'un paragraphe sur
l'ISO en morceaux.

## 3. Actifs d'une release

| Actif | Rôle |
|---|---|
| `scanoria-X.Y.Z.tar.zst` | lot de mise à jour |
| `release.json` | métadonnées, dont `notes_md` |
| `SHA256SUMS` | exactement deux lignes : `release.json` et l'archive |
| `SHA256SUMS.sig` | signature Ed25519 brute (64 octets) de `SHA256SUMS` |
| `scanoria-X.Y.Z-amd64.iso.partNN` | ISO d'installation en morceaux (< 2 Gio chacun) |
| `scanoria-X.Y.Z-amd64.iso.SHA256SUMS` | empreintes de l'ISO entière et de chaque morceau |
| `scanoria-X.Y.Z-amd64.iso.SHA256SUMS.sig` | signature Ed25519 brute de ce fichier |

L'appliance ne lit que les quatre premiers actifs (ARCHITECTURE § 6.2). Une
ISO dépasse en général la limite de 2 Gio par actif de release GitHub. Elle
est donc publiée **en morceaux** dans la release elle-même : elle reste ainsi
attachée au tag, sans dépendre de la durée de conservation des artefacts de
workflow.

Reconstituer et vérifier l'ISO :

```bash
v=X.Y.Z
openssl pkeyutl -verify -pubin -inkey update-pubkey.pem -rawin \
  -in scanoria-$v-amd64.iso.SHA256SUMS -sigfile scanoria-$v-amd64.iso.SHA256SUMS.sig
cat scanoria-$v-amd64.iso.part* > scanoria-$v-amd64.iso
sha256sum --check --ignore-missing scanoria-$v-amd64.iso.SHA256SUMS
```

Sous Windows : `copy /b scanoria-X.Y.Z-amd64.iso.part00 + scanoria-X.Y.Z-amd64.iso.part01 + … scanoria-X.Y.Z-amd64.iso`, puis `Get-FileHash`.

## 4. Signature

- Clé **Ed25519**. La clé publique `update-pubkey.pem` est versionnée à la
  racine et épinglée dans l'appliance par l'ISO, jamais par une mise à jour.
  Son empreinte (DER) figure dans `src/iso/build.env`.
- La clé privée vit hors ligne et dans le secret `UPDATE_SIGNING_KEY` de
  l'environment `release`, limité à `main`. Personne d'autre ne la lit :
  ni Claude, ni la CI des PR.
- `sign-assets.sh` reçoit la clé par l'environnement, jamais en argument. Il
  l'écrit en 0600 dans le répertoire temporaire du runner, vérifie qu'elle
  correspond à `update-pubkey.pem`, signe avec
  `openssl pkeyutl -sign -rawin`, vérifie la signature, puis efface la clé.
- `verify-release-assets.sh` refait les contrôles de l'appliance :
  - tailles ;
  - deux lignes exactement dans `SHA256SUMS` ;
  - signature ;
  - empreintes ;
  - cohérence de `release.json` ;
  - morceaux de l'ISO.
- Changer de clé n'est pas prévu en 0.1 : cela demande une nouvelle ISO.

## 5. Validation, puis promotion ou rejet : `promote.yml`

L'instance de validation (une VM de dev pilotée par AWX, sur le canal
`prerelease`) installe la candidate et la teste.

**Le verdict est un statut de commit** de contexte **`scanoria/validation`**,
posé sur le commit du tag `vX.Y.Z` :

```bash
# Jeton d'AWX : droits « Commit statuses » (écriture) et « Contents » (écriture,
# pour repository_dispatch) sur ce dépôt seulement.
gh api repos/<propriétaire>/<dépôt>/statuses/<sha> \
  -f state=success -f context=scanoria/validation \
  -f description="validation X.Y.Z" -f target_url=<lien vers le rapport, facultatif>
```

AWX peut ensuite déclencher la promotion ou le rejet lui-même :

```bash
gh api repos/<propriétaire>/<dépôt>/dispatches -f event_type=scanoria-validation \
  -F 'client_payload[version]=X.Y.Z' -F 'client_payload[action]=promote'
```

Une personne peut aussi lancer *Actions → Promote → Run workflow* (depuis
`main`), avec la version et l'action `promote` ou `reject`.

**Promotion** (`action=promote`), refusée sauf si toutes ces conditions sont
remplies :

1. La release `vX.Y.Z` existe, est publiée (pas un brouillon) et est encore
   une pré-version.
2. Son titre ne commence pas par `[rejected]`.
3. `ci-ok` a réussi sur son commit.
4. Le **dernier** statut `scanoria/validation` de ce commit est `success`.
   Un `failure` posé après un `success` bloque.
5. Ses actifs sont intacts : signature vérifiée avec `update-pubkey.pem`
   versionné.
6. La version est strictement supérieure à la version stable actuelle.

La release devient alors une version stable marquée *latest*, **sans
reconstruction** : mêmes actifs, mêmes signatures. Le canal `stable` des
appliances la voit aussitôt.

**Rejet** (`action=reject`) : le titre est préfixé par `[rejected]`. Les
appliances ignorent cette release, même sur le canal `prerelease`, et elle
ne peut plus être promue. La correction passe par X.Y.Z+1.

## 6. Ce qu'il ne faut jamais faire

- Supprimer ou déplacer un tag publié, ou reconstruire un numéro.
- Modifier les actifs d'une release publiée.
- Publier hors de `main`, ou ajouter `continue-on-error` pour passer.
- Lire, copier ou faire tourner `UPDATE_SIGNING_KEY` sans l'accord du
  propriétaire du dépôt.

Ces actions demandent toujours l'accord explicite du propriétaire
(CLAUDE.md § 16).
