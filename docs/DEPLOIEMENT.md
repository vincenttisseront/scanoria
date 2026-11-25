# Déploiement après verdict favorable (0.8 : J9, J11–J13, J16)

> SPDX-License-Identifier: AGPL-3.0-or-later. Copyright (C) 2026 Vincent Tisseront.

Après un verdict **favorable** d'une release (ou d'une branche configurée), Scanoria **déclenche, propose ou promeut** ; il ne déploie jamais lui-même. L'appliance ne détient **aucun accès à la production** : ni SSH, ni Ansible, ni `kubectl`. Elle **ne fusionne aucune PR** : la fusion automatique, quand elle existe, est celle de la forge.

Rien ne part si le verdict n'est pas `passed`. Le refus est enregistré dans `deployments` (`status = 'refused'`) avec sa raison : `verdict-not-passed`, `target-disabled` ou `project-suspended`.

## Cibles

Une cible (`deploy_targets`) appartient à un projet, pour un environnement (`production`, `staging`…) et un déclencheur (`release` ou `branch`). Elle se déclare dans la page du projet, carte « Déploiement après verdict favorable » (administrateur), et chaque changement est tracé dans l'audit. Une exécution (`deployments`) est créée **une seule fois** par cible et par analyse.

| Type | Ce que fait l'appliance | Jeton |
|---|---|---|
| `registry-promotion` (J13) | résout l'empreinte de la candidate (étiquette `{tag}` par défaut) dans le dépôt « candidat », signe l'attestation J9, copie l'image **par empreinte** vers le dépôt « validé » (index multi-architecture compris), relit l'empreinte dans la destination, puis y joint l'attestation | `registry-token` (compte et mot de passe ou jeton du registre) |
| `gitops-pr` (J12) | ouvre, dans le dépôt de déploiement (Argo CD, Flux), une PR qui remplace l'empreinte `@sha256:` de l'image dans les fichiers désignés | jeton de la forge du projet |
| `cd-trigger` (J11, défaut) | déclenche la CD existante (`workflow_dispatch` Forgejo ou GitHub, déclencheur de pipeline GitLab, job Jenkins), puis suit son résultat 6 h au plus | forge : celui du projet ; GitLab et Jenkins : `deploy-token` |

Ordre fixe pour une analyse : registre (et attestation), puis GitOps, puis CD. À la première étape en échec, les suivantes échouent avec `E_DEPLOY_PREVIOUS` : la chaîne s'arrête net.

### J11 : cible proposée automatiquement

Un workflow du dépôt (`.forgejo/workflows/`, `.gitea/workflows/` ou `.github/workflows/`) qui se déclenche à la main et déclare l'entrée `scanoria_report` est **proposé** comme cible `cd-trigger`. L'administrateur confirme une fois, puis la cible joue seule. Entrées passées, si le workflow les déclare :

| Entrée | Valeur |
|---|---|
| `scanoria_report` | lien vers l'analyse dans la console (rapport signé, verdict) |
| `scanoria_commit` | empreinte du commit analysé |
| `scanoria_tag` | tag de la release |
| `scanoria_image` | première image promue, `dépôt@sha256:…` |

```yaml
# .forgejo/workflows/deploy.yml (exemple)
on:
  workflow_dispatch:
    inputs:
      scanoria_report: { required: true, type: string }
      scanoria_commit: { required: true, type: string }
      scanoria_tag: { required: false, type: string }
jobs:
  deploy:
    runs-on: docker
    steps:
      - run: echo "Déploiement de $SCANORIA_COMMIT (rapport $SCANORIA_REPORT)"
        env:
          SCANORIA_COMMIT: ${{ inputs.scanoria_commit }}
          SCANORIA_REPORT: ${{ inputs.scanoria_report }}
```

Les entrées sont **toujours passées par des variables d'environnement**, jamais interpolées directement dans un script (`run: … ${{ inputs.… }}`) : c'est la règle que zizmor (H1) vérifie, et elle protège d'une valeur piégée. Scanoria borne déjà les valeurs : `scanoria_tag` n'est transmis que s'il ne contient que des lettres, chiffres et `._/+-` (vide sinon), et aucune entrée ne contient de caractère de contrôle ni ne dépasse 500 caractères.

Pour Jenkins, les entrées sont passées en paramètres en majuscules (`SCANORIA_REPORT`…), par `buildWithParameters`, avec un compte et un jeton d'API Jenkins.

Un déclenchement n'est **jamais rejoué** automatiquement : l'exécution est réservée avant l'appel, et une passe interrompue finit au pire en échec par délai, jamais en double déploiement.

### J12 : PR GitOps

La modification est **textuelle et bornée** : seules les références `<image>[:<étiquette>]@sha256:<hex>` déjà présentes voient leur empreinte changer, à l'octet près pour le reste du fichier. Aucun outil du dépôt n'est exécuté. Refus : chemin absolu ou `..`, fichier qui n'est pas un fichier ordinaire (lien symbolique), plus de 256 Kio, binaire, aucune référence épinglée, plus de 100 références. La branche est `scanoria/promote/<environnement>-<analyse>`, le retour arrière se fait par revert.

La fusion est **humaine par défaut**. Un administrateur peut autoriser, pour cette cible seulement, la fusion automatique **de la forge** (modale de confirmation, `auto_merge_by` tracé) : Scanoria active alors « fusionner quand les contrôles passent », et c'est la forge qui fusionne.

## J9 : attestations

Pour chaque image promue, une déclaration in-toto (Statement v1) est construite :

- sujet : le dépôt « validé » et l'empreinte `sha256` de l'image ;
- `predicateType` : `https://github.com/vincenttisseront/scanoria/attestation/release-verdict/v1` ;
- prédicat : `scan_id`, `project_id`, `verdict` (toujours `passed`), `commit_sha`, `ref`, `tag`, `report_sha256` (rapport de release signé, contrat 36), `report_url`, `evaluated_at`.

La signature passe par la demande root `sign-attestation` (contrat 37) : la console envoie la déclaration canonique elle-même ; le helper la relit (JSON canonique, forme exacte, sujet unique par empreinte, `scan_id` égal, verdict `passed`), recalcule son SHA-256, puis signe la PAE DSSE avec la clé de l'appliance. La clé privée ne quitte jamais le helper. Codes : `E_ATTEST_ENCODING`, `E_ATTEST_CANONICAL`, `E_ATTEST_DIGEST`, `E_ATTEST_STATEMENT`, `E_ATTEST_SUBJECT`, `E_ATTEST_SCAN`, `E_ATTEST_VERDICT`, `E_ATTEST_KEY`.

L'enveloppe est poussée au **format cosign** (étiquette `sha256-<hex>.att`, couche `application/vnd.dsse.envelope.v1+json`). Sans droit d'écriture, elle reste téléchargeable depuis la console (`GET /api/deploy/attestations/:id`), et c'est signalé.

Vérification :

```sh
curl -fsS https://analyse.exemple.test/api/system/appliance-key > appliance-key.json
scanoria-verify attestation registre.exemple.test/valide/app@sha256:<hex> --key appliance-key.json
# ou, avec cosign :
jq -r .pem appliance-key.json > appliance.pem
cosign verify-attestation --key appliance.pem --insecure-ignore-tlog \
  --type https://github.com/vincenttisseront/scanoria/attestation/release-verdict/v1 \
  registre.exemple.test/valide/app@sha256:<hex>
```

Politique d'admission Kyverno d'exemple : [`docs/exemples/admission/`](exemples/admission/).

## J16 : chaîne autonome

Avec `projects.autonomous_chain` (case de la PR d'intégration, chantier C) :

1. l'analyse de PR publie son statut ;
2. si le verdict est favorable **et** que la description de la PR contient la ligne `/scanoria auto-merge` (demande de l'auteur), Scanoria active la fusion automatique native de la forge ; la forge fusionne quand les contrôles requis sont verts ;
3. le tag lance le profil `release` (chantier A) ;
4. le verdict favorable lance les cibles : registre, GitOps, puis CD.

Toute étape défavorable ou non concluante arrête la chaîne ; la page du projet montre chaque étape, la raison (I9) et le lien vers l'analyse pour demander une exception (J15). Un échec de déploiement est rattaché à l'analyse ; la notification arrive avec F10 (0.9).

## API

| Route | Rôle |
|---|---|
| `GET /api/deploy/projects/:id/targets` | lecture |
| `POST /api/deploy/projects/:id/targets` | admin |
| `GET /api/deploy/projects/:id/proposals` | admin |
| `GET /api/deploy/projects/:id/chain` | lecture |
| `PATCH /api/deploy/targets/:id` | admin |
| `DELETE /api/deploy/targets/:id` | admin |
| `GET /api/deploy/scans/:id` | lecture |
| `GET /api/deploy/attestations/:id` | lecture |

## Limites connues

- La politique Kyverno est validée par `kyverno test` (chargement et périmètre) ; la vérification d'une vraie attestation par Kyverno demande un cluster et un registre joignable, non montés en CI. `cosign verify-attestation` et `scanoria-verify attestation` sont, eux, testés contre un vrai registre (b40-live).
- Forgejo ne rend un identifiant de run que s'il accepte `return_run_info` ; sinon (comme GitHub sans `return_run_details`), le run est cherché parmi les derniers déclenchements manuels, puis l'exécution est marquée `E_DEPLOY_UNTRACKED` au bout de 10 minutes.
