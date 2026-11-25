# Modèles CI officiels de Scanoria (J3)

Chaque modèle tient en une ligne d'appel et enveloppe `scanoria-scan` par
l'étape commune `scanoria-ci.sh` : verdict du quality gate en code de sortie,
téléversement des résultats produits par la CI (J6), et **OIDC par défaut**
quand la CI le permet (J4) : aucun secret à créer.

| CI | Fichiers | Appel | Authentification |
|---|---|---|---|
| GitHub Actions | `github/scanoria.yml`, `github/action.yml` | `run: sh .github/scanoria/scanoria-ci.sh` ou `uses: <dépôt d'actions>@<sha>` | OIDC (`id-token: write`) |
| Forgejo Actions | `forgejo/scanoria.yml`, `forgejo/action.yml` | `run: sh .forgejo/scanoria/scanoria-ci.sh` | OIDC (`enable-openid-connect: true`) |
| GitLab CI | `gitlab/scanoria.yml` | `include: [{local: .gitlab/scanoria.yml, inputs: {…}}]` | OIDC (`id_tokens`, audience `scanoria`) |
| Jenkins | `jenkins/vars/scanoria.groovy` | `scanoria(url: …, project: …)` | jeton d'API du projet (identifiant Jenkins) |
| Tekton | `tekton/scanoria-task.yaml` | `taskRef: {name: scanoria}` | jeton d'API du projet (Secret) |

La console les sert sous **Projets → Intégration CI**, avec l'adresse de
l'appliance, l'identifiant du projet et l'empreinte du client déjà remplis, et
la PR d'intégration (J2) les ajoute d'elle-même au dépôt.

- Les modèles sont versionnés avec l'appliance. Ils sont copiés dans le dépôt
  (épinglés par son commit) ; le client `scanoria-scan` téléchargé depuis
  l'appliance est refusé si son empreinte diffère de `SCANORIA_CLIENT_SHA256`.
- Les actions tierces sont épinglées par empreinte (`@<sha>`), les images par
  `@sha256:`. Droits minimaux : `contents: read`, `id-token: write`,
  `statuses: read` (mode tiré).
- **Mode poussé** (`SCANORIA_MODE=push`) : la CI appelle l'appliance et attend
  le verdict. **Mode tiré** (`pull`) : l'appliance n'est pas jointe ; la CI
  attend le statut de commit `scanoria/release-gate` que l'appliance pose
  (GitHub et Forgejo).
- Jenkins et Tekton n'émettent pas de jeton OIDC de CI standard : ils utilisent
  le jeton d'API du projet, rangé dans le magasin de secrets de la CI.
- **Le verdict qui fait foi est le statut de commit `scanoria/*` posé par
  l'appliance**, exigé par la protection de branche (J2), pas le résultat du
  job : l'étape tourne dans la CI du dépôt, qu'un auteur de PR peut modifier.
- Liaisons OIDC créées à l'enrôlement : branche principale, tags et PR
  (`refs/pull/*` ; GitLab : `refs/heads/*`, la branche source d'une merge
  request), avec l'identifiant immuable du dépôt épinglé : un dépôt supprimé
  puis recréé sous le même nom n'est pas accepté. Une PR venue d'un fork ne
  reçoit pas de jeton OIDC (GitHub) : l'analyse de PR de l'appliance (G18)
  la couvre.
