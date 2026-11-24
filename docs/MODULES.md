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
| `needs` | non | `sysctl` (posés et retirés par le module), `postgres` (base dédiée) |
| `options` | oui | schéma des paramètres (§ 3) — G3 |
| `options_i18n` | non | traductions des titres et descriptions d'options |
| `scan` | `scanner` | exécution (§ 4) |
| `outputs` | `scanner` | sorties déclarées : `sarif: {path, version: "2.1.0"}` et/ou `cyclonedx: {path, version: "1.x"}` — G2 |
| `testbed` | `scanner` | banc d'essai (§ 5) — F12 |
| `service` | `service` | `{port, health_path, units}` |
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

En 0.2, les options sont validées et enregistrées à l'installation ; le worker
d'analyses (0.3) les applique à la commande.

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

En 0.2, les modules `feed` sont déclaratifs (manifeste seulement) : leur mise à
jour planifiée et les lots hors ligne signés arrivent en 0.6 (§ 9).

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

Une attente avec `rule` compte les résultats SARIF dont `ruleId` vaut `rule` ;
sans `rule`, tous les résultats. `category` est une étiquette pour le rapport.
`min` vaut au moins 1.

Règles du banc d'essai :

- fichiers ordinaires seulement (ni lien, ni fichier spécial), noms en
  `[A-Za-z0-9._+@-]`, chemin relatif au module ;
- faux secrets **générés au hasard**, d'un format qui n'est pas celui d'un
  fournisseur réel protégé par le blocage des poussées de GitHub, et jamais
  de clé privée PEM ;
- le banc est exclu des contrôles du dépôt Scanoria lui-même, **et de rien
  d'autre** : `.gitleaks.toml` (`^modules/[^/]+/testbed/`), osv-scanner
  (`--x-exclude`), dependency-review (`allow-ghsas` de la dépendance figée),
  SonarQube Cloud (`sonar.exclusions`).

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
