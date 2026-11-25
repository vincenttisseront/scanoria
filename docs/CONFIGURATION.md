# Configuration en code (J8) et reprise de l'existant (J5)

## `.scanoria.yml` dans un dépôt analysé

Fichier facultatif, à la racine du dépôt. La console le lit **à chaque
analyse**, au commit analysé, **sans rien exécuter**. Schéma JSON :
[`scanoria-config.schema.json`](scanoria-config.schema.json), aussi servi par la
console (`GET /api/config/schema`).

```yaml
version: 1
profiles:            # profil par déclencheur (G9) ; un champ absent garde le choix du projet
  pr: rapide
  nightly: complet
  release: release
exceptions:          # des DEMANDES : un administrateur les approuve (F5, J15)
  - kind: path
    path: "tests/fixtures/**"
    tool: gitleaks
    reason: "Jeux d'essai volontairement vulnérables"
    until: 2027-03-01
  - kind: vuln
    vuln: CVE-2026-12345
    package: lodash
    reason: "Fonction vulnérable jamais appelée"
    until: 2027-01-31
ignore:              # chemins ignorés, notés dans la couverture (G15)
  - "docs/**"
  - { path: "vendor/**", reason: "Code tiers", until: 2027-02-01 }
```

Règles :

- **Rien n'est approuvé par le fichier.** Exceptions et chemins ignorés
  deviennent des demandes (`requested_via = config`, identité non humaine) :
  l'auteur d'un commit ne lève jamais seul un blocage. Un chemin ignoré reste
  analysé tant que sa demande n'est pas approuvée.
- **Verrous (G8).** Un profil demandé par le fichier n'échappe pas aux verrous
  du profil que le projet aurait choisi : ils s'y ajoutent. Un profil inconnu
  ou archivé est signalé et ignoré. Un module exigé par un verrou ne peut pas
  être exclu ; un avis `MAL-` n'a jamais d'exception (H4).
- **Fichier invalide** (YAML cassé, ancres ou alias, étiquettes, clés
  inconnues ou en double, plusieurs documents, octets non UTF-8, plus de
  64 Kio, chemin hors du dépôt ou couvrant tout le dépôt) : signalé sur la
  page du projet, et la **configuration précédente** reste appliquée.
- Dates de fin : obligatoires, ramenées à un an au plus.
- L'état de la dernière lecture (commit, empreinte, problèmes, demandes
  déposées) est affiché sur la page du projet (`projects.config_state`).

## Export et import de la configuration de l'appliance

**Système → Configuration** : export en YAML versionné des profils (avec leurs
verrous), quality gates, jeux de règles (dernière version), tables de gravité
modifiées, règles de tri et projets. **Aucun secret** n'y figure : jetons de
forge, clés SSH et jeton du connecteur IA se ressaisissent dans la console.

L'import montre d'abord les écarts (création, modification, inchangé) et les
problèmes (verrou assoupli, parent inconnu, cycle, profil archivé, projet sur
archive). L'application, confirmée dans une modale, exige l'empreinte de
l'aperçu : un fichier modifié entre-temps est refusé. Tout est appliqué dans
une seule transaction et tracé dans l'audit (`config.export`, `config.import`).

## Reprise de l'existant (J5)

Page d'un projet → **Reprendre l'existant** (administrateur). Sources :

| Source | Traduction |
|---|---|
| `.gitleaks.toml` (`allowlist`, `allowlists`) | chemins dont l'expression se traduit exactement en glob ; `regexes`, `commits`, `stopwords` signalés |
| `.gitleaksignore` | chemin du fichier pour gitleaks |
| `.trivyignore`, `.trivyignore.yaml` | avis (CVE, GHSA…) ou règle Trivy ; `exp:` / `expired_at` repris s'il est plus proche |
| `osv-scanner.toml` (`IgnoredVulns`) | avis, motif et `ignoreUntil` repris |
| `.semgrepignore` | chemins pour Opengrep et Semgrep ; négations signalées |
| `sonar-project.properties` | `sonar.exclusions`, règles `multicriteria` globales |
| `.checkov.yaml`, `.hadolint.yaml`, `.bandit` | règles ignorées |
| `# nosec` (fichiers Python, 40 au plus) | chemin du fichier pour Bandit |
| SonarQube (`FALSE-POSITIVE`, `WONTFIX`) | résultat correspondant de la console |
| Dependency-Track (`NOT_AFFECTED`, `FALSE_POSITIVE`, supprimé) | avis et composant |
| DefectDojo (faux positif, risque accepté) | avis, sinon résultat correspondant |

Chaque entrée devient une **demande** `tool-import`, motif « importé (…) »,
date de fin par défaut à 90 jours. Ce qui ne se traduit pas exactement est
listé, jamais élargi. Le jeton d'administration d'une instance est chiffré le
temps de l'aperçu (une heure au plus), puis effacé à l'application.
