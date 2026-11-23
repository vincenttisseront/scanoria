# Lancer le projet — mode d'emploi

Le kit contient :

| Fichier | Rôle |
|---|---|
| `CLAUDE.md` | Contexte complet du projet : objet, principes, architecture, catalogue, analyses, gate de release, mises à jour, itérations, fonctionnalités F1–F20, consignes |
| `.claude/settings.json` | Sonnet 5.5 en session principale, Opus 5.5 en conseiller |
| `.claude/agents/search.md`, `grep.md`, `audit.md` | Sous-agents Haiku 5.5 : exploration, points d'appel, relecture de diff dans un worktree isolé |
| `.gitignore` | Sorties de construction, dépendances, et surtout **clés privées jamais versionnées** |
| `DEMARRAGE.md` | Ce fichier : préparatifs, puis prompts à coller dans Claude Code |

## 1. Décisions à prendre avant le premier prompt
1. **Nom : Scanoria** (décidé), sans publication pour l'instant : aucun nom de domaine à réserver. `CLAUDE.md` est déjà rédigé avec ce nom.
2. **Licence : AGPL-3.0-or-later** (décidée), titulaire Vincent Tisseront. Les conséquences sont décrites dans `CLAUDE.md`, section 14.
3. **Forges (D4) : Forgejo d'abord** (décidé), puis GitHub et GitLab.
4. **Planchers matériels (D6) : console seule 2 vCPU / 4 Go / 40 Go** (décidé), refus en dessous. Pour chaque module, son manifeste fait foi.
5. **Dépôt public, sans aucune communication ; cycle Git géré par Claude** (décidé) : règles dans `CLAUDE.md`, sections 12 et 16.

## 2. Préparatifs (une fois)
1. **Dépôt GitHub public** `<propriétaire>/scanoria`, vide (sans README). Public ne veut pas dire annoncé : pas de site ni de communication. Mais n'y mettez jamais rien qui révèle votre infrastructure, et jamais de secret.
2. **Copier le kit** à la racine du dépôt (le nom est déjà en place partout).
3. **Accès de Claude à GitHub.** Claude gère push, PR, merges et publications. Son environnement doit donc être authentifié sur ce dépôt (`gh auth login`, ou un jeton à granularité fine limité au dépôt) avec ces droits :
   - *Contents* : lecture et écriture ;
   - *Pull requests* : lecture et écriture ;
   - *Workflows* : lecture et écriture (indispensable pour modifier `.github/workflows`) ;
   - *Actions* : lecture ;
   - *Metadata* : lecture.
4. **Environment `release`** (*Settings → Environments*) limité à la branche `main`.
5. **Clé de signature des mises à jour** (Ed25519), sur un poste de confiance :
   ```bash
   openssl genpkey -algorithm ed25519 -out signing.key
   openssl pkey -in signing.key -pubout -out update-pubkey.pem   # clé PUBLIQUE : à donner à Claude en 0.1, elle sera versionnée
   gh secret set UPDATE_SIGNING_KEY --env release --repo <propriétaire>/scanoria < signing.key
   ```
   Rangez `signing.key` **hors ligne**, dans un coffre ou un gestionnaire de mots de passe, puis supprimez la copie locale. Une clé perdue oblige à réinstaller chaque appliance. Ne la donnez jamais à Claude : seul le travail de signature s'en sert.
6. **SonarQube Cloud** (gratuit pour un dépôt public) : importez le dépôt, désactivez l'*Automatic Analysis*, puis posez le jeton en secret de dépôt `SONAR_TOKEN`. La couverture de tests sera ainsi envoyée par la CI.
7. **Protection de `main`** (*Settings → Rules → Rulesets*), après la première CI verte : PR obligatoire, contrôles requis `ci-ok`, CodeQL (`analyze`) et quality gate SonarQube Cloud, pas de force-push ni de suppression. Claude peut la poser pour vous à ce moment-là : il demandera votre accord.
8. **Machine de construction** : Windows avec Docker Desktop (WSL2), ou Linux avec Docker ou Podman. Elle a besoin de l'ISO officielle Ubuntu Server 24.04, que le script de construction vérifie.
9. **VM de test** : 4 vCPU, 8 Go de RAM, 80 Go de disque. Dans votre DDI, créez `analyse.<domaine>` et `*.analyse.<domaine>` vers son adresse : c'est l'accès par nom.
10. **Instance de validation**, utile à partir de la première version candidate : une seconde VM et AWX, sur le même modèle que pour Ipnoria. Le jeton d'AWX a besoin de *Contents* en lecture et écriture pour envoyer son verdict.

## 3. Premier prompt (itération 0.1)
Ouvrez Claude Code à la racine du dépôt (`claude`), puis collez :

```text
Lis CLAUDE.md en entier. Décisions : nom = Scanoria, licence = AGPL-3.0-or-later, dépôt public non annoncé, cycle Git
géré par toi selon la section 16, forge prioritaire = Forgejo, planchers = section 11. Clé publique de signature : update-pubkey.pem (déjà versionnée).

Nous démarrons l'itération 0.1 (section 13) et rien d'autre : ISO console seule, assistant de premier démarrage,
console (auth locale, rôles, journal d'audit cliquable, À propos et licence), PostgreSQL 16, pare-feu nftables,
nom de l'appliance, AC interne et certificat <nom de l'appliance>/*.<nom de l'appliance>, mise à jour en ligne
par les releases GitHub (F18, section 10), la commande de tests de fumée (selftest), et la chaîne de publication (CI avec contrôle ci-ok, version candidate, validation,
promotion), sur le modèle de celle d'Ipnoria.

1. Commence par un plan : arborescence, fichiers, schéma de base initial, liste des tests par fichier, contenu de la CI.
   Signale tout point de CLAUDE.md qui te semble contradictoire ou risqué. Attends mon accord avant d'écrire du code.
2. Puis implémente par étapes, avec les tests de chaque étape (tests confiés aux sous-agents Haiku, section 16).
3. Termine par une relecture du diff avec le sous-agent audit et corrige ce qu'il trouve. Ouvre la PR « 0.1.0 » avec
   la section du CHANGELOG, fusionne-la quand ci-ok est vert, puis suis la publication et rapporte le résultat.
```

## 4. Prompts des itérations suivantes
```text
Itération 0.N de CLAUDE.md (section 13), fonctionnalités F… de la section 15. Mêmes règles : plan d'abord et mon accord,
puis implémentation avec tests, relecture par audit, PR avec CHANGELOG, merge quand ci-ok est vert et suivi de la
publication. Rien hors de cette itération ; note dans CLAUDE.md toute décision nouvelle que je prends en cours de route.
```

## 5. Ordre de marche conseillé
- 0.1 → 0.3 : l'appliance devient utile (catalogue, premiers scanners, analyses de vos dépôts).
- 0.4 → 0.6 : SonarQube, SBOM, hors ligne.
- 0.8 : **Scanoria contrôle ses propres releases et celles d'Ipnoria**, en plus de CodeQL et SonarQube Cloud.
