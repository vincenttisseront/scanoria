# Forges : connexion, webhooks, retour dans les PR (0.7)

Ce document décrit comment l'appliance se raccorde à une forge (Forgejo, GitHub,
GitLab), ce qu'elle y lit et y écrit, et pourquoi. Il couvre J1, J7, J15 (côté
forge), G18, H6, I25 et V8.

## 1. Connexion (J1)

| Forge | Mode de connexion | Ce que l'administrateur fait |
|---|---|---|
| GitHub | **Application GitHub** créée par l'appliance (flux du manifeste) | « Connecter GitHub en un clic », puis « Installer » sur les dépôts voulus |
| Forgejo | **Jeton d'un compte de service** | crée un compte dédié dans la forge, lui donne accès aux dépôts, colle son jeton |
| GitLab | **Jeton d'un compte de service** (ou d'un *bot user* de groupe) | idem |

### Pourquoi un jeton de service pour Forgejo et GitLab

Le brief initial prévoyait des applications OAuth pour Forgejo et GitLab. Une
application OAuth agit **au nom d'une personne** : ses droits sont ceux de
l'administrateur qui l'a autorisée, ils disparaissent quand ce compte part,
et elle demande un jeton de rafraîchissement à garder. Pour un service qui
tourne sans personne derrière, un **compte de service** est plus sûr et plus
simple :

- ses droits sont **réduits** à ce qui est nécessaire (portées ci-dessous) et
  limités aux dépôts auxquels on l'ajoute ;
- il est **révocable** à tout moment dans la forge, sans toucher à un compte
  humain ;
- ses actions sont identifiées dans la forge (commentaires, statuts) comme
  celles de l'appliance ;
- un seul secret à garder, chiffré en base, jamais réaffiché.

La console l'affiche ainsi pour chaque forge de ce type, avec les portées
exactes. Les types `forgejo-oauth` et `gitlab-oauth` restent prévus dans le
schéma pour une version ultérieure.

**Portées exactes demandées :**

| Forge | Portées |
|---|---|
| Forgejo | `read:user`, `read:organization`, `write:repository`, `write:issue` |
| GitLab | `api`, `read_repository` (GitLab n'a pas de portée plus fine pour les statuts de commit et les discussions de MR) |
| GitHub (application) | `metadata:read`, `contents:read`, `statuses:write`, `checks:write`, `pull_requests:write` ; évènements `push`, `pull_request`, `issue_comment`, `repository` |

### GitHub en un clic

1. La console prépare le manifeste (droits minimaux, webhook vers
   `/api/forges/<id>/webhook`, retour vers `/forges/github`) et un **jeton
   d'état** signé (HMAC de la clé de l'appliance), lié à l'administrateur et
   valable 30 minutes.
2. Le navigateur poste le manifeste à GitHub ; l'administrateur valide.
3. GitHub revient sur `/forges/github?code=…&state=…`. La page rappelle
   `POST /api/forges/github/convert` (session et CSRF de la console : le cookie
   est `SameSite=Strict`, il n'accompagne pas la redirection). L'état est
   vérifié, le code échangé contre la clé privée de l'application, le secret
   du webhook et le secret OAuth, tous **chiffrés** en base. Audit
   `forge.app-create`.
4. L'administrateur installe l'application. GitHub revient sur
   `/forges/github?installation_id=…` ; l'identifiant n'est retenu **que si
   GitHub confirme**, avec le JWT de l'application, qu'il lui appartient.
   Audit `forge.app-install`. La découverte démarre.

Le jeton de clonage est un jeton d'installation (une heure), renouvelé toutes
les 30 minutes. Limite connue : une forge GitHub = une installation utilisée
pour les jetons (la première) ; plusieurs organisations = plusieurs forges.

### Enrôlement automatique

La découverte (chaque heure, ou à la demande) :

- crée un projet par dépôt utilisable (profil proposé par F1) ;
- **suspend** le projet d'un dépôt archivé dans la forge
  (`projects.suspended_at`, raison `forge-archived`, audit `project.suspend`) :
  plus d'analyse planifiée, plus de webhook traité ; le désarchivage le
  **reprend** (audit `project.resume`) ;
- pose le **webhook signé** sur chaque dépôt actif (Forgejo, GitLab ; GitHub :
  porté par l'application), si l'adresse de la console est connue ;
- purge les livraisons de webhooks de plus de 30 jours.

## 2. Webhooks : `POST /api/forges/:id/webhook`

Route publique : aucune session, la **signature** fait foi.

| Contrôle | Refus |
|---|---|
| taille ≤ 1 Mio | 413 |
| secret de webhook connu | 403 |
| signature HMAC-SHA256 (`X-Forgejo-Signature` / `X-Gitea-Signature`, `X-Hub-Signature-256`) ou jeton `X-Gitlab-Token`, comparée **à temps constant** | 401 |
| identifiant de livraison présent et bien formé | 400 |
| livraison jamais vue (`webhook_deliveries`) | 409 (rejeu) |

Chaque refus est **compté** (`webhook_deliveries`, statut `rejected`, sous un
identifiant aléatoire : un faux ne peut pas « brûler » l'identifiant d'une vraie
livraison) et affiché dans la console (rejets sur 30 jours). Seuls les
évènements utiles sont traités : push sur une branche suivie, PR ouverte ou
mise à jour, commentaire de PR, installation et dépôt (GitHub). Le contenu du
webhook n'est **jamais cru** : la PR est relue dans la forge (têtes, base).

### Modes poussé et tiré (section 7.2)

Le mode est **automatique** : un webhook signé accepté dans les 30 dernières
minutes → mode poussé ; sinon l'appliance **interroge** la forge toutes les
5 minutes (PR ouvertes, commentaires des dernières 24 heures). Requêtes
sortantes seulement. Un commentaire n'est traité qu'une fois, quel que soit le
chemin.

## 3. Retour dans la PR

- **Statut de commit** `scanoria/<profil>` : en cours, échec anticipé (V8),
  puis verdict final ; lien vers l'analyse dans la console, explication courte
  (I9). Un verdict non concluant est un échec (G13). Republié quand une
  exception approuvée change le verdict (contrat 27, sans réanalyse).
- **Un seul commentaire de synthèse** par PR, mis à jour en place : verdict,
  raisons bloquantes, nouveaux résultats (avec l'explication I2 marquée
  « proposé par IA »), lien « demander une exception » (J15), revue des
  dépendances (H6 : nouvelles dépendances, licence, âge et quarantaine,
  scripts d'installation).
- **Annotations ligne à ligne** (J7), bornées à 30, sur les fichiers modifiés de la PR
  (check run GitHub, revue Forgejo, discussions GitLab).

Tout texte publié passe par `sanitizeForForge` : HTML échappé, images
neutralisées, mentions `@…` et références `#…`, `!…` désamorcées, liens limités
à la console et aux références CWE/CVE/OSV, caractères de contrôle et
bidirectionnels retirés, longueur bornée.

## 4. Analyse des PR (G18)

L'analyse d'une PR porte sur son commit de tête (`refs/pull/<n>/head`,
`refs/merge-requests/<n>/head`). Les **fichiers modifiés** (lus dans la forge,
3 000 au plus, sinon analyse complète) sont passés aux modules qui déclarent
`scan.incremental` (`/changed-files.txt`). Le quality gate compare à la
**base de la PR** : un résultat est « nouveau » s'il n'était pas dans la
dernière analyse de la branche cible. Une analyse de PR ne déclare jamais un
résultat corrigé. La branche principale reçoit une **analyse complète chaque
nuit** quand des PR ont été analysées.

## 5. `/scanoria accept` (J15)

```
/scanoria accept <résultat> --until AAAA-MM-JJ --reason "motif"
```

- l'auteur du commentaire devient le **demandeur** (identité de la forge,
  jamais un compte de la console) : `requested_via = 'pr-comment'` ;
- les auteurs du commit analysé sont lus dans la forge et **ne peuvent pas
  approuver** ;
- une commande malformée reçoit une aide ; un paquet malveillant (`MAL-`) ou
  une exigence verrouillée est refusé ;
- les commandes des robots, de l'appliance elle-même et celles placées dans un
  bloc de code sont ignorées.

L'approbation se fait dans la console par un administrateur ; le verdict est
alors réévalué et le statut republié.

## 6. Verdict défavorable anticipé (V8)

Le runner écrit `progress.json` après chaque module. Le worker ingère les
modules terminés en avance (ingestion idempotente) et évalue le gate ; une
raison **certaine** (paquet malveillant, secret, KEV, licence interdite) est
publiée aussitôt (`scans.early_failure`, statut d'échec). Un verdict favorable
attend toujours tous les modules.
