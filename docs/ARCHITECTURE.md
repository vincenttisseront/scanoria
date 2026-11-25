<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Vincent Tisseront
-->

# Architecture de Scanoria

Ce document fixe les **contrats communs** de la 0.1 (puis des itérations suivantes, § 4.1, 4.2 et 12) : arborescence, chemins sur
l'appliance, utilisateurs et droits, protocole des demandes de la console au
service root, état publié, format des releases, AC interne, tests de fumée et
base de données. `CLAUDE.md` reste la référence fonctionnelle (sections 2, 3,
10, 12, 13, 14, 16). Toute évolution d'un contrat modifie **d'abord** ce
document et les schémas de `src/rootfs/usr/share/scanoria/`, dans la même PR.

Conventions : noms d'exemple `analyse.exemple.test`, adresses RFC 5737
(`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) et RFC 3849
(`2001:db8::/32`). Horodatages en UTC, RFC 3339 avec `Z`. Versions
`X.Y.Z` sans suffixe : une version candidate est une *prerelease* GitHub du même
numéro, promue sans reconstruction.

---

## 1. Vue d'ensemble

```
┌──────────────────────────── appliance ─────────────────────────────────────┐
│ nftables (table inet scanoria) : 22/80/443 depuis les réseaux d'admin       │
│ nginx :443 (TLS <nom>, *.<nom>) ─► 127.0.0.1:3000 console (Node 22, scanoria)│
│ PostgreSQL 16 (socket Unix, authentification peer) ◄── console             │
│                                                                             │
│ console ──écrit──► /var/lib/scanoria/requests/incoming/*.json               │
│          ◄─lit──── /var/lib/scanoria/requests/{done,failed}/*.json          │
│          ◄─lit──── /run/scanoria/state.json                                 │
│ scanoria-helper (root, déclenché par .path) : valide, exécute, publie       │
│   ├─ scanoria-ca        AC interne, certificats                             │
│   ├─ scanoria-firewall  nftables                                            │
│   ├─ scanoria-selfupdate releases signées, N-1, retour arrière              │
│   ├─ scanoria-state     état JSON (chaque minute et après chaque demande)    │
│   └─ scanoria-selftest  tests de fumée                                       │
└─────────────────────────────────────────────────────────────────────────────┘
```

La console ne fait **jamais** d'opération privilégiée : elle dépose des demandes
et lit l'état. `scanoria-helper` ne fait confiance à rien dans une demande
(CLAUDE.md, principe 4) ; l'autorisation (rôle `admin`) est contrôlée par la
console avant le dépôt, le helper contrôle la forme, les valeurs et les
préconditions.

## 2. Arborescence du dépôt en 0.1 et répartition des lots

| Chemin | Rôle | Lot |
|---|---|---|
| `VERSION`, `webui/VERSION` | numéro de version (identiques) | architecte, puis PR de version |
| `CHANGELOG.md` | une section par version = notes de version | architecte, puis chaque lot ajoute ses lignes |
| `docs/ARCHITECTURE.md` | ce document | architecte |
| `src/rootfs/usr/share/scanoria/requests/*.schema.json` | schémas des demandes et du résultat | architecte (contrat) |
| `src/rootfs/usr/share/scanoria/schemas/*.schema.json` | schémas de `state.json`, du rapport selftest, de `release.json` | architecte (contrat) |
| `webui/server/db/migrations/001_initial.sql` | schéma initial | architecte (contrat) |
| `webui/**` (reste) | console Nuxt 4 + Nuxt UI, Nitro, zod, i18n fr/en, `migrate.mjs`, tests unitaires et e2e (`webui/tests/`) | **A — console** |
| `src/rootfs/**` (reste) | scripts root, unités systemd, sysusers/tmpfiles, gabarits nginx et nftables, valeurs par défaut de `/etc/scanoria` | **B — système** |
| `tests/b01-*.sh` … `tests/b19-*.sh` | batteries shell du lot B : `b01` demandes hostiles, `b02` mises à jour signées, `b03` AC, `b04` contrôles statiques | **B — système** |
| `build.sh`, `make-iso.ps1`, `src/iso/**` | construction du lot de mise à jour (`--bundle`), de l'ISO (`--iso`), autoinstall, paquets hors ligne, Node 22 | **C — ISO** |
| `src/rootfs/usr/sbin/scanoria-firstboot`, `src/rootfs/usr/lib/systemd/system/scanoria-firstboot.service`, `src/rootfs/usr/lib/scanoria/firstboot/` (`hash-password.py`, `netcheck.py`) | assistant de premier démarrage (console texte, mode sans intervention sous QEMU : `docs/TESTING.md` § 4) | **C — ISO** |
| `OPEN-SOURCE.md` | composants tiers livrés dans l'ISO et leurs licences | **C — ISO** |
| `tests/b20-*.sh` … `tests/b29-*.sh` | tests de construction : `b20` contrôles statiques et assemblage sur une fausse sortie, `b21` sorties réelles (`SCANORIA_OUT`) | **C — ISO** |
| `.github/**` | CI (`ci-ok`), CodeQL, Dependabot, `release.yml` (candidate, signature, promotion) | **D — CI et publication** |
| `docs/RELEASING.md`, `docs/CI-CD.md`, `docs/TESTING.md`, `CONTRIBUTING.md` | documentation de la chaîne | **D — CI et publication** |
| `tests/b30-*.sh` … `tests/b39-*.sh` | vérification des actifs de release (format, signature) : `b30` chaîne de signature | **D — CI et publication** |

Hors 0.1 : `modules/`, `catalog/`, `scanoria-worker`, Podman/Quadlet (Podman est
installé par l'ISO mais rien ne l'utilise encore).

## 3. Chemins sur l'appliance

### 3.1 Utilisateurs système

| Utilisateur | Rôle |
|---|---|
| `scanoria` (groupe `scanoria`, système, sans shell, maison `/var/lib/scanoria/console`) | console Node ; rôle PostgreSQL `scanoria` (peer) |
| `root` | `scanoria-helper` et les commandes qu'il appelle, timers |
| `postgres` | PostgreSQL ; `pg_dump`/`pg_restore` lancés par root via `runuser -u postgres` |

Créés par `src/rootfs/usr/lib/sysusers.d/scanoria.conf` ; répertoires par
`src/rootfs/usr/lib/tmpfiles.d/scanoria.conf` (lot B).

### 3.2 Arborescence et droits

| Chemin | Propriétaire, mode | Contenu |
|---|---|---|
| `/opt/scanoria/` | root:root 0755 | logiciel versionné, **jamais modifiable par `scanoria`** |
| `/opt/scanoria/node/` | root:root 0755 | Node.js 22 (installé par l'ISO ; changer de majeure = nouvelle ISO) |
| `/opt/scanoria/releases/X.Y.Z/` | root:root 0755, fichiers 0644/0755 | lot de mise à jour extrait (§ 6.3) |
| `/opt/scanoria/current` | lien symbolique → `releases/X.Y.Z` | version active |
| `/opt/scanoria/previous` | lien symbolique → `releases/X.Y.Z` | N-1 (absent après l'installation initiale) |
| `/usr/sbin/scanoria-*` | root:root 0755 | commandes (§ 3.4), déployées depuis `current/rootfs` |
| `/usr/lib/scanoria/` | root:root 0755 | bibliothèques (`lib/common.sh`, `py/scanoria/*.py`), outils de l'assistant (`firstboot/`) |
| `/usr/lib/systemd/system/scanoria-*` | root:root 0644 | unités (§ 3.5) |
| `/usr/share/scanoria/` | root:root 0755 | schémas, gabarits nginx/nftables, `defaults/`, `update-source.json`, `MANIFEST` |
| `/etc/scanoria/` | root:scanoria 0750 | configuration système, écrite **par le helper seul** |
| `/etc/scanoria/appliance.json` | root:scanoria 0640 | `{"fqdn": "analyse.exemple.test"}` |
| `/etc/scanoria/admin-networks.json` | root:scanoria 0640 | `{"networks": ["192.0.2.0/24"]}` |
| `/etc/scanoria/update.json` | root:scanoria 0640 | politique de mise à jour (champs de `set-update-policy`) |
| `/etc/scanoria/tls.json` | root:scanoria 0640 | `{"mode": "internal" \| "imported"}` |
| `/etc/scanoria/console.env` | root:scanoria 0640 | environnement de la console (§ 3.6) |
| `/etc/scanoria/update-pubkey.pem` | root:root 0644 | clé publique Ed25519 épinglée, **posée par l'ISO, jamais par une mise à jour** |
| `/etc/scanoria/nftables/scanoria.nft` | root:root 0600 | règles générées |
| `/etc/scanoria/pki/` | root:root 0700 | AC et certificats (§ 7) |
| `/var/lib/scanoria/` | root:scanoria 0750 | données |
| `/var/lib/scanoria/console/` | scanoria:scanoria 0700 | données propres à la console |
| `/var/lib/scanoria/bootstrap/` | scanoria:scanoria 0700 | `admin.json` déposé par le premier démarrage (§ 9.3) |
| `/var/lib/scanoria/requests/` | root:scanoria 0750 | file des demandes |
| `…/requests/tmp/` | scanoria:scanoria 0700 | écriture en cours par la console |
| `…/requests/incoming/` | scanoria:scanoria 0700 | demandes complètes, prêtes |
| `…/requests/work/` | root:root 0700 | demandes prises en charge par le helper |
| `…/requests/done/`, `…/requests/failed/` | root:scanoria 0750, fichiers 0640 | résultats (§ 5.6), purgés après 30 jours |
| `/var/lib/scanoria/uploads/<uuid>/` | scanoria:scanoria 0700 | archive de mise à jour téléversée (3 fichiers, § 6.2) |
| `/var/lib/scanoria/updates/` | root:root 0700 | téléchargements, `staging/` ; `check.json` (dernière recherche), `alert.json` (échec du retour arrière, repris dans `state.json.update.alert`), `auto-apply.json` (dernière tentative planifiée) |
| `/var/lib/scanoria/backups/pre-update/` | root:root 0700 | sauvegardes de base avant mise à jour |
| `/var/lib/scanoria/selftest/last.json` | root:scanoria 0640 | dernier rapport selftest |
| `/var/lib/scanoria/public/scanoria-ca.crt` | root:scanoria 0644 (répertoire 0750) | certificat de l'AC interne à distribuer aux postes |
| `/var/lib/scanoria/firstboot.done` | root:root 0644 | marqueur de fin du premier démarrage |
| `/run/scanoria/` | root:scanoria 0750 (tmpfiles) | `state.json` (0640), `helper.lock`, `helper-current.json` (demande en cours, étape) |
| `/etc/nginx/sites-available/scanoria.conf` (+ lien dans `sites-enabled/`) | root:root 0644 | site généré par le helper (§ 4) |
| `/etc/nginx/scanoria/scanoria-ca.crt` | root:root 0644 | copie de l'AC servie par nginx (`www-data` ne lit pas `/var/lib/scanoria`) |
| `/etc/nginx/scanoria.d/` | root:root 0755 | un fichier par module actif (0.2), vide en 0.1 |

`tmp/` et `incoming/` sont sur le même système de fichiers (renommage atomique).

### 3.3 Fichiers déployés par une mise à jour

Une mise à jour (ou un retour arrière) synchronise `current/rootfs/` vers `/`
**uniquement** sous ces préfixes :
`/usr/sbin/scanoria-*`, `/usr/lib/scanoria/`, `/usr/share/scanoria/`,
`/usr/lib/systemd/system/scanoria-*`, `/usr/lib/sysusers.d/scanoria.conf`,
`/usr/lib/tmpfiles.d/scanoria.conf`. Tout autre chemin de `rootfs/` fait échouer
la construction (lot C) et est ignoré par `scanoria-selfupdate`. La liste des
fichiers déployés est écrite dans `/usr/share/scanoria/MANIFEST` ; un fichier
présent dans l'ancien manifeste et absent du nouveau est supprimé. `/etc` n'est
**jamais** écrit par un déploiement : les valeurs initiales vivent dans
`/usr/share/scanoria/defaults/` et sont copiées par le premier démarrage si
absentes.

### 3.4 Commandes

| Commande | Lot | Rôle |
|---|---|---|
| `scanoria-helper run` | B | traite la file `incoming/` (FIFO, une demande à la fois, verrou `/run/scanoria/helper.lock`) |
| `scanoria-helper exec --origin timer\|firstboot\|cli --type <type> --params '<json>'` | B | exécute une demande construite localement (même validation, même résultat dans `done/`/`failed/`, résultat JSON aussi sur la sortie standard, code de sortie 0 si `status` = `ok`) ; `requested_by` = `{"user_id": 0, "username": "system"}` |
| `scanoria-helper scheduled update-check\|update-apply\|cert-renew` | B | tâches des timers (§ 3.5) : lisent la politique puis passent par `exec --origin timer` |
| `scanoria-ca init\|issue\|import\|status` | B | AC interne et certificats (appelé par le helper) |
| `scanoria-firewall apply\|status\|render` | B | génère, vérifie (`nft -c`) et charge la table `inet scanoria` ; `render` écrit les règles sur la sortie standard sans les charger |
| `scanoria-selfupdate check\|apply\|rollback\|install-local\|verify` | B | mises à jour (§ 6) ; `install-local <dir>` = installation initiale depuis l'ISO, refusée si `/opt/scanoria/current` existe, lancée dans le chroot de l'installation (sans systemd actif) depuis une copie extraite du lot ; `<dir>` contient l'archive, `release.json`, `SHA256SUMS` et éventuellement `.sig` (signature non exigée : le support d'installation fait foi) ; `verify <dir> <version>` contrôle des actifs sans rien installer. Sorties de `apply`/`rollback` : `from_version`, `to_version` |
| `scanoria-state` | B | publie `/run/scanoria/state.json` |
| `scanoria-selftest [--json] [--quick]` | B | tests de fumée (§ 8) |
| `scanoria-firstboot` | C | assistant texte du premier démarrage ; mode sans intervention sous QEMU (fichier fw_cfg `opt/scanoria/unattended.json`, `docs/TESTING.md` § 4) |

`scanoria-helper`, `scanoria-selfupdate`, `scanoria-state` et
`scanoria-selftest` sont écrits en **Python 3, bibliothèque standard seule**
(`/usr/lib/scanoria/py/scanoria/`), lancés par de petits lanceurs bash
(`python3 -I -B`) : validation réelle des demandes par les schémas (mots-clés
inconnus refusés), JSON piégé refusé (clés en double, NaN, UTF-8 invalide),
commandes externes appelées avec une liste d'arguments, jamais par un shell.
`scanoria-ca`, `scanoria-firewall` et `scanoria-firstboot` sont en bash
(`set -euo pipefail`, shellcheck propre), `jq` pour le JSON, `openssl` pour la
PKI, `python3 -I` pour les contrôles délicats (adresses et réseaux IP
canoniques).

### 3.5 Unités systemd (lot B, sauf mention)

| Unité | Rôle |
|---|---|
| `scanoria-console.service` | `User=scanoria`, `EnvironmentFile=/etc/scanoria/console.env`, `ExecStartPre=/opt/scanoria/node/bin/node /opt/scanoria/current/webui/migrate.mjs`, `ExecStart=/opt/scanoria/node/bin/node /opt/scanoria/current/webui/server/index.mjs`, durcissement (`ProtectSystem=strict`, `ReadWritePaths=` limités à `requests/tmp`, `requests/incoming`, `uploads`, `console`, `bootstrap`, `NoNewPrivileges=yes`…) |
| `scanoria-helper.path` + `scanoria-helper.service` | `PathExistsGlob=/var/lib/scanoria/requests/incoming/*.json` → `scanoria-helper run` (oneshot) |
| `scanoria-state.timer` + `.service` | chaque minute (et lancé par le helper après chaque demande) |
| `scanoria-update-check.timer` | quotidien, délai aléatoire ; `exec --origin timer --type check-update` si `auto_check` |
| `scanoria-update-apply.timer` | toutes les 15 min ; si `auto_apply` et dans la fenêtre : nouvelle vérification (`check-update`) juste avant, puis `apply-update` seulement si le résultat est frais (≤ 30 min), du canal configuré, et la version supérieure à l'installée et à une version abandonnée par un retour à N-1 (`updates/skip-version.json`) |
| `scanoria-cert-renew.timer` | quotidien ; `issue-certificate` (sans `force`) en mode interne |
| `scanoria-firewall.service` | charge les règles au démarrage, avant le réseau |
| `scanoria-firstboot.service` | lot C ; tant que `firstboot.done` est absent |
| `scanoria-dns-check.timer` + `.path` + `.service` | 0.2 : `exec --origin timer --type check-dns` toutes les heures, à chaque réécriture de `appliance.json` (changement de nom) et après chaque changement de routage (§ 4.1) |
| `scanoria-canaries.timer` + `.service` | 0.6 : chaque nuit (02:30, délai aléatoire 90 min), `exec --origin timer --type run-canaries`, priorité basse (`Nice=15`, E/S `idle`) |
| `scanoria-self-sbom.timer` + `.service` | 0.6 : 40 min après le démarrage puis chaque jour (05:00, délai aléatoire 1 h), `exec --origin timer --type self-sbom` |

### 3.6 Environnement de la console (`/etc/scanoria/console.env`)

```
NODE_ENV=production
NITRO_HOST=127.0.0.1
NITRO_PORT=3000
NUXT_DATABASE_URL=postgresql:///scanoria?host=/var/run/postgresql
NUXT_STATE_FILE=/run/scanoria/state.json
NUXT_REQUESTS_DIR=/var/lib/scanoria/requests
NUXT_UPLOADS_DIR=/var/lib/scanoria/uploads
NUXT_BOOTSTRAP_DIR=/var/lib/scanoria/bootstrap
NUXT_PUBLIC_FILES_DIR=/var/lib/scanoria/public
NUXT_VERSION_FILE=/opt/scanoria/current/VERSION
NUXT_UPDATE_SOURCE_FILE=/usr/share/scanoria/update-source.json
```

La console expose `GET /api/health` sans authentification :
`200 {"status":"ok","version":"0.1.0","db":"ok"}` ou `503` avec
`"status":"error"`. Rien d'autre (aucune information sur la configuration).

## 4. Réseau, nom, pare-feu

- **Nom** : `appliance.json` porte le FQDN (minuscules, au moins deux étiquettes,
  pas de joker). La console répond sur `<nom>` ; `*.<nom>` est réservé aux
  modules (0.2). nginx (`/etc/nginx/sites-enabled/scanoria.conf`, généré depuis
  `/usr/share/scanoria/nginx/scanoria.conf.tmpl`, contrôlé par `nginx -t` avant
  rechargement, ancien fichier restauré sinon) : port 80 → redirection 443, sauf
  `/scanoria-ca.crt` servi en clair ; port 443 → `127.0.0.1:3000` ; autre nom →
  444 ; téléversement limité à 1 Gio sur `/api/system/updates/upload`.
- **Pare-feu** : table `inet scanoria` seule gérée (jamais `flush ruleset`).
  Chaîne `input` (hook input, policy drop) : `lo`, `ct state established,related`,
  ICMP/ICMPv6 nécessaires, DHCP client, puis `tcp dport {22, 80, 443}` depuis les
  ensembles `admin4`/`admin6`. Sortant libre (mises à jour). Chargement :
  `nft -c -f` puis `nft -f`, règles précédentes rechargées en cas d'échec.
  Valeur proposée par le premier démarrage : le réseau de l'interface configurée.
- **PostgreSQL** : `listen_addresses = ''` en 0.1 (socket seul), base `scanoria`
  propriété du rôle `scanoria`, `pg_hba` : `local scanoria scanoria peer`,
  locale `en_US.UTF-8`.

### 4.1 Aiguillage des modules par nom (0.2)

- `scanoria.routing.apply(fqdn, services)`, appelé par le moteur des modules sous
  le verrou du helper, avec la liste **complète** des modules `service`
  `[{id, hostname, port, enabled}]`. Il écrit `/etc/nginx/scanoria.d/`
  (inclus par le site de la console) depuis
  `/usr/share/scanoria/nginx/modules/*.tmpl` :
  - `module-<id>.conf` : module actif → `<hostname>.<nom>` vers
    `127.0.0.1:<port>`, certificat générique, en-têtes de sécurité de la console
    (cadre `SAMEORIGIN`, en-têtes amont masqués), corps jusqu'à 256 Mio sans
    tampon ; module désactivé → redirection 302 vers
    `https://<nom>/modules/unavailable?m=<id>` ;
  - `00-catchall.conf` : tout autre `<libellé>.<nom>` → même page
    (`m=<libellé>`), et port 80 → `https://<libellé>.<nom>` ;
  - un fichier géré absent de la liste est retiré, les autres fichiers du
    répertoire ne sont jamais touchés.
- Validation stricte avant toute écriture (`E_INVALID_PARAM`) : id
  `[a-z0-9-]{1,64}`, libellé = une étiquette DNS en minuscules, nom complet
  ≤ 253, port entier 1024–65535 hors 3000 et 5432, `enabled` booléen, ni id ni
  libellé ni port actif en double. Écriture atomique fichier par fichier, liens
  plantés retirés sans être suivis, `nginx -t`, rechargement ; si `nginx -t`
  échoue, l'ancien contenu est remis à l'identique (`E_INTERNAL`).
- Dernière liste appliquée : `/var/lib/scanoria/routing/sites.json`
  (`{fqdn, applied_at, services}`). `routing.resync()` la rejoue quand le nom
  de l'appliance a changé (lancé par `check-dns`).
- Chaque site porte une ligne `# scanoria-route: id=… mode=… host=… port=… fqdn=…`
  relue par le contrôle `routing.sites` de `scanoria-selftest`.

### 4.2 Vérification DNS (0.2)

Demande `check-dns {}` : résout `<nom>`, `*.<nom>` (nom de sonde aléatoire) et
`<libellé>.<nom>` de chaque module routé, en `A` (et `AAAA` si l'appliance a une
IPv6), par `resolvectl --synthesize=no --cache=no -p dns` (sans `/etc/hosts`,
où l'appliance se déclare elle-même). Adresse attendue : adresse source de la
route vers une adresse de documentation (`ip route get`, aucun paquet émis).
Résultat dans `/var/lib/scanoria/dns/status.json` (root:scanoria 0640,
`schemas/dns-status.schema.json`) : `{fqdn, checked_at, records: [{name, type,
expected, resolved, ok}]}` ; `output` : `{fqdn, records, ok, not_resolved,
routing_resynced}`. Sans nom : `E_PRECONDITION` et `fqdn: null`.

## 5. Protocole des demandes console → scanoria-helper

### 5.1 Types (liste fermée en 0.1)

| Type | Paramètres (`params`) | Effet | Délai max |
|---|---|---|---|
| `set-hostname` | `fqdn` | hostname, `/etc/hosts`, `appliance.json`, nouvelle AC (contrainte de nom), nouveau certificat, nginx ; en mode importé, repasse en interne (`output.tls_mode_changed`) | 300 s |
| `set-admin-networks` | `networks[1..64]` (CIDR v4/v6), `allow_self_lockout` | nftables ; `E_LOCKOUT` si `requested_by.address` n'est couverte par aucun réseau, sauf `allow_self_lockout` | 60 s |
| `issue-certificate` | `force` | certificat interne `<nom>`/`*.<nom>`, mode interne ; sans `force`, rien si > 30 jours restants | 120 s |
| `import-certificate` | `cert_pem`, `key_pem`, `chain_pem?` | contrôle (§ 7.3) puis mode importé | 120 s |
| `check-update` | `channel?` | interroge les releases ; `output` + `state.json.update` | 120 s |
| `apply-update` | `{source:"github", version}` ou `{source:"upload", upload_id}` | § 6.4 ; version GitHub revérifiée (publiée, non rejetée, du canal configuré) | 3300 s |
| `rollback-update` | `expected_current`, `expected_target` | § 6.5 ; la version abandonnée n'est plus réinstallée automatiquement | 3300 s |
| `set-update-policy` | `channel`, `auto_check`, `auto_apply`, `maintenance_window` | `update.json` ; `auto_apply` exige une fenêtre | 30 s |
| `run-selftest` | `quick` | `scanoria-selftest --json` ; rapport dans `output` | 300 s |
| `check-dns` | aucun | 0.2, § 4.2 : sites des modules régénérés si le nom a changé, puis vérification DNS | 180 s |
| `self-sbom` | aucun | 0.6, § 13 : SBOM de la console et des images installées, comparés par Grype et OSV-Scanner confinés (F19) | 3300 s |
| `run-canaries` | `ids?` | 0.6, § 13 : banc d'essai F12 rejoué (G14) ; `E_CANARY_FAILED` si un canari échoue, sans jamais désactiver | 3300 s |
| `start-trial` | `module`, `version`, `trial_id?`, `action?` (`start`, `abandon`) | 0.6, § 13 : candidate de l'index vérifié tirée par empreinte et retenue (F13), ou retirée | 1200 s |

Schémas complets (JSON Schema 2020-12, `additionalProperties: false` partout) :
`src/rootfs/usr/share/scanoria/requests/<type>.schema.json`. La console valide
avec zod **les mêmes contraintes** (un test de la console compare des exemples
aux schémas) ; le helper revalide tout, plus strictement si besoin (adresses IP
canoniques, PEM réellement analysables, version existante).

### 5.2 Enveloppe commune

```json
{
  "version": 1,
  "id": "3f1c2a9e-7b4d-4e2a-9c1f-0a1b2c3d4e5f",
  "type": "set-hostname",
  "created_at": "2026-11-23T08:00:00Z",
  "requested_by": { "user_id": 1, "username": "admin", "address": "192.0.2.10" },
  "params": { "fqdn": "analyse.exemple.test" }
}
```

`id` : UUID v4 minuscule. `requested_by.address` : adresse cliente vue par la
console (optionnelle, utilisée par l'anti-verrouillage). `user_id` 0 est réservé
à `system` (demandes `exec`).

### 5.3 Nommage et écriture atomique (console)

- Nom : `<AAAAMMJJ>T<HHMMSS>Z-<id>.json`, ex.
  `20261123T080000Z-3f1c2a9e-7b4d-4e2a-9c1f-0a1b2c3d4e5f.json`.
  Expression exacte :
  `^[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\.json$`.
  L'horodatage du nom = `created_at` à la seconde ; l'ordre lexical = l'ordre FIFO.
- Écriture : insertion de la ligne `helper_requests` (`pending`, paramètres
  **sans secret**), création exclusive de `tmp/<nom>.part` (mode 0600), écriture,
  `fsync`, renommage en `incoming/<nom>`. Taille maximale : 128 Kio.

### 5.4 Prise en charge (helper)

Pour chaque nom de `incoming/`, dans l'ordre lexical :
1. nom non conforme → déplacé hors de la file, résultat `failed/invalid-<horodatage>-<aléa>.json`, `E_INVALID_NAME` ;
2. **renommage** dans `work/` (root 0700) ; ensuite seulement : `lstat` (fichier
   régulier, pas de lien symbolique, un seul lien physique, propriétaire
   `scanoria`, ≤ 128 Kio) → sinon `E_NOT_REGULAR_FILE`, `E_BAD_OWNER`, `E_TOO_LARGE` ;
3. **copie unique** du contenu dans un fichier root ; seule cette copie est
   lue ensuite (un descripteur resté ouvert côté console ne peut plus rien changer) ;
4. JSON valide (`E_INVALID_JSON`), type connu (`E_UNKNOWN_TYPE`), schéma
   (`E_SCHEMA`), `id` = celui du nom (`E_ID_MISMATCH`), `id` jamais vu dans
   `done/`/`failed/` (`E_DUPLICATE_ID`), `created_at` ni plus vieux que 24 h ni
   plus de 5 min dans le futur (`E_STALE`) ;
5. exécution sous délai (`E_TIMEOUT`), étape courante publiée dans `state.json` ;
6. résultat écrit atomiquement dans `done/` (succès) ou `failed/` (échec), même
   nom que la demande ; copie de `work/` supprimée ; `scanoria-state` relancé.

Aucune valeur issue d'une demande n'est interpolée dans une commande shell sans
avoir passé la validation ; arguments toujours passés en tableau, jamais `eval`.

### 5.5 Codes de résultat (liste fermée)

| Statut | Codes |
|---|---|
| `ok` | `OK` |
| `rejected` (forme) | `E_INVALID_NAME`, `E_NOT_REGULAR_FILE`, `E_BAD_OWNER`, `E_TOO_LARGE`, `E_INVALID_JSON`, `E_UNKNOWN_TYPE`, `E_SCHEMA`, `E_ID_MISMATCH`, `E_DUPLICATE_ID`, `E_STALE`, `E_INVALID_PARAM` |
| `error` (exécution) | `E_PRECONDITION`, `E_LOCKOUT`, `E_NETWORK`, `E_NOT_FOUND`, `E_SIGNATURE`, `E_CHECKSUM`, `E_ARCHIVE`, `E_VERSION`, `E_DISK_SPACE`, `E_CERT_INVALID`, `E_CERT_NAMES`, `E_CERT_KEY_MISMATCH`, `E_CERT_EXPIRED`, `E_NO_PREVIOUS`, `E_HEALTH_ROLLED_BACK`, `E_ROLLBACK_FAILED`, `E_TIMEOUT`, `E_INTERNAL` |

Le champ `message` est un texte technique en anglais pour le journal ; la
console affiche un libellé **traduit (fr/en) à partir du code**. Ajouter un code
= modifier `result.schema.json`, ce tableau et les traductions de la console.

### 5.6 Résultat

Schéma : `requests/result.schema.json`.

```json
{
  "version": 1, "id": "3f1c2a9e-…", "type": "set-hostname", "origin": "console",
  "status": "ok", "code": "OK", "message": "hostname set",
  "received_at": "2026-11-23T08:00:01Z", "started_at": "2026-11-23T08:00:01Z",
  "finished_at": "2026-11-23T08:00:09Z",
  "output": { "fqdn": "analyse.exemple.test", "tls_mode_changed": false }
}
```

Jamais de secret dans un résultat (ni `key_pem`, ni contenu de clé).
`origin` vaut `timer`, `firstboot` ou `cli` pour les actions lancées par
`exec` : la console **ingère tous** les résultats (lecture de `done/` et
`failed/` toutes les 5 s environ et au retour de chaque demande), crée la ligne
`helper_requests` manquante, met à jour `update_history` et écrit le journal
d'audit. Une demande `pending` sans résultat après 1 h passe en `lost`.

### 5.7 État publié : `/run/scanoria/state.json`

Schéma : `schemas/state.schema.json`. Écrit atomiquement (fichier temporaire +
renommage) par `scanoria-state` chaque minute et après chaque demande. Contenu :
`appliance` (fqdn, version, previous_version, firstboot_done, ressources),
`helper` (`busy`, `current {id, type, step, started_at}`, `queue_length`),
`update` (politique, dernière recherche, version disponible, notes),
`tls` (mode, SAN, dates, empreintes), `firewall`, `services`, `disks`,
`selftest`. La console considère l'état **indisponible** au-delà de 3 minutes et
l'affiche comme tel. Pendant une demande longue, elle affiche l'indicateur
d'attente avec `helper.current.step` traduit.

Étapes publiées : `apply-update` = `download`, `verify`, `extract`, `backup`,
`stop`, `deploy`, `migrate`, `start`, `health`, `cleanup` (+ `rollback` en cas
d'échec) ; `rollback-update` = `stop`, `restore`, `deploy`, `start`, `health` ;
autres types = `run`.

## 6. Releases et mises à jour (F18)

### 6.1 Source

`/usr/share/scanoria/update-source.json` = `{"repo": "<propriétaire>/<dépôt>"}`,
**généré à la construction** (`build.sh` depuis `GITHUB_REPOSITORY` ou
`--repo`), jamais écrit en dur dans le dépôt. Expression :
`^[A-Za-z0-9-]{1,39}/[A-Za-z0-9._-]{1,100}$`. La page « À propos » en tire le
lien vers le code source de la version installée : `https://github.com/<repo>/tree/vX.Y.Z`.

### 6.2 Actifs d'une release (tag `vX.Y.Z`)

| Actif | Contenu |
|---|---|
| `scanoria-X.Y.Z.tar.zst` | lot de mise à jour (§ 6.3) |
| `release.json` | métadonnées (schéma `schemas/release.schema.json`) : `release`, `tag`, `commit`, `built_at`, `archive`, `archive_sha256`, `archive_size`, `min_upgrade_from`, `node_major`, `notes_md` (section du CHANGELOG) |
| `SHA256SUMS` | exactement deux lignes au format `sha256sum` : `<hex>  release.json` et `<hex>  scanoria-X.Y.Z.tar.zst` |
| `SHA256SUMS.sig` | signature Ed25519 **brute** (64 octets) de `SHA256SUMS` |

Signature (travail de publication, environment `release`, clé
`UPDATE_SIGNING_KEY`) :
`openssl pkeyutl -sign -inkey signing.key -rawin -in SHA256SUMS -out SHA256SUMS.sig`.
Vérification (appliance) :
`openssl pkeyutl -verify -pubin -inkey /etc/scanoria/update-pubkey.pem -rawin -in SHA256SUMS -sigfile SHA256SUMS.sig`.
Clé publique épinglée = `update-pubkey.pem` du dépôt, empreinte SHA-256 (DER
SubjectPublicKeyInfo) `696af1d4c9cfb71c47e9940e6d80d69a8074786967fc1e7e857f5865a3b1f803`.
L'ISO n'est **pas** un actif de mise à jour. Elle dépasse la limite de 2 Gio par
actif de release GitHub : elle est publiée **en morceaux**
`scanoria-X.Y.Z-amd64.iso.partNN` (moins de 2 Gio chacun), avec un fichier
d'empreintes des morceaux et de l'ISO reconstituée, signé à part
(`docs/RELEASING.md`). `SHA256SUMS` garde exactement ses deux lignes.

Une importation manuelle (appliance sans Internet) téléverse les trois fichiers
`scanoria-X.Y.Z.tar.zst`, `SHA256SUMS`, `SHA256SUMS.sig` **et** `release.json`
dans `/var/lib/scanoria/uploads/<upload_id>/` ; le helper les copie dans
`updates/staging/` avant toute vérification.

### 6.3 Contenu du lot (`build.sh --bundle`, lot C)

```
scanoria-X.Y.Z/
  VERSION                 # X.Y.Z
  LICENSE  CHANGELOG.md  OPEN-SOURCE.md
  webui/                  # sortie Nitro (.output) : server/index.mjs, public/, nitro.json
  webui/VERSION
  webui/migrate.mjs       # lanceur autonome (lot A), code de sortie 0/1
  webui/migrations/NNN_*.sql
  rootfs/                 # copie de src/rootfs + usr/share/scanoria/update-source.json
```

Règles d'extraction (lot B) : uniquement fichiers réguliers et répertoires sous
`scanoria-X.Y.Z/` (ni lien, ni périphérique, ni chemin absolu, ni `..`),
propriétaire root, droits normalisés (0755/0644, exécutables sous
`rootfs/usr/sbin/` et `webui/` selon besoin), extraction dans
`releases/X.Y.Z.tmp` puis renommage. Archive ≤ 1 Gio. Paquets nécessaires :
`zstd`, `jq`, `openssl`, `curl` (lot C les met dans l'ISO).

### 6.4 Recherche et installation

1. **Canaux** : `stable` (défaut) = `releases/latest` ; `prerelease` = la plus
   récente des releases publiées, prereleases comprises. Les brouillons et les
   releases dont le titre commence par `[rejected]` (candidate rejetée,
   marquée ainsi par le lot D) sont ignorés.
2. **API sans jeton** : `https://api.github.com/repos/<repo>/releases/latest` ou
   `…/releases?per_page=20`, `User-Agent: scanoria-appliance/X.Y.Z`, HTTPS seul
   (`curl --proto =https --tlsv1.2`), délais bornés.
3. **Repli** sur `403`/`429`/erreur réseau : `stable` → en-tête `Location` de
   `https://github.com/<repo>/releases/latest` (`…/tag/vX.Y.Z`) ; `prerelease` →
   flux `https://github.com/<repo>/releases.atom`. Téléchargements toujours par
   `https://github.com/<repo>/releases/download/vX.Y.Z/<actif>`.
4. **Vérification** dans cet ordre : `SHA256SUMS` (≤ 4 Kio) et `.sig` (64 octets)
   → signature (`E_SIGNATURE`) → `release.json` (≤ 128 Kio) haché (`E_CHECKSUM`)
   et validé par son schéma → `release`/`tag` égaux à la version demandée →
   version **strictement supérieure** à la version installée, `min_upgrade_from`
   ≤ installée, `node_major` = majeure de `/opt/scanoria/node` (`E_VERSION`) →
   espace disque (`E_DISK_SPACE`) → archive (≤ `archive_size`) hachée.
5. **Installation** : extraction ; `pg_dump -Fc` dans `backups/pre-update/` ;
   arrêt de la console ; déploiement de `rootfs` (§ 3.3) ; `previous` ← ancien
   `current`, `current` ← nouvelle version (liens remplacés atomiquement) ;
   `systemctl daemon-reload` ; démarrage (migrations par `ExecStartPre`) ;
   santé : `/api/health` en ≤ 120 s avec la bonne version, puis
   `scanoria-selftest --quick`. Échec → **retour arrière automatique** (base
   restaurée, liens et `rootfs` remis, `E_HEALTH_ROLLED_BACK`) ; échec du retour
   arrière → `E_ROLLBACK_FAILED` (alerte permanente dans l'état).
6. Conservation : `current` et `previous` seulement, plus la sauvegarde liée à
   `previous`. Notes de version affichées : `release.json.notes_md` (signé).

7. **Toujours proposée** : pour une version demandée à GitHub (`--version`), la
   release `vX.Y.Z` est relue juste avant le téléchargement
   (`…/releases/tags/vX.Y.Z`, repli sur l'en-tête `Location` ou le flux atom) :
   brouillon, titre `[rejected]` ou pré-version sur le canal `stable` →
   `E_VERSION`. Une candidate rejetée reste signée valablement : la signature
   seule ne suffit pas. Changer de canal efface le résultat de la dernière
   vérification (`updates/check.json`).
8. **Budget de temps** : le helper accorde 3300 s et transmet une échéance
   (`SCANORIA_UPDATE_DEADLINE`, 300 s avant son arrêt forcé). Téléchargement et
   `pg_dump` sont bornés pour laisser au moins 1500 s après l'arrêt de la
   console (déploiement, santé, retour arrière) ; sinon `E_TIMEOUT` **avant**
   d'arrêter la console, sans rien changer.

Jamais d'installation automatique sans `auto_apply` **et** fenêtre de maintenance.

### 6.5 Retour à N-1

`rollback-update` vérifie `expected_current` = `current` et `expected_target`
= `previous` (`E_PRECONDITION`, `E_NO_PREVIOUS`), arrête la console, restaure la
sauvegarde de base prise avant la mise à jour (les données créées depuis sont
perdues : la console l'annonce dans sa modale), échange les liens, redéploie
`rootfs` de N-1, redémarre et contrôle la santé. Après un retour arrière,
`previous` n'existe plus (pas de « retour du retour »). La version abandonnée
est notée dans `updates/skip-version.json` (affichée dans la console,
`state.update.skipped_version`) : la mise à jour automatique ne réinstalle ni
elle ni une version inférieure ; seule une version plus récente est proposée
d'office.

## 7. AC interne et TLS

### 7.1 Emplacements (`/etc/scanoria/pki/`, root:root 0700)

```
ca/ca.key  ca/ca.crt            AC courante (ECDSA P-256, 0600 pour la clé)
ca/archive/<horodatage>/        AC précédentes
internal/privkey.pem  internal/fullchain.pem   certificat émis par l'AC
imported/privkey.pem  imported/fullchain.pem   certificat importé
active -> internal | imported   lien suivi par nginx
```

nginx : `ssl_certificate /etc/scanoria/pki/active/fullchain.pem;`
`ssl_certificate_key /etc/scanoria/pki/active/privkey.pem;`. Copie publique de
l'AC : `/var/lib/scanoria/public/scanoria-ca.crt` (téléchargeable depuis la
console et sur `http://<nom>/scanoria-ca.crt`), empreinte affichée.

### 7.2 Profils

- **AC** : `CN=Scanoria CA <nom>`, 10 ans, `basicConstraints=critical,CA:TRUE,pathlen:0`,
  `keyUsage=critical,keyCertSign,cRLSign`, **`nameConstraints=critical,permitted;DNS:<nom>,excluded;IP:0.0.0.0/0.0.0.0,excluded;IP:::/0`** :
  l'AC importée sur les postes ne peut signer que `<nom>` et ses sous-domaines.
  Conséquence : `set-hostname` crée une **nouvelle AC** (l'ancienne est
  archivée) et les postes doivent réimporter l'AC — la console l'annonce.
- **Serveur** : ECDSA P-256, `CN=<nom>`, `subjectAltName=DNS:<nom>,DNS:*.<nom>`,
  `extendedKeyUsage=serverAuth`, `keyUsage=critical,digitalSignature`, 397 jours,
  numéro de série aléatoire de 128 bits.
- **Renouvellement** : `scanoria-cert-renew.timer` quotidien, émet un nouveau
  certificat interne quand il reste moins de 30 jours. Un certificat importé
  n'est jamais renouvelé par l'appliance : l'état et selftest signalent son
  échéance.

### 7.3 Import

Refus si : PEM illisible ou clé chiffrée (`E_CERT_INVALID`), clé ni RSA ≥ 2048
ni ECDSA P-256/P-384 (`E_CERT_INVALID`), clé et certificat ne correspondent pas
(`E_CERT_KEY_MISMATCH`), certificat expiré, pas encore valide ou valide moins
d'un jour (`E_CERT_EXPIRED`), SAN ne couvrant pas **à la fois** `<nom>` et
`*.<nom>` (`E_CERT_NAMES`). `fullchain` = certificat + chaîne fournie. Toute
bascule passe par `nginx -t` ; échec → retour à l'état précédent.

## 8. `scanoria-selftest`

`scanoria-selftest [--json] [--quick]`. Codes de sortie : **0** = `pass` ou
`warn`, **1** = au moins un `fail`, **2** = erreur d'usage ou interne. Avec
`--json`, rapport conforme à `schemas/selftest.schema.json` sur la sortie
standard ; le helper l'enregistre dans `/var/lib/scanoria/selftest/last.json`.

```json
{ "version": 1, "appliance_version": "0.1.0", "started_at": "…", "finished_at": "…",
  "status": "warn",
  "checks": [ { "id": "tls.cert-valid", "status": "pass", "message": "expires in 380 days", "details": {} } ] }
```

Vérifications (identifiants stables, traduits par la console) :

| id | Contrôle | `--quick` |
|---|---|---|
| `version.files` | `current/VERSION` = `current/webui/VERSION` | oui |
| `layout.release` | `current` valide, `previous` valide s'il existe | oui |
| `perms.paths` | propriétaires et modes du § 3.2 | oui |
| `pubkey.present` | `update-pubkey.pem` Ed25519, root 0644 | oui |
| `services.postgresql`, `services.nginx`, `services.console`, `services.helper-path` | unités actives | oui |
| `db.connect`, `db.migrations` | connexion ; dernière migration appliquée = dernière livrée | oui |
| `console.health` | `/api/health` via nginx (nom de l'appliance, AC interne) : 200 et bonne version | oui |
| `tls.cert-valid` | > 14 j `pass`, 1–14 j `warn`, expiré `fail` | oui |
| `tls.cert-names`, `tls.key-match`, `tls.ca-present` | SAN `<nom>`+`*.<nom>`, clé, AC | oui |
| `firewall.loaded` | table `inet scanoria` chargée, ensembles non vides | oui |
| `requests.queue` | aucune demande de plus de 10 min dans `incoming/` (`warn`) | oui |
| `disk.free` | `/` et `/var` : < 10 % `warn`, < 5 % `fail` | oui |
| `routing.sites` | 0.2 : sites de `/etc/nginx/scanoria.d/` générés pour le nom actuel et cohérents avec `modules/state.json` (aucun site d'un module absent, module routé = site actif, module désactivé jamais servi) | oui |
| `dns.resolve` | `<nom>` et `test.<nom>` résolus (`warn`) | non |
| `time.sync` | horloge synchronisée (`warn`) | non |
| `hardware.floor` | ≥ 2 vCPU, 4 Go, 40 Go (`warn`) | non |

## 9. Base de données de la console

### 9.1 Migrations

`webui/server/db/migrations/NNN_nom.sql`, numérotation continue à 3 chiffres,
jamais modifiées une fois publiées. `migrate.mjs` (lot A) : verrou consultatif
PostgreSQL, chaque fichier dans une transaction, enregistrement dans
`schema_migrations (version, name, checksum SHA-256, applied_at)` ; une empreinte
différente d'une migration déjà appliquée = échec (code 1). Pas de migration
descendante : le retour à N-1 restaure la sauvegarde.

### 9.2 Tables (`001_initial.sql`)

| Table | Contenu |
|---|---|
| `schema_migrations` | migrations appliquées |
| `roles` | `viewer` (10), `operator` (20), `admin` (30) |
| `users` | `username` (`^[a-z0-9][a-z0-9._-]{0,63}$`, unique), `role`, `auth_source` (`local`), `password_hash` PHC, `must_change_password`, `locale` fr/en, `is_active`, `failed_logins`, `locked_until`, dates |
| `sessions` | `token_hash` (SHA-256 hex du jeton du cookie, jamais le jeton), `user_id`, `expires_at`, `last_seen_at`, `revoked_at`, `ip`, `user_agent` |
| `audit_log` | ajout seul (UPDATE interdit) : acteur (id, nom figé, type, IP), `action` `<domaine>.<verbe>`, cible, `outcome` success/failure/denied, `request_id`, `details` JSONB **sans secret** |
| `appliance_settings` | réglages de la console (`clé` → JSONB) : sessions, verrouillage, langue par défaut. Les réglages système vivent dans `/etc/scanoria` |
| `helper_requests` | demandes au helper et résultats ingérés (`pending`/`running`/`ok`/`error`/`rejected`/`lost`) |
| `update_history` | `apply`/`rollback`/`auto-rollback`, versions, canal, source, statut, code |

### 9.3 Mots de passe et premier administrateur

Hachage **PBKDF2-HMAC-SHA256**, 600 000 itérations, sel aléatoire de 16 octets,
hash de 32 octets, format PHC :
`$pbkdf2-sha256$i=600000$<sel base64 sans =>$<hash base64 sans =>`
(Node : `crypto.pbkdf2`, Python : `hashlib.pbkdf2_hmac`, comparaison à temps
constant). Le premier démarrage (lot C, root) écrit
`/var/lib/scanoria/bootstrap/admin.json` = `{"username": "admin", "password_hash": "<PHC>"}`
(propriétaire `scanoria`, 0600) ; la console, au démarrage, crée ce compte
`admin` s'il n'existe **aucun** administrateur, audite `system.bootstrap-admin`,
puis supprime le fichier. Le mot de passe en clair n'est jamais écrit sur disque.

## 10. Premier démarrage (lot C)

Installation (autoinstall) : paquets, Node 22 dans `/opt/scanoria/node`, clé
publique dans `/etc/scanoria/update-pubkey.pem`, `scanoria-selfupdate
install-local` du lot embarqué. La base `scanoria` et son rôle sont créés au
premier démarrage (PostgreSQL ne tourne pas dans le chroot de l'installation).
Premier démarrage, en console texte : langue, clavier, réseau, nom (FQDN),
fuseau, mot de passe administrateur de la console, mot de passe du compte
système `sysadmin`, réseaux d'administration. Il applique via `scanoria-helper exec --origin firstboot`
(`set-hostname`, `set-admin-networks`, `issue-certificate`), copie
`/usr/share/scanoria/defaults/` vers `/etc/scanoria` si absent, dépose
`bootstrap/admin.json`, démarre la console, lance `scanoria-selftest`, affiche
l'URL et l'empreinte de l'AC, puis crée `firstboot.done`. Refus d'installation
sous le plancher D6 (2 vCPU, 4 Go, 40 Go).

## 11. Tests attendus (rappel des contrats à couvrir)

- Lot A : validation zod alignée sur chaque schéma (exemples valides et hostiles),
  écriture atomique des demandes, ingestion des résultats, PBKDF2 (format PHC),
  migrations sur un vrai PostgreSQL 16 (`en_US.UTF-8`), rôles, audit.
- Lot B : demandes hostiles (noms, liens symboliques, liens physiques, tailles,
  propriétaires, JSON piégés, injections dans `fqdn`/CIDR/PEM, `..`), codes de
  résultat, extraction d'archive piégée, signature/empreinte invalides,
  rétrogradation refusée, retour arrière.
- Lot C : contenu du lot conforme au § 6.3 (préfixes autorisés, pas de lien),
  `update-source.json` généré, aucune clé privée dans les sorties.
- Lot D : actifs de release conformes au § 6.2, signature vérifiée avec
  `update-pubkey.pem` avant publication, promotion sans reconstruction.

## 12. Analyses (0.3)

Contrats communs de la 0.3, fixés avant les chantiers. Références : `CLAUDE.md`
§ 3.5, 5.2, 6 et 15 ; schéma `webui/server/db/migrations/003_analyses.sql` ;
types `webui/shared/analysis.ts` ; schémas `scan-job` et `scan-result` dans
`src/rootfs/usr/share/scanoria/schemas/`.

### 12.1 Processus

```
console (scanoria) ─ enqueueScan() ─▶ table scans (file, G17)
scanoria-worker (scanoria, Node) ─ plan (G7, G11) ─▶ /var/lib/scanoria/scans/jobs/incoming/<id>.json
scanoria-runner (root, Python) ─ valide, récupère la source, lance chaque module confiné (§ 6.4)
                                ─▶ /var/lib/scanoria/scans/results/<id>/result.json + sorties
scanoria-worker ─ ingère (résultats unifiés, G5, G19) ─ évalue le quality gate (G13) ─▶ scans.verdict
scanoria-ai (scanoria-ai, Node) ─ file ai_tasks ─HTTPS─▶ Ollama externe (§ 3.5 de CLAUDE.md)
```

- **scanoria-worker** tourne sous `scanoria`, sans privilège, comme la console
  (même rôle PostgreSQL). Il tient la file, choisit l'ordre (priorités de
  `SCAN_PRIORITY`, quotas par projet, aucune famine), résout le profil, dépose
  une tâche quand le runner a une place libre, ingère les résultats et rend le
  verdict. Il ne lance jamais de conteneur.
- **scanoria-runner** tourne en root, comme le helper, mais dans sa propre file
  pour ne jamais bloquer les demandes d'administration. Il ne fait confiance à
  rien dans la tâche (principe 4) : chaque module doit être installé, sain et
  actif dans `modules/state.json` ; l'image, les bases, la commande, le délai
  et les limites viennent de l'état publié et du manifeste de l'index vérifié.
  Il publie sa capacité dans `/run/scanoria/runner.json`
  (`{slots, busy, updated_at}`, root:scanoria 0640), bornée par la RAM.
- **scanoria-ai** : service sans privilège, utilisateur `scanoria-ai`, seul
  autorisé à sortir vers le serveur Ollama (règle nftables `meta skuid`).
  En https, le certificat du serveur est vérifié (AC du système, plus l'AC
  fournie le cas échéant). L'administrateur peut désactiver cette vérification
  pour un certificat autosigné (`skip_tls_verify` de `set-ai-endpoint`, champ
  `tls_verify: false` de `/etc/scanoria/ai.json`) : https seulement, jamais
  avec une AC, signalé dans le formulaire, la modale d'activation et l'état du
  connecteur. Le nom et les adresses restent épinglés.

### 12.2 Arborescence ajoutée

| Chemin | Propriétaire, mode | Contenu |
|---|---|---|
| `/var/lib/scanoria/scans/` | root:scanoria 0750 | file entre worker et runner |
| `…/scans/jobs/tmp/`, `…/jobs/incoming/` | scanoria:scanoria 0700 | tâches en cours d'écriture, puis prêtes (renommage atomique, fichiers 0600) |
| `…/scans/jobs/work/` | root:root 0700 | tâches prises en charge ; le fichier est supprimé dès sa lecture (il peut contenir un jeton) |
| `…/scans/results/<job-id>/` | root:scanoria 0750, fichiers 0640 | `result.json` et sorties, purgés après 24 h |
| `…/scans/workspaces/<job-id>/` | root:root 0700 | source récupérée, **supprimée** après la tâche (§ 6.4, étape 3) |
| `/var/lib/scanoria/console/secret.key` | scanoria:scanoria 0600 | clé AES-256 des secrets en base, créée au premier démarrage de la console, incluse dans les sauvegardes |
| `/var/lib/scanoria/console/ai-token.key` | scanoria:scanoria 0600 | clé AES-256 dédiée au seul jeton du connecteur IA, créée au premier jeton ; seule clé copiée dans `/run/scanoria-ai` (scanoria-ai ne peut déchiffrer rien d'autre) |
| `/var/lib/scanoria/console/scan-logs/<scan-id>/<module>.log` | scanoria:scanoria 0600 | journaux des modules copiés par le worker (G20), purgés avec l'analyse |

### 12.3 Secrets en base

Table `credentials` : AES-256-GCM, `secret_enc = 0x01 | nonce (12) | chiffré | étiquette (16)`,
données associées = `credentials.id`. La valeur n'est jamais renvoyée par l'API,
jamais journalisée, jamais copiée dans l'audit ; seul `hint` s'affiche. Elle ne
quitte la console que vers le runner, dans une tâche 0600 supprimée à la lecture.

### 12.4 Tâches et résultats du runner

- Tâche : `scan-job.schema.json`. Une tâche = une analyse : la source est
  récupérée une fois, puis chaque module tourne sur la même copie en lecture
  seule. `history: full` si un module du plan déclare `scan.history: full`
  (gitleaks), sinon `shallow`.
- La source Git est récupérée **dans un conteneur jetable** du module système
  `git-fetch` (installé automatiquement comme dépendance des scanners qui lisent
  un dépôt, G1), avec un réseau limité à l'hôte de la forge et sans exécuter de
  hook, de filtre ni de sous-module. Une archive téléversée est extraite sans
  lien ni chemin sortant, avec des limites de taille.
- Résultat : `scan-result.schema.json`. Classes d'erreur (G12) : `infra`
  (mémoire, délai, image absente, échec de podman, runner redémarré) relancée
  automatiquement par le worker, au plus 2 fois ; `tool` (sortie invalide ou
  absente, code de sortie inattendu) et `input` (source inaccessible, archive
  piégée) jamais relancées. Une sortie déclarée est validée contre son schéma
  (SARIF 2.1.0, CycloneDX) avant publication (G2) ; invalide = `invalid-output`.

### 12.5 Analyses reproductibles (G11)

`scans.plan` fige, au moment du dépôt : la liste des modules résolue depuis le
profil (G7) avec version, empreinte d'image, options et versions des bases,
les règles du quality gate, et le commit. « Rejouer à l'identique » crée une
analyse `trigger = replay`, `replay_of = <id>`, avec le même plan ; si un module
ou une image du plan n'est plus disponible, l'analyse est non concluante et le
dit.

### 12.6 Résultats unifiés

- Gravité normalisée par `severity_maps` (G5), alimentée par défaut depuis les
  niveaux SARIF (`error` → `high`, `warning` → `medium`, `note` → `low`,
  `none` → `info`) et les propriétés usuelles (`security-severity` : ≥ 9
  `critical`, ≥ 7 `high`, ≥ 4 `medium`, > 0 `low`).
- Empreinte stable (G19) : SHA-256 de `outil | règle | chemin | contexte`, où
  le contexte est le texte normalisé (espaces repliés) des lignes autour du
  résultat, sans numéro de ligne ; pour une dépendance, `écosystème | nom |
  version | identifiant d'avis`. `partialFingerprints` SARIF est utilisé quand
  l'outil le fournit.
- Un secret n'est jamais stocké : message et extrait sont masqués à
  l'ingestion ; seuls type, emplacement et empreinte restent (F7).
- Un avis `MAL-` (OSV) marque `malicious = true` : toujours bloquant, aucune
  exception possible (H4).
- Un résultat absent d'une analyse complète réussie de la même branche passe
  `fixed` ; il redevient `new` s'il réapparaît.

### 12.7 Verdict

`evaluateGate(scanId)` produit `VerdictDetails` (`webui/shared/analysis.ts`) :
raisons ordonnées, bloquantes ou non, avec les actions qui débloqueraient.
Non concluant (G13) dès qu'un module du plan est absent, en erreur, en délai
dépassé ou à sortie invalide, sauf exception datée de type `module`. L'IA
(I9) ne fait que rédiger à partir de `verdict_details` ; elle n'entre jamais dans
le calcul.

### 12.8 API pour la CI

`Authorization: Bearer scn_…` (jeton de projet, `api_tokens`, seule l'empreinte
SHA-256 est gardée). `POST /api/projects/:id/scans {ref, profile?}` → `202
{scan_id, url}` ; `GET /api/scans/:id/verdict` → état et verdict (`GET
/api/scans/:id` est la route de la console, par session). Le client
`scanoria-scan` attend le verdict et rend 0 (passed), 1 (failed), 2
(inconclusive), 3 (erreur d'utilisation ou d'accès).

## 13. Vigilance de l'appliance (0.6, chantier B)

- **Images retenues** (`/var/lib/scanoria/modules/retained/<id>/<version>.json`,
  root 0600) : manifeste vérifié et empreinte d'une version **figée** par un
  projet (G6) ou **candidate** d'un essai (F13). Le runner ne lance une autre
  version que l'installée que si elle est retenue et que l'empreinte concorde ;
  sinon le module est `missing`, classe `infra` (G12), et le verdict non
  concluant (G13). `modules.remove_image` ne retire jamais une image retenue.
- **Versions figées** : la console publie `/var/lib/scanoria/pins/pins.json`
  (`{version: 1, pins: [{module, version, image_digest}]}`), lu sans confiance
  par le helper (fichier régulier, propriétaire `scanoria`, ≤ 1 Mio, JSON
  strict). À la mise à jour d'un module, l'ancienne version figée est retenue.
  Les versions qu'aucun projet ne fige plus et les essais de plus de 14 jours
  sont retirés lors des passages `run-canaries` et `self-sbom`. Si `pins.json`
  est illisible (absent : aucune version figée), le helper échoue fermé : aucune version figée n'est
  retirée et l'ancienne version d'un module mis à jour est gardée.
- **Essais et versions figées au runner** : une candidate d'essai ne sert qu'une
  tâche marquée `trial` (le rejeu d'une analyse d'essai est refusé par la
  console), et toute version autre que l'installée exige son empreinte.
- **Canaris** : un échec est classé `detection` (le module tourne sans trouver
  le cas connu, alerte et audit `module.canary-failed`) ou `infra` (délai,
  mémoire, image, runner resté occupé : gardé dans l'historique, sans alerte).
- **État publié** : `/var/lib/scanoria/vigilance/state.json` (root:scanoria
  0640) : images retenues et dernier relevé `self-sbom` ; les SARIF des
  comparateurs sont sous `vigilance/self/<console|module-<id>>/`.
- **Analyses d'essai** (trigger `trial`, `trial_id`, `replay_of`, ref
  `trial:<ref>`) : priorité 5, plan réduit au module essayé ; la tâche du runner
  porte `trial: true` et l'empreinte de la candidate. Aucune ingestion : les
  sorties sont comparées par empreinte G19 aux résultats de l'analyse d'origine
  (`module_trials.summary`) ; ni verdict, ni statut, ni liste, ni statistique.
- **SBOM de la console** : produit par `build.sh` (`npm sbom`, CycloneDX,
  déterministe) et livré dans le lot signé sous
  `/usr/share/scanoria/sbom/console.cdx.json`.


## 14. Relais IA des modules d'analyse par IA (0.7, chantier E, contrats 31 et 32)

Un module `scanner` qui déclare `scan.network: ai-relay` (K1–K10) parle une
API compatible OpenAI, mais ne joint jamais Ollama ni aucun réseau : son
conteneur reste en `--network=none`.

```
conteneur du module (--network=none, utilisateur 65534)
  outil ──HTTPS──▶ 127.0.0.1:8443 (pont, scan-tools/ai-relay/bridge.py)
                     │ octets relayés, sans rien lire
                     ▼
  /run/scanoria-relay/relay.sock (montage ro)  ═══  /run/scanoria-ai/relay.sock (hôte)
                                                      │ HTTPS, certificat ai-relay.<nom>
                                                      ▼
                                              scanoria-ai : relais (server/ai/relay.ts)
                                                      │ garde-fous § 3.5, journal, cache
                                                      ▼
                                              Ollama externe (règle nftables meta skuid)
```

- **Transport** : le relais est servi par `scanoria-ai` en HTTPS sur un socket
  Unix (`/run/scanoria-ai/relay.sock`, 0666 dans un répertoire 0700), avec le
  certificat `ai-relay.<nom de l'appliance>` émis par l'AC interne
  (`scanoria-ca issue-relay`, renouvelé avec `cert-renew`, copié en 0400 dans
  le répertoire d'exécution par `aiendpoint.install_runtime`). L'AC interne est
  contrainte à `DNS:<nom>` et exclut toute adresse IP : d'où le nom et non une
  adresse. Le runner monte le seul socket, en lecture seule, dans le
  conteneur ; aucun réseau Podman, aucune règle nftables, aucun autre
  conteneur ne le joint. Le pont écoute sur la boucle locale du conteneur, et
  un `/etc/hosts` monté désigne `ai-relay.<nom>` par `127.0.0.1` : le TLS va de
  l'outil au relais.
- **Variables** : `OPENAI_BASE_URL` et `OPENAI_API_BASE`
  (`https://ai-relay.<nom>:8443/v1`), `SCANORIA_AI_MODEL=scanoria` (alias : le
  modèle est choisi par l'appliance, clé de sélection `relay`, qui suit le
  modèle par défaut), `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`,
  `NODE_EXTRA_CA_CERTS` (`/run/scanoria-relay/ca.pem`). La commande du module
  est lancée sous le pont (`python3 -I /scanoria-relay/bridge.py`, interpréteur
  réglable par `scan.relay_python`), qui la lit dans
  `/run/scanoria-relay/command.json` (écrit par le runner, 0400, jamais en
  argument).
- **Jeton éphémère** : `scr_` + 48 octets aléatoires, créé par le runner pour un
  module d'une analyse ; sa portée `{purpose, module_id, project_id, scan_id,
  expires_at}` est écrite sous son empreinte dans `/run/scanoria-relay/tokens`
  (root:scanoria-ai 0750, fichiers 0640), seul endroit que lit le relais. Le
  jeton passe par un secret Podman monté pour l'utilisateur 65534 et lu par le
  pont, qui le donne à l'outil par `OPENAI_API_KEY` : jamais en argument, ni
  dans `podman inspect`, ni dans le journal (masqué). Il est retiré à la fin du
  module et expire au-delà du délai du module ; le runner purge au démarrage
  jetons et secrets orphelins.
- **Vérification préalable** : avant le conteneur, le runner appelle
  `GET /v1/relay/check`. Relais absent, connecteur inactif, disjoncteur
  ouvert, aucun modèle (`E_RELAY_UNAVAILABLE`), projet « aucun envoi à l'IA »,
  archivé ou inconnu (`E_RELAY_OPT_OUT`), jeton refusé (`E_RELAY_TOKEN`) :
  module `skipped`, jamais une erreur au sens de G13. Un module relié au relais
  n'est jamais repris du cache de résultats (V4).
- **Garde-fous par requête** (`prepareChat`) : consigne de l'appliance en
  tête ; outils, `functions`, `tool_choice` retirés ; rôles `tool`/`function`
  et contenus non textuels refusés ; chaque message masqué (secrets, y compris
  les messages système fournis par l'outil) ; corps ≤ 512 Kio, 64 messages,
  240 000 caractères ; `max_tokens` borné ; JSON (`response_format`) transmis à
  Ollama ; sortie nettoyée. Une requête à la fois vers Ollama (file de 8, puis
  503), même disjoncteur que les tâches de la console, cache par projet et
  module (`ai_cache`, kind `relay`), journal `ai_calls` (`via = 'relay'`,
  `module_id`, modèle `nom@empreinte12`), sans le contenu. Routes :
  `GET /v1/models`, `POST /v1/chat/completions` (flux SSE en un morceau si
  demandé), `POST /v1/embeddings`, `GET /v1/relay/check`.
- **Banc d'essai I23** : le banc d'essai d'installation d'un module relié tourne
  par le relais (jeton `testbed`, sans projet) ; sans connecteur, l'installation
  échoue avec `E_RELAY_UNAVAILABLE`. Un module d'IA qui ne tient plus les
  attentes de son banc d'essai deux nuits de suite est désactivé de lui-même
  (`vigilance.disable_failed_ai_modules`) ; un outil qui s'arrête en erreur
  (relais, modèle) est une panne « infra », jamais une détection perdue.
- **Jamais bloquant** (§ 3.5) : une erreur, un délai ou une sortie invalide
  d'un module relié (502 du relais, disjoncteur, file pleine, opt-out posé en
  cours d'analyse) le rend `skipped` avec la cause lisible ; le verdict n'est
  jamais non concluant à cause de l'IA. Le runner marque l'entrée du module
  `ai_relay: true` dans `result.json` : la console en déduit l'origine « IA »
  sans relire l'index du catalogue.

**Résultats IA (contrat 32)** : les résultats d'un module relié sont ingérés
avec `origin = 'ai'` (badge « IA », gravité `info` tant qu'ils ne sont pas
confirmés, la gravité native gardée dans `native_severity` et rendue à la
confirmation ; modèle et empreinte lus
dans le journal du relais de la dernière analyse). `evaluate.ts` les écarte du
verdict avant toute règle (`excludeUnconfirmedAi`, même un avis `MAL-` cité par
un modèle) tant que `ai_confirmed_at` est vide. `POST /api/findings/:id/ai-confirm`
(operator ou plus, compte `kind = 'human'` seulement, audit
`finding.ai-confirm`) les confirme : statut `nouveau` → `confirmé`, et le
résultat compte comme un autre dans les verdicts évalués ensuite. I24 : accord
IA/humain par module (`/api/ai/agreement`, champ `modules`).

**Diff de la PR (`scan.pr_diff`, K2 et K4)** : pour une analyse de PR, le
worker fige le commit de base (`pull_request.base_sha`) dans le plan
(`source.pr_base`, G11) et le transmet au runner (`pr_base` de la tâche). Si
un module du plan déclare `scan.pr_diff`, le conteneur de récupération
(`fetch.FETCH_SCRIPT`) récupère aussi la base si le miroir ne l'a pas, puis
écrit `git diff --no-ext-diff --no-textconv -M <merge-base> <tête>` dans
`ws/pr/pr.diff`, au plus 4 Mio (écriture bornée). En clone superficiel,
l'historique est approfondi en deux paliers (50 puis 1 000 commits) pour
trouver le point de divergence ; sans lui, aucun diff (jamais base → tête,
faux dès que la branche a divergé). Ces récupérations n'arrêtent jamais
l'analyse. Le runner monte le diff en lecture seule sur
`/pr.diff` (`SCANORIA_PR_DIFF`). `required` : hors PR, base ou point de
divergence introuvable, diff trop gros, le module est `skipped` (`E_PR_DIFF_UNAVAILABLE`, classe `input`) ;
`optional` : il tourne sans diff. Une sortie qui dépend du diff n'est jamais
mise en cache (V4).

**Modules d'analyse par IA livrés (0.7)** :

| Module | Ce qu'il lance | Règles | Diff |
|---|---|---|---|
| `pr-agent` (K2) | PR-Agent 0.50.0 en mode « diff seul » (plain-diff) : `review` puis `describe`, sortie JSON | `pr-agent/key-issue`, `pr-agent/security-concern` ; description proposée, effort et note dans `runs[0].properties["scanoria/pr-agent"]` | `required` |
| `fraim` (K4) | workflows Fraim 0.8.0 `code`, `iac` (fichiers modifiés seulement pour une PR incrémentale) et `risk_flagger` sur le diff | `fraim/code`, `fraim/iac`, `fraim/risk-flagger` ; indicateur de risque `pr_risk` dans `runs[0].properties["scanoria/fraim"]` | `optional` |

Ni l'un ni l'autre ne reçoit de jeton de forge, d'URL de PR ou de webhook :
leurs résultats sont publiés dans la PR par le client de forge de l'appliance
(contrat 30), marqués « (IA) ». Un outil qui n'obtient aucune réponse du
modèle rend le code 3 : module `skipped`, jamais « aucun résultat ». K1
(Kodus) n'est pas livré : voir `docs/ETUDE-K1-KODUS.md`.

