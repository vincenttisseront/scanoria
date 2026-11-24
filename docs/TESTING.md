<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Vincent Tisseront
-->

# Tests

Tous les tests ci-dessous tournent dans la CI ([CI-CD.md](CI-CD.md)). La
plupart se lancent aussi sur un poste Linux.

## 1. Console (`webui/`)

Scripts npm standard, appelés tels quels par la CI :

| Commande | Contenu |
|---|---|
| `npm run lint` | ESLint |
| `npm run typecheck` | `nuxt typecheck` (vue-tsc) |
| `npm run test` | Vitest, deux projets : `server` (tests unitaires `tests/unit`, et tests d'intégration contre un **vrai PostgreSQL 16** `tests/integration`, dont l'API servie par h3 dans le processus) et `app` (pages, composants et composables de la console dans l'environnement Nuxt, `tests/app`, API simulée) |
| `npm run test:app` | Projet `app` seul |
| `npm run build` | Construction Nitro (`.output/`) |
| `npm run test:e2e` | Tests de bout en bout contre le serveur construit (`tests/e2e`) |

Les tests d'intégration et de bout en bout ont besoin de `DATABASE_URL`, qui
désigne une base d'administration. Chaque fichier de test y crée sa base
jetable. Sans `DATABASE_URL`, ces tests sont **sautés** ; la CI les lance
toujours. Pour un essai en local :

```bash
docker run -d --rm --name pg16 -p 5432:5432 -e POSTGRES_HOST_AUTH_METHOD=trust \
  -e POSTGRES_INITDB_ARGS="--encoding=UTF8 --locale=en_US.UTF-8" postgres:16
cd webui && DATABASE_URL=postgresql://postgres@127.0.0.1:5432/postgres npm run test
```

La base de test est en locale `en_US.UTF-8`, comme sur l'appliance. La CI
vérifie la locale avant de lancer les tests. Elle ajoute la couverture lcov
(`webui/coverage/lcov.info`, un seul rapport pour les deux projets : `app/`,
`server/` et `shared/`), envoyée à SonarQube Cloud.

## 2. Batteries shell `tests/bNN-*.sh`

| Plage | Lot | Contenu |
|---|---|---|
| `b01`–`b19` | système | `b01` demandes hostiles, `b02` mises à jour signées et retour arrière, `b03` AC et certificats, `b04` contrôles statiques (SPDX, shellcheck, systemd, nftables, schémas) |
| `b20`–`b29` | ISO | `b20` contrôles statiques, assemblage du lot sur une fausse sortie, assistant (dont le fichier du mode sans intervention) ; `b21` lot et ISO réellement produits (`SCANORIA_OUT`) |
| `b30`–`b39` | CI et publication | `b30` chaîne de signature (`test-release-chain.sh`, sur le lot produit si `SCANORIA_OUT`) |

`b03` et `b04` font aussi `nginx -t` et `nft -c` quand ils tournent en root :
la CI les relance ainsi après les batteries sans root.

Conventions :

- Chaque batterie est un script bash **autonome**. Il sort en 0 si tout
  passe, et autrement en un code différent de 0.
- **Sans root** : le lanceur refuse de tourner en root. Un test qui exige root
  et de vrais services porte le suffixe `-live.sh`. Il ne tourne que sur une
  machine de test, jamais en CI.
- Une batterie qui a besoin des sorties de construction lit `SCANORIA_OUT`.
  C'est le répertoire `out/` de `build.sh`, défini par le travail `iso-build`.
  Sans cette variable, la batterie **saute** ces cas : elle affiche `skip` et
  sort en 0.
- Les clés et certificats de test sont **générés à l'exécution** dans un
  répertoire temporaire. Aucun en-tête de clé privée n'est versionné, même
  factice : gitleaks n'a pas d'exception ([SECURITE.md](SECURITE.md)).
- Dépendances disponibles en CI : bash, jq, zstd, xorriso, gnupg, openssl,
  python3 (`yaml`, `jsonschema`), shellcheck, Node 22.

```bash
.github/scripts/run-batteries.sh                  # toutes, hors -live
.github/scripts/run-batteries.sh 'b2[0-9]-*.sh'   # une plage
SCANORIA_OUT=$PWD/out .github/scripts/run-batteries.sh 'b3[0-9]-*.sh'
```

### Mesure des délais (0.6)

`tests/b28-orchestration.sh` (sans root) couvre l'applicabilité (V6), le cache de résultats (V4), l'ordonnancement (V5) et le graphe SBOM (V3) du runner. `tests/bench/` mesure les délais réels sur 2 vCPU / 4 Go (workflow `bench.yml`, hors de `ci-ok`) : voir `tests/bench/README.md`.

## 3. Chaîne de publication

`.github/scripts/test-release-chain.sh [RÉPERTOIRE_DU_LOT]` génère des clés
Ed25519 **jetables**. Il signe un lot, fabriqué ou réel (`out/` après
`build.sh --bundle`), puis le vérifie comme l'appliance. Il refuse ensuite
les cas hostiles :

- mauvaise clé, ou clé non Ed25519 ;
- `SHA256SUMS` modifié, ou portant une troisième ligne même signée ;
- signature tronquée ou absente ;
- archive ou `release.json` modifiés ;
- lien symbolique ;
- autre version ;
- morceau d'ISO modifié ou manquant ;
- empreintes de l'ISO non signées.

Il tourne dans `lint`, sur un faux lot, et dans `iso-build`, sur le lot
produit.

## 4. Test de démarrage de l'ISO

`.github/scripts/iso-boot-test.sh ISO RÉPERTOIRE` est lancé par `iso.yml`, et
par `release.yml` avant toute publication. Il a besoin de `/dev/kvm`
(disponible sur `ubuntu-latest` après une règle udev), de QEMU, de socat et
de netpbm.

1. **Installation** : QEMU/KVM avec 2 vCPU, 6 Gio de RAM et un disque virtuel
   de 48 Go, soit au-dessus du plancher D6. Le réseau virtuel est en plage
   RFC 5737 (`192.0.2.0/24`). La machine démarre sur l'ISO, l'entrée par
   défaut lance l'autoinstall, puis la machine s'éteint. Délai : 60 min.
2. **Premier démarrage sans intervention** : la machine redémarre sur le
   disque. QEMU lui passe un fichier de réponses par **fw_cfg**
   (`opt/scanoria/unattended.json`). Les mots de passe y sont générés à
   l'exécution ; ils ne sont jamais affichés ni conservés.
3. **Vérifications** :
   - l'assistant se termine en `ok` ;
   - `scanoria-selftest` sort en 0 (`pass` ou `warn`), sans aucun contrôle
     `fail`, avec la bonne version ;
   - `GET /api/health`, via nginx (port 443 redirigé), rend
     `{"status":"ok","version":"X.Y.Z","db":"ok"}`.

Journaux (port série, captures d'écran toutes les 5 min, rapport selftest) :
artefact `iso-boot-logs`.

### Contrat avec l'assistant de premier démarrage (lot ISO)

Le mode sans intervention n'existe que **sous QEMU**, quand le fichier fw_cfg
est présent. Seul l'hyperviseur peut le fournir, et celui-ci contrôle déjà
entièrement la machine.

L'assistant le lit dans
`/sys/firmware/qemu_fw_cfg/by_name/opt/scanoria/unattended.json/raw`, après
`modprobe qemu_fw_cfg`. Il le valide aussi strictement que les saisies
interactives, puis applique les mêmes étapes que le mode interactif.

```json
{
  "version": 1,
  "language": "en",
  "keyboard": "us",
  "timezone": "Etc/UTC",
  "network": { "mode": "dhcp" },
  "fqdn": "analyse.exemple.test",
  "admin_password": "<généré à l'exécution>",
  "sysadmin_password": "<généré à l'exécution>",
  "admin_networks": ["192.0.2.0/24"],
  "report": "serial",
  "poweroff": false
}
```

Avec `"report": "serial"`, l'assistant écrit sur `/dev/ttyS0`, une ligne
chacun et dans cet ordre :

```
SCANORIA-SELFTEST-JSON <sortie de « scanoria-selftest --json » encodée en base64, sur une ligne>
SCANORIA-SELFTEST-EXIT <code de sortie de scanoria-selftest>
SCANORIA-FIRSTBOOT-END ok|error
```

Il n'écrit jamais de mot de passe sur le port série ni dans les journaux.
Avec `"poweroff": false`, la machine reste allumée pour le contrôle de
`/api/health`.

## 5. Lint et sécurité

```bash
.github/scripts/install-tools.sh /tmp/outils shellcheck actionlint gitleaks osv-scanner
PATH=/tmp/outils:$PATH
.github/scripts/check-repo.sh
.github/scripts/lint-shell.sh
actionlint
gitleaks git --config .gitleaks.toml --redact --log-opts=HEAD .
osv-scanner scan source --config osv-scanner.toml --recursive .
```
