<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Vincent Tisseront
-->

# Console Scanoria (`webui/`)

Nuxt 4 + Nuxt UI, serveur Nitro, PostgreSQL 16 (`pg`, SQL explicite), zod,
i18n français et anglais. Contrats : `../docs/ARCHITECTURE.md` (§ 3.6, § 5, § 9).

La console ne fait **aucune** action privilégiée : elle dépose des demandes JSON
dans `requests/tmp` → `requests/incoming` et lit `/run/scanoria/state.json` et
`requests/{done,failed}`.

## Commandes

| Commande | Rôle |
|---|---|
| `npm ci` | dépendances (lance `nuxt prepare`) |
| `npm run lint` | ESLint (`@nuxt/eslint`) |
| `npm run typecheck` | `vue-tsc` (application, serveur, tests) |
| `npm test` | vitest : unitaires ; intégration si `DATABASE_URL` est défini |
| `npm run build` | sortie Nitro dans `.output/` |
| `npm run test:e2e` | serveur construit lancé contre PostgreSQL (`DATABASE_URL`, après `build`) |
| `npm run migrate` | `node migrate.mjs` (base de `NUXT_DATABASE_URL` ou `DATABASE_URL`) |

`DATABASE_URL` désigne une base d'administration d'un PostgreSQL 16 jetable
(droit `CREATE DATABASE`) : chaque fichier de test crée puis supprime sa propre
base `scanoria_test_<aléa>`. Exemple :
`DATABASE_URL=postgresql://postgres@127.0.0.1:5432/postgres npm test`.

## Lot de mise à jour (lot C)

- `webui/` du lot = contenu de `.output/` (`server/index.mjs`, `public/`, `nitro.json`) ;
- `webui/migrate.mjs` = ce fichier, autonome : il charge `pg` depuis
  `webui/server/node_modules` (dépendances embarquées par Nitro) et lit les
  migrations dans `webui/migrations/` (ou `NUXT_MIGRATIONS_DIR`) ;
- `webui/migrations/NNN_*.sql` = copie de `server/db/migrations/` ;
- `webui/VERSION`.

Les migrations sont aussi embarquées dans le serveur (`serverAssets`) et
appliquées au démarrage (désactivable : `NUXT_MIGRATE_ON_START=false`).

## Environnement

Variables de `/etc/scanoria/console.env` (§ 3.6), plus :
`NUXT_TRUST_PROXY` (défaut `true` : `X-Real-IP` pris en compte seulement pour
une connexion venant de la boucle locale), `NUXT_INGEST_INTERVAL_MS` (défaut 5000).
Le cookie de session est `__Host-scanoria_session` (`Secure`) : en
développement, ouvrir la console sur `http://localhost:3000`.
