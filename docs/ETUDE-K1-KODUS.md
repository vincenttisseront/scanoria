# Étude K1 : Kodus (revue de code IA des PR)

Étude du 2026-11-25 (chantier E de la 0.7), à partir des fichiers publics du
dépôt `kodustech/kodus-ai` (branche `main`), de sa documentation et du
registre GHCR. **Recommandation : ne pas intégrer K1 en 0.7** et garder
PR-Agent (K2, `modules/pr-agent`) comme revue de code IA des PR. La décision
revient à l'intégrateur.

## Constats

| Point | Constat | Effet pour Scanoria |
|---|---|---|
| Licence | Double licence : `AGPL-3.0-only`, sauf les fichiers `*.ee.*` et les dossiers `ee/`, sous la « Kodus Enterprise Code License » (propriétaire). Elle permet d'exécuter le code EE non modifié pour les fonctions Community, mais interdit de le modifier, de le distribuer et de l'incorporer à un autre produit. | Restriction `no-redistribution` au minimum : jamais dans un lot hors ligne, images tirées par l'administrateur, acceptation explicite. Heurte le principe 1 (logiciels libres ou gratuits sans réserve). |
| Accès à la forge | Kodus enregistre ses webhooks et poste lui-même ses commentaires. Sur Forgejo, le jeton exige `repository` et `issue` en lecture et écriture, `organization` et `user` en lecture, et l'utilisateur doit être **administrateur de chaque dépôt** revu. Aucun mode « sans publication » côté serveur. | Contraire à la préférence du brief (aucun jeton d'écriture, publication par le client de forge de l'appliance, contrat 30). |
| CLI | Le CLI `kodus` revoit un diff local et rend du JSON ou du Markdown, mais n'est qu'un client de l'API Kodus (`KODUS_API_URL`, `KODUS_TEAM_KEY`) : le serveur complet reste nécessaire. | Pas de variante « scanner sans service » (option b impossible). |
| Poids | Services `api`, `worker`, `webhooks`, `web` (et `kodus-mcp-manager`), plus PostgreSQL 16 avec pgvector, MongoDB et RabbitMQ. Aucun minimum matériel publié. | Incompatible avec le plancher de 2 vCPU / 4 Go (D6) ; à mesurer en banc si K1 était retenu. |
| IA | Point compatible OpenAI arbitraire possible (`API_LLM_PROVIDER=openai_compatible`, `API_LLM_BASE_URL`, `API_LLM_PROVIDER_MODEL`, `API_LLM_API_KEY`). Ollama n'est pas documenté explicitement. | Branchable sur le relais, sous réserve d'essai. |
| Sorties réseau par défaut | Télémétrie quotidienne vers le serveur de l'éditeur (coupée par `KODUS_TELEMETRY_DISABLED=true`), bac à sable E2B en SaaS (`SANDBOX_PROVIDER`), traces Langfuse vers son service en ligne, et `API_CLOUD_MODE` à forcer à `false`. | Chacune à neutraliser, puis à vérifier par une capture réseau. |

## Si K1 était retenu malgré tout

Module `service` facultatif, licence déclarée `other` avec acceptation
explicite, images épinglées par empreinte tirées par l'administrateur (jamais
dans un lot hors ligne), jeton Forgejo dédié et révocable affiché dans la
console, toutes les sorties ci-dessus coupées, LLM par le relais, et alternative
exclusive de K2 selon les ressources (F14).

## Incertitudes

- La dernière release GitHub (2.2.17) est plus récente que la dernière image
  stable trouvée sur GHCR (2.2.12).
- Aucun minimum matériel publié.
- Aucun appel réseau caché vérifié en conditions réelles.
- Compatibilité avec Ollama non confirmée par la documentation.
- Liste exacte des fichiers EE nécessaires au fonctionnement Community
  inconnue.
