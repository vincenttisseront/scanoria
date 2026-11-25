# Module pr-agent (0.7, K2)

Revue de code par l'IA de chaque PR : points à revoir (bogues, failles,
performance), préoccupation de sécurité, description proposée. Le module ne
détient aucun accès à la forge.

## Outil et image

- **PR-Agent 0.50.0** (MIT ; licence relevée le 2026-11-25 sur PyPI et sur le
  fichier `LICENSE` du dépôt `the-pr-agent/pr-agent` : le retour vers
  Apache-2.0 annoncé n'a pas eu lieu à cette date).
- Aucune image amont épinglable : l'image est construite par la CI de Scanoria
  (`image/Containerfile`, base python 3.13-slim épinglée par empreinte,
  dépendances par empreintes dans `image/requirements.lock`, roues seulement).
  Le module porte `image_pending: true` jusqu'à la PR de suivi qui pose
  l'empreinte publiée (docs/MODULES.md § 8).
- `pragent_scan.py` (outil de l'appliance, `scan-tools/pr-agent/`) lance
  PR-Agent **dans le processus**, en mode « diff seul » (`--diff-file`,
  fournisseur `plain-diff`) : `review`, puis `describe`, chacun avec
  `--json-output`. Aucune URL de PR, aucun jeton de forge, aucune
  configuration distante (`PR_AGENT_EXTRA_CONFIG_URL` retiré) ; le répertoire
  courant n'a pas de dépôt Git, donc PR-Agent ne lit que le diff.

## Entrées et sorties

- Entrée : le diff de la PR, calculé par le runner (`scan.pr_diff: required`,
  `/pr.diff`). Hors PR, le module est `skipped`, sans effet sur le verdict.
- Modèle : celui de l'appliance (alias `scanoria`), joint par le relais IA
  (contrat 31) ; aucun modèle de repli.
- Sortie SARIF (`/out/pr-agent.sarif`) :

| Règle | Contenu | Gravité à la confirmation |
|---|---|---|
| `pr-agent/key-issue` | point à revoir, avec fichier et lignes du diff | medium |
| `pr-agent/security-concern` | préoccupation de sécurité de la PR | high |

  `runs[0].properties["scanoria/pr-agent"]` : description proposée (titre,
  type, résumé), effort de revue (1 à 5), note (0 à 100), fichiers non revus.
- Les résultats sont « IA » (contrat 32) : `info` et hors verdict tant qu'une
  personne ne les a pas confirmés ; publiés dans la PR, marqués « (IA) », par
  le client de forge de l'appliance (contrat 30).
- Un chemin absolu, avec `..` ou absent du diff est écarté ; tous les textes
  sont bornés et nettoyés.
- Sans réponse structurée du modèle (relais injoignable, sortie invalide),
  l'outil rend 3 : module `skipped`, jamais « aucun résultat ».

## Banc d'essai

`testbed/pr.diff` ajoute `app.py`, dont la requête SQL concatène l'entrée
utilisateur. Le banc (F12, I23) monte ce diff sur `/pr.diff` et attend au
moins un `pr-agent/key-issue`. `tests/native-*.json` : sortie JSON de PR-Agent
0.50.0 obtenue contre un faux modèle ; `tests/recorded.sarif` : sa conversion.

## Ressources

1 Go de RAM, 1 vCPU. PR-Agent et le module K1 (Kodus) étaient prévus comme
alternatives ; K1 n'est pas livré (docs/ETUDE-K1-KODUS.md).
