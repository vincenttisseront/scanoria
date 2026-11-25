# Module fraim (0.7, K4)

Analyse par l'IA du code et de l'infrastructure en code, et indicateur de
risque de chaque PR.

## Outil et image

- **Fraim 0.8.0** de Resourcely (MIT ; licence relevée le 2026-11-25 sur PyPI
  et sur le fichier `LICENSE` du dépôt `fraim-dev/fraim`).
- Aucune image amont épinglable : image construite par la CI de Scanoria
  (`image/Containerfile`, base python 3.13-slim épinglée par empreinte,
  dépendances par empreintes dans `image/requirements.lock`, roues seulement),
  `image_pending: true` jusqu'à la PR de suivi (docs/MODULES.md § 8).
- `fraim_scan.py` (outil de l'appliance, `scan-tools/fraim/`) lance les
  workflows **dans le processus**, dans une seule boucle asyncio :
  - `code` et `iac` sur `/src`, limités aux fichiers modifiés pour une PR
    incrémentale (`scan.incremental`, G18) ;
  - `risk_flagger` si le diff de la PR est fourni (`scan.pr_diff: optional`) :
    Fraim lit ce fichier au lieu de lancer git, et ne reçoit ni URL de PR, ni
    relecteur, ni webhook Slack (rien n'est publié par l'outil).
- Les outils tree-sitter que Fraim propose au modèle ne lui parviennent pas
  (le relais retire tout outil) : aucune grammaire n'est téléchargée.

## Sorties

| Règle | Workflow | Gravité à la confirmation |
|---|---|---|
| `fraim/code` | faille probable du code (`properties.type` : type relevé) | selon le niveau SARIF (error : high, warning : medium, note : low) |
| `fraim/iac` | configuration d'infrastructure risquée | idem |
| `fraim/risk-flagger` | changement à risque de la PR (`properties.type` : catégorie de risque) | gravité de risque de Fraim (critical…low) |

`runs[0].properties["scanoria/fraim"]` : workflows lancés et en échec, appels
au modèle réussis et échoués (`partial` si une partie a échoué), et
`pr_risk`, l'indicateur de risque de la PR (plus haute gravité relevée par
`risk_flagger`, ou `none`).

Résultats « IA » (contrat 32) : `info` et hors verdict tant qu'une personne
ne les a pas confirmés. Fraim saute en silence un morceau dont l'appel au
modèle échoue : l'outil compte donc chaque appel, et rend 3 (module
`skipped`) si aucun n'a réussi, au lieu d'un faux « aucun résultat ».

## Banc d'essai

`testbed/app.py` (requête SQL par concaténation), `testbed/main.tf` (seau
ouvert à tous) et `testbed/pr.diff`. Attente unique et stable :
`fraim/code` au moins une fois. `tests/native-results.json` : résultats au
format de Fraim ; `tests/recorded.sarif` : leur conversion.
