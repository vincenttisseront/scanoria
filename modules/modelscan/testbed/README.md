# Banc d'essai de modelscan (K8)

Modèles factices dont le résultat est connu d'avance. Aucun n'est un vrai
modèle, et aucun n'est jamais chargé : ModelScan lit leurs opcodes ou leur
configuration.

- `models/trapped.pkl` : pickle **piégé inerte**, écrit opcode par opcode
  (`GLOBAL operator.attrgetter`, puis `REDUCE` avec l'argument `"real"`).
  Chargé, il ne ferait que construire `operator.attrgetter("real")`, sans
  aucun effet ; il suffit à montrer qu'un pickle appelle une fonction à son
  chargement → `modelscan/pickle-unsafe-op`, `critical` ;
- `models/lambda.keras` : archive Keras dont `config.json` déclare une couche
  `Lambda` (fonction factice, aucun code) → `modelscan/keras-lambda`,
  `critical` (vérifié dans l'image TensorFlow, `tests/b29-live.sh`) ;
- `models/healthy.pkl` : pickle d'un dictionnaire de nombres, sans aucun
  global → aucun résultat.
