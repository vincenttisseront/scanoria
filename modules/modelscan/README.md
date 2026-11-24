# Module modelscan (0.6, K8)

Repère les fichiers de modèles d'apprentissage automatique qui exécutent du
code à leur chargement. Analyse statique seule, sans IA et sans réseau.

## Outil et image

- **ModelScan 0.8.8** (Protect AI, Apache-2.0 ; `modelscan/tools/` sous MIT),
  avec **tomlkit 0.13.3** (MIT). Protect AI ne publie aucune image de
  conteneur : les deux paquets sont livrés **tels quels** avec l'appliance,
  dans `src/rootfs/usr/lib/scanoria/scan-tools/modelscan/vendor/`, à partir
  des archives PyPI vérifiées par SHA-256 (voir `vendor/README.md`). Le
  fichier `vendor/SHA256SUMS` est contrôlé par `tests/b29-ouverture.sh`.
- L'image d'exécution est l'image officielle **tensorflow/tensorflow 2.21.0**
  (Apache-2.0, Google), épinglée par empreinte. Elle apporte numpy, h5py et
  TensorFlow, sans lesquels ModelScan ne lit ni les modèles H5, ni les
  modèles Keras, ni les SavedModel.
- `modelscan_sarif.py` (outil de l'appliance) lance ModelScan, écrit son
  rapport JSON natif (`/out/modelscan.json`, identique à `modelscan -r json`)
  puis le convertit en SARIF 2.1.0 (`/out/modelscan.sarif`).

## Gravité et quality gate

Un modèle qui exécute du code à son chargement est **`critical`**, quelle que
soit la gravité propre de ModelScan (gardée dans `properties.modelscan_severity`) :

| Règle | Cas | Gravité |
|---|---|---|
| `modelscan/pickle-unsafe-op`, `pytorch-unsafe-op`, `numpy-unsafe-op` | import d'un global dangereux dans un pickle (appelé par `REDUCE` au chargement) | critical |
| `modelscan/keras-lambda`, `h5-lambda`, `savedmodel-lambda` | couche Lambda : code Python sérialisé, exécuté à la désérialisation | critical |
| `modelscan/tensorflow-unsafe-op` | opérateurs `ReadFile` / `WriteFile` d'un graphe, exécutés à l'inférence | high |

**Catégorie du gate : `sast`.** Le module déclare `categories: [sast]`. Ses
résultats appartiennent donc à la famille `sast` de l'évaluateur
(`server/gates/evaluate.ts`), bloquée dès `sast_block_from` (`high` par
défaut) : un modèle piégé bloque sans aucun réglage. C'est le bon classement,
car le problème est du **code exécutable caché dans un fichier du dépôt**
(CWE-502, désérialisation de données non fiables), pas une vulnérabilité de
dépendance (`vuln`, dont le seuil suit les CVE) ni une erreur de
configuration (`iac`). La même catégorie fait entrer le module dans le profil
`complet` sans le citer.

## Applicabilité

Le module ne sert qu'aux dépôts qui contiennent des modèles. Il n'est pas
dans la sélection conseillée ; la détection F1 le propose dès qu'un fichier
de modèle est trouvé (`.pkl`, `.pickle`, `.joblib`, `.pt`, `.pth`, `.ckpt`,
`.bin` sous un dossier de modèle, `.npy`, `.h5`, `.keras`, `saved_model.pb`).
`scan.applies_to` (contrat 23) reprend ces motifs : sans aucun fichier de
modèle, le module n'est pas lancé (« not-applicable », noté dans la
couverture G15, jamais compté comme absent G13).

## Tests

- `tests/b29-ouverture.sh` : manifeste, `vendor/` intact, conversion sur des
  rapports piégés (`tests/native-sample.json` → `tests/recorded.sarif`),
  analyse réelle du banc d'essai sans TensorFlow ;
- `tests/b29-live.sh` (CI, root, vrai podman) : banc d'essai (F12) et analyse
  d'un dépôt piégé par le vrai runner, dans l'image épinglée ;
- `webui/tests/integration/modelscan-gate.test.ts` : verdict défavorable.
