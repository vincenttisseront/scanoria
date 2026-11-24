# Mesure des délais d'analyse (0.6, V1–V10)

Batterie de référence lancée par `.github/workflows/bench.yml` (PR qui touchent
le runner, le plan ou les modules, puis chaque lundi) sur une machine jetable root.

- `gen.py <dossier> small|medium|large` : dépôt d'essai déterministe (40, 1 500
  et 8 000 fichiers ; 5, 40 et 120 dépendances npm). Généré à chaque mesure,
  jamais versionné.
- `run.sh <sortie>` : appliance de test vide, modules installés par le helper
  (gitleaks, OSV-Scanner, Trivy, Syft, Grype, reach-index ; vraies images et
  vraies bases), vue par le runner comme une machine de 2 vCPU / 4 Go, conteneurs
  bornés par `machine.slice` (`CPUQuota=200%`, `MemoryMax=4G`). Chaque dépôt est
  analysé à froid, puis avec le cache de résultats rempli (V4).
- `store.py` : range les sorties d'une analyse dans le cache, comme le worker.
- `compare.py` : rapport Markdown (durée totale et par outil) comparé à
  `baseline.json`. Une hausse de plus de 15 % de la durée totale, ou d'un outil
  dont la référence dépasse 5 s, est une **régression signalée, non bloquante**
  (hors de `ci-ok`).

`baseline.json` n'est mis à jour **que par l'intégrateur**, à partir de
l'artefact `bench/mesures.json` d'une exécution sur `main`.
