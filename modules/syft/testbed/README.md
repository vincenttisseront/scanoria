# Banc d'essai (Scanoria) : SBOM

Petit dépôt figé, un composant par écosystème : `minimist` 1.2.8 (npm, licence
MIT déclarée dans `package-lock.json`), `six` 1.17.0 (PyPI, `requirements.txt`)
et `github.com/google/uuid` v1.6.0 (Go, `go.mod` et `go.sum`). Le banc d'essai
(F12) vérifie que Syft les inventorie tous, avec leur purl et la licence connue.
Ne jamais installer ces dépendances.
