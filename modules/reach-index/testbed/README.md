# Banc d'essai de reach-index (I11)

Dépôt factice où l'atteignabilité est connue d'avance :

- `src/cli.js` importe **minimist** et l'appelle (appel atteignable) ;
- `src/report.js` importe **lodash** sans jamais l'appeler (import seul) ;
- `app.py` appelle `yaml.load` (PyYAML) ;
- `java/App.java` instancie `org.yaml.snakeyaml.Yaml` ;
- `cmd/main.go` appelle `parse.Do` d'un module Go fictif (`exemple.test/lib/parse`).

Rien de ce code n'est exécuté : il est seulement lu par l'indexeur.
