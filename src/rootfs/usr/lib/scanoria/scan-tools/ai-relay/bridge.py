# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Vincent Tisseront
"""Pont du relais IA, lancé dans le conteneur d'un module d'analyse par IA
(0.7, contrat 31) : python3 -I /scanoria-relay/bridge.py -- COMMANDE…

Le conteneur reste en --network=none. Le pont écoute sur 127.0.0.1 (boucle
locale du conteneur, port SCANORIA_RELAY_PORT) et relaie chaque connexion,
octet par octet, vers le socket Unix du relais monté en lecture seule sur
/run/scanoria-relay/relay.sock. Il ne lit ni ne modifie rien de ce qui passe :
le TLS va de l'outil au relais de scanoria-ai, qui vérifie le jeton et
applique les garde-fous (CLAUDE.md § 3.5).

Le jeton éphémère est lu dans le secret Podman /run/secrets/relay-token et
passé à l'outil par OPENAI_API_KEY : il n'apparaît ni en argument, ni dans la
configuration du conteneur. Le pont rend le code de sortie de l'outil, ou
70 s'il ne peut pas démarrer.
"""

import os
import signal
import socket
import subprocess
import sys
import threading

SOCKET = "/run/scanoria-relay/relay.sock"
TOKEN = "/run/secrets/relay-token"
MAX_CONNECTIONS = 32
EX_SOFTWARE = 70


def pump(src, dst):
    try:
        while True:
            data = src.recv(65536)
            if not data:
                break
            dst.sendall(data)
    except OSError:
        pass
    finally:
        for s, how in ((dst, socket.SHUT_WR), (src, socket.SHUT_RD)):
            try:
                s.shutdown(how)
            except OSError:
                pass


def serve(listener, slots):
    while True:
        try:
            client, _ = listener.accept()
        except OSError:
            return
        if not slots.acquire(blocking=False):
            client.close()
            continue
        threading.Thread(target=handle, args=(client, slots), daemon=True).start()


def handle(client, slots):
    upstream = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        upstream.connect(SOCKET)
        back = threading.Thread(target=pump, args=(upstream, client), daemon=True)
        back.start()
        pump(client, upstream)
        back.join()
    except OSError:
        pass
    finally:
        upstream.close()
        client.close()
        slots.release()


def main(argv):
    if len(argv) < 3 or argv[1] != "--":
        sys.stderr.write("usage: bridge.py -- COMMAND [ARG...]\n")
        return EX_SOFTWARE
    try:
        with open(TOKEN, encoding="ascii") as f:
            token = f.read(256).strip()
    except OSError:
        sys.stderr.write("ai-relay bridge: relay token missing\n")
        return EX_SOFTWARE
    try:
        port = int(os.environ.get("SCANORIA_RELAY_PORT", "8443"))
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", port))
        listener.listen(MAX_CONNECTIONS)
    except (OSError, ValueError) as e:
        sys.stderr.write("ai-relay bridge: cannot listen: %s\n" % e.__class__.__name__)
        return EX_SOFTWARE
    threading.Thread(target=serve, args=(listener, threading.BoundedSemaphore(MAX_CONNECTIONS)), daemon=True).start()
    env = dict(os.environ)
    env["OPENAI_API_KEY"] = token
    env.pop("SCANORIA_RELAY_PORT", None)
    try:
        child = subprocess.Popen(argv[2:], env=env, close_fds=True)
    except OSError as e:
        sys.stderr.write("ai-relay bridge: cannot start the tool: %s\n" % e.__class__.__name__)
        return 127
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda s, _f: child.send_signal(s))
    rc = child.wait()
    listener.close()
    return rc if rc >= 0 else 128 - rc


if __name__ == "__main__":
    sys.exit(main(sys.argv))
