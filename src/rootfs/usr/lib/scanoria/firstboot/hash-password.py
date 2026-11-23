# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Vincent Tisseront
"""Hachage PBKDF2-HMAC-SHA256 au format PHC (ARCHITECTURE § 9.3).

Lit le mot de passe sur l'entrée standard (UTF-8, sans fin de ligne ajoutée),
écrit sur la sortie standard :
    $pbkdf2-sha256$i=600000$<sel base64 sans =>$<hash base64 sans =>
Le mot de passe n'apparaît jamais dans les arguments ni sur disque.
Lancer avec « python3 -I » (bibliothèque standard seulement).
"""

import base64
import hashlib
import os
import sys

ITERATIONS = 600000
SALT_BYTES = 16
HASH_BYTES = 32
MIN_LEN = 12
MAX_LEN = 128


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii").rstrip("=")


def main() -> int:
    raw = sys.stdin.buffer.read()
    try:
        password = raw.decode("utf-8")
    except UnicodeDecodeError:
        print("password is not valid UTF-8", file=sys.stderr)
        return 2
    if not MIN_LEN <= len(password) <= MAX_LEN:
        print("password length out of bounds", file=sys.stderr)
        return 2
    salt = os.urandom(SALT_BYTES)
    digest = hashlib.pbkdf2_hmac("sha256", raw, salt, ITERATIONS, HASH_BYTES)
    print(f"$pbkdf2-sha256$i={ITERATIONS}${b64(salt)}${b64(digest)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
