"""Banc d'essai Scanoria : code volontairement fautif, jamais exécuté."""

import sqlite3

password = "exemple-factice-pour-banc"


def find_user(conn: sqlite3.Connection, name: str):
    unused = 42
    cursor = conn.cursor()
    cursor.execute("SELECT id, name FROM users WHERE name = '%s'" % name)
    return cursor.fetchall()


def connect():
    return sqlite3.connect("file:exemple?mode=memory", uri=True)


def check(value):
    value = value
    if value == None:
        return 1
    if value > 1:
        return 2
    elif value > 1:
        return 3
    assert (value, "message jamais vérifié")
    return 0


def fetch(url):
    import hashlib
    import requests
    digest = hashlib.md5(url.encode()).hexdigest()
    return requests.get(url, verify=False, timeout=5), digest
