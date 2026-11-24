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
