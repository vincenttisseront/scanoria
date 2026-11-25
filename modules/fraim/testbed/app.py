# Banc d'essai Scanoria : code volontairement vulnérable, jamais exécuté.
import sqlite3


def find(db, name):
    q = "SELECT * FROM users WHERE name = '" + name + "'"
    return db.execute(q).fetchall()
