import sqlite3


def find(db, name):
    q = "SELECT * FROM users WHERE name = '" + name + "'"
    return db.execute(q).fetchall()
