# Banc d'essai Scanoria : code volontairement vulnérable, jamais exécuté.
import pickle
import subprocess

import yaml


def run(cmd):
    return subprocess.call(cmd, shell=True)


def load(blob):
    return pickle.loads(blob)


def config(text):
    return yaml.load(text)
