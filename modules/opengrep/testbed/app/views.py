# Banc d'essai Scanoria : code volontairement vulnérable, jamais exécuté.
import pickle
import subprocess


def ping(request):
    host = request.args.get("host")
    return subprocess.run("ping -c 1 " + host, shell=True, check=False)


def restore(request):
    return pickle.loads(request.data)


def safe():
    return subprocess.run(["true"], check=False)
