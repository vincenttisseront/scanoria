# Banc d'essai inerte du module vulnhuntr (K3) : application Flask volontairement
# vulnérable (SSRF et injection de commande). Jamais exécutée : Vulnhuntr la lit.
import subprocess

import requests
from flask import Flask, request

app = Flask(__name__)


@app.route("/fetch")
def fetch():
    url = request.args.get("url", "")
    return requests.get(url, timeout=5).text


@app.route("/ping")
def ping():
    host = request.args.get("host", "")
    return subprocess.check_output("ping -c 1 " + host, shell=True)
