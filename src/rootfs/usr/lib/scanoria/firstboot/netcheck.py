# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Vincent Tisseront
"""Contrôles d'adresses de l'assistant de premier démarrage.

Lancer avec « python3 -I netcheck.py <commande> <valeur> ». Sortie 0 et forme
canonique sur la sortie standard si la valeur est valide, sortie 1 sinon.

  networks "<liste>"   réseaux CIDR v4/v6 séparés par virgules ou espaces,
                       1 à 64, dédoublonnés → tableau JSON canonique
  iface "<a/p>"        adresse d'interface avec préfixe → « adresse/préfixe »
  iface-network "<a/p>"  réseau de cette adresse → « réseau/préfixe »
  ip "<adresse>"       adresse IP seule → forme canonique
  ips "<liste>"        0 à 3 adresses IP → séparées par des espaces
  ipjson-networks      lit la sortie de « ip -j addr show » sur l'entrée
                       standard → réseaux globaux, tableau JSON
"""

import ipaddress
import json
import re
import sys

SPLIT = re.compile(r"[\s,;]+")
TOKEN = re.compile(r"^[0-9A-Fa-f:./]{1,49}$")


def tokens(text):
    return [t for t in SPLIT.split(text.strip()) if t]


def networks(text):
    out = []
    items = tokens(text)
    if not 1 <= len(items) <= 64:
        raise ValueError("count")
    for item in items:
        if not TOKEN.match(item) or "/" not in item:
            raise ValueError(item)
        net = ipaddress.ip_network(item, strict=False)
        canon = net.with_prefixlen.lower()
        if canon not in out:
            out.append(canon)
    return json.dumps(out)


def iface(text):
    if not TOKEN.match(text) or "/" not in text:
        raise ValueError(text)
    itf = ipaddress.ip_interface(text)
    if itf.ip.is_unspecified or itf.ip.is_multicast or itf.ip.is_loopback:
        raise ValueError(text)
    if itf.network.prefixlen == itf.max_prefixlen and itf.version == 4:
        raise ValueError(text)
    return itf.with_prefixlen.lower()


def iface_network(text):
    iface(text)
    return ipaddress.ip_interface(text).network.with_prefixlen.lower()


def ip(text):
    if not TOKEN.match(text) or "/" in text:
        raise ValueError(text)
    addr = ipaddress.ip_address(text)
    if addr.is_unspecified or addr.is_multicast:
        raise ValueError(text)
    return addr.compressed


def ips(text):
    items = tokens(text)
    if len(items) > 3:
        raise ValueError("count")
    return " ".join(ip(i) for i in items)


def ipjson_networks(_unused):
    data = json.load(sys.stdin)
    out = []
    for link in data:
        for addr in link.get("addr_info", []):
            if addr.get("scope") != "global":
                continue
            net = ipaddress.ip_interface(
                f"{addr['local']}/{addr['prefixlen']}").network.with_prefixlen
            if net not in out:
                out.append(net)
    if not out:
        raise ValueError("none")
    return json.dumps(out)


COMMANDS = {
    "networks": networks,
    "iface": iface,
    "iface-network": iface_network,
    "ip": ip,
    "ips": ips,
    "ipjson-networks": ipjson_networks,
}


def main(argv):
    if len(argv) not in (2, 3) or argv[1] not in COMMANDS:
        print(__doc__, file=sys.stderr)
        return 2
    try:
        print(COMMANDS[argv[1]](argv[2] if len(argv) == 3 else ""))
    except (ValueError, KeyError, TypeError):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
