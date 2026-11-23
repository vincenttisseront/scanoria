# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Vincent Tisseront
"""Noms et adresses : formes canoniques uniquement."""

import ipaddress

from . import common


def check_fqdn(fqdn):
    """FQDN en minuscules, au moins deux étiquettes, sans joker (ARCHITECTURE § 4)."""
    return (isinstance(fqdn, str) and 4 <= len(fqdn) <= 253
            and common.FQDN_RE.match(fqdn) is not None and "." in fqdn)


def canonical_network(s):
    """Réseau CIDR canonique (bits d'hôte nuls, IPv6 compressée en minuscules) ou None."""
    if not isinstance(s, str) or len(s) > 49:
        return None
    try:
        n = ipaddress.ip_network(s, strict=True)
    except ValueError:
        return None
    return n if str(n) == s else None


def parse_address(s):
    """Adresse cliente ; une IPv4 encapsulée (::ffff:a.b.c.d) est ramenée en IPv4."""
    try:
        a = ipaddress.ip_address(s)
    except ValueError:
        return None
    if a.version == 6 and a.ipv4_mapped is not None:
        return a.ipv4_mapped
    if a.version == 6 and a.scope_id:
        return None
    return a


def covered(address, networks):
    return any(address.version == n.version and address in n for n in networks)
