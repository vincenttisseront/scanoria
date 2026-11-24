# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Vincent Tisseront
"""Vérification DNS de l'appliance et de ses modules (CLAUDE.md § 3.4).

Demande check-dns (helper) : résout <fqdn>, *.<fqdn> (nom de sonde aléatoire)
et <libellé>.<fqdn> pour chaque module routé, en A (et AAAA si l'appliance a une
adresse IPv6), et compare aux adresses de l'appliance. Écrit
/var/lib/scanoria/dns/status.json (schemas/dns-status.schema.json) :
  {fqdn, checked_at, records: [{name, type, expected, resolved: [], ok}]}

La résolution passe par systemd-resolved sans /etc/hosts ni synthèse locale
(resolvectl --synthesize=no --cache=no -p dns) : l'appliance se déclare dans
/etc/hosts et se résoudrait sinon toujours elle-même. Adresses de l'appliance :
adresse source de la route par défaut (« ip route get » vers une adresse de
documentation, sans émission de paquet).

Lancée toutes les heures (scanoria-dns-check.timer), après chaque changement de
nom (scanoria-dns-check.path) et après chaque changement de routage.
"""

import ipaddress
import json
import os
import re
import secrets

from . import common, routing, schema
from .common import Fail

STATUS_FILE = common.VARLIB + "/dns/status.json"
# Destinations de documentation (RFC 5737, RFC 3849) : seule la route est
# consultée, aucun paquet n'est émis.
ROUTE_PROBES = (("A", "-4", "192.0.2.1"), ("AAAA", "-6", "2001:db8::1"))
RR_RE = re.compile(r"^\S+\s+IN\s+(A|AAAA)\s+([0-9A-Fa-f.:]{2,45})(\s|$)", re.ASCII | re.MULTILINE)
MAX_RESOLVED = 16


def _usable(addr):
    return not (addr.is_loopback or addr.is_link_local or addr.is_unspecified or addr.is_multicast)


def appliance_addresses(timeout=30):
    """{"A": "192.0.2.10", "AAAA": "2001:db8::10"} : adresses de sortie de l'appliance."""
    found = {}
    for rtype, fam, dest in ROUTE_PROBES:
        r = common.run("ip", ["-j", fam, "route", "get", dest], timeout=timeout)
        if r.returncode != 0:
            continue
        try:
            routes = json.loads(r.text)
            src = routes[0].get("prefsrc") if isinstance(routes, list) and routes else None
            addr = ipaddress.ip_address(src)
        except (ValueError, TypeError, AttributeError, IndexError):
            continue
        if addr.version == (4 if rtype == "A" else 6) and _usable(addr):
            found[rtype] = str(addr)
    return found


def lookup(name, rtype, timeout=20):
    """Adresses publiées par le DNS pour name (liste triée, vide si aucune)."""
    r = common.run("resolvectl", ["query", "--legend=no", "--synthesize=no", "--cache=no",
                                  "-p", "dns", "-t", rtype, name], timeout=timeout)
    if r.returncode != 0:
        return []
    want = 4 if rtype == "A" else 6
    out = set()
    for m in RR_RE.finditer(r.text):
        if m.group(1) != rtype:
            continue
        try:
            a = ipaddress.ip_address(m.group(2))
        except ValueError:
            continue
        if a.version == want:
            out.add(str(a))
    return sorted(out)[:MAX_RESOLVED]


def names_to_check(fqdn):
    """[(nom affiché, nom résolu)] : appliance, joker, puis modules routés."""
    probe = "scanoria-probe-%s.%s" % (secrets.token_hex(6), fqdn)
    names = [(fqdn, fqdn), ("*." + fqdn, probe)]
    rec = routing.recorded()
    if rec is not None:
        labels = sorted({s.get("hostname") for s in rec["services"] if isinstance(s, dict)
                         and isinstance(s.get("hostname"), str) and routing.LABEL_RE.match(s["hostname"])})
        for label in labels:
            host = "%s.%s" % (label, fqdn)
            if len(host) <= 253:
                names.append((host, host))
    return names


def check(fqdn, timeout=20):
    """Rapport DNS (non écrit)."""
    records = []
    if fqdn is not None:
        expected = appliance_addresses()
        types = [t for t in ("A", "AAAA") if t in expected] or ["A"]
        for shown, query in names_to_check(fqdn):
            for t in types:
                resolved = lookup(query, t, timeout)
                exp = expected.get(t)
                records.append({"name": shown, "type": t, "expected": exp, "resolved": resolved,
                                "ok": exp is not None and exp in resolved})
    return {"fqdn": fqdn, "checked_at": common.iso(common.now()), "records": records}


def write_status(status):
    errs = schema.load("schemas", "dns-status").errors(status)
    if errs:
        raise Fail("E_INTERNAL", "dns status does not match its schema: %s" % errs[:3])
    os.makedirs(os.path.dirname(STATUS_FILE), mode=0o750, exist_ok=True)
    common.write_json(STATUS_FILE, status)


def act_check_dns(c):
    """Action check-dns du helper : routage resynchronisé si le nom a changé, puis DNS."""
    fqdn = routing.appliance_fqdn()
    synced, routing_error = False, None
    if fqdn is not None:
        try:
            synced = routing.resync(c.left())
        except Fail as e:  # le contrôle DNS reste utile même si nginx refuse les sites
            routing_error = e.message
    status = check(fqdn)
    write_status(status)
    if fqdn is None:
        raise Fail("E_PRECONDITION", "appliance name not set")
    bad = sorted({r["name"] for r in status["records"] if not r["ok"]})
    out = {"fqdn": fqdn, "records": len(status["records"]), "ok": not bad,
           "not_resolved": bad, "routing_resynced": synced}
    if routing_error:
        raise Fail("E_INTERNAL", "DNS checked, but module sites could not be regenerated: "
                   + routing_error, out)
    return out
