# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Vincent Tisseront
"""scanoria-state : publie /run/scanoria/state.json (ARCHITECTURE § 5.7).

  scanoria-state [--stdout]

Écrit atomiquement (0640 root:scanoria) un état conforme à
schemas/state.schema.json ; --stdout l'affiche aussi.
"""

import os
import sys

from . import common, schema

SERVICES = (
    "postgresql.service", "nginx.service", "scanoria-console.service", "scanoria-helper.path",
    "scanoria-firewall.service", "scanoria-state.timer", "scanoria-update-check.timer",
    "scanoria-update-apply.timer", "scanoria-cert-renew.timer", "scanoria-catalog-refresh.timer",
)
SERVICE_STATES = ("active", "inactive", "failed", "activating", "deactivating", "unknown")


def _json(path, default=None):
    try:
        return common.load_json_file(path, 1 << 20)
    except (OSError, common.JsonError):
        return default


def memory_mb():
    try:
        with open("/proc/meminfo", encoding="ascii") as f:
            for ln in f:
                if ln.startswith("MemTotal:"):
                    return int(ln.split()[1]) // 1024
    except (OSError, ValueError):
        pass
    return 0


def appliance():
    fqdn = (_json(common.ETC + "/appliance.json") or {}).get("fqdn")
    from .netutil import check_fqdn
    return {
        "fqdn": fqdn if check_fqdn(fqdn) else None,
        "version": common.installed_version() or "0.0.0",
        "previous_version": common.installed_version("previous"),
        "firstboot_done": os.path.exists(common.VARLIB + "/firstboot.done"),
        "cpu_count": os.cpu_count() or 0,
        "memory_mb": memory_mb(),
    }


def helper():
    cur = _json(common.CURRENT_FILE)
    v = schema.load("schemas", "state").schema["properties"]["helper"]["properties"]["current"]
    if cur is not None and not schema.Validator(v).valid(cur):
        cur = None
    try:
        queue = len(os.listdir(common.REQ + "/incoming"))
    except OSError:
        queue = 0
    return {"busy": cur is not None, "current": cur, "queue_length": queue}


def update():
    pol = _json(common.ETC + "/update.json") or {}
    chk = _json(common.UPDATE_CHECK_FILE) or {}
    alert = _json(common.UPDATE_ALERT_FILE)
    skip = _json(common.UPDATE_SKIP_FILE) or {}
    skipped = skip.get("version") if isinstance(skip, dict) else None
    out = {
        "channel": pol.get("channel") if pol.get("channel") in ("stable", "prerelease") else "stable",
        "auto_check": pol.get("auto_check") is True,
        "auto_apply": pol.get("auto_apply") is True,
        "maintenance_window": pol.get("maintenance_window") if isinstance(pol.get("maintenance_window"), dict) else None,
        "last_check_at": chk.get("checked_at"),
        "last_check_code": chk.get("code"),
        "latest_version": chk.get("latest_version"),
        "skipped_version": skipped if isinstance(skipped, str) and common.SEMVER_RE.match(skipped) else None,
        "available": False,
        "notes_md": chk.get("notes_md"),
        "published_at": chk.get("published_at"),
        "source_url": chk.get("source_url"),
        "alert": alert if isinstance(alert, dict) else None,
    }
    try:
        out["available"] = common.parse_version(out["latest_version"]) > common.parse_version(
            common.installed_version())
    except ValueError:
        out["available"] = False
    return out


def tls():
    empty = {"mode": "none", "subject_alt_names": [], "not_before": None, "not_after": None,
             "fingerprint_sha256": None, "ca_fingerprint_sha256": None, "ca_not_after": None}
    try:
        out, _ = common.run_protocol("scanoria-ca", ["status"], timeout=30)
    except common.Fail:
        return empty
    res = {k: out.get(k, empty[k]) for k in empty}
    if res["mode"] not in ("internal", "imported"):
        res["mode"] = "none"
    return res


def firewall():
    try:
        out, _ = common.run_protocol("scanoria-firewall", ["status"], timeout=30)
        return {"loaded": out.get("loaded") is True, "admin_networks": list(out.get("admin_networks") or [])}
    except common.Fail:
        return {"loaded": False, "admin_networks": []}


def services():
    r = common.run("systemctl", ["is-active"] + list(SERVICES), timeout=30)
    states = r.text.splitlines()
    res = {}
    for i, name in enumerate(SERVICES):
        s = states[i].strip() if i < len(states) else "unknown"
        if s == "reloading":
            s = "active"
        res[name] = s if s in SERVICE_STATES else "unknown"
    return res


def disks():
    res, seen = [], set()
    for mount in ("/", "/var"):
        try:
            st = os.stat(mount)
            if st.st_dev in seen:
                continue
            seen.add(st.st_dev)
            v = os.statvfs(mount)
        except OSError:
            continue
        res.append({"mount": mount, "size_mb": v.f_blocks * v.f_frsize // (1 << 20),
                    "avail_mb": v.f_bavail * v.f_frsize // (1 << 20)})
    return res


def selftest():
    rep = _json(common.SELFTEST_LAST)
    if isinstance(rep, dict) and rep.get("status") in ("pass", "warn", "fail") \
            and isinstance(rep.get("finished_at"), str):
        return {"status": rep["status"], "finished_at": rep["finished_at"]}
    return None


def modules_usage():
    """Relevés des modules permanents (contrat 11 de la 0.4), recopiés par la console."""
    try:
        from . import modules, services
        return services.usage(modules.load_registry())
    except Exception as e:  # noqa: BLE001 — l'état est publié même sans relevé
        common.log("modules usage unavailable: %r" % e)
        return []


def appliance_key():
    from . import offline
    return offline.appliance_key_info()


def build():
    return {
        "version": 1,
        "generated_at": common.iso(common.now()),
        "appliance": appliance(),
        "helper": helper(),
        "update": update(),
        "tls": tls(),
        "firewall": firewall(),
        "services": services(),
        "disks": disks(),
        "selftest": selftest(),
        "modules_usage": modules_usage(),
        "appliance_key": appliance_key(),
    }


def main(argv):
    if argv not in ([], ["--stdout"]):
        sys.stderr.write("usage: scanoria-state [--stdout]\n")
        return 2
    if not common.TEST_ROOT and os.geteuid() != 0:
        sys.stderr.write("scanoria-state: root required\n")
        return 2
    state = build()
    errs = schema.load("schemas", "state").errors(state)
    if errs:
        common.log("state does not match its schema: %s" % "; ".join(errs[:5]))
        return 1
    os.makedirs(common.RUN, mode=0o750, exist_ok=True)
    common.write_json(common.STATE_FILE, state, 0o640)
    if argv == ["--stdout"]:
        sys.stdout.write(common.dumps(state))
    return 0
