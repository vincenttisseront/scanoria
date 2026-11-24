# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Vincent Tisseront
"""Vigilance de l'appliance (0.6, chantier B), exécutée en root par le helper.

- G6, version figée par projet (contrat 24) : la console publie les versions
  figées dans /var/lib/scanoria/console/pins.json (lu sans confiance). Une mise
  à jour de module garde alors l'image de l'ancienne version et son manifeste
  vérifié (« image retenue ») ; le runner ne lance une version différente de
  la version installée que si elle est retenue ici. Une version figée ne peut
  donc désigner qu'une image déjà installée une fois par le chemin vérifié.
- F13, mise à jour d'outil à l'essai (contrat 25) : start-trial récupère
  l'image candidate de l'index signé et la retient (« trial ») ; les analyses
  d'essai la lancent comme une version figée. « abandon » la retire.
- G14, canaris nocturnes : le banc d'essai F12 de chaque scanner installé et
  actif est rejoué ; un échec est signalé, jamais une désactivation.
- F19, alertes sur l'appliance : SBOM de la console (livré dans le lot signé)
  et des images des modules installés (Syft confiné), comparés aux bases hors
  ligne par Grype et OSV-Scanner confinés ; les SARIF sont publiés pour la
  console, qui tient self_vulns.

Rien n'est installé d'office : sans Syft ou sans comparateur, le trou de
couverture est publié et la demande réussit.
"""

import os
import re
import shutil
import stat
import time

from . import catalogverify, common, testbed
from .common import Fail

RETAINED_DIR = common.VARLIB + "/modules/retained"
VIG_DIR = common.VARLIB + "/vigilance"
STATE = VIG_DIR + "/state.json"
SELF_DIR = VIG_DIR + "/self"
SELF_STATUS = SELF_DIR + "/status.json"
PINS_FILE = common.VARLIB + "/console/pins.json"
WORK = common.VARLIB + "/modules/work"
MAX_PINS_BYTES = 256 * 1024
MAX_PINS = 5000
MAX_RETAINED = 200
MAX_SBOM = 64 << 20
MAX_SARIF = 32 << 20
# Image d'essai jamais abandonnée par la console (essai oublié) : retirée au-delà.
TRIAL_MAX_AGE_S = 14 * 86400
# Canaris : attente d'un runner libre avant chaque module, bornée.
CANARY_IDLE_WAIT_S = 1800
CANARY_IDLE_POLL_S = 30
SUBJECT_RE = re.compile(r"(console|module:[a-z0-9][a-z0-9-]{1,40})\Z")
DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
KINDS = ("pin", "trial")
MATCHERS = ("grype", "osv-scanner")


def _test_env(name, default):
    return os.environ.get(name) or default if common.TEST_ROOT else default


CONSOLE_SBOM = _test_env("SCANORIA_TEST_CONSOLE_SBOM", os.path.join(common.SHARE_DIR, "sbom", "console.cdx.json"))
RUNNER_STATE = _test_env("SCANORIA_RUNNER_STATE", common.RUN + "/runner.json")


def image_digest(image):
    if not isinstance(image, str) or "@" not in image:
        return None
    d = image.split("@", 1)[1]
    return d if DIGEST_RE.match(d) else None


def _check_id(mid):
    if not isinstance(mid, str) or not catalogverify.MODULE_ID_RE.match(mid):
        raise Fail("E_INVALID_PARAM", "invalid module id")


def _check_version(ver):
    if not isinstance(ver, str) or not catalogverify.MODULE_VERSION_RE.match(ver):
        raise Fail("E_INVALID_PARAM", "invalid module version")


# --------------------------------------------------------------------------
# Images retenues (G6, F13)
# --------------------------------------------------------------------------

def _record_path(mid, ver):
    _check_id(mid)
    _check_version(ver)
    return os.path.join(RETAINED_DIR, mid, ver + ".json")


def _valid_record(rec, mid=None, ver=None):
    if not isinstance(rec, dict) or rec.get("kind") not in KINDS:
        return False
    m = rec.get("manifest")
    if not isinstance(m, dict):
        return False
    try:
        catalogverify.check_module(m)
    except Fail:
        return False
    if (mid is not None and m.get("id") != mid) or (ver is not None and m.get("version") != ver):
        return False
    if rec.get("module") != m.get("id") or rec.get("version") != m.get("version"):
        return False
    return rec.get("image_digest") == image_digest(m.get("image")) is not None


def retained_for(mid, ver):
    """Enregistrement retenu (validé) pour mid@ver, ou None."""
    try:
        path = _record_path(mid, ver)
        st = os.lstat(path)
    except (Fail, OSError):
        return None
    if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or (not common.TEST_ROOT and st.st_uid != 0):
        return None
    try:
        rec = common.load_json_file(path, 4 << 20)
    except (OSError, common.JsonError):
        return None
    return rec if _valid_record(rec, mid, ver) else None


def list_retained():
    out = []
    try:
        mids = sorted(os.listdir(RETAINED_DIR))
    except OSError:
        return out
    for mid in mids:
        if not catalogverify.MODULE_ID_RE.match(mid):
            continue
        try:
            names = sorted(os.listdir(os.path.join(RETAINED_DIR, mid)))
        except OSError:
            continue
        for n in names:
            if not n.endswith(".json"):
                continue
            rec = retained_for(mid, n[:-5]) if catalogverify.MODULE_VERSION_RE.match(n[:-5]) else None
            if rec:
                out.append(rec)
    return out[:MAX_RETAINED * 2]


def retain(manifest, kind, trial_id=None):
    """Retient l'image et le manifeste vérifié d'une version (pin ou trial)."""
    catalogverify.check_module(manifest)
    digest = image_digest(manifest.get("image"))
    if kind not in KINDS or digest is None:
        raise Fail("E_INVALID_PARAM", "cannot retain module %s without a pinned image" % manifest.get("id"))
    cur = retained_for(manifest["id"], manifest["version"])
    if cur and cur["kind"] == "pin" and kind == "trial":
        kind = "pin"   # une version figée reste figée, même essayée
    if len(list_retained()) >= MAX_RETAINED and not cur:
        raise Fail("E_DISK_SPACE", "too many retained module images")
    rec = {"module": manifest["id"], "version": manifest["version"], "image": manifest["image"],
           "image_digest": digest, "kind": kind, "trial_id": trial_id if kind == "trial" else None,
           "retained_at": common.iso(common.now()), "manifest": manifest}
    os.makedirs(RETAINED_DIR, mode=0o700, exist_ok=True)
    d = os.path.join(RETAINED_DIR, manifest["id"])
    os.makedirs(d, mode=0o700, exist_ok=True)
    common.write_json(_record_path(manifest["id"], manifest["version"]), rec, 0o600, group_scanoria=False)
    return rec


def _image_in_use(image, reg, skip=None):
    if any((e.get("manifest") or {}).get("image") == image for e in reg["modules"].values()):
        return True
    return any(r["image"] == image for r in list_retained()
               if skip is None or (r["module"], r["version"]) != skip)


def image_retained(image):
    """Consulté par modules.remove_image : une image retenue n'est jamais retirée."""
    return bool(image) and any(r["image"] == image for r in list_retained())


def release(reg, mid, ver, remove_image=True):
    """Oublie mid@ver ; retire l'image si plus rien ne l'utilise. True si retirée de la liste."""
    rec = retained_for(mid, ver)
    try:
        os.unlink(_record_path(mid, ver))
    except (OSError, Fail):
        return False
    if rec and remove_image and not _image_in_use(rec["image"], reg, skip=(mid, ver)):
        common.run("podman", ["rmi", "--ignore", rec["image"]], timeout=300)
    return True


# --------------------------------------------------------------------------
# Versions figées publiées par la console (lecture sans confiance)
# --------------------------------------------------------------------------

def read_pins():
    """{(module, version, digest)} figés par au moins un projet ; vide si illisible."""
    try:
        st = os.lstat(PINS_FILE)
    except OSError:
        return set()
    if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or st.st_size > MAX_PINS_BYTES:
        common.log("pins file ignored: not a regular file or too large")
        return set()
    if not common.TEST_ROOT and st.st_uid != common.scanoria_ids()[0]:
        common.log("pins file ignored: bad owner")
        return set()
    try:
        fd = os.open(PINS_FILE, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, "rb") as f:
            data = f.read(MAX_PINS_BYTES + 1)
        doc = common.loads_strict(data)
    except (OSError, common.JsonError):
        common.log("pins file ignored: unreadable")
        return set()
    if not isinstance(doc, dict) or doc.get("version") != 1 or not isinstance(doc.get("pins"), list):
        return set()
    out = set()
    for p in doc["pins"][:MAX_PINS]:
        if not isinstance(p, dict):
            continue
        mid, ver, dig = p.get("module"), p.get("version"), p.get("image_digest")
        if isinstance(mid, str) and catalogverify.MODULE_ID_RE.match(mid) and isinstance(ver, str) \
                and catalogverify.MODULE_VERSION_RE.match(ver) and isinstance(dig, str) and DIGEST_RE.match(dig):
            out.add((mid, ver, dig))
    return out


def keep_pinned(old_manifest):
    """Mise à jour d'un module : l'ancienne version figée par un projet est retenue.

    Retourne True si l'image doit être gardée."""
    key = (old_manifest.get("id"), old_manifest.get("version"), image_digest(old_manifest.get("image")))
    if key[2] is None or key not in read_pins():
        return False
    try:
        retain(old_manifest, "pin")
    except Fail as f:
        common.log("pinned version %s %s not retained: %s" % (key[0], key[1], f.message))
        return False
    publish_state()
    return True


def gc_retained(reg, now=None):
    """Versions plus figées par aucun projet, essais trop anciens : retirées."""
    pins = read_pins()
    now = now or common.now()
    released = []
    for r in list_retained():
        key = (r["module"], r["version"], r["image_digest"])
        if r["kind"] == "pin" and key in pins:
            continue
        if r["kind"] == "trial":
            try:
                age = (now - common.parse_iso(r.get("retained_at"))).total_seconds()
            except (TypeError, ValueError):
                age = TRIAL_MAX_AGE_S + 1
            if age <= TRIAL_MAX_AGE_S:
                continue
        installed = (reg["modules"].get(r["module"]) or {}).get("manifest") or {}
        # La version installée n'a plus besoin d'un enregistrement (adoption d'un essai).
        if release(reg, r["module"], r["version"], remove_image=installed.get("image") != r["image"]):
            released.append("%s@%s" % (r["module"], r["version"]))
    if released:
        publish_state()
    return released


# --------------------------------------------------------------------------
# Résolution par le runner (contrats 24 et 25)
# --------------------------------------------------------------------------

def alternate(entry, item):
    """Version demandée par une tâche du runner.

    None : la version installée ; dict : manifeste retenu (version figée ou
    candidate) ; False : version demandée absente de la machine (module
    « missing », classe infra, G12)."""
    m = entry.get("manifest") if isinstance(entry, dict) else None
    if not isinstance(m, dict):
        return None
    want = item.get("image_digest")
    if item.get("version") == m.get("version") and (want is None or want == image_digest(m.get("image"))):
        return None
    rec = retained_for(item.get("id"), item.get("version"))
    if rec is None or (want is not None and rec["image_digest"] != want):
        return False
    return rec["manifest"]


def is_trial(job):
    """Tâche d'une analyse d'essai (contrat 25) : ni cache V4, ni SBOM partagé gardé."""
    return job.get("trial") is True


# --------------------------------------------------------------------------
# État publié pour la console
# --------------------------------------------------------------------------

def _self_status():
    try:
        st = common.load_json_file(SELF_STATUS, 1 << 20)
        return st if isinstance(st, dict) else None
    except (OSError, common.JsonError):
        return None


def publish_state():
    retained = [{"module": r["module"], "version": r["version"], "image_digest": r["image_digest"],
                 "kind": r["kind"], "trial_id": r.get("trial_id"), "retained_at": r.get("retained_at")}
                for r in list_retained()]
    st = {"version": 1, "updated_at": common.iso(common.now()), "retained": retained,
          "self_sbom": _self_status()}
    common.shared_dir(VIG_DIR)
    common.write_json(STATE, st, 0o640)
    return st


# --------------------------------------------------------------------------
# start-trial (F13)
# --------------------------------------------------------------------------

def _scanner_entry(reg, mid):
    e = reg["modules"].get(mid)
    m = (e or {}).get("manifest") or {}
    if not e:
        raise Fail("E_NOT_FOUND", "module %s is not installed" % mid)
    if m.get("type") != "scanner" or "system" in (m.get("categories") or []):
        raise Fail("E_TRIAL_INVALID", "only scanners can be tried")
    return e, m


def act_start_trial(c):
    from . import modules
    p = c.params
    mid, ver, action = p["module"], p["version"], p.get("action", "start")
    _check_id(mid)
    _check_version(ver)
    reg = modules.load_registry()
    if action == "abandon":
        rec = retained_for(mid, ver)
        released = False
        if rec and rec["kind"] == "trial" and (p.get("trial_id") in (None, rec.get("trial_id"))):
            installed = (reg["modules"].get(mid) or {}).get("manifest") or {}
            released = release(reg, mid, ver, remove_image=installed.get("image") != rec["image"])
        publish_state()
        return {"module": mid, "version": ver, "action": "abandon", "released": released}
    e, old = _scanner_entry(reg, mid)
    if e.get("status") != "healthy" or e.get("enabled") is not True:
        raise Fail("E_PRECONDITION", "module %s is %s" % (mid, e.get("status")))
    new = modules.lookup(modules.catalog(), mid, ver)
    catalogverify.check_module(new)
    if new.get("type") != "scanner" or "system" in (new.get("categories") or []):
        raise Fail("E_TRIAL_INVALID", "candidate %s %s is not a scanner" % (mid, ver))
    if modules.vkey(new["version"]) <= modules.vkey(old["version"]):
        raise Fail("E_VERSION", "%s %s is not newer than the installed %s" % (mid, ver, old["version"]))
    digest = image_digest(new.get("image"))
    if digest is None:
        raise Fail("E_TRIAL_IMAGE", "candidate %s %s has no pinned image" % (mid, ver))
    r = new["license"]["restrictions"]
    if r != "none" and r != e.get("accepted"):
        raise Fail("E_LICENSE", "the license restrictions of %s changed: they must be accepted first" % mid)
    for d in modules.requires_of(new):
        if d not in reg["modules"]:
            raise Fail("E_DEPENDENCY", "%s %s requires %s" % (mid, ver, d), {"requires": [d]})
    common.set_step("pull")
    try:
        modules.pull(new, c.left())
    except Fail:
        raise Fail("E_TRIAL_IMAGE", "cannot pull the candidate image of %s %s" % (mid, ver))
    try:
        common.set_step("health")
        modules.scanner_health(new, min(c.left(), modules.SCANNER_HEALTH_TIMEOUT))
        rec = retain(new, "trial", p.get("trial_id"))
    except Exception:
        if not _image_in_use(new["image"], reg):
            common.run("podman", ["rmi", "--ignore", new["image"]], timeout=300)
        raise
    publish_state()
    return {"module": mid, "version": ver, "action": "start", "image_digest": rec["image_digest"],
            "from_version": old["version"], "trial_id": p.get("trial_id")}


# --------------------------------------------------------------------------
# run-canaries (G14)
# --------------------------------------------------------------------------

def _runner_busy():
    try:
        st = common.load_json_file(RUNNER_STATE, 4096)
        return isinstance(st, dict) and isinstance(st.get("busy"), int) and st["busy"] > 0
    except (OSError, common.JsonError):
        return False


def wait_idle(c):
    """Attend un runner sans analyse en cours, dans la limite du délai de la demande."""
    waited = 0
    while _runner_busy() and waited < CANARY_IDLE_WAIT_S and c.left() > CANARY_IDLE_POLL_S * 4:
        time.sleep(CANARY_IDLE_POLL_S)
        waited += CANARY_IDLE_POLL_S
    return waited


def canary_modules(reg, ids=None):
    out = []
    for mid in sorted(reg["modules"]):
        e = reg["modules"][mid]
        m = e.get("manifest") or {}
        if ids and mid not in ids:
            continue
        if m.get("type") != "scanner" or "system" in (m.get("categories") or []):
            continue
        if e.get("status") != "healthy" or e.get("enabled") is not True:
            continue
        out.append((mid, m))
    return out


def run_canary(m, timeout):
    t0 = time.monotonic()
    res = {"module": m["id"], "version": m["version"], "image_digest": image_digest(m.get("image")),
           "ok": False, "details": {"expect": []}, "duration_ms": 0, "run_at": common.iso(common.now())}
    try:
        tb = testbed.run(m, timeout=timeout)
        res["ok"] = tb.get("passed") is True
        res["details"] = {"expect": tb.get("details") if isinstance(tb.get("details"), list) else []}
    except Fail as f:
        details = ((f.output or {}).get("testbed") or {}).get("details")
        res["details"] = {"expect": details if isinstance(details, list) else [],
                          "error": {"code": f.code, "message": f.message[:500]}}
    except Exception as exc:  # noqa: BLE001 — un module n'arrête pas les autres
        common.log("canary of %s failed: %r" % (m["id"], exc))
        res["details"] = {"expect": [], "error": {"code": "E_INTERNAL", "message": "internal error"}}
    res["duration_ms"] = int((time.monotonic() - t0) * 1000)
    return res


def act_run_canaries(c):
    from . import modules
    reg = modules.load_registry()
    ids = c.params.get("ids")
    if ids:
        for i in ids:
            _check_id(i)
        unknown = [i for i in ids if i not in reg["modules"]]
        if unknown:
            raise Fail("E_NOT_FOUND", "not an installed module: %s" % ", ".join(unknown))
    todo = canary_modules(reg, ids)
    results = []
    for mid, m in todo:
        if c.left() < 60:
            results.append({"module": mid, "version": m["version"], "image_digest": image_digest(m.get("image")),
                            "ok": False, "details": {"expect": [], "error": {"code": "E_TIMEOUT",
                                                                             "message": "no time left for this canary"}},
                            "duration_ms": 0, "run_at": common.iso(common.now())})
            continue
        common.set_step("wait")
        wait_idle(c)
        common.set_step("run")
        results.append(run_canary(m, min(c.left() - 30, testbed.DEFAULT_TIMEOUT)))
    try:
        gc_retained(reg)
    except Fail as f:
        common.log("retained images cleanup: %s" % f.message)
    out = {"canaries": results, "at": common.iso(common.now())}
    failed = [r["module"] for r in results if not r["ok"]]
    if failed:
        raise Fail("E_CANARY_FAILED", "canary failed for: %s" % ", ".join(failed), out)
    return out


# --------------------------------------------------------------------------
# self-sbom (F19)
# --------------------------------------------------------------------------

def _usable(reg, mid):
    e = reg["modules"].get(mid)
    m = (e or {}).get("manifest") or {}
    if not e or e.get("status") != "healthy" or e.get("enabled") is not True or m.get("type") != "scanner":
        return None
    try:
        catalogverify.check_module(m)
    except Fail:
        return None
    return m


def _subject_dir(subject):
    return os.path.join(SELF_DIR, subject.replace(":", "-"))


def _copy_bounded(src, dest, limit):
    st = os.lstat(src)
    if not stat.S_ISREG(st.st_mode) or st.st_size > limit:
        raise Fail("E_SELFSBOM_OUTPUT", "output missing or too large")
    with open(src, "rb") as f:
        data = f.read(limit + 1)
    try:
        common.loads_strict(data)   # JSON valide, sinon refusé
    except common.JsonError:
        raise Fail("E_SELFSBOM_OUTPUT", "output is not valid JSON")
    common.atomic_write(dest, data, 0o640)
    return data


def _sbom_of_image(syft, image, work, timeout):
    """SBOM CycloneDX d'une image installée : système de fichiers de l'image monté
    en lecture seule (podman image mount), lu par Syft confiné, sans réseau."""
    r = common.run("podman", ["image", "mount", image], timeout=120)
    path = r.text.strip().splitlines()[-1] if r.returncode == 0 and r.text.strip() else ""
    if not path.startswith("/"):
        raise Fail("E_SELFSBOM_IMAGE", "cannot mount the image")
    out = os.path.join(work, "out")
    os.mkdir(out, 0o700)
    testbed._give_to_container(out)
    try:
        cmd = [(syft.get("scan") or {}).get("command", ["/syft"])[0], "scan", "dir:/src", "--quiet",
               "--override-default-catalogers", "image", "--source-name", "image",
               "--output", "cyclonedx-json@1.6=/out/sbom.cdx.json"]
        rc = testbed.run_confined(syft, cmd, [(path, "/src", "ro"), (out, "/out", "rw")], timeout=timeout,
                                  env=(syft.get("scan") or {}).get("env"))
    finally:
        common.run("podman", ["image", "unmount", image], timeout=120)
    if rc != 0:
        raise Fail("E_SELFSBOM_IMAGE", "syft exited with code %d" % rc)
    return os.path.join(out, "sbom.cdx.json")


def _match(matcher, sbom_path, work, timeout):
    """SARIF du comparateur (sbom_command du manifeste) sur un SBOM."""
    scan = matcher.get("scan") or {}
    cmd = scan.get("sbom_command")
    if not isinstance(cmd, list):
        raise Fail("E_SELFSBOM_OUTPUT", "%s cannot read an SBOM" % matcher["id"])
    from . import feeds
    feeds.require_ready(matcher)
    src = os.path.join(work, "src-" + matcher["id"])
    out = os.path.join(work, "out-" + matcher["id"])
    os.mkdir(src, 0o700)
    os.mkdir(out, 0o700)
    shutil.copyfile(sbom_path, os.path.join(src, "sbom.cdx.json"))
    testbed._give_to_container(src)
    testbed._give_to_container(out)
    rc = testbed.run_confined(matcher, testbed.render_command(cmd, testbed.option_defaults(matcher)),
                              [(src, "/src", "ro"), (out, "/out", "rw")], timeout=timeout, env=scan.get("env"))
    if rc not in (scan.get("exit_codes_ok") or testbed.SCANNER_OK_RC):
        raise Fail("E_SELFSBOM_OUTPUT", "%s exited with code %d" % (matcher["id"], rc))
    decl = (matcher.get("outputs") or {}).get("sarif") or {}
    rel = testbed._out_rel(decl.get("path"))
    return os.path.join(out, rel)


def _components(data):
    try:
        doc = common.loads_strict(data)
        comps = doc.get("components") if isinstance(doc, dict) else None
        return len(comps) if isinstance(comps, list) else 0
    except common.JsonError:
        return 0


def act_self_sbom(c):
    from . import modules
    import hashlib
    reg = modules.load_registry()
    try:
        gc_retained(reg)
    except Fail as f:
        common.log("retained images cleanup: %s" % f.message)
    syft = _usable(reg, "syft")
    matchers = [m for m in (_usable(reg, x) for x in MATCHERS) if m]
    gaps = []
    if not syft:
        gaps.append("syft-missing")
    if not matchers:
        gaps.append("matcher-missing")
    common.shared_dir(VIG_DIR)
    common.shared_dir(SELF_DIR)
    os.makedirs(WORK, mode=0o700, exist_ok=True)
    import secrets
    work = os.path.join(WORK, "self-sbom-" + secrets.token_hex(6))
    os.mkdir(work, 0o700)
    subjects = []
    try:
        todo = []
        if os.path.isfile(CONSOLE_SBOM):
            todo.append(("console", None, None))
        else:
            gaps.append("console-sbom-missing")
        if syft:
            seen = set()
            for mid in sorted(reg["modules"]):
                m = reg["modules"][mid].get("manifest") or {}
                img = m.get("image")
                if not img or image_digest(img) is None or img in seen:
                    continue
                seen.add(img)
                todo.append(("module:" + mid, m, img))
        for subject, m, img in todo:
            if c.left() < 120:
                gaps.append("timeout")
                break
            common.set_step("sbom")
            sd = _subject_dir(subject)
            common.shared_dir(sd)
            entry = {"subject": subject, "version": m["version"] if m else common.installed_version(),
                     "image_digest": image_digest(img), "components": 0, "sbom_sha256": None,
                     "tools": [], "error": None}
            sub = os.path.join(work, subject.replace(":", "-"))
            os.mkdir(sub, 0o700)
            try:
                src = CONSOLE_SBOM if m is None else _sbom_of_image(syft, img, sub, min(900, c.left() - 60))
                data = _copy_bounded(src, os.path.join(sd, "sbom.cdx.json"), MAX_SBOM)
                entry["sbom_sha256"] = hashlib.sha256(data).hexdigest()
                entry["components"] = _components(data)
            except Fail as f:
                entry["error"] = {"code": f.code, "message": f.message[:300]}
                subjects.append(entry)
                continue
            for mt in matchers:
                common.set_step("match")
                tool = {"id": mt["id"], "version": mt["version"], "ok": False, "output": None, "error": None}
                try:
                    sarif = _match(mt, os.path.join(sd, "sbom.cdx.json"), sub, min(900, max(60, c.left() - 60)))
                    rel = "%s/%s.sarif" % (os.path.basename(sd), mt["id"])
                    _copy_bounded(sarif, os.path.join(SELF_DIR, rel), MAX_SARIF)
                    tool.update(ok=True, output=rel)
                except Fail as f:
                    tool["error"] = {"code": f.code, "message": f.message[:300]}
                entry["tools"].append(tool)
            subjects.append(entry)
    finally:
        shutil.rmtree(work, ignore_errors=True)
    status = {"version": 1, "at": common.iso(common.now()), "subjects": subjects, "gaps": gaps}
    common.write_json(SELF_STATUS, status, 0o640)
    publish_state()
    return status
