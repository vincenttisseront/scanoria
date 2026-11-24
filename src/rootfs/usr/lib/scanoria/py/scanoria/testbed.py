# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Vincent Tisseront
"""Banc d'essai à l'installation (F12) et exécution confinée des scanners (§ 6.4).

Le banc d'essai d'un module est une archive testbed-<id>-<version>.tar.zst de
la release du catalogue, dont l'empreinte est dans l'index signé. Elle est
téléchargée, vérifiée, extraite sans lien ni chemin sortant, puis analysée par
le scanner dans un conteneur jetable : aucun réseau, système de fichiers en
lecture seule, sources en lecture seule sur /src, /out seul écrivable, aucune
capacité, no-new-privileges, utilisateur non root, limites mémoire, CPU et
PIDs, délai maximal. Les sorties déclarées sont validées (SARIF 2.1.0 ou
CycloneDX) puis comparées aux résultats attendus (testbed.expect).
"""

import json
import os
import re
import shutil
import stat
import tarfile
import time

from . import catalogverify, common, selfupdate
from .common import Fail

WORK = common.VARLIB + "/modules/work"
NOBODY = 65534
MAX_ARCHIVE = 64 << 20
MAX_EXTRACTED = 256 << 20
MAX_MEMBERS = 20000
MAX_OUTPUT = 64 << 20
DEFAULT_TIMEOUT = 900
# 128 + SIGKILL : délai dépassé (podman --timeout) ou limite mémoire atteinte.
KILLED_RC = 137
SCANNER_OK_RC = (0, 1)


# --------------------------------------------------------------------------
# Conteneur confiné
# --------------------------------------------------------------------------

PLACEHOLDER_RE = re.compile(r"\{opt\.([a-z][a-z0-9_]{0,40})\}")
SAFE_ARG_RE = re.compile(r"[A-Za-z0-9._,:=/@+-]*\Z")


def option_defaults(manifest):
    props = (manifest.get("options") or {}).get("properties") or {}
    return {k: p["default"] for k, p in props.items() if isinstance(p, dict) and "default" in p}


def render_command(cmd, options):
    """Remplace {opt.<nom>} dans l'argv par la valeur de l'option (G3).

    Valeur au jeu de caractères sûr ; un argument qui ne commençait pas par « - »
    ne peut pas en commencer un après substitution (aucune option injectée)."""
    vals = {}
    for k, v in (options or {}).items():
        if isinstance(v, bool):
            vals[k] = "true" if v else "false"
        elif isinstance(v, (int, float)):
            vals[k] = str(v)
        elif isinstance(v, str):
            vals[k] = v
        elif isinstance(v, list) and all(isinstance(x, str) for x in v):
            vals[k] = ",".join(v)
    out = []
    for arg in cmd:
        def sub(mm):
            k = mm.group(1)
            if k not in vals:
                raise Fail("E_INVALID_PARAM", "unknown placeholder {opt.%s}" % k)
            if not SAFE_ARG_RE.match(vals[k]):
                raise Fail("E_INVALID_PARAM", "unsafe value for option %s" % k)
            return vals[k]
        new = PLACEHOLDER_RE.sub(sub, arg)
        if new != arg and new.startswith("-") and not arg.startswith("-"):
            raise Fail("E_INVALID_PARAM", "option value cannot start with '-'")
        if not new or len(new) > 1000:
            raise Fail("E_INVALID_PARAM", "invalid rendered argument")
        out.append(new)
    return out


def memory_mb(manifest):
    """Limite mémoire du conteneur : resources.min_ram_mb du manifeste, bornée."""
    res = manifest.get("resources") or {}
    mem = res.get("min_ram_mb") if isinstance(res.get("min_ram_mb"), int) else 512
    return max(128, min(int(mem), 65536))


def confined_args(manifest, mounts=(), name=None):
    """Arguments « podman run » d'un conteneur jetable confiné (§ 6.4)."""
    res = manifest.get("resources") or {}
    mem = memory_mb(manifest)
    cpu = res.get("min_cpu") if isinstance(res.get("min_cpu"), (int, float)) else 1
    cpu = max(1, min(int(cpu), 64))
    args = ["run", "--rm", "--network=none", "--read-only", "--cap-drop=ALL",
            "--security-opt=no-new-privileges", "--user", "%d:%d" % (NOBODY, NOBODY),
            "--memory", "%dm" % mem, "--memory-swap", "%dm" % mem, "--cpus", str(cpu),
            "--pids-limit", "512", "--tmpfs", "/tmp:rw,nosuid,nodev,size=256m,mode=1777",
            "--pull=never", "--log-driver=none",
            # Utilisateur 65534 sans répertoire personnel dans la plupart des
            # images : sans HOME, certains outils (OSV-Scanner) s'arrêtent en
            # erreur générale (code 127) avant même d'analyser.
            "--env", "HOME=/tmp", "--env", "TMPDIR=/tmp"]
    if name:
        args += ["--name", name]
    for host, target, mode in mounts:
        args += ["--volume", "%s:%s:%s" % (host, target, mode)]
    return args


FEEDS = common.VARLIB + "/feeds"


def feed_mounts(manifest):
    """Chaque feed de requires.feeds, en lecture seule sur /feeds/<id>."""
    res = []
    for fid in ((manifest.get("requires") or {}).get("feeds") or []):
        if not isinstance(fid, str) or not catalogverify.MODULE_ID_RE.match(fid):
            raise Fail("E_DEPENDENCY", "invalid feed id")
        host = os.path.join(FEEDS, fid)
        os.makedirs(host, mode=0o755, exist_ok=True)
        res.append((host, "/feeds/" + fid, "ro"))
    return res


def stderr_hint(raw, limit=400):
    """Fin lisible de stderr pour un message d'erreur : une ligne, caractères
    imprimables seulement. Les bancs d'essai ne contiennent que des données
    factices, et la sortie est quand même bornée."""
    text = (raw or b"").decode("utf-8", "replace")
    text = re.sub(r"[^\x20-\x7e\u00a0-\u024f]+", " ", text)
    text = re.sub(r" {2,}", " ", text).strip()
    return text[-limit:]


def run_confined(manifest, command, mounts=(), timeout=DEFAULT_TIMEOUT, env=None, with_stderr=False, network=None):
    """Lance command dans l'image du module ; retourne le code de sortie
    (ou (code, fin de stderr) avec with_stderr).

    network : arguments qui remplacent --network=none (scanner relié à un service, svcnet)."""
    import secrets
    name = "scanoria-run-%s" % secrets.token_hex(8)
    args = confined_args(manifest, list(mounts) + feed_mounts(manifest), name=name)
    if network:
        from . import svcnet
        args = svcnet.network_args(args, network)
    # Délai appliqué par podman lui-même, et conteneur nommé retiré quoi qu'il arrive.
    args += ["--timeout", str(int(timeout))]
    for k in sorted(env or {}):
        args += ["--env", "%s=%s" % (k, env[k])]
    args += ["--entrypoint", json.dumps([command[0]]), manifest["image"]] + list(command[1:])
    try:
        r = common.run("podman", args, timeout=timeout + 60, stdout_limit=1 << 20,
                       stderr_tail=4096 if with_stderr else 0)
    finally:
        common.run("podman", ["rm", "--force", "--ignore", "--time", "0", name], timeout=120)
    if with_stderr:
        return r.returncode, stderr_hint(r.stderr)
    return r.returncode


# --------------------------------------------------------------------------
# Archive du banc d'essai
# --------------------------------------------------------------------------

def _member_path(name):
    """Chemin relatif sûr, ou None. Retire un éventuel préfixe « ./ »."""
    if not isinstance(name, str) or "\x00" in name or "\\" in name or name.startswith("/"):
        return None
    parts = [x for x in name.split("/") if x not in ("", ".")]
    if not parts or any(x == ".." for x in parts) or len(name) > 1024:
        return None
    return "/".join(parts)


def extract(archive, dest):
    """Extrait une archive tar.zst dans dest (créé vide) : fichiers et répertoires seulement."""
    tar_path = archive + ".tar"
    r = common.run("zstd", ["-q", "-d", "-f", "--no-progress", "-o", tar_path, archive], timeout=300)
    if r.returncode != 0 or not os.path.isfile(tar_path):
        raise Fail("E_ARCHIVE", "testbed archive cannot be decompressed")
    if os.path.getsize(tar_path) > MAX_EXTRACTED + (MAX_MEMBERS * 1024):
        raise Fail("E_ARCHIVE", "testbed archive too large")
    try:
        tf = tarfile.open(tar_path, "r:")
    except tarfile.TarError:
        raise Fail("E_ARCHIVE", "testbed archive is not a tar archive")
    with tf:
        members, total = [], 0
        for i, m in enumerate(tf):
            if i >= MAX_MEMBERS:
                raise Fail("E_ARCHIVE", "too many entries in the testbed archive")
            rel = _member_path(m.name)
            if rel is None:
                raise Fail("E_ARCHIVE", "unsafe path in the testbed archive")
            if not (m.isreg() or m.isdir()):
                raise Fail("E_ARCHIVE", "testbed archive may only hold files and directories")
            total += m.size
            if total > MAX_EXTRACTED:
                raise Fail("E_ARCHIVE", "testbed archive too large once extracted")
            members.append((rel, m))
        if not members:
            raise Fail("E_ARCHIVE", "empty testbed archive")
        # Préfixe unique « testbed/ » retiré s'il couvre toutes les entrées.
        if all(rel == "testbed" or rel.startswith("testbed/") for rel, _ in members):
            members = [(rel[len("testbed/"):], m) for rel, m in members if rel != "testbed"]
        # Droits du seul propriétaire : l'arbre est ensuite donné à l'utilisateur
        # du conteneur (_give_to_container), monté en lecture seule.
        os.makedirs(dest, mode=0o700, exist_ok=False)
        base = os.path.realpath(dest)
        for rel, m in members:
            # rel est relatif sans « .. » et seuls des répertoires réels sont créés
            # (aucun lien) : la cible reste sous base.
            target = os.path.join(base, rel)
            if m.isdir():
                _mkdirs(base, rel)
                continue
            _mkdirs(base, os.path.dirname(rel))
            src = tf.extractfile(m)
            fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, "wb") as out, src:
                shutil.copyfileobj(src, out, 1 << 20)
    os.unlink(tar_path)


def _mkdirs(base, rel):
    cur = base
    for part in [x for x in rel.split("/") if x]:
        cur = os.path.join(cur, part)
        try:
            st = os.lstat(cur)
        except FileNotFoundError:
            os.mkdir(cur, 0o700)
            continue
        if not stat.S_ISDIR(st.st_mode):
            raise Fail("E_ARCHIVE", "path conflict in the testbed archive")


CACHE = common.VARLIB + "/modules/testbeds"
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")


def _from_cache(digest, dest):
    """Archive déjà vérifiée (0.6, canaris G14 hors ligne) : copiée si son empreinte concorde."""
    path = os.path.join(CACHE, digest + ".tar.zst")
    try:
        st = os.lstat(path)
    except OSError:
        return False
    if not stat.S_ISREG(st.st_mode) or st.st_size > MAX_ARCHIVE:
        return False
    shutil.copyfile(path, dest)
    if selfupdate.sha256_file(dest) == digest:
        return True
    os.unlink(dest)
    return False


def _to_cache(digest, src):
    try:
        os.makedirs(CACHE, mode=0o700, exist_ok=True)
        tmp = os.path.join(CACHE, ".%s.part" % digest)
        shutil.copyfile(src, tmp)
        os.chmod(tmp, 0o600)
        os.rename(tmp, os.path.join(CACHE, digest + ".tar.zst"))
    except OSError as e:
        common.log("testbed cache not written: %s" % e)


def fetch_archive(manifest, dest):
    """Télécharge et vérifie l'archive du banc d'essai déclarée dans l'index.

    0.6 : l'archive vérifiée est gardée par empreinte, pour que les canaris
    nocturnes (G14) rejouent le banc d'essai sans Internet."""
    name, digest = manifest.get("testbed_archive"), manifest.get("testbed_sha256")
    if not isinstance(name, str) or not isinstance(digest, str):
        raise Fail("E_TESTBED", "module %s has no testbed in the catalog" % manifest["id"])
    if SHA256_RE.match(digest) and _from_cache(digest, dest):
        return
    src = catalogverify.source_info()
    if src is None:
        raise Fail("E_PRECONDITION", "catalog source unknown: refresh the catalog")
    url = catalogverify.download_url(src["repo"], catalogverify.tag_number(src["tag"]), name)
    code, _ = selfupdate.curl(url, dest, MAX_ARCHIVE, timeout=300)
    if code != 200:
        raise Fail("E_NETWORK", "cannot download the testbed (HTTP %d)" % code)
    if selfupdate.sha256_file(dest) != digest:
        raise Fail("E_CHECKSUM", "testbed checksum mismatch")
    if SHA256_RE.match(digest):
        _to_cache(digest, dest)


# --------------------------------------------------------------------------
# Sorties et résultats attendus
# --------------------------------------------------------------------------

def _out_rel(declared):
    if not isinstance(declared, str) or not declared.startswith("/out/"):
        raise Fail("E_TESTBED", "declared output must be under /out")
    rel = _member_path(declared[len("/out/"):])
    if rel is None:
        raise Fail("E_TESTBED", "invalid declared output path")
    return rel


def _open_under(base, rel):
    """Ouvre base/rel sans suivre aucun lien, à aucun niveau (le scanner écrit /out)."""
    parts = rel.split("/")
    dfd = os.open(base, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in parts[:-1]:
            nfd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=dfd)
            os.close(dfd)
            dfd = nfd
        # O_NONBLOCK : un FIFO ne bloque pas le helper ; vérifié aussitôt par fstat.
        return os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_NOCTTY, dir_fd=dfd)
    finally:
        os.close(dfd)


def _read_output(out_dir, rel):
    try:
        fd = _open_under(out_dir, rel)
    except OSError:
        raise Fail("E_TESTBED", "declared output missing")
    with os.fdopen(fd, "rb") as f:
        if not stat.S_ISREG(os.fstat(f.fileno()).st_mode):
            raise Fail("E_TESTBED", "declared output is not a regular file")
        os.set_blocking(f.fileno(), True)
        data = f.read(MAX_OUTPUT + 1)
    if len(data) > MAX_OUTPUT:
        raise Fail("E_TESTBED", "output too large")
    try:
        return common.loads_strict(data)
    except common.JsonError:
        raise Fail("E_TESTBED", "output is not valid JSON")


def sarif_results(doc, version="2.1.0"):
    """Contrôle de forme SARIF ; retourne [(ruleId, catégories)]."""
    if not isinstance(doc, dict) or doc.get("version") != version or not isinstance(doc.get("runs"), list):
        raise Fail("E_TESTBED", "output is not SARIF %s" % version)
    found = []
    for run in doc["runs"]:
        drv = run.get("tool", {}).get("driver") if isinstance(run, dict) and isinstance(run.get("tool"), dict) else None
        if not isinstance(drv, dict) or not isinstance(drv.get("name"), str):
            raise Fail("E_TESTBED", "SARIF run without tool.driver.name")
        rules = {}
        for r in drv.get("rules") or []:
            if isinstance(r, dict) and isinstance(r.get("id"), str):
                props = r.get("properties") if isinstance(r.get("properties"), dict) else {}
                tags = props.get("tags") if isinstance(props.get("tags"), list) else []
                rules[r["id"]] = {t for t in tags if isinstance(t, str)}
        results = run.get("results")
        if not isinstance(results, list):
            raise Fail("E_TESTBED", "SARIF run without results array")
        for res in results:
            if not isinstance(res, dict) or not isinstance(res.get("message"), dict):
                raise Fail("E_TESTBED", "malformed SARIF result")
            rid = res.get("ruleId") if isinstance(res.get("ruleId"), str) else None
            cats = set(rules.get(rid, set()))
            props = res.get("properties") if isinstance(res.get("properties"), dict) else {}
            if isinstance(props.get("category"), str):
                cats.add(props["category"])
            for t in props.get("tags") or []:
                if isinstance(t, str):
                    cats.add(t)
            found.append((rid, cats))
    return found


def cyclonedx_components(doc, version):
    if not isinstance(doc, dict) or doc.get("bomFormat") != "CycloneDX":
        raise Fail("E_TESTBED", "output is not CycloneDX")
    spec = doc.get("specVersion")
    if not isinstance(spec, str) or not (spec == version or spec.startswith(str(version).rstrip("x").rstrip("."))):
        raise Fail("E_TESTBED", "unexpected CycloneDX version")
    comps = doc.get("components", [])
    if not isinstance(comps, list):
        raise Fail("E_TESTBED", "malformed CycloneDX components")
    return [(c.get("name") if isinstance(c, dict) else None, set()) for c in comps]


def check_expect(found, expect):
    """Vérifie chaque attente {rule?, category?, min} ; retourne les détails."""
    details = []
    for e in expect:
        if not isinstance(e, dict) or not isinstance(e.get("min"), int) or isinstance(e.get("min"), bool):
            raise Fail("E_TESTBED", "malformed testbed expectation")
        # category n'est qu'une étiquette du rapport (convention des manifestes).
        n = sum(1 for rid, _ in found if "rule" not in e or rid == e["rule"])
        details.append({"rule": e.get("rule"), "category": e.get("category"), "min": e["min"],
                        "found": n, "ok": n >= e["min"]})
    return details


def collect(manifest, out_dir):
    outputs = manifest.get("outputs")
    if not isinstance(outputs, dict) or not outputs:
        raise Fail("E_TESTBED", "module declares no output")
    found = []
    for kind, spec in sorted(outputs.items()):
        if not isinstance(spec, dict):
            raise Fail("E_TESTBED", "malformed output declaration")
        doc = _read_output(out_dir, _out_rel(spec.get("path")))
        if kind == "sarif":
            found += sarif_results(doc, spec.get("version", "2.1.0"))
        elif kind == "cyclonedx":
            found += cyclonedx_components(doc, spec.get("version", "1.5"))
        else:
            raise Fail("E_TESTBED", "unsupported output kind %s" % kind)
    return found


# --------------------------------------------------------------------------
# Banc d'essai complet
# --------------------------------------------------------------------------

def _give_to_container(path):
    """Donne l'arbre path à l'utilisateur du conteneur (65534), droits du propriétaire seul."""
    if os.geteuid() == 0:
        for d, dirs, files in os.walk(path):
            for n in [d] + [os.path.join(d, x) for x in dirs + files]:
                os.lchown(n, NOBODY, NOBODY)
    # podman sans root (essais) : 65534 du conteneur est un sous-uid de l'appelant.
    elif common.run("podman", ["unshare", "chown", "-R", "%d:%d" % (NOBODY, NOBODY), path],
                    timeout=60).returncode != 0:
        raise Fail("E_INTERNAL", "cannot hand the work directory to the container user")


def _prepare_out(out):
    """/out appartient à l'utilisateur du conteneur, et à lui seul (0700)."""
    os.mkdir(out, 0o700)
    _give_to_container(out)


def run(manifest, timeout=None):
    """Lance le banc d'essai ; retourne {passed, at, details} ou lève Fail(E_TESTBED…)."""
    tb = manifest.get("testbed")
    if manifest.get("type") != "scanner":
        return {"passed": True, "at": common.iso(common.now()), "details": "no testbed for this module type"}
    if not isinstance(tb, dict) or not isinstance(tb.get("expect"), list) or not tb["expect"]:
        raise Fail("E_TESTBED", "scanner %s declares no testbed expectation" % manifest["id"])
    scan = manifest.get("scan") or {}
    if scan.get("network", "none") == "target":
        raise Fail("E_PRECONDITION", "networked scanners are not supported yet")
    from . import svcnet
    svc = None
    try:
        if svcnet.service_of(manifest):
            # Scanner relié à un service (contrat 12) : son service doit déjà être sain.
            from . import modules
            svc = svcnet.resolve(modules.load_registry(), manifest)
        tools = svcnet.tool_mount(manifest)
    except svcnet.Unavailable as u:
        raise Fail("E_DEPENDENCY" if u.code == svcnet.E_SERVICE_MISSING else "E_TESTBED", u.message)
    os.makedirs(WORK, mode=0o700, exist_ok=True)
    import secrets
    work = os.path.join(WORK, "testbed-%s-%s" % (manifest["id"], secrets.token_hex(6)))
    os.mkdir(work, 0o700)
    try:
        archive = os.path.join(work, "testbed.tar.zst")
        fetch_archive(manifest, archive)
        src, out = os.path.join(work, "src"), os.path.join(work, "out")
        extract(archive, src)
        _give_to_container(src)
        os.unlink(archive)
        _prepare_out(out)
        t = scan.get("timeout_s") if isinstance(scan.get("timeout_s"), int) else DEFAULT_TIMEOUT
        t = max(10, min(t, timeout or DEFAULT_TIMEOUT))
        cmd = render_command(scan["command"], option_defaults(manifest))
        mounts = [(src, "/src", "ro"), (out, "/out", "rw")] + tools
        if scan.get("requires_sbom") is True:
            # Module qui ne lit que le SBOM de l'analyse (contrat 14 de la 0.5) :
            # le banc d'essai porte son SBOM, sbom.cdx.json, à la racine.
            mounts.append((src, "/sbom", "ro"))
        started = time.monotonic()
        if svc:
            try:
                with svcnet.Attachment(svc, svcnet.TESTBED_KEY, budget_s=max(60, t - 60)) as att:
                    rc, hint = run_confined(manifest, cmd, mounts, timeout=t, env=scan.get("env"),
                                            with_stderr=True, network=att.args())
            except svcnet.Unavailable as u:
                raise Fail("E_TESTBED", u.message)
        else:
            rc, hint = run_confined(manifest, cmd, mounts, timeout=t, env=scan.get("env"), with_stderr=True)
        if rc not in (scan.get("exit_codes_ok") or SCANNER_OK_RC):
            msg = "scanner %s exited with code %d on its testbed" % (manifest["id"], rc)
            if rc == KILLED_RC and time.monotonic() - started < t:
                # Tué avant son délai : le noyau l'a arrêté à la limite mémoire du
                # conteneur. Le message le dit, avec la limite appliquée.
                msg = ("scanner %s was killed on its testbed, most likely out of memory "
                       "(container limit %d MB from resources.min_ram_mb)" % (manifest["id"], memory_mb(manifest)))
            raise Fail("E_TESTBED", msg + (": " + hint if hint else ""))
        details = check_expect(collect(manifest, out), tb["expect"])
        bad = [d for d in details if not d["ok"]]
        if bad:
            raise Fail("E_TESTBED", "testbed expectation not met: %s" % ", ".join(
                "%s≥%d (found %d)" % (d["rule"] or d["category"] or "results", d["min"], d["found"]) for d in bad),
                {"testbed": {"passed": False, "details": details}})
        return {"passed": True, "at": common.iso(common.now()), "details": details}
    finally:
        shutil.rmtree(work, ignore_errors=True)

