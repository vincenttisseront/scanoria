# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Vincent Tisseront
"""prefetch-images : images des modules présentes et vérifiées avant toute analyse (V1).

Une analyse ne tire jamais d'image (« podman run --pull=never ») : une image
absente rend le module en erreur infra (E_IMAGE_MISSING, G12), et le worker
dépose alors cette demande avant la relance. Le helper la traite aussi chaque
jour (scanoria-prefetch-images.timer).

Pour chaque module installé, et pour chaque version figée par un projet (G6,
params.pins), l'image doit être présente sous son empreinte (référence
@sha256:, celle du manifeste installé) ; sinon elle est récupérée depuis le
registre. Une version figée n'est acceptée que si elle figure, avec la même
empreinte, dans l'index du catalogue installé (signé) : la demande ne peut
jamais faire récupérer une image inconnue du catalogue. Les images des lots
hors ligne sont chargées par import-bundle.
"""

from . import catalogverify, common, modules
from .common import Fail

MAX_PINS = 500
PULL_TIMEOUT = 900


def _catalog_images():
    """{(module, version): image} de l'index du catalogue installé."""
    out = {}
    for m in (catalogverify.installed_index() or {}).get("modules") or []:
        if isinstance(m, dict) and isinstance(m.get("image"), str) and catalogverify.IMAGE_RE.match(m["image"]):
            out[(m.get("id"), m.get("version"))] = m["image"]
    return out


def wanted(reg, pins):
    """[(image, module, origine)] sans doublon, et [refus] des versions figées inconnues."""
    seen, out, refused = set(), [], []
    for mid in sorted(reg["modules"]):
        m = (reg["modules"][mid] or {}).get("manifest") or {}
        img = m.get("image")
        if isinstance(img, str) and catalogverify.IMAGE_RE.match(img) and img not in seen:
            seen.add(img)
            out.append((img, mid, "installed"))
    catalog = _catalog_images() if pins else {}
    for p in pins[:MAX_PINS]:
        img = catalog.get((p["module_id"], p["version"]))
        if not img or not img.endswith("@" + p["image_digest"]):
            refused.append({"module": p["module_id"], "version": p["version"],
                            "code": "E_PREFETCH_UNKNOWN_IMAGE"})
            continue
        if img not in seen:
            seen.add(img)
            out.append((img, p["module_id"], "pin"))
    return out, refused


def act_prefetch_images(c):
    reg = modules.load_registry()
    todo, refused = wanted(reg, c.params.get("pins") or [])
    present, pulled, failed = 0, [], list(refused)
    for img, mid, origin in todo:
        if modules.podman("image", "exists", img, timeout=60) == 0:
            present += 1
            continue
        if c.left() < 30:
            failed.append({"module": mid, "code": "E_TIMEOUT"})
            continue
        if modules.podman("pull", "--quiet", img, timeout=min(PULL_TIMEOUT, c.left())) == 0:
            pulled.append({"module": mid, "origin": origin})
            common.log("prefetch-images: image of %s pulled" % mid)
        else:
            failed.append({"module": mid, "code": "E_PREFETCH_FAILED"})
            common.log("prefetch-images: cannot pull the image of %s" % mid)
    out = {"checked": len(todo), "present": present, "pulled": pulled, "failed": failed}
    errors = [f for f in failed if f["code"] != "E_PREFETCH_UNKNOWN_IMAGE"]
    if errors:
        raise Fail("E_PREFETCH_FAILED", "%d image(s) cannot be fetched: %s" % (
            len(errors), ", ".join(sorted({f["module"] for f in errors}))[:1500]), out)
    if refused:
        raise Fail("E_PREFETCH_UNKNOWN_IMAGE", "pinned version(s) unknown to the signed catalog: %s" % (
            ", ".join(sorted({f["module"] for f in refused}))[:1500]), out)
    return out
