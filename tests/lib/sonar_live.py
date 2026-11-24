# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Vincent Tisseront
"""Pilote Python de tests/b17-live.sh (SonarQube réel, podman réel, root).

  sonar_live.py provision SONARQUBE.json PORT PHASE   → JSON de provision.run
  sonar_live.py reset SONARQUBE.json PORT REQUEST_ID  → JSON de act_reset_service_admin
  sonar_live.py scan SONARQUBE.json SCANNER.json SRC OUT TIMEOUT NAME
      → lance le scanner relié au service exactement comme le runner :
        svcnet.resolve (jeton root 0600), svcnet.Attachment (secret Podman),
        svcnet.network_args (réseau interne du service), svcnet.tool_mount ;
        affiche le code de sortie.
SCANORIA_TEST_ROOT et SCANORIA_TEST_BIN (podman réel) sont fixés par l'appelant.
"""

import json
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "src/rootfs/usr/lib/scanoria/py"))
sys.path.insert(0, os.path.join(ROOT, "tests/lib"))

from scanoria import common, modules, provision, svcnet  # noqa: E402
import modcheck  # noqa: E402


def load(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def registry(sq, port):
    return {"modules": {"sonarqube": {"manifest": sq, "status": "healthy", "enabled": True, "host_port": port}}}


class Ctx:
    def __init__(self, rid, mid):
        self.req = {"id": rid}
        self.params = {"id": mid}

    def left(self):
        return 300


def main(argv):
    cmd = argv[0]
    sq = load(argv[1])
    if cmd == "provision":
        out = provision.run(sq, {"host_port": int(argv[2]), "phase": argv[3], "timeout": 900})
        print(json.dumps(out))
        return 0
    if cmd == "reset":
        modules.load_registry = lambda: registry(sq, int(argv[2]))
        print(json.dumps(provision.act_reset_service_admin(Ctx(argv[3], "sonarqube"))))
        return 0
    if cmd == "scan":
        sc, src, out, timeout, name = load(argv[2]), argv[3], argv[4], int(argv[5]), argv[6]
        svc = svcnet.resolve(registry(sq, 0), sc)
        # Branche analysée (plugin de branches) : transmise comme par le runner.
        if len(argv) > 7:
            svc["branch"] = argv[7]
        args = modcheck.podman_args(sc, src, out, "/nonexistent", tool=False)
        args[args.index("--network=slirp4netns")] = "--network=none"
        args.insert(1, "--name=" + name)
        mounts = svcnet.tool_mount(sc)
        img = args.index(sc["image"])
        args[img:img] = ["--volume=%s:%s:%s" % m for m in mounts]
        with svcnet.Attachment(svc, svcnet.TESTBED_KEY, max(60, timeout - 60)) as att:
            args = svcnet.network_args(args, att.args())
            print("podman " + " ".join(args), file=sys.stderr)
            try:
                rc = subprocess.run(["podman"] + args, timeout=timeout, check=False).returncode
            except subprocess.TimeoutExpired:
                rc = 124
            subprocess.run(["podman", "rm", "-f", name], capture_output=True, check=False)
        print(rc)
        return 0
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except (common.Fail, svcnet.Unavailable) as e:
        print("%s: %s" % (getattr(e, "code", "?"), e), file=sys.stderr)
        sys.exit(1)
