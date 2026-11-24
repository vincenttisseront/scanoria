#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Vincent Tisseront
#
# b19 — SBOM de la 0.5 (chantier A), sans root ni conteneur :
#   1. manifestes syft, grype, grype-db, dependency-track et dtrack-upload
#      (schéma, images épinglées, réseau, chaînage du SBOM) ;
#   2. base grype-db téléchargée par le helper (feeds.py) face à un faux
#      serveur HTTPS : empreinte, même hôte, préparation confinée simulée,
#      disposition <base>/6/{vulnerability.db, import.json}, refus ;
#   3. mise en service de Dependency-Track (dtrack.py) face à un faux serveur :
#      mot de passe admin remplacé, équipe et droits minimaux, clé d'API,
#      reprise, mot de passe changé à la main, réinitialisation ;
#   4. outil d'envoi dtrack_upload.py : envoi, traitement, relecture, codes
#      de sortie, clé jamais affichée ;
#   5. runner (mode test, podman simulé) : producteurs d'abord, SBOM monté en
#      lecture seule, sbom_command, dtrack-upload facultatif, ordre du résultat.
# Dépendances : bash, python3 (PyYAML), jq, curl, openssl.

# shellcheck disable=SC2016,SC2015
set -euo pipefail
export PYTHONDONTWRITEBYTECODE=1

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
PYLIB="$ROOT/src/rootfs/usr/lib/scanoria/py"
RUNNER="$ROOT/src/rootfs/usr/sbin/scanoria-runner"
TOOL="$ROOT/src/rootfs/usr/lib/scanoria/scan-tools/dtrack"
MC="$ROOT/tests/lib/modcheck.py"
TMP=$(mktemp -d)
PIDS=()
cleanup() {
	for p in "${PIDS[@]}"; do kill "$p" 2> /dev/null || true; done
	chmod -R u+rwX "$TMP" 2> /dev/null || true
	rm -rf "$TMP"
}
trap cleanup EXIT
for t in python3 jq curl openssl; do command -v "$t" > /dev/null || { echo "outil manquant : $t" >&2; exit 2; }; done
python3 -c 'import yaml' 2> /dev/null || { echo "python3-yaml requis" >&2; exit 2; }

PASS=0
FAIL=0
ok() { PASS=$((PASS + 1)); printf 'ok   %s\n' "$1"; }
ko() { FAIL=$((FAIL + 1)); printf 'FAIL %s\n' "$1"; }
expect() { if [[ "$2" == "$3" ]]; then ok "$1"; else ko "$1 (obtenu « $2 », attendu « $3 »)"; fi; }
check() { local l=$1; shift; if "$@" > "$TMP/last.log" 2>&1; then ok "$l"; else ko "$l"; sed 's/^/     /' "$TMP/last.log" | head -n 10; fi; }
yq() { python3 -c 'import json, sys, yaml; print(json.dumps(yaml.safe_load(open(sys.argv[1], encoding="utf-8"))))' "$1"; }
export PYLIB

# --- 1. Manifestes ------------------------------------------------------------------------
for id in syft grype grype-db dependency-track dtrack-upload; do
	check "$id : manifeste conforme" python3 "$MC" manifest "$ROOT/modules/$id/module.yaml"
	yq "$ROOT/modules/$id/module.yaml" > "$TMP/$id.json"
	jq -e '(.image // .feed.hydrate.image) | test("@sha256:[0-9a-f]{64}$")' "$TMP/$id.json" > /dev/null && ok "$id : image épinglée par empreinte" || ko "$id : image non épinglée"
	jq -e '.license.verified_at | test("^2026-")' "$TMP/$id.json" > /dev/null && ok "$id : licence vérifiée en amont" || ko "$id : licence non vérifiée"
	jq -e '.requires.appliance == ">=0.5.0"' "$TMP/$id.json" > /dev/null && ok "$id : appliance 0.5 requise" || ko "$id : version d'appliance"
done
expect "syft : aucun réseau" "$(jq -r .scan.network "$TMP/syft.json")" none
expect "syft : SBOM CycloneDX 1.6 sur /out" "$(jq -c .outputs.cyclonedx "$TMP/syft.json")" '{"path":"/out/sbom.cdx.json","version":"1.6"}'
expect "syft : catégorie sbom (profils complet et release)" "$(jq -c .categories "$TMP/syft.json")" '["sbom"]'
expect "grype : base grype-db requise" "$(jq -c .requires.feeds "$TMP/grype.json")" '["grype-db"]'
expect "grype : lit le SBOM de l'analyse" "$(jq -r '.scan.sbom_command[1]' "$TMP/grype.json")" "sbom:/src/sbom.cdx.json"
expect "grype : sans SBOM, analyse /src elle-même" "$(jq -r '.scan.command[1]' "$TMP/grype.json")" "dir:/src"
expect "grype : aucune mise à jour ni validation d'âge en ligne" \
	"$(jq -c '[.scan.env.GRYPE_DB_AUTO_UPDATE, .scan.env.GRYPE_DB_VALIDATE_AGE, .scan.env.GRYPE_DB_REQUIRE_UPDATE_CHECK, .scan.env.GRYPE_CHECK_FOR_APP_UPDATE]' "$TMP/grype.json")" \
	'["false","false","false","false"]'
expect "grype-db : source HTTPS d'Anchore (liste v6)" "$(jq -r .feed.source.ref "$TMP/grype-db.json")" "https://grype.anchore.io/databases/v6/latest.json"
expect "grype-db : préparée par l'image épinglée de grype" "$(jq -r .feed.hydrate.image "$TMP/grype-db.json")" "$(jq -r .image "$TMP/grype.json")"
expect "dependency-track : libellé dtrack" "$(jq -r .hostname "$TMP/dependency-track.json")" dtrack
expect "dependency-track : PostgreSQL" "$(jq -r .needs.postgres "$TMP/dependency-track.json")" true
expect "dependency-track : télémétrie coupée" "$(jq -r .service.env.TELEMETRY_SUBMISSION_ENABLED_DEFAULT "$TMP/dependency-track.json")" false
jq -e '.service.egress | length > 0 and all(test("^[a-z0-9.-]+$"))' "$TMP/dependency-track.json" > /dev/null \
	&& ok "dependency-track : sortie Internet déclarée (miroirs)" || ko "dependency-track : sortie Internet non déclarée"
jq -e '.resources.min_ram_mb >= 4096' "$TMP/dependency-track.json" > /dev/null && ok "dependency-track : mémoire déclarée (≥ 4 Go)" || ko "dependency-track : mémoire sous-estimée"
expect "dtrack-upload : réseau du service seulement" "$(jq -r .scan.network "$TMP/dtrack-upload.json")" "service:dependency-track"
expect "dtrack-upload : facultatif, SBOM requis" "$(jq -c '[.scan.service_optional, .scan.requires_sbom]' "$TMP/dtrack-upload.json")" '[true,true]'
[[ -f "$TOOL/dtrack_upload.py" ]] && ok "dtrack-upload : outil de l'appliance présent" || ko "dtrack-upload : outil absent"
python3 - "$ROOT" > "$TMP/hostile.out" <<'EOF'
import copy, json, sys, yaml
sys.path.insert(0, sys.argv[1] + "/tests/lib")
import modcheck
v = modcheck.load_schema()
base = yaml.safe_load(open(sys.argv[1] + "/modules/grype/module.yaml"))
def case(label, fn, want):
    m = copy.deepcopy(base)
    fn(m)
    errs = modcheck.manifest_errors(m, v)
    print("%s\t%s" % (label, "oui" if any(want in e for e in errs) else "non: %s" % errs[:2]))
case("sbom_command sans entrée sbom", lambda m: m["scan"].update(inputs=["repo"]), "entrée « sbom »")
case("sbom_command sans la sortie", lambda m: m["scan"].update(sbom_command=["/grype", "sbom:/src/sbom.cdx.json"]), "absent de scan.sbom_command")
case("sbom_command avec « .. »", lambda m: m["scan"]["sbom_command"].append("/sbom/../etc"), "« .. »")
case("service_optional sans service", lambda m: m["scan"].update(service_optional=True), "service:<id>")
case("requires_sbom non booléen", lambda m: m["scan"].update(requires_sbom="oui"), "schéma")
EOF
while IFS=$'\t' read -r label verdict; do expect "manifeste hostile refusé : $label" "$verdict" oui; done < "$TMP/hostile.out"

# --- 2. Base grype-db (feeds.py) -----------------------------------------------------------
T="$TMP/root"
STUBS="$TMP/stubs"
SRV="$TMP/srv"
mkdir -p "$T/var/lib/scanoria" "$T/etc" "$STUBS" "$SRV/grype"
export SCANORIA_TEST_ROOT="$T" SCANORIA_TEST_BIN="$STUBS"
openssl req -x509 -newkey ed25519 -nodes -days 1 -subj "/CN=b19" -addext "subjectAltName=IP:127.0.0.1" \
	-keyout "$TMP/srv.key" -out "$TMP/srv.pem" 2> /dev/null
CURL=$(command -v curl)
cat > "$STUBS/curl" <<-EOF
	#!/bin/bash
	printf '%s\n' "\$*" >> "$TMP/curl.log"
	exec "$CURL" --cacert "$TMP/srv.pem" --noproxy 127.0.0.1 "\$@"
EOF
# podman simulé : « grype db import » écrit la base préparée dans /db/cache/6.
cat > "$STUBS/podman" <<EOF
#!/usr/bin/env python3
import json, os, sys
a = sys.argv[1:]
with open("$TMP/podman.log", "a") as f:
    f.write(json.dumps(a) + "\n")
mode = open("$TMP/hydrate-mode").read().strip() if os.path.exists("$TMP/hydrate-mode") else "ok"
if a[:2] == ["image", "exists"] or a[:1] in (["rm"], ["unshare"], ["pull"]):
    sys.exit(0)
if a[:1] != ["run"]:
    sys.exit(0)
vols = {}
for i, x in enumerate(a):
    if x == "--volume":
        host, target, m = a[i + 1].rsplit(":", 2)
        vols[target] = host
if mode == "fail":
    print("error: database import failed", file=sys.stderr); sys.exit(1)
cache = os.path.join(vols["/db"], "cache", "6")
os.makedirs(cache, exist_ok=True)
if mode == "symlink":
    os.symlink("/etc/passwd", cache + "/vulnerability.db")
else:
    open(cache + "/vulnerability.db", "wb").write(b"SQLite format 3\x00" + b"x" * 64)
digest = "sha256:0" if mode == "nodigest" else "xxh64:0123456789abcdef"
json.dump({"digest": digest, "source": "archive.tar.zst", "client_version": "6.1.4"}, open(cache + "/import.json", "w"))
sys.exit(0)
EOF
chmod 0755 "$STUBS/curl" "$STUBS/podman"
python3 "$ROOT/tests/lib/fakefeeds.py" serve "$TMP/srv.pem" "$TMP/srv.key" "$TMP/port" "$SRV" &
PIDS+=($!)
for _ in $(seq 50); do [[ -s "$TMP/port" ]] && break; sleep 0.1; done
HOST="127.0.0.1:$(cat "$TMP/port")"
head -c 4096 /dev/urandom > "$SRV/grype/vulnerability-db_v6.1.4_2026-11-24T00:00:00Z_1764000000.tar.zst"
listing() { # [jq]
	local f="vulnerability-db_v6.1.4_2026-11-24T00:00:00Z_1764000000.tar.zst"
	jq -cn --arg p "$f" --arg c "sha256:$(sha256sum "$SRV/grype/$f" | cut -d' ' -f1)" \
		'{status: "active", schemaVersion: "v6.1.4", built: "2026-11-24T00:00:00Z", path: $p, checksum: $c}' | jq -c "${1:-.}" > "$SRV/grype/latest.json"
}
GDB=$(jq -c --arg ref "https://$HOST/grype/latest.json" '.feed.source.ref = $ref | .resources.disk_mb = 1' "$TMP/grype-db.json")
refresh() {
	R=$(python3 - "$GDB" <<-'PY' 2> "$TMP/err" || true
		import json, sys
		sys.path.insert(0, __import__("os").environ["PYLIB"])
		from scanoria import feeds
		from scanoria.common import Fail
		try:
		    feeds.refresh(json.loads(sys.argv[1]), None, timeout=120)
		    print("OK")
		except Fail as f:
		    print(f.code + " " + f.message)
	PY
	)
}
FEEDS="$T/var/lib/scanoria/feeds"
listing
refresh
expect "grype-db : téléchargement et préparation" "${R%% *}" OK
[[ "${R%% *}" == OK ]] || { echo "     $R"; sed 's/^/     /' "$TMP/err" | tail -n 5; }
[[ -f "$FEEDS/grype-db/6/vulnerability.db" && -f "$FEEDS/grype-db/6/import.json" ]] \
	&& ok "grype-db : disposition attendue par Grype (6/vulnerability.db, 6/import.json)" || ko "grype-db : disposition inattendue"
[[ ! -e "$FEEDS/grype-db/archive.tar.zst" && ! -e "$FEEDS/grype-db/cache" ]] && ok "grype-db : archive et cache de travail non conservés" || ko "grype-db : fichiers de travail conservés"
expect "grype-db : schéma relevé" "$(jq -r .details.schema "$FEEDS/.store/grype-db/status.json")" v6.1.4
expect "grype-db : date de construction amont" "$(jq -r .details.upstream_updated_at "$FEEDS/.store/grype-db/status.json")" "2026-11-24T00:00:00Z"
jq -e '.details.archive | test("^sha256:[0-9a-f]{64}$")' "$FEEDS/.store/grype-db/status.json" > /dev/null && ok "grype-db : empreinte de l'archive gardée" || ko "grype-db : empreinte absente"
H=$(grep '"run"' "$TMP/podman.log" | tail -n 1)
for want in '"--network=none"' '"--read-only"' '"--cap-drop=ALL"' ':/db:rw"' 'GRYPE_DB_CACHE_DIR=/db/cache' 'GRYPE_DB_AUTO_UPDATE=false'; do
	grep -qF -- "$want" <<< "$H" && ok "préparation confinée : $want" || ko "préparation confinée : $want absent"
done
first=$(readlink "$FEEDS/grype-db")
fails() { # libellé motif
	refresh
	expect "grype-db : $1 → refusé" "${R%% *}" E_FEED_UNAVAILABLE
	grep -qF -- "$2" <<< "$R" && ok "grype-db : $1 : motif « $2 »" || ko "grype-db : $1 : motif absent ($R)"
	expect "grype-db : $1 : base précédente gardée" "$(readlink "$FEEDS/grype-db")" "$first"
}
listing '.checksum = "sha256:" + ("0" * 64)'; fails "empreinte fausse" "checksum mismatch"
listing '.path = "../../etc/passwd.tar.zst"'; fails "chemin d'archive hostile" "invalid archive path"
listing '.schemaVersion = "v5.0.0"'; fails "schéma non pris en charge" "unsupported database schema"
listing '.status = "deprecated"'; fails "liste dépréciée" "listing status"
listing '.path = "%2F%2Fevil.exemple.test%2Fx.tar.zst"'; fails "archive hors de l'hôte de la liste" "invalid archive path"
listing; echo fail > "$TMP/hydrate-mode"; fails "préparation en échec" "database preparation failed"
echo symlink > "$TMP/hydrate-mode"; fails "base préparée en lien symbolique (jamais suivi)" "lacks vulnerability.db"
echo nodigest > "$TMP/hydrate-mode"; fails "import.json sans empreinte xxh64" "no database digest"
rm -f "$TMP/hydrate-mode"
refresh
expect "grype-db : nouvelle version après correction" "${R%% *}/$([[ "$(readlink "$FEEDS/grype-db")" != "$first" ]] && echo nouvelle)" OK/nouvelle

# --- 3. Mise en service de Dependency-Track (dtrack.py) ------------------------------------
STATE="$TMP/dt-state.json"
jq -n '{up: true, admin_password: "admin", force_change: true, teams: [{uuid: "0b9e1c2d-3f4a-4b5c-8d6e-7f8091a2b3c4", name: "Administrators", permissions: [{name: "ACCESS_MANAGEMENT"}], apiKeys: []}], projects: {}, processing: 2}' > "$STATE"
python3 -I "$ROOT/tests/lib/fake_dtrack.py" "$STATE" "$TMP/dt-port" "$TMP/dt.log" &
PIDS+=($!)
for _ in $(seq 50); do [[ -s "$TMP/dt-port" ]] && break; sleep 0.1; done
DPORT=$(cat "$TMP/dt-port")
[[ -n "$DPORT" ]] && ok "faux serveur Dependency-Track démarré" || { ko "faux serveur Dependency-Track"; exit 1; }
SEC="$TMP/dt-secrets"
prov() {
	R=$(python3 - "$DPORT" "$SEC" <<-'PY' 2> "$TMP/err" || true
		import json, sys
		sys.path.insert(0, __import__("os").environ["PYLIB"])
		from scanoria import provision
		from scanoria.common import Fail
		try:
		    r = provision.run({"id": "dependency-track"}, {"host_port": int(sys.argv[1]), "secrets_dir": sys.argv[2], "timeout": 30, "phase": "install"})
		    print("OK " + json.dumps(r, sort_keys=True))
		except Fail as f:
		    print(f.code + " " + f.message)
	PY
	)
}
st() { jq -r "$1" "$STATE"; }
prov
expect "provision : première mise en service" "${R%% *}" OK
[[ "${R%% *}" == OK ]] || { echo "     $R"; tail -n 5 "$TMP/err"; }
expect "provision : mot de passe admin par défaut remplacé" "$(st '.admin_password != "admin" and .force_change == false')" true
expect "provision : mot de passe connu de l'appliance seulement (fichier 0600)" "$(stat -c %a "$SEC/admin-password")/$(st .admin_password)" "600/$(tr -d '\n' < "$SEC/admin-password")"
expect "provision : équipe d'analyse créée" "$(st '[.teams[] | select(.name == "Scanoria (analyses)")] | length')" 1
expect "provision : droits minimaux de l'équipe" "$(st '.teams[] | select(.name == "Scanoria (analyses)") | [.permissions[].name] | sort | join(",")')" "BOM_UPLOAD,PROJECT_CREATION_UPLOAD,VIEW_PORTFOLIO"
KEY=$(tr -d '\n' < "$SEC/scan-token")
expect "provision : clé d'API de l'équipe (fichier 0600)" "$(stat -c %a "$SEC/scan-token")/$(jq -r --arg k "$KEY" '[.teams[].apiKeys[]] | index($k) != null' "$STATE")" "600/true"
expect "provision : résultat" "${R#OK }" '{"admin_known": true, "token_renewed": true, "version": "4.14.7"}'
pw=$(st .admin_password)
prov
expect "provision : reprise sans changement (clé gardée, mot de passe gardé)" "${R#OK }/$(st .admin_password)/$(st '[.teams[].apiKeys[]] | length')" \
	'{"admin_known": true, "token_renewed": false, "version": "4.14.7"}/'"$pw"'/1'
jq '.teams |= map(.apiKeys = [])' "$STATE" > "$STATE.n" && mv "$STATE.n" "$STATE"
prov
expect "provision : clé révoquée dans Dependency-Track → renouvelée" "$(jq -r .token_renewed <<< "${R#OK }")/$([[ "$(tr -d '\n' < "$SEC/scan-token")" != "$KEY" ]] && echo nouvelle)" true/nouvelle
KEY=$(tr -d '\n' < "$SEC/scan-token")
jq '.admin_password = "change-a-la-main-0123456789"' "$STATE" > "$STATE.n" && mv "$STATE.n" "$STATE"
prov
expect "provision : mot de passe changé à la main, clé valide → clé gardée" "${R#OK }" '{"admin_known": false, "token_renewed": false, "version": "4.14.7"}'
jq '.teams |= map(.apiKeys = [])' "$STATE" > "$STATE.n" && mv "$STATE.n" "$STATE"
prov
expect "provision : mot de passe inconnu et clé invalide → E_DTRACK_ADMIN" "${R%% *}" E_DTRACK_ADMIN
jq --arg p "$(tr -d '\n' < "$SEC/admin-password")" '.admin_password = $p' "$STATE" > "$STATE.n" && mv "$STATE.n" "$STATE"
# Arrêt brutal entre le changement et le remplacement du fichier : repris.
mv "$SEC/admin-password" "$SEC/admin-password.new"
prov
expect "provision : changement interrompu repris (.new)" "${R%% *}/$([[ -f "$SEC/admin-password" && ! -e "$SEC/admin-password.new" ]] && echo repris)" OK/repris
jq '.up = false' "$STATE" > "$STATE.n" && mv "$STATE.n" "$STATE"
R=$(python3 - "$DPORT" "$SEC" <<-'PY' 2>&1 || true
	import sys, time
	sys.path.insert(0, __import__("os").environ["PYLIB"])
	from scanoria import dtrack
	from scanoria.common import Fail
	try:
	    dtrack.wait_up(dtrack.Http(int(sys.argv[1])), time.monotonic() + 0.2)
	    print("OK")
	except Fail as f:
	    print(f.code)
PY
)
expect "provision : API muette → E_DTRACK_UNAVAILABLE" "$R" E_DTRACK_UNAVAILABLE
jq '.up = true' "$STATE" > "$STATE.n" && mv "$STATE.n" "$STATE"
old=$(tr -d '\n' < "$SEC/admin-password")
R=$(python3 - "$DPORT" "$SEC" <<-'PY' 2>&1 || true
	import sys, time
	sys.path.insert(0, __import__("os").environ["PYLIB"])
	from scanoria import dtrack, provision
	from scanoria.common import Fail
	try:
	    pw = provision.RESETTERS["dependency-track"](int(sys.argv[1]), sys.argv[2], time.monotonic() + 30)
	    print("OK" if provision.PASSWORD_RE.match(pw) else "BAD")
	except Fail as f:
	    print(f.code)
PY
)
expect "réinitialisation : nouveau mot de passe admin" "$R/$([[ "$(st .admin_password)" != "$old" && "$(st .admin_password)" == "$(tr -d '\n' < "$SEC/admin-password")" ]] && echo appliqué)" OK/appliqué
expect "secrets sauvegardés avec la base (admin, clé)" "$(python3 -c 'import sys; sys.path.insert(0, sys.argv[1]); from scanoria import provision; print(",".join(provision.data_secrets("dependency-track")))' "$PYLIB")" "admin-password,scan-token"
grep -qF -- "$KEY" "$TMP/dt.log" "$TMP/err" && ko "provision : clé d'API dans un journal" || ok "provision : clé d'API absente des journaux"

# --- 4. Envoi des SBOM (dtrack_upload.py) --------------------------------------------------
C="$TMP/c"
KEY=$(tr -d '\n' < "$SEC/scan-token")   # clé courante de l'équipe d'analyse
mkdir -p "$C/out" "$C/sbom" "$C/secrets"
cp "$ROOT/modules/dtrack-upload/testbed/sbom.cdx.json" "$C/sbom/sbom.cdx.json"
printf '%s\n' "$KEY" > "$C/secrets/scan-token"
up() { # code libellé [env…]
	local want=$1 label=$2 rc=0
	shift 2
	env SCANORIA_SERVICE_URL="http://127.0.0.1:$DPORT" SCANORIA_PROJECT_KEY="scanoria-testbed" SCANORIA_REF="main" \
		SCANORIA_TOKEN_FILE="$C/secrets/scan-token" SCANORIA_OUT_DIR="$C/out" SCANORIA_SBOM_DIR="$C/sbom" SCANORIA_BUDGET_S=60 "$@" \
		python3 -I "$TOOL/dtrack_upload.py" "$C/sbom/sbom.cdx.json" "$C/out/dtrack.cdx.json" > "$C/stdout" 2> "$C/stderr" || rc=$?
	expect "dtrack_upload : $label (code $want)" "$rc" "$want"
}
: > "$TMP/dt.log"
up 0 "envoi, traitement, relecture"
PUUID=$(st '.projects["scanoria-testbed@main"].uuid')
expect "dtrack_upload : projet scanoria-testbed, version = référence" "$(st '.projects | keys | join(",")')" "scanoria-testbed@main"
expect "dtrack_upload : sortie CycloneDX 1.6 avec le projet Dependency-Track" \
	"$(jq -r '.specVersion + " " + (.metadata.properties[] | select(.name == "scanoria:dtrack:project") | .value)' "$C/out/dtrack.cdx.json")" "1.6 $PUUID"
expect "dtrack_upload : composant relu (attente du banc d'essai)" "$(python3 "$MC" expect "$ROOT/modules/dtrack-upload/module.yaml" "$C/out/dtrack.cdx.json" | head -n 1 | cut -c1-4)" "ok  "
expect "dtrack_upload : traitement attendu (jeton interrogé jusqu'à la fin)" "$(grep -c '"p": "api/v1/event/token/' "$TMP/dt.log")" 3
expect "dtrack_upload : clé par en-tête X-Api-Key à chaque appel authentifié" "$(jq -s '[.[] | select(.p != "api/version") | .key_header] | all' "$TMP/dt.log")" true
grep -qF -- "$KEY" "$C/stdout" "$C/stderr" "$C/out/dtrack.cdx.json" && ko "dtrack_upload : clé affichée" || ok "dtrack_upload : clé jamais affichée ni écrite"
[[ ! -e "$C/out/.dtrack.tmp" ]] && ok "dtrack_upload : aucun fichier temporaire laissé" || ko "dtrack_upload : fichier temporaire laissé"
rm -f "$C/out/dtrack.cdx.json"
jq '.reject_bom = true' "$STATE" > "$STATE.n" && mv "$STATE.n" "$STATE"
up 4 "envoi refusé"
[[ ! -e "$C/out/dtrack.cdx.json" ]] && ok "dtrack_upload : aucune sortie partielle" || ko "dtrack_upload : sortie partielle"
jq '.reject_bom = false' "$STATE" > "$STATE.n" && mv "$STATE.n" "$STATE"
up 3 "service injoignable" SCANORIA_SERVICE_URL="http://127.0.0.1:1" SCANORIA_BUDGET_S=1
up 2 "adresse du service hostile" SCANORIA_SERVICE_URL="http://evil.exemple.test@127.0.0.1/"
up 2 "clé de projet hostile" SCANORIA_PROJECT_KEY='x;rm -rf /'
up 2 "référence hostile" SCANORIA_REF='main; curl evil'
up 2 "sortie hors de /out" SCANORIA_OUT_DIR="$C/sbom"
printf 'pas une clé !\n' > "$C/secrets/scan-token"
up 3 "clé malformée"
printf '%s\n' "$KEY" > "$C/secrets/scan-token"
printf '%s\n' "odt_inconnue_$RANDOM$RANDOM" > "$C/secrets/scan-token"
up 4 "clé refusée par Dependency-Track"
printf '%s\n' "$KEY" > "$C/secrets/scan-token"
printf '{"bomFormat": "SPDX"}' > "$C/sbom/sbom.cdx.json"
up 6 "SBOM qui n'est pas du CycloneDX"
rm "$C/sbom/sbom.cdx.json"
ln -s /etc/passwd "$C/sbom/sbom.cdx.json"
up 6 "SBOM en lien symbolique"
rm "$C/sbom/sbom.cdx.json"
up 6 "SBOM absent"

# --- 5. Runner : chaînage du SBOM ----------------------------------------------------------
T="$TMP/rroot"
STUBS="$TMP/rstubs"
SCANS="$T/var/lib/scanoria/scans"
DSEC="$T/var/lib/scanoria/modules/dependency-track/secrets"
mkdir -p "$T/var/lib/scanoria/modules" "$T/run/scanoria" "$T/proc" "$T/sys/fs/cgroup/fake.scope/container" \
	"$T/etc/ssl/certs" "$T/usr/lib/scanoria/scan-tools/dtrack" "$T/var/lib/scanoria/feeds/grype-db/6" "$STUBS" "$DSEC"
printf 'MemTotal:       16384000 kB\n' > "$T/proc/meminfo"
for i in 0 1 2 3; do printf 'processor\t: %d\n' "$i"; done > "$T/proc/cpuinfo"
echo "52428800" > "$T/sys/fs/cgroup/fake.scope/container/memory.peak"
printf 'usage_usec 1234000\n' > "$T/sys/fs/cgroup/fake.scope/container/cpu.stat"
echo "AC de test" > "$T/etc/ssl/certs/ca-certificates.crt"
echo db > "$T/var/lib/scanoria/feeds/grype-db/6/vulnerability.db"
cp "$TOOL"/*.py "$T/usr/lib/scanoria/scan-tools/dtrack/"
export SCANORIA_TEST_ROOT="$T" SCANORIA_TEST_BIN="$STUBS" SCANORIA_TEST_RESOLVE="forge.exemple.test=192.0.2.10"
unset SCANORIA_TEST_OWNER_UID SCANORIA_SCANS_DIR SCANORIA_RUNNER_STATE
RTOK="odt_$(head -c 20 /dev/urandom | od -An -tx1 | tr -d ' \n')"
printf '%s\n' "$RTOK" > "$DSEC/scan-token"
chmod 0600 "$DSEC/scan-token"
SYFT_IMG=$(jq -r .image "$TMP/syft.json")
GRYPE_IMG=$(jq -r .image "$TMP/grype.json")
UP_IMG=$(jq -r .image "$TMP/dtrack-upload.json")
cat > "$STUBS/podman" <<EOF
#!/usr/bin/env python3
# Bouchon de podman : clone simulé ; syft, grype et dtrack-upload rendent leurs sorties enregistrées.
import json, os, sys
a = sys.argv[1:]
with open("$TMP/rpodman.log", "a") as f:
    f.write(json.dumps(a) + "\n")
if a[:2] in (["image", "exists"], ["network", "exists"]) or a[:2] == ["secret", "create"]:
    sys.exit(0)
if a[:1] == ["inspect"]:
    fmt = a[a.index("--format") + 1]
    print("/fake.scope" if "Cgroup" in fmt else "false"); sys.exit(0)
if a[:1] != ["run"]:
    sys.exit(0)
vols = {}
for i, x in enumerate(a):
    if x == "--volume":
        host, target, mode = a[i + 1].rsplit(":", 2)
        vols[target] = (host, mode)
ep = json.loads(a[a.index("--entrypoint") + 1])
img_i = a.index("--entrypoint") + 2
image, rest = a[img_i], a[img_i + 1:]
if ep == ["/bin/sh"]:   # git-fetch
    src = vols["/src"][0]
    os.makedirs(src, exist_ok=True)
    open(src + "/package-lock.json", "w").write("{}\n")
    print("commit=$(printf 'b19' | sha256sum | cut -c1-40)")
    sys.exit(0)
name = {"$SYFT_IMG": "syft", "$GRYPE_IMG": "grype", "$UP_IMG": "dtrack-upload"}[image]
with open("$TMP/runs.jsonl", "a") as f:
    f.write(json.dumps({"module": name, "cmd": [ep[0]] + rest, "sbom": vols.get("/sbom", [None, None])[1],
                        "sbom_file": os.path.exists(os.path.join(vols["/sbom"][0], "sbom.cdx.json")) if "/sbom" in vols else False,
                        "src_sbom": os.path.exists(os.path.join(vols["/src"][0], "sbom.cdx.json")) if "/src" in vols else False,
                        "args": a}) + "\n")
out = vols["/out"][0]
if name == "syft":
    if os.path.exists("$TMP/syft-broken"):
        open(out + "/sbom.cdx.json", "w").write('{"bomFormat": "CycloneDX", "specVersion": "1.2"}')
    else:
        open(out + "/sbom.cdx.json", "w").write(open("$ROOT/modules/syft/tests/recorded.cdx.json").read())
elif name == "grype":
    open(out + "/result.sarif", "w").write(open("$ROOT/modules/grype/tests/recorded.sarif").read())
else:
    open(out + "/dtrack.cdx.json", "w").write(open("$ROOT/modules/dtrack-upload/tests/recorded.cdx.json").read())
sys.exit(0)
EOF
printf '#!/bin/sh\ncat > /dev/null\nexit 0\n' > "$STUBS/nft"
chmod 0755 "$STUBS/podman" "$STUBS/nft"
GIMG="docker.io/exemple/git@sha256:$(printf 'git' | sha256sum | cut -d' ' -f1)"
registry() { # statut_dependency-track
	python3 - "$T/var/lib/scanoria/modules/installed.json" "$TMP" "$GIMG" "$1" <<'EOF'
import json, sys
path, tmp, gimg, dstatus = sys.argv[1:5]
man = {k: json.load(open("%s/%s.json" % (tmp, k))) for k in ("syft", "grype", "dtrack-upload", "dependency-track")}
git = {"id": "git-fetch", "name": "git", "type": "scanner", "version": "1.0.0", "categories": ["system"],
       "license": {"spdx": "MIT", "restrictions": "none"}, "image": gimg,
       "resources": {"min_ram_mb": 256, "min_cpu": 1, "disk_mb": 10},
       "requires": {"modules": [], "feeds": []}, "conflicts": [],
       "options": {"type": "object", "additionalProperties": False, "properties": {}},
       "scan": {"inputs": ["repo"], "network": "none", "timeout_s": 60, "command": ["git"]},
       "outputs": {"sarif": {"path": "/out/r.sarif", "version": "2.1.0"}}}
reg = {"modules": {k: {"manifest": v, "status": "healthy", "enabled": True, "options": {}} for k, v in man.items()}, "operations": []}
reg["modules"]["git-fetch"] = {"manifest": git, "status": "healthy", "enabled": True, "options": {}}
reg["modules"]["dependency-track"].update(status=dstatus, host_port=18080)
json.dump(reg, open(path, "w"))
EOF
}
uuid() { python3 -c 'import uuid; print(uuid.uuid4())'; }
PROJ=$(uuid)
mods() { jq -c '[.[] | {id: ., version: $v[.]}]' --argjson v "$(jq -n --slurpfile s "$TMP/syft.json" --slurpfile g "$TMP/grype.json" --slurpfile u "$TMP/dtrack-upload.json" \
	'{syft: $s[0].version, grype: $g[0].version, "dtrack-upload": $u[0].version}')" <<< "$1"; }
job() { # id modules-json [ref]
	jq -cn --arg id "$1" --arg sid "$(uuid)" --arg pr "$PROJ" --arg ref "${3:-refs/tags/v1.2.0}" --argjson m "$2" '
		{schema: 1, id: $id, scan_id: $sid, project_id: $pr, created_at: "2026-11-24T10:00:00Z",
		 source: {kind: "git", url: "https://forge.exemple.test/exemple/depot.git", ref: $ref, history: "shallow", default_branch: "main"},
		 modules: $m}'
}
drop() { mkdir -p "$SCANS/jobs/incoming"; printf '%s' "$2" > "$SCANS/jobs/incoming/$1.json"; chmod 0600 "$SCANS/jobs/incoming/$1.json"; }
run_runner() { "$RUNNER" --once 2> "$TMP/runner.err" || { echo "runner : code $?"; sed 's/^/     /' "$TMP/runner.err"; }; }
res() { cat "$SCANS/results/$1/result.json" 2> /dev/null || echo '{}'; }
statuses() { res "$1" | jq -r '[.modules[] | .id + "=" + .status + (if .error then ":" + .error.code else "" end)] | join(" ")'; }
valid() {
	python3 -I -B -c 'import json, sys; sys.path.insert(0, sys.argv[1]); from scanoria import schema
errs = schema.load("schemas", "scan-result").errors(json.load(open(sys.argv[2])))
print("; ".join(errs[:3])); sys.exit(1 if errs else 0)' "$PYLIB" "$SCANS/results/$1/result.json"
}
runs() { jq -r '.module' "$TMP/runs.jsonl" 2> /dev/null | paste -sd' '; }

registry healthy
: > "$TMP/runs.jsonl"
id=$(uuid); drop "$id" "$(job "$id" "$(mods '["grype", "dtrack-upload", "syft"]')")"; run_runner
expect "chaîne : les trois modules réussissent" "$(statuses "$id")" "grype=ok dtrack-upload=ok syft=ok"
check "chaîne : résultat conforme au schéma" valid "$id"
expect "chaîne : Syft lancé avant les modules qui lisent le SBOM" "$(runs)" "syft grype dtrack-upload"
expect "chaîne : Grype lit le SBOM (sbom_command)" "$(jq -r 'select(.module == "grype") | .cmd[1]' "$TMP/runs.jsonl")" "sbom:/src/sbom.cdx.json"
expect "chaîne : Grype lit le SBOM sur /src à la place du dépôt (comme en re-corrélation)" "$(jq -r 'select(.module == "grype") | (.src_sbom | tostring) + "/" + (.sbom // "aucun")' "$TMP/runs.jsonl")" "true/aucun"
expect "chaîne : SBOM monté en lecture seule sur /sbom pour dtrack-upload" "$(jq -r 'select(.module == "dtrack-upload") | .sbom + "/" + (.sbom_file | tostring)' "$TMP/runs.jsonl")" "ro/true"
expect "chaîne : Syft ne voit pas de SBOM" "$(jq -r 'select(.module == "syft") | .sbom // "aucun"' "$TMP/runs.jsonl")" aucun
jq -r 'select(.module == "dtrack-upload") | .args[]' "$TMP/runs.jsonl" > "$TMP/up-args.txt"
grep -qx "SCANORIA_REF=v1.2.0" "$TMP/up-args.txt" && ok "chaîne : version Dependency-Track = étiquette analysée" || ko "chaîne : SCANORIA_REF absent"
grep -qx -- "--network=scanoria-mod-dependency-track_scan" "$TMP/up-args.txt" && ok "chaîne : dtrack-upload sur le seul réseau interne du service" || ko "chaîne : réseau du service absent"
grep -qE ":/scanoria:ro$" "$TMP/up-args.txt" && ok "chaîne : outil de l'appliance monté en lecture seule" || ko "chaîne : outil non monté"
grep -qF -- "$RTOK" "$TMP/rpodman.log" && ko "chaîne : clé d'API dans les arguments de podman" || ok "chaîne : clé d'API jamais en argument"
expect "chaîne : sorties publiées" "$(res "$id" | jq -r '[.modules[] | .outputs | to_entries[] | .value] | join(" ")')" "grype/result.sarif dtrack-upload/dtrack.cdx.json syft/sbom.cdx.json"
expect "chaîne : SBOM de l'espace de travail supprimé avec lui" "$(find "$SCANS/workspaces" -mindepth 1 | wc -l)" 0

: > "$TMP/runs.jsonl"
id=$(uuid); drop "$id" "$(job "$id" "$(mods '["grype", "dtrack-upload"]')" "refs/heads/main")"; run_runner
expect "sans Syft : Grype analyse /src, dtrack-upload sans SBOM → skipped" "$(statuses "$id")" "grype=ok dtrack-upload=skipped:E_SBOM_MISSING"
expect "sans Syft : commande habituelle de Grype, sans /sbom" "$(jq -r 'select(.module == "grype") | .cmd[1] + " " + (.sbom // "aucun")' "$TMP/runs.jsonl")" "dir:/src aucun"

touch "$TMP/syft-broken"
: > "$TMP/runs.jsonl"
id=$(uuid); drop "$id" "$(job "$id" "$(mods '["syft", "grype"]')")"; run_runner
expect "SBOM invalide (G2) : Syft non concluant, jamais transmis à Grype" "$(statuses "$id")/$(jq -r 'select(.module == "grype") | .cmd[1]' "$TMP/runs.jsonl")" "syft=invalid-output:E_INVALID_OUTPUT grype=ok/dir:/src"
rm -f "$TMP/syft-broken"

registry failed
: > "$TMP/runs.jsonl"
id=$(uuid); drop "$id" "$(job "$id" "$(mods '["syft", "dtrack-upload", "grype"]')")"; run_runner
expect "Dependency-Track absent : dtrack-upload facultatif → skipped, le reste réussit" "$(statuses "$id")" "syft=ok dtrack-upload=skipped:E_SERVICE_MISSING grype=ok"
expect "Dependency-Track absent : dtrack-upload jamais lancé" "$(runs)" "syft grype"

# Libellé de version d'un projet dans un service.
R=$(python3 -c '
import sys; sys.path.insert(0, sys.argv[1]); from scanoria import sbom
cases = [({"kind": "git", "ref": "refs/tags/v1.0"}, "v1.0"), ({"kind": "git", "ref": "refs/heads/feat/x"}, "feat/x"),
         ({"kind": "git", "ref": "main"}, "main"), ({"kind": "archive"}, "archive"), ({"kind": "git", "ref": "a/../b"}, "unknown"),
         ({"kind": "git", "ref": "x;y"}, "unknown"), ({"kind": "git"}, "unknown")]
print(all(sbom.ref_label(s) == w for s, w in cases))' "$PYLIB")
expect "sbom.ref_label : référence nettoyée, valeurs hostiles écartées" "$R" True

# Qui lit le SBOM d'une analyse : Grype (prefers_sbom) et dtrack-upload (requires_sbom) ;
# OSV-Scanner et Trivy ont un sbom_command de re-corrélation (contrat 16) mais
# analysent le dépôt dans une analyse.
R=$(python3 -c '
import sys, yaml; sys.path.insert(0, sys.argv[1]); from scanoria import sbom
out = []
for mid in ("grype", "dtrack-upload", "osv-scanner", "trivy", "syft"):
    m = yaml.safe_load(open("%s/modules/%s/module.yaml" % (sys.argv[2], mid)))
    out.append("%s=%s%s" % (mid, int(sbom.consumes(m)), int(sbom.prefers(m))))
print(" ".join(out))' "$PYLIB" "$ROOT")
expect "contrat 14 : seuls Grype et dtrack-upload lisent le SBOM de l'analyse" "$R" "grype=11 dtrack-upload=10 osv-scanner=00 trivy=00 syft=00"

echo
echo "b19-sbom : $PASS réussis, $FAIL échoués"
[[ $FAIL -eq 0 ]]
