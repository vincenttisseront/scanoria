#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Vincent Tisseront
#
# b17-live — SonarQube Community Build réel et module sonar-scanner (chantier B
# de la 0.4), podman réel, en root sur une machine jetable (job CI sonarqube-live).
#  1. réglages noyau du manifeste (vm.max_map_count, fs.file-max) et limites
#     nofile/nproc du conteneur ;
#  2. SonarQube à l'image épinglée du manifeste, rattaché au réseau interne
#     scanoria-mod-sonarqube_scan (contrat 12) et publié sur la boucle locale
#     pour le helper ;
#  3. mise en service par provision.py : mot de passe admin remplacé,
#     utilisateur et jeton d'analyse dédiés, authentification forcée,
#     idempotence ; réinitialisation du mot de passe affiché une seule fois ;
#  4. banc d'essai de sonar-scanner lancé comme par le runner (svcnet : jeton
#     en secret Podman, réseau interne seul, outil monté en lecture seule) :
#     SARIF conforme au schéma officiel 2.1.0, attentes du banc d'essai ;
#  5. sans service sain : le scanner ne peut pas joindre SonarQube.
# Base embarquée de SonarQube (H2) : le branchement PostgreSQL relève du moteur
# des services (b12-live). La RAM de la machine est mesurée et affichée.
# Dépendances : podman, curl, jq, python3, python3-yaml, python3-jsonschema.

# shellcheck disable=SC2015
set -euo pipefail
export PYTHONDONTWRITEBYTECODE=1

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
LIVE="$ROOT/tests/lib/sonar_live.py"
MC="$ROOT/tests/lib/modcheck.py"
[[ $EUID -eq 0 ]] || { echo "b17-live : à lancer en root (machine jetable)" >&2; exit 2; }
for t in podman curl jq python3 sysctl timeout; do command -v "$t" > /dev/null || { echo "outil manquant : $t" >&2; exit 2; }; done

WORK=$(mktemp -d)
NET=scanoria-mod-sonarqube_scan
PUB=b17-pub-$$
CT=scanoria-mod-sonarqube
PORT=19000
cleanup() {
	podman rm -f "$CT" > /dev/null 2>&1 || true
	podman network rm -f "$NET" "$PUB" > /dev/null 2>&1 || true
	rm -rf "$WORK"
}
trap cleanup EXIT

PASS=0
FAIL=0
ok() { PASS=$((PASS + 1)); printf 'ok   %s\n' "$1"; }
ko() { FAIL=$((FAIL + 1)); printf 'FAIL %s\n' "$1"; }
expect() { [[ "$2" == "$3" ]] && ok "$1" || ko "$1 (obtenu « $2 », attendu « $3 »)"; }
yq() { python3 -c 'import json, sys, yaml; print(json.dumps(yaml.safe_load(open(sys.argv[1], encoding="utf-8"))))' "$1"; }

SARIF_COMMIT=1742a253eb654bf8a4ed7c60eaef7412b2c23553
SARIF_SHA256=c3b4bb2d6093897483348925aaa73af03b3e3f4bd4ca38cef26dcb4212a2682e
curl --proto '=https' --tlsv1.2 -fsSL --retry 3 -o "$WORK/sarif-schema.json" \
	"https://raw.githubusercontent.com/oasis-tcs/sarif-spec/$SARIF_COMMIT/sarif-2.1/schema/sarif-schema-2.1.0.json"
echo "$SARIF_SHA256  $WORK/sarif-schema.json" | sha256sum --check --strict --quiet

yq "$ROOT/modules/sonarqube/module.yaml" > "$WORK/sonarqube.json"
yq "$ROOT/modules/sonar-scanner/module.yaml" > "$WORK/sonar-scanner.json"
SQ_IMAGE=$(jq -r .image "$WORK/sonarqube.json")
SC_IMAGE=$(jq -r .image "$WORK/sonar-scanner.json")
echo "Machine : $(nproc) vCPU, $(awk '/MemTotal/ {printf "%d Mo", $2/1024}' /proc/meminfo) de RAM, $(awk '/MemAvailable/ {printf "%d Mo", $2/1024}' /proc/meminfo) disponibles"

# Appliance de test : chemins préfixés, podman réel (svcnet, Attachment).
export SCANORIA_TEST_ROOT="$WORK/root"
export SCANORIA_TEST_BIN="$WORK/bin"
mkdir -p "$SCANORIA_TEST_ROOT/usr/lib/scanoria" "$SCANORIA_TEST_ROOT/run/scanoria" "$SCANORIA_TEST_BIN"
cp -R "$ROOT/src/rootfs/usr/lib/scanoria/scan-tools" "$SCANORIA_TEST_ROOT/usr/lib/scanoria/"
chmod -R a+rX,go-w "$SCANORIA_TEST_ROOT/usr"
ln -s "$(command -v podman)" "$SCANORIA_TEST_BIN/podman"
SEC="$SCANORIA_TEST_ROOT/var/lib/scanoria/modules/sonarqube/secrets"

# --- 1. Réglages noyau et limites -----------------------------------------------------------
for k in vm.max_map_count fs.file-max; do
	want=$(jq -r --arg k "$k" '.needs.sysctl[$k]' "$WORK/sonarqube.json")
	cur=$(sysctl -n "$k")
	[[ "$cur" -ge "$want" ]] || sysctl -q -w "$k=$want"
	[[ "$(sysctl -n "$k")" -ge "$want" ]] && ok "sysctl $k ≥ $want" || ko "sysctl $k"
done
NOFILE=$(jq -r '.needs.sysctl.nofile' "$WORK/sonarqube.json")
NPROC=$(jq -r '.needs.sysctl.nproc' "$WORK/sonarqube.json")

# --- 2. SonarQube --------------------------------------------------------------------------
echo "::group::SonarQube"
podman pull -q "$SQ_IMAGE" > /dev/null
podman pull -q "$SC_IMAGE" > /dev/null
podman network create --internal "$NET" > /dev/null
podman network create "$PUB" > /dev/null
podman run -d --name "$CT" --network "$PUB" --network "$NET" -p "127.0.0.1:$PORT:9000" \
	--ulimit "nofile=$NOFILE:$NOFILE" --ulimit "nproc=$NPROC:$NPROC" \
	--env SONAR_TELEMETRY_ENABLE=false --env SONAR_UPDATECENTER_ACTIVATE=false \
	"$SQ_IMAGE" > /dev/null
t0=$SECONDS
python3 -I "$LIVE" provision "$WORK/sonarqube.json" "$PORT" install > "$WORK/prov1.json" \
	|| { podman logs --tail 80 "$CT" || true; ko "mise en service"; }
echo "SonarQube prêt en $((SECONDS - t0)) s ; mémoire du conteneur : $(podman stats --no-stream --format '{{.MemUsage}}' "$CT" 2>/dev/null || echo '?')"
echo "::endgroup::"
jq -c . "$WORK/prov1.json" || true
expect "mise en service : mot de passe admin connu" "$(jq -r .admin_known "$WORK/prov1.json")" true
expect "mise en service : jeton créé" "$(jq -r .token_renewed "$WORK/prov1.json")" true

ADMIN_PW=$(cat "$SEC/admin-password" 2>/dev/null || true)
code() { curl -s -o /dev/null -w '%{http_code}' "$@"; }
[[ -n "$ADMIN_PW" && "$ADMIN_PW" != admin ]] && ok "admin : mot de passe aléatoire" || ko "admin : mot de passe aléatoire"
expect "admin/admin refusé" "$(curl -s -u admin:admin "http://127.0.0.1:$PORT/api/authentication/validate" | jq -r .valid)" false
expect "admin : nouveau mot de passe valide" "$(curl -s -u "admin:$ADMIN_PW" "http://127.0.0.1:$PORT/api/authentication/validate" | jq -r .valid)" true
expect "authentification forcée (anonyme refusé)" "$(code "http://127.0.0.1:$PORT/api/issues/search")" 401
expect "fichiers de secrets 0600" "$(stat -c %a "$SEC/admin-password" "$SEC/scan-token" | sort -u)" 600
TOKEN=$(cat "$SEC/scan-token")
expect "jeton d'analyse valide" "$(curl -s -H "Authorization: Bearer $TOKEN" "http://127.0.0.1:$PORT/api/authentication/validate" | jq -r .valid)" true
expect "jeton d'analyse : pas administrateur" "$(code -H "Authorization: Bearer $TOKEN" "http://127.0.0.1:$PORT/api/system/info")" 403
expect "utilisateur scanoria-scan" "$(curl -s -u "admin:$ADMIN_PW" "http://127.0.0.1:$PORT/api/users/search?q=scanoria-scan" | jq -r '.users[0].login')" scanoria-scan
expect "visibilité privée par défaut" "$(curl -s -u "admin:$ADMIN_PW" "http://127.0.0.1:$PORT/api/navigation/organization" > /dev/null; curl -s -u "admin:$ADMIN_PW" "http://127.0.0.1:$PORT/api/settings/values?keys=projects.default.visibility" | jq -r '.settings[0].value // "private"')" private

python3 -I "$LIVE" provision "$WORK/sonarqube.json" "$PORT" enable > "$WORK/prov2.json" || ko "mise en service rejouée"
expect "idempotence : jeton conservé" "$(jq -r .token_renewed "$WORK/prov2.json")" false
# Valeurs secrètes comparées sans jamais être affichées (journal CI public).
[[ "$(cat "$SEC/admin-password")" == "$ADMIN_PW" ]] && ok "idempotence : même mot de passe" || ko "idempotence : mot de passe changé"

RID=$(python3 -c 'import uuid; print(uuid.uuid4())')
python3 -I "$LIVE" reset "$WORK/sonarqube.json" "$PORT" "$RID" > "$WORK/reset.json" || ko "réinitialisation"
NEWPW=$(jq -r .password "$SCANORIA_TEST_ROOT/run/scanoria/oneshot/$RID.json" 2>/dev/null || true)
expect "réinitialisation : sortie sans mot de passe" "$(jq -c . "$WORK/reset.json")" '{"id":"sonarqube","login":"admin","oneshot":true}'
[[ -n "$NEWPW" && "$NEWPW" != "$ADMIN_PW" ]] && ok "réinitialisation : nouveau mot de passe déposé une fois" || ko "réinitialisation : fichier à usage unique"
expect "réinitialisation : nouveau mot de passe accepté" "$(curl -s -u "admin:$NEWPW" "http://127.0.0.1:$PORT/api/authentication/validate" | jq -r .valid)" true
expect "réinitialisation : ancien refusé" "$(curl -s -u "admin:$ADMIN_PW" "http://127.0.0.1:$PORT/api/authentication/validate" | jq -r .valid)" false
expect "réinitialisation : jeton d'analyse intact" "$(curl -s -H "Authorization: Bearer $TOKEN" "http://127.0.0.1:$PORT/api/authentication/validate" | jq -r .valid)" true

# --- 4. Banc d'essai de sonar-scanner -------------------------------------------------------
echo "::group::sonar-scanner"
src="$WORK/src"
out="$WORK/out"
cp -R "$ROOT/modules/sonar-scanner/$(jq -r .testbed.path "$WORK/sonar-scanner.json")" "$src"
chmod -R a+rX,go-w "$src"
mkdir -p "$out"
chmod 0777 "$out"
TIMEOUT=$(jq -r .scan.timeout_s "$WORK/sonar-scanner.json")
t0=$SECONDS
rc=$(python3 -I "$LIVE" scan "$WORK/sonarqube.json" "$WORK/sonar-scanner.json" "$src" "$out" "$TIMEOUT" "b17-scan-$$" | tail -n 1)
echo "Analyse en $((SECONDS - t0)) s, code $rc"
echo "::endgroup::"
expect "sonar-scanner : code de sortie" "$rc" 0
expect "secret Podman supprimé après l'analyse" "$(podman secret ls --format '{{.Name}}' | grep -c '^scanoria-scan-' || true)" 0
sarif="$out/result.sarif"
if [[ -s "$sarif" ]]; then
	python3 "$MC" sarif "$WORK/sarif-schema.json" "$sarif" && ok "SARIF 2.1.0 conforme au schéma officiel" || ko "SARIF non conforme"
	python3 "$MC" expect "$ROOT/modules/sonar-scanner/module.yaml" "$sarif" && ok "attentes du banc d'essai satisfaites" \
		|| { ko "attentes du banc d'essai"; jq -c '[.runs[].results[].ruleId]' "$sarif"; }
	expect "aucun résultat tronqué" "$(jq -r '.runs[0].properties.scanoria.truncated' "$sarif")" false
	grep -qF -- "$TOKEN" "$sarif" && ko "jeton dans la sortie" || ok "jeton absent de la sortie"
	[[ ! -e "$out/.work" ]] && ok "répertoire de travail supprimé" || ko "répertoire de travail laissé"
	echo "Résultats : $(jq -c '[.runs[0].results[] | {r: .ruleId, l: .level}]' "$sarif")"
	# Diagnostic : ce que le serveur connaît du projet du banc d'essai.
	for q in "issues/search?components=scanoria-testbed" "issues/search?projects=scanoria-testbed" \
		"issues/search?componentKeys=scanoria-testbed" "hotspots/search?project=scanoria-testbed" \
		"measures/component?component=scanoria-testbed&metricKeys=ncloc,files,code_smells,security_hotspots" \
		"qualityprofiles/search?language=py"; do
		echo "api/$q → $(curl -s -u "admin:$NEWPW" "http://127.0.0.1:$PORT/api/$q" | jq -c '{total: (.total // .paging.total), rules: ([.issues[]?.rule, .hotspots[]?.ruleKey] | unique), measures: .component.measures, profiles: [.profiles[]? | {name, activeRuleCount, isDefault}]}')"
	done
else
	ko "sortie SARIF absente"
fi

# --- 5. Confinement : réseau interne seulement ----------------------------------------------
reach() { podman run --rm --network "$1" --entrypoint python3 "$SC_IMAGE" -I -c \
	"import urllib.request,sys
try: urllib.request.urlopen('$2', timeout=5); print('yes')
except Exception as e: print('no')"; }
expect "réseau interne : SonarQube joignable par son nom" "$(reach "$NET" "http://$CT:9000/api/system/status")" yes
expect "réseau interne : aucune sortie" "$(reach "$NET" "https://example.com/")" no
podman stop -t 30 "$CT" > /dev/null
rc=$(python3 -I "$LIVE" scan "$WORK/sonarqube.json" "$WORK/sonar-scanner.json" "$src" "$out" 120 "b17-scan2-$$" | tail -n 1 || true)
expect "service arrêté : serveur indisponible (code 3)" "$rc" 3

printf '\nb17-live : %d réussis, %d échecs\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
