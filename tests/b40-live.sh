#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Vincent Tisseront
#
# b40-live — déploiement après verdict favorable (0.8, J9, J11–J13) contre un
# VRAI Forgejo (API, Actions, registre de conteneurs OCI) et le VRAI helper
# root en mode test (job CI deploy-live, machine de test root jetable) :
#   1. AC jetable, certificat de forge.exemple.test ;
#   2. Forgejo en conteneur (image épinglée par empreinte), HTTPS, Actions et
#      registre actifs ; administrateur et compte de service (scanoria-bot,
#      droits réduits : dépôts, tickets, paquets) et leurs jetons ;
#   3. arborescence du helper (SCANORIA_TEST_ROOT), clé Ed25519 de
#      l'appliance créée par le helper lui-même ;
#   4. la console (tests/integration/deploy-live.test.ts, vrai PostgreSQL) :
#      refus sans verdict favorable, puis attestation signée par le helper,
#      promotion par empreinte, attestation cosign poussée, PR GitOps jamais
#      fusionnée, workflow_dispatch déclenché une seule fois ;
#   5. vérification indépendante de l'attestation dans le registre :
#      scanoria-verify attestation (Python + openssl) et cosign
#      verify-attestation (binaire officiel épinglé par SHA-256), refus sur
#      l'image candidate sans attestation ;
#   6. nettoyage : conteneur, entrées /etc/hosts.
# Moteur : podman (CI) ; SCANORIA_ENGINE=docker pour une machine de développement.
# Dépendances : bash, openssl, curl, jq, python3, podman, postgresql-16, node et webui/node_modules.

# shellcheck disable=SC2016,SC2015
set -euo pipefail

[[ "$(id -u)" -eq 0 ]] || { echo "b40-live : root requis" >&2; exit 2; }
ENGINE=${SCANORIA_ENGINE:-podman}
for t in openssl curl jq node python3 "$ENGINE"; do command -v "$t" > /dev/null || { echo "outil manquant : $t" >&2; exit 2; }; done

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
# Forgejo 17.0.2 (licence GPL-3.0-or-later), même empreinte que b34-live.
FORGEJO_IMAGE=${SCANORIA_FORGEJO_IMAGE:-"codeberg.org/forgejo/forgejo@sha256:879f4f10a98e3e167b32cde5f7ae3af0163d50bfacf567559a27a0e95a95670c"}
# cosign v2.4.3 (licence Apache-2.0), linux-amd64 : SHA-256 relevé le 2026-11-25
# et identique à cosign_checksums.txt de la release.
COSIGN_URL="https://github.com/sigstore/cosign/releases/download/v2.4.3/cosign-linux-amd64"
COSIGN_SHA256="caaad125acef1cb81d58dcdc454a1e429d09a750d1e9e2b3ed1aed8964454708"
PRED="https://github.com/vincenttisseront/scanoria/attestation/release-verdict/v1"
CLI=${SCANORIA_FORGEJO_CLI:-forgejo}
NAME=scanoria-b40-forgejo
PORT=3000
TMP=$(mktemp -d)
HOSTS_MARK="# scanoria-b40"
cleanup() {
	"$ENGINE" rm -f "$NAME" > /dev/null 2>&1 || true
	sed -i "/$HOSTS_MARK\$/d" /etc/hosts || true
	rm -rf "$TMP"
}
trap cleanup EXIT

PASS=0
FAIL=0
ok() { PASS=$((PASS + 1)); printf 'ok   %s\n' "$1"; }
ko() { FAIL=$((FAIL + 1)); printf 'FAIL %s\n' "$1"; }

# --- 1. AC et certificat jetables -----------------------------------------------------------
cd "$TMP"
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=Scanoria b40 AC de test" -keyout ca.key -out ca.pem > /dev/null 2>&1
openssl req -newkey rsa:2048 -nodes -subj "/CN=forge.exemple.test" -keyout forge.key -out forge.csr > /dev/null 2>&1
printf 'subjectAltName=DNS:forge.exemple.test\nextendedKeyUsage=serverAuth\n' > forge.ext
openssl x509 -req -in forge.csr -CA ca.pem -CAkey ca.key -CAcreateserial -days 2 -extfile forge.ext -out forge.pem > /dev/null 2>&1
mkdir -p certs && cp forge.pem forge.key certs/ && chmod 755 certs && chmod 644 certs/*
printf '127.0.0.1 forge.exemple.test analyse.exemple.test %s\n' "$HOSTS_MARK" >> /etc/hosts
ok "AC jetable et certificat émis"

# --- 2. Forgejo (Actions et registre de conteneurs) -----------------------------------------
env_args=()
for prefix in FORGEJO GITEA; do
	env_args+=(
		-e "${prefix}__security__INSTALL_LOCK=true"
		-e "${prefix}__server__PROTOCOL=https"
		-e "${prefix}__server__HTTP_PORT=$PORT"
		-e "${prefix}__server__DOMAIN=forge.exemple.test"
		-e "${prefix}__server__ROOT_URL=https://forge.exemple.test:$PORT/"
		-e "${prefix}__server__CERT_FILE=/certs/forge.pem"
		-e "${prefix}__server__KEY_FILE=/certs/forge.key"
		-e "${prefix}__server__DISABLE_SSH=true"
		-e "${prefix}__database__DB_TYPE=sqlite3"
		-e "${prefix}__actions__ENABLED=true"
		-e "${prefix}__packages__ENABLED=true"
		-e "${prefix}__service__DISABLE_REGISTRATION=true"
		-e "${prefix}__repository__DEFAULT_BRANCH=main"
		-e "${prefix}__log__LEVEL=Warn"
	)
done
"$ENGINE" run -d --name "$NAME" --network host -v "$TMP/certs:/certs:ro" "${env_args[@]}" "$FORGEJO_IMAGE" > /dev/null
for _ in $(seq 1 90); do
	curl -sf -m 5 --noproxy "*" --cacert "$TMP/ca.pem" "https://forge.exemple.test:$PORT/api/v1/version" > /dev/null 2>&1 && break
	sleep 1
done
if curl -sf -m 5 --noproxy "*" --cacert "$TMP/ca.pem" "https://forge.exemple.test:$PORT/api/v1/version" > "$TMP/version.json"; then
	ok "Forgejo démarré en HTTPS (version $(jq -r .version "$TMP/version.json"))"
else
	ko "Forgejo injoignable"
	"$ENGINE" logs "$NAME" 2>&1 | tail -n 40
	exit 1
fi

fj() { "$ENGINE" exec -u git "$NAME" "$CLI" admin user "$@"; }
pw() { openssl rand -hex 16; }
fj create --admin --username scanoria-admin --password "$(pw)" --email admin@exemple.test --must-change-password=false > /dev/null
fj create --username scanoria-bot --password "$(pw)" --email scanoria-bot@exemple.test --must-change-password=false > /dev/null
tok() { fj generate-access-token --username "$1" --token-name "b40-$1" --scopes "$2" --raw | tail -n 1; }
jq -n --arg admin "$(tok scanoria-admin all)" \
	--arg bot "$(tok scanoria-bot read:user,read:organization,write:repository,write:issue,write:package)" \
	'{admin: $admin, bot: $bot}' > "$TMP/tokens.json"
chmod 600 "$TMP/tokens.json"
[[ $(jq '[.[] | select(length >= 20)] | length' "$TMP/tokens.json") -eq 2 ]] && ok "comptes et jetons créés (compte de service à droits réduits)" || ko "jetons Forgejo"

# --- 3. Arborescence du helper root (mode test) ---------------------------------------------
H="$TMP/helper"
mkdir -p "$H"/var/lib/scanoria/requests/{tmp,incoming,work,done,failed} "$H/run/scanoria" "$H/etc/scanoria" "$TMP/out"
chmod 0700 "$H/var/lib/scanoria/requests/incoming" "$H/var/lib/scanoria/requests/work"
echo '{"fqdn": "analyse.exemple.test"}' > "$H/etc/scanoria/appliance.json"

# --- 4. Console contre le vrai Forgejo et le vrai helper ------------------------------------
if [[ -z "${DATABASE_URL:-}" ]]; then
	systemctl start postgresql.service
	runuser -u postgres -- psql -X -q -c "ALTER USER postgres PASSWORD 'b40-live-postgres'" > /dev/null
	DATABASE_URL="postgres://postgres:b40-live-postgres@127.0.0.1:5432/postgres"
fi
if (cd "$ROOT/webui" && DATABASE_URL="$DATABASE_URL" \
	SCANORIA_DEPLOY_FORGEJO_URL="https://forge.exemple.test:$PORT" SCANORIA_DEPLOY_CA="$TMP/ca.pem" SCANORIA_DEPLOY_TOKENS="$TMP/tokens.json" \
	SCANORIA_DEPLOY_HELPER_ROOT="$H" SCANORIA_DEPLOY_OUT="$TMP/out" \
	node_modules/.bin/vitest run --project server tests/integration/deploy-live.test.ts); then
	ok "console : refus sans verdict favorable, attestation signée par le helper, promotion, PR GitOps, CD déclenchée"
else
	ko "console contre le vrai Forgejo"
	"$ENGINE" logs "$NAME" 2>&1 | tail -n 40
fi
[[ -f "$H/etc/scanoria/keys/appliance.ed25519" ]] && ok "clé de l'appliance créée par le helper" || ko "clé de l'appliance absente"
[[ "$(stat -c %a "$H/etc/scanoria/keys/appliance.ed25519" 2> /dev/null)" == 600 ]] && ok "clé privée 0600" || ko "droits de la clé privée"
openssl pkey -in "$H/etc/scanoria/keys/appliance.ed25519" -pubout -out "$TMP/appliance.pem" 2> /dev/null || true
grep -rlq 'PRIVATE KEY' "$H/var/lib/scanoria/requests/done" "$H/run/scanoria" 2> /dev/null && ko "clé privée dans un résultat du helper" || ok "clé privée jamais publiée par le helper"

# --- 5. Vérification indépendante de l'attestation ------------------------------------------
if [[ -s "$TMP/out/image.txt" ]]; then
	IMAGE=$(< "$TMP/out/image.txt")
	CANDIDATE=$(< "$TMP/out/candidate.txt")
	export SCANORIA_REGISTRY_USER=scanoria-bot
	SCANORIA_REGISTRY_PASSWORD=$(jq -r .bot "$TMP/tokens.json")
	export SCANORIA_REGISTRY_PASSWORD
	V="$ROOT/src/rootfs/usr/share/scanoria/client/scanoria-verify-attestation"
	if out=$(python3 -I "$V" "$IMAGE" --key "$TMP/appliance.pem" --cacert "$TMP/ca.pem"); then
		[[ "$(jq -r '"\(.verified)/\(.verdict)"' <<< "$out")" == "true/passed" ]] \
			&& ok "scanoria-verify attestation : image validée, verdict passed" || ko "scanoria-verify attestation : sortie inattendue ($out)"
	else
		ko "scanoria-verify attestation : refus de l'image validée ($out)"
	fi
	python3 -I "$V" "$CANDIDATE" --key "$TMP/appliance.pem" --cacert "$TMP/ca.pem" > /dev/null && rc=0 || rc=$?
	[[ $rc -eq 1 ]] && ok "scanoria-verify attestation : image candidate sans attestation refusée" || ko "scanoria-verify attestation : candidate (code $rc)"
	openssl genpkey -algorithm ed25519 -out "$TMP/autre.key" 2> /dev/null
	openssl pkey -in "$TMP/autre.key" -pubout -out "$TMP/autre.pem" 2> /dev/null
	python3 -I "$V" "$IMAGE" --key "$TMP/autre.pem" --cacert "$TMP/ca.pem" > /dev/null && rc=0 || rc=$?
	[[ $rc -eq 1 ]] && ok "scanoria-verify attestation : autre clé refusée" || ko "scanoria-verify attestation : autre clé (code $rc)"

	# cosign officiel, épinglé par SHA-256 ; identifiants du registre dans une configuration jetable.
	curl -fsSL -m 120 -o "$TMP/cosign" "$COSIGN_URL"
	if [[ "$(sha256sum "$TMP/cosign" | cut -d' ' -f1)" == "$COSIGN_SHA256" ]]; then
		ok "cosign téléchargé, empreinte vérifiée"
		chmod 0755 "$TMP/cosign"
		mkdir -p "$TMP/docker"
		jq -n --arg h "forge.exemple.test:$PORT" --arg a "$(printf 'scanoria-bot:%s' "$SCANORIA_REGISTRY_PASSWORD" | base64 -w0)" '{auths: {($h): {auth: $a}}}' > "$TMP/docker/config.json"
		cosign() { DOCKER_CONFIG="$TMP/docker" SSL_CERT_FILE="$TMP/ca.pem" "$TMP/cosign" "$@"; }
		if cosign verify-attestation --key "$TMP/appliance.pem" --insecure-ignore-tlog --type "$PRED" "$IMAGE" > "$TMP/cosign.out" 2> "$TMP/cosign.err"; then
			jq -r '.payload' < <(head -n 1 "$TMP/cosign.out") | base64 -d | jq -e --arg p "$PRED" '.predicateType == $p and .predicate.verdict == "passed"' > /dev/null \
				&& ok "cosign verify-attestation : attestation Scanoria valide" || ko "cosign verify-attestation : contenu inattendu"
		else
			ko "cosign verify-attestation : refus de l'image validée"
			sed 's/^/     /' "$TMP/cosign.err" | tail -n 20
		fi
		cosign verify-attestation --key "$TMP/appliance.pem" --insecure-ignore-tlog --type "$PRED" "$CANDIDATE" > /dev/null 2>&1 \
			&& ko "cosign verify-attestation : image candidate acceptée" || ok "cosign verify-attestation : image candidate sans attestation refusée"
		cosign verify-attestation --key "$TMP/autre.pem" --insecure-ignore-tlog --type "$PRED" "$IMAGE" > /dev/null 2>&1 \
			&& ko "cosign verify-attestation : autre clé acceptée" || ok "cosign verify-attestation : autre clé refusée"
	else
		ko "cosign : empreinte inattendue"
	fi
else
	ko "aucune image promue à vérifier"
fi

echo
echo "b40-live : $PASS réussis, $FAIL échoués"
[[ $FAIL -eq 0 ]]
